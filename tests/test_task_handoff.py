"""The asyncio hand-off behind `SqlAlchemySessionStore`: its backstop, its ownership, its join.

`test_cookie_lookup_async_handoff.py` proves what a store does with it; this proves the parts a
store cannot show on its own. A call whose clean-up never ends is cancelled again and again until
it does. An abandoned call that nothing else references is kept alive by the hand-off rather than
collected mid-clean-up. The join returns only once every abandoned call has ended. And an outcome
never reaches the loop's exception handler, not even when the loop shuts down mid-clean-up - the
path `asyncio.run` takes, which reports a leftover task's exception text and all.

The calls here are plain coroutines: no database, no driver, every wait an event bounded by
`GUARD`. The backstop runs on a bound no test waits out, and the loop's clock is moved past it one
round at a time (`LeapingClock`), so its timer fires exactly when the test says and never on a
slow machine's own schedule. A call that swallows cancellations is released in a `finally`, so a
regression that stops cancelling it fails the test in seconds and leaves the loop able to close.
"""

from __future__ import annotations

import asyncio
import gc
import weakref
from collections.abc import Callable, Coroutine
from typing import Any

import anyio
import pytest

from fastapi_better_auth import SqlAlchemySessionStore
from fastapi_better_auth._internal.stores.task_handoff import WIND_DOWN_SECONDS, TaskHandoff
from tests.deadlines import GUARD, LONG, LeapingClock
from tests.stores import TOKEN

BACKSTOP_ROUNDS = 3
"""Cancellations a stubborn call takes before it ends: the caller's, then two of the backstop's."""

SPINS = 20
"""Loop iterations a test lets pass to show that something did *not* happen in them."""


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def spin() -> None:
    for _ in range(SPINS):
        await asyncio.sleep(0)


async def bounded(event: asyncio.Event) -> None:
    """Wait for `event`, or fail the test within `GUARD`. Entered after any leap of the clock."""
    with anyio.fail_after(GUARD):
        await event.wait()


async def abandoned(handoff: TaskHandoff, call: Callable[[], Coroutine[Any, Any, object]]) -> None:
    """Run `call` through `handoff`, and cancel the caller as soon as the call has started."""
    started = asyncio.Event()

    async def tracked() -> object:
        started.set()
        return await call()

    with anyio.fail_after(GUARD), anyio.CancelScope() as caller:
        async with anyio.create_task_group() as group:
            group.start_soon(handoff.run, tracked)
            await started.wait()
            caller.cancel()
    assert caller.cancelled_caught


class Stubborn:
    """A call whose clean-up does not end on a cancellation: it ends on the `needed`-th.

    `reached(n)` is set when the `n`-th cancellation arrives. `released` ends the call however
    many have; every test sets it in a `finally`, because a call that swallows cancellations and
    is never released is a task no loop teardown can end.
    """

    def __init__(self, needed: int) -> None:
        self.needed = needed
        self.cancellations = 0
        self.released = asyncio.Event()
        self.ended = asyncio.Event()
        self._reached: dict[int, asyncio.Event] = {}

    def reached(self, count: int) -> asyncio.Event:
        return self._reached.setdefault(count, asyncio.Event())

    async def __call__(self) -> object:
        try:
            while not self.released.is_set():
                try:
                    await self.released.wait()
                except asyncio.CancelledError:
                    self.cancellations += 1
                    self.reached(self.cancellations).set()
                    if self.cancellations >= self.needed:
                        raise
            return None
        finally:
            self.ended.set()


@pytest.mark.anyio
async def test_the_wind_down_bound_is_longer_than_sqlalchemys_own_graceful_close() -> None:
    """SQLAlchemy gives a graceful close two seconds; a driver that bounds its own clean-up gets
    to finish it cleanly before the backstop forces anything."""
    assert WIND_DOWN_SECONDS > 2.0


def test_the_store_documents_the_bound_it_uses() -> None:
    """The class docstring states the wind-down bound in seconds; it must be this one."""
    assert f"within {WIND_DOWN_SECONDS:g} seconds" in (SqlAlchemySessionStore.__doc__ or "")
    assert f"every {WIND_DOWN_SECONDS:g} seconds" in (SqlAlchemySessionStore.__doc__ or "")


@pytest.mark.anyio
async def test_a_result_and_an_error_reach_the_waiting_caller_unchanged() -> None:
    handoff = TaskHandoff()
    failure = LookupError("the database said no")

    async def answers() -> int:
        return 7

    async def fails() -> int:
        raise failure

    with anyio.fail_after(GUARD):
        assert await handoff.run(answers) == 7
        with pytest.raises(LookupError) as caught:
            await handoff.run(fails)
    assert caught.value is failure
    assert caught.value.__context__ is None
    assert handoff.winding_down == 0


@pytest.mark.anyio
async def test_a_call_whose_clean_up_does_not_end_is_cancelled_again_until_it_does(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One cancellation from the caller, then one from the backstop's own timer each time the
    clock passes the bound, until the call ends - and none after it has."""
    clock = LeapingClock(monkeypatch)
    handoff = TaskHandoff(wind_down=LONG)
    call = Stubborn(needed=BACKSTOP_ROUNDS)
    try:
        await abandoned(handoff, call)
        await bounded(call.reached(1))
        await spin()
        assert call.cancellations == 1, "the caller did not cancel its call exactly once"
        for count in range(2, BACKSTOP_ROUNDS + 1):
            clock.leap(LONG)
            await bounded(call.reached(count))
            await spin()
            assert call.cancellations == count, "one pass of the bound is one cancellation"
        await bounded(call.ended)
        with anyio.fail_after(GUARD):
            await handoff.settled()
        clock.leap(LONG)
        await spin()
    finally:
        call.released.set()

    assert call.cancellations == BACKSTOP_ROUNDS
    assert handoff.winding_down == 0


@pytest.mark.anyio
async def test_a_call_that_ends_within_the_bound_is_cancelled_once() -> None:
    handoff = TaskHandoff(wind_down=LONG)
    call = Stubborn(needed=1)
    try:
        await abandoned(handoff, call)
        with anyio.fail_after(GUARD):
            await handoff.settled()
        await spin()
    finally:
        call.released.set()

    assert call.cancellations == 1


@pytest.mark.anyio
async def test_the_handoff_owns_an_abandoned_call_until_it_ends() -> None:
    """asyncio keeps only weak references to its tasks. A call whose clean-up waits on something
    only it can reach would be collected mid-clean-up, its connection with it, if the hand-off
    did not hold it; and the join is what a test waits on before it disposes an engine."""
    handoff = TaskHandoff(wind_down=LONG)
    before = asyncio.all_tasks()

    async def clean_up_only_this_call_can_reach() -> object:
        loop = asyncio.get_running_loop()
        try:
            await loop.create_future()
        except asyncio.CancelledError:
            await asyncio.shield(loop.create_future())
        return None

    await abandoned(handoff, clean_up_only_this_call_can_reach)
    left = asyncio.all_tasks() - before
    try:
        assert len(left) == 1, f"expected the one abandoned call to be winding down: {left}"
        alive = weakref.ref(next(iter(left)))
        left.clear()
        del before
        gc.collect()

        task = alive()
        assert task is not None, "the abandoned call was collected while it was still winding down"
        assert handoff.winding_down == 1
        join = asyncio.ensure_future(handoff.settled())
        await spin()
        assert not join.done(), "the join returned while a call was still winding down"

        task.cancel()
        del task
        with anyio.fail_after(GUARD):
            await join
        assert handoff.winding_down == 0
    finally:
        for task in left:
            task.cancel()


def test_no_outcome_reaches_the_loop_even_when_it_shuts_down_mid_clean_up() -> None:
    """`asyncio.run` cancels whatever is left at shutdown and hands any task that then ends with
    an exception to the loop's exception handler, whose default prints the exception's text - a
    driver error's embeds the token. The abandoned call here ends with one, at shutdown."""
    reports: list[dict[str, Any]] = []

    async def call() -> object:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            try:
                await asyncio.shield(asyncio.Event().wait())
            except asyncio.CancelledError:
                raise LookupError(f"failed while matching ({TOKEN})") from None
        return None

    async def main() -> None:
        asyncio.get_running_loop().set_exception_handler(
            lambda _loop, context: reports.append(context)
        )
        handoff = TaskHandoff(wind_down=LONG)
        caller = asyncio.ensure_future(handoff.run(call))
        await spin()
        caller.cancel()
        # Bounded: a caller that waited for its call's clean-up would wait here for good.
        done, _ = await asyncio.wait({caller}, timeout=GUARD)
        assert caller in done, "the cancelled caller waited for its call's clean-up"
        assert caller.cancelled()
        assert handoff.winding_down == 1

    asyncio.run(main())
    gc.collect()
    assert reports == []
