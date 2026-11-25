"""The lock first-use schema discovery takes its turns under: one holder, newest waiter next.

`test_cookie_lookup_discovery_turn.py` proves what the order is for; this pins the primitive on
both anyio backends. One holder at a time. On release the turn goes to the newest waiter. A waiter
cancelled while it waits leaves the line; one cancelled just as it is handed the turn passes it
on, so the turn is never lost - to the next waiter, or back to free when nobody waits. And it is
released however its holder leaves. Every wait is on an event or bounded by `GUARD`.
"""

from __future__ import annotations

import anyio
import pytest

from fastapi_better_auth._internal.stores.newest_first import NewestFirstLock
from tests.deadlines import GUARD

WAITERS = ("first", "second", "third")


async def taken(lock: NewestFirstLock, order: list[str], name: str) -> None:
    async with lock:
        order.append(name)


async def free_again(lock: NewestFirstLock) -> None:
    """Take and give back the lock, or fail the test if it is still held."""
    with anyio.fail_after(GUARD):
        async with lock:
            pass


def test_it_is_built_outside_any_event_loop() -> None:
    """Stores are built in synchronous setup, before the loop exists."""
    NewestFirstLock()


@pytest.mark.anyio
async def test_one_holder_at_a_time() -> None:
    lock = NewestFirstLock()
    inside: list[str] = []
    peak = 0

    async def hold(name: str) -> None:
        nonlocal peak
        async with lock:
            inside.append(name)
            peak = max(peak, len(inside))
            await anyio.wait_all_tasks_blocked()
            inside.remove(name)

    with anyio.fail_after(GUARD):
        async with anyio.create_task_group() as group:
            for name in WAITERS:
                group.start_soon(hold, name)
    assert peak == 1


@pytest.mark.anyio
async def test_the_turn_goes_to_the_newest_waiter() -> None:
    lock = NewestFirstLock()
    order: list[str] = []
    with anyio.fail_after(GUARD):
        async with anyio.create_task_group() as group:
            await lock.acquire()
            for name in WAITERS:
                group.start_soon(taken, lock, order, name)
                await anyio.wait_all_tasks_blocked()
            lock.release()
    assert order == list(reversed(WAITERS))


@pytest.mark.anyio
async def test_a_waiter_cancelled_while_it_waits_leaves_the_line() -> None:
    lock = NewestFirstLock()
    order: list[str] = []
    leaving = anyio.CancelScope()
    with anyio.fail_after(GUARD):
        async with anyio.create_task_group() as group:
            await lock.acquire()
            group.start_soon(taken, lock, order, "stays")
            await anyio.wait_all_tasks_blocked()
            group.start_soon(cancellable, lock, order, leaving)
            await anyio.wait_all_tasks_blocked()
            leaving.cancel()
            await anyio.wait_all_tasks_blocked()
            lock.release()
    assert order == ["stays"]
    await free_again(lock)


async def cancellable(lock: NewestFirstLock, order: list[str], scope: anyio.CancelScope) -> None:
    with scope:
        await taken(lock, order, "leaves")


@pytest.mark.anyio
@pytest.mark.parametrize("others", [1, 0], ids=["another-waiter", "nobody-else"])
async def test_a_waiter_cancelled_as_it_is_handed_the_turn_passes_it_on(others: int) -> None:
    """The newest waiter is cancelled and handed the turn in the same step, with no checkpoint
    between: it must not keep the turn, and nobody may be left waiting for it."""
    lock = NewestFirstLock()
    order: list[str] = []
    leaving = anyio.CancelScope()
    with anyio.fail_after(GUARD):
        async with anyio.create_task_group() as group:
            await lock.acquire()
            for index in range(others):
                group.start_soon(taken, lock, order, f"waiting-{index}")
                await anyio.wait_all_tasks_blocked()
            group.start_soon(cancellable, lock, order, leaving)
            await anyio.wait_all_tasks_blocked()
            leaving.cancel()
            lock.release()
    assert leaving.cancelled_caught
    assert order == [f"waiting-{index}" for index in range(others)]
    await free_again(lock)


@pytest.mark.anyio
async def test_released_with_nobody_waiting_it_can_be_taken_again() -> None:
    lock = NewestFirstLock()
    await free_again(lock)
    await free_again(lock)


@pytest.mark.anyio
async def test_a_holder_that_raises_releases_it() -> None:
    lock = NewestFirstLock()
    with pytest.raises(LookupError):
        async with lock:
            raise LookupError("the read failed")
    await free_again(lock)
