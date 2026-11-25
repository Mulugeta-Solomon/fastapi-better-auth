"""First-use schema discovery is answered again while callers keep arriving (F22).

A store whose `connect()` was never called reads the schema inside its first lookup, under that
request's `lookup_timeout`, one read at a time. When a read overruns, its caller leaves and the
read is abandoned; the next caller in line starts it again from nothing. Handed to the oldest
waiter - the one with the least budget left, only the gap between two arrivals - every new read is
cut short before it can finish, for as long as traffic keeps arriving faster than one read takes,
and no request is answered on a database that is perfectly healthy again. Handed to the newest
waiter, the second read has a whole deadline to finish in.

Through the real verifier and the real store, both flavours: `SqlAlchemySessionStore` on asyncio,
`SyncStoreAdapter` on asyncio and trio. Each read is held until the test lets it go - the store's
`_columns` is wrapped, so a read is counted on the caller's own task the moment it starts - and
time moves only when the test moves it: `LeapingClock` on asyncio, trio's `MockClock` on trio
(passed to the backend as its clock, running at real speed so `GUARD` still bounds every wait).
A FIFO hand-over also ends with a caller served once the last read is let go; what differs is how
many reads it started on the way, which is what is pinned.
"""

from __future__ import annotations

import pathlib
from collections.abc import AsyncIterator, Callable
from typing import Any

import anyio
import pytest
from trio.testing import MockClock

from fastapi_better_auth import AuthServiceUnavailable, SqlAlchemySessionStore, SyncStoreAdapter
from tests.cookies import COOKIE, http, run, sign
from tests.deadlines import (
    GUARD,
    LONG,
    LeapingClock,
    every_call_ended,
    every_slot_returned,
    verifier,
)
from tests.stores import TOKEN, StoreFixture

COOKIE_PAIR = f"{COOKIE}={sign(TOKEN)}"

QUEUED_BEHIND_THE_STALL = 3
"""Callers that arrive while the first read is stalled, before its caller's deadline."""
CALLERS = 6
"""Every caller: the first, those queued behind it, and two that arrive after it has left."""
GAP = LONG / (QUEUED_BEHIND_THE_STALL + 1)
"""Between two arrivals: shorter than a read takes here, which lasts until the test ends it."""
REFUSED = {0, 1}
"""The first caller, whose read stalled, and the second, the oldest waiter, whose deadline passes
while the newest waiter's read runs."""

LEGS = (("async", "asyncio"), ("sync", "asyncio"), ("sync", "trio"))

Store = SqlAlchemySessionStore | SyncStoreAdapter


@pytest.fixture(params=LEGS, ids=["-".join(leg) for leg in LEGS])
def leg(request: pytest.FixtureRequest) -> tuple[str, str]:
    value = request.param
    assert isinstance(value, tuple)
    return value  # pyright: ignore[reportUnknownVariableType]


@pytest.fixture
def trio_clock() -> MockClock:
    return MockClock(rate=1.0)


@pytest.fixture
def anyio_backend(leg: tuple[str, str], trio_clock: MockClock) -> object:
    _, backend = leg
    return ("trio", {"clock": trio_clock}) if backend == "trio" else "asyncio"


@pytest.fixture
async def leap(
    leg: tuple[str, str], trio_clock: MockClock, monkeypatch: pytest.MonkeyPatch
) -> Callable[[float], None]:
    """Move the running loop's clock forward by that many seconds."""
    _, backend = leg
    if backend == "trio":
        return trio_clock.jump
    return LeapingClock(monkeypatch).leap


@pytest.fixture
async def fixture(tmp_path: pathlib.Path, leg: tuple[str, str]) -> AsyncIterator[StoreFixture]:
    flavour, _ = leg
    built = StoreFixture(tmp_path, flavour)
    yield built
    await built.aclose()


class HeldReads:
    """Every schema read a caller starts, counted on that caller's task and held until let go."""

    def __init__(self, store: Store, monkeypatch: pytest.MonkeyPatch) -> None:
        self.started = 0
        self._gates: list[anyio.Event] = []
        original = store._columns  # pyright: ignore[reportPrivateUsage]

        async def columns() -> Any:
            self.started += 1
            gate = anyio.Event()
            self._gates.append(gate)
            await gate.wait()
            return await original()

        monkeypatch.setattr(store, "_columns", columns)

    def let_the_newest_finish(self) -> None:
        self._gates[-1].set()

    def let_all_finish(self) -> None:
        for gate in self._gates:
            gate.set()


async def answered(store: Store) -> str:
    try:
        session = await run(verifier(store, lookup_timeout=LONG), http(cookie=COOKIE_PAIR))
    except AuthServiceUnavailable:
        return "refused"
    return "answered" if session is not None else "no session"


async def drained(store: Store) -> None:
    if isinstance(store, SqlAlchemySessionStore):
        await every_call_ended(store)
    else:
        await every_slot_returned(store)


@pytest.mark.anyio
async def test_discovery_is_answered_again_while_callers_keep_arriving(
    fixture: StoreFixture, monkeypatch: pytest.MonkeyPatch, leap: Callable[[float], None]
) -> None:
    store, _ = fixture()
    reads = HeldReads(store, monkeypatch)
    outcomes: dict[int, str] = {}
    finished = anyio.Event()

    async def caller(index: int) -> None:
        outcomes[index] = await answered(store)
        if len(outcomes) == CALLERS:
            finished.set()

    try:
        async with anyio.create_task_group() as group:
            group.start_soon(caller, 0)
            await anyio.wait_all_tasks_blocked()
            for index in range(1, CALLERS):
                leap(GAP)
                group.start_soon(caller, index)
                await anyio.wait_all_tasks_blocked()
            reads.let_the_newest_finish()
            with anyio.fail_after(GUARD):
                await finished.wait()
    finally:
        reads.let_all_finish()

    assert reads.started == 2, f"{reads.started} schema reads were started, not 2"
    assert store._plan is not None  # pyright: ignore[reportPrivateUsage]
    assert {index for index, what in outcomes.items() if what != "answered"} == REFUSED, outcomes
    await drained(store)
