"""`SyncStoreAdapter.max_concurrency` bounds worker threads for the whole life of each thread.

A lookup abandoned at the verifier's deadline (or by any cancellation) returns to its caller, but
its worker thread cannot be interrupted: it runs on, holding a pooled connection, until the
database answers. If the adapter's slot went back when the caller left, every request during a
database hang would start one more thread and pin one more connection, and the bound the adapter
documents would be no bound at all. So a slot is held until its thread really ends, on asyncio and
trio alike. Further requests wait for a slot cancellably, and are refused at their own deadline
without starting a thread.

The database here is a real SQLite file whose driver is made to stop answering; `ThreadGate`
counts the threads inside the driver and releases them.
"""

from __future__ import annotations

import logging
import pathlib
import threading
from collections.abc import AsyncIterator, Iterator
from typing import Any

import anyio
import pytest
from sqlalchemy import Engine, QueuePool

from fastapi_better_auth import AuthServiceUnavailable, SyncStoreAdapter
from fastapi_better_auth._internal.stores import thread_handoff
from fastapi_better_auth._internal.stores.thread_handoff import run_in_worker
from tests.cookies import COOKIE, http, run, sign
from tests.deadlines import DEADLINE, GUARD, OVERRUN_KIND, every_slot_returned, kinds, verifier
from tests.log_hygiene import capturing
from tests.stores import SESSION_ID, TOKEN, StoreFixture

LIMIT = 2
HUNG = LIMIT + 1
CYCLES = 10
STRAGGLER_WAIT = 0.2
"""How long a would-be extra thread is given to (wrongly) reach the driver before the count is
read. A thread that was started does reach it within milliseconds; this only bounds the read."""

COOKIE_PAIR = f"{COOKIE}={sign(TOKEN)}"


class ThreadGate:
    """Holds every statement inside `do_execute` until released, and counts who is inside."""

    def __init__(self, engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
        self.release = threading.Event()
        self._lock = threading.Lock()
        self.inside = 0
        self.peak = 0
        original = engine.dialect.do_execute

        def do_execute(cursor: Any, statement: str, parameters: Any, context: Any = None) -> None:
            with self._lock:
                self.inside += 1
                self.peak = max(self.peak, self.inside)
            try:
                self.release.wait(GUARD)
                original(cursor, statement, parameters, context)
            finally:
                with self._lock:
                    self.inside -= 1

        monkeypatch.setattr(engine.dialect, "do_execute", do_execute)


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


@pytest.fixture
async def bounded(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[SyncStoreAdapter, ThreadGate, Engine]]:
    fixture = StoreFixture(tmp_path, "sync")
    store, _ = fixture(store_options={"max_concurrency": LIMIT})
    assert isinstance(store, SyncStoreAdapter)
    await store.connect()
    engine = fixture.engines[-1]
    assert isinstance(engine, Engine)
    gate = ThreadGate(engine, monkeypatch)
    try:
        yield store, gate, engine
    finally:
        gate.release.set()
        await every_slot_returned(store)
        await fixture.aclose()


async def abandoned(store: SyncStoreAdapter, requests: int) -> None:
    """`requests` lookups through one verifier, each refused at the deadline while the database
    does not answer."""
    built = verifier(store, lookup_timeout=DEADLINE)
    for _ in range(requests):
        with anyio.fail_after(GUARD), pytest.raises(AuthServiceUnavailable):
            await run(built, http(cookie=COOKIE_PAIR))


@pytest.mark.anyio
async def test_abandoned_lookups_never_run_more_threads_than_the_limit(
    bounded: tuple[SyncStoreAdapter, ThreadGate, Engine], records: list[logging.LogRecord]
) -> None:
    store, gate, engine = bounded

    await abandoned(store, HUNG)
    await anyio.sleep(STRAGGLER_WAIT)

    assert gate.peak == LIMIT, f"{gate.peak} threads were inside the database at once, over {LIMIT}"
    assert isinstance(engine.pool, QueuePool)
    assert engine.pool.checkedout() <= LIMIT
    assert kinds(records) == [OVERRUN_KIND]


@pytest.mark.anyio
async def test_slots_come_back_when_the_database_answers_and_it_serves_again(
    bounded: tuple[SyncStoreAdapter, ThreadGate, Engine],
) -> None:
    store, gate, engine = bounded
    await abandoned(store, HUNG)

    gate.release.set()
    await every_slot_returned(store)

    assert gate.inside == 0
    assert isinstance(engine.pool, QueuePool)
    assert engine.pool.checkedout() == 0
    session = await run(verifier(store, lookup_timeout=GUARD), http(cookie=COOKIE_PAIR))
    assert session is not None
    assert session.id == SESSION_ID


@pytest.mark.anyio
async def test_a_lookup_cancelled_while_waiting_for_a_slot_starts_no_thread_and_leaks_none(
    bounded: tuple[SyncStoreAdapter, ThreadGate, Engine],
) -> None:
    """With every slot held by a hung thread, a further lookup waits on the limiter itself, so a
    cancellation there must leave no slot behind and no thread started."""
    store, gate, _ = bounded
    await abandoned(store, LIMIT)
    limiter = store._get_limiter()  # pyright: ignore[reportPrivateUsage]
    assert limiter.borrowed_tokens == LIMIT

    with anyio.move_on_after(DEADLINE) as waiting:
        await store.fetch_session_by_token(TOKEN)

    assert waiting.cancelled_caught
    assert limiter.borrowed_tokens == LIMIT
    assert gate.peak == LIMIT
    gate.release.set()
    await every_slot_returned(store)


@pytest.mark.anyio
async def test_no_slot_leaks_across_many_hang_and_recover_cycles(
    bounded: tuple[SyncStoreAdapter, ThreadGate, Engine],
) -> None:
    store, gate, engine = bounded

    for _ in range(CYCLES):
        gate.release.clear()
        await abandoned(store, HUNG)
        gate.release.set()
        await every_slot_returned(store)

    assert gate.peak == LIMIT
    assert isinstance(engine.pool, QueuePool)
    assert engine.pool.checkedout() == 0
    session = await run(verifier(store, lookup_timeout=GUARD), http(cookie=COOKIE_PAIR))
    assert session is not None


# ---------------------------------------------------------------- the hand-off on its own


@pytest.mark.anyio
async def test_a_call_that_raises_gives_its_slot_back() -> None:
    limiter = anyio.CapacityLimiter(1)

    def broken() -> None:
        raise LookupError("the driver raised")

    with pytest.raises(LookupError):
        await run_in_worker(limiter, broken)

    assert limiter.borrowed_tokens == 0


@pytest.mark.anyio
async def test_a_thread_that_fails_to_start_gives_its_slot_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limiter = anyio.CapacityLimiter(1)

    async def no_thread(*args: object, **kwargs: object) -> None:
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(thread_handoff, "run_sync", no_thread)

    with pytest.raises(RuntimeError, match="can't start new thread"):
        await run_in_worker(limiter, lambda: None)

    assert limiter.borrowed_tokens == 0


@pytest.mark.anyio
async def test_a_call_withdrawn_before_its_thread_starts_never_runs() -> None:
    """The caller left before the worker began: the slot is given back at once, exactly once, and
    the worker refuses to start a call nobody is waiting for."""
    limiter = anyio.CapacityLimiter(1)
    post = thread_handoff._post_to_this_loop()  # pyright: ignore[reportPrivateUsage]
    slot = thread_handoff._Slot(limiter, post)  # pyright: ignore[reportPrivateUsage]
    await limiter.acquire_on_behalf_of(slot)
    ran: list[bool] = []

    slot.settle()

    assert limiter.borrowed_tokens == 0
    with pytest.raises(thread_handoff.AbandonedBeforeStartError):
        slot.run(lambda: ran.append(True))
    assert ran == []
    assert limiter.borrowed_tokens == 0
