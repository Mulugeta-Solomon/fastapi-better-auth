"""`SyncStoreAdapter.max_concurrency` bounds worker threads for the whole life of each thread.

A lookup abandoned at the verifier's deadline (or by any cancellation) returns to its caller, but
its worker thread cannot be interrupted: it runs on, holding a pooled connection, until the
database answers. If the adapter's slot went back when the caller left, every request during a
database hang would start one more thread and pin one more connection, and the bound the adapter
documents would be no bound at all. So a slot is held until its thread really ends, on asyncio and
trio alike. Further requests wait for a slot cancellably, and are refused at their own deadline
without starting a thread.

The database here is a real SQLite file whose driver is made to stop answering (`DriverGate`).
Nothing here waits on a timer to decide an outcome. A lookup is abandoned only after the gate has
seen it reach the database. A lookup is known to be waiting for a slot when the limiter counts it
as waiting. "No extra thread ever started" is a count of every call that reached the database,
read once all slots are back, which means every thread has ended.
"""

from __future__ import annotations

import logging
import pathlib
from collections.abc import AsyncIterator, Iterator

import anyio
import pytest
from sqlalchemy import Engine, QueuePool

from fastapi_better_auth import AuthServiceUnavailable, SyncStoreAdapter
from fastapi_better_auth._internal.stores import thread_handoff
from fastapi_better_auth._internal.stores.thread_handoff import run_in_worker
from tests.cookies import COOKIE, http, run, sign
from tests.deadlines import (
    DEADLINE,
    GUARD,
    OVERRUN_KIND,
    DriverGate,
    every_slot_returned,
    kinds,
    verifier,
)
from tests.log_hygiene import capturing
from tests.stores import SESSION_ID, TOKEN, StoreFixture

LIMIT = 2
CYCLES = 10

COOKIE_PAIR = f"{COOKIE}={sign(TOKEN)}"

Bounded = tuple[SyncStoreAdapter, DriverGate, Engine]


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


@pytest.fixture
async def bounded(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Bounded]:
    fixture = StoreFixture(tmp_path, "sync")
    store, _ = fixture(store_options={"max_concurrency": LIMIT})
    assert isinstance(store, SyncStoreAdapter)
    await store.connect()
    engine = fixture.engines[-1]
    assert isinstance(engine, Engine)
    gate = DriverGate(engine, monkeypatch)
    try:
        yield store, gate, engine
    finally:
        gate.release.set()
        await every_slot_returned(store)
        await fixture.aclose()


def checked_out(engine: Engine) -> int:
    pool = engine.pool
    assert isinstance(pool, QueuePool)
    return pool.checkedout()


def borrowed(store: SyncStoreAdapter) -> int:
    return store._get_limiter().borrowed_tokens  # pyright: ignore[reportPrivateUsage]


def waiting(store: SyncStoreAdapter) -> int:
    return store._get_limiter().statistics().tasks_waiting  # pyright: ignore[reportPrivateUsage]


async def hold_every_slot(store: SyncStoreAdapter, gate: DriverGate) -> None:
    """`LIMIT` lookups, each abandoned only once the gate has seen it reach the database. Their
    callers are gone when this returns, and their threads are still blocked there."""
    reached = gate.entries + LIMIT
    with anyio.CancelScope() as callers:
        async with anyio.create_task_group() as group:
            for _ in range(LIMIT):
                group.start_soon(store.fetch_session_by_token, TOKEN)
            await gate.entered(reached)
            callers.cancel()
    assert callers.cancelled_caught


async def recovered(store: SyncStoreAdapter, gate: DriverGate) -> None:
    """Let the database answer, and wait for every thread to end."""
    gate.release.set()
    await every_slot_returned(store)


@pytest.mark.anyio
async def test_abandoned_threads_keep_their_slots_and_no_further_thread_starts(
    bounded: Bounded, records: list[logging.LogRecord]
) -> None:
    """With every slot held by an abandoned thread, a further request waits for a slot and is
    refused at its own deadline. Its deadline can fire early or late without changing anything
    here: it was never going to get a slot."""
    store, gate, engine = bounded
    await hold_every_slot(store, gate)
    assert borrowed(store) == LIMIT, "abandoned threads gave their slots back while still running"

    with anyio.fail_after(GUARD), pytest.raises(AuthServiceUnavailable):
        await run(verifier(store, lookup_timeout=DEADLINE), http(cookie=COOKIE_PAIR))
    await recovered(store, gate)

    assert gate.entries == LIMIT, f"{gate.entries} calls reached the database, over {LIMIT}"
    assert gate.peak == LIMIT
    assert checked_out(engine) == 0
    assert kinds(records) == [OVERRUN_KIND]


@pytest.mark.anyio
async def test_slots_come_back_when_the_database_answers_and_it_serves_again(
    bounded: Bounded,
) -> None:
    store, gate, engine = bounded
    await hold_every_slot(store, gate)

    await recovered(store, gate)

    assert gate.inside == 0
    assert checked_out(engine) == 0
    session = await run(verifier(store, lookup_timeout=GUARD), http(cookie=COOKIE_PAIR))
    assert session is not None
    assert session.id == SESSION_ID


@pytest.mark.anyio
async def test_a_lookup_cancelled_while_waiting_for_a_slot_starts_no_thread_and_leaks_none(
    bounded: Bounded,
) -> None:
    """The further lookup is cancelled only once the limiter counts it as waiting, so the
    cancellation is known to land on the slot wait and not anywhere else."""
    store, gate, _ = bounded
    await hold_every_slot(store, gate)

    with anyio.fail_after(GUARD), anyio.CancelScope() as caller:
        async with anyio.create_task_group() as group:
            group.start_soon(store.fetch_session_by_token, TOKEN)
            while waiting(store) == 0:
                await anyio.lowlevel.checkpoint()
            caller.cancel()

    assert caller.cancelled_caught
    assert waiting(store) == 0
    assert borrowed(store) == LIMIT
    await recovered(store, gate)
    assert gate.entries == LIMIT, "the cancelled lookup reached the database"


@pytest.mark.anyio
async def test_no_slot_leaks_across_many_hang_and_recover_cycles(bounded: Bounded) -> None:
    store, gate, engine = bounded

    for _ in range(CYCLES):
        gate.release.clear()
        await hold_every_slot(store, gate)
        assert borrowed(store) == LIMIT
        await recovered(store, gate)
        assert borrowed(store) == 0

    assert gate.entries == LIMIT * CYCLES
    assert gate.peak == LIMIT
    assert checked_out(engine) == 0
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
