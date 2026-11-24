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
from tests.cookies import COOKIE, http, run, sign
from tests.deadlines import DEADLINE, GUARD, OVERRUN_KIND, kinds, verifier
from tests.log_hygiene import capturing
from tests.stores import TOKEN, StoreFixture

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


async def every_slot_returned(store: SyncStoreAdapter) -> None:
    """Wait until every slot is back - which, with slots held for a thread's whole life, is every
    worker thread having ended - or fail saying so. Taking all the slots is the proof: a thread
    still running would hold one, and the acquire would wait for it."""
    limiter = store._get_limiter()  # pyright: ignore[reportPrivateUsage]
    probes = [object() for _ in range(int(limiter.total_tokens))]
    try:
        with anyio.fail_after(GUARD):
            for probe in probes:
                await limiter.acquire_on_behalf_of(probe)
    except TimeoutError:
        pytest.fail(
            f"{limiter.borrowed_tokens} adapter slot(s) still held {GUARD}s after the database"
            " answered: a worker thread did not end, or a slot leaked"
        )
    finally:
        for probe in probes:
            if probe in limiter.statistics().borrowers:
                limiter.release_on_behalf_of(probe)


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
