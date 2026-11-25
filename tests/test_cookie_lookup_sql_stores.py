"""The lookup deadline over the shipped SQL stores: the request is released, and the store recovers.

The fakes elsewhere prove what the verifier does with a store that does not answer; these prove
it against `SqlAlchemySessionStore` and `SyncStoreAdapter` themselves, over a real (SQLite)
database whose driver has been made to stop answering - once mid-lookup, and once during the
first-use schema discovery a store runs inside its first lookup when `connect()` was never
called. In each case the caller is released, the pooled connection comes back, the discovery a
cancellation interrupted is not left half done, and the next request is served.

Where the case depends on *where* the cancellation lands, the lookup is abandoned by an explicit
cancel only once the driver has seen it arrive. That is an event, not a 20 ms timer that a busy
machine can fire before the worker thread has even started. The one deadline-driven case asserts
only what holds wherever the deadline lands.

The async store runs on asyncio alone, as `test_store_lookup_warning.py` explains (aiosqlite
drives the event loop directly); the sync adapter runs on both backends. What the sync adapter
cannot do - interrupt its worker thread - is pinned here too: the DBAPI call is still blocked
after its caller has gone, and its connection returns only when the database answers.
"""

from __future__ import annotations

import asyncio
import logging
import pathlib
import time
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any

import anyio
import pytest
from sqlalchemy import Engine, QueuePool, event
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.util import await_only

from fastapi_better_auth import AuthServiceUnavailable, SqlAlchemySessionStore, SyncStoreAdapter
from tests.cookies import COOKIE, http, run, sign
from tests.deadlines import (
    DEADLINE,
    GUARD,
    LONG,
    OVERRUN_KIND,
    OVERRUN_REASON,
    WEDGE_BACKSTOP,
    DriverGate,
    abandoned_once_inside,
    every_call_ended,
    every_slot_returned,
    kinds,
    verifier,
)
from tests.log_hygiene import capturing
from tests.stores import SESSION_ID, TOKEN, StoreFixture

COOKIE_PAIR = f"{COOKIE}={sign(TOKEN)}"
CLEANUP_DELAY = 0.05
"""Seconds a sync connection takes to go back to its pool, on the worker thread. It is there so
that a drain which mistook "the statement returned" for "the worker is done" fails every time.
It cannot fail a correct test: everything after it waits on an event bounded by `GUARD`."""
STAGES = ("lookup", "discovery")
"""Where the driver stops answering: after `connect()`, or before it - so the cancellation lands
in the store's first-use schema discovery."""


def checked_out(engine: Engine) -> int:
    """Connections the engine's pool has handed out and not had back. A file-backed SQLite engine
    pools with a `QueuePool` (`AsyncAdaptedQueuePool` for aiosqlite), which can say."""
    pool = engine.pool
    assert isinstance(pool, QueuePool)
    return pool.checkedout()


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


@pytest.fixture(params=STAGES)
def stage(request: pytest.FixtureRequest) -> str:
    value = request.param
    assert isinstance(value, str)
    return value


async def served(store: SqlAlchemySessionStore | SyncStoreAdapter) -> None:
    session = await run(verifier(store, lookup_timeout=GUARD), http(cookie=COOKIE_PAIR))
    assert session is not None
    assert session.id == SESSION_ID


def lookup_through(store: SqlAlchemySessionStore | SyncStoreAdapter) -> Callable[[], Any]:
    """One cookie request through the verifier, with a deadline no case waits out."""
    built = verifier(store, lookup_timeout=LONG)
    return lambda: run(built, http(cookie=COOKIE_PAIR))


# ---------------------------------------------------------------- SyncStoreAdapter


@pytest.fixture
async def sync_fixture(tmp_path: pathlib.Path) -> AsyncIterator[StoreFixture]:
    fixture = StoreFixture(tmp_path, "sync")
    yield fixture
    await fixture.aclose()


async def gated(
    fixture: StoreFixture, monkeypatch: pytest.MonkeyPatch, *, connect: bool
) -> tuple[SyncStoreAdapter, Engine, DriverGate]:
    """A sync store over a fresh database, its engine with a slow check-in, and the gate."""
    store, _ = fixture()
    assert isinstance(store, SyncStoreAdapter)
    engine = fixture.engines[-1]
    assert isinstance(engine, Engine)
    if connect:
        await store.connect()
    event.listen(engine, "checkin", lambda *_: time.sleep(CLEANUP_DELAY))
    return store, engine, DriverGate(engine, monkeypatch)


async def drained(store: SyncStoreAdapter, gate: DriverGate) -> None:
    """Let the database answer and wait until every worker thread has ended (`every_slot_returned`
    explains why that is what the slots mean), or fail the test."""
    gate.release.set()
    await every_slot_returned(store)


@pytest.mark.anyio
async def test_a_hung_sync_adapter_releases_its_caller_but_not_its_thread(
    sync_fixture: StoreFixture, monkeypatch: pytest.MonkeyPatch, records: list[logging.LogRecord]
) -> None:
    """`SyncStoreAdapter` hands off with `abandon_on_cancel`, so a cancellation frees the caller -
    but a thread cannot be interrupted: the DBAPI call is still blocked after its caller has gone,
    and its connection comes back only when the database answers."""
    store, engine, gate = await gated(sync_fixture, monkeypatch, connect=True)
    try:
        await abandoned_once_inside(lambda: gate.entered(1), lookup_through(store))
        assert gate.inside == 1, "the worker thread was not still blocked in the database"
        assert checked_out(engine) == 1, "the abandoned thread no longer held its connection"
    finally:
        await drained(store, gate)

    assert checked_out(engine) == 0
    assert kinds(records) == []
    await served(store)


@pytest.mark.anyio
async def test_a_sync_adapter_recovers_from_an_abandoned_lookup(
    sync_fixture: StoreFixture, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    """Abandoned mid-lookup, or mid-discovery with no `connect()`: once the database answers, the
    connection is back and the next request is served - discovery included, rerun rather than
    left half done."""
    store, engine, gate = await gated(sync_fixture, monkeypatch, connect=stage == "lookup")
    try:
        await abandoned_once_inside(lambda: gate.entered(1), lookup_through(store))
    finally:
        await drained(store, gate)

    assert checked_out(engine) == 0
    await served(store)


@pytest.mark.anyio
async def test_a_sync_adapter_overrun_is_refused_and_the_store_recovers(
    sync_fixture: StoreFixture, monkeypatch: pytest.MonkeyPatch, records: list[logging.LogRecord]
) -> None:
    """The verifier's own deadline over the real adapter. It may land before the worker thread has
    started or while it is blocked in the database; every assertion here holds either way."""
    store, engine, gate = await gated(sync_fixture, monkeypatch, connect=True)
    try:
        with anyio.fail_after(GUARD), pytest.raises(AuthServiceUnavailable) as caught:
            await run(verifier(store, lookup_timeout=DEADLINE), http(cookie=COOKIE_PAIR))
    finally:
        await drained(store, gate)

    assert OVERRUN_REASON in caught.value.reason
    assert kinds(records) == [OVERRUN_KIND]
    assert checked_out(engine) == 0
    await served(store)


# ---------------------------------------------------------------- SqlAlchemySessionStore


class AwaitingDriver:
    """Makes an async engine's driver wait inside `do_execute` until released.

    SQLAlchemy runs `do_execute` in a greenlet on the event loop, and the aiosqlite adapter awaits
    its worker from there; `await_only` is that same bridge, so the wait is a real await a
    cancellation can land on - a database that stopped answering, met where asyncpg would meet it.
    `reached` is set the first time a statement arrives.
    """

    def __init__(self, engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch) -> None:
        self.release = asyncio.Event()
        self.reached = asyncio.Event()
        dialect = engine.sync_engine.dialect
        original = dialect.do_execute

        def do_execute(cursor: Any, statement: str, parameters: Any, context: Any = None) -> None:
            self.reached.set()
            if not self.release.is_set():
                await_only(asyncio.wait_for(self.release.wait(), WEDGE_BACKSTOP))
            original(cursor, statement, parameters, context)

        monkeypatch.setattr(dialect, "do_execute", do_execute)


class TestAsyncStore:
    @pytest.fixture
    def anyio_backend(self) -> str:
        return "asyncio"

    @pytest.fixture
    async def async_fixture(self, tmp_path: pathlib.Path) -> AsyncIterator[StoreFixture]:
        fixture = StoreFixture(tmp_path, "async")
        yield fixture
        await fixture.aclose()

    @pytest.mark.anyio
    async def test_an_async_store_is_cancelled_cleanly_and_recovers(
        self,
        async_fixture: StoreFixture,
        monkeypatch: pytest.MonkeyPatch,
        stage: str,
        records: list[logging.LogRecord],
    ) -> None:
        """The production path: the store's await is cancelled inside the driver, its connection
        goes back to the pool rather than leaking, and a discovery the cancellation interrupted
        runs again on the next request instead of being left half done or locked.

        The abandoned call winds down on a task of its own after its caller has gone, so the pool
        is read only once every such call has ended (`every_call_ended`)."""
        store, _ = async_fixture()
        assert isinstance(store, SqlAlchemySessionStore)
        if stage == "lookup":
            await store.connect()
        engine = async_fixture.engines[-1]
        assert isinstance(engine, AsyncEngine)
        driver = AwaitingDriver(engine, monkeypatch)

        await abandoned_once_inside(driver.reached.wait, lookup_through(store))
        driver.release.set()
        await every_call_ended(store)

        await served(store)
        assert kinds(records) == []
        assert checked_out(engine.sync_engine) == 0
