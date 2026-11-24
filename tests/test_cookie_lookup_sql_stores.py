"""The lookup deadline over the shipped SQL stores: the request is released, and the store recovers.

The fakes elsewhere prove what the verifier does with a store that does not answer; these prove
it against `SqlAlchemySessionStore` and `SyncStoreAdapter` themselves, over a real (SQLite)
database whose driver has been made to stop answering - once mid-lookup, and once during the
first-use schema discovery a store runs inside its first lookup when `connect()` was never
called. In each case the request is refused within the deadline, the pooled connection comes
back, the discovery a cancellation interrupted is not left half done, and the next request is
served.

The async store runs on asyncio alone, as `test_store_lookup_warning.py` explains (aiosqlite
drives the event loop directly); the sync adapter runs on both backends. What the sync adapter
cannot do - interrupt its worker thread - is pinned here too: the DBAPI call is still blocked
after the refusal, and its connection returns only when the database answers.
"""

from __future__ import annotations

import asyncio
import logging
import pathlib
import threading
from collections.abc import AsyncIterator, Iterator
from typing import Any

import anyio
import anyio.to_thread
import pytest
from sqlalchemy import Engine, QueuePool
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.util import await_only

from fastapi_better_auth import AuthServiceUnavailable, SqlAlchemySessionStore, SyncStoreAdapter
from tests.cookies import COOKIE, http, run, sign
from tests.deadlines import DEADLINE, GUARD, OVERRUN_KIND, OVERRUN_REASON, kinds, verifier
from tests.log_hygiene import capturing
from tests.stores import SESSION_ID, TOKEN, StoreFixture

COOKIE_PAIR = f"{COOKIE}={sign(TOKEN)}"
STAGES = ("lookup", "discovery")
"""Where the driver stops answering: after `connect()`, or before it - so the deadline lands in
the store's first-use schema discovery."""


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


async def refused_then_served(
    store: SqlAlchemySessionStore | SyncStoreAdapter, release: Any
) -> AuthServiceUnavailable:
    """One request refused at the deadline, the database released, then one request served."""
    try:
        with anyio.fail_after(GUARD), pytest.raises(AuthServiceUnavailable) as caught:
            await run(verifier(store, lookup_timeout=DEADLINE), http(cookie=COOKIE_PAIR))
    finally:
        await release()
    session = await run(verifier(store, lookup_timeout=GUARD), http(cookie=COOKIE_PAIR))
    assert session is not None
    assert session.id == SESSION_ID
    return caught.value


# ---------------------------------------------------------------- SyncStoreAdapter


class BlockingDriver:
    """Makes a sync engine's driver block inside `do_execute` until released - a database that
    has stopped answering, met exactly where `SyncStoreAdapter`'s worker thread meets it.

    The wait is itself bounded by `GUARD`, so a test that forgets to release cannot wedge the
    suite; `entered` and `finished` are how a test sees the thread from outside.
    """

    def __init__(self, engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        original = engine.dialect.do_execute

        def do_execute(cursor: Any, statement: str, parameters: Any, context: Any = None) -> None:
            self.entered.set()
            try:
                self.release.wait(GUARD)
                original(cursor, statement, parameters, context)
            finally:
                self.finished.set()

        monkeypatch.setattr(engine.dialect, "do_execute", do_execute)

    async def drained(self) -> None:
        """Release the thread and wait for it, on the loop that is still open."""
        self.release.set()
        await anyio.to_thread.run_sync(self.finished.wait, GUARD)


@pytest.fixture
async def sync_fixture(tmp_path: pathlib.Path) -> AsyncIterator[StoreFixture]:
    fixture = StoreFixture(tmp_path, "sync")
    yield fixture
    await fixture.aclose()


@pytest.mark.anyio
async def test_a_hung_sync_adapter_releases_the_request_but_not_its_thread(
    sync_fixture: StoreFixture, monkeypatch: pytest.MonkeyPatch, records: list[logging.LogRecord]
) -> None:
    """`SyncStoreAdapter` hands off with `abandon_on_cancel`, so the deadline frees the request -
    but a thread cannot be interrupted: the DBAPI call is still blocked after the refusal, and
    finishes (its connection back in the pool) only when the database answers."""
    store, _ = sync_fixture()
    await store.connect()
    engine = sync_fixture.engines[-1]
    assert isinstance(engine, Engine)
    driver = BlockingDriver(engine, monkeypatch)
    try:
        with anyio.fail_after(GUARD), pytest.raises(AuthServiceUnavailable) as caught:
            await run(verifier(store, lookup_timeout=DEADLINE), http(cookie=COOKIE_PAIR))
        assert await anyio.to_thread.run_sync(driver.entered.wait, GUARD)
        assert not driver.finished.is_set(), "the worker thread was not still running"
        assert checked_out(engine) == 1, "the abandoned thread no longer held its connection"
    finally:
        await driver.drained()

    assert OVERRUN_REASON in caught.value.reason
    assert kinds(records) == [OVERRUN_KIND]
    assert checked_out(engine) == 0


@pytest.mark.anyio
async def test_a_sync_adapter_recovers_from_an_overrun(
    sync_fixture: StoreFixture,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    records: list[logging.LogRecord],
) -> None:
    """Mid-lookup, or mid-discovery with no `connect()`: refused, then served once it answers."""
    store, _ = sync_fixture()
    if stage == "lookup":
        await store.connect()
    engine = sync_fixture.engines[-1]
    assert isinstance(engine, Engine)
    driver = BlockingDriver(engine, monkeypatch)

    refusal = await refused_then_served(store, driver.drained)

    assert OVERRUN_REASON in refusal.reason
    assert kinds(records) == [OVERRUN_KIND]
    assert checked_out(engine) == 0


# ---------------------------------------------------------------- SqlAlchemySessionStore


class AwaitingDriver:
    """Makes an async engine's driver wait inside `do_execute` until released.

    SQLAlchemy runs `do_execute` in a greenlet on the event loop, and the aiosqlite adapter awaits
    its worker from there; `await_only` is that same bridge, so the wait is a real await the
    deadline can cancel - a database that stopped answering, met where asyncpg would meet it.
    """

    def __init__(self, engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch) -> None:
        self.release = asyncio.Event()
        self.entered = 0
        dialect = engine.sync_engine.dialect
        original = dialect.do_execute

        def do_execute(cursor: Any, statement: str, parameters: Any, context: Any = None) -> None:
            self.entered += 1
            if not self.release.is_set():
                await_only(asyncio.wait_for(self.release.wait(), GUARD))
            original(cursor, statement, parameters, context)

        monkeypatch.setattr(dialect, "do_execute", do_execute)

    async def released(self) -> None:
        self.release.set()


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
        """The production path: the store's await is cancelled at the deadline, its connection
        goes back to the pool rather than leaking, and a discovery the cancellation interrupted
        runs again on the next request instead of being left half done or locked."""
        store, _ = async_fixture()
        if stage == "lookup":
            await store.connect()
        engine = async_fixture.engines[-1]
        assert isinstance(engine, AsyncEngine)
        driver = AwaitingDriver(engine, monkeypatch)

        refusal = await refused_then_served(store, driver.released)

        assert driver.entered >= 2
        assert OVERRUN_REASON in refusal.reason
        assert kinds(records) == [OVERRUN_KIND]
        assert checked_out(engine.sync_engine) == 0
