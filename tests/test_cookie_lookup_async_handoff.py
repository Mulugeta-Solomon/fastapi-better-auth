"""An abandoned `SqlAlchemySessionStore` lookup is cancelled once, and winds down in order.

anyio cancels level-triggered: while a scope is cancelled, every await inside it is cancelled
again. SQLAlchemy meets a cancelled `execute` by closing the connection gracefully under
`asyncio.shield` - asyncpg sends the server a cancel request there - and a second delivery
interrupts that close, so the socket is cut and the server keeps the abandoned statement (F20).
So the store's database call runs on a task of its own, and a caller that leaves - its deadline
passed, or its client gone - cancels it exactly once and does not wait for the clean-up.

The driver here is SQLite's, made to hold each statement and to behave on cancellation the way
SQLAlchemy does (`tests/deadlines.py::AsyncDriverGate`): every case counts the cancellations that
reached the statement, and whether its shielded clean-up ran to the end or was cut short. The
deadline case moves the loop's clock past the deadline only once the statement is held
(`LeapingClock`), so the deadline lands where the case says it does on any machine.

Asyncio only: SQLAlchemy's asyncio extension, and aiosqlite under it, drive the asyncio loop
directly. `SyncStoreAdapter`'s cancellation story is `test_cookie_lookup_sql_stores.py`'s.
"""

from __future__ import annotations

import asyncio
import gc
import logging
import pathlib
from collections.abc import AsyncIterator, Iterator
from typing import Any

import anyio
import pytest
from sqlalchemy import QueuePool
from sqlalchemy.ext.asyncio import AsyncEngine

from fastapi_better_auth import AuthServiceUnavailable, SqlAlchemySessionStore
from tests.cookies import CAPTURED_TOKEN, COOKIE, http, run, sign
from tests.deadlines import (
    GUARD,
    LONG,
    OVERRUN_KIND,
    OVERRUN_REASON,
    AsyncDriverGate,
    LeapingClock,
    abandoned_once_inside,
    every_call_ended,
    kinds,
    verifier,
)
from tests.log_hygiene import LIBRARY_LOGGER, assert_no_leak, capturing
from tests.stores import SESSION_ID, TOKEN, DeniedError, DriverFault, StoreFixture

COOKIE_PAIR = f"{COOKIE}={sign(TOKEN)}"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def fixture(tmp_path: pathlib.Path) -> AsyncIterator[StoreFixture]:
    built = StoreFixture(tmp_path, "async")
    yield built
    await built.aclose()


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


@pytest.fixture
async def loop_reports() -> AsyncIterator[list[dict[str, Any]]]:
    """Everything that reaches the running loop's exception handler during the test.

    An unretrieved task exception arrives here, and asyncio's default handler would print it -
    text and all. anyio's test runner keeps its own handler on the loop, which is put back after.
    """
    loop = asyncio.get_running_loop()
    previous = loop.get_exception_handler()
    reports: list[dict[str, Any]] = []
    loop.set_exception_handler(lambda _loop, context: reports.append(context))
    try:
        yield reports
    finally:
        loop.set_exception_handler(previous)


def checked_out(engine: AsyncEngine) -> int:
    pool = engine.sync_engine.pool
    assert isinstance(pool, QueuePool)
    return pool.checkedout()


async def connected(fixture: StoreFixture) -> tuple[SqlAlchemySessionStore, AsyncEngine]:
    """A store over a fresh database, its schema already discovered."""
    store, _ = fixture()
    assert isinstance(store, SqlAlchemySessionStore)
    engine = fixture.engines[-1]
    assert isinstance(engine, AsyncEngine)
    await store.connect()
    return store, engine


async def served(store: SqlAlchemySessionStore) -> None:
    """The store answers again, under a deadline no case waits out: recovery may rediscover the
    schema on a fresh connection, which a starved machine can take longer than `GUARD` to do."""
    session = await run(verifier(store, lookup_timeout=LONG), http(cookie=COOKIE_PAIR))
    assert session is not None
    assert session.id == SESSION_ID


def lookup_through(store: SqlAlchemySessionStore) -> Any:
    """One cookie request through the verifier, with a deadline no case waits out."""
    built = verifier(store, lookup_timeout=LONG)
    return lambda: run(built, http(cookie=COOKIE_PAIR))


def outcome(gate: AsyncDriverGate) -> tuple[int, int, int]:
    """(cancellations that reached the statement, clean-ups that ended, clean-ups cut short)."""
    return gate.cancellations, gate.cleaned_up, gate.interrupted


async def refused_past_deadline(
    store: SqlAlchemySessionStore, gate: AsyncDriverGate, clock: LeapingClock
) -> AuthServiceUnavailable:
    """One request, whose deadline the clock passes once its statement is held."""
    refusals: list[AuthServiceUnavailable] = []
    finished = anyio.Event()

    async def request() -> None:
        try:
            await run(verifier(store, lookup_timeout=LONG), http(cookie=COOKIE_PAIR))
        except AuthServiceUnavailable as exc:
            refusals.append(exc)
        finally:
            finished.set()

    async with anyio.create_task_group() as group:
        group.start_soon(request)
        with anyio.fail_after(GUARD):
            await gate.arrived.wait()
        # The guard above is exited before the leap: it would expire with the deadline.
        clock.leap(LONG)
        with anyio.fail_after(GUARD):
            await finished.wait()
    assert len(refusals) == 1, "the request was not refused at its deadline"
    return refusals[0]


@pytest.mark.anyio
async def test_a_lookup_past_its_deadline_cancels_the_database_call_once(
    fixture: StoreFixture, monkeypatch: pytest.MonkeyPatch, records: list[logging.LogRecord]
) -> None:
    """The verifier's own deadline: the caller is refused at once, while the statement it left
    behind has received one cancellation and is still in its clean-up - which then runs to the
    end rather than being cut short by a second delivery."""
    store, engine = await connected(fixture)
    gate = AsyncDriverGate(engine, monkeypatch)
    clock = LeapingClock(monkeypatch)
    try:
        refusal = await refused_past_deadline(store, gate, clock)
        assert OVERRUN_REASON in refusal.reason
        assert outcome(gate) == (1, 0, 0), "the caller waited for the clean-up, or cut it short"
    finally:
        gate.open()

    await every_call_ended(store)
    assert outcome(gate) == (1, 1, 0)
    assert kinds(records) == [OVERRUN_KIND]
    assert checked_out(engine) == 0
    await served(store)


@pytest.mark.anyio
async def test_a_cancelled_caller_cancels_the_database_call_once(
    fixture: StoreFixture, monkeypatch: pytest.MonkeyPatch, records: list[logging.LogRecord]
) -> None:
    """A client gone, no deadline involved: the same path, and the cancellation still reaches
    the caller as a cancellation rather than as a refusal."""
    store, engine = await connected(fixture)
    gate = AsyncDriverGate(engine, monkeypatch)
    try:
        await abandoned_once_inside(gate.arrived.wait, lookup_through(store))
        assert outcome(gate) == (1, 0, 0), "the caller waited for the clean-up, or cut it short"
    finally:
        gate.open()

    await every_call_ended(store)
    assert outcome(gate) == (1, 1, 0)
    assert kinds(records) == []
    assert checked_out(engine) == 0
    await served(store)


@pytest.mark.anyio
async def test_a_late_error_from_an_abandoned_call_is_dropped_unread(
    fixture: StoreFixture,
    monkeypatch: pytest.MonkeyPatch,
    records: list[logging.LogRecord],
    loop_reports: list[dict[str, Any]],
) -> None:
    """An abandoned call that ends with a driver error has nobody to answer. Its error's text
    embeds the token, so it may not reach the loop's exception handler or a log line, and it is
    not an outage either: the store's latch is left as it was, so the next real failure of the
    same kind is still reported."""
    store, engine = await connected(fixture)
    fault = DriverFault(engine, monkeypatch)
    gate = AsyncDriverGate(engine, monkeypatch)
    gate.late_error = DeniedError
    try:
        await abandoned_once_inside(gate.arrived.wait, lookup_through(store))
    finally:
        gate.open()
    await every_call_ended(store)
    gc.collect()

    assert gate.late_raised == 1, "the abandoned call did not end with its late error"
    assert loop_reports == []
    assert [record for record in records if record.levelno >= logging.WARNING] == []
    assert [record for record in records if record.name == LIBRARY_LOGGER] == []
    # Every logger, aiosqlite's DEBUG lines included: the held statement never reached the driver,
    # so a token anywhere here came from the late error.
    assert_no_leak(records, TOKEN, CAPTURED_TOKEN)

    fault.error = DeniedError
    with pytest.raises(AuthServiceUnavailable):
        await store.fetch_session_by_token(TOKEN)
    assert kinds(records) == ["DeniedError"]


@pytest.mark.anyio
async def test_a_call_its_caller_waits_for_answers_as_it_always_did(
    fixture: StoreFixture, monkeypatch: pytest.MonkeyPatch, records: list[logging.LogRecord]
) -> None:
    """Nobody cancelled: the record comes back, and a driver error is the uniform refusal with
    one WARNING per kind, chained to nothing that could carry the token (A1)."""
    store, engine = await connected(fixture)
    fault = DriverFault(engine, monkeypatch)
    record = await store.fetch_session_by_token(TOKEN)
    assert record is not None
    assert record.id == SESSION_ID

    fault.error = DeniedError
    for _ in range(3):
        with pytest.raises(AuthServiceUnavailable) as caught:
            await store.fetch_session_by_token(TOKEN)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None
        assert caught.value.__suppress_context__

    assert kinds(records) == ["DeniedError"]
    # This library's lines only: aiosqlite logs every statement's parameters at DEBUG itself.
    assert_no_leak([record for record in records if record.name == LIBRARY_LOGGER], TOKEN)
    assert checked_out(engine) == 0


@pytest.mark.anyio
async def test_a_cancelled_discovery_winds_down_and_runs_again(
    fixture: StoreFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Schema discovery takes the same path: `connect()` abandoned mid-discovery cancels the
    reflection once, and leaves the store to discover afresh on its next call."""
    store, _ = fixture()
    assert isinstance(store, SqlAlchemySessionStore)
    engine = fixture.engines[-1]
    assert isinstance(engine, AsyncEngine)
    gate = AsyncDriverGate(engine, monkeypatch)
    try:
        await abandoned_once_inside(gate.arrived.wait, store.connect)
        assert outcome(gate) == (1, 0, 0), "the caller waited for the clean-up, or cut it short"
    finally:
        gate.open()

    await every_call_ended(store)
    assert outcome(gate) == (1, 1, 0)
    await store.connect()
    await served(store)
    assert checked_out(engine) == 0
