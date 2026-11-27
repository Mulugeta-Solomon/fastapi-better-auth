"""What the `SyncStoreAdapter(statement_timeout=...)` live modules share, on either anyio backend.

The WP-56 modules observe the server and hold their locks through asyncpg, which drives the asyncio
loop directly and cannot run on trio. Everything here is synchronous instead, through the case's
own driver (`tests.stores.SYNC_DRIVERS`), and every call that waits on the server runs on a worker
thread (`in_thread`), so the event loop of either backend stays free while it waits.

Imports `tests.stores`, which names post-0.1.0 exports: a live module imports this only inside its
published-wheel guard.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypeVar

import anyio
import anyio.to_thread
from sqlalchemy import Connection, Engine, QueuePool, event, text

from fastapi_better_auth import (
    AuthServiceUnavailable,
    CookieVerifier,
    SessionError,
    SyncStoreAdapter,
)
from tests.cookies import COOKIE, http, run, sign
from tests.deadlines import outage_lines
from tests.stores import sync_postgres_engine

from .conftest import POSTGRES_URL

T = TypeVar("T")

QUERY_CANCELED = "57014"
FORGED_TOKEN = "a-token-that-names-no-session"
FORGED = f"{COOKIE}={sign(FORGED_TOKEN)}"

QUEUED = """
select count(*) from pg_stat_activity
where application_name = :name and state = 'active' and wait_event_type = 'Lock'
"""
IN_A_TRANSACTION = """
select count(*) from pg_stat_activity
where application_name = :name and state = 'active' and wait_event_type = 'Lock'
and xact_start < query_start
"""
"""A queued statement inside a transaction that began before it. Under `AUTOCOMMIT` a statement
is its own transaction, and `xact_start` equals `query_start`."""
LOCK_HELD = """
select count(*) from pg_locks
where relation = cast(:table as regclass) and mode = 'AccessExclusiveLock' and granted
"""
SERVER_VALUE = "select current_setting('statement_timeout')"


async def in_thread(call: Callable[..., T], *args: Any) -> T:
    """Run a blocking call off the event loop, on either backend."""
    return await anyio.to_thread.run_sync(call, *args)


def harness_engine(driver: str, **options: Any) -> Engine:
    """An engine on the harness database through `driver`; the case skips without it."""
    return sync_postgres_engine(driver, POSTGRES_URL, **options)


def count(observer: Engine, query: str, params: dict[str, str]) -> int:
    """One `count(*)` the server answers, on a connection of its own."""
    with observer.connect() as connection:
        return int(connection.scalar(text(query), params) or 0)


def server_value(observer: Engine) -> str:
    """The server's own `statement_timeout` for the harness role, as a fresh connection sees it."""
    with observer.connect() as connection:
        return str(connection.scalar(text(SERVER_VALUE)))


class Lock:
    """A second client holding `ACCESS EXCLUSIVE` on a table copy until released.

    Its connection is used from worker threads one call at a time, never at once."""

    def __init__(self, blocker: Engine, table: str) -> None:
        self._blocker = blocker
        self.table = table
        self._connection: Connection | None = None

    def take(self) -> None:
        connection = self._blocker.connect()
        connection.execute(text(f"LOCK TABLE {self.table} IN ACCESS EXCLUSIVE MODE"))
        self._connection = connection

    def release(self) -> None:
        connection, self._connection = self._connection, None
        if connection is not None:
            connection.rollback()
            connection.close()


async def one_lookup(built: CookieVerifier) -> str:
    """How one request's lookup ended: the server's refusal is a store error, the client's a
    deadline, and a lookup that reached the database and found nothing is `SessionRevoked`."""
    try:
        await run(built, http(cookie=FORGED))
    except AuthServiceUnavailable as exc:
        return "deadline" if "did not answer within" in exc.reason else "store-error"
    except SessionError as exc:
        return type(exc).__name__
    return "accepted"


def outages(records: list[logging.LogRecord]) -> list[tuple[object, object]]:
    """The (driver error, SQLSTATE) each store-outage WARNING names, in order."""
    found: list[tuple[object, object]] = []
    for record in outage_lines(records):
        driver, sqlstate, *_ = tuple(record.args or ())
        found.append((driver, sqlstate))
    return found


def held(store: SyncStoreAdapter, engine: Engine) -> tuple[int, int]:
    """The adapter's limiter slots in use, and the engine's connections checked out."""
    limiter = store._get_limiter()  # pyright: ignore[reportPrivateUsage]
    pool = engine.pool
    assert isinstance(pool, QueuePool)
    return int(limiter.borrowed_tokens), pool.checkedout()


def driver_error(error: BaseException) -> tuple[str, object]:
    """The driver's error class under SQLAlchemy's, and the SQLSTATE where that driver keeps it:
    `sqlstate` on psycopg (3), `pgcode` on psycopg2."""
    orig = getattr(error, "orig", None)
    code = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
    return type(orig).__name__, code


POLL = 0.02
"""How often `queued_while` asks the server; each ask is a round trip on a worker thread."""


@dataclass(frozen=True)
class Watched:
    """A call made while the server was watched: how it ended, when it started (monotonic), how
    long it took, and when the server first showed its statement queued on a lock inside a
    transaction (`None` if it never did)."""

    outcome: object
    started: float
    took: float
    queued_at: float | None


async def queued_while(observer: Engine, name: str, call: Callable[[], Awaitable[T]]) -> Watched:
    """Run `call` while polling the server for its statement queued on a lock in a transaction.

    The phase is read from the server, not assumed: a case asserts `queued_at` came before the
    call ended, so a deadline or a bound is known to have landed on a statement in that phase. An
    exception `call` raises is the outcome, for the case to assert on."""
    started = time.monotonic()
    seen: list[float] = []

    async def watch() -> None:
        while not seen:
            if await in_thread(count, observer, IN_A_TRANSACTION, {"name": name}) >= 1:
                seen.append(time.monotonic() - started)
            else:
                await anyio.sleep(POLL)

    outcome: object = None
    took = 0.0
    async with anyio.create_task_group() as group:
        group.start_soon(watch)
        try:
            outcome = await call()
        except Exception as exc:  # noqa: BLE001 - the case asserts on it
            outcome = exc
        took = time.monotonic() - started
        group.cancel_scope.cancel()
    return Watched(outcome, started, took, seen[0] if seen else None)


async def back_within(
    store: SyncStoreAdapter, engine: Engine, since: float, window: float
) -> float | None:
    """Seconds after `since` at which every slot and every pooled connection were back, polled
    until `window` has passed since `since`; `None` if they were not back by then."""
    while time.monotonic() - since < window:
        if held(store, engine) == (0, 0):
            return time.monotonic() - since
        await anyio.sleep(POLL)
    return None


def pooled_values(engine: Engine, size: int) -> list[str]:
    """`statement_timeout` as each of `size` pooled connections reports it, all checked out at
    once, so every connection the pool holds is read."""
    connections = [engine.connect() for _ in range(size)]
    try:
        return [str(connection.scalar(text(SERVER_VALUE))) for connection in connections]
    finally:
        for connection in connections:
            connection.close()


def mentions(records: list[logging.LogRecord], secret: str) -> list[str]:
    """Every captured record whose rendered message, or whose exception text, carries `secret`."""
    found: list[str] = []
    for record in records:
        rendered = record.getMessage() + (str(record.exc_info[1]) if record.exc_info else "")
        if secret in rendered:
            found.append(rendered)
    return found


class Opened:
    """Counts the connections an engine's pool opens from now on."""

    def __init__(self, engine: Engine) -> None:
        self.count = 0
        event.listen(engine, "connect", self._opened)

    def _opened(self, *_: object) -> None:
        self.count += 1
