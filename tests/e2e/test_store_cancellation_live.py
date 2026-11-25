"""Lookups abandoned at their deadline leave nothing running on the live Postgres (F20).

The unit lane proves, against a driver that only behaves like SQLAlchemy's, that an abandoned
lookup's database call is cancelled exactly once. This proves what that is for, on asyncpg and a
real server: the cancel request reaches Postgres, so the abandoned statement stops there and its
backend goes away, rather than waiting on the server - holding a connection slot and whatever lock
it queued for - while the client-side pool looks perfectly healthy.

The statement is made to hang the honest way: a second connection holds an `ACCESS EXCLUSIVE`
lock on the session table, so every lookup queues behind it. The tables are copies in a schema of
this module's own, so the auth server and every other lane keep reading theirs. Each wave sends
more lookups than the pool has connections; after each one, the store's backends waiting on that
lock must go back to none and the store's connections must stay within the pool. The waits poll
for the condition with a generous backstop instead of sleeping for a guess.

Asyncio only: `asyncpg` drives the event loop directly, as in every other store-backed lane.
"""

from __future__ import annotations

import asyncio
import inspect
import secrets
import time
from collections.abc import AsyncIterator
from typing import Any, NamedTuple

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from fastapi_better_auth import AuthServiceUnavailable, SessionError
from tests.cookies import COOKIE, http, run, sign
from tests.deadlines import every_call_ended, verifier

from .conftest import POSTGRES_URL

try:
    from fastapi_better_auth import CookieVerifier, SqlAlchemySessionStore
except ImportError:
    pytest.skip(
        "this build of fastapi-better-auth-bridge publishes no session stores",
        allow_module_level=True,
    )

if "lookup_timeout" not in inspect.signature(CookieVerifier.__init__).parameters:
    pytest.skip(
        "this build of fastapi-better-auth-bridge predates CookieVerifier(lookup_timeout=...)",
        allow_module_level=True,
    )

pytestmark = pytest.mark.e2e

POOL_SIZE = 2
MAX_OVERFLOW = 1
CEILING = POOL_SIZE + MAX_OVERFLOW
LOOKUP_TIMEOUT = 1.0
"""Long enough that a lookup reaches the database and queues on the lock well inside it."""
WAVES = 5
PER_WAVE = 2 * CEILING
"""More lookups than the pool has connections: the rest wait for one and are refused too."""
SETTLE_BACKSTOP = 10.0
"""How long a wave's backends may take to go away before the wave counts as leaked. Healthy
clean-up takes tens of milliseconds; this only ever runs out on a leak."""
POLL = 0.05

FORGED = f"{COOKIE}={sign('a-token-that-names-no-session')}"

WAITING_ON_THE_LOCK = """
select count(*) from pg_stat_activity
where application_name = :name and wait_event_type = 'Lock'
"""
CONNECTED = "select count(*) from pg_stat_activity where application_name = :name"


class Backends(NamedTuple):
    """What the server holds for the store: backends queued on the lock, and all of them."""

    waiting: int
    connected: int


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def observer() -> AsyncIterator[AsyncEngine]:
    built = create_async_engine(POSTGRES_URL)
    yield built
    await built.dispose()


@pytest.fixture
async def schema(harness: str, observer: AsyncEngine) -> AsyncIterator[str]:
    """Empty copies of the two tables in a schema nobody else reads, dropped however it ends."""
    name = f"f20_{secrets.token_hex(6)}"
    async with observer.begin() as connection:
        await connection.execute(text(f"CREATE SCHEMA {name}"))
        for table in ('"user"', "session"):
            await connection.execute(
                text(f"CREATE TABLE {name}.{table} (LIKE public.{table} INCLUDING ALL)")
            )
    try:
        yield name
    finally:
        async with observer.begin() as connection:
            await connection.execute(text(f"DROP SCHEMA {name} CASCADE"))


@pytest.fixture
def application_name() -> str:
    """How this test's store connections are told apart from everyone else's on the server."""
    return f"f20-store-{secrets.token_hex(4)}"


@pytest.fixture
async def engine(application_name: str) -> AsyncIterator[AsyncEngine]:
    built = create_async_engine(
        POSTGRES_URL,
        pool_size=POOL_SIZE,
        max_overflow=MAX_OVERFLOW,
        connect_args={"server_settings": {"application_name": application_name}},
    )
    yield built
    await built.dispose()


@pytest.fixture
async def loop_reports() -> AsyncIterator[list[dict[str, Any]]]:
    """Everything that reaches the running loop's exception handler during the test."""
    loop = asyncio.get_running_loop()
    previous = loop.get_exception_handler()
    reports: list[dict[str, Any]] = []
    loop.set_exception_handler(lambda _loop, context: reports.append(context))
    try:
        yield reports
    finally:
        loop.set_exception_handler(previous)


@pytest.fixture
async def blocker() -> AsyncIterator[AsyncEngine]:
    """The second client, which holds the lock every lookup queues behind."""
    built = create_async_engine(POSTGRES_URL)
    yield built
    await built.dispose()


async def backends(observer: AsyncEngine, name: str) -> Backends:
    async with observer.connect() as connection:
        waiting = await connection.scalar(text(WAITING_ON_THE_LOCK), {"name": name})
        connected = await connection.scalar(text(CONNECTED), {"name": name})
    return Backends(int(waiting or 0), int(connected or 0))


async def settled(observer: AsyncEngine, name: str) -> Backends:
    """Poll until no store backend waits on the lock and the rest fit the pool, or the backstop
    runs out; either way, the last reading."""
    give_up = time.monotonic() + SETTLE_BACKSTOP
    while True:
        seen = await backends(observer, name)
        if (seen.waiting == 0 and seen.connected <= CEILING) or time.monotonic() > give_up:
            return seen
        await asyncio.sleep(POLL)


async def one_lookup(built: Any) -> str:
    try:
        await run(built, http(cookie=FORGED))
    except AuthServiceUnavailable as exc:
        return "deadline" if "did not answer within" in exc.reason else "store-error"
    except SessionError as exc:
        return type(exc).__name__
    return "accepted"


@pytest.mark.anyio
async def test_lookups_abandoned_at_their_deadline_leave_no_backend_behind(
    engine: AsyncEngine,
    observer: AsyncEngine,
    blocker: AsyncEngine,
    schema: str,
    application_name: str,
    loop_reports: list[dict[str, Any]],
) -> None:
    store = SqlAlchemySessionStore(engine=engine, schema=schema)
    await store.connect()
    built = verifier(store, lookup_timeout=LOOKUP_TIMEOUT)
    assert await one_lookup(built) == "SessionRevoked"
    waves: list[Backends] = []

    async with blocker.connect() as lock:
        await lock.execute(text(f"LOCK TABLE {schema}.session IN ACCESS EXCLUSIVE MODE"))
        for _ in range(WAVES):
            outcomes = await asyncio.gather(*(one_lookup(built) for _ in range(PER_WAVE)))
            assert outcomes == ["deadline"] * PER_WAVE
            waves.append(await settled(observer, application_name))
        await lock.rollback()
    started = time.monotonic()
    answer = await one_lookup(built)
    recovered_in = time.monotonic() - started

    assert [wave.waiting for wave in waves] == [0] * WAVES, f"backends left behind: {waves}"
    assert max(wave.connected for wave in waves) <= CEILING, f"connections leaked: {waves}"
    assert answer == "SessionRevoked", "the store did not answer once the lock was released"
    assert recovered_in < LOOKUP_TIMEOUT
    await every_call_ended(store)
    assert loop_reports == []
