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

The other two cases are a server that stops answering altogether, which no cancel request
reaches: a relay between the store and Postgres stops forwarding both ways (`relay.py`). At the
shipped bound, every abandoned call must have ended within it; on the lockfile's asyncpg the
driver's own two-second close timeout ends them, so that case claims the bound and no more. The
backstop case makes the driver's close unbounded, as asyncpg 0.30.0's is against a silent peer,
and proves by order that the backstop is what ends the calls. Both then require a clean pool and
a store that answers as soon as the relay forwards again.

Asyncio only: `asyncpg` drives the event loop directly, as in every other store-backed lane.
"""

from __future__ import annotations

import asyncio
import gc
import inspect
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any, NamedTuple

import anyio
import pytest
from sqlalchemy import QueuePool, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from fastapi_better_auth import AuthServiceUnavailable, SessionError

from .conftest import POSTGRES_URL
from .relay import StallingRelay

try:
    # The test helpers import post-0.1.0 names too, so they belong under the guard as well: the
    # canary's published-wheel leg installs the last release, and must skip here, not raise.
    from fastapi_better_auth import CookieVerifier, SqlAlchemySessionStore
    from fastapi_better_auth._internal.stores.task_handoff import WIND_DOWN_SECONDS, TaskHandoff
    from tests.cookies import COOKIE, http, run, sign
    from tests.deadlines import GUARD, LONG, LeapingClock, every_call_ended, verifier
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
# Lookups outside the waves - before them, and to prove recovery - run under `LONG`. Every
# connection a wave touched was closed, so recovery opens new ones inside the lookup's deadline,
# and on a starved machine a 2 s deadline cancelled each attempt before it connected (the
# constraint the store's docstring warns operators about). Recovery is the property, not speed.

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
    steady = verifier(store, lookup_timeout=LONG)
    assert await one_lookup(steady) == "SessionRevoked"
    waves: list[Backends] = []

    async with blocker.connect() as lock:
        await lock.execute(text(f"LOCK TABLE {schema}.session IN ACCESS EXCLUSIVE MODE"))
        for _ in range(WAVES):
            outcomes = await asyncio.gather(*(one_lookup(built) for _ in range(PER_WAVE)))
            assert outcomes == ["deadline"] * PER_WAVE
            waves.append(await settled(observer, application_name))
        await lock.rollback()
    started = time.monotonic()
    answer = await one_lookup(steady)
    recovered_in = time.monotonic() - started

    assert [wave.waiting for wave in waves] == [0] * WAVES, f"backends left behind: {waves}"
    assert max(wave.connected for wave in waves) <= CEILING, f"connections leaked: {waves}"
    assert answer == "SessionRevoked", "the store did not answer once the lock was released"
    assert recovered_in < SETTLE_BACKSTOP
    await every_call_ended(store)
    gc.collect()  # a driver future dropped unread is reported when it is collected
    assert loop_reports == []


# ---------------------------------------------------------------- a server that stopped answering

STALL_LOOKUP_TIMEOUT = 0.5
"""Long enough for a lookup through the forwarding relay; every stalled one runs into it."""
STALL_WAVES = 3
RECOVERY_LOOKUPS = 3


@pytest.fixture
async def relay(harness: str) -> AsyncIterator[StallingRelay]:
    target = make_url(POSTGRES_URL)
    built = StallingRelay(target.host or "127.0.0.1", target.port or 5432)
    await built.start()
    try:
        yield built
    finally:
        built.resume()
        await built.close()


@pytest.fixture
async def relayed_engine(relay: StallingRelay) -> AsyncIterator[AsyncEngine]:
    built = create_async_engine(
        make_url(POSTGRES_URL).set(host="127.0.0.1", port=relay.port),
        pool_size=POOL_SIZE,
        max_overflow=MAX_OVERFLOW,
    )
    yield built
    await built.dispose()


def checked_out(engine: AsyncEngine) -> int:
    pool = engine.sync_engine.pool
    assert isinstance(pool, QueuePool)
    return pool.checkedout()


def unbounded_close(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make asyncpg's graceful close wait for as long as the server is silent.

    SQLAlchemy asks for `close(timeout=2)`, and asyncpg 0.32 honours it on a loop timer. asyncpg
    0.30.0 does not, against a stalled peer: measured on the harness, its close waited for exactly
    as long as the server was paused. This gives the lockfile's driver that behaviour through its
    public API, so that nothing but the store's backstop can end the clean-up.
    """
    import asyncpg  # pyright: ignore[reportMissingTypeStubs] - asyncpg ships no stubs

    # Read off the class's namespace: asyncpg ships no annotation for `timeout`.
    original: Callable[..., Awaitable[None]] = vars(asyncpg.Connection)["close"]

    async def close(self: Any, *, timeout: float | None = None) -> None:
        await original(self, timeout=None)

    monkeypatch.setattr(asyncpg.Connection, "close", close)


async def stalled_waves(relay: StallingRelay, built: CookieVerifier) -> None:
    """Stall the relay and run every wave into its deadline. The caller resumes the relay."""
    relay.stall()
    for _ in range(STALL_WAVES):
        outcomes = await asyncio.gather(*(one_lookup(built) for _ in range(PER_WAVE)))
        assert outcomes == ["deadline"] * PER_WAVE


async def recovered(store: SqlAlchemySessionStore, engine: AsyncEngine) -> None:
    """The store answers once the relay forwards again, and leaves nothing checked out."""
    steady = verifier(store, lookup_timeout=LONG)
    answers = [await one_lookup(steady) for _ in range(RECOVERY_LOOKUPS)]
    await every_call_ended(store)
    assert answers == ["SessionRevoked"] * RECOVERY_LOOKUPS, answers
    assert checked_out(engine) == 0


@pytest.mark.anyio
async def test_at_the_shipped_bound_calls_abandoned_against_a_stalled_server_end_within_it(
    relay: StallingRelay, relayed_engine: AsyncEngine, loop_reports: list[dict[str, Any]]
) -> None:
    """The store as shipped: every abandoned call has ended within one wind-down bound (plus a
    guard) of the last wave. On the lockfile's asyncpg the driver's own two-second close timeout
    is what ends them; this case claims only the bound, which holds whoever ends them."""
    store = SqlAlchemySessionStore(engine=relayed_engine)
    await store.connect()
    assert await one_lookup(verifier(store, lookup_timeout=LONG)) == "SessionRevoked"
    try:
        await stalled_waves(relay, verifier(store, lookup_timeout=STALL_LOOKUP_TIMEOUT))
        with anyio.fail_after(WIND_DOWN_SECONDS + GUARD):
            await store._handoff.settled()  # pyright: ignore[reportPrivateUsage]
    finally:
        relay.resume()

    await recovered(store, relayed_engine)
    gc.collect()  # a driver future dropped unread is reported when it is collected
    assert loop_reports == []


@pytest.mark.anyio
async def test_the_backstop_ends_a_clean_up_the_driver_would_never_end(
    relay: StallingRelay,
    relayed_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    loop_reports: list[dict[str, Any]],
) -> None:
    """By order, not by speed. The driver's close is unbounded (`unbounded_close`) and the
    store's bound is one nobody waits out, so after the waves the abandoned calls are still
    winding down - cancelled once, waiting on a server that will not answer. Only when the loop's
    clock passes the bound (`LeapingClock`) does the backstop cancel them again, and then they end
    within a guard; without the backstop they never would. The pool is clean and the store answers
    once the relay forwards again."""
    unbounded_close(monkeypatch)
    clock = LeapingClock(monkeypatch)
    store = SqlAlchemySessionStore(engine=relayed_engine)
    store._handoff = TaskHandoff(wind_down=LONG)  # pyright: ignore[reportPrivateUsage]
    await store.connect()
    assert await one_lookup(verifier(store, lookup_timeout=LONG)) == "SessionRevoked"
    try:
        await stalled_waves(relay, verifier(store, lookup_timeout=STALL_LOOKUP_TIMEOUT))
        winding = store._handoff.winding_down  # pyright: ignore[reportPrivateUsage]
        assert winding >= 1, "an abandoned call ended before the backstop: nothing was proven"
        clock.leap(LONG)
        with anyio.fail_after(GUARD):
            await store._handoff.settled()  # pyright: ignore[reportPrivateUsage]
    finally:
        relay.resume()

    await recovered(store, relayed_engine)
    gc.collect()  # a driver future dropped unread is reported when it is collected
    assert loop_reports == []
