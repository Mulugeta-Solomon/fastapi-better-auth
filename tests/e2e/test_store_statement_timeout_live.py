"""`SqlAlchemySessionStore(statement_timeout=...)` on the live Postgres, through asyncpg (#121).

The option makes the server end any statement of the store that runs past the bound, whatever
becomes of its client, and touches nothing else on the engine the application lent it. Each case
here proves one half of that against the harness Postgres:

- **The server ends a lookup at the bound.** With the `session` table locked by another client,
  a lookup queues on the lock until Postgres cancels it (SQLSTATE 57014), long before the
  verifier's own `lookup_timeout`. The store logs that SQLSTATE, which no client-side deadline
  could produce.
- **Nothing else on the pool is bounded.** A statement the application runs on the same engine,
  queued on the same lock at the same time, is still waiting after the store's lookup was ended,
  and completes once the lock is released.
- **The pool's connections carry the server's own value afterwards.** Every connection the pool
  holds is read at once, after the store used each of them. This holds for a session-level
  `set_config` too, because every transaction the store opens rolls back and Postgres undoes a
  session-level setting made in a transaction that rolls back. So it pins the store's contract,
  not the local flag: the flag is pinned by the statement's text (`test_statement_timeout_units`)
  and, behaviourally, by the autocommit cases, where the two flags part ways.
- **Discovery is bounded too.** `connect()` reads the column defaults with `pg_get_expr`, which
  takes a lock on the table, so the same lock holds it. It raises what it raises for any database
  error, and the store reads the schema again on the next try.
- **Least privilege.** A role holding `SELECT` on the two tables and nothing else sets the bound
  and reads a real session: `set_config` on `statement_timeout` needs no grant.
- **No transaction, no bound.** A transaction-local setting ends with the statement that made it
  when the engine runs in `AUTOCOMMIT`, so every lookup would run unbounded. The store refuses
  such an engine with a `ConfigurationError` before any lookup reaches the database, whether the
  engine was built that way, is a copy made with `execution_options`, or was switched after
  `connect()`. This is also where the local flag shows: a session-level `set_config` would hold
  on such an engine, pass the store's own check, and stay on the pool's connections.

The locked tables are copies in a schema of this module's own, so the auth server and every other
lane keep reading theirs. No case sleeps to synchronise: each waits for the condition it needs,
polling, with a backstop that only ever runs out red.

The canary's published-wheel leg installs a release that may predate the option; the module skips
itself there, by the constructor's signature. Asyncio only: asyncpg drives the event loop directly.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from typing import Any

import anyio
import pytest
from sqlalchemy import event, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from fastapi_better_auth import AuthServiceUnavailable, ConfigurationError, SessionError

from .conftest import PASSWORD, POSTGRES_URL, raw_token, sign_in, sign_out, sign_up
from .roles import READ_BOTH, as_superuser, engine_as, login_granted

try:
    # Post-0.1.0 names belong under the guard: the published-wheel lane must skip, not raise.
    from fastapi_better_auth import CookieVerifier, SqlAlchemySessionStore
    from tests.cookies import COOKIE, http, run, sign
    from tests.deadlines import GUARD, every_call_ended, outage_lines, verifier
    from tests.stores import StatementLog, writes_emitted
except ImportError:
    pytest.skip(
        "this build of fastapi-better-auth-bridge publishes no session stores",
        allow_module_level=True,
    )

if "statement_timeout" not in inspect.signature(SqlAlchemySessionStore.__init__).parameters:
    pytest.skip(
        "this build of fastapi-better-auth-bridge predates SqlAlchemySessionStore(statement_timeout=...)",
        allow_module_level=True,
    )

pytestmark = pytest.mark.e2e

BOUND = 0.25
"""The store's `statement_timeout`, in seconds: what the server waits before it cancels."""
LOOKUP_TIMEOUT = 20.0
"""The verifier's own deadline, far above the bound: a refusal that took this long came from the
client, not from the server, and the case fails on its reason rather than on a timer."""
CLIENT_SIDE = LOOKUP_TIMEOUT / 4
"""A refusal must arrive well inside this to count as the server's. Healthy runs take the bound
plus a few milliseconds."""
QUERY_CANCELED = "57014"
POOL_SIZE = 2
BACKSTOP = 10.0
"""How long a wait for a condition may take before the case fails. Healthy runs take tens of
milliseconds; this only ever runs out red."""
POLL = 0.05

FORGED_TOKEN = "a-token-that-names-no-session"
FORGED = f"{COOKIE}={sign(FORGED_TOKEN)}"

WAITING_ON_A_LOCK = """
select count(*) from pg_stat_activity
where application_name = :name and wait_event_type = 'Lock'
"""
SERVER_VALUE = "select current_setting('statement_timeout')"


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
    """Empty copies of the two tables in a schema nobody else reads, dropped however it ends.

    `INCLUDING ALL` copies the column defaults, and a default is what makes discovery wait on a
    lock of the table (`pg_get_expr` opens it)."""
    name = f"wp56_{secrets.token_hex(6)}"
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
    """How this case's pool is told apart from everyone else's on the server."""
    return f"wp56-pool-{secrets.token_hex(4)}"


@pytest.fixture
async def engine(application_name: str) -> AsyncIterator[AsyncEngine]:
    """The application's engine, lent to the store: a pool of fixed size, so every connection
    it holds can be checked out at once and read."""
    built = create_async_engine(
        POSTGRES_URL,
        pool_size=POOL_SIZE,
        max_overflow=0,
        connect_args={"server_settings": {"application_name": application_name}},
    )
    yield built
    await built.dispose()


@pytest.fixture
async def blocker() -> AsyncIterator[AsyncEngine]:
    """The second client, which holds the lock every statement on the table queues behind."""
    built = create_async_engine(POSTGRES_URL)
    yield built
    await built.dispose()


@pytest.fixture
def logs(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    """The library's records, read when asserted: `caplog.records` is the current phase's list."""
    caplog.set_level(logging.DEBUG, logger="fastapi_better_auth")
    return caplog


async def server_value(observer: AsyncEngine) -> str:
    """The server's own `statement_timeout` for the harness role, as a fresh connection sees it."""
    async with observer.connect() as connection:
        return str(await connection.scalar(text(SERVER_VALUE)))


async def waiting_on_a_lock(observer: AsyncEngine, name: str) -> int:
    async with observer.connect() as connection:
        return int(await connection.scalar(text(WAITING_ON_A_LOCK), {"name": name}) or 0)


async def until(condition: Callable[[], Awaitable[bool]], what: str) -> None:
    """Poll `condition` until it holds; fail, naming `what`, if `BACKSTOP` runs out first."""
    give_up = time.monotonic() + BACKSTOP
    while not await condition():
        if time.monotonic() > give_up:
            pytest.fail(f"{what} did not happen within {BACKSTOP}s")
        await asyncio.sleep(POLL)


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


async def timed(built: CookieVerifier) -> tuple[str, float]:
    started = time.monotonic()
    outcome = await one_lookup(built)
    return outcome, time.monotonic() - started


def sqlstates(records: list[logging.LogRecord]) -> list[object]:
    """The SQLSTATE each store-outage WARNING names, in order."""
    return [tuple(record.args or ())[1] for record in outage_lines(records)]


@pytest.mark.anyio
async def test_a_lookup_queued_on_a_lock_is_ended_by_the_server_at_the_bound(
    engine: AsyncEngine,
    blocker: AsyncEngine,
    schema: str,
    logs: pytest.LogCaptureFixture,
) -> None:
    store = SqlAlchemySessionStore(engine=engine, schema=schema, statement_timeout=BOUND)
    await store.connect()
    built = verifier(store, lookup_timeout=LOOKUP_TIMEOUT)
    assert await one_lookup(built) == "SessionRevoked"

    async with blocker.connect() as lock:
        await lock.execute(text(f"LOCK TABLE {schema}.session IN ACCESS EXCLUSIVE MODE"))
        outcome, took = await timed(built)
        await lock.rollback()
    recovered = await one_lookup(built)
    await every_call_ended(store)

    assert outcome == "store-error", "the lookup was not ended by the server"
    assert BOUND <= took < CLIENT_SIDE, f"refused after {took:.3f}s"
    assert sqlstates(logs.records) == [QUERY_CANCELED]
    assert recovered == "SessionRevoked"


@pytest.mark.anyio
async def test_a_statement_the_application_runs_on_the_same_pool_is_not_bounded(
    engine: AsyncEngine,
    observer: AsyncEngine,
    blocker: AsyncEngine,
    schema: str,
    application_name: str,
    logs: pytest.LogCaptureFixture,
) -> None:
    """Both queue on one lock, through one pool. The store's lookup is ended at the bound; the
    application's statement is still waiting after that, and completes once the lock goes."""
    store = SqlAlchemySessionStore(engine=engine, schema=schema, statement_timeout=BOUND)
    await store.connect()
    built = verifier(store, lookup_timeout=LOOKUP_TIMEOUT)
    own = await server_value(observer)

    async def application() -> tuple[Any, ...]:
        async with engine.connect() as connection:
            query = f"select current_setting('statement_timeout'), count(*) from {schema}.session"
            row = (await connection.execute(text(query))).one()
        return tuple(row)

    async with blocker.connect() as lock:
        await lock.execute(text(f"LOCK TABLE {schema}.session IN ACCESS EXCLUSIVE MODE"))
        queued = asyncio.ensure_future(application())
        try:
            await until(
                lambda: _equals(waiting_on_a_lock(observer, application_name), 1),
                "the application's statement queuing on the lock",
            )
            outcome, took = await timed(built)
            still_waiting = await waiting_on_a_lock(observer, application_name)
            pending = not queued.done()
            await lock.rollback()
            with anyio.fail_after(GUARD):
                answered = await queued
        finally:
            queued.cancel()
    await every_call_ended(store)

    assert outcome == "store-error"
    assert took < CLIENT_SIDE
    assert sqlstates(logs.records) == [QUERY_CANCELED]
    assert pending, "the application's statement ended while the store's was being cancelled"
    assert still_waiting == 1
    assert answered == (own, 0)


async def _equals(reading: Awaitable[int], expected: int) -> bool:
    return await reading == expected


@pytest.mark.anyio
async def test_every_pooled_connection_carries_the_servers_own_value_afterwards(
    engine: AsyncEngine,
    observer: AsyncEngine,
    blocker: AsyncEngine,
    schema: str,
    application_name: str,
) -> None:
    """Each connection of the pool runs a lookup the server ends and one that completes. Then
    the whole pool is checked out at once, and no new connection is opened to do it.

    Passes for a session-level setting too (the module docstring says why): what it pins is
    that nothing the store does outlives its own transaction on a connection it gives back."""
    opened: list[object] = []

    def counted(connection: object, _record: object) -> None:
        opened.append(connection)

    event.listen(engine.sync_engine, "connect", counted)
    store = SqlAlchemySessionStore(engine=engine, schema=schema, statement_timeout=BOUND)
    await store.connect()
    built = verifier(store, lookup_timeout=LOOKUP_TIMEOUT)
    own = await server_value(observer)

    async with blocker.connect() as lock:
        await lock.execute(text(f"LOCK TABLE {schema}.session IN ACCESS EXCLUSIVE MODE"))
        refused = await asyncio.gather(*(one_lookup(built) for _ in range(POOL_SIZE)))
        await lock.rollback()
    answered = await asyncio.gather(*(one_lookup(built) for _ in range(POOL_SIZE)))
    await every_call_ended(store)
    held = len(opened)
    readings = await every_connection_reads(engine)

    assert refused == ["store-error"] * POOL_SIZE
    assert answered == ["SessionRevoked"] * POOL_SIZE
    assert held == POOL_SIZE, f"the lookups opened {held} connections"
    assert len(opened) == POOL_SIZE, "reading the pool opened a connection of its own"
    assert readings == [own] * POOL_SIZE


async def every_connection_reads(engine: AsyncEngine) -> list[str]:
    """`statement_timeout` as each connection of the pool reports it, all checked out at once."""
    connections = [await engine.connect() for _ in range(POOL_SIZE)]
    try:
        return [str(await connection.scalar(text(SERVER_VALUE))) for connection in connections]
    finally:
        for connection in connections:
            await connection.close()


@pytest.mark.anyio
async def test_connect_is_bounded_and_raises_what_it_raises_for_any_database_error(
    engine: AsyncEngine,
    observer: AsyncEngine,
    blocker: AsyncEngine,
    schema: str,
    application_name: str,
) -> None:
    """Discovery waits on the lock (`pg_get_expr` opens the table). Without the option, a
    cancellation by hand ends it - the same SQLSTATE, from an ordinary database error - and
    `connect()` raises SQLAlchemy's `DBAPIError` with the driver's error under it. With the
    option, the server ends it at the bound, and `connect()` raises exactly that again. Either
    way the schema is read again on the next try."""
    unbounded = SqlAlchemySessionStore(engine=engine, schema=schema)
    bounded = SqlAlchemySessionStore(engine=engine, schema=schema, statement_timeout=BOUND)

    async with blocker.connect() as lock:
        await lock.execute(text(f"LOCK TABLE {schema}.session IN ACCESS EXCLUSIVE MODE"))
        by_hand = await cancelled_by_hand(unbounded, observer, application_name)
        started = time.monotonic()
        # The guard only ever runs out red: a schema read with no bound would wait on the lock
        # this block holds, for good.
        with pytest.raises(DBAPIError) as by_the_bound, anyio.fail_after(CLIENT_SIDE):
            await bounded.connect()
        took = time.monotonic() - started
        await lock.rollback()
    await bounded.connect()
    answer = await one_lookup(verifier(bounded, lookup_timeout=LOOKUP_TIMEOUT))
    await every_call_ended(bounded)
    await every_call_ended(unbounded)

    assert type(by_the_bound.value) is type(by_hand)
    assert type(by_the_bound.value.orig) is type(by_hand.orig)
    assert getattr(by_hand.orig, "sqlstate", None) == QUERY_CANCELED
    assert getattr(by_the_bound.value.orig, "sqlstate", None) == QUERY_CANCELED
    assert BOUND <= took < CLIENT_SIDE, f"discovery ended after {took:.3f}s"
    assert answer == "SessionRevoked"


async def cancelled_by_hand(
    store: SqlAlchemySessionStore, observer: AsyncEngine, name: str
) -> DBAPIError:
    """`connect()` on `store` while discovery is queued on the lock, ended by `pg_cancel_backend`."""
    attempt = asyncio.ensure_future(store.connect())
    try:
        await until(
            lambda: _equals(waiting_on_a_lock(observer, name), 1),
            "discovery queuing on the lock",
        )
        async with observer.connect() as connection:
            await connection.execute(
                text(
                    "select pg_cancel_backend(pid) from pg_stat_activity"
                    " where application_name = :name and wait_event_type = 'Lock'"
                ),
                {"name": name},
            )
        with anyio.fail_after(GUARD), pytest.raises(DBAPIError) as caught:
            await attempt
    finally:
        attempt.cancel()
    return caught.value


@pytest.mark.anyio
async def test_the_first_lookup_reads_the_schema_under_the_bound_too(
    engine: AsyncEngine,
    blocker: AsyncEngine,
    schema: str,
    logs: pytest.LogCaptureFixture,
) -> None:
    """No `connect()`: the first lookup's discovery is what the server ends. The verifier turns
    the store's untranslated database error into the uniform refusal and one WARNING (R47a)."""
    store = SqlAlchemySessionStore(engine=engine, schema=schema, statement_timeout=BOUND)
    built = verifier(store, lookup_timeout=LOOKUP_TIMEOUT)

    async with blocker.connect() as lock:
        await lock.execute(text(f"LOCK TABLE {schema}.session IN ACCESS EXCLUSIVE MODE"))
        outcome, took = await timed(built)
        await lock.rollback()
    recovered = await one_lookup(built)
    await every_call_ended(store)

    assert outcome == "store-error"
    assert BOUND <= took < CLIENT_SIDE
    assert sqlstates(logs.records) == [QUERY_CANCELED]
    assert recovered == "SessionRevoked"


@pytest.fixture
def signed_in_user(harness: str) -> Iterator[tuple[str, str]]:
    """A user no other lane shares, signed in. Yields its id and its session cookie."""
    user_id, email = sign_up(harness, "wp56-grants")
    cookie = sign_in(harness, email, PASSWORD)
    yield user_id, cookie
    sign_out(harness, cookie)


@pytest.mark.anyio
async def test_select_on_both_tables_is_all_the_bound_needs(
    signed_in_user: tuple[str, str],
) -> None:
    """The role the store's docstring asks for, and no more: the bound is set first in each of
    its transactions, and a real session and its user are read under it."""
    user_id, cookie = signed_in_user
    log = StatementLog()

    async with login_granted(READ_BOTH) as login, engine_as(login) as engine:
        log.attach(engine)
        store = SqlAlchemySessionStore(engine=engine, statement_timeout=BOUND)
        await store.connect()
        record = await store.fetch_session_by_token(raw_token(cookie))
        user = await store.fetch_user_by_id(user_id)
        await every_call_ended(store)

    assert record is not None
    assert record.user is not None
    assert record.user.id == user_id
    assert user is not None
    assert user.id == user_id
    assert len(log.settings) == 3, "one per transaction: discovery and two lookups"
    assert writes_emitted(log, int(BOUND * 1000)) == []


# ---------------------------------------------------------------- an engine without a transaction

AUTOCOMMIT = "AUTOCOMMIT"


def autocommit_engine(how: str, application_name: str) -> AsyncEngine:
    """An engine that runs every statement in a transaction of its own: built so, or lent so."""
    options: dict[str, Any] = {
        "pool_size": POOL_SIZE,
        "max_overflow": 0,
        "connect_args": {"server_settings": {"application_name": application_name}},
    }
    if how == "built":
        return create_async_engine(POSTGRES_URL, isolation_level=AUTOCOMMIT, **options)
    return create_async_engine(POSTGRES_URL, **options).execution_options(
        isolation_level=AUTOCOMMIT
    )


def lookups_sent(log: StatementLog, schema: str) -> list[str]:
    """The statements that read the session or user table itself: lookups, not discovery."""
    return [statement for statement in log.statements if f"FROM {schema}." in statement]


@pytest.mark.anyio
@pytest.mark.parametrize("how", ["built", "lent-copy"])
async def test_an_engine_in_autocommit_is_refused_before_any_lookup(
    how: str, observer: AsyncEngine, schema: str, application_name: str
) -> None:
    """`connect()` and the lookup both refuse, as configuration, and neither sends a lookup.
    Afterwards the pool's connections carry the server's own value, as they would not had the
    store's setting been session-level."""
    engine = autocommit_engine(how, application_name)
    log = StatementLog()
    log.attach(engine)
    store = SqlAlchemySessionStore(engine=engine, schema=schema, statement_timeout=BOUND)
    try:
        with pytest.raises(ConfigurationError, match=AUTOCOMMIT) as refused:
            await store.connect()
        with pytest.raises(ConfigurationError, match=AUTOCOMMIT):
            await store.fetch_session_by_token(FORGED_TOKEN)
        await every_call_ended(store)
        readings = await every_connection_reads(engine)
    finally:
        await engine.dispose()

    assert "statement_timeout" in str(refused.value)
    assert lookups_sent(log, schema) == []
    assert readings == [await server_value(observer)] * POOL_SIZE


@pytest.mark.anyio
@pytest.mark.parametrize("spelling", [AUTOCOMMIT, "autocommit"])
async def test_an_engine_switched_to_autocommit_after_connect_is_refused_at_the_lookup(
    spelling: str, engine: AsyncEngine, schema: str
) -> None:
    """Discovery read the bound back on a transaction; the engine was changed in place since.
    The next lookup refuses rather than run without the bound. In lower case too: SQLAlchemy
    takes the level in any case and keeps the spelling it was given, and nothing after
    discovery reads the setting back."""
    store = SqlAlchemySessionStore(engine=engine, schema=schema, statement_timeout=BOUND)
    await store.connect()
    log = StatementLog()
    log.attach(engine)

    engine.sync_engine.update_execution_options(isolation_level=spelling)
    with pytest.raises(ConfigurationError, match=AUTOCOMMIT):
        await store.fetch_session_by_token(FORGED_TOKEN)
    await every_call_ended(store)

    assert lookups_sent(log, schema) == []


@pytest.mark.anyio
async def test_autocommit_is_refused_even_where_the_roles_own_value_is_the_same(
    harness: str,
) -> None:
    """The role's own `statement_timeout` equals the store's, so on an engine in AUTOCOMMIT the
    value read back is the same number. It came from the role, not from the store's statement,
    and would bound the store only until somebody changed the role: still refused."""
    async with login_granted(READ_BOTH) as login:
        await as_superuser(
            f"ALTER ROLE \"{login.name}\" SET statement_timeout = '{int(BOUND * 1000)}ms'",
            step="giving the role its own statement_timeout",
        )
        engine = create_async_engine(login.url, isolation_level=AUTOCOMMIT)
        try:
            async with engine.connect() as connection:
                roles_own = str(await connection.scalar(text(SERVER_VALUE)))
            store = SqlAlchemySessionStore(engine=engine, statement_timeout=BOUND)
            with pytest.raises(ConfigurationError, match=AUTOCOMMIT):
                await store.connect()
            await every_call_ended(store)
        finally:
            await engine.dispose()

    assert roles_own == f"{int(BOUND * 1000)}ms", "the role's own value did not take"


# ---------------------------------------------------------------- what the option sends


class Counted:
    """The statements one store sends through `log`, step by step: discovery, then each lookup."""

    def __init__(self, log: StatementLog) -> None:
        self.log = log
        self.steps: list[int] = []
        self._seen = 0

    def step(self) -> None:
        self.steps.append(len(self.log.statements) - self._seen)
        self._seen = len(self.log.statements)


async def drive(engine: AsyncEngine, schema: str, **options: Any) -> Counted:
    """Discovery, a lookup by token and one by user id, counted from the engine's own events."""
    log = StatementLog()
    log.attach(engine)
    counted = Counted(log)
    store = SqlAlchemySessionStore(engine=engine, schema=schema, **options)
    try:
        await store.connect()
        counted.step()
        await store.fetch_session_by_token(FORGED_TOKEN)
        counted.step()
        await store.fetch_user_by_id("nobody")
        counted.step()
        await every_call_ended(store)
    finally:
        log.detach(engine)
    return counted


def without_the_bound(log: StatementLog) -> list[tuple[str, Any]]:
    """`log` less the settings statement and its readback: what the store reads."""
    return [
        (statement, parameters)
        for statement, parameters in zip(log.statements, log.parameters, strict=True)
        if statement not in log.settings and "pg_settings" not in statement
    ]


@pytest.mark.anyio
async def test_the_bound_adds_its_statements_and_nothing_else(
    engine: AsyncEngine, schema: str
) -> None:
    """Counted on a warmed engine, so SQLAlchemy's own first-connect statements are not in it.
    Unset: discovery's reads, then one statement per lookup. Set: discovery also sends the
    settings statement and its readback, each lookup sends the settings statement first, and
    everything else is byte for byte what the unset store sent. Both stores pass the read-only
    invariant, the set one only for its own settings statement at its own value."""
    async with engine.connect():
        pass
    unset = await drive(engine, schema)
    bounded = await drive(engine, schema, statement_timeout=BOUND)
    discovery_unset, *lookups_unset = unset.steps
    discovery_bounded, *lookups_bounded = bounded.steps

    assert lookups_unset == [1, 1]
    assert lookups_bounded == [2, 2]
    assert discovery_bounded == discovery_unset + 2
    assert unset.log.settings == []
    assert len(bounded.log.settings) == 3
    assert without_the_bound(bounded.log) == without_the_bound(unset.log)
    assert writes_emitted(unset.log) == []
    assert writes_emitted(bounded.log, int(BOUND * 1000)) == []
