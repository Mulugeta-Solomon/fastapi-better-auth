"""What discovery reads back under `statement_timeout=`, and from whom, on the live Postgres.

Discovery proves that the store's transaction-local setting still holds for the statement after
it. A value read back is not proof on its own: the application can give its pooled connections a
session-level `statement_timeout` of its own, for example from a `connect` listener, and that
value can equal the store's. Each case here gives every pooled connection exactly that.

- **On an engine built in `AUTOCOMMIT`** the store's setting ends with the statement that made
  it, and what discovery reads is the application's equal value. It must still refuse: the bound
  would last only until the application changed its value, and nothing would say so.
- **On an engine that keeps a transaction** the same equal value is a legitimate deployment.
  Discovery passes, and a lookup is bounded by the store's own setting: with the application's
  value set to no timeout at all, the server still ends a lookup queued on a lock at the bound.

The pools here hold one connection, so every case runs on the same connection as the one before
it in that case. The tables are copies in a schema of this module's own.
"""

from __future__ import annotations

import inspect
import logging
import secrets
import time
from collections.abc import AsyncIterator
from typing import Any

import pytest
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from fastapi_better_auth import AuthServiceUnavailable, ConfigurationError, SessionError

from .conftest import POSTGRES_URL

try:
    # Post-0.1.0 names belong under the guard: the published-wheel lane must skip, not raise.
    from fastapi_better_auth import CookieVerifier, SqlAlchemySessionStore
    from tests.cookies import COOKIE, http, run, sign
    from tests.deadlines import every_call_ended, outage_lines, verifier
    from tests.stores import StatementLog
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
"""The store's `statement_timeout`, in seconds."""
BOUND_MS = int(BOUND * 1000)
EQUAL_VALUE = f"{BOUND_MS}ms"
"""The application's own session-level value, equal to the store's, as `SHOW` prints it."""
NO_TIMEOUT = "0"
LOOKUP_TIMEOUT = 20.0
"""The verifier's own deadline, far above the bound, so a refusal by the server is told apart."""
CLIENT_SIDE = LOOKUP_TIMEOUT / 4
QUERY_CANCELED = "57014"
AUTOCOMMIT = "AUTOCOMMIT"
SHOW = "show statement_timeout"

FORGED_TOKEN = "a-token-that-names-no-session"
FORGED = f"{COOKIE}={sign(FORGED_TOKEN)}"


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
    name = f"wp56d_{secrets.token_hex(6)}"
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
async def blocker() -> AsyncIterator[AsyncEngine]:
    """The second client, which holds the lock a lookup queues behind."""
    built = create_async_engine(POSTGRES_URL)
    yield built
    await built.dispose()


@pytest.fixture
def logs(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.set_level(logging.DEBUG, logger="fastapi_better_auth")
    return caplog


def give_every_connection_the_equal_value(dbapi_connection: Any, _record: Any) -> None:
    """The application's `connect` listener: a session-level value, equal to the store's.

    Run on the driver's own connection, outside any transaction, so it holds for the session
    whatever the engine's isolation level, as an application's listener would mean it to."""

    async def set_it(driver: Any) -> None:
        await driver.execute(f"SET statement_timeout = '{EQUAL_VALUE}'")

    dbapi_connection.run_async(set_it)


class Pool:
    """An engine of one connection that carries the equal value, and how often it connected."""

    def __init__(self, engine: AsyncEngine) -> None:
        self.engine = engine
        self.opened: list[object] = []
        event.listen(engine.sync_engine, "connect", give_every_connection_the_equal_value)
        event.listen(engine.sync_engine, "connect", self._counted)

    def _counted(self, dbapi_connection: object, _record: object) -> None:
        self.opened.append(dbapi_connection)

    async def value(self) -> str:
        """`statement_timeout` as the pooled connection reports it, outside the store."""
        async with self.engine.connect() as connection:
            return str(await connection.scalar(text(SHOW)))


@pytest.fixture
async def pool_of_one(request: pytest.FixtureRequest) -> AsyncIterator[Pool]:
    """One connection; `AUTOCOMMIT` when the case is parametrised `indirect` with it."""
    options: dict[str, Any] = {"pool_size": 1, "max_overflow": 0}
    level = getattr(request, "param", None)
    if level is not None:
        options["isolation_level"] = level
    built = create_async_engine(POSTGRES_URL, **options)
    try:
        yield Pool(built)
    finally:
        await built.dispose()


def lookups_sent(log: StatementLog, schema: str) -> list[str]:
    """The statements that read the session or user table itself: lookups, not discovery."""
    return [statement for statement in log.statements if f"FROM {schema}." in statement]


async def one_lookup(built: CookieVerifier) -> str:
    try:
        await run(built, http(cookie=FORGED))
    except AuthServiceUnavailable as exc:
        return "deadline" if "did not answer within" in exc.reason else "store-error"
    except SessionError as exc:
        return type(exc).__name__
    return "accepted"


@pytest.mark.anyio
@pytest.mark.parametrize("pool_of_one", [AUTOCOMMIT], indirect=True)
async def test_autocommit_is_refused_where_the_applications_session_value_is_the_same(
    pool_of_one: Pool, schema: str
) -> None:
    """The engine was built in `AUTOCOMMIT`, so its options do not say so, and the value read
    back is the application's: equal, and set in this session. It is still not the store's."""
    equal = await pool_of_one.value()
    log = StatementLog()
    log.attach(pool_of_one.engine)
    store = SqlAlchemySessionStore(
        engine=pool_of_one.engine, schema=schema, statement_timeout=BOUND
    )

    with pytest.raises(ConfigurationError, match=AUTOCOMMIT):
        await store.connect()
    with pytest.raises(ConfigurationError, match=AUTOCOMMIT):
        await store.fetch_session_by_token(FORGED_TOKEN)
    await every_call_ended(store)

    assert equal == EQUAL_VALUE, "the application's session value did not take"
    assert lookups_sent(log, schema) == []
    assert len(pool_of_one.opened) == 1


@pytest.mark.anyio
async def test_an_equal_session_value_on_a_transactional_engine_is_served_under_the_stores_bound(
    pool_of_one: Pool, blocker: AsyncEngine, schema: str, logs: pytest.LogCaptureFixture
) -> None:
    """Discovery passes. Then the application sets its own value on the one pooled connection to
    no timeout at all, and a lookup queued on a lock is still ended by the server at the bound:
    the store's own setting is what bounds it, not the application's."""
    equal = await pool_of_one.value()
    store = SqlAlchemySessionStore(
        engine=pool_of_one.engine, schema=schema, statement_timeout=BOUND
    )
    await store.connect()
    async with pool_of_one.engine.connect() as connection:
        await connection.execute(text(f"SET statement_timeout = {NO_TIMEOUT}"))
        await connection.commit()
    unbounded = await pool_of_one.value()
    built = verifier(store, lookup_timeout=LOOKUP_TIMEOUT)

    async with blocker.connect() as lock:
        await lock.execute(text(f"LOCK TABLE {schema}.session IN ACCESS EXCLUSIVE MODE"))
        started = time.monotonic()
        outcome = await one_lookup(built)
        took = time.monotonic() - started
        await lock.rollback()
    recovered = await one_lookup(built)
    await every_call_ended(store)

    assert equal == EQUAL_VALUE, "the application's session value did not take"
    assert unbounded == NO_TIMEOUT, "the application's change did not take"
    assert outcome == "store-error", "the lookup was not ended by the server"
    assert BOUND <= took < CLIENT_SIDE, f"refused after {took:.3f}s"
    assert [tuple(r.args or ())[1] for r in outage_lines(logs.records)] == [QUERY_CANCELED]
    assert recovered == "SessionRevoked"
    assert len(pool_of_one.opened) == 1
