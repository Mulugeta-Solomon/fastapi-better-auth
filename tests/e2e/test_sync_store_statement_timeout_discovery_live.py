"""What `SyncStoreAdapter(statement_timeout=...)` refuses at the schema read, and from whom, on the
live Postgres, on psycopg and psycopg2, on asyncio and trio.

A transaction-local setting holds only inside a transaction. Under `AUTOCOMMIT` it ends with the
statement that made it, so every lookup would run unbounded. Autocommit can reach a sync driver
without showing in the engine's options, and the schema read is what sees those ways:

- **Every way autocommit arrives is refused**: an engine built with `isolation_level="AUTOCOMMIT"`,
  a copy made with `execution_options`, the DBAPI connection's own `autocommit = True` set in a
  `connect` or a `checkout` listener, and psycopg's own `autocommit=True` connect argument (which
  psycopg2 does not have). An engine switched after `connect()`, in either spelling, is refused at
  the next lookup.
- **An equal session-level value is not the adapter's.** With the application's own value, equal
  to the adapter's, on every connection, an engine in `AUTOCOMMIT` is still refused. On an engine
  that keeps a transaction the same value is a legitimate deployment: it passes, and a lookup is
  still bounded by the adapter's own setting after the application changes its value to none.
- **Each schema read proves its own probe**, on one pooled connection, and a third one on that
  connection without a transaction is refused although the connection held a probe before.

The pools here hold one connection unless a case says otherwise. Tables are copies in a schema of
the case's own. Observers are synchronous, through the case's own driver (`sync_postgres`).
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import Engine, event, text

from fastapi_better_auth import ConfigurationError

from .table_copies import sync_table_copies

try:
    # Post-0.1.0 names belong under the guard: the published-wheel lane must skip, not raise.
    from fastapi_better_auth import SyncStoreAdapter
    from tests.deadlines import every_slot_returned, verifier
    from tests.stores import (
        PROBE_SETTING,
        PROBE_VALUE,
        SYNC_DRIVER_ABSENT,
        SYNC_DRIVERS,
        StatementLog,
        setting_values,
    )

    from .sync_postgres import (
        FORGED_TOKEN,
        QUERY_CANCELED,
        Lock,
        harness_engine,
        in_thread,
        one_lookup,
        outages,
        queued_while,
        server_value,
    )
except ImportError:
    pytest.skip(
        "this build of fastapi-better-auth-bridge publishes no session stores",
        allow_module_level=True,
    )

if "statement_timeout" not in inspect.signature(SyncStoreAdapter.__init__).parameters:
    pytest.skip(
        "this build of fastapi-better-auth-bridge predates SyncStoreAdapter(statement_timeout=...)",
        allow_module_level=True,
    )

pytestmark = pytest.mark.e2e

BOUND = 0.5
BOUND_MS = int(BOUND * 1000)
EQUAL_VALUE = f"{BOUND_MS}ms"
"""The application's own session-level value, equal to the adapter's, as `SHOW` prints it."""
NO_TIMEOUT = "0"
LOOKUP_TIMEOUT = 20.0
CLIENT_SIDE = LOOKUP_TIMEOUT / 4
AUTOCOMMIT = "AUTOCOMMIT"
SHOW = "show statement_timeout"
PROBE_READ = "select current_setting(:name, true)"
ENDED = ""
"""What Postgres answers for the probe on a connection whose transaction that set it has ended."""
APPLICATION_NAME = "wp57-discovery"

ROUTES: tuple[tuple[str, str], ...] = tuple(
    (driver, route)
    for driver in SYNC_DRIVERS
    for route in ("built", "options-copy", "connect-listener", "checkout-listener", "connect-arg")
    if route != "connect-arg" or driver == "psycopg"
)
"""Each way autocommit reaches each driver. Only psycopg takes `autocommit=True` as a connect
argument; psycopg2 has no such argument, so that route is not one it has."""


def needs(driver: str) -> str:
    pytest.importorskip(driver, reason=SYNC_DRIVER_ABSENT.format(driver=driver))
    return driver


@pytest.fixture(params=SYNC_DRIVERS)
def driver(request: pytest.FixtureRequest) -> str:
    return needs(str(request.param))


@pytest.fixture
def observer(driver: str) -> Iterator[Engine]:
    built = harness_engine(driver)
    yield built
    built.dispose()


@pytest.fixture
def schema(harness: str, observer: Engine) -> Iterator[str]:
    with sync_table_copies(observer, "wp57d") as name:
        yield name


@pytest.fixture
def logs(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.set_level(logging.DEBUG, logger="fastapi_better_auth")
    return caplog


def no_transaction(dbapi_connection: Any, *_: Any) -> None:
    """Application code that puts a pooled connection into autocommit, where the engine's options
    cannot show it. Both drivers name the attribute alike."""
    dbapi_connection.autocommit = True


def give_the_equal_value(dbapi_connection: Any, _record: Any) -> None:
    """The application's `connect` listener: a session-level value equal to the adapter's,
    committed, so it holds for the session whatever the engine's isolation level."""
    cursor = dbapi_connection.cursor()
    cursor.execute(f"SET statement_timeout = '{EQUAL_VALUE}'")
    cursor.close()
    dbapi_connection.commit()


def autocommit_engine(driver: str, route: str) -> Engine:
    options: dict[str, Any] = {"pool_size": 1, "max_overflow": 0}
    if route == "built":
        return harness_engine(driver, isolation_level=AUTOCOMMIT, **options)
    if route == "options-copy":
        return harness_engine(driver, **options).execution_options(isolation_level=AUTOCOMMIT)
    if route == "connect-arg":
        return harness_engine(driver, connect_args={"autocommit": True}, **options)
    engine = harness_engine(driver, **options)
    event.listen(engine, route.removesuffix("-listener"), no_transaction)
    return engine


def lookups_sent(log: StatementLog, schema: str) -> list[str]:
    """The statements that read the session or user table itself: lookups, not discovery."""
    return [statement for statement in log.statements if f"FROM {schema}." in statement]


def pool_value(engine: Engine, query: str = SHOW, **params: Any) -> str | None:
    """One value as the pooled connection reports it, outside the adapter; None if NULL."""
    with engine.connect() as connection:
        found = connection.scalar(text(query), params)
    return None if found is None else str(found)


async def refused_throughout(engine: Engine, schema: str) -> tuple[str, list[str], str | None]:
    """`connect()` and a lookup on `engine`, each refused as configuration: the refusal's text,
    the lookups that reached the database anyway, and the pooled connection's value afterwards."""
    log = StatementLog()
    log.attach(engine)
    store = SyncStoreAdapter(engine=engine, schema=schema, statement_timeout=BOUND)
    with pytest.raises(ConfigurationError, match=AUTOCOMMIT) as refused:
        await store.connect()
    with pytest.raises(ConfigurationError, match=AUTOCOMMIT):
        await store.fetch_session_by_token(FORGED_TOKEN)
    await every_slot_returned(store)
    return str(refused.value), lookups_sent(log, schema), await in_thread(pool_value, engine)


@pytest.mark.anyio
@pytest.mark.parametrize(("driver_name", "route"), ROUTES, ids=[f"{d}-{r}" for d, r in ROUTES])
async def test_every_way_autocommit_reaches_the_driver_is_refused_before_any_lookup(
    harness: str, driver_name: str, route: str
) -> None:
    """`connect()` and the lookup both refuse, and neither sends a lookup. The pooled connection
    carries the server's own value afterwards: nothing the adapter set outlived its statement."""
    driver = needs(driver_name)
    observer = harness_engine(driver)
    engine = autocommit_engine(driver, route)
    try:
        with sync_table_copies(observer, "wp57d") as schema:
            refusal, sent, reading = await refused_throughout(engine, schema)
        own = await in_thread(server_value, observer)
    finally:
        engine.dispose()
        observer.dispose()

    assert "statement_timeout" in refusal
    assert sent == []
    assert reading == own


@pytest.mark.anyio
@pytest.mark.parametrize("spelling", [AUTOCOMMIT, "autocommit"])
async def test_an_engine_switched_to_autocommit_after_connect_is_refused_at_the_lookup(
    spelling: str, driver: str, schema: str
) -> None:
    engine = harness_engine(driver, pool_size=1, max_overflow=0)
    store = SyncStoreAdapter(engine=engine, schema=schema, statement_timeout=BOUND)
    try:
        await store.connect()
        log = StatementLog()
        log.attach(engine)
        engine.update_execution_options(isolation_level=spelling)
        with pytest.raises(ConfigurationError, match=AUTOCOMMIT):
            await store.fetch_session_by_token(FORGED_TOKEN)
        await every_slot_returned(store)
    finally:
        engine.dispose()

    assert lookups_sent(log, schema) == []


class Pool:
    """An engine of one connection that carries the application's equal value."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.opened: list[object] = []
        event.listen(engine, "connect", give_the_equal_value)
        event.listen(engine, "connect", self._counted)

    def _counted(self, dbapi_connection: object, _record: object) -> None:
        self.opened.append(dbapi_connection)


@pytest.fixture
def pool_of_one(driver: str, request: pytest.FixtureRequest) -> Iterator[Pool]:
    """One connection, with the equal value; `AUTOCOMMIT` when parametrised `indirect` with it."""
    options: dict[str, Any] = {
        "pool_size": 1,
        "max_overflow": 0,
        "connect_args": {"application_name": APPLICATION_NAME},
    }
    level = getattr(request, "param", None)
    if level is not None:
        options["isolation_level"] = level
    built = harness_engine(driver, **options)
    try:
        yield Pool(built)
    finally:
        built.dispose()


@pytest.mark.anyio
@pytest.mark.parametrize("pool_of_one", [AUTOCOMMIT], indirect=True)
async def test_autocommit_is_refused_where_the_applications_session_value_is_the_same(
    pool_of_one: Pool, schema: str
) -> None:
    """Built in `AUTOCOMMIT`, so its options do not say so, and the value read back is the
    application's: equal, and set in this session. It is still not the adapter's."""
    equal = await in_thread(pool_value, pool_of_one.engine)
    log = StatementLog()
    log.attach(pool_of_one.engine)
    store = SyncStoreAdapter(engine=pool_of_one.engine, schema=schema, statement_timeout=BOUND)

    with pytest.raises(ConfigurationError, match=AUTOCOMMIT):
        await store.connect()
    with pytest.raises(ConfigurationError, match=AUTOCOMMIT):
        await store.fetch_session_by_token(FORGED_TOKEN)
    await every_slot_returned(store)

    assert equal == EQUAL_VALUE, "the application's session value did not take"
    assert lookups_sent(log, schema) == []
    assert len(pool_of_one.opened) == 1


def set_no_timeout(engine: Engine) -> None:
    """The application changes its own session-level value on the one pooled connection."""
    with engine.connect() as connection:
        connection.execute(text(f"SET statement_timeout = {NO_TIMEOUT}"))
        connection.commit()


@pytest.mark.anyio
async def test_an_equal_session_value_on_a_transactional_engine_is_served_under_the_bound(
    driver: str, pool_of_one: Pool, observer: Engine, schema: str, logs: pytest.LogCaptureFixture
) -> None:
    """Discovery passes. The application then sets its own value to no timeout at all, and a
    lookup queued on a lock is still ended by the server at the bound: the adapter's own setting
    bounds it, not the application's."""
    equal = await in_thread(pool_value, pool_of_one.engine)
    store = SyncStoreAdapter(engine=pool_of_one.engine, schema=schema, statement_timeout=BOUND)
    await store.connect()
    await in_thread(set_no_timeout, pool_of_one.engine)
    unbounded = await in_thread(pool_value, pool_of_one.engine)
    built = verifier(store, lookup_timeout=LOOKUP_TIMEOUT)
    blocker = harness_engine(driver)
    lock = Lock(blocker, f"{schema}.session")

    try:
        await in_thread(lock.take)
        watched = await queued_while(observer, APPLICATION_NAME, lambda: one_lookup(built))
    finally:
        await in_thread(lock.release)
        blocker.dispose()
    recovered = await one_lookup(built)
    await every_slot_returned(store)

    assert equal == EQUAL_VALUE, "the application's session value did not take"
    assert unbounded == NO_TIMEOUT, "the application's change did not take"
    assert watched.queued_at is not None
    assert watched.outcome == "store-error", "the lookup was not ended by the server"
    assert BOUND <= watched.took < CLIENT_SIDE, f"refused after {watched.took:.3f}s"
    assert [sqlstate for _, sqlstate in outages(logs.records)] == [QUERY_CANCELED]
    assert recovered == "SessionRevoked"
    assert len(pool_of_one.opened) == 1


def probes_sent(log: StatementLog) -> list[str]:
    """Every probe value the adapter set, in order, from the engine's own events."""
    found: list[str] = []
    for statement, parameters in zip(log.statements, log.parameters, strict=True):
        values = setting_values(statement, parameters) if statement in log.settings else None
        if values is not None and values[0] == PROBE_SETTING:
            found.append(str(values[1]))
    return found


async def probe_on_the_pool(pool: Pool) -> str | None:
    return await in_thread(lambda: pool_value(pool.engine, PROBE_READ, name=PROBE_SETTING))


@pytest.mark.anyio
async def test_each_schema_read_on_one_connection_proves_its_own_probe(
    pool_of_one: Pool, schema: str
) -> None:
    """Two schema reads on the same connection pass, each with a probe of its own, and the first
    probe reads as an empty string, not NULL, before the second. Then that connection runs
    without a transaction, and a third is refused: what it reads is that empty string."""
    never_set = await probe_on_the_pool(pool_of_one)
    log = StatementLog()
    log.attach(pool_of_one.engine)
    first = SyncStoreAdapter(engine=pool_of_one.engine, schema=schema, statement_timeout=BOUND)
    await first.connect()
    after_first = await probe_on_the_pool(pool_of_one)
    second = SyncStoreAdapter(engine=pool_of_one.engine, schema=schema, statement_timeout=BOUND)
    await second.connect()
    after_second = await probe_on_the_pool(pool_of_one)
    passed = probes_sent(log)

    event.listen(pool_of_one.engine, "checkout", no_transaction)
    third = SyncStoreAdapter(engine=pool_of_one.engine, schema=schema, statement_timeout=BOUND)
    with pytest.raises(ConfigurationError, match=AUTOCOMMIT):
        await third.connect()
    for store in (first, second, third):
        await every_slot_returned(store)

    assert never_set is None
    assert after_first == ENDED
    assert after_second == ENDED
    assert len(passed) == 2
    assert passed[0] != passed[1]
    assert all(PROBE_VALUE.fullmatch(probe) for probe in passed)
    assert len(probes_sent(log)) == 3, "the third schema read set no probe of its own"
    assert len(pool_of_one.opened) == 1
