"""`SyncStoreAdapter(statement_timeout=...)` on the live Postgres, on psycopg and psycopg2, on
asyncio and trio.

The adapter runs each lookup on a worker thread, and a thread cannot be interrupted: a lookup
abandoned at its deadline keeps its thread, its limiter slot and its pooled connection until the
DBAPI call returns. The server-side bound is what ends that call. So the case this module exists
for is the second one:

- **The server ends a lookup at the bound.** With the `session` copy locked by another client, a
  lookup queues on the lock, inside a transaction (read from `pg_stat_activity`), until Postgres
  cancels it with SQLSTATE 57014, long before the verifier's own `lookup_timeout`. It is refused,
  logged once naming 57014, and the next lookup after the lock goes answers.
- **The slot comes back.** A lookup abandoned at `lookup_timeout` while the lock is held. With the
  option set, its slot and its pooled connection are back within the bound plus `MARGIN`, while
  the lock is still held. Without it they are still held after that, and the statement is still
  queued on the server. A database that never answers, or a network path gone dead, is not this
  case: the server never hears of those, and no server setting ends them.
- **The schema read is bounded too**, and raises what any database error raises.
- **Least privilege.** `SELECT` on the two tables is all the role needs.
- **What the option sends.** Unset, one statement per lookup. Set, two per lookup and three more
  at the schema read, and everything else byte for byte what the unset adapter sent.

Every observer and the lock holder are synchronous, through the case's own driver, on worker
threads (`sync_postgres`), so no case depends on asyncpg. The locked tables are copies in a schema
of the case's own. No case sleeps to synchronise: each polls the server for what it needs.

The canary's published-wheel leg installs a release whose adapter predates the option; the module
skips itself there, by the adapter's own signature.
"""

from __future__ import annotations

import inspect
import logging
import secrets
from collections.abc import Iterator
from typing import Any

import anyio
import pytest
from sqlalchemy import Engine
from sqlalchemy.exc import DBAPIError

from fastapi_better_auth import AuthServiceUnavailable

from .conftest import PASSWORD, raw_token, sign_in, sign_out, sign_up
from .roles import READ_BOTH, Login, sync_engine_as, sync_login_granted
from .table_copies import sync_table_copies

try:
    # Post-0.1.0 names belong under the guard: the published-wheel lane must skip, not raise.
    from fastapi_better_auth import SyncStoreAdapter
    from tests.deadlines import every_slot_returned, verifier
    from tests.stores import (
        PROBE_SETTING,
        SETTING,
        SYNC_DRIVER_ABSENT,
        SYNC_DRIVERS,
        StatementLog,
        setting_values,
        writes_emitted,
    )

    from .sync_postgres import (
        FORGED_TOKEN,
        LOCK_HELD,
        QUERY_CANCELED,
        QUEUED,
        Lock,
        Opened,
        back_within,
        count,
        driver_error,
        harness_engine,
        held,
        in_thread,
        mentions,
        one_lookup,
        outages,
        pooled_values,
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
"""The adapter's `statement_timeout`, in seconds: what the server waits before it cancels."""
BOUND_MS = int(BOUND * 1000)
LOOKUP_TIMEOUT = 20.0
"""The verifier's own deadline, far above the bound, so a refusal by the server is told apart."""
CLIENT_SIDE = LOOKUP_TIMEOUT / 4
"""A refusal must arrive well inside this to count as the server's."""
POOL_SIZE = 2

ABANDONED_AT = 0.5
"""The `lookup_timeout` of the slot case: the lookup is abandoned here, before the bound."""
SLOT_BOUND = 1.5
"""The slot case's `statement_timeout`: a second after the lookup was abandoned."""
MARGIN = 1.0
"""How long after the bound the slot and the connection may take to come back. Measured locally
at about 20 ms past it: the server's cancel, the error back through the driver, the `ROLLBACK`
on the way back to the pool, and the release posted to the event loop."""


@pytest.fixture(params=SYNC_DRIVERS)
def driver(request: pytest.FixtureRequest) -> str:
    name = str(request.param)
    pytest.importorskip(name, reason=SYNC_DRIVER_ABSENT.format(driver=name))
    return name


@pytest.fixture
def observer(driver: str) -> Iterator[Engine]:
    built = harness_engine(driver)
    yield built
    built.dispose()


@pytest.fixture
def schema(harness: str, observer: Engine) -> Iterator[str]:
    """Empty copies of the two tables in a schema nobody else reads (`sync_table_copies`)."""
    with sync_table_copies(observer, "wp57") as name:
        yield name


@pytest.fixture
def application_name() -> str:
    """How this case's pool is told apart from everyone else's on the server."""
    return f"wp57-pool-{secrets.token_hex(4)}"


@pytest.fixture
def engine(driver: str, application_name: str) -> Iterator[Engine]:
    """The application's engine, lent to the adapter: a pool of fixed size."""
    built = harness_engine(
        driver,
        pool_size=POOL_SIZE,
        max_overflow=0,
        connect_args={"application_name": application_name},
    )
    yield built
    built.dispose()


@pytest.fixture
def lock(driver: str, schema: str) -> Iterator[Lock]:
    """The second client, which holds the lock every statement on the session copy queues behind.
    Released however the case ends, before the copies are dropped."""
    blocker = harness_engine(driver)
    held_lock = Lock(blocker, f"{schema}.session")
    yield held_lock
    held_lock.release()
    blocker.dispose()


@pytest.fixture
def logs(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    """The library's records, from the worker threads too."""
    caplog.set_level(logging.DEBUG, logger="fastapi_better_auth")
    return caplog


@pytest.mark.anyio
async def test_a_lookup_queued_on_a_lock_is_ended_by_the_server_at_the_bound(
    engine: Engine,
    observer: Engine,
    lock: Lock,
    schema: str,
    application_name: str,
    logs: pytest.LogCaptureFixture,
) -> None:
    store = SyncStoreAdapter(engine=engine, schema=schema, statement_timeout=BOUND)
    await store.connect()
    built = verifier(store, lookup_timeout=LOOKUP_TIMEOUT)
    assert await one_lookup(built) == "SessionRevoked"

    await in_thread(lock.take)
    watched = await queued_while(observer, application_name, lambda: one_lookup(built))
    await in_thread(lock.release)
    recovered = await one_lookup(built)
    await every_slot_returned(store)

    assert watched.queued_at is not None, (
        "the server never showed the lookup queued in a transaction"
    )
    assert watched.queued_at < watched.took
    assert watched.outcome == "store-error", "the lookup was not ended by the server"
    assert BOUND <= watched.took < CLIENT_SIDE, f"refused after {watched.took:.3f}s"
    assert [sqlstate for _, sqlstate in outages(logs.records)] == [QUERY_CANCELED]
    assert recovered == "SessionRevoked"
    assert mentions(logs.records, FORGED_TOKEN) == []


@pytest.mark.anyio
async def test_a_lookup_the_server_ends_raises_the_refusal_and_nothing_with_the_token(
    engine: Engine,
    observer: Engine,
    lock: Lock,
    schema: str,
    application_name: str,
    logs: pytest.LogCaptureFixture,
) -> None:
    """Called on the store itself, as route code may. The driver's error carries the token
    (psycopg2 writes it into the statement's text); the refusal that leaves the adapter carries
    neither, on its text, its repr or its chain, and no log record names it."""
    store = SyncStoreAdapter(engine=engine, schema=schema, statement_timeout=BOUND)
    await store.connect()

    await in_thread(lock.take)
    watched = await queued_while(
        observer, application_name, lambda: store.fetch_session_by_token(FORGED_TOKEN)
    )
    await in_thread(lock.release)
    await every_slot_returned(store)

    refusal = watched.outcome
    assert isinstance(refusal, AuthServiceUnavailable), f"the lookup gave {refusal!r}"
    assert watched.queued_at is not None
    assert BOUND <= watched.took < CLIENT_SIDE
    assert FORGED_TOKEN not in str(refusal)
    assert FORGED_TOKEN not in repr(refusal)
    assert FORGED_TOKEN not in refusal.reason
    assert refusal.__cause__ is None
    assert refusal.__context__ is None
    assert outages(logs.records) == [("QueryCanceled", QUERY_CANCELED)]
    assert mentions(logs.records, FORGED_TOKEN) == []


@pytest.mark.anyio
@pytest.mark.parametrize("bounded", [True, False], ids=["bounded", "unbounded"])
async def test_an_abandoned_lookups_slot_and_connection_come_back_at_the_bound(
    bounded: bool,
    engine: Engine,
    observer: Engine,
    lock: Lock,
    schema: str,
    application_name: str,
    logs: pytest.LogCaptureFixture,
) -> None:
    """The lookup is abandoned at `lookup_timeout` while the server shows it queued on the lock.
    Its thread runs on. Bounded, the server ends its statement at the bound, and the slot and the
    connection are back within `MARGIN` after it, with the lock still held. Unbounded, they are
    still held a full `MARGIN` after the bound, and the statement is still queued."""
    timeout = SLOT_BOUND if bounded else None
    store = SyncStoreAdapter(engine=engine, schema=schema, statement_timeout=timeout)
    await store.connect()
    built = verifier(store, lookup_timeout=ABANDONED_AT)
    window = SLOT_BOUND + MARGIN
    opened = Opened(engine)

    await in_thread(lock.take)
    try:
        watched = await queued_while(observer, application_name, lambda: one_lookup(built))
        back_at = await back_within(store, engine, watched.started, window)
        holding = held(store, engine)
        lock_held = await in_thread(count, observer, LOCK_HELD, {"table": lock.table})
        queued = await in_thread(count, observer, QUEUED, {"name": application_name})
    finally:
        await in_thread(lock.release)
        await every_slot_returned(store)
    answered = await one_lookup(verifier(store, lookup_timeout=LOOKUP_TIMEOUT))
    await every_slot_returned(store)
    reopened = opened.count
    readings = await in_thread(pooled_values, engine, POOL_SIZE)
    own = await in_thread(server_value, observer)

    assert watched.queued_at is not None, (
        "the server never showed the lookup queued in a transaction"
    )
    assert watched.queued_at < watched.took, "the deadline landed before the statement queued"
    assert watched.outcome == "deadline"
    assert ABANDONED_AT <= watched.took < SLOT_BOUND
    assert lock_held == 1, "the lock went before the measurement ended"
    assert answered == "SessionRevoked", "the pool did not serve after the lock went"
    assert reopened == 0, "the abandoned lookup's connection was not given back whole"
    assert readings == [own] * POOL_SIZE
    assert mentions(logs.records, FORGED_TOKEN) == []
    kinds = [kind for kind, _ in outages(logs.records)]
    if bounded:
        assert back_at is not None, f"slot or connection still held {window}s after the start"
        assert SLOT_BOUND <= back_at < window, f"back after {back_at:.3f}s"
        assert (holding, queued) == ((0, 0), 0)
        assert kinds == ["LookupDeadlineExceeded", "QueryCanceled"]
        assert outages(logs.records)[1][1] == QUERY_CANCELED
    else:
        assert back_at is None
        assert (holding, queued) == ((1, 1), 1)
        assert kinds == ["LookupDeadlineExceeded"]


@pytest.mark.anyio
async def test_the_schema_read_is_bounded_and_raises_what_any_database_error_raises(
    engine: Engine,
    observer: Engine,
    lock: Lock,
    schema: str,
    application_name: str,
) -> None:
    """Discovery waits on the lock (`pg_get_expr` opens the table). The server ends it at the
    bound; `connect()` raises SQLAlchemy's `DBAPIError` with the driver's own error under it,
    naming 57014. Nothing is kept: the next `connect()` reads the schema."""
    store = SyncStoreAdapter(engine=engine, schema=schema, statement_timeout=BOUND)

    await in_thread(lock.take)
    with anyio.fail_after(CLIENT_SIDE):
        watched = await queued_while(observer, application_name, store.connect)
    await in_thread(lock.release)
    await store.connect()
    answer = await one_lookup(verifier(store, lookup_timeout=LOOKUP_TIMEOUT))
    await every_slot_returned(store)

    assert isinstance(watched.outcome, DBAPIError), f"connect() gave {watched.outcome!r}"
    assert driver_error(watched.outcome) == ("QueryCanceled", QUERY_CANCELED)
    assert watched.queued_at is not None
    assert watched.queued_at < watched.took
    assert BOUND <= watched.took < CLIENT_SIDE, f"discovery ended after {watched.took:.3f}s"
    assert answer == "SessionRevoked"


@pytest.fixture
def signed_in_user(harness: str) -> Iterator[tuple[str, str]]:
    """A user no other lane shares, signed in. Yields its id and its session cookie."""
    user_id, email = sign_up(harness, "wp57-grants")
    cookie = sign_in(harness, email, PASSWORD)
    yield user_id, cookie
    sign_out(harness, cookie)


@pytest.fixture
def login(driver: str) -> Iterator[Login]:
    with sync_login_granted(driver, READ_BOTH) as granted:
        yield granted


def settings_named(log: StatementLog) -> list[object]:
    """The setting each settings statement in `log` names, in order."""
    found: list[object] = []
    for statement, parameters in zip(log.statements, log.parameters, strict=True):
        values = setting_values(statement, parameters) if statement in log.settings else None
        if values is not None:
            found.append(values[0])
    return found


@pytest.mark.anyio
async def test_select_on_both_tables_is_all_the_bound_needs(
    driver: str, login: Login, signed_in_user: tuple[str, str]
) -> None:
    user_id, cookie = signed_in_user
    log = StatementLog()

    with sync_engine_as(driver, login) as engine:
        log.attach(engine)
        store = SyncStoreAdapter(engine=engine, statement_timeout=BOUND)
        await store.connect()
        record = await store.fetch_session_by_token(raw_token(cookie))
        user = await store.fetch_user_by_id(user_id)
        await every_slot_returned(store)

    assert record is not None
    assert record.user is not None
    assert record.user.id == user_id
    assert user is not None
    assert user.id == user_id
    assert settings_named(log) == [PROBE_SETTING, SETTING, SETTING, SETTING]
    assert len(log.settings) == len(settings_named(log)), "a settings statement in another shape"
    assert writes_emitted(log, BOUND_MS) == []


class Counted:
    """The statements one adapter sends through `log`, step by step: discovery, then lookups."""

    def __init__(self, log: StatementLog) -> None:
        self.log = log
        self.steps: list[int] = []
        self._seen = 0

    def step(self) -> None:
        self.steps.append(len(self.log.statements) - self._seen)
        self._seen = len(self.log.statements)


async def drive(engine: Engine, schema: str, **options: Any) -> Counted:
    """Discovery, a lookup by token and one by user id, counted from the engine's own events."""
    log = StatementLog()
    log.attach(engine)
    counted = Counted(log)
    store = SyncStoreAdapter(engine=engine, schema=schema, **options)
    try:
        await store.connect()
        counted.step()
        await store.fetch_session_by_token(FORGED_TOKEN)
        counted.step()
        await store.fetch_user_by_id("nobody")
        counted.step()
        await every_slot_returned(store)
    finally:
        log.detach(engine)
    return counted


def without_the_bound(log: StatementLog) -> list[tuple[str, Any]]:
    """`log` less the settings statements and their readback: what the adapter reads."""
    return [
        (statement, parameters)
        for statement, parameters in zip(log.statements, log.parameters, strict=True)
        if statement not in log.settings and "pg_settings" not in statement
    ]


@pytest.mark.anyio
async def test_the_bound_adds_its_statements_and_nothing_else(engine: Engine, schema: str) -> None:
    """Counted on a warmed engine, so SQLAlchemy's own first-connect statements are not in it."""
    with engine.connect():
        pass
    unset = await drive(engine, schema)
    bounded = await drive(engine, schema, statement_timeout=BOUND)
    discovery_unset, *lookups_unset = unset.steps
    discovery_bounded, *lookups_bounded = bounded.steps

    assert lookups_unset == [1, 1]
    assert lookups_bounded == [2, 2]
    assert discovery_bounded == discovery_unset + 3
    assert unset.log.settings == []
    assert settings_named(bounded.log) == [PROBE_SETTING, SETTING, SETTING, SETTING]
    assert without_the_bound(bounded.log) == without_the_bound(unset.log)
    assert writes_emitted(unset.log) == []
    assert writes_emitted(bounded.log, BOUND_MS) == []
