"""The two SQLAlchemy stores: one for an async engine, one for the shops that have neither."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from functools import partial
from typing import TYPE_CHECKING, Any

import anyio

from ..errors import ConfigurationError
from ..newest_first import NewestFirstLock
from .outage import OutageLatch, report_once
from .records import StoredSession, StoredUser
from .statement_timeout import validated_statement_timeout
from .task_handoff import TaskHandoff
from .thread_handoff import run_in_worker

if TYPE_CHECKING:
    from sqlalchemy import Connection, Engine, Select
    from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

    from ..errors import AuthServiceUnavailable
    from .sqlalchemy_core import Discovered, Plan

Row = Mapping[str, Any]
Rows = Sequence[Row]

MISSING = (
    "{adapter} needs the sqlalchemy package, which is not installed. Install it with:"
    ' pip install "fastapi-better-auth-bridge[sqlalchemy]" - and an async driver'
    " (postgresql+asyncpg, postgresql+psycopg, mysql+asyncmy) for the engine you pass it."
)

DEFAULT_MAX_CONCURRENCY = 8
"""Worker-thread ceiling for a pool whose capacity cannot be read (`NullPool`, `StaticPool`).

A conservative bound on concurrent DB threads when the engine's pool does not state a size, so
a flood of cancelled lookups cannot open an unbounded number of connections. A `QueuePool` (the
production default) is introspectable and the limiter is sized to it instead - see `_pool_ceiling`.
"""


def _core(adapter: str):
    """The module that imports SQLAlchemy, reached only once a store is actually built.

    `sqlalchemy` is an optional extra, so `import fastapi_better_auth` has to work without it.
    Deferring the import to here is what makes that true, and makes its absence a startup
    `ConfigurationError` naming the extra rather than an `ImportError` from a package import.
    """
    try:
        from . import sqlalchemy_core
    except ImportError as exc:
        raise ConfigurationError(MISSING.format(adapter=adapter)) from exc
    return sqlalchemy_core


class _CoreStore(ABC):
    """Everything the two flavours share: the tables, the plan, and the row mapping.

    Only *how* a statement runs differs between them - awaited on an async driver, or handed to
    a worker thread - so the statements themselves, the schema discovery and every decision
    about what a row means live here and are proven once for both.
    """

    def __init__(
        self,
        *,
        adapter: str,
        session_table: str,
        user_table: str,
        schema: str | None,
        session_columns: Sequence[str] | None,
        user_columns: Sequence[str] | None,
    ) -> None:
        self._sql = _core(adapter)
        self._schema = schema
        self._names = self._sql.validated_names(session_table, user_table)
        self._allowed = (
            self._sql.validated_columns("session_columns", session_columns),
            self._sql.validated_columns("user_columns", user_columns),
        )
        self._turn = NewestFirstLock()
        self._plan: Plan | None = None
        self._outage = OutageLatch()

    async def connect(self) -> None:
        """Read the live schema now, rather than on whichever request arrives first.

        Optional but recommended: call it from a lifespan handler and a database whose Better
        Auth migration never ran stops the application from starting, instead of answering the
        first authenticated request with a `ConfigurationError`. Idempotent, and it does only
        what the first lookup would have done anyway.

        Raises:
            ConfigurationError: If a table is absent, or is missing a column every lookup reads.
            SQLAlchemyError: A database error while reading, as SQLAlchemy raised it (a
                `DBAPIError`, the driver's own error under `.orig`) - one a
                `statement_timeout=` bound ended included. Nothing is kept: the next call, or
                the first lookup, reads the schema again.
        """
        await self._ready()

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        """The session stored under this raw token, with its user, in one SELECT.

        See `SessionStore.fetch_session_by_token`. A blank token never reaches the database.
        """
        if not token.strip():
            return None
        plan = await self._ready()
        found = await self._select(plan.session_statement, {self._sql.TOKEN_PARAM: token})
        self._outage.rearm()
        return self._sql.session_from(found, plan, token)

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        """The user row with this id. See `SessionStore.fetch_user_by_id`.

        Where the database generates ids, `user_id` is the text Better Auth writes for one -
        `"7"` for a serial id, lowercase hyphenated for a uuid - and is bound as the column's own
        type. Any other spelling of it (`"07"`, upper-case hex) is a miss, never a query.
        """
        if not user_id.strip():
            return None
        plan = await self._ready()
        bound = self._sql.bound_user_id(plan, user_id)
        if bound is None:
            return None
        found = await self._select(plan.user_statement, {self._sql.USER_ID_PARAM: bound})
        self._outage.rearm()
        return self._sql.user_from(found, plan, user_id, check_identity=True)

    async def _ready(self) -> Plan:
        """Discovery happens once, whoever gets there first.

        The statement depends on which columns exist - the admin plugin's are surfaced only
        where they were created - so this is not a cache in front of a fixed query, it *is* the
        query. The lock is what stops a burst of first requests each inspecting the schema.

        Without `connect()`, the read runs inside a request, under its `lookup_timeout`, and a
        read whose caller leaves is abandoned and started again by the next holder. So the turn
        goes to the newest waiter, which has the most of its deadline left, not the oldest, which
        has only the gap between two arrivals: first-in-first-out, a read that overran once is
        cut short again and again for as long as requests arrive faster than one read takes
        (`NewestFirstLock`, F22).
        """
        plan = self._plan
        if plan is not None:
            return plan
        session, user = self._names
        session_allowed, user_allowed = self._allowed
        async with self._turn:
            if self._plan is None:
                discovered = await self._columns()
                self._plan = self._sql.plan_for(
                    session,
                    user,
                    self._schema,
                    discovered.columns,
                    types=discovered.types,
                    dialect=discovered.dialect,
                    session_allowed=session_allowed,
                    user_allowed=user_allowed,
                )
            return self._plan

    def _reflected(self, connection: Connection) -> Discovered:
        return self._sql.reflected(connection, self._names, self._schema)

    def _unavailable(
        self, error: BaseException, params: Mapping[str, Any]
    ) -> AuthServiceUnavailable:
        """The refusal a lookup's database error becomes, the operator told once per kind (R47)."""
        report_once(self._outage, error, self._sql.lookup_marker(params))
        return self._sql.lookup_unavailable(params)

    @abstractmethod
    async def _columns(self) -> Discovered:
        """The columns each table has, read however this flavour reaches the database."""

    @abstractmethod
    async def _select(self, statement: Select[Any], params: Mapping[str, Any]) -> Rows:
        """Run one statement and materialize its rows before the connection closes."""


class SqlAlchemySessionStore(_CoreStore):
    """Better Auth's `session` and `user` tables, read through an async SQLAlchemy engine.

    The store for the shared-database topology: Better Auth writes sessions into Postgres (or
    MySQL, or SQLite) and this reads them, one SELECT per lookup and no ORM anywhere -
    SQLAlchemy Core against a declared, quoted schema, so nothing here depends on your models,
    your metadata or your session lifecycle.

        engine = create_async_engine("postgresql+asyncpg://user:pw@host/db")
        store = SqlAlchemySessionStore(engine=engine)

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            await store.connect()   # optional: fail at startup, not at the first request
            yield

    **It never writes.** No INSERT, no UPDATE, no DELETE, no touch that refreshes an expiry -
    the Better Auth server owns every write there is, and a second author of the same rows is
    how a revoked session comes back. The invariant is asserted against the statements the
    engine actually emits, not against a promise. On Postgres the store's role needs `SELECT` on
    `session` and `user` and nothing else - the admin plugin's columns and a deployment's
    `additionalFields` are columns of `user`, not separate grants - plus `USAGE` on their schema,
    which `PUBLIC` holds on `public` by default, so only a non-default `schema=` needs it granted.
    Granting no more is what turns the read-only property into a database guarantee. A role
    granted less (`SELECT` on `session` alone) still passes `connect()`, since discovery reads the
    system catalog, and then answers every lookup with `AuthServiceUnavailable` - the uniform 401 -
    logging one WARNING per kind of failure (driver error class and SQLSTATE, never its text)
    until a lookup completes again.

    **The session and its user arrive together**, joined in one statement, so the happy path is
    one query and the record's `user` is already populated. `fetch_user_by_id` is there for
    callers that need a user on its own. Unset, `statement_timeout=` adds nothing: a lookup sends
    that one statement. Set, it sends two (the bound, then the lookup) and discovery sends three
    more (a probe, the bound, and their readback); counted from the engine's own events on the
    live lane.

    **The schema is read once, on first use** (or from `connect()`), and it decides two things.
    That every column a lookup needs is there - and if one is not, that is a
    `ConfigurationError` rather than a database error on every request. And whether the admin
    plugin's columns (`banned`, `banReason`, `banExpires`, `impersonatedBy`) exist, which is
    what makes them surface where they do and stay absent where they do not. A *default*
    better-auth column that is missing is a loud warning naming it; a missing admin column is
    silence, because that plugin is optional upstream.

    **Ids the database generates.** Discovery also reads the type of the id columns
    (`session.id`, `session.userId`, `session.impersonatedBy`, `user.id`). Where a deployment lets
    the database generate ids, an integer column's value is read as its decimal text and a uuid
    column's as lowercase hyphenated text - what Better Auth puts in its own JSON - so records,
    `Session.id` and `Session.raw` carry strings either way; `fetch_user_by_id` takes that same
    text and binds it as the column's type. A column of any other type is read as text, as
    before. Tested on SQLite (integer ids; uuids as text), where reflection never reports a uuid
    type: a SQLAlchemy `Uuid` column there reflects as `CHAR(32)` and is read as its stored text.

    **Timestamps.** Postgres `timestamptz` answers an aware `datetime` and is the tested path.
    SQLite and MySQL answer a naive one, because those columns carry no offset - it is read as
    UTC, which is what Better Auth wrote. A column holding local time would be misread by
    exactly its offset.

    **Every column of the two tables is read by default**, including a deployment's own
    `additionalFields`, so they reach the record's `payload` the same way they reach the Redis
    store's. That payload is handed to `parse_user`, so do not store a secret on the `user` or
    `session` table that a verified request should not see - a column added there is readable
    through the record.

    **Where the tables are not yours to shape**, `user_columns=` and `session_columns=` name the
    extra columns that may travel, and nothing else is selected. They are opt-in and change no
    default. What they never restrict is Better Auth's own set: the required columns are how a
    session is found at all, and the optional and admin ones carry `banned`, `banExpires` and
    `impersonatedBy` - a ban is this library's business, not the deployment's. A name the live
    table does not have is a `ConfigurationError` at discovery, beside the missing-column one.
    `RedisSessionStore` has no equivalent: it reads one stored JSON document, and a document has
    no SELECT to narrow.

    **A lookup that is cancelled or passes its deadline** (a client gone, `CookieVerifier`'s
    `lookup_timeout`) returns to its caller at once, and its database call is cancelled exactly
    once. The call runs on an asyncio task of its own for that reason: a cancellation delivered
    again and again, as anyio delivers it, would cut short the close SQLAlchemy runs on a
    cancelled statement, and with it the cancel request the driver sends the server - leaving the
    statement running there, holding a backend and any lock it waits on. Cancelled once, the
    driver asks the server to stop the statement and the connection is closed in order. Until
    that has happened the connection stays checked out, so the engine's pool bounds the calls
    winding down, and lookups that find it full wait for a connection and are refused at their
    own deadline. A call that has not wound down within 5 seconds (a server that stopped
    answering) is cancelled again every 5 seconds until it ends, which gives its connection's
    place back to the pool without waiting for the server. A server-side statement timeout
    shorter than `lookup_timeout` (Postgres `statement_timeout`, MySQL `max_execution_time`) is
    still the right setting: it ends a slow statement on the server whatever becomes of its
    client. And a lookup that finds no idle connection opens a new one inside its own deadline,
    so keep `lookup_timeout` well above the time a new connection takes.

    **A statement timeout of the store's own** (`statement_timeout=`, seconds, Postgres only) is
    that setting without touching the role or the pool the application lends: a role-level or
    engine-level timeout would bound every other statement the application runs as well. Set,
    every transaction the store opens - each lookup, and the schema read that `connect()` and the
    first lookup run - sets `SELECT set_config('statement_timeout', :ms, true)` first, the value
    rounded up to whole milliseconds (discovery sets its probe, below, just before it). The setting is transaction-local, so it ends with the
    `ROLLBACK` the store sends, and no other checkout of the pool ever sees it. For the store's
    own transactions it replaces a role-level or database-level value, even a shorter one. Keep it
    below `lookup_timeout`. A lookup the server ends is refused as above (`AuthServiceUnavailable`,
    one WARNING naming SQLSTATE 57014); a schema read it ends raises from `connect()` as any
    database error does. It bounds the statements after it in each transaction, not itself, the
    `ROLLBACK`, or what SQLAlchemy sends to open a connection. On an engine in `AUTOCOMMIT` the
    setting would end with the statement that made it, so the store refuses such an engine with a
    `ConfigurationError` before any lookup reaches the database: from the engine's options before
    every transaction, and from the setting read back at discovery. The readback is proven to be
    the store's own: discovery first sets a random probe, transaction-locally, in a custom setting
    of the library's (`fastapi_better_auth.discovery_probe`), and reads it back with the bound. So
    an application's own session-level value, even one equal to the store's, does not pass for
    it. Afterwards that setting reads as an empty string on the lent connection. Tested on
    asyncpg; the role needs no grant beyond the `SELECT` above. `SyncStoreAdapter` has no such option: give its
    role the timeout (`ALTER ROLE ... SET statement_timeout`), as for any other database.

    Args:
        engine: An `AsyncEngine`. Always injected, never built here: the pool, the TLS
            configuration and the lifecycle belong to the application, and this store must not
            close a pool it was lent. Needs the `[sqlalchemy]` extra and an async driver.
        session_table: The session table's name, for a deployment that renamed it upstream.
        user_table: The user table's name.
        schema: The database schema both tables live in, or `None` for the connection's default.
        session_columns: The extra session columns that may be selected, or `None` (the default)
            for every column. Better Auth's own columns are always selected; a single string is
            refused rather than iterated one character at a time.
        user_columns: The same for the user table - the columns beyond Better Auth's own that a
            verified request's `session.user` may carry.
        statement_timeout: Seconds, or `None` (the default) to send nothing of the kind. PostgreSQL
            only: a transaction-local `statement_timeout`, rounded up to whole milliseconds, set
            first in every transaction the store opens - each lookup and the schema read. Keep
            it below `CookieVerifier`'s `lookup_timeout`.

    Raises:
        ConfigurationError: If `sqlalchemy` is not installed, if `engine` is not an
            `AsyncEngine`, if either table name is blank or the two are the same, if either
            allow-list is not a sequence of distinct non-blank names, if `statement_timeout` is not
            a positive, finite number of seconds within what Postgres accepts or is set on an
            engine that is not PostgreSQL, or - from `connect()` or the first lookup - if the
            schema cannot answer a lookup at all, if an allow-list names a column the table does
            not have, or if `statement_timeout` is set on an engine in `AUTOCOMMIT` (from a
            lookup too, when the engine was switched after `connect()`).
    """

    def __init__(
        self,
        *,
        engine: AsyncEngine,
        session_table: str = "session",
        user_table: str = "user",
        schema: str | None = None,
        session_columns: Sequence[str] | None = None,
        user_columns: Sequence[str] | None = None,
        statement_timeout: float | None = None,
    ) -> None:
        super().__init__(
            adapter="SqlAlchemySessionStore",
            session_table=session_table,
            user_table=user_table,
            schema=schema,
            session_columns=session_columns,
            user_columns=user_columns,
        )
        self._engine = self._sql.validated_async_engine(engine)
        self._timeout = self._sql.bounded_engine(
            self._engine, validated_statement_timeout(statement_timeout)
        )
        self._handoff = TaskHandoff()

    async def _columns(self) -> Discovered:
        return await self._handoff.run(self._inspected)

    async def _inspected(self) -> Discovered:
        connection = await self._engine.connect()
        try:
            await self._bounded(connection, confirm=True)
            return await connection.run_sync(self._reflected)
        finally:
            await _returned(connection)

    async def _select(self, statement: Select[Any], params: Mapping[str, Any]) -> Rows:
        # Only the database call is handed off. Its error is translated here, in the caller's
        # task, so an abandoned call that fails late has nobody to report to and trips no latch.
        try:
            return await self._handoff.run(partial(self._queried, statement, dict(params)))
        except self._sql.SQLAlchemyError as exc:
            failure = self._unavailable(exc, params)
        # Raised outside the `except` so no `__context__` links back to the DBAPIError whose
        # str() embeds the token; `from None` clears `__cause__` as well (A1).
        raise failure from None

    async def _queried(self, statement: Select[Any], params: dict[str, Any]) -> Rows:
        connection = await self._engine.connect()
        try:
            await self._bounded(connection)
            return self._sql.rows(await connection.execute(statement, params))
        finally:
            await _returned(connection)

    async def _bounded(self, connection: AsyncConnection, *, confirm: bool = False) -> None:
        """Open the transaction with the store's bound, when it has one; else send nothing.

        Sent before any read in every transaction the store opens, so every read after it is
        bounded, and transaction-local, so it ends with the `ROLLBACK` `_returned` sends. On an
        engine in `AUTOCOMMIT` it would end with itself, so that engine is refused: from its
        options before every transaction, and - for discovery, which every lookup waits on - by
        reading the setting back in the same transaction, which also sees an engine built so.
        Discovery sets a fresh probe first and reads it back with the bound: the probe proves the
        readback ran in the transaction that set the bound (`confirmed_bound`).
        """
        if self._timeout is None:
            return
        self._sql.refuse_autocommit(self._engine)
        probe = self._sql.new_probe() if confirm else None
        if probe is not None:
            await connection.execute(self._sql.timeout_statement(), self._sql.probe_params(probe))
        await connection.execute(
            self._sql.timeout_statement(), self._sql.timeout_params(self._timeout)
        )
        if probe is not None:
            found = await connection.execute(self._sql.readback_statement())
            self._sql.confirmed_bound(found.all(), self._timeout, probe)


async def _returned(connection: AsyncConnection) -> None:
    """Close `connection` here, on the handed-off task, so a cancellation of the call reaches it.

    Closing sends a `ROLLBACK` on the way back to the pool, and a server can stop answering right
    there. `async with engine.connect()` would run that close where no cancellation reaches it -
    SQLAlchemy 2.1 swallows them until the close is done, 2.0 orphans it - so the call's one
    cancellation and every backstop one would pass it by while it held its connection for as long
    as the server stayed silent. Awaited here, the cancellation lands in the `ROLLBACK` and
    SQLAlchemy invalidates the connection.

    A close that fails - cancelled, or raising - is closed once more before its exception leaves.
    On SQLAlchemy 2.0 a close whose `ROLLBACK` raises leaves before the pool's check-in, and the
    slot would be lost for good; 2.1 checks in from a `finally`, and there the second close does
    nothing. (Below 2.0.38, which the extra no longer allows, a close whose terminate the backstop
    cut short lost its slot the same way.) The second close may try the server again, and the
    call's deadline and the backstop bound that as they bound everything else here. Its outcome
    is dropped unread: the first exception is what leaves, to `_select`'s translation or as the
    cancellation, and nothing of the second goes anywhere.
    """
    try:
        await connection.close()
    except (Exception, asyncio.CancelledError):
        await _closed_again(connection)
        raise


async def _closed_again(connection: AsyncConnection) -> None:
    try:
        await connection.close()
    except (Exception, asyncio.CancelledError):  # noqa: BLE001 - dropped; see `_returned`
        return


class SyncStoreAdapter(_CoreStore):
    """`SqlAlchemySessionStore` for a deployment whose database has no async driver.

    Same tables, same statements, same records - run on a worker thread through
    `anyio.to_thread`, because a synchronous DBAPI call made on the event loop stops every
    other task in the process for the length of the round trip. That is the whole difference:

        engine = create_engine("postgresql+psycopg2://user:pw@host/db")
        store = SyncStoreAdapter(engine=engine)

    Reach for it when the driver you already run in production is a synchronous one and adding
    a second, async driver to the deployment is the larger change. `SqlAlchemySessionStore` is
    the better answer wherever an async driver is available: a thread per lookup is real
    overhead, and the engine's pool has to be sized for those threads as well as for requests.

    Because it needs no async driver, it runs on **both** anyio backends - asyncio and trio.

    Every rule `SqlAlchemySessionStore` publishes holds here unchanged: read-only (so the same
    `SELECT`-only grant on the two tables is all its role needs), one statement for the session
    and its user, the schema discovered once, admin columns surfaced where they exist, naive
    timestamps read as UTC, and the same opt-in `user_columns` / `session_columns` allow-lists
    over the extra columns a deployment's own tables carry.

    **Concurrent lookups are bounded by this adapter, not by the process-wide thread pool.** Each
    lookup runs its DBAPI call on a worker thread that checks out one pooled connection; without a
    bound, a flood of concurrent (or cancelled) lookups would exhaust the connection pool and error
    a legitimate request with a checkout timeout. The adapter holds its own `anyio.CapacityLimiter`,
    sized to the engine's pool where it is introspectable (a `QueuePool`'s size plus overflow) so
    the *limiter* is where excess lookups queue - cheap and cancellable - rather than the pool.

    **The bound is on worker threads, for each thread's whole life**, on asyncio and trio alike.
    A cancelled lookup (a client gone, `CookieVerifier`'s `lookup_timeout`) returns to its caller
    at once, but a thread cannot be interrupted: the DBAPI call it started runs on, holding its
    pooled connection, and the thread keeps its slot until that call ends. So while the database
    is not answering, this adapter never holds more than `max_concurrency` threads and
    connections; further lookups wait for a slot without starting a thread, and are refused at
    their own deadline. Those slots come back only when the database answers or the driver gives
    up, so give the database a reason to: a server-side statement timeout (Postgres
    `statement_timeout`, MySQL `max_execution_time`) and a driver connect/read timeout end an
    abandoned call, and an engine `pool_timeout` shorter than the request deadline turns a
    checkout wait into an error rather than a hang.

    Args:
        engine: A synchronous `Engine`, injected. Its pool needs room for the worker threads
            this adapter uses, which is one per concurrent lookup.
        session_table: The session table's name.
        user_table: The user table's name.
        schema: The database schema both tables live in, or `None`.
        session_columns: The extra session columns that may be selected, or `None` (the default)
            for every column. Better Auth's own columns are always selected.
        user_columns: The same for the user table.
        max_concurrency: The most lookups that may run on worker threads at once. `None` (the
            default) sizes the bound to the engine's connection pool where that is introspectable,
            and otherwise to a conservative default; pass a positive int to set it explicitly.

    Raises:
        ConfigurationError: If `sqlalchemy` is not installed, if `engine` is an `AsyncEngine` or
            not an `Engine` at all, if either table name is blank or the two are the same, if
            either allow-list is not a sequence of distinct non-blank names, if `max_concurrency`
            is not a positive int, or - at discovery - if an allow-list names a column the table
            does not have.
    """

    def __init__(
        self,
        *,
        engine: Engine,
        session_table: str = "session",
        user_table: str = "user",
        schema: str | None = None,
        session_columns: Sequence[str] | None = None,
        user_columns: Sequence[str] | None = None,
        max_concurrency: int | None = None,
    ) -> None:
        super().__init__(
            adapter="SyncStoreAdapter",
            session_table=session_table,
            user_table=user_table,
            schema=schema,
            session_columns=session_columns,
            user_columns=user_columns,
        )
        self._engine = self._sql.validated_sync_engine(engine)
        self._limiter_tokens = _limiter_tokens(
            self._engine, _validated_concurrency(max_concurrency)
        )
        self._limiter: anyio.CapacityLimiter | None = None

    async def _columns(self) -> Discovered:
        return await run_in_worker(self._get_limiter(), self._inspected)

    def _inspected(self) -> Discovered:
        with self._engine.connect() as connection:
            return self._reflected(connection)

    async def _select(self, statement: Select[Any], params: Mapping[str, Any]) -> Rows:
        # A cancellation frees the async caller at once; the DBAPI call keeps running on its worker
        # thread, which keeps its limiter token (and so its connection) until it finishes.
        return await run_in_worker(
            self._get_limiter(), partial(self._queried, statement, dict(params))
        )

    def _get_limiter(self) -> anyio.CapacityLimiter:
        # Created lazily on first use, INSIDE the running loop: unlike anyio.Lock, a
        # CapacityLimiter binds to the backend at construction, and the adapter is built in
        # synchronous setup. The None-check and set share no await, so no two callers race it.
        limiter = self._limiter
        if limiter is None:
            limiter = anyio.CapacityLimiter(self._limiter_tokens)
            self._limiter = limiter
        return limiter

    def _queried(self, statement: Select[Any], params: Mapping[str, Any]) -> Rows:
        try:
            with self._engine.connect() as connection:
                return self._sql.rows(connection.execute(statement, dict(params)))
        except self._sql.SQLAlchemyError as exc:
            failure = self._unavailable(exc, params)
        raise failure from None


def _validated_concurrency(max_concurrency: object) -> int | None:
    if max_concurrency is None:
        return None
    if isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int):
        raise ConfigurationError(
            "SyncStoreAdapter(max_concurrency=...) must be a positive int or None (size the"
            f" bound to the engine's pool); got {type(max_concurrency).__name__}."
        )
    if max_concurrency < 1:
        raise ConfigurationError(
            "SyncStoreAdapter(max_concurrency=...) must be at least 1; a bound of"
            f" {max_concurrency} would let no lookup run."
        )
    return max_concurrency


def _limiter_tokens(engine: Engine, max_concurrency: int | None) -> int:
    """The adapter's worker-thread bound: the caller's if given, else the engine's pool size."""
    return max_concurrency if max_concurrency is not None else _pool_ceiling(engine)


def _pool_ceiling(engine: Engine) -> int:
    """How many connections the engine's pool can hand out at once, or a conservative default.

    Sizing the limiter to this is what makes the *limiter*, not the pool, the point excess lookups
    queue at: a `QueuePool` states its size and overflow, so the bound matches what the pool can
    serve and a flood waits on the limiter instead of exhausting the pool. A pool that cannot state
    a size (`NullPool`, `StaticPool`) falls back to `DEFAULT_MAX_CONCURRENCY`.
    """
    pool = getattr(engine, "pool", None)
    size = getattr(pool, "size", None)
    if not callable(size):
        return DEFAULT_MAX_CONCURRENCY
    try:
        base = size()
    except Exception:  # noqa: BLE001 - an exotic pool that cannot answer falls back to the default
        return DEFAULT_MAX_CONCURRENCY
    if not isinstance(base, int) or base < 1:
        return DEFAULT_MAX_CONCURRENCY
    overflow = getattr(pool, "_max_overflow", 0)
    extra = overflow if isinstance(overflow, int) and overflow > 0 else 0
    return base + extra
