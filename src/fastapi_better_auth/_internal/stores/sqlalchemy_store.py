"""The two SQLAlchemy stores: one for an async engine, one for the shops that have neither."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

import anyio
from anyio.to_thread import run_sync

from ..errors import ConfigurationError
from .records import StoredSession, StoredUser

if TYPE_CHECKING:
    from sqlalchemy import Connection, Engine, Select
    from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

    from .sqlalchemy_core import Columns, Plan

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
        self, *, adapter: str, session_table: str, user_table: str, schema: str | None
    ) -> None:
        self._sql = _core(adapter)
        self._schema = schema
        self._names = self._sql.validated_names(session_table, user_table)
        self._lock = anyio.Lock()
        self._plan: Plan | None = None

    async def connect(self) -> None:
        """Read the live schema now, rather than on whichever request arrives first.

        Optional but recommended: call it from a lifespan handler and a database whose Better
        Auth migration never ran stops the application from starting, instead of answering the
        first authenticated request with a `ConfigurationError`. Idempotent, and it does only
        what the first lookup would have done anyway.

        Raises:
            ConfigurationError: If a table is absent, or is missing a column every lookup reads.
        """
        await self._ready()

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        """The session stored under this raw token, with its user, in one statement.

        See `SessionStore.fetch_session_by_token`. A blank token never reaches the database.
        """
        if not token.strip():
            return None
        plan = await self._ready()
        found = await self._select(plan.session_statement, {self._sql.TOKEN_PARAM: token})
        return self._sql.session_from(found, plan, token)

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        """The user row with this id. See `SessionStore.fetch_user_by_id`."""
        if not user_id.strip():
            return None
        plan = await self._ready()
        found = await self._select(plan.user_statement, {self._sql.USER_ID_PARAM: user_id})
        return self._sql.user_from(found, plan, user_id, check_identity=True)

    async def _ready(self) -> Plan:
        """Discovery happens once, whoever gets there first.

        The statement depends on which columns exist - the admin plugin's are surfaced only
        where they were created - so this is not a cache in front of a fixed query, it *is* the
        query. The lock is what stops a burst of first requests each inspecting the schema.
        """
        plan = self._plan
        if plan is not None:
            return plan
        session, user = self._names
        async with self._lock:
            if self._plan is None:
                self._plan = self._sql.plan_for(session, user, self._schema, await self._columns())
            return self._plan

    def _reflected(self, connection: Connection) -> dict[str, tuple[str, ...] | None]:
        return self._sql.reflected(connection, self._names, self._schema)

    @abstractmethod
    async def _columns(self) -> Columns:
        """The columns each table has, read however this flavour reaches the database."""

    @abstractmethod
    async def _select(self, statement: Select[Any], params: Mapping[str, Any]) -> Rows:
        """Run one statement and materialize its rows before the connection closes."""


class SqlAlchemySessionStore(_CoreStore):
    """Better Auth's `session` and `user` tables, read through an async SQLAlchemy engine.

    The store for the shared-database topology: Better Auth writes sessions into Postgres (or
    MySQL, or SQLite) and this reads them, one statement per lookup and no ORM anywhere -
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
    engine actually emits, not against a promise.

    **The session and its user arrive together**, joined in one statement, so the happy path is
    a single round trip and the record's `user` is already populated. `fetch_user_by_id` is
    there for callers that need a user on its own.

    **The schema is read once, on first use** (or from `connect()`), and it decides two things.
    That every column a lookup needs is there - and if one is not, that is a
    `ConfigurationError` rather than a database error on every request. And whether the admin
    plugin's columns (`banned`, `banReason`, `banExpires`, `impersonatedBy`) exist, which is
    what makes them surface where they do and stay absent where they do not. A *default*
    better-auth column that is missing is a loud warning naming it; a missing admin column is
    silence, because that plugin is optional upstream.

    **Timestamps.** Postgres `timestamptz` answers an aware `datetime` and is the tested path.
    SQLite and MySQL answer a naive one, because those columns carry no offset - it is read as
    UTC, which is what Better Auth wrote. A column holding local time would be misread by
    exactly its offset.

    **Every column of the two tables is read**, including a deployment's own `additionalFields`,
    so they reach the record's `payload` the same way they reach the Redis store's. That payload
    is handed to `parse_user`, so do not store a secret on the `user` or `session` table that a
    verified request should not see - a column added there is readable through the record.

    Args:
        engine: An `AsyncEngine`. Always injected, never built here: the pool, the TLS
            configuration and the lifecycle belong to the application, and this store must not
            close a pool it was lent. Needs the `[sqlalchemy]` extra and an async driver.
        session_table: The session table's name, for a deployment that renamed it upstream.
        user_table: The user table's name.
        schema: The database schema both tables live in, or `None` for the connection's default.

    Raises:
        ConfigurationError: If `sqlalchemy` is not installed, if `engine` is not an
            `AsyncEngine`, if either table name is blank or the two are the same, or - from
            `connect()` or the first lookup - if the schema cannot answer a lookup at all.
    """

    def __init__(
        self,
        *,
        engine: AsyncEngine,
        session_table: str = "session",
        user_table: str = "user",
        schema: str | None = None,
    ) -> None:
        super().__init__(
            adapter="SqlAlchemySessionStore",
            session_table=session_table,
            user_table=user_table,
            schema=schema,
        )
        self._engine = self._sql.validated_async_engine(engine)

    async def _columns(self) -> Columns:
        async with self._engine.connect() as connection:
            return await self._inspected(connection)

    async def _inspected(self, connection: AsyncConnection) -> Columns:
        return await connection.run_sync(self._reflected)

    async def _select(self, statement: Select[Any], params: Mapping[str, Any]) -> Rows:
        try:
            async with self._engine.connect() as connection:
                return self._sql.rows(await connection.execute(statement, dict(params)))
        except self._sql.SQLAlchemyError:
            failure = self._sql.lookup_unavailable(params)
        # Raised outside the `except` so no `__context__` links back to the DBAPIError whose
        # str() embeds the token; `from None` clears `__cause__` as well (A1).
        raise failure from None


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

    Every rule `SqlAlchemySessionStore` publishes holds here unchanged: read-only, one statement
    for the session and its user, the schema discovered once, admin columns surfaced where they
    exist, naive timestamps read as UTC.

    **Concurrent lookups are bounded by this adapter, not by the process-wide thread pool.** Each
    lookup runs its DBAPI call on a worker thread that checks out one pooled connection; without a
    bound, a flood of concurrent (or cancelled) lookups would exhaust the connection pool and error
    a legitimate request with a checkout timeout. The adapter holds its own `anyio.CapacityLimiter`,
    sized to the engine's pool where it is introspectable (a `QueuePool`'s size plus overflow) so
    the *limiter* is where excess lookups queue - cheap and cancellable - rather than the pool. A
    cancelled lookup returns to the caller promptly, but the DBAPI call it started still runs to
    completion on its worker thread and its connection returns to the pool only when it finishes.

    Args:
        engine: A synchronous `Engine`, injected. Its pool needs room for the worker threads
            this adapter uses, which is one per concurrent lookup.
        session_table: The session table's name.
        user_table: The user table's name.
        schema: The database schema both tables live in, or `None`.
        max_concurrency: The most lookups that may run on worker threads at once. `None` (the
            default) sizes the bound to the engine's connection pool where that is introspectable,
            and otherwise to a conservative default; pass a positive int to set it explicitly.

    Raises:
        ConfigurationError: If `sqlalchemy` is not installed, if `engine` is an `AsyncEngine` or
            not an `Engine` at all, if either table name is blank or the two are the same, or if
            `max_concurrency` is not a positive int.
    """

    def __init__(
        self,
        *,
        engine: Engine,
        session_table: str = "session",
        user_table: str = "user",
        schema: str | None = None,
        max_concurrency: int | None = None,
    ) -> None:
        super().__init__(
            adapter="SyncStoreAdapter",
            session_table=session_table,
            user_table=user_table,
            schema=schema,
        )
        self._engine = self._sql.validated_sync_engine(engine)
        self._limiter = anyio.CapacityLimiter(
            _limiter_tokens(self._engine, _validated_concurrency(max_concurrency))
        )

    async def _columns(self) -> Columns:
        return await run_sync(self._inspected, abandon_on_cancel=True, limiter=self._limiter)

    def _inspected(self) -> Columns:
        with self._engine.connect() as connection:
            return self._reflected(connection)

    async def _select(self, statement: Select[Any], params: Mapping[str, Any]) -> Rows:
        # abandon_on_cancel frees the async caller on cancellation; the DBAPI call keeps running on
        # its worker thread and its connection returns to the pool only when it finishes. The
        # limiter bounds concurrent threads (hence checked-out connections) to the adapter's own.
        return await run_sync(
            self._queried, statement, dict(params), abandon_on_cancel=True, limiter=self._limiter
        )

    def _queried(self, statement: Select[Any], params: Mapping[str, Any]) -> Rows:
        try:
            with self._engine.connect() as connection:
                return self._sql.rows(connection.execute(statement, dict(params)))
        except self._sql.SQLAlchemyError:
            failure = self._sql.lookup_unavailable(params)
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
