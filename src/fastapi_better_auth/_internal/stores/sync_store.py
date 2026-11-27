"""`SyncStoreAdapter`: the SQLAlchemy store for a synchronous engine, run on worker threads."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from functools import partial
from typing import TYPE_CHECKING, Any

import anyio

from ..errors import ConfigurationError
from .sqlalchemy_store import CoreStore, Rows
from .statement_timeout import validated_statement_timeout
from .thread_handoff import run_in_worker

if TYPE_CHECKING:
    from sqlalchemy import Connection, Engine, Select

    from .sqlalchemy_core import Discovered

DEFAULT_MAX_CONCURRENCY = 8
"""Worker-thread ceiling for a pool whose capacity cannot be read (`NullPool`, `StaticPool`).

A conservative bound on concurrent DB threads when the engine's pool does not state a size, so
a flood of cancelled lookups cannot open an unbounded number of connections. A `QueuePool` (the
production default) is introspectable and the limiter is sized to it instead - see `_pool_ceiling`.
"""


class SyncStoreAdapter(CoreStore):
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
    up, so give the database a reason to: a server-side statement timeout (`statement_timeout=`
    below on Postgres, `max_execution_time` on MySQL) and the driver's own timeouts end an
    abandoned call, and an engine `pool_timeout` shorter than the request deadline turns a
    checkout wait into an error rather than a hang.

    **A statement timeout of the adapter's own** (`statement_timeout=`, seconds, Postgres only) is
    `SqlAlchemySessionStore`'s option: the same meaning, the same statements, the same refusals.
    Set, every transaction the adapter opens - each lookup, and the schema read - sends
    `SELECT set_config('statement_timeout', :ms, true)` before it reads anything, and the schema
    read sets its probe first and reads both back, so an engine in `AUTOCOMMIT` is refused with a
    `ConfigurationError`. Here it is what gives a slot back. A lookup abandoned at its deadline
    keeps its thread, its slot and its pooled connection until the DBAPI call returns, and the
    server ends that call at the bound: the slot and the connection come back then, while
    whatever held the statement (a lock, a load) is still there. It ends only a statement that a
    reachable server is running. A call stuck opening a connection, or waiting on a network path
    that has gone dead, never reaches the server, so no server setting ends it; bound that with
    the driver's own settings (libpq's `connect_timeout`, TCP keepalives and `tcp_user_timeout`,
    which psycopg and psycopg2 both take). Unset, the adapter sends nothing it did not send
    before. Tested on psycopg (3) and psycopg2, on asyncio and trio; the role needs no grant
    beyond the `SELECT` above.

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
        statement_timeout: Seconds, or `None` (the default) to send nothing of the kind. PostgreSQL
            only, as for `SqlAlchemySessionStore`: a transaction-local `statement_timeout`,
            rounded up to whole milliseconds, set before any read in every transaction the adapter
            opens - each lookup and the schema read, where a probe is set just before it. Keep it
            below `CookieVerifier`'s `lookup_timeout`.

    Raises:
        ConfigurationError: If `sqlalchemy` is not installed, if `engine` is an `AsyncEngine` or
            not an `Engine` at all, if either table name is blank or the two are the same, if
            either allow-list is not a sequence of distinct non-blank names, if `max_concurrency`
            is not a positive int, if `statement_timeout` is not a positive, finite number of
            seconds within what Postgres accepts or is set on an engine that is not PostgreSQL,
            or - from `connect()` or the first lookup - if an allow-list names a column the table
            does not have, or if `statement_timeout` is set on an engine in `AUTOCOMMIT` (from a
            lookup too, when the engine was switched after `connect()`).
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
        statement_timeout: float | None = None,
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
        self._timeout = self._sql.bounded_engine(
            self._engine, validated_statement_timeout(statement_timeout)
        )
        self._limiter_tokens = _limiter_tokens(
            self._engine, _validated_concurrency(max_concurrency)
        )
        self._limiter: anyio.CapacityLimiter | None = None

    async def _columns(self) -> Discovered:
        return await run_in_worker(self._get_limiter(), self._inspected)

    def _inspected(self) -> Discovered:
        with self._engine.connect() as connection:
            self._bounded(connection, confirm=True)
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
                self._bounded(connection)
                return self._sql.rows(connection.execute(statement, dict(params)))
        except self._sql.SQLAlchemyError as exc:
            failure = self._unavailable(exc, params)
        raise failure from None

    def _bounded(self, connection: Connection, *, confirm: bool = False) -> None:
        """Set the adapter's bound on the transaction just opened, when it has one; else send
        nothing. `SqlAlchemySessionStore._bounded`'s rule, run on the worker thread.

        Sent before any read in every transaction the adapter opens, and transaction-local, so it
        ends with the `ROLLBACK` the connection sends on its way back to the pool. An engine in
        `AUTOCOMMIT` is refused: from its options before every transaction, and at discovery from
        the probe and the bound read back in the same transaction (`confirmed_bound`).
        """
        if self._timeout is None:
            return
        self._sql.refuse_autocommit(self._engine)
        probe = self._sql.new_probe() if confirm else None
        for params in self._sql.settings_in_order(self._timeout, probe):
            connection.execute(self._sql.timeout_statement(), params)
        if probe is not None:
            found = connection.execute(self._sql.readback_statement())
            self._sql.confirmed_bound(found.all(), self._timeout, probe)


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
