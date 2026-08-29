"""Everything in this package that touches SQLAlchemy - which is why nothing imports it eagerly.

`sqlalchemy` is an optional extra, so importing `fastapi_better_auth` must work without it. This
module is the one place the library names it, and `sqlalchemy_store` reaches it through a guarded
import at construction time - the same shape `httpx_transports` uses for its own extra.

Better Auth's schema as SQLAlchemy Core sees it: two tables, quoted, and two SELECTs.

Declared rather than reflected. Reflection would make the statement depend on a round trip
whose result nobody reviewed, and it cannot tell a column better-auth added from one this
deployment did - which is precisely the difference `plan_for` exists to make. What *is* read
from the live database is the column list, once, so that a query never names a column that is
not there and the admin plugin's fields are surfaced only where they exist.

Identifiers are camelCase and one table is called `user`, which is a reserved word in Postgres.
SQLAlchemy quotes both for us because it quotes anything that is not a plain lowercase
non-reserved name - the statements are asserted against, so the day that changes is a red test
and not a syntax error in production.
"""

from __future__ import annotations

import hmac
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    Connection,
    DateTime,
    Engine,
    MetaData,
    Select,
    Table,
    Text,
    bindparam,
    inspect,
    select,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from ..errors import AuthServiceUnavailable, ConfigurationError
from ..reasons import fingerprint
from .diagnostics import drifted, unusable
from .records import StoredSession, StoredUser
from .upstream import as_db_flag, as_moment, as_text

# Re-exported so `sqlalchemy_store` can name the exception class in an `except` without importing
# `sqlalchemy` itself - that module has to import cleanly when the extra is absent (D-146).
__all__ = ["SQLAlchemyError"]

SESSION_REQUIRED: tuple[str, ...] = ("id", "token", "expiresAt", "userId")
SESSION_OPTIONAL: tuple[str, ...] = ("createdAt", "updatedAt", "ipAddress", "userAgent")
SESSION_ADMIN: tuple[str, ...] = ("impersonatedBy",)
USER_REQUIRED: tuple[str, ...] = ("id",)
USER_OPTIONAL: tuple[str, ...] = (
    "name",
    "email",
    "emailVerified",
    "image",
    "createdAt",
    "updatedAt",
)
USER_ADMIN: tuple[str, ...] = ("role", "banned", "banReason", "banExpires")

SESSION_COLUMNS = SESSION_REQUIRED + SESSION_OPTIONAL + SESSION_ADMIN
USER_COLUMNS = USER_REQUIRED + USER_OPTIONAL + USER_ADMIN
KNOWN = frozenset(SESSION_COLUMNS + USER_COLUMNS)

MOMENTS = frozenset({"expiresAt", "createdAt", "updatedAt", "banExpires"})
# `emailVerified` keeps SQLAlchemy's `Boolean`, which coerces the 0/1 SQLite/MySQL store back to
# a bool for the payload. `banned` deliberately does NOT: it is promoted to the record and a
# security decision keys on it, so it is read raw and validated by `as_db_flag` (A3), which lets
# a malformed value be a miss instead of a coerced `True`.
TYPED_BOOL = frozenset({"emailVerified"})
RAW_FLAGS = frozenset({"banned"})

SESSION_PREFIX = "s_"
USER_PREFIX = "u_"
TOKEN_PARAM = "token"
USER_ID_PARAM = "user_id"
ROW_LIMIT = 2
"""Two, so that a second row is *seen* rather than silently discarded by a `LIMIT 1`.

`session.token` carries a unique constraint upstream, so a second row means the constraint is
not there - a hand-rolled migration, a copied table - and picking one of two sessions at random
is not something this library will do. Two rows is a miss.
"""

MISSING_TABLE = (
    "table {table} does not exist in the database this store was pointed at. Either the Better"
    " Auth migration has not been run against it, or the table is named something else - pass"
    " session_table= / user_table= (and schema=) to say so."
)
MISSING_REQUIRED = (
    "table {table} is missing {columns}, which this store reads on every lookup. A session"
    " cannot be found without them, so every request would fail at the database instead of"
    " here. Run the Better Auth migration, or point the store at the table that has them."
)
BLANK_NAME = "{parameter} must be a non-empty table name; got {value!r}."
SAME_NAME = "session_table and user_table are both {value!r}; they name two different tables."
WRONG_ENGINE = "engine must be a SQLAlchemy {expected}; got {actual}. {advice}"
ASYNC_ADVICE = (
    "Build one with create_async_engine(...) and an async driver (postgresql+asyncpg,"
    " postgresql+psycopg, mysql+asyncmy), or use SyncStoreAdapter if your deployment only has a"
    " synchronous engine."
)
SYNC_ADVICE = (
    "Build one with create_engine(...). If you already have an AsyncEngine, use"
    " SqlAlchemySessionStore instead - it needs no worker thread."
)


Columns = Mapping[str, "tuple[str, ...] | None"]
"""Each table's columns once discovered, in the database's own order; `None` = no such table."""


@dataclass(frozen=True)
class Plan:
    """Which columns this database actually has, and the two statements that read them."""

    session_columns: tuple[str, ...]
    user_columns: tuple[str, ...]
    session_statement: Select[Any]
    user_statement: Select[Any]


def validated_name(parameter: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(BLANK_NAME.format(parameter=parameter, value=value))
    return value


def validated_names(session_table: object, user_table: object) -> tuple[str, str]:
    """Checked at construction, before anything is built out of them or asked of a database."""
    session_name = validated_name("session_table", session_table)
    user_name = validated_name("user_table", user_table)
    if session_name == user_name:
        raise ConfigurationError(SAME_NAME.format(value=session_name))
    return session_name, user_name


def _column(name: str) -> Column[Any]:
    """Typed where this library knows the type, and deliberately untyped where it does not.

    An unrecognized name is an `additionalFields` entry, or a column somebody's own migration
    added. It gets SQLAlchemy's `NullType`, which applies no result processing at all, so
    whatever the driver hands back reaches the payload unchanged - the only honest treatment of
    a column whose type is the deployment's business rather than ours.
    """
    if name in MOMENTS:
        return Column(name, DateTime(timezone=True))
    if name in TYPED_BOOL:
        return Column(name, Boolean)
    if name in KNOWN and name not in RAW_FLAGS:
        return Column(name, Text)
    return Column(name)


def plan_for(session_table: str, user_table: str, schema: str | None, present: Columns) -> Plan:
    """Decide what to select, refusing a schema no lookup could work against.

    Three outcomes, and the difference between them is the whole point. An absent *table*, or a
    missing column this store reads on every lookup, is a `ConfigurationError` while the
    application is being built - a store that cannot find a session cannot fail safe at request
    time, it can only fail at the database on every request. A missing *optional* column is a
    warning naming it: the store still works, the field is simply absent from every record. A
    missing *admin* column is neither, because the admin plugin is optional upstream and saying
    so on every boot would train an operator to ignore the line that matters.

    Columns this library has never heard of are selected too, after the ones it knows and in the
    database's own order, so a deployment's `additionalFields` reach the payload the same way
    they reach the Redis store's - which reads the whole stored object and could not drop them
    if it tried. Two adapters behind one Protocol answering different payloads for the same
    session is a difference nobody would see until it mattered.
    """
    session_columns = _accepted(
        session_table, present, SESSION_REQUIRED, SESSION_OPTIONAL, SESSION_ADMIN
    )
    user_columns = _accepted(user_table, present, USER_REQUIRED, USER_OPTIONAL, USER_ADMIN)
    metadata = MetaData(schema=schema)
    session = Table(session_table, metadata, *(_column(name) for name in session_columns))
    user = Table(user_table, metadata, *(_column(name) for name in user_columns))
    return Plan(
        session_columns=session_columns,
        user_columns=user_columns,
        session_statement=_session_statement(session, user, session_columns, user_columns),
        user_statement=_user_statement(user, user_columns),
    )


def _accepted(
    table: str,
    present: Columns,
    required: tuple[str, ...],
    optional: tuple[str, ...],
    admin: tuple[str, ...],
) -> tuple[str, ...]:
    columns = present.get(table)
    if columns is None:
        raise ConfigurationError(MISSING_TABLE.format(table=table))
    absent = tuple(name for name in required if name not in columns)
    if absent:
        raise ConfigurationError(MISSING_REQUIRED.format(table=table, columns=", ".join(absent)))
    drift = tuple(name for name in optional if name not in columns)
    if drift:
        drifted(table, drift)
    known = required + tuple(name for name in optional + admin if name in columns)
    return known + tuple(name for name in columns if name not in known)


def _session_statement(
    session: Table, user: Table, session_columns: tuple[str, ...], user_columns: tuple[str, ...]
) -> Select[Any]:
    """One statement, one round trip: the session and its user, joined.

    Labelled because both tables carry `id`, `createdAt` and `updatedAt`, and a result mapping
    with two `id` keys resolves to whichever the driver happened to put last.
    """
    labelled = [session.c[name].label(f"{SESSION_PREFIX}{name}") for name in session_columns]
    labelled += [user.c[name].label(f"{USER_PREFIX}{name}") for name in user_columns]
    return (
        select(*labelled)
        .select_from(session.join(user, session.c["userId"] == user.c["id"]))
        .where(session.c["token"] == bindparam(TOKEN_PARAM))
        .limit(ROW_LIMIT)
    )


def _user_statement(user: Table, user_columns: tuple[str, ...]) -> Select[Any]:
    labelled = [user.c[name].label(f"{USER_PREFIX}{name}") for name in user_columns]
    return select(*labelled).where(user.c["id"] == bindparam(USER_ID_PARAM)).limit(ROW_LIMIT)


def session_from(rows: Sequence[Mapping[str, Any]], plan: Plan, token: str) -> StoredSession | None:
    """Build a record from the joined row, or answer a miss and say why in the log."""
    row = _only(rows, "session", token)
    if row is None:
        return None
    payload = _payload(row, plan.session_columns, SESSION_PREFIX)
    user = user_from(rows, plan, token)
    expires_at = as_moment(payload.get("expiresAt"))
    user_id = as_text(payload.get("userId"))
    stored_token = as_text(payload.get("token"))
    if expires_at is None or user_id is None or stored_token is None or user is None:
        unusable("session", _why(expires_at, user_id, stored_token, user), token)
        return None
    # Equality was delegated to `WHERE token = :token`, i.e. to the DB collation. A
    # case/accent/pad-insensitive collation (MySQL's `utf8mb4_0900_ai_ci` default) folds a
    # different token onto this row, so the stored token is checked against the presented one -
    # constant-time, the same guard the Redis store calls the one that matters (A2, D-160).
    if not hmac.compare_digest(stored_token.encode("utf-8"), token.encode("utf-8")):
        unusable("session", "it names a different session than the token it was found under", token)
        return None
    return StoredSession(
        token=stored_token,
        user_id=user_id,
        expires_at=expires_at,
        payload=payload,
        user=user,
        impersonated_by=as_text(payload.get("impersonatedBy")),
    )


def user_from(rows: Sequence[Mapping[str, Any]], plan: Plan, subject: str) -> StoredUser | None:
    row = _only(rows, "user", subject)
    if row is None:
        return None
    payload = _payload(row, plan.user_columns, USER_PREFIX)
    identifier = as_text(payload.get("id"))
    if identifier is None:
        unusable("user", "its id is null or blank", subject)
        return None
    raw_banned = payload.get("banned")
    banned = as_db_flag(raw_banned)
    if raw_banned is not None and banned is None:
        # Present but not a readable boolean - the Redis store refuses this, so the SQL store
        # must too, or the two answer the same session differently (A3, D-160).
        unusable("user", "its banned field is not a boolean", subject)
        return None
    if "banned" in payload:
        # Normalize the raw 0/1 a SQLite/MySQL column answers to a bool, so both stores put the
        # same value on the payload they hand `parse_user`.
        payload["banned"] = banned
    return StoredUser(
        id=identifier,
        payload=payload,
        banned=banned,
        ban_expires=as_moment(payload.get("banExpires")),
    )


def _only(rows: Sequence[Mapping[str, Any]], kind: str, subject: str) -> Mapping[str, Any] | None:
    if not rows:
        return None
    if len(rows) > 1:
        unusable(kind, "more than one row matched a value that is unique upstream", subject)
        return None
    return rows[0]


def _payload(row: Mapping[str, Any], columns: tuple[str, ...], prefix: str) -> dict[str, Any]:
    """The row under upstream's own key names, with every moment made timezone-aware."""
    built: dict[str, Any] = {}
    for name in columns:
        value = row[f"{prefix}{name}"]
        built[name] = as_moment(value) if name in MOMENTS and value is not None else value
    return built


def _why(
    expires_at: object, user_id: str | None, stored_token: str | None, user: StoredUser | None
) -> str:
    absent = [
        name
        for name, value in (
            ("expiresAt", expires_at),
            ("userId", user_id),
            ("token", stored_token),
            ("its user row", user),
        )
        if value is None
    ]
    return f"{', '.join(absent)} is null, blank or unreadable"


def reflected(
    connection: Connection, names: Sequence[str], schema: str | None
) -> dict[str, tuple[str, ...] | None]:
    """The column names each table actually has, in the database's own order.

    Ordered rather than a set, because the order is what puts a deployment's own columns after
    the ones this library knows about; `None` is how an absent table is told apart from a table
    that happens to be missing everything.
    """
    inspector = inspect(connection)
    found: dict[str, tuple[str, ...] | None] = {}
    for name in names:
        if not inspector.has_table(name, schema=schema):
            found[name] = None
            continue
        columns = inspector.get_columns(name, schema=schema)
        found[name] = tuple(str(column["name"]) for column in columns)
    return found


def rows(result: Any) -> list[Mapping[str, Any]]:
    """At most `ROW_LIMIT` rows, materialized before the connection closes."""
    return [dict(row) for row in result.mappings().fetchmany(ROW_LIMIT)]


def lookup_unavailable(params: Mapping[str, Any]) -> AuthServiceUnavailable:
    """The failure a query-time database error must be turned into - carrying NO parameter.

    SQLAlchemy's `DBAPIError.__str__` embeds the bound parameters (`[parameters: ('<token>',)]`)
    because an operator-built engine defaults to `hide_parameters=False`, so an untranslated error
    from `connection.execute` puts the raw session token into any `logger.exception` a consumer
    writes (A1, D-160). This is the one thing the whole store is built to prevent - it is why
    `StoredSession.token` is `repr=False`. The escaping error carries a fingerprint of the subject
    and nothing else; the caller raises it `from None` so the original never rides along on
    `__cause__`/`__context__`. `AuthServiceUnavailable` because a lookup that could not complete is
    a refusal, the same family as a JWKS fetch that could not complete - which is what lets the
    verifier answer the uniform 401.
    """
    subject = next((value for value in params.values() if isinstance(value, str)), "")
    return AuthServiceUnavailable(
        reason=f"session store lookup could not complete [{fingerprint(subject)}]"
    )


def validated_async_engine(engine: object) -> AsyncEngine:
    """Annotated `AsyncEngine`; the object was built by someone else, at startup, from config."""
    if not isinstance(engine, AsyncEngine):
        raise ConfigurationError(
            WRONG_ENGINE.format(
                expected="AsyncEngine", actual=type(engine).__name__, advice=ASYNC_ADVICE
            )
        )
    return engine


def validated_sync_engine(engine: object) -> Engine:
    """An `AsyncEngine` here would leave a coroutine nobody awaited, at the first request."""
    if isinstance(engine, AsyncEngine) or not isinstance(engine, Engine):
        raise ConfigurationError(
            WRONG_ENGINE.format(expected="Engine", actual=type(engine).__name__, advice=SYNC_ADVICE)
        )
    return engine
