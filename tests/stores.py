"""Fixtures the store suites share: a real SQLite schema, a recording Redis, and the payloads.

The SQLite schema here is written by hand from the *live* Postgres schema the harness migrates
(`session` and `user`, camelCase identifiers, `user` a reserved word) rather than generated from
the store's own table metadata. A schema generated from the code under test would agree with it
by construction and prove nothing; this one disagrees the moment the store's idea of the schema
drifts from better-auth's.

Every database here is file-backed, never `:memory:`. SQLAlchemy gives a memory SQLite a
connection-scoped database, so a second connection - or a worker thread, which is exactly what
`SyncStoreAdapter` uses - sees an empty one.
"""

from __future__ import annotations

import json
import pathlib
import threading
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)
EXPIRES_AT = NOW + timedelta(days=7)

TOKEN = "wBNhqX3M2CKkT7bmDTmeEMA1S1qCcWnn"
SESSION_ID = "QOzpVhyGW3v9C3i0m5xB4Xgyby1adidd"
USER_ID = "cIrUeXmXVG5Kg0Pzt4rCozIxLv3oeOMG"
ADMIN_ID = "McPLn0oFODOJXADr6Mu0CxzTpaQB2XU2"

# The default better-auth schema, then the columns only the admin plugin creates. Split
# because "the admin columns are absent" is a supported deployment, not drift.
BASE_SESSION_COLUMNS: tuple[tuple[str, str], ...] = (
    ("id", "TEXT NOT NULL PRIMARY KEY"),
    ("expiresAt", "TIMESTAMP NOT NULL"),
    ("token", "TEXT NOT NULL UNIQUE"),
    ("createdAt", "TIMESTAMP NOT NULL"),
    ("updatedAt", "TIMESTAMP NOT NULL"),
    ("ipAddress", "TEXT"),
    ("userAgent", "TEXT"),
    ("userId", "TEXT NOT NULL"),
)
ADMIN_SESSION_COLUMNS: tuple[tuple[str, str], ...] = (("impersonatedBy", "TEXT"),)
BASE_USER_COLUMNS: tuple[tuple[str, str], ...] = (
    ("id", "TEXT NOT NULL PRIMARY KEY"),
    ("name", "TEXT NOT NULL"),
    ("email", "TEXT NOT NULL UNIQUE"),
    ("emailVerified", "BOOLEAN NOT NULL"),
    ("image", "TEXT"),
    ("createdAt", "TIMESTAMP NOT NULL"),
    ("updatedAt", "TIMESTAMP NOT NULL"),
)
ADMIN_USER_COLUMNS: tuple[tuple[str, str], ...] = (
    ("role", "TEXT"),
    ("banned", "BOOLEAN"),
    ("banReason", "TEXT"),
    ("banExpires", "TIMESTAMP"),
)

SESSION_ROW: Mapping[str, Any] = {
    "id": SESSION_ID,
    "expiresAt": EXPIRES_AT,
    "token": TOKEN,
    "createdAt": NOW,
    "updatedAt": NOW,
    "ipAddress": "",
    "userAgent": "python-httpx/0.28.1",
    "userId": USER_ID,
    "impersonatedBy": None,
}
USER_ROW: Mapping[str, Any] = {
    "id": USER_ID,
    "name": "Seed User",
    "email": "seed@example.com",
    "emailVerified": False,
    "image": None,
    "createdAt": NOW,
    "updatedAt": NOW,
    "role": None,
    "banned": False,
    "banReason": None,
    "banExpires": None,
}


def _ddl(table: str, columns: Sequence[tuple[str, str]]) -> str:
    body = ", ".join(f'"{name}" {kind}' for name, kind in columns)
    return f'CREATE TABLE "{table}" ({body})'


def _insert(table: str, row: Mapping[str, Any], columns: Sequence[tuple[str, str]]) -> str:
    names = [name for name, _ in columns]
    placeholders = ", ".join(f":{name}" for name in names)
    quoted = ", ".join(f'"{name}"' for name in names)
    return f'INSERT INTO "{table}" ({quoted}) VALUES ({placeholders})'


def _values(row: Mapping[str, Any], columns: Sequence[tuple[str, str]]) -> dict[str, Any]:
    return {name: row.get(name) for name, _ in columns}


def _relaxed(
    columns: Sequence[tuple[str, str]], relax: Sequence[str]
) -> tuple[tuple[str, str], ...]:
    """Drop `NOT NULL` from named columns, so a row carrying a NULL there can be seeded."""
    return tuple(
        (name, kind.replace(" NOT NULL", "") if name in relax else kind) for name, kind in columns
    )


def build_schema(
    path: pathlib.Path,
    *,
    admin: bool = True,
    sessions: Sequence[Mapping[str, Any]] = (SESSION_ROW,),
    users: Sequence[Mapping[str, Any]] = (USER_ROW,),
    drop_session_columns: Sequence[str] = (),
    drop_user_columns: Sequence[str] = (),
    relax_session_columns: Sequence[str] = (),
    extra_session_columns: Sequence[tuple[str, str]] = (),
    extra_user_columns: Sequence[tuple[str, str]] = (),
    unique_token: bool = True,
    session_table: str = "session",
    user_table: str = "user",
) -> None:
    """Create and seed a SQLite database that mirrors better-auth's migrated schema."""
    session_columns = BASE_SESSION_COLUMNS + (ADMIN_SESSION_COLUMNS if admin else ())
    user_columns = BASE_USER_COLUMNS + (ADMIN_USER_COLUMNS if admin else ())
    session_columns = _relaxed(
        tuple(c for c in session_columns if c[0] not in drop_session_columns),
        relax_session_columns,
    )
    if not unique_token:
        # A hand-rolled migration that dropped the constraint upstream relies on: two rows can
        # then answer one token, and the store has to notice rather than pick one.
        session_columns = tuple(
            (name, kind.replace(" UNIQUE", "")) for name, kind in session_columns
        )
    user_columns = tuple(c for c in user_columns if c[0] not in drop_user_columns)
    session_columns += tuple(extra_session_columns)
    user_columns += tuple(extra_user_columns)
    engine = create_engine(f"sqlite+pysqlite:///{path}")
    with engine.begin() as connection:
        connection.execute(text(_ddl(user_table, user_columns)))
        connection.execute(text(_ddl(session_table, session_columns)))
        for user in users:
            connection.execute(
                text(_insert(user_table, user, user_columns)), _values(user, user_columns)
            )
        for session in sessions:
            connection.execute(
                text(_insert(session_table, session, session_columns)),
                _values(session, session_columns),
            )
    engine.dispose()


def async_engine(path: pathlib.Path) -> AsyncEngine:
    return create_async_engine(f"sqlite+aiosqlite:///{path}")


def sync_engine(path: pathlib.Path) -> Engine:
    return create_engine(f"sqlite+pysqlite:///{path}")


class StatementLog:
    """Every SQL statement an engine actually sent to its driver, in order.

    The read-only invariant is asserted against this and not against the store's source: an
    intention to read is not evidence, and a write emitted through a path nobody read is
    exactly the shape that would survive a code review.
    """

    def __init__(self) -> None:
        self.statements: list[str] = []
        self.threads: list[int] = []

    def attach(self, engine: Engine | AsyncEngine) -> None:
        target = engine.sync_engine if isinstance(engine, AsyncEngine) else engine
        event.listen(target, "before_cursor_execute", self._record)

    def _record(
        self,
        conn: Any,
        cursor: Any,
        statement: str,
        parameters: Any,
        context: Any,
        executemany: bool,
    ) -> None:
        self.statements.append(statement)
        self.threads.append(threading.get_ident())

    @property
    def verbs(self) -> frozenset[str]:
        return frozenset(
            line.split(maxsplit=1)[0].upper() for line in self.statements if line.split()
        )


class RecordingRedis:
    """The slice of redis-py the store may touch, plus the ones it must never touch.

    The write commands exist on purpose. A fake without them would refuse a write with an
    `AttributeError` - which proves the fake, not the store. These record instead, so
    "no write was issued" is an assertion over what was actually called.
    """

    def __init__(self, values: Mapping[str, str | bytes] | None = None) -> None:
        self.values: dict[str, str | bytes] = dict(values or {})
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.closed = False

    async def get(self, name: str) -> bytes | None:
        self.calls.append(("get", (name,)))
        found = self.values.get(name)
        if found is None:
            return None
        return found.encode() if isinstance(found, str) else found

    async def set(self, name: str, value: Any, **kwargs: Any) -> None:
        self.calls.append(("set", (name, value)))

    async def delete(self, *names: str) -> None:
        self.calls.append(("delete", names))

    async def expire(self, name: str, seconds: int) -> None:
        self.calls.append(("expire", (name, seconds)))

    async def getdel(self, name: str) -> None:
        self.calls.append(("getdel", (name,)))

    async def aclose(self) -> None:
        self.calls.append(("aclose", ()))
        self.closed = True

    @property
    def commands(self) -> frozenset[str]:
        return frozenset(name for name, _ in self.calls)


class DecodingRedis(RecordingRedis):
    """A client built with `decode_responses=True`, which answers `str` rather than `bytes`."""

    async def get(self, name: str) -> str | None:  # type: ignore[override]
        self.calls.append(("get", (name,)))
        found = self.values.get(name)
        if found is None:
            return None
        return found.decode() if isinstance(found, bytes) else found


def stored(
    *,
    session: Mapping[str, Any] | None = None,
    user: Mapping[str, Any] | None = None,
    envelope: Mapping[str, Any] | None = None,
) -> str:
    """The JSON better-auth's secondary storage actually holds, or a variation on it."""
    if envelope is not None:
        return json.dumps(envelope)
    return json.dumps({"session": session or wire_session(), "user": user or wire_user()})


def wire_session(**overrides: Any) -> dict[str, Any]:
    """The session object as `JSON.stringify` wrote it: camelCase, ISO-8601 with a `Z`."""
    payload: dict[str, Any] = {
        "id": SESSION_ID,
        "ipAddress": "",
        "userAgent": "python-httpx/0.28.1",
        "expiresAt": _iso(EXPIRES_AT),
        "userId": USER_ID,
        "token": TOKEN,
        "createdAt": _iso(NOW),
        "updatedAt": _iso(NOW),
    }
    payload.update(overrides)
    return payload


def wire_user(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": "Seed User",
        "email": "seed@example.com",
        "emailVerified": False,
        "image": None,
        "createdAt": _iso(NOW),
        "updatedAt": _iso(NOW),
        "role": None,
        "banned": False,
        "banReason": None,
        "banExpires": None,
        "id": USER_ID,
    }
    payload.update(overrides)
    return payload


def _iso(moment: datetime) -> str:
    """`Date.prototype.toISOString()`: always UTC, always a `Z`, always three fractional digits."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + (
        f"{moment.microsecond // 1000:03d}Z"
    )
