"""The stores read. They do not write - not a row, not a key, not a bookkeeping stamp.

The Node side owns every write there is: creating a session, extending one, deleting one. A
write from here would be a second author of the same state, and the two that look harmless are
the two that do the damage - a `touch` that rewrites `expiresAt` extends a session the bridge
was only asked to read, and an `EXPIRE` refreshed on read makes a revoked session outlive its
revocation.

Asserted three ways, because each is blind to what the others catch:

1. **What was emitted.** Every SQL statement the engine actually handed its driver, and every
   command the Redis client actually received, over a drive of the whole store surface. This is
   the only one that sees a write issued through a path nobody read.
2. **What the source can express.** An AST scan of the stores package for the write constructs -
   `insert()`, `.delete(...)`, `.set(...)`, `.commit()`. This is the only one that fires on a
   write on a branch no test reaches.
3. **What the database holds.** Every row, before and after. This is the only one that survives
   a write issued through a construct nobody thought to ban.
"""

from __future__ import annotations

import ast
import pathlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.ext.asyncio import AsyncEngine

from fastapi_better_auth import (
    RedisSessionStore,
    SessionStore,
    SqlAlchemySessionStore,
    SyncStoreAdapter,
)
from tests.stores import (
    TOKEN,
    USER_ID,
    RecordingRedis,
    StatementLog,
    async_engine,
    build_schema,
    stored,
    sync_engine,
)

PACKAGE = pathlib.Path(__file__).resolve().parent.parent / "src" / "fastapi_better_auth"
STORES = PACKAGE / "_internal" / "stores"

READ_VERBS = frozenset({"SELECT", "PRAGMA"})
UNKNOWN_TOKEN = "5RmMvJt3xQ8bWfKcApZnUhLd2YeGsT7q"


@pytest.fixture
def anyio_backend() -> str:
    """aiosqlite is an asyncio driver."""
    return "asyncio"


# ---------------------------------------------------------------- 2. what the source can express


@dataclass(frozen=True)
class Ban:
    """One write construct, and a snippet proving the scanner can see it."""

    id: str
    kind: str
    probe: str


CALLS = frozenset(
    {
        "begin",
        "commit",
        "create_all",
        "delete",
        "drop_all",
        "eval",
        "evalsha",
        "execute_command",
        "expire",
        "flushall",
        "flushdb",
        "getdel",
        "getset",
        "insert",
        "pexpire",
        "pipeline",
        "set",
        "setex",
        "setnx",
        "update",
    }
)
"""Banned as an *attribute* - `connection.begin()`, `client.set(...)`, `table.insert()`.

The receiver is deliberately not named. A rule written as `table` `.` `insert` would watch one
spelling, and the write nobody anticipates arrives on a receiver called something else - the
same lesson `test_lint_guards` learned from the D-010 rules (D-056).

Two entries are wider than they look and stay that way on purpose. `.update(...)` catches
`dict.update` as well as `table.update()`, and `.set(...)` catches every `set` method there is:
the stores package builds its mappings by comprehension, so nothing it legitimately does is
refused, and the alternative is a rule that a write can walk past by being spelled as a method
on something innocuous. The bare-name half of the ban is `NAMES`, which lists only the
SQLAlchemy constructs - `set` and `update` as bare names are a builtin and a common local, and
banning those would be a rule people route around rather than obey.
"""

NAMES = frozenset({"Delete", "Insert", "Update", "delete", "insert", "update"})
"""Banned as a bare name: `insert(table)`, or an imported `sqlalchemy.update`."""

PROBES: tuple[Ban, ...] = (
    Ban("sqlalchemy-insert-call", "attribute", "await connection.execute(table.insert())\n"),
    Ban("sqlalchemy-insert-name", "name", "from sqlalchemy import insert\nstmt = insert(table)\n"),
    Ban("sqlalchemy-update-name", "name", "stmt = update(table).values(seen=1)\n"),
    Ban("sqlalchemy-delete-name", "name", "stmt = delete(table)\n"),
    Ban("transaction-begin", "attribute", "async with engine.begin() as connection:\n    pass\n"),
    Ban("transaction-commit", "attribute", "await connection.commit()\n"),
    Ban("redis-set", "attribute", "await client.set(key, value)\n"),
    Ban("redis-setex", "attribute", "await client.setex(key, 60, value)\n"),
    Ban("redis-delete", "attribute", "await client.delete(key)\n"),
    Ban("redis-expire", "attribute", "await client.expire(key, 60)\n"),
    Ban("redis-eval", "attribute", "await client.eval(script, 1, key)\n"),
    Ban("redis-pipeline", "attribute", "async with client.pipeline() as pipe:\n    pass\n"),
)

LEGAL: tuple[tuple[str, str], ...] = (
    ("set-literal", "seen = {'a', 'b'}\n"),
    ("set-builtin", "seen = set(names)\n"),
    ("frozenset", "seen = frozenset(('a',))\n"),
    ("dict-merge", "merged = {**a, **b}\n"),
    ("select", "stmt = select(table).where(table.c.token == bindparam('token'))\n"),
    ("connect", "async with engine.connect() as connection:\n    pass\n"),
    ("get", "value = await client.get(key)\n"),
    ("inspect", "columns = inspect(connection).get_columns(name)\n"),
)


def writes_in(tree: ast.AST) -> Iterator[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in CALLS:
            yield node.attr
        if isinstance(node, ast.Name) and node.id in NAMES:
            yield node.id


def store_sources() -> tuple[pathlib.Path, ...]:
    return tuple(p for p in STORES.rglob("*.py") if "__pycache__" not in p.parts)


def test_the_scanner_reads_the_whole_stores_package() -> None:
    """A guard that scans an empty file set passes by vacuum."""
    scanned = {path.name for path in store_sources()}

    assert "__init__.py" in scanned
    assert len(scanned) >= 4


@pytest.mark.parametrize("ban", PROBES, ids=lambda b: b.id)
def test_the_scanner_fires_on_a_synthetic_write(ban: Ban) -> None:
    """Prove the instrument: an unproven guard is not a guard."""
    assert next(writes_in(ast.parse(ban.probe)), None) is not None


@pytest.mark.parametrize("source", [case[1] for case in LEGAL], ids=[c[0] for c in LEGAL])
def test_the_read_shapes_stay_legal(source: str) -> None:
    """A ban that also refuses the safe form is one nobody can comply with."""
    assert next(writes_in(ast.parse(source)), None) is None


def test_no_store_module_can_express_a_write() -> None:
    found = {
        f"{path.name}: {name}"
        for path in store_sources()
        for name in writes_in(ast.parse(path.read_text(encoding="utf-8")))
    }

    assert not found, f"a write construct reached the stores package: {sorted(found)}"


# ---------------------------------------------------------------- 1. and 3. what actually happened


def snapshot(engine: Engine) -> list[tuple[Any, ...]]:
    with engine.connect() as connection:
        sessions = connection.execute(text('SELECT * FROM "session" ORDER BY id')).all()
        users = connection.execute(text('SELECT * FROM "user" ORDER BY id')).all()
    return [tuple(row) for row in (*sessions, *users)]


@pytest.mark.anyio
@pytest.mark.parametrize("flavour", ["async", "sync"])
async def test_no_sql_write_is_emitted_and_no_row_changes(
    tmp_path: pathlib.Path, flavour: str
) -> None:
    path = tmp_path / f"{flavour}.sqlite"
    build_schema(path)
    observer = sync_engine(path)
    before = snapshot(observer)
    log = StatementLog()
    engine: Engine | AsyncEngine
    store: SessionStore

    if flavour == "async":
        engine = async_engine(path)
        store = SqlAlchemySessionStore(engine=engine)
    else:
        engine = sync_engine(path)
        store = SyncStoreAdapter(engine=engine)
    log.attach(engine)

    await store.fetch_session_by_token(TOKEN)
    await store.fetch_session_by_token(UNKNOWN_TOKEN)
    await store.fetch_user_by_id(USER_ID)
    await store.fetch_user_by_id("nobody")

    if isinstance(engine, AsyncEngine):
        await engine.dispose()
    else:
        engine.dispose()

    assert log.statements, "nothing was executed; this proves nothing"
    assert log.verbs <= READ_VERBS, f"a non-read statement was emitted: {sorted(log.verbs)}"
    assert snapshot(observer) == before
    observer.dispose()


@pytest.mark.anyio
async def test_no_redis_command_but_get_is_ever_issued() -> None:
    client = RecordingRedis({TOKEN: stored()})
    store = RedisSessionStore(client=client)

    await store.fetch_session_by_token(TOKEN)
    await store.fetch_session_by_token(UNKNOWN_TOKEN)
    await store.fetch_session_by_token("")
    await store.fetch_user_by_id(USER_ID)

    assert client.commands == {"get"}
    assert client.values == {TOKEN: stored()}
