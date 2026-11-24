"""The integer range a user lookup may bind: the reflected column's, on that dialect, never wider.

A value the column cannot hold names no row, so it must be a miss with no query. Bound anyway, it
is not a miss: asyncpg's int2/int4 encoders raise `OverflowError` ("value out of int32 range"),
re-raised as `asyncpg.exceptions.DataError` (an `InterfaceError`), which SQLAlchemy translates to
a DBAPI error and the store to `AuthServiceUnavailable` plus an outage warning - the wrong signal
for an id nobody has. The type class alone cannot say the width (SQLite's `INTEGER` is 64-bit,
Postgres's 32-bit), so the dialect decides it with the type.

The width cases are decided on plans built here (no database). The store cases run for real on
SQLite: the 64-bit boundaries against seeded rows, and a Postgres `INTEGER` column (type and
dialect injected at the reflection seam) refusing past int32 before any statement is sent.
"""

from __future__ import annotations

import dataclasses
import pathlib
from collections.abc import AsyncIterator, Sequence
from typing import Any

import pytest
from sqlalchemy import BIGINT, INTEGER, SMALLINT, Connection, Integer
from sqlalchemy.dialects import mysql
from sqlalchemy.dialects.postgresql import asyncpg
from sqlalchemy.types import TypeEngine

from fastapi_better_auth._internal.stores import sqlalchemy_core
from fastapi_better_auth._internal.stores.sqlalchemy_core import (
    SESSION_COLUMNS,
    USER_COLUMNS,
    Discovered,
    bound_user_id,
    plan_for,
)
from tests.stores import FLAVOURS, SESSION_ROW, USER_ROW, StoreFixture

PRESENT = {"session": SESSION_COLUMNS, "user": USER_COLUMNS}
INT64 = (-(2**63), 2**63 - 1)

WIDTHS: list[tuple[str, TypeEngine[Any], str, tuple[int, int]]] = [
    ("pg-smallint", SMALLINT(), "postgresql", (-(2**15), 2**15 - 1)),
    ("pg-integer", INTEGER(), "postgresql", (-(2**31), 2**31 - 1)),
    ("pg-bigint", BIGINT(), "postgresql", INT64),
    ("sqlite-integer", INTEGER(), "sqlite", INT64),
    ("sqlite-bigint", BIGINT(), "sqlite", INT64),
    ("mysql-tinyint", mysql.TINYINT(), "mysql", (-(2**7), 2**7 - 1)),
    ("mysql-smallint", mysql.SMALLINT(), "mysql", (-(2**15), 2**15 - 1)),
    ("mysql-mediumint", mysql.MEDIUMINT(), "mysql", (-(2**23), 2**23 - 1)),
    ("mysql-int", mysql.INTEGER(), "mysql", (-(2**31), 2**31 - 1)),
    ("mysql-int-unsigned", mysql.INTEGER(unsigned=True), "mysql", (0, 2**32 - 1)),
    ("mysql-bigint", mysql.BIGINT(), "mysql", INT64),
    # Wider than int64 in MySQL; held to int64, the ceiling every path keeps (see sql_ids).
    ("mysql-bigint-unsigned", mysql.BIGINT(unsigned=True), "mysql", (0, 2**63 - 1)),
    ("mariadb-int", mysql.INTEGER(), "mariadb", (-(2**31), 2**31 - 1)),
    # A dialect whose widths this library does not know keeps the 64-bit bound.
    ("unknown-dialect", INTEGER(), "mssql", INT64),
    ("no-dialect", Integer(), "", INT64),
]


def plan(column_type: TypeEngine[Any], dialect: str) -> sqlalchemy_core.Plan:
    types = {"session": {"userId": column_type}, "user": {"id": column_type}}
    return plan_for("session", "user", None, PRESENT, types=types, dialect=dialect or None)


@pytest.mark.parametrize(
    ("case", "column_type", "dialect", "bounds"), WIDTHS, ids=[w[0] for w in WIDTHS]
)
class TestWidths:
    def test_the_boundaries_bind(
        self, case: str, column_type: TypeEngine[Any], dialect: str, bounds: tuple[int, int]
    ) -> None:
        low, high = bounds
        built = plan(column_type, dialect)

        assert bound_user_id(built, str(low)) == low
        assert bound_user_id(built, str(high)) == high

    def test_one_past_either_boundary_is_a_miss(
        self, case: str, column_type: TypeEngine[Any], dialect: str, bounds: tuple[int, int]
    ) -> None:
        low, high = bounds
        built = plan(column_type, dialect)

        assert bound_user_id(built, str(low - 1)) is None
        assert bound_user_id(built, str(high + 1)) is None


@pytest.mark.parametrize("column_type", [SMALLINT(), INTEGER(), BIGINT()], ids=str)
def test_the_width_changes_no_statement(column_type: TypeEngine[Any]) -> None:
    """Compiled, not executed: the range gates the bind and leaves SQLAlchemy's typed bind as it is.

    Which cast the bind carries is SQLAlchemy's choice and differs by release (2.0.0 casts a
    SMALLINT bind as INTEGER, later releases as SMALLINT), so the cast's name is not pinned here.
    """
    with_dialect = plan(column_type, "postgresql").user_statement.compile(dialect=asyncpg.dialect())
    without = plan(column_type, "").user_statement.compile(dialect=asyncpg.dialect())

    assert str(with_dialect) == str(without)
    assert '"user".id = $1::' in str(with_dialect)


# --- through the real store, on SQLite --------------------------------------------------------


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(params=FLAVOURS)
def flavour(request: pytest.FixtureRequest) -> str:
    kind = request.param
    assert isinstance(kind, str)
    return kind


@pytest.fixture
async def build(tmp_path: pathlib.Path, flavour: str) -> AsyncIterator[StoreFixture]:
    fixture = StoreFixture(tmp_path, flavour)
    yield fixture
    await fixture.aclose()


def serial_users(*ids: int) -> dict[str, Any]:
    return {
        "session_types": {"userId": "INTEGER NOT NULL"},
        "user_types": {"id": "INTEGER NOT NULL PRIMARY KEY"},
        "sessions": [{**SESSION_ROW, "userId": ids[0]}],
        "users": [
            {**USER_ROW, "id": user_id, "email": f"u{index}@example.com"}
            for index, user_id in enumerate(ids)
        ],
    }


@pytest.fixture
def postgres_integer_reflection(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reflection answers what Postgres does for an `integer` id column, dialect included."""
    real = sqlalchemy_core.reflected

    def reflected_as_postgres(
        connection: Connection, names: Sequence[str], schema: str | None
    ) -> Discovered:
        found = real(connection, names, schema)
        types = {table: dict(columns) for table, columns in found.types.items()}
        types["user"]["id"] = INTEGER()
        types["session"]["userId"] = INTEGER()
        return dataclasses.replace(found, types=types, dialect="postgresql")

    monkeypatch.setattr(sqlalchemy_core, "reflected", reflected_as_postgres)


class TestStore:
    @pytest.mark.anyio
    async def test_sqlite_integer_ids_span_the_full_64_bit_range(self, build: StoreFixture) -> None:
        low, high = INT64
        store, _log = build(**serial_users(high, low))

        for user_id in (high, low):
            found = await store.fetch_user_by_id(str(user_id))
            assert found is not None and found.id == str(user_id)

    @pytest.mark.anyio
    async def test_discovery_records_the_dialect(self, build: StoreFixture) -> None:
        recorded: list[str | None] = []
        real = sqlalchemy_core.reflected

        def recording(connection: Connection, names: Sequence[str], schema: str | None) -> Any:
            found = real(connection, names, schema)
            recorded.append(found.dialect)
            return found

        store, _log = build(**serial_users(7))
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(sqlalchemy_core, "reflected", recording)
            await store.connect()

        assert recorded == ["sqlite"]

    @pytest.mark.anyio
    @pytest.mark.usefixtures("postgres_integer_reflection")
    @pytest.mark.parametrize("user_id", [2**31, -(2**31) - 1])
    async def test_past_int32_on_a_postgres_integer_column_is_a_miss_and_no_query(
        self, build: StoreFixture, user_id: int
    ) -> None:
        store, log = build(**serial_users(7))
        await store.connect()
        log.statements.clear()

        assert await store.fetch_user_by_id(str(user_id)) is None
        assert log.selects == []

    @pytest.mark.anyio
    @pytest.mark.usefixtures("postgres_integer_reflection")
    async def test_the_int32_maximum_still_queries(self, build: StoreFixture) -> None:
        store, log = build(**serial_users(2**31 - 1))
        await store.connect()
        log.statements.clear()

        found = await store.fetch_user_by_id(str(2**31 - 1))

        assert found is not None and found.id == str(2**31 - 1)
        assert len(log.selects) == 1
