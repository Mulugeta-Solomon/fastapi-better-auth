"""Reading and binding ids by their column's type, without a database.

`sql_ids` decides what an id read from a column of each kind is, and what text may be bound to
one; `sqlalchemy_core.kind_of` decides the kind from a reflected type. Both are checked here
against the types each dialect's reflection actually answers, and the statements are compiled
for the Postgres drivers - compiled, not executed: no live Postgres runs in this lane.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import pytest
from sqlalchemy import (
    BIGINT,
    CHAR,
    INTEGER,
    NUMERIC,
    TEXT,
    UUID,
    VARCHAR,
    BigInteger,
    Boolean,
    Integer,
    SmallInteger,
    Text,
    Uuid,
)
from sqlalchemy.dialects import mysql, postgresql, sqlite
from sqlalchemy.dialects.postgresql import asyncpg, psycopg
from sqlalchemy.types import NullType, TypeEngine

from fastapi_better_auth._internal.reasons import fingerprint
from fastapi_better_auth._internal.stores.sql_ids import IdKind, bind_id, read_id
from fastapi_better_auth._internal.stores.sqlalchemy_core import (
    SESSION_COLUMNS,
    SESSION_PREFIX,
    USER_COLUMNS,
    USER_PREFIX,
    Plan,
    kind_of,
    lookup_marker,
    plan_for,
    session_from,
    user_from,
)

PRESENT = {"session": SESSION_COLUMNS, "user": USER_COLUMNS}
TOKEN = "wBNhqX3M2CKkT7bmDTmeEMA1S1qCcWnn"
EXPIRES_AT = datetime(2999, 1, 1, tzinfo=timezone.utc)
AN_UUID = uuid.UUID("3f2b8c4e-9a1d-4c7e-8b5f-0d6e2a9c1b7f")


def typed_plan(column_type: TypeEngine[Any]) -> Plan:
    """A plan whose four id columns all reflected as `column_type`."""
    types = {
        "session": {"id": column_type, "userId": column_type, "impersonatedBy": column_type},
        "user": {"id": column_type},
    }
    return plan_for("session", "user", None, PRESENT, types=types)


def joined_row(
    session_id: object, user_id: object, impersonated_by: object = None
) -> dict[str, Any]:
    session: dict[str, Any] = {
        **dict.fromkeys(SESSION_COLUMNS),
        "id": session_id,
        "token": TOKEN,
        "expiresAt": EXPIRES_AT,
        "userId": user_id,
        "impersonatedBy": impersonated_by,
    }
    user: dict[str, Any] = {**dict.fromkeys(USER_COLUMNS), "id": user_id}
    return {
        **{f"{SESSION_PREFIX}{name}": value for name, value in session.items()},
        **{f"{USER_PREFIX}{name}": value for name, value in user.items()},
    }


class TestReadId:
    @pytest.mark.parametrize(
        ("kind", "value", "expected"),
        [
            (IdKind.INTEGER, 7, "7"),
            (IdKind.INTEGER, 0, "0"),
            (IdKind.INTEGER, 2**63 - 1, str(2**63 - 1)),
            (IdKind.INTEGER, True, None),
            (IdKind.INTEGER, False, None),
            (IdKind.INTEGER, 7.0, None),
            (IdKind.INTEGER, "7", None),
            (IdKind.INTEGER, b"7", None),
            (IdKind.INTEGER, None, None),
            (IdKind.UUID, AN_UUID, str(AN_UUID)),
            (IdKind.UUID, AN_UUID.hex, str(AN_UUID)),
            (IdKind.UUID, str(AN_UUID).upper(), str(AN_UUID)),
            (IdKind.UUID, f"{{{AN_UUID}}}", None),
            (IdKind.UUID, f"urn:uuid:{AN_UUID}", None),
            (IdKind.UUID, AN_UUID.bytes, None),
            (IdKind.UUID, AN_UUID.int, None),
            (IdKind.UUID, "not-a-uuid", None),
            (IdKind.TEXT, "abc", "abc"),
            (IdKind.TEXT, " ", None),
            (IdKind.TEXT, 7, None),
            (IdKind.TEXT, AN_UUID, None),
        ],
    )
    def test_only_what_the_column_type_promises_is_an_id(
        self, kind: IdKind, value: object, expected: str | None
    ) -> None:
        assert read_id(kind, value) == expected

    def test_a_driver_uuid_subclass_cannot_choose_its_rendering(self) -> None:
        """asyncpg answers its own `UUID` subclass; the text is rebuilt from the value."""

        class LoudUUID(uuid.UUID):
            def __str__(self) -> str:
                return "LOUD"

        assert read_id(IdKind.UUID, LoudUUID(str(AN_UUID))) == str(AN_UUID)


class TestBindId:
    @pytest.mark.parametrize(
        ("candidate", "expected"),
        [
            ("7", 7),
            ("0", 0),
            ("-5", -5),
            (str(2**63 - 1), 2**63 - 1),
            (str(-(2**63)), -(2**63)),
            (str(2**63), None),
            ("9" * 5000, None),
            ("07", None),
            ("+7", None),
            ("-0", None),
            (" 7", None),
            ("7_0", None),
            ("٧", None),
            ("7.0", None),
        ],
    )
    def test_an_integer_binds_from_its_canonical_text_only(
        self, candidate: str, expected: int | None
    ) -> None:
        assert bind_id(IdKind.INTEGER, candidate) == expected

    def test_a_uuid_binds_from_its_canonical_text_only(self) -> None:
        assert bind_id(IdKind.UUID, str(AN_UUID)) == AN_UUID
        for spelling in (str(AN_UUID).upper(), AN_UUID.hex, f"{{{AN_UUID}}}", "x"):
            assert bind_id(IdKind.UUID, spelling) is None

    def test_text_binds_as_it_was_given(self) -> None:
        assert bind_id(IdKind.TEXT, "07") == "07"


KINDS: list[tuple[TypeEngine[Any] | None, IdKind]] = [
    (Integer(), IdKind.INTEGER),
    (BigInteger(), IdKind.INTEGER),
    (SmallInteger(), IdKind.INTEGER),
    (INTEGER(), IdKind.INTEGER),
    (BIGINT(), IdKind.INTEGER),
    (mysql.INTEGER(), IdKind.INTEGER),
    (UUID(), IdKind.UUID),
    (Uuid(), IdKind.UUID),
    (TEXT(), IdKind.TEXT),
    (VARCHAR(36), IdKind.TEXT),
    (CHAR(32), IdKind.TEXT),
    (NUMERIC[Any](), IdKind.TEXT),
    (Boolean(), IdKind.TEXT),
    (NullType(), IdKind.TEXT),
    (None, IdKind.TEXT),
]


class TestKindOf:
    @pytest.mark.parametrize(("column_type", "expected"), KINDS)
    def test_integer_and_uuid_by_family_and_everything_else_text(
        self, column_type: TypeEngine[Any] | None, expected: IdKind
    ) -> None:
        assert kind_of(column_type) is expected

    def test_those_are_the_types_each_dialect_reflects(self) -> None:
        """The classes above are what reflection hands back, not stand-ins for them."""
        assert postgresql.base.ischema_names["integer"] is INTEGER
        assert postgresql.base.ischema_names["bigint"] is BIGINT
        assert postgresql.base.ischema_names["uuid"] is UUID
        assert sqlite.base.ischema_names["INTEGER"] is INTEGER
        assert mysql.base.ischema_names["int"] is mysql.INTEGER


class TestStatements:
    def test_a_text_id_deployment_gets_the_statements_it_always_had(self) -> None:
        untyped = plan_for("session", "user", None, PRESENT)
        typed = typed_plan(Text())

        for dialect in (sqlite.dialect(), asyncpg.dialect()):
            assert str(typed.user_statement.compile(dialect=dialect)) == str(
                untyped.user_statement.compile(dialect=dialect)
            )
            assert str(typed.session_statement.compile(dialect=dialect)) == str(
                untyped.session_statement.compile(dialect=dialect)
            )

    @pytest.mark.parametrize(
        ("column_type", "cast"),
        [
            (Text(), "VARCHAR"),
            (INTEGER(), "INTEGER"),
            (BIGINT(), "BIGINT"),
            (UUID(), "UUID"),
        ],
    )
    @pytest.mark.parametrize("dialect", [asyncpg.dialect(), psycopg.dialect()], ids=str)
    def test_the_user_id_binds_as_the_reflected_type_on_postgres(
        self, column_type: TypeEngine[Any], cast: str, dialect: Any
    ) -> None:
        """A `bigint` id cast to `integer` would fail past 2**31, so the width is kept."""
        compiled = str(typed_plan(column_type).user_statement.compile(dialect=dialect))

        assert '"user".id = ' in compiled
        assert f"::{cast}" in compiled.split("WHERE", 1)[1].split("LIMIT", 1)[0]


class TestRows:
    def test_a_boolean_in_an_integer_id_column_is_a_miss(self) -> None:
        plan = typed_plan(Integer())

        assert session_from([joined_row(True, 7)], plan, TOKEN) is None
        assert session_from([joined_row(11, True)], plan, TOKEN) is None
        assert user_from([joined_row(11, False)], plan, "0") is None

    def test_a_boolean_impersonator_is_none(self) -> None:
        record = session_from(
            [joined_row(11, 7, impersonated_by=True)], typed_plan(Integer()), TOKEN
        )

        assert record is not None
        assert record.impersonated_by is None

    def test_a_driver_uuid_reads_as_text(self) -> None:
        record = session_from([joined_row(AN_UUID, AN_UUID)], typed_plan(Uuid()), TOKEN)

        assert record is not None and record.user is not None
        assert (record.id, record.user_id, record.user.id) == (str(AN_UUID),) * 3

    def test_an_integer_in_a_uuid_column_is_a_miss(self) -> None:
        assert session_from([joined_row(AN_UUID, AN_UUID.int)], typed_plan(Uuid()), TOKEN) is None

    def test_a_text_column_still_refuses_an_integer(self) -> None:
        """The coercion is the SQL layer's, per column type; a text column is read as before."""
        assert session_from([joined_row(11, 7)], typed_plan(Text()), TOKEN) is None


class TestLookupMarker:
    @pytest.mark.parametrize("value", [7, AN_UUID])
    def test_a_typed_parameter_is_fingerprinted_as_its_canonical_text(self, value: object) -> None:
        """The outage line names the lookup by the same fingerprint the verifier computed."""
        assert lookup_marker({"user_id": value}) == fingerprint(str(value))

    def test_a_boolean_is_not_a_subject(self) -> None:
        assert lookup_marker({"user_id": True}) == fingerprint("")
