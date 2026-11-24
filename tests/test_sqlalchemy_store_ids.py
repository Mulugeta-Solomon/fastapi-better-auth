"""The SQL store under Better Auth's non-default id modes: serial integers and UUIDs.

Better Auth's default id is a random string, but a deployment may hand id generation to the
database instead - serial integers, or the database's own uuid type - and its CLI then migrates
every `id` column (and every column referencing one) to that type. A driver hands those values
back as `int` or `uuid.UUID`, not `str`, and the store has to read them as the ids they are: the
text Better Auth itself would put in its JSON (decimal digits; lowercase hyphenated UUID).

SQLite, both flavours, as the rest of the SQL suites. SQLite's reflection never answers a uuid
type (a column SQLAlchemy's `Uuid` created reflects as `CHAR(32)`, one declared `UUID` as
`NUMERIC`), so the uuid cases that need the store to *know* a column is a uuid inject that one
fact at the reflection seam - the type Postgres reflection answers for a native `uuid` column -
and everything after it (the statement, the bind, the driver, the read) runs for real.
"""

from __future__ import annotations

import logging
import pathlib
import uuid
from collections.abc import AsyncIterator, Iterator, Sequence
from typing import Any

import pytest
from sqlalchemy import Connection, Engine, Uuid, event
from sqlalchemy.ext.asyncio import AsyncEngine

from fastapi_better_auth import CsrfDisabled, SqlAlchemySessionStore, SyncStoreAdapter
from fastapi_better_auth._internal.cookie_verifier import CookieVerifier
from fastapi_better_auth._internal.stores import sqlalchemy_core
from fastapi_better_auth._internal.stores.sqlalchemy_core import Discovered
from tests.cookies import COOKIE, SECRET, http, run, sign
from tests.stores import FLAVOURS, SESSION_ROW, TOKEN, USER_ROW, StoreFixture

Build = StoreFixture
Store = SqlAlchemySessionStore | SyncStoreAdapter

SERIAL_SESSION_ID = 11
SERIAL_USER_ID = 7
SERIAL_ADMIN_ID = 3

SERIAL_SESSION_TYPES = {
    "id": "INTEGER NOT NULL PRIMARY KEY",
    "userId": "INTEGER NOT NULL",
    "impersonatedBy": "INTEGER",
}
SERIAL_USER_TYPES = {"id": "INTEGER NOT NULL PRIMARY KEY"}

USER_UUID = uuid.UUID("3f2b8c4e-9a1d-4c7e-8b5f-0d6e2a9c1b7f")
SESSION_UUID = uuid.UUID("b1e5d0a2-6c3f-4e8a-9d7b-2f4c8e1a5d90")
UUID_COLUMNS = (("session", "id"), ("session", "userId"), ("user", "id"))


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(params=FLAVOURS)
def flavour(request: pytest.FixtureRequest) -> str:
    kind = request.param
    assert isinstance(kind, str)
    return kind


@pytest.fixture
async def build(tmp_path: pathlib.Path, flavour: str) -> AsyncIterator[Build]:
    fixture = StoreFixture(tmp_path, flavour)
    yield fixture
    await fixture.aclose()


def serial_schema(
    *,
    user: dict[str, Any] | None = None,
    user_types: dict[str, str] | None = None,
    session_types: dict[str, str] | None = None,
    **session: Any,
) -> dict[str, Any]:
    """The schema `generateId: "serial"` migrates: every id column an integer.

    The `*_types` overrides drop a `PRIMARY KEY` where a case seeds a value SQLite would refuse
    under one: an `INTEGER PRIMARY KEY` holds integers only, a plain `INTEGER` column anything.
    """
    return {
        "session_types": {**SERIAL_SESSION_TYPES, **(session_types or {})},
        "user_types": SERIAL_USER_TYPES if user_types is None else user_types,
        "sessions": [{**SESSION_ROW, "id": SERIAL_SESSION_ID, "userId": SERIAL_USER_ID, **session}],
        "users": [{**USER_ROW, "id": SERIAL_USER_ID, **(user or {})}],
    }


def hex_uuid_schema() -> dict[str, Any]:
    """Uuid ids as SQLAlchemy's `Uuid` stores them where there is no native type: 32 hex digits."""
    return {
        "session_types": {"id": "CHAR(32) NOT NULL PRIMARY KEY", "userId": "CHAR(32) NOT NULL"},
        "user_types": {"id": "CHAR(32) NOT NULL PRIMARY KEY"},
        "sessions": [{**SESSION_ROW, "id": SESSION_UUID.hex, "userId": USER_UUID.hex}],
        "users": [{**USER_ROW, "id": USER_UUID.hex}],
    }


@pytest.fixture
def uuid_reflection(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reflection answers `Uuid` for the id columns, as Postgres reflection does for `uuid`."""
    real = sqlalchemy_core.reflected

    def reflected_as_uuid(
        connection: Connection, names: Sequence[str], schema: str | None
    ) -> Discovered:
        found = real(connection, names, schema)
        types = {table: dict(columns) for table, columns in found.types.items()}
        for table, column in UUID_COLUMNS:
            types[table][column] = Uuid()
        return Discovered(columns=found.columns, types=types)

    monkeypatch.setattr(sqlalchemy_core, "reflected", reflected_as_uuid)


class BoundParameters:
    """The parameters each statement actually reached the driver with."""

    def __init__(self, engine: Engine | AsyncEngine) -> None:
        self.seen: list[Any] = []
        target = engine.sync_engine if isinstance(engine, AsyncEngine) else engine
        event.listen(target, "before_cursor_execute", self._record)

    def _record(self, *args: Any) -> None:
        self.seen.append(args[3])

    @property
    def flat(self) -> Iterator[Any]:
        for parameters in self.seen:
            yield from parameters if isinstance(parameters, (tuple, list)) else ()


class TestSerialIds:
    @pytest.mark.anyio
    async def test_a_valid_session_with_integer_ids_is_found(self, build: Build) -> None:
        """F3. The driver answers `int` for an integer id column; the shared text validator
        refuses anything that is not a `str`, so a valid session read as unreadable - a miss,
        and every request of a serial-id deployment a 401."""
        store, _log = build(**serial_schema())

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.id == "11"
        assert record.user_id == "7"
        assert record.user is not None
        assert record.user.id == "7"

    @pytest.mark.anyio
    async def test_the_user_is_found_by_its_integer_id(self, build: Build) -> None:
        store, _log = build(**serial_schema())

        found = await store.fetch_user_by_id("7")

        assert found is not None
        assert found.id == "7"

    @pytest.mark.anyio
    async def test_the_payloads_carry_the_ids_as_text(self, build: Build) -> None:
        """`Session.raw` and the payload `parse_user` reads are what Better Auth's JSON says."""
        store, _log = build(**serial_schema())

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None and record.user is not None
        assert (record.payload["id"], record.payload["userId"]) == ("11", "7")
        assert record.user.payload["id"] == "7"

    @pytest.mark.anyio
    async def test_the_user_lookup_binds_an_integer(self, build: Build) -> None:
        """Compared as the column's own type, never as a string against an integer column."""
        store, _log = build(**serial_schema())
        bound = BoundParameters(build.engines[-1])

        await store.fetch_user_by_id("7")

        assert 7 in list(bound.flat)
        assert "7" not in list(bound.flat)

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "spelling", ["07", "+7", " 7", "7 ", "7.0", "0x7", "7_0", "-0", "٧", "9" * 30, "abc"]
    )
    async def test_another_spelling_of_an_id_is_a_miss_and_no_query(
        self, build: Build, spelling: str
    ) -> None:
        """Only the canonical text binds: a second spelling that found the row would answer an
        id that is not the one asked for, and a 30-digit one would overflow the driver."""
        store, log = build(**serial_schema())
        await store_connected(store)
        log.statements.clear()

        assert await store.fetch_user_by_id(spelling) is None
        assert log.selects == []

    @pytest.mark.anyio
    async def test_the_refused_id_is_logged_by_fingerprint_only(
        self, build: Build, caplog: pytest.LogCaptureFixture
    ) -> None:
        store, _log = build(**serial_schema())

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            await store.fetch_user_by_id("not-a-serial-id")

        assert any("integer id column" in record.getMessage() for record in caplog.records)
        assert "not-a-serial-id" not in caplog.text

    @pytest.mark.anyio
    async def test_an_impersonating_admin_id_is_read_as_text(self, build: Build) -> None:
        """`impersonatedBy` references a user, so it is an integer column too; reading it as
        unreadable would drop the provenance of every impersonated session silently."""
        store, _log = build(**serial_schema(impersonatedBy=SERIAL_ADMIN_ID))

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.impersonated_by == "3"
        assert record.payload["impersonatedBy"] == "3"

    @pytest.mark.anyio
    async def test_no_impersonation_stays_none(self, build: Build) -> None:
        store, _log = build(**serial_schema())

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.impersonated_by is None


class TestMixedIds:
    @pytest.mark.anyio
    async def test_serial_users_with_text_session_ids(self, build: Build) -> None:
        """Upstream documents exactly this: a `generateId` callback leaving the user id to a
        serial column and giving sessions a generated string."""
        store, _log = build(
            session_types={"userId": "INTEGER NOT NULL"},
            user_types=SERIAL_USER_TYPES,
            sessions=[{**SESSION_ROW, "userId": SERIAL_USER_ID}],
            users=[{**USER_ROW, "id": SERIAL_USER_ID}],
        )

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None and record.user is not None
        assert record.id == SESSION_ROW["id"]
        assert (record.user_id, record.user.id) == ("7", "7")


class TestWrongTypedValues:
    """A value its column's type does not promise is untrusted, exactly as a non-`str` was.

    SQLite cannot hold a `bool` (it stores 1) and its INTEGER affinity turns `'7'` and `7.0`
    into 7, so what it *can* hold wrongly - a REAL, a BLOB, text - is seeded here; the `bool`
    is refused at row level in `test_sql_ids.py`.
    """

    @pytest.mark.anyio
    @pytest.mark.parametrize("value", [11.5, b"11", "eleven"])
    async def test_a_session_id_that_is_not_an_integer_is_a_miss(
        self, build: Build, value: object
    ) -> None:
        store, _log = build(**serial_schema(id=value, session_types={"id": "INTEGER NOT NULL"}))

        assert await store.fetch_session_by_token(TOKEN) is None

    @pytest.mark.anyio
    @pytest.mark.parametrize("value", [7.5, b"7", "seven"])
    async def test_a_user_id_that_is_not_an_integer_is_a_miss(
        self, build: Build, value: object
    ) -> None:
        store, _log = build(
            **serial_schema(userId=value, user={"id": value}, user_types={"id": "INTEGER"})
        )

        assert await store.fetch_session_by_token(TOKEN) is None

    @pytest.mark.anyio
    @pytest.mark.parametrize("value", [3.5, b"3", "three"])
    async def test_an_unreadable_impersonator_is_none_not_its_raw_value(
        self, build: Build, value: object
    ) -> None:
        store, _log = build(**serial_schema(impersonatedBy=value))

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.impersonated_by is None
        assert record.payload["impersonatedBy"] is None


class TestUuidIds:
    @pytest.mark.anyio
    async def test_uuids_stored_as_text_read_unchanged(self, build: Build) -> None:
        """`generateId: "uuid"` on a database without a uuid type: a text column, read as text."""
        store, _log = build(
            sessions=[{**SESSION_ROW, "id": str(SESSION_UUID), "userId": str(USER_UUID)}],
            users=[{**USER_ROW, "id": str(USER_UUID)}],
        )

        record = await store.fetch_session_by_token(TOKEN)
        found = await store.fetch_user_by_id(str(USER_UUID))

        assert record is not None
        assert (record.id, record.user_id) == (str(SESSION_UUID), str(USER_UUID))
        assert found is not None and found.id == str(USER_UUID)

    @pytest.mark.anyio
    async def test_a_sqlalchemy_uuid_column_on_sqlite_is_text_to_reflection(
        self, build: Build
    ) -> None:
        """Pinned, not endorsed: SQLite reflects SQLAlchemy's `Uuid` column as `CHAR(32)`, so the
        store reads the 32 hex digits stored there as the id - a table Better Auth did not write,
        since its SQLite uuid ids are hyphenated text (the case above)."""
        store, _log = build(**hex_uuid_schema())

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.user_id == USER_UUID.hex

    @pytest.mark.anyio
    @pytest.mark.usefixtures("uuid_reflection")
    async def test_a_uuid_column_reads_lowercase_hyphenated(self, build: Build) -> None:
        store, _log = build(**hex_uuid_schema())

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None and record.user is not None
        assert (record.id, record.user_id) == (str(SESSION_UUID), str(USER_UUID))
        assert record.user.id == str(USER_UUID)
        assert (record.payload["id"], record.user.payload["id"]) == (
            str(SESSION_UUID),
            str(USER_UUID),
        )

    @pytest.mark.anyio
    @pytest.mark.usefixtures("uuid_reflection")
    async def test_a_uuid_column_is_looked_up_by_its_canonical_text(self, build: Build) -> None:
        store, _log = build(**hex_uuid_schema())

        found = await store.fetch_user_by_id(str(USER_UUID))

        assert found is not None
        assert found.id == str(USER_UUID)

    @pytest.mark.anyio
    @pytest.mark.usefixtures("uuid_reflection")
    @pytest.mark.parametrize(
        "spelling",
        [str(USER_UUID).upper(), USER_UUID.hex, f"{{{USER_UUID}}}", f"urn:uuid:{USER_UUID}"],
    )
    async def test_another_spelling_of_a_uuid_is_a_miss(self, build: Build, spelling: str) -> None:
        store, _log = build(**hex_uuid_schema())

        assert await store.fetch_user_by_id(spelling) is None


class TestCookieVerifierPath:
    @pytest.mark.anyio
    async def test_a_serial_id_deployment_gets_a_session_with_text_ids(self, build: Build) -> None:
        store, _log = build(**serial_schema(impersonatedBy=SERIAL_ADMIN_ID))

        session = await run(cookie_verifier(store), http(cookie=f"{COOKIE}={sign(TOKEN)}"))

        assert session is not None
        assert session.user.id == "7"
        assert session.id == "11"
        assert session.impersonated_by == "3"
        assert (session.raw["id"], session.raw["userId"]) == ("11", "7")

    @pytest.mark.anyio
    @pytest.mark.usefixtures("uuid_reflection")
    async def test_a_uuid_deployment_gets_a_session_with_text_ids(self, build: Build) -> None:
        store, _log = build(**hex_uuid_schema())

        session = await run(cookie_verifier(store), http(cookie=f"{COOKIE}={sign(TOKEN)}"))

        assert session is not None
        assert session.user.id == str(USER_UUID)
        assert session.id == str(SESSION_UUID)


def cookie_verifier(store: Store) -> CookieVerifier:
    return CookieVerifier(
        secret=SECRET,
        store=store,
        csrf=CsrfDisabled(reason="the id suite does not exercise CSRF"),
        secure_cookies=False,
    )


async def store_connected(store: Store) -> None:
    await store.connect()
