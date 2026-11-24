"""The SQL store under Better Auth's non-default id modes: serial integers and UUIDs.

Better Auth's default id is a random string, but a deployment may hand id generation to the
database instead - serial integers, or the database's own uuid type - and its CLI then migrates
every `id` column (and every column referencing one) to that type. A driver hands those values
back as `int` or `uuid.UUID`, not `str`, and the store has to read them as the ids they are: the
text Better Auth itself would put in its JSON (decimal digits; lowercase hyphenated UUID).

SQLite, both flavours, as the rest of the SQL suites.
"""

from __future__ import annotations

import pathlib
from collections.abc import AsyncIterator
from typing import Any

import pytest

from tests.stores import FLAVOURS, SESSION_ROW, TOKEN, USER_ROW, StoreFixture

Build = StoreFixture

SERIAL_SESSION_ID = 11
SERIAL_USER_ID = 7

SERIAL_SESSION_TYPES = {
    "id": "INTEGER NOT NULL PRIMARY KEY",
    "userId": "INTEGER NOT NULL",
    "impersonatedBy": "INTEGER",
}
SERIAL_USER_TYPES = {"id": "INTEGER NOT NULL PRIMARY KEY"}


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


def serial_schema(**session: Any) -> dict[str, Any]:
    """The schema `generateId: "serial"` migrates: every id column an integer."""
    return {
        "session_types": SERIAL_SESSION_TYPES,
        "user_types": SERIAL_USER_TYPES,
        "sessions": [{**SESSION_ROW, "id": SERIAL_SESSION_ID, "userId": SERIAL_USER_ID, **session}],
        "users": [{**USER_ROW, "id": SERIAL_USER_ID}],
    }


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
