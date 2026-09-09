"""The opt-in column allow-lists on the two SQL adapters (#49).

A shared-database deployment does not always own the `user` table. Other services put internal
reference ids and status columns on it, and this store reads *every* column by default (D-156) -
so they reach `StoredUser.payload`, and from there `parse_user` and the verified session. The
allow-list is how such a deployment says which extra columns may travel, without giving up the
default that makes `additionalFields` work everywhere else.

What it never restricts is Better Auth's own set. The required columns are how a session is found
at all, and the optional and admin ones carry `banned` / `banExpires` / `impersonatedBy` - a ban
is this library's business, not the deployment's, so an allow-list cannot switch one off.

Its own module rather than a class in `test_sqlalchemy_store.py`: that file is at its size limit
(D-253/D-254), and both read one `StoreFixture` so the two flavours cannot drift apart. Asyncio
only, for the same reason as its sibling - `aiosqlite` drives the event loop directly.
"""

from __future__ import annotations

import pathlib
import re
from collections.abc import AsyncIterator
from typing import Any

import pytest

from fastapi_better_auth import ConfigurationError
from fastapi_better_auth._internal.stores.sqlalchemy_core import (
    SESSION_ADMIN,
    SESSION_OPTIONAL,
    SESSION_REQUIRED,
    USER_ADMIN,
    USER_OPTIONAL,
    USER_REQUIRED,
)
from tests.stores import ADMIN_ID, FLAVOURS, SESSION_ROW, TOKEN, USER_ID, USER_ROW, StoreFixture

USER_EXTRAS = (("tenantId", "TEXT"), ("internalRef", "TEXT"))
SESSION_EXTRAS = (("deviceId", "TEXT"), ("traceRef", "TEXT"))
TENANT = "tenant-7"
INTERNAL = "internal-do-not-publish"
DEVICE = "device-3"
TRACE = "trace-do-not-publish"

SEEDED_USERS = ({**USER_ROW, "tenantId": TENANT, "internalRef": INTERNAL},)
SEEDED_SESSIONS = ({**SESSION_ROW, "deviceId": DEVICE, "traceRef": TRACE},)


@pytest.fixture
def anyio_backend() -> str:
    """aiosqlite is an asyncio driver; there is no trio leg of this suite to run."""
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


def seeded(store_options: dict[str, Any] | None = None, **overrides: Any) -> dict[str, Any]:
    """Both tables carrying two extra columns each, so an allow-list has something to exclude."""
    schema: dict[str, Any] = {
        "store_options": store_options,
        "extra_user_columns": USER_EXTRAS,
        "extra_session_columns": SESSION_EXTRAS,
        "users": SEEDED_USERS,
        "sessions": SEEDED_SESSIONS,
    }
    schema.update(overrides)
    return schema


class TestUserColumns:
    @pytest.mark.anyio
    async def test_without_an_allow_list_every_extra_column_still_travels(
        self, build: StoreFixture
    ) -> None:
        """Prove the instrument. The default is unchanged (D-156), so the exclusions below are
        exclusions and not a schema that never had the column."""
        store, log = build(**seeded())

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.user is not None
        assert record.user.payload["tenantId"] == TENANT
        assert record.user.payload["internalRef"] == INTERNAL
        assert "internalRef" in " ".join(log.selects)

    @pytest.mark.anyio
    async def test_an_empty_allow_list_selects_no_extra_column_at_all(
        self, build: StoreFixture
    ) -> None:
        """The emitted SQL, not just the payload: a store that selected the column and dropped it
        afterwards would still have sent it over the wire and into the driver's buffers."""
        store, log = build(**seeded({"user_columns": []}))

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.user is not None
        assert "tenantId" not in record.user.payload
        assert "internalRef" not in record.user.payload
        emitted = " ".join(log.selects)
        assert emitted
        assert "tenantId" not in emitted
        assert "internalRef" not in emitted

    @pytest.mark.anyio
    async def test_a_named_column_travels_and_the_rest_do_not(self, build: StoreFixture) -> None:
        store, log = build(**seeded({"user_columns": ["tenantId"]}))

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.user is not None
        assert record.user.payload["tenantId"] == TENANT
        assert "internalRef" not in record.user.payload
        assert "internalRef" not in " ".join(log.selects)

    @pytest.mark.anyio
    async def test_the_by_id_lookup_honours_it_too(self, build: StoreFixture) -> None:
        """`fetch_user_by_id` runs the other statement. Two statements built from one plan, and a
        list applied to only one of them would leak through whichever the caller reached for."""
        store, log = build(**seeded({"user_columns": ["tenantId"]}))

        record = await store.fetch_user_by_id(USER_ID)

        assert record is not None
        assert record.payload["tenantId"] == TENANT
        assert "internalRef" not in record.payload
        assert "internalRef" not in " ".join(log.selects)

    @pytest.mark.anyio
    async def test_better_auths_own_columns_are_selected_whatever_the_list_says(
        self, build: StoreFixture
    ) -> None:
        """A ban is this library's business, not the deployment's. An allow-list that could
        switch `banned` off would be a way to configure the ban check into silence."""
        banned = {**SEEDED_USERS[0], "banned": True, "role": "user", "banReason": "conformance"}
        store, _log = build(**seeded({"user_columns": []}, users=(banned,)))

        record = await store.fetch_user_by_id(USER_ID)

        assert record is not None
        assert record.banned is True
        assert record.payload["banReason"] == "conformance"
        for name in USER_REQUIRED + USER_OPTIONAL + USER_ADMIN:
            assert name in record.payload, name

    @pytest.mark.anyio
    async def test_naming_a_column_this_library_already_reads_adds_nothing(
        self, build: StoreFixture
    ) -> None:
        """`email` is selected anyway, so naming it is redundant rather than wrong - and it must
        not be selected twice, which would put a duplicate label in the joined statement."""
        store, log = build(**seeded({"user_columns": ["email"]}))

        record = await store.fetch_user_by_id(USER_ID)

        assert record is not None
        assert record.payload["email"] == "seed@example.com"
        assert "tenantId" not in record.payload
        # Word-boundaried: `u_emailVerified` starts with the same eight characters.
        assert len(re.findall(r"\bu_email\b", " ".join(log.selects))) == 1

    @pytest.mark.anyio
    async def test_the_known_columns_still_come_first(self, build: StoreFixture) -> None:
        """The allow-list narrows the tail; it does not reorder it, and it cannot let a
        deployment's own column displace one this library promises."""
        store, _log = build(**seeded({"user_columns": ["tenantId"]}))

        record = await store.fetch_user_by_id(USER_ID)

        assert record is not None
        assert list(record.payload)[: len(USER_REQUIRED)] == list(USER_REQUIRED)
        assert list(record.payload)[-1] == "tenantId"


class TestSessionColumns:
    @pytest.mark.anyio
    async def test_an_empty_allow_list_selects_no_extra_session_column(
        self, build: StoreFixture
    ) -> None:
        store, log = build(**seeded({"session_columns": []}))

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert "deviceId" not in record.payload
        assert "traceRef" not in record.payload
        emitted = " ".join(log.selects)
        assert emitted
        assert "deviceId" not in emitted
        assert "traceRef" not in emitted

    @pytest.mark.anyio
    async def test_a_named_session_column_travels_and_the_rest_do_not(
        self, build: StoreFixture
    ) -> None:
        store, log = build(**seeded({"session_columns": ["deviceId"]}))

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.payload["deviceId"] == DEVICE
        assert "traceRef" not in record.payload
        assert "traceRef" not in " ".join(log.selects)

    @pytest.mark.anyio
    async def test_better_auths_own_session_columns_are_selected_whatever_the_list_says(
        self, build: StoreFixture
    ) -> None:
        impersonated = {**SEEDED_SESSIONS[0], "impersonatedBy": ADMIN_ID}
        store, _log = build(**seeded({"session_columns": []}, sessions=(impersonated,)))

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.impersonated_by == ADMIN_ID
        for name in SESSION_REQUIRED + SESSION_OPTIONAL + SESSION_ADMIN:
            assert name in record.payload, name

    @pytest.mark.anyio
    async def test_the_two_lists_are_independent(self, build: StoreFixture) -> None:
        """One statement carries both tables' columns, so a list applied to the wrong half is a
        mistake nothing else in this file would catch."""
        store, _log = build(**seeded({"session_columns": []}))

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.user is not None
        assert "deviceId" not in record.payload
        assert record.user.payload["internalRef"] == INTERNAL


class TestNamesTheTableDoesNotHave:
    """The same point `MISSING_REQUIRED` fires: discovery, so `connect()` from a lifespan stops
    the application rather than letting a typo silently narrow every payload for a year."""

    @pytest.mark.anyio
    async def test_an_unknown_user_column_stops_the_deployment(self, build: StoreFixture) -> None:
        store, _log = build(**seeded({"user_columns": ["tenantId", "tenntId"]}))

        with pytest.raises(ConfigurationError, match="tenntId") as caught:
            await store.connect()

        assert "user" in str(caught.value)

    @pytest.mark.anyio
    async def test_an_unknown_session_column_stops_the_deployment(
        self, build: StoreFixture
    ) -> None:
        store, _log = build(**seeded({"session_columns": ["deviceIdd"]}))

        with pytest.raises(ConfigurationError, match="deviceIdd") as caught:
            await store.connect()

        assert "session" in str(caught.value)

    @pytest.mark.anyio
    async def test_a_column_this_library_knows_but_the_table_lacks_is_refused_too(
        self, build: StoreFixture
    ) -> None:
        """`image` is a default better-auth column, and its absence is otherwise a warning. Named
        in an allow-list it is a claim about the live table, and the claim is wrong."""
        store, _log = build(**seeded({"user_columns": ["image"]}, drop_user_columns=("image",)))

        with pytest.raises(ConfigurationError, match="image"):
            await store.connect()

    @pytest.mark.anyio
    async def test_the_first_lookup_refuses_it_just_the_same(self, build: StoreFixture) -> None:
        """`connect()` is optional. A deployment that never calls it must still refuse rather
        than answer a request from a plan built out of a name the table does not have."""
        store, _log = build(**seeded({"user_columns": ["tenntId"]}))

        with pytest.raises(ConfigurationError, match="tenntId"):
            await store.fetch_session_by_token(TOKEN)


class TestConstruction:
    """Refused before a database is touched: these are typing mistakes at the call site, and the
    first request is far too late to learn that an allow-list was never the shape it looked."""

    @pytest.mark.anyio
    async def test_a_bare_string_is_refused_rather_than_iterated(self, build: StoreFixture) -> None:
        """`user_columns="tenantId"` is a sequence of eight one-character names, and every one of
        them is absent from the table - so without this it would be a confusing discovery error
        about a column called `t`."""
        with pytest.raises(ConfigurationError, match="one character at a time"):
            build(**seeded({"user_columns": "tenantId"}))

    @pytest.mark.anyio
    @pytest.mark.parametrize("blank", ["", "   "], ids=["empty", "spaces"])
    async def test_a_blank_name_is_refused(self, build: StoreFixture, blank: str) -> None:
        with pytest.raises(ConfigurationError):
            build(**seeded({"session_columns": ["deviceId", blank]}))

    @pytest.mark.anyio
    async def test_a_repeated_name_is_refused(self, build: StoreFixture) -> None:
        """A duplicate is a merge artefact or a copy-paste, and silently de-duplicating it would
        hide which of the two lists a reviewer is actually looking at."""
        with pytest.raises(ConfigurationError, match="tenantId"):
            build(**seeded({"user_columns": ["tenantId", "tenantId"]}))

    @pytest.mark.anyio
    async def test_a_name_that_is_not_a_string_is_refused(self, build: StoreFixture) -> None:
        with pytest.raises(ConfigurationError):
            build(**seeded({"user_columns": ["tenantId", 3]}))

    @pytest.mark.anyio
    async def test_an_unordered_collection_is_refused(self, build: StoreFixture) -> None:
        """A `set` has no order, and order is what puts a deployment's own columns after the ones
        this library knows. The annotation says `Sequence` and the check enforces it."""
        with pytest.raises(ConfigurationError, match="sequence"):
            build(**seeded({"user_columns": {"tenantId"}}))
