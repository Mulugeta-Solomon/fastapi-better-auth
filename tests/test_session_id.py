"""`Session.id`: the session row's own id, typed where the store reads it (#84).

Better Auth's `session` table keys every row on `id`, and it is the id get-session and the Redis
document carry too. It is not the token: the token is the credential, and the id is what a route
can log, compare or hand to its own tables without holding a credential at all.

Where it is read decides how strict it is. The SQL store selects the column on every lookup and
Better Auth declares it the primary key, so a row without a usable one is data the store cannot
vouch for - a miss, and the request a 401, like a row missing `token` or `userId`. The Redis
document and the get-session body are JSON nobody here promised to carry it, so a missing or
malformed one there is `None` and the session still verifies. Mode B has no session row at all:
the JWT plugin's default payload is the *user*, and its `id` claim is the user's id, so a JWT
session's `id` is `None` whatever the claims say.
"""

from __future__ import annotations

import logging
import pathlib
from collections.abc import AsyncIterator
from typing import Any

import pytest
from pydantic import ValidationError

from fastapi_better_auth import (
    CookieVerifier,
    CsrfDisabled,
    Session,
    SessionRevoked,
    StoredSession,
    StoredUser,
    User,
)
from fastapi_better_auth._internal.stores.session_document import parse_session_document
from tests import remote_fixtures as remote
from tests.cookies import (
    CAPTURED_TOKEN,
    COOKIE,
    FAR_FUTURE,
    SECRET,
    FakeStore,
    http,
    run,
    sign,
    stored_session,
    verifier,
)
from tests.jwt_fixtures import SIGNER, build
from tests.stores import (
    EXPIRES_AT,
    FLAVOURS,
    SESSION_ID,
    SESSION_ROW,
    TOKEN,
    USER_ID,
    RecordingRedis,
    StoreFixture,
    stored,
    wire_session,
    wire_user,
)
from tests.tokens import (
    GOLDEN_CLAIMS,
    GOLDEN_JWKS,
    GOLDEN_TOKEN,
    claims,
    frozen_at,
    inside_the_golden_validity,
)
from tests.transports import json_reply

ROW_ID = "Hq2vX9mTz4Lp7RkYd1Wn8Hs3Cj6Fg0Ae"
LONE_SURROGATE = chr(0xD800) + "sess"
UNUSABLE_DOCUMENT_IDS: tuple[object, ...] = ("", "   ", 42, 4.2, True, ["sess"], {"id": 1})
LOGGER = "fastapi_better_auth"


def base_user() -> User:
    return User(id=USER_ID)


def live_row_without_an_id() -> dict[str, Any]:
    """The seeded (live) session row with no id. Built here so no test local holds its token."""
    return {**SESSION_ROW, "id": None}


def upstream_with_id(value: object) -> dict[str, Any]:
    """A get-session document whose session id is `value`, built outside any test frame."""
    document = remote.document()
    document["session"]["id"] = value
    return document


def custom_record(**overrides: Any) -> StoredSession:
    """A record the way the README's own `DictSessionStore` builds one: no `id` keyword at all."""
    fields: dict[str, Any] = {
        "token": CAPTURED_TOKEN,
        "user_id": USER_ID,
        "expires_at": FAR_FUTURE,
        "payload": {"userId": USER_ID},
        "user": StoredUser(id=USER_ID, payload={"id": USER_ID}),
    }
    fields.update(overrides)
    return StoredSession(**fields)


# ---------------------------------------------------------------- the model


class TestTheField:
    def test_a_session_built_without_one_reads_none(self) -> None:
        """Third-party verifiers build `Session(...)` without it, so it has to default."""
        assert Session[User](user=base_user(), expires_at=None, raw={}).id is None

    def test_a_session_carries_the_id_it_was_given(self) -> None:
        session = Session[User](user=base_user(), expires_at=None, id=ROW_ID, raw={})

        assert session.id == ROW_ID

    def test_it_is_frozen_like_every_other_field(self) -> None:
        session = Session[User](user=base_user(), expires_at=None, id=ROW_ID, raw={})

        with pytest.raises(ValidationError):
            session.id = "another-row"

    def test_the_docstring_says_where_it_comes_from_in_each_mode(self) -> None:
        doc = Session.__doc__ or ""

        assert "id:" in doc
        assert "Mode B" in doc


class TestTheRecord:
    def test_a_record_built_the_documented_way_without_an_id_still_builds(self) -> None:
        """The README's custom store never names `id`; a new required field would break it."""
        assert custom_record().id is None

    def test_a_record_carries_the_id_a_store_gives_it(self) -> None:
        assert custom_record(id=ROW_ID).id == ROW_ID

    @pytest.mark.parametrize("value", [42, b"sess", ["sess"], 4.2], ids=repr)
    def test_an_id_that_is_not_text_is_refused_where_the_store_builds_it(
        self, value: object
    ) -> None:
        """Typed at the store boundary: a custom store's bug is named there, not as a
        validation error out of a verifier three frames later."""
        with pytest.raises(TypeError, match="StoredSession.id must be a str or None"):
            custom_record(id=value)

    @pytest.mark.parametrize("value", ["", "   ", "\t"], ids=repr)
    def test_a_blank_id_is_refused_where_the_store_builds_it(self, value: str) -> None:
        with pytest.raises(ValueError, match="StoredSession.id must not be blank"):
            custom_record(id=value)

    def test_the_id_is_in_the_record_repr_and_the_token_still_is_not(self) -> None:
        """A row id is not a credential - `raw` already renders it - so it may be rendered."""
        rendered = repr(custom_record(id=ROW_ID))

        assert ROW_ID in rendered
        assert CAPTURED_TOKEN not in rendered


# ---------------------------------------------------------------- the SQL store: required


@pytest.fixture
def anyio_backend() -> str:
    """aiosqlite and the Redis double are asyncio here; there is no trio leg to run."""
    return "asyncio"


@pytest.fixture(params=FLAVOURS)
def flavour(request: pytest.FixtureRequest) -> str:
    kind = request.param
    assert isinstance(kind, str)
    return kind


@pytest.fixture
async def sql(tmp_path: pathlib.Path, flavour: str) -> AsyncIterator[StoreFixture]:
    fixture = StoreFixture(tmp_path, flavour)
    yield fixture
    await fixture.aclose()


class TestTheSqlStore:
    @pytest.mark.anyio
    async def test_the_row_id_reaches_the_record(self, sql: StoreFixture) -> None:
        store, _log = sql()

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.id == SESSION_ID

    @pytest.mark.anyio
    @pytest.mark.parametrize("value", [None, "", "   "], ids=repr)
    async def test_a_row_without_a_usable_id_is_a_miss_and_a_warning(
        self, sql: StoreFixture, value: str | None, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Better Auth declares `id` the primary key, so no real row lacks one: a row that does
        is data this store cannot vouch for, exactly as a NULL `token` or `userId` is."""
        store, _log = sql(sessions=({**SESSION_ROW, "id": value},), relax_session_columns=("id",))

        with caplog.at_level(logging.WARNING, logger=LOGGER):
            record = await store.fetch_session_by_token(TOKEN)

        assert record is None
        messages = [entry.getMessage() for entry in caplog.records]
        assert any("id is null, blank or unreadable" in message for message in messages), messages
        assert all(TOKEN not in message for message in messages)

    @pytest.mark.anyio
    async def test_the_seeded_row_verifies_and_its_id_is_the_session_id(
        self, sql: StoreFixture
    ) -> None:
        """The shared fixture row is a live session, so a test that drives it through a verifier
        is refused only for the reason it plants - never for an expiry nobody chose."""
        store, _log = sql()

        session = await run(sql_verifier(store), http(cookie=f"{COOKIE}={sign(TOKEN)}"))

        assert session is not None
        assert session.id == SESSION_ID

    @pytest.mark.anyio
    async def test_through_the_verifier_that_row_is_the_uniform_401(
        self, sql: StoreFixture
    ) -> None:
        store, _log = sql(sessions=(live_row_without_an_id(),), relax_session_columns=("id",))

        with pytest.raises(SessionRevoked):
            await run(sql_verifier(store), http(cookie=f"{COOKIE}={sign(TOKEN)}"))


def sql_verifier(store: Any) -> CookieVerifier:
    return CookieVerifier(
        secret=SECRET,
        store=store,
        csrf=CsrfDisabled(reason="this suite is about the stored session id"),
        secure_cookies=False,
    )


# ---------------------------------------------------------------- the document: optional


class TestTheDocument:
    def test_the_session_id_reaches_the_record(self) -> None:
        record = parse_session_document({"session": wire_session(), "user": wire_user()}, "k")

        assert record is not None
        assert record.id == SESSION_ID

    @pytest.mark.parametrize("value", UNUSABLE_DOCUMENT_IDS, ids=repr)
    def test_a_malformed_id_is_none_and_never_a_refusal(
        self, value: object, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Nothing guarantees a stored document carries it, so its absence refuses nothing -
        and says nothing either: it is not a record this reader distrusts."""
        document = {"session": wire_session(id=value), "user": wire_user()}

        with caplog.at_level(logging.WARNING, logger=LOGGER):
            record = parse_session_document(document, "k")

        assert record is not None
        assert record.id is None
        assert caplog.records == []

    def test_an_absent_id_is_none_and_never_a_refusal(self) -> None:
        session = {name: value for name, value in wire_session().items() if name != "id"}

        record = parse_session_document({"session": session, "user": wire_user()}, "k")

        assert record is not None
        assert record.id is None

    def test_an_unencodable_id_is_none_rather_than_a_crash_downstream(self) -> None:
        document = {"session": wire_session(id=LONE_SURROGATE), "user": wire_user()}

        record = parse_session_document(document, "k")

        assert record is not None
        assert record.id is None

    @pytest.mark.anyio
    async def test_the_redis_store_reads_it_through_the_same_parser(self) -> None:
        from fastapi_better_auth import RedisSessionStore

        store = RedisSessionStore(client=RecordingRedis({TOKEN: stored()}))

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.id == SESSION_ID
        assert record.expires_at == EXPIRES_AT


# ---------------------------------------------------------------- the verifiers


class TestModeA:
    @pytest.mark.anyio
    async def test_the_record_id_is_the_session_id(self) -> None:
        store = FakeStore(sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, id=ROW_ID)})

        session = await run(verifier(store=store), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

        assert session is not None
        assert session.id == ROW_ID

    @pytest.mark.anyio
    async def test_a_record_without_one_is_a_session_without_one(self) -> None:
        store = FakeStore(sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN)})

        session = await run(verifier(store=store), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

        assert session is not None
        assert session.id is None


class TestModeC:
    @pytest.mark.anyio
    async def test_the_get_session_id_is_the_session_id(self) -> None:
        guarded = remote.verifier(remote.RecordingTransport(json_reply(upstream_with_id(ROW_ID))))

        session = await remote.run(guarded, remote.with_cookie())

        assert session.id == ROW_ID

    @pytest.mark.anyio
    @pytest.mark.parametrize("value", [None, "", 42], ids=repr)
    async def test_a_document_without_a_usable_one_still_verifies_with_none(
        self, value: object
    ) -> None:
        guarded = remote.verifier(remote.RecordingTransport(json_reply(upstream_with_id(value))))

        session = await remote.run(guarded, remote.with_cookie())

        assert session.user.id == remote.USER_ID
        assert session.id is None


class TestModeB:
    @pytest.mark.anyio
    async def test_a_default_payload_jwt_has_no_session_id_though_it_carries_an_id_claim(
        self,
    ) -> None:
        """The JWT plugin's default payload is the user object, so `id` is the USER's id - a
        Mode B session that read it would hand every route a user id labelled a session id."""
        guarded, _transport = build(json_reply(GOLDEN_JWKS))

        with frozen_at(inside_the_golden_validity()):
            session = await guarded.verify(GOLDEN_TOKEN, User)

        assert session.raw["id"] == GOLDEN_CLAIMS["id"]
        assert session.id is None

    @pytest.mark.anyio
    async def test_no_claim_a_token_carries_becomes_the_session_id(self) -> None:
        guarded, _transport = build()
        token = SIGNER.sign(claims(id=ROW_ID, sid=ROW_ID, session_id=ROW_ID))

        session = await guarded.verify(token, User)

        assert session.id is None
