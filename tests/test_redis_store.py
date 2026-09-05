"""The Redis store: one `GET` on the raw token, and nothing else - ever.

When better-auth is configured with secondary storage, Redis is the whole truth: the Postgres
session table may never receive the row at all, and a session that was signed out is *gone from
Redis* while a stale replica or an un-cascaded row could still be sitting in the database. A
store that fell back to the database on a miss would therefore resurrect revoked sessions
(D-008), so the interesting assertions here are about what this store does *not* do.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import sys
from typing import Any

import pytest
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    ConfigurationError,
    CookieVerifier,
    CsrfDisabled,
    RedisSessionStore,
    SessionError,
    SessionStore,
    SharedSecret,
    User,
)
from fastapi_better_auth._internal.reasons import REDACTED
from fastapi_better_auth._internal.stores import redis_store as redis_store_module
from tests.stores import (
    ADMIN_ID,
    EXPIRES_AT,
    SESSION_ID,
    TOKEN,
    USER_ID,
    DecodingRedis,
    RecordingRedis,
    stored,
    wire_session,
    wire_user,
)

UNKNOWN_TOKEN = "5RmMvJt3xQ8bWfKcApZnUhLd2YeGsT7q"
EXTRA = "fastapi-better-auth-bridge[redis]"
FAR_FUTURE_ISO = "2999-01-01T00:00:00.000Z"
VERIFIER_SECRET = SharedSecret("Qb8Xm2vTz6Lp1RkYd9Wn4Hs7Cj3Fg5Ae")

NESTING = sys.getrecursionlimit() * 4
NESTED_BOMB = "[" * NESTING + "]" * NESTING
"""A few kilobytes - far under the byte cap - and deeper than json's recursive scanner goes."""

LONE_SURROGATE_TOKEN = chr(0xD800) + "abc"
"""An unpaired surrogate: a `str` Python holds happily and cannot encode as UTF-8.

Spelled with `chr` rather than an escape so the file itself stays encodable. `json.dumps`
writes it as an escape, so the stored value is ASCII and only the *parsed* token carries it -
which is exactly how it arrives from a real Redis holding what some other writer put there.
"""


def store_over(**values: str) -> tuple[RedisSessionStore, RecordingRedis]:
    client = RecordingRedis(values)
    return RedisSessionStore(client=client), client


def _labelled(value: object) -> str:
    """Name a case by its label and never by its stored value: some of them are kilobytes."""
    return value if isinstance(value, str) and len(value) <= 24 else "value"


def _minus(key: str) -> dict[str, Any]:
    return {name: value for name, value in wire_session().items() if name != key}


class TestFetchSessionByToken:
    @pytest.mark.anyio
    async def test_it_reads_the_raw_token_key_and_embeds_the_user(self) -> None:
        """The key is the token itself, with no namespace in front of it - checked live against
        the harness's secondary-storage topology, and pinned here."""
        store, client = store_over(**{TOKEN: stored()})

        record = await store.fetch_session_by_token(TOKEN)

        assert client.calls == [("get", (TOKEN,))]
        assert record is not None
        assert record.token == TOKEN
        assert record.user_id == USER_ID
        assert record.expires_at == EXPIRES_AT
        assert record.payload["id"] == SESSION_ID
        assert record.user is not None
        assert record.user.id == USER_ID
        assert record.user.payload["email"] == "seed@example.com"

    @pytest.mark.anyio
    async def test_the_happy_path_costs_exactly_one_round_trip(self) -> None:
        """The stored value already carries the user, so the second fetch a database needs
        does not exist here. A store that issued it anyway would be paying for nothing."""
        store, client = store_over(**{TOKEN: stored()})

        await store.fetch_session_by_token(TOKEN)

        assert len(client.calls) == 1

    @pytest.mark.anyio
    async def test_the_z_suffixed_timestamp_is_read_as_aware_utc(self) -> None:
        """`JSON.stringify(new Date())` writes `...Z`, which `datetime.fromisoformat` did not
        accept before 3.11 - so this is the one parse the store cannot delegate."""
        store, _client = store_over(**{TOKEN: stored()})

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.expires_at.tzinfo is not None
        assert record.expires_at == EXPIRES_AT

    @pytest.mark.anyio
    async def test_an_iso_expiry_without_a_z_is_still_read_as_utc(self) -> None:
        """C6. A custom `secondaryStorage` that serializes a `Date` without the trailing `Z`
        answers a naive ISO string; `as_moment` still reads it as UTC. Reachable, so pinned - the
        alternative reading (leave it naive) would fail `StoredSession`'s aware-only contract."""
        # Same instant as EXPIRES_AT, but written without the trailing `Z` fromisoformat needs.
        value = stored(session=wire_session(expiresAt="2026-09-05T12:00:00.000"))
        store, _client = store_over(**{TOKEN: value})

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.expires_at.tzinfo is not None
        assert record.expires_at == EXPIRES_AT

    @pytest.mark.anyio
    async def test_a_client_that_decodes_responses_is_read_the_same_way(self) -> None:
        """`Redis(decode_responses=True)` answers `str`, the default answers `bytes`. Both are
        deployments people have, and neither is the store's business to insist on."""
        client = DecodingRedis({TOKEN: stored()})
        store = RedisSessionStore(client=client)

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.user_id == USER_ID

    @pytest.mark.anyio
    async def test_a_miss_is_a_miss_and_never_a_second_lookup(self) -> None:
        """The whole of D-008 in one assertion: an absent key is the answer, not a question."""
        store, client = store_over(**{TOKEN: stored()})

        record = await store.fetch_session_by_token(UNKNOWN_TOKEN)

        assert record is None
        assert client.calls == [("get", (UNKNOWN_TOKEN,))]

    @pytest.mark.anyio
    @pytest.mark.parametrize("blank", ["", "   ", "\n"], ids=["empty", "spaces", "newline"])
    async def test_a_blank_token_never_reaches_redis(self, blank: str) -> None:
        store, client = store_over(**{TOKEN: stored()})

        record = await store.fetch_session_by_token(blank)

        assert record is None
        assert client.calls == []

    @pytest.mark.anyio
    async def test_the_admin_fields_surface_from_the_stored_payload(self) -> None:
        value = stored(
            session=wire_session(impersonatedBy=ADMIN_ID),
            user=wire_user(banned=True, banReason="testing", banExpires="2026-12-01T00:00:00.000Z"),
        )
        store, _client = store_over(**{TOKEN: value})

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.impersonated_by == ADMIN_ID
        assert record.user is not None
        assert record.user.banned is True
        assert record.user.ban_expires is not None
        assert record.user.ban_expires.tzinfo is not None
        assert record.user.payload["banReason"] == "testing"

    @pytest.mark.anyio
    async def test_a_payload_without_the_admin_keys_reports_unknown_not_false(self) -> None:
        value = json.dumps(
            {
                "session": {
                    key: val for key, val in wire_session().items() if key != "impersonatedBy"
                },
                "user": {
                    key: val
                    for key, val in wire_user().items()
                    if key not in {"banned", "banReason", "banExpires", "role"}
                },
            }
        )
        store, _client = store_over(**{TOKEN: value})

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.impersonated_by is None
        assert record.user is not None
        assert record.user.banned is None


class TestMalformedValues:
    """Every one of these is a miss and a warning. None of them is a 500: a 500 is
    distinguishable from the uniform 401 on the wire, and this input is not the client's."""

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("label", "value"),
        [
            ("not-json", "{not json at all"),
            ("json-scalar", '"a string"'),
            ("json-list", "[]"),
            ("json-null", "null"),
            ("no-session", json.dumps({"user": wire_user()})),
            ("no-user", json.dumps({"session": wire_session()})),
            ("session-not-object", json.dumps({"session": 5, "user": wire_user()})),
            ("user-not-object", json.dumps({"session": wire_session(), "user": "nope"})),
            ("no-expiry", json.dumps({"session": _minus("expiresAt"), "user": wire_user()})),
            ("expiry-not-a-date", stored(session=wire_session(expiresAt="soon"))),
            ("expiry-a-number", stored(session=wire_session(expiresAt=1767225600))),
            ("no-user-id", stored(session=wire_session(userId=""))),
            ("no-token", stored(session=wire_session(token=""))),
            ("empty-object", "{}"),
            ("blank-user-id", stored(user=wire_user(id="   "))),
            ("banned-not-a-boolean", stored(user=wire_user(banned="yes"))),
            ("banned-a-number", stored(user=wire_user(banned=1))),
            ("ban-expiry-not-a-date", stored(user=wire_user(banExpires="whenever"))),
            ("deeply-nested", NESTED_BOMB),
            ("surrogate-token", stored(session=wire_session(token=LONE_SURROGATE_TOKEN))),
        ],
        ids=_labelled,
    )
    async def test_it_is_a_miss(
        self, label: str, value: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        store, _client = store_over(**{TOKEN: value})

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            record = await store.fetch_session_by_token(TOKEN)

        assert record is None, label
        assert caplog.records, f"{label} was refused silently"

    @pytest.mark.anyio
    async def test_a_client_answering_something_that_is_not_bytes_is_a_miss(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A client wrapper, a decoding layer, a mock somebody wired in: whatever answered, if
        it is not a string of bytes it is not a stored session."""

        class Odd:
            async def get(self, name: str) -> object:
                return {"already": "parsed"}

        store = RedisSessionStore(client=Odd())

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            record = await store.fetch_session_by_token(TOKEN)

        assert record is None
        assert caplog.records

    @pytest.mark.anyio
    async def test_a_value_answering_for_a_different_token_is_a_miss(self) -> None:
        """Redis is keyed by the token, and the value repeats it. If the two disagree, someone
        else wrote that key - and honouring it would authenticate the wrong session."""
        store, _client = store_over(**{TOKEN: stored(session=wire_session(token=UNKNOWN_TOKEN))})

        assert await store.fetch_session_by_token(TOKEN) is None

    @pytest.mark.anyio
    async def test_an_oversized_value_is_refused_before_it_is_parsed(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        padded = json.dumps({"session": wire_session(userAgent="x" * 200_000), "user": wire_user()})
        store, _client = store_over(**{TOKEN: padded})

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            record = await store.fetch_session_by_token(TOKEN)

        assert record is None
        assert caplog.records

    @pytest.mark.anyio
    async def test_no_stored_value_reaches_the_warning_it_causes(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A malformed value is still session data. The line names a fingerprint of the key and
        what was wrong with the value - never the key, and never the value."""
        store, _client = store_over(**{TOKEN: stored(session=wire_session(expiresAt="soon"))})

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            await store.fetch_session_by_token(TOKEN)

        written = " ".join(entry.getMessage() for entry in caplog.records)
        assert written
        assert TOKEN not in written
        assert SESSION_ID not in written
        assert USER_ID not in written

    @pytest.mark.anyio
    async def test_the_cap_counts_bytes_not_characters(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """D1. A `decode_responses=True` client answers `str`; a multibyte character is more than
        one byte on the wire the cap is about. This value is under the cap in characters and over
        it in bytes, so only a byte count refuses it - the reason is `cap`, not `not JSON`."""
        value = "é" * 40  # 40 characters, 80 UTF-8 bytes
        assert len(value) < 50 < len(value.encode("utf-8"))
        client = DecodingRedis({TOKEN: value})
        store = RedisSessionStore(client=client, max_bytes=50)

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            record = await store.fetch_session_by_token(TOKEN)

        assert record is None
        assert any("cap" in entry.getMessage() for entry in caplog.records)

    @pytest.mark.anyio
    async def test_a_hostile_type_name_cannot_forge_a_second_log_line(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """D2. The type name is the only interpolated part of an `unusable` reason. A client
        answering an object whose class name carries a newline must not forge a WARNING line."""

        class Odd:
            pass

        Odd.__name__ = "bytes\n2026-01-01 CRITICAL forged log line"

        class Weird:
            async def get(self, name: str) -> object:
                return Odd()

        store = RedisSessionStore(client=Weird())

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            assert await store.fetch_session_by_token(TOKEN) is None

        written = " ".join(entry.getMessage() for entry in caplog.records)
        assert "forged log line" not in written
        assert REDACTED in written


class TestBannedThroughTheVerifier:
    """B2. `StoredUser` now refuses a `banned` that is not `bool | None`, and that refusal is a
    `TypeError` - so the question this answers is whether a real stored value can reach it. It
    cannot: `_user` refuses a non-boolean `banned` before any record is built, so a JSON `1`
    stays a miss, and the verifier turns the miss into a refusal rather than a 500."""

    @pytest.mark.anyio
    async def test_a_banned_of_one_is_a_refusal_and_never_an_escape(self) -> None:
        value = stored(session=wire_session(expiresAt=FAR_FUTURE_ISO), user=wire_user(banned=1))
        store = RedisSessionStore(client=RecordingRedis({TOKEN: value}))
        verifier = CookieVerifier(
            secret=VERIFIER_SECRET,
            store=store,
            csrf=CsrfDisabled(reason="this row is about the ban check, not CSRF"),
            secure_cookies=False,
        )
        connection = _cookie_connection(TOKEN)
        credential = verifier.extract(connection)
        assert credential is not None

        with pytest.raises(SessionError):
            await verifier.verify(credential, User)


def _cookie_connection(token: str) -> HTTPConnection:
    digest = hmac.new(
        VERIFIER_SECRET.get_secret_value().encode(), token.encode(), hashlib.sha256
    ).digest()
    value = f"{token}.{base64.b64encode(digest).decode()}"
    return HTTPConnection(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"cookie", f"better-auth.session_token={value}".encode())],
        }
    )


class TestFetchUserById:
    @pytest.mark.anyio
    async def test_it_is_a_miss_and_issues_no_command_at_all(self) -> None:
        """better-auth's secondary storage keys sessions and an active-session list - never a
        user by id. There is nothing here to answer from, and guessing a key or reaching for a
        database would be the fallback D-008 forbids. A session fetched from this store always
        carries its user, so the sanctioned flow never asks."""
        store, client = store_over(**{TOKEN: stored()})

        record = await store.fetch_user_by_id(USER_ID)

        assert record is None
        assert client.calls == []


class TestReadOnly:
    @pytest.mark.anyio
    async def test_every_path_issues_only_get(self) -> None:
        """Asserted against the commands the client actually received. The Node side owns every
        write, including the touch that extends a session - one issued here would rewrite an
        expiry the bridge is only supposed to read."""
        store, client = store_over(**{TOKEN: stored()})

        await store.fetch_session_by_token(TOKEN)
        await store.fetch_session_by_token(UNKNOWN_TOKEN)
        await store.fetch_session_by_token("")
        await store.fetch_user_by_id(USER_ID)

        assert client.commands == {"get"}


class TestKeyPrefix:
    @pytest.mark.anyio
    async def test_a_prefix_is_prepended_when_one_is_configured(self) -> None:
        """A deployment whose `secondaryStorage` namespaces its keys is a configuration, not a
        different protocol. The default is the empty prefix better-auth itself uses."""
        store = RedisSessionStore(
            client=(client := RecordingRedis({f"ba:{TOKEN}": stored()})), key_prefix="ba:"
        )

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert client.calls == [("get", (f"ba:{TOKEN}",))]


class TestConstruction:
    def test_it_satisfies_the_protocol(self) -> None:
        assert isinstance(RedisSessionStore(client=RecordingRedis()), SessionStore)

    @pytest.mark.anyio
    @pytest.mark.parametrize("anyio_backend", ["asyncio"])
    async def test_a_url_builds_a_client_the_store_then_owns(self) -> None:
        """The `[redis]` extra's whole purpose: a deployment with no client of its own gets one,
        and the store closes what it built.

        asyncio only, and that is redis-py's constraint rather than this store's: its client
        touches `asyncio` directly, so a client *it* built cannot run under trio. A client the
        application injects is never touched here, which is why every other case in this module
        runs on both backends."""
        async with RedisSessionStore(url="redis://localhost:56379/0") as store:
            assert isinstance(store, SessionStore)

    def test_neither_a_url_nor_a_client_is_refused(self) -> None:
        with pytest.raises(ConfigurationError, match="url"):
            RedisSessionStore()

    @pytest.mark.parametrize("bad", [7, "", "   "], ids=["int", "empty", "blank"])
    def test_a_url_that_is_not_a_usable_string_is_refused(self, bad: Any) -> None:
        """D3. `url=` was unvalidated while the `Raises:` block promises a `ConfigurationError`
        for every construction failure; `url=7` was an `AttributeError` from `from_url`."""
        with pytest.raises(ConfigurationError, match="url"):
            RedisSessionStore(url=bad)

    def test_a_rejected_url_does_not_echo_its_value(self) -> None:
        """A redis URL can carry a password; the refusal for a bad one must not put it in the
        message or on `__cause__`."""
        secret = (
            "gopher://user:sup3r-secret-pw@host:6379/0"  # unsupported scheme -> from_url rejects
        )
        with pytest.raises(ConfigurationError) as caught:
            RedisSessionStore(url=secret)

        assert "sup3r-secret-pw" not in str(caught.value)
        assert caught.value.__cause__ is None

    @pytest.mark.parametrize(
        "cap", [0, -1, 1.5, True, "8192"], ids=["zero", "negative", "float", "bool", "string"]
    )
    def test_a_cap_that_could_not_admit_a_value_is_refused(self, cap: Any) -> None:
        """A cap below one refuses every stored value - a total authentication outage that
        startup would otherwise call healthy."""
        with pytest.raises(ConfigurationError, match="max_bytes"):
            RedisSessionStore(client=RecordingRedis(), max_bytes=cap)

    def test_a_refused_argument_never_gets_as_far_as_building_a_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ordering, pinned: a refusal after the client was built would leave a connection pool
        nobody holds and nobody closes. Blocking the import proves the build never happened."""
        monkeypatch.setitem(sys.modules, "redis", None)
        monkeypatch.setitem(sys.modules, "redis.asyncio", None)

        with pytest.raises(ConfigurationError, match="key_prefix"):
            RedisSessionStore(url="redis://localhost:56379/0", key_prefix=7)  # type: ignore[arg-type]

    def test_a_prefix_that_is_not_a_string_is_refused(self) -> None:
        """It is concatenated onto the token to form the key; a non-string would either raise
        on the first request or, worse, stringify into a key nobody meant."""
        with pytest.raises(ConfigurationError, match="key_prefix"):
            RedisSessionStore(client=RecordingRedis(), key_prefix=7)  # type: ignore[arg-type]

    def test_both_a_url_and_a_client_is_refused(self) -> None:
        """Two sources of truth for which Redis is authoritative is one too many."""
        with pytest.raises(ConfigurationError):
            RedisSessionStore(url="redis://localhost:56379/0", client=RecordingRedis())

    def test_constructing_without_the_library_names_the_extra_to_install(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Blocked rather than uninstalled: the failure has to be a startup
        `ConfigurationError` naming the extra, not an `ImportError` at the first fetch."""
        monkeypatch.setitem(sys.modules, "redis", None)
        monkeypatch.setitem(sys.modules, "redis.asyncio", None)

        with pytest.raises(ConfigurationError) as caught:
            RedisSessionStore(url="redis://localhost:56379/0")

        assert EXTRA in str(caught.value)

    def test_an_injected_client_needs_no_import_at_all(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The extra buys the client, not the store."""
        monkeypatch.setitem(sys.modules, "redis", None)
        monkeypatch.setitem(sys.modules, "redis.asyncio", None)

        assert isinstance(RedisSessionStore(client=RecordingRedis()), SessionStore)

    @pytest.mark.anyio
    async def test_closing_the_store_leaves_an_injected_client_open(self) -> None:
        """Lifecycle belongs to whoever built the client; closing a shared pool out from under
        the application that lent it to us is an outage well beyond this library."""
        client = RecordingRedis()

        async with RedisSessionStore(client=client) as store:
            assert isinstance(store, SessionStore)

        assert not client.closed

    @pytest.mark.anyio
    async def test_closing_a_store_closes_the_client_it_built(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """C3, the other branch: the `url=` path owns the client it built, so it must close it -
        a no-op close is a pool leak on every `url=` store. The only existing close assertion
        covers the *borrowed* branch, so this one is outcome-unpinned without it."""
        built = RecordingRedis()

        class FakeRedis:
            @staticmethod
            def from_url(url: str) -> RecordingRedis:
                return built

        monkeypatch.setattr(redis_store_module, "_import_redis", lambda: FakeRedis)

        async with RedisSessionStore(url="redis://localhost:6379/0") as store:
            assert isinstance(store, SessionStore)

        assert built.closed


class TestFailures:
    @pytest.mark.anyio
    async def test_a_connection_failure_propagates_untranslated(self) -> None:
        """A store does not know what an unreachable Redis means to the request that needed it.
        The verifier above does, and turns it into `AuthServiceUnavailable` - a refusal."""

        class Broken:
            async def get(self, name: str) -> Any:
                raise ConnectionError("redis is down")

        store = RedisSessionStore(client=Broken())

        with pytest.raises(ConnectionError):
            await store.fetch_session_by_token(TOKEN)

    @pytest.mark.anyio
    async def test_the_store_holds_no_database_to_fall_back_to(self) -> None:
        """Structural, not behavioural: there is no engine, no session maker and no URL for a
        database anywhere on this object, so the fallback D-008 forbids cannot be added by
        accident. C5: an allowlist, not a type denylist - a `_fallback_dsn = "postgresql://..."`
        is a `str` and would slip a name-based check, so this asserts the store's attributes ARE
        exactly the four it should have and nothing has crept in."""
        store, _client = store_over(**{TOKEN: stored()})

        assert set(vars(store)) == {"_built", "_client", "_prefix", "_max_bytes"}


class TestConstantTimeTokenCompare:
    @pytest.mark.anyio
    async def test_the_stored_token_check_goes_through_compare_digest(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """C1. A mismatch is a miss whether the compare is `==` or `compare_digest`, so the
        constant-time property is outcome-invisible and pinned only by reaching the call. The
        token repeated in the stored value is a secret, and a `==` there is a timing oracle."""
        seen: list[tuple[object, object]] = []
        real = hmac.compare_digest

        def spy(left: Any, right: Any) -> bool:
            seen.append((left, right))
            return real(left, right)

        monkeypatch.setattr(hmac, "compare_digest", spy)
        store, _client = store_over(**{TOKEN: stored()})

        assert await store.fetch_session_by_token(TOKEN) is not None
        assert seen, "the stored-token check did not reach hmac.compare_digest"
        assert all(isinstance(side, bytes) for pair in seen for side in pair), (
            "compare_digest must be handed bytes, or it raises on a non-ASCII token"
        )
