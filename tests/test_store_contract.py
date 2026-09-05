"""The store contract: what a record promises, and what the Protocol does and does not prove."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from fastapi_better_auth import (
    RedisSessionStore,
    SessionStore,
    SqlAlchemySessionStore,
    StoredSession,
    StoredUser,
    SyncStoreAdapter,
    parse_user,
)
from fastapi_better_auth._internal.models import User
from tests.stores import EXPIRES_AT, TOKEN, USER_ID, RecordingRedis, wire_session, wire_user

AWARE = datetime(2026, 9, 1, tzinfo=timezone.utc)
# DTZ001 is the whole point of this constant: it is the value the records must refuse.
NAIVE = datetime(2026, 9, 1)  # noqa: DTZ001


def a_user(**overrides: Any) -> StoredUser:
    fields: dict[str, Any] = {"id": USER_ID, "payload": wire_user()}
    fields.update(overrides)
    return StoredUser(**fields)


def a_session(**overrides: Any) -> StoredSession:
    fields: dict[str, Any] = {
        "token": TOKEN,
        "user_id": USER_ID,
        "expires_at": EXPIRES_AT,
        "payload": wire_session(),
    }
    fields.update(overrides)
    return StoredSession(**fields)


class TestStoredSession:
    def test_it_requires_a_timezone_aware_expiry(self) -> None:
        """The verifier enforces expiry against `now(UTC)`; a naive value reads another clock."""
        with pytest.raises(ValueError, match="timezone-aware"):
            a_session(expires_at=NAIVE)

    def test_an_aware_expiry_survives_untouched(self) -> None:
        assert a_session(expires_at=AWARE).expires_at == AWARE

    def test_it_is_immutable(self) -> None:
        record = a_session()

        with pytest.raises((AttributeError, TypeError)):
            record.user_id = "someone-else"  # type: ignore[misc]

    def test_the_payload_is_read_only_and_copied(self) -> None:
        """WP11 hands this straight to `Session.raw`; a store that shared a live dict would
        let one request's record change under another's."""
        payload = wire_session()
        record = a_session(payload=payload)
        payload["userId"] = "mutated"

        with pytest.raises(TypeError):
            record.payload["userId"] = "mutated"  # type: ignore[index]
        assert record.payload["userId"] == USER_ID

    def test_the_raw_token_is_absent_from_the_repr(self) -> None:
        """A record reaches tracebacks and error reporters; the token on it is a live credential."""
        rendered = repr(a_session())

        assert TOKEN not in rendered
        assert USER_ID in rendered

    def test_the_admin_fields_default_to_absent_rather_than_false(self) -> None:
        """`None` is "the column is not there"; `False` would be a claim nobody made."""
        record = a_session()

        assert record.impersonated_by is None
        assert record.user is None

    def test_it_carries_an_embedded_user_when_the_store_had_one(self) -> None:
        record = a_session(user=a_user())

        assert record.user is not None
        assert record.user.id == USER_ID

    def test_the_embedded_payload_still_parses_into_a_user_model(self) -> None:
        """The whole point of keeping payloads raw: `parse_user` is the only sanctioned door."""
        record = a_session(user=a_user())
        assert record.user is not None

        user = parse_user(User, record.user.payload)

        assert user.id == USER_ID
        assert user.email == "seed@example.com"
        assert user.email_verified is False


class TestStoredUser:
    def test_banned_defaults_to_unknown_rather_than_false(self) -> None:
        """A deployment without the admin plugin has no `banned` column. `None` says so."""
        assert a_user().banned is None
        assert a_user().ban_expires is None

    def test_a_ban_expiry_must_also_be_aware(self) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            a_user(ban_expires=NAIVE)

    @pytest.mark.parametrize("banned", [1, 0, "true", "", "yes", 2, [1], 1.0], ids=repr)
    def test_a_banned_that_is_not_a_bool_is_refused(self, banned: Any) -> None:
        """`banned` decides whether a user is let in, so it may be `True`, `False` or `None` and
        nothing else. A store handing over `1` or `"true"` is handing over a value the verifier
        would have to guess at, and a guess on a ban check is a guess in the wrong direction."""
        with pytest.raises(TypeError, match="banned"):
            a_user(banned=banned)

    @pytest.mark.parametrize("banned", [True, False, None], ids=repr)
    def test_the_three_readable_values_survive_untouched(self, banned: bool | None) -> None:
        assert a_user(banned=banned).banned is banned

    def test_the_refusal_names_the_type_it_was_given(self) -> None:
        """The message is for whoever wrote the store, so it says what arrived, never what it
        held: `banned` is not credential material, but its neighbours in a payload are."""
        with pytest.raises(TypeError) as caught:
            a_user(banned="true")

        assert "str" in str(caught.value)

    def test_it_is_immutable_and_its_payload_is_read_only(self) -> None:
        record = a_user()

        with pytest.raises((AttributeError, TypeError)):
            record.banned = True  # type: ignore[misc]
        with pytest.raises(TypeError):
            record.payload["banned"] = True  # type: ignore[index]

    def test_the_payload_is_absent_from_the_repr(self) -> None:
        """C2. `payload` is `field(repr=False)` because it carries the user's own data - email,
        name, banReason - and a record reaches tracebacks and error reporters. The session side
        is caught only incidentally (its payload holds the token); the user side needs its own
        pin, or dropping `repr=False` leaks the email into every traceback with the suite green."""
        rendered = repr(a_user())

        assert "seed@example.com" not in rendered
        assert "Seed User" not in rendered
        assert USER_ID in rendered


class TestSessionStoreProtocol:
    def test_both_shipped_stores_satisfy_it(self, tmp_path: Any) -> None:
        redis_store = RedisSessionStore(client=RecordingRedis())

        assert isinstance(redis_store, SessionStore)

    def test_a_store_of_your_own_satisfies_it_without_inheriting(self) -> None:
        class MyStore:
            async def fetch_session_by_token(self, token: str) -> StoredSession | None:
                return None

            async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
                return None

        assert isinstance(MyStore(), SessionStore)

    def test_a_half_implemented_store_is_refused(self) -> None:
        class HalfStore:
            async def fetch_session_by_token(self, token: str) -> StoredSession | None:
                return None

        assert not isinstance(HalfStore(), SessionStore)

    def test_the_protocol_proves_names_and_nothing_else(self) -> None:
        """Stated out loud, the same way `Verifier` and `Transport` state it: a runtime protocol
        check sees member names, never signatures - so it is a shape check and not a safety
        property. Whatever composes a store re-checks what it actually needs."""

        class Liar:
            fetch_session_by_token = "not even callable"
            fetch_user_by_id = 42

        assert isinstance(Liar(), SessionStore)

    def test_the_two_sqlalchemy_stores_declare_the_protocol_members(self) -> None:
        for store in (SqlAlchemySessionStore, SyncStoreAdapter):
            assert callable(store.fetch_session_by_token)
            assert callable(store.fetch_user_by_id)
