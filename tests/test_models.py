"""`User` / `Session` pinned against the real better-auth 1.7.1 wire shapes.

The JWT payload is decoded out of the committed vector rather than read from its
`claims` key, so a stale or hand-edited fixture cannot pass this suite.
"""

from __future__ import annotations

import base64
import json
import pathlib
from datetime import datetime, timezone
from typing import Any, cast

import pytest
from pydantic import SecretStr, ValidationError
from typing_extensions import assert_type

from fastapi_better_auth import Session, User

VECTOR_DIR = pathlib.Path(__file__).parent / "vectors"
JWT_DOC: dict[str, Any] = json.loads((VECTOR_DIR / "jwt_v1.json").read_text())

# Verified live against better-auth 1.7.1 (2026-08-26): the `user` object of
# GET /api/auth/get-session. Keys are camelCase; `image` is nullable.
GET_SESSION_USER: dict[str, Any] = {
    "id": "cIrUeXmXVG5Kg0Pzt4rCozIxLv3oeOMG",
    "name": "Seed User",
    "email": "seed@example.com",
    "emailVerified": False,
    "image": None,
    "createdAt": "2026-08-20T15:34:02.764Z",
    "updatedAt": "2026-08-20T15:34:02.764Z",
}
CAPTURED_AT = datetime(2026, 8, 20, 15, 34, 2, 764000, tzinfo=timezone.utc)


class AdminUser(User):
    """A user subclass carrying server-controlled admin-plugin fields."""

    role: str | None = None
    ban_expires: datetime | None = None


def decoded_jwt_payload() -> dict[str, Any]:
    segment: str = JWT_DOC["token"].split(".")[1]
    padded = segment + "=" * (-len(segment) % 4)
    payload: dict[str, Any] = json.loads(base64.urlsafe_b64decode(padded))
    return payload


def base_user() -> User:
    return User.model_validate(GET_SESSION_USER)


def accepts_a_base_session(session: Session[User]) -> str:
    """D4 static probe: this only typechecks if `Session` is covariant in its user."""
    return session.user.id


def test_the_jwt_fixture_is_live() -> None:
    """Prove the instrument: the decoded token must agree with the recorded claims."""
    assert decoded_jwt_payload() == JWT_DOC["claims"]


def test_jwt_payload_parses_into_a_user() -> None:
    user = User.model_validate(decoded_jwt_payload())

    assert user.id == "cIrUeXmXVG5Kg0Pzt4rCozIxLv3oeOMG"
    assert user.email == "seed@example.com"
    assert user.name == "Seed User"
    assert user.email_verified is False
    assert user.image is None
    assert user.created_at == CAPTURED_AT
    assert user.updated_at == CAPTURED_AT


def test_registered_jwt_claims_are_ignored_not_promoted() -> None:
    user = User.model_validate(decoded_jwt_payload())

    for claim in ("sub", "iss", "aud", "exp", "iat"):
        assert claim in decoded_jwt_payload()
        assert not hasattr(user, claim)


def test_get_session_user_object_parses() -> None:
    user = base_user()

    assert user.id == GET_SESSION_USER["id"]
    assert user.email_verified is False
    assert user.created_at == CAPTURED_AT


def test_field_names_are_accepted_alongside_aliases() -> None:
    user = User(id="u1", email_verified=True)

    assert user.email_verified is True


@pytest.mark.parametrize("field", ["email", "name", "email_verified", "image"])
def test_only_id_is_required(field: str) -> None:
    """Upstream ships ~6 releases/month and `definePayload` can strip fields (D-027)."""
    user = User.model_validate({"id": "u1"})

    assert getattr(user, field) is None


def test_aliases_are_validation_only() -> None:
    """A7: camelCase comes in, snake_case goes out - even when asked for aliases."""
    dumped = User.model_validate(GET_SESSION_USER).model_dump(by_alias=True)

    assert "email_verified" in dumped
    assert "emailVerified" not in dumped
    assert [key for key in dumped if any(char.isupper() for char in key)] == []


def test_a_subclass_keeps_the_camelcase_alias_generator() -> None:
    user = AdminUser.model_validate(
        {**GET_SESSION_USER, "role": "admin", "banExpires": "2026-09-01T00:00:00Z"}
    )

    assert user.role == "admin"
    assert user.ban_expires == datetime(2026, 9, 1, tzinfo=timezone.utc)
    assert user.email == "seed@example.com"


# --- id hardening (D5) ------------------------------------------------------------


@pytest.mark.parametrize("payload", [{}, {"id": ""}, {"id": None}])
def test_a_user_without_a_usable_id_is_rejected(payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        User.model_validate(payload)


def test_an_integer_id_is_coerced_to_string() -> None:
    """Better Auth's `advanced.database.useNumberId` makes integer ids legitimate."""
    user = User.model_validate({"id": 42})

    assert user.id == "42"


def test_a_boolean_id_is_rejected() -> None:
    """`bool` is an `int` subclass; coercing `True` to \"True\" would authorize a ghost."""
    with pytest.raises(ValidationError):
        User.model_validate({"id": True})


@pytest.mark.parametrize(
    "bad_id",
    ["   ", "\t\n", "\x00", "a\nb", "a\x7fb", "a\x1fb", "x" * 256],
    ids=["spaces", "tabs-newline", "nul", "newline", "delete", "unit-sep", "too-long"],
)
def test_an_unusable_id_is_rejected(bad_id: str) -> None:
    with pytest.raises(ValidationError):
        User.model_validate({"id": bad_id})


def test_the_id_length_ceiling_is_inclusive() -> None:
    assert User.model_validate({"id": "x" * 255}).id == "x" * 255


@pytest.mark.parametrize(("field", "limit"), [("email", 320), ("name", 1000), ("image", 4096)])
def test_the_other_string_fields_are_bounded(field: str, limit: int) -> None:
    assert getattr(User.model_validate({"id": "u1", field: "x" * limit}), field) == "x" * limit

    with pytest.raises(ValidationError):
        User.model_validate({"id": "u1", field: "x" * (limit + 1)})


# --- datetimes (D3) ---------------------------------------------------------------


def test_a_naive_user_timestamp_is_read_as_utc() -> None:
    """Upstream-supplied and display-grade: assume UTC rather than reject (A4)."""
    user = User.model_validate({"id": "u1", "createdAt": "2026-08-20T15:34:02.764"})

    assert user.created_at == CAPTURED_AT
    assert user.created_at is not None and user.created_at.tzinfo is not None


def test_a_naive_session_expiry_is_rejected() -> None:
    """We are the expiry enforcer: a naive value reads the wrong clock fail-open (A3)."""
    with pytest.raises(ValidationError):
        naive = datetime(2026, 9, 1)  # noqa: DTZ001 - the naive value is the subject
        Session[User](user=base_user(), expires_at=naive, raw={})


def test_an_epoch_session_expiry_is_aware() -> None:
    session = Session[User](user=base_user(), expires_at=cast("Any", 1787241849), raw={})

    assert session.expires_at is not None
    assert session.expires_at.tzinfo is not None


# --- Session shape ----------------------------------------------------------------


def test_session_carries_the_subclass_through() -> None:
    user = AdminUser.model_validate({**GET_SESSION_USER, "role": "admin"})
    session = Session[AdminUser](user=user, expires_at=None, raw=dict(GET_SESSION_USER))

    assert_type(session.user, AdminUser)
    assert session.user.role == "admin"
    assert session.expires_at is None
    assert session.token is None


def test_a_subclass_session_satisfies_a_base_session_parameter() -> None:
    """D4: without covariance every shared helper would need a cast."""
    session = Session[AdminUser](
        user=AdminUser.model_validate(GET_SESSION_USER), expires_at=None, raw={}
    )

    assert accepts_a_base_session(session) == GET_SESSION_USER["id"]


def test_session_carries_the_expiry_and_token_it_was_given() -> None:
    expires = datetime(2026, 9, 1, tzinfo=timezone.utc)
    session = Session[User](
        user=base_user(), expires_at=expires, token=SecretStr("raw-session-token"), raw={}
    )

    assert session.expires_at == expires
    assert session.token is not None
    assert session.token.get_secret_value() == "raw-session-token"


def test_omitting_the_expiry_is_a_construction_error() -> None:
    """A defaulted None would make "verifier forgot to map expiry" look like "immortal"."""
    with pytest.raises(ValidationError):
        Session[User](user=base_user(), raw={})  # pyright: ignore[reportCallIssue]


def test_an_explicit_none_expiry_is_accepted_as_a_deliberate_statement() -> None:
    session = Session[User](user=base_user(), expires_at=None, raw={})

    assert session.expires_at is None


def test_the_raw_payload_is_also_required() -> None:
    with pytest.raises(ValidationError):
        Session[User](user=base_user(), expires_at=None)  # pyright: ignore[reportCallIssue]


def test_models_are_frozen() -> None:
    user = base_user()
    session = Session[User](user=user, expires_at=None, raw={})

    with pytest.raises(ValidationError):
        user.id = "hijacked"

    with pytest.raises(ValidationError):
        session.token = SecretStr("hijacked")


def test_session_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Session[User](
            user=base_user(),
            expires_at=None,
            raw={},
            ip_address="203.0.113.7",  # pyright: ignore[reportCallIssue]
        )


# --- raw (D6) ---------------------------------------------------------------------


def test_raw_is_a_read_only_copy_of_what_was_handed_in() -> None:
    payload: dict[str, Any] = {"session": {"ipAddress": "203.0.113.7"}, "user": GET_SESSION_USER}
    session = Session[User](user=base_user(), expires_at=None, raw=payload)

    assert session.raw == payload
    assert session.raw is not payload

    with pytest.raises(TypeError):
        cast("dict[str, Any]", session.raw)["injected"] = "x"


def test_raw_nested_containers_stay_shared_with_the_caller() -> None:
    """D-028: the copy is one level deep. Never hand one payload to two constructions."""
    payload: dict[str, Any] = {"session": {"ipAddress": "203.0.113.7"}}
    session = Session[User](user=base_user(), expires_at=None, raw=payload)

    assert session.raw["session"] is payload["session"]


def test_raw_preserves_fields_the_models_do_not_promote() -> None:
    payload: dict[str, Any] = {
        "id": "sess_1",
        "userId": "u1",
        "ipAddress": "203.0.113.7",
        "userAgent": "curl/8.7.1",
    }
    session = Session[User](user=base_user(), expires_at=None, raw=payload)

    assert session.raw["ipAddress"] == "203.0.113.7"
    assert session.raw["userAgent"] == "curl/8.7.1"


def test_raw_repr_masks_the_session_token_but_keeps_it_reachable() -> None:
    """D-194: cookie mode puts the raw token under `raw['token']` in cleartext, defeating the
    SecretStr masking on `Session.token` the moment `repr(session.raw)` is rendered (into a log or
    a debug 500). The repr masks that one value; the value stays reachable by key."""
    the_token = "SBYZ1bzGdkhXcLuqsW70JjhvmIY4PU3B"
    payload: dict[str, Any] = {"token": the_token, "userId": "u1", "ipAddress": "203.0.113.7"}
    session = Session[User](user=base_user(), expires_at=None, raw=payload)

    rendered = repr(session.raw)
    assert the_token not in rendered
    assert "<redacted>" in rendered
    assert "203.0.113.7" in rendered, "only the token is masked, not the rest of the payload"

    assert session.raw["token"] == the_token, "the value stays reachable by key"
    assert len(session.raw) == 3
    assert set(session.raw) == {"token", "userId", "ipAddress"}


def test_raw_repr_is_clean_when_there_is_no_token() -> None:
    """A JWT-mode payload carries no `token` field, so nothing is masked and the repr is faithful."""
    payload: dict[str, Any] = {"sub": "u1", "iss": "https://auth.example.com"}
    session = Session[User](user=base_user(), expires_at=None, raw=payload)

    rendered = repr(session.raw)
    assert "<redacted>" not in rendered
    assert "u1" in rendered


# --- equality and hashing (D8) ----------------------------------------------------


def test_users_compare_and_hash_by_value() -> None:
    """A public guarantee: `User` is usable as a dict key and in sets."""
    first = User.model_validate(GET_SESSION_USER)
    second = User.model_validate(GET_SESSION_USER)

    assert first == second
    assert hash(first) == hash(second)
    # frozen=True adds __hash__ at runtime; pyright only sees BaseModel.__eq__.
    assert len({first, second}) == 1  # pyright: ignore[reportUnhashable]


def test_a_session_is_formally_hashable_but_raises_when_hashed() -> None:
    session = Session[User](user=base_user(), expires_at=None, raw={})

    assert type(session).__hash__ is not None

    with pytest.raises(TypeError):
        hash(session)
