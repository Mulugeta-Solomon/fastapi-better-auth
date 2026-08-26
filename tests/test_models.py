"""`User` / `Session` pinned against the real better-auth 1.7.1 wire shapes.

The JWT payload is decoded out of the committed vector rather than read from its
`claims` key, so a stale or hand-edited fixture cannot pass this suite.
"""

from __future__ import annotations

import base64
import json
import pathlib
from datetime import datetime, timezone
from typing import Any

import pytest
from pydantic import ValidationError
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


class AdminUser(User):
    """A user subclass in the shape operators actually write (admin plugin fields)."""

    role: str | None = None
    ban_reason: str | None = None


def decoded_jwt_payload() -> dict[str, Any]:
    segment: str = JWT_DOC["token"].split(".")[1]
    padded = segment + "=" * (-len(segment) % 4)
    payload: dict[str, Any] = json.loads(base64.urlsafe_b64decode(padded))
    return payload


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
    assert user.created_at == datetime(2026, 8, 20, 15, 34, 2, 764000, tzinfo=timezone.utc)
    assert user.updated_at == datetime(2026, 8, 20, 15, 34, 2, 764000, tzinfo=timezone.utc)


def test_registered_jwt_claims_are_ignored_not_promoted() -> None:
    user = User.model_validate(decoded_jwt_payload())

    for claim in ("sub", "iss", "aud", "exp", "iat"):
        assert claim in decoded_jwt_payload()
        assert not hasattr(user, claim)


def test_get_session_user_object_parses() -> None:
    user = User.model_validate(GET_SESSION_USER)

    assert user.id == GET_SESSION_USER["id"]
    assert user.email_verified is False
    assert user.created_at == datetime(2026, 8, 20, 15, 34, 2, 764000, tzinfo=timezone.utc)


def test_field_names_are_accepted_alongside_aliases() -> None:
    user = User(id="u1", email_verified=True)

    assert user.email_verified is True


@pytest.mark.parametrize("field", ["email", "name", "email_verified", "image"])
def test_only_id_is_required(field: str) -> None:
    """Upstream ships ~6 releases/month and `definePayload` can strip fields (D-027)."""
    user = User.model_validate({"id": "u1"})

    assert getattr(user, field) is None


@pytest.mark.parametrize("payload", [{}, {"id": ""}, {"id": None}])
def test_a_user_without_a_usable_id_is_rejected(payload: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        User.model_validate(payload)


def test_a_subclass_keeps_the_camelcase_alias_generator() -> None:
    user = AdminUser.model_validate({**GET_SESSION_USER, "role": "admin", "banReason": "spam"})

    assert user.role == "admin"
    assert user.ban_reason == "spam"
    assert user.email == "seed@example.com"


def test_session_carries_the_subclass_through() -> None:
    user = AdminUser.model_validate({**GET_SESSION_USER, "role": "admin"})
    session = Session[AdminUser](user=user, raw=dict(GET_SESSION_USER))

    assert_type(session.user, AdminUser)
    assert session.user.role == "admin"
    assert session.expires_at is None
    assert session.token is None


def test_session_defaults_and_required_fields() -> None:
    user = User.model_validate(GET_SESSION_USER)
    expires = datetime(2026, 9, 1, tzinfo=timezone.utc)
    session = Session[User](user=user, expires_at=expires, token="raw-session-token", raw={})

    assert session.expires_at == expires
    assert session.token == "raw-session-token"

    with pytest.raises(ValidationError):
        Session[User](user=user)  # type: ignore[call-arg]


def test_models_are_frozen() -> None:
    user = User.model_validate(GET_SESSION_USER)
    session = Session[User](user=user, raw={})

    with pytest.raises(ValidationError):
        user.id = "hijacked"

    with pytest.raises(ValidationError):
        session.token = "hijacked"


def test_session_rejects_unknown_fields() -> None:
    """`Session` is constructed by verifiers, never parsed — an unknown kwarg is a bug."""
    user = User.model_validate(GET_SESSION_USER)

    with pytest.raises(ValidationError):
        Session[User](user=user, raw={}, ip_address="203.0.113.7")  # type: ignore[call-arg]


def test_raw_is_a_shallow_copy_of_what_was_handed_in() -> None:
    """D-028: the mapping is rebuilt, its nested containers are shared."""
    user = User.model_validate(GET_SESSION_USER)
    payload: dict[str, Any] = {"session": {"ipAddress": "203.0.113.7"}, "user": GET_SESSION_USER}
    session = Session[User](user=user, raw=payload)

    assert session.raw == payload
    assert session.raw is not payload
    assert session.raw["session"] is payload["session"]


def test_raw_preserves_fields_the_models_do_not_promote() -> None:
    user = User.model_validate(GET_SESSION_USER)
    payload: dict[str, Any] = {
        "id": "sess_1",
        "token": "t",
        "userId": "u1",
        "expiresAt": "2026-09-01T00:00:00.000Z",
        "createdAt": "2026-08-20T15:34:02.764Z",
        "updatedAt": "2026-08-20T15:34:02.764Z",
        "ipAddress": "203.0.113.7",
        "userAgent": "curl/8.7.1",
    }
    session = Session[User](user=user, raw=payload)

    assert session.raw["ipAddress"] == "203.0.113.7"
    assert session.raw["userAgent"] == "curl/8.7.1"
