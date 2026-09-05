"""The Q3 outcome table as a pure function of one response, plus the `X-Retry-After` parse.

`session_document_from` reads a `TransportResponse` and either returns the parsed record or raises
the mapped `SessionError` - the whole outcome table except the fetch failures (raised at the fetch
site so no credential rides out) and the token/expiry/ban checks (made against the forwarded
credential in the verifier). This suite drives the function directly, one row per outcome.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pytest

from fastapi_better_auth import (
    AuthServiceUnavailable,
    InvalidCredential,
    SessionRevoked,
    TransportResponse,
)
from fastapi_better_auth._internal.remote_response import (
    DEFAULT_BACKOFF,
    MAX_BACKOFF,
    MIN_BACKOFF,
    retry_after_seconds,
    session_document_from,
)

URI = "https://auth.example.com/api/auth/get-session?disableCookieCache=true&disableRefresh=true"
TOKEN = "SBYZ1bzGdkhXcLuqsW70JjhvmIY4PU3B"
MARKER = "tok_fp=abcd1234"


def body(
    *,
    token: str = TOKEN,
    user_id: str = "u1",
    expires: str = "2999-01-01T00:00:00.000Z",
    **user_over: Any,
) -> bytes:
    session = {
        "id": "sess",
        "token": token,
        "userId": user_id,
        "expiresAt": expires,
        "impersonatedBy": None,
    }
    user: dict[str, Any] = {
        "id": user_id,
        "email": "seed@example.com",
        "banned": False,
        "banExpires": None,
    }
    user.update(user_over)
    return json.dumps({"session": session, "user": user}).encode("utf-8")


def response(
    content: bytes,
    *,
    status: int = 200,
    content_type: str | None = "application/json",
    **headers: str,
) -> TransportResponse:
    all_headers: dict[str, str] = dict(headers)
    if content_type is not None:
        all_headers["content-type"] = content_type
    return TransportResponse(status_code=status, headers=all_headers, content=content)


def outcome(resp: TransportResponse, *, verified: bool = False) -> Any:
    return session_document_from(resp, uri=URI, marker=MARKER, signature_verified=verified)


# ---------------------------------------------------------------- the happy path


def test_a_valid_document_returns_a_record_naming_the_token() -> None:
    record = outcome(response(body()))

    assert record.token == TOKEN
    assert record.user is not None
    assert record.user.id == "u1"


# ---------------------------------------------------------------- 200 + null


def test_null_without_a_verified_signature_is_invalid_credential() -> None:
    with pytest.raises(InvalidCredential) as caught:
        outcome(response(b"null"), verified=False)

    assert "no session" in caught.value.reason
    assert MARKER in caught.value.reason


def test_null_with_a_verified_signature_is_session_revoked() -> None:
    """Ruling 4: a keyring positively verified the cookie, so the session existed and is gone."""
    with pytest.raises(SessionRevoked) as caught:
        outcome(response(b"null"), verified=True)

    assert MARKER in caught.value.reason


# ---------------------------------------------------------------- unusable 200s


def test_a_json_object_missing_the_shape_is_service_unavailable() -> None:
    with pytest.raises(AuthServiceUnavailable) as caught:
        outcome(response(json.dumps({"session": {}}).encode()))

    assert "cannot read" in caught.value.reason


def test_a_non_object_json_body_is_service_unavailable() -> None:
    with pytest.raises(AuthServiceUnavailable) as caught:
        outcome(response(b"[1, 2, 3]"))

    assert "not a JSON object" in caught.value.reason


def test_a_body_that_is_not_json_is_service_unavailable() -> None:
    with pytest.raises(AuthServiceUnavailable) as caught:
        outcome(response(b"<html>nope</html>"))

    assert "not JSON" in caught.value.reason


def test_a_non_json_content_type_is_service_unavailable() -> None:
    with pytest.raises(AuthServiceUnavailable) as caught:
        outcome(response(body(), content_type="text/html"))

    assert "not JSON" in caught.value.reason


def test_a_missing_content_type_is_service_unavailable() -> None:
    with pytest.raises(AuthServiceUnavailable) as caught:
        outcome(response(body(), content_type=None))

    assert "not JSON" in caught.value.reason


# ---------------------------------------------------------------- non-200


@pytest.mark.parametrize("status", [401, 403, 500, 502])
def test_a_plain_non_200_names_the_status_and_uri(status: int) -> None:
    with pytest.raises(AuthServiceUnavailable) as caught:
        outcome(response(b"", status=status))

    assert str(status) in caught.value.reason
    assert URI in caught.value.reason


@pytest.mark.parametrize("status", [404, 405, 415])
def test_a_routing_status_points_at_base_path(status: int) -> None:
    with pytest.raises(AuthServiceUnavailable) as caught:
        outcome(response(b"", status=status))

    assert "base_path" in caught.value.reason


@pytest.mark.parametrize("status", [301, 302, 307])
def test_a_redirect_is_never_followed(status: int) -> None:
    with pytest.raises(AuthServiceUnavailable) as caught:
        outcome(response(b"", status=status))

    assert "redirect" in caught.value.reason


def test_a_429_names_the_backoff_it_would_take() -> None:
    with pytest.raises(AuthServiceUnavailable) as caught:
        outcome(response(b"", status=429, **{"x-retry-after": "12"}))

    assert "429" in caught.value.reason
    assert "12s" in caught.value.reason


# ---------------------------------------------------------------- retry_after_seconds


def headers(**pairs: str) -> Mapping[str, str]:
    return dict(pairs)


def test_retry_after_prefers_the_standard_header() -> None:
    assert retry_after_seconds(headers(**{"retry-after": "7", "x-retry-after": "40"})) == 7


def test_retry_after_falls_back_to_the_upstream_header() -> None:
    """Upstream sends only X-Retry-After; the standard name is read first for a normalising proxy."""
    assert retry_after_seconds(headers(**{"x-retry-after": "9"})) == 9


def test_retry_after_defaults_when_absent() -> None:
    assert retry_after_seconds(headers()) == DEFAULT_BACKOFF


def test_retry_after_defaults_when_unparseable() -> None:
    assert retry_after_seconds(headers(**{"x-retry-after": "soon"})) == DEFAULT_BACKOFF


def test_retry_after_is_clamped_high_and_low() -> None:
    assert retry_after_seconds(headers(**{"x-retry-after": "9999"})) == MAX_BACKOFF
    assert retry_after_seconds(headers(**{"x-retry-after": "0"})) == MIN_BACKOFF
