"""Shape of the error taxonomy: hierarchy, wire constants, and where `reason` lives.

The no-leak invariant these constants exist to serve is proven end-to-end in
`tests/test_error_response_oracle.py`; this file pins the classes themselves.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuthError,
    ConfigurationError,
    CsrfFailure,
    InvalidCredential,
    SessionError,
    SessionExpired,
    SessionRevoked,
)

UNAUTHENTICATED: tuple[type[SessionError], ...] = (
    SessionError,
    InvalidCredential,
    SessionExpired,
    SessionRevoked,
    AuthServiceUnavailable,
)


def test_configuration_errors_are_not_http_errors() -> None:
    """Config errors abort startup; they must never be answerable as a response."""
    assert issubclass(ConfigurationError, BetterAuthError)
    assert issubclass(BetterAuthError, Exception)
    assert not issubclass(BetterAuthError, HTTPException)
    assert not issubclass(ConfigurationError, HTTPException)


def test_request_time_errors_are_http_errors() -> None:
    assert issubclass(SessionError, HTTPException)
    assert not issubclass(SessionError, BetterAuthError)


@pytest.mark.parametrize("error_cls", [*UNAUTHENTICATED, CsrfFailure])
def test_every_request_time_error_is_a_session_error(error_cls: type[SessionError]) -> None:
    error = error_cls(reason="internal detail")

    assert isinstance(error, SessionError)
    assert isinstance(error, HTTPException)


@pytest.mark.parametrize("error_cls", [*UNAUTHENTICATED, CsrfFailure])
def test_reason_is_keyword_only_and_required(error_cls: type[SessionError]) -> None:
    with pytest.raises(TypeError):
        error_cls("positional reason")  # type: ignore[call-arg]

    with pytest.raises(TypeError):
        error_cls()  # type: ignore[call-arg]


@pytest.mark.parametrize("error_cls", [*UNAUTHENTICATED, CsrfFailure])
def test_reason_is_carried_on_the_exception(error_cls: type[SessionError]) -> None:
    error = error_cls(reason="kid nOtInJwKs cache miss")

    assert error.reason == "kid nOtInJwKs cache miss"


@pytest.mark.parametrize("error_cls", UNAUTHENTICATED)
def test_the_401_family_is_uniform(error_cls: type[SessionError]) -> None:
    error = error_cls(reason="whatever happened")

    assert error.status_code == 401
    assert error.detail == "Not authenticated"
    assert error.headers == {"WWW-Authenticate": "Bearer"}


def test_an_unverifiable_session_fails_closed() -> None:
    """Infra state is not the client's business — 503 would be an availability oracle."""
    assert AuthServiceUnavailable(reason="upstream timeout").status_code == 401


def test_csrf_failure_is_a_403_without_a_challenge() -> None:
    error = CsrfFailure(reason="origin not in the allowlist")

    assert error.status_code == 403
    assert error.detail == "Forbidden"
    assert error.headers is None


@pytest.mark.parametrize("error_cls", UNAUTHENTICATED)
def test_headers_are_per_instance_not_a_shared_class_constant(
    error_cls: type[SessionError],
) -> None:
    first = error_cls(reason="one")
    second = error_cls(reason="two")
    first_headers = first.headers
    assert isinstance(first_headers, dict)
    first_headers["WWW-Authenticate"] = "poisoned"

    assert second.headers == {"WWW-Authenticate": "Bearer"}
