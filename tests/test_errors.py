"""Shape of the error taxonomy: hierarchy, wire constants, and where `reason` lives.

The subclass list is enumerated from `SessionError.__subclasses__()` rather than written
out, because a hand-maintained tuple tests the tuple, not the set — a rogue subclass
added later would never be sampled by it.
"""

from __future__ import annotations

import copy
import gc
import pickle
from collections.abc import Mapping
from typing import ClassVar

import pytest
from fastapi import HTTPException

from fastapi_better_auth import (
    BEARER_CHALLENGE,
    AmbiguousCredentials,
    AuthServiceUnavailable,
    BetterAuthError,
    ConfigurationError,
    CsrfFailure,
    InvalidCredential,
    MissingCredential,
    SessionError,
    SessionExpired,
    SessionRevoked,
)

REASON = "signature mismatch kid=iRAEH8dY tok_fp=9f3ab21c"
SHIPPED_NAMES = frozenset(
    {
        "InvalidCredential",
        "SessionExpired",
        "SessionRevoked",
        "AuthServiceUnavailable",
        "MissingCredential",
        "CsrfFailure",
        "AmbiguousCredentials",
    }
)
SANCTIONED_WIRE_SHAPES: dict[int, tuple[str, dict[str, str] | None]] = {
    400: ("Ambiguous request", None),
    401: ("Not authenticated", {"WWW-Authenticate": "Bearer"}),
    403: ("Forbidden", None),
}


def shipped_session_errors() -> tuple[type[SessionError], ...]:
    """Every `SessionError` subclass this package ships, found transitively."""
    seen: list[type[SessionError]] = []
    stack: list[type[SessionError]] = [SessionError]
    while stack:
        for subclass in stack.pop().__subclasses__():
            if subclass not in seen:
                seen.append(subclass)
                stack.append(subclass)
    return tuple(cls for cls in seen if cls.__module__ == SessionError.__module__)


def every_request_time_error() -> tuple[type[SessionError], ...]:
    return (SessionError, *shipped_session_errors())


@pytest.fixture(autouse=True)
def collect_dead_subclasses() -> None:
    """Rogue subclasses briefly enter `__subclasses__()` before their creation raises."""
    gc.collect()


def test_the_enumeration_is_not_empty_and_finds_every_shipped_subclass() -> None:
    """Prove the instrument: an enumeration that finds nothing would pass everything."""
    assert {cls.__name__ for cls in shipped_session_errors()} == SHIPPED_NAMES


def test_configuration_errors_are_not_http_errors() -> None:
    """Config errors abort startup; they must never be answerable as a response."""
    assert issubclass(ConfigurationError, BetterAuthError)
    assert issubclass(BetterAuthError, Exception)
    assert not issubclass(BetterAuthError, HTTPException)
    assert not issubclass(ConfigurationError, HTTPException)


def test_request_time_errors_are_http_errors() -> None:
    assert issubclass(SessionError, HTTPException)
    assert not issubclass(SessionError, BetterAuthError)


@pytest.mark.parametrize("error_cls", every_request_time_error(), ids=lambda c: c.__name__)
def test_every_request_time_error_is_a_session_error(error_cls: type[SessionError]) -> None:
    error = error_cls(reason=REASON)

    assert isinstance(error, SessionError)
    assert isinstance(error, HTTPException)


@pytest.mark.parametrize("error_cls", every_request_time_error(), ids=lambda c: c.__name__)
def test_reason_is_keyword_only_and_required(error_cls: type[SessionError]) -> None:
    with pytest.raises(TypeError):
        error_cls("positional reason")  # pyright: ignore[reportCallIssue]

    with pytest.raises(TypeError):
        error_cls()  # pyright: ignore[reportCallIssue]


@pytest.mark.parametrize("error_cls", every_request_time_error(), ids=lambda c: c.__name__)
def test_reason_is_carried_on_the_exception(error_cls: type[SessionError]) -> None:
    assert error_cls(reason=REASON).reason == REASON


@pytest.mark.parametrize("error_cls", every_request_time_error(), ids=lambda c: c.__name__)
def test_every_error_renders_a_sanctioned_wire_shape(error_cls: type[SessionError]) -> None:
    error = error_cls(reason=REASON)

    assert error.status_code in SANCTIONED_WIRE_SHAPES
    detail, headers = SANCTIONED_WIRE_SHAPES[error.status_code]
    assert error.detail == detail
    assert error.headers == headers


def test_csrf_failure_is_the_only_403() -> None:
    by_status = {cls.__name__ for cls in shipped_session_errors() if cls.response_status == 403}

    assert by_status == {"CsrfFailure"}


def test_ambiguous_credentials_is_the_only_400() -> None:
    """A 400 says the *request shape* is wrong; nothing else in the family may claim that."""
    by_status = {cls.__name__ for cls in shipped_session_errors() if cls.response_status == 400}

    assert by_status == {"AmbiguousCredentials"}


def test_the_401_family_is_exactly_the_credential_outcomes() -> None:
    by_status = {cls.__name__ for cls in shipped_session_errors() if cls.response_status == 401}

    assert by_status == SHIPPED_NAMES - {"CsrfFailure", "AmbiguousCredentials"}


def test_a_missing_credential_is_indistinguishable_from_a_forged_one() -> None:
    """Anonymous traffic and an attack differ for operators, never for the client."""
    missing = MissingCredential(reason="no credential presented")
    forged = InvalidCredential(reason=REASON)

    assert (missing.status_code, missing.detail, missing.headers) == (
        forged.status_code,
        forged.detail,
        forged.headers,
    )


def test_ambiguous_credentials_offers_no_authentication_challenge() -> None:
    """Re-authenticating would not help: the client sent two credentials on purpose."""
    assert AmbiguousCredentials(reason="2 credentials presented").headers is None


def test_an_unverifiable_session_fails_closed() -> None:
    """Infra state is not the client's business - 503 would be an availability oracle."""
    assert AuthServiceUnavailable(reason="jwks fetch failed").status_code == 401


def test_csrf_failure_carries_no_authentication_challenge() -> None:
    assert CsrfFailure(reason="origin rejected").headers is None


@pytest.mark.parametrize(
    "error_cls",
    [cls for cls in shipped_session_errors() if cls.response_status == 401],
    ids=lambda c: c.__name__,
)
def test_headers_are_per_instance_not_a_shared_class_constant(
    error_cls: type[SessionError],
) -> None:
    first = error_cls(reason="one")
    second = error_cls(reason="two")
    first_headers = first.headers
    assert isinstance(first_headers, dict)
    first_headers["WWW-Authenticate"] = "poisoned"

    assert second.headers == {"WWW-Authenticate": "Bearer"}
    assert BEARER_CHALLENGE == {"WWW-Authenticate": "Bearer"}


def test_the_exported_challenge_constant_is_read_only() -> None:
    with pytest.raises(TypeError):
        BEARER_CHALLENGE["WWW-Authenticate"] = "poisoned"  # pyright: ignore[reportIndexIssue]


# --- observability surface (B3) ---------------------------------------------------


@pytest.mark.parametrize("error_cls", every_request_time_error(), ids=lambda c: c.__name__)
def test_repr_carries_the_reason_and_str_does_not(error_cls: type[SessionError]) -> None:
    error = error_cls(reason=REASON)

    assert repr(error) == f"{error_cls.__name__}(reason={REASON!r})"
    assert REASON not in str(error)
    assert str(error) == f"{error.status_code}: {error.detail}"


# --- pickling (B5) ----------------------------------------------------------------


@pytest.mark.parametrize("error_cls", every_request_time_error(), ids=lambda c: c.__name__)
def test_a_session_error_survives_pickle_and_copy(error_cls: type[SessionError]) -> None:
    """`copy`/`pickle` raise TypeError on a kw-only exception unless `__reduce__` says how."""
    error = error_cls(reason=REASON)

    revived = pickle.loads(pickle.dumps(error))
    assert type(revived) is error_cls
    assert revived.reason == REASON
    assert revived.status_code == error.status_code
    assert revived.detail == error.detail
    assert revived.headers == error.headers

    assert copy.copy(error).reason == REASON
    assert copy.deepcopy(error).reason == REASON


# --- the sanctioned-surface guard (D7) --------------------------------------------


@pytest.mark.parametrize(
    ("attribute", "value"),
    [("status_code", 402), ("detail", "sub_123 not found"), ("headers", {"X-Debug": "leak"})],
)
def test_a_subclass_may_not_shadow_the_starlette_attributes(attribute: str, value: object) -> None:
    """Instance attrs silently win over class attrs: a shadowing subclass ships 401."""
    with pytest.raises(TypeError):
        type("Shadowing", (SessionError,), {attribute: value})


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("response_status", 428),
        ("response_status", 500),
        ("response_status", 400),
        ("response_detail", "user sub_123 is banned"),
        ("response_headers", {"X-Auth-Debug": "kid=abc"}),
        ("response_headers", None),
    ],
    ids=[
        "status-428",
        "status-500",
        "status-400-without-its-body",
        "chatty-detail",
        "debug-header",
        "missing-challenge",
    ],
)
def test_a_subclass_may_not_leave_the_sanctioned_surface(attribute: str, value: object) -> None:
    with pytest.raises(TypeError):
        type("Rogue", (SessionError,), {attribute: value})


def test_a_compliant_subclass_is_still_allowed() -> None:
    """The guard must not make the documented extension mechanism unusable."""

    class TenantSuspended(SessionError):
        """A sanctioned 403 written by an operator."""

        response_status: ClassVar[int] = 403
        response_detail: ClassVar[str] = "Forbidden"
        response_headers: ClassVar[Mapping[str, str] | None] = None

    error = TenantSuspended(reason="tenant tnt_9f3a suspended")

    assert error.status_code == 403
    assert error.detail == "Forbidden"
    assert error.headers is None
    assert error.reason == "tenant tnt_9f3a suspended"


def test_error_classes_stay_importable_from_the_root() -> None:
    assert {InvalidCredential, SessionExpired, SessionRevoked, AuthServiceUnavailable} <= set(
        shipped_session_errors()
    )
