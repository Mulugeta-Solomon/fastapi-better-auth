"""ORACLE - the executable statement of the no-leak invariant (D-005).

Every request-time failure is raised through a real FastAPI app with a distinct,
fingerprint-shaped `reason`. What a client may observe is the status code and one uniform
body; what an operator may observe is the exception class, its `reason`, and its `repr`.

Two control routes leak on purpose - one through the body, one through a response header -
and the instrument-proof test asserts the detector fires on both. Every assertion runs
twice: once with a custom `SessionError` handler registered, once on FastAPI's default
handler, which is the path most deployments actually run.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx2
import pytest
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exception_handlers import http_exception_handler
from fastapi.testclient import TestClient

from fastapi_better_auth import (
    AuthServiceUnavailable,
    CsrfFailure,
    InvalidCredential,
    SessionError,
    SessionExpired,
    SessionRevoked,
)

UNAUTHENTICATED_CASES: tuple[tuple[str, type[SessionError], str], ...] = (
    ("invalid", InvalidCredential, "signature mismatch kid=iRAEH8dY tok_fp=9f3ab21c"),
    ("expired", SessionExpired, "expiry 1787241849 elapsed sid_fp=7c1de90f"),
    ("revoked", SessionRevoked, "revocation absent upstream sid_fp=3ba57ce1"),
    ("unavailable", AuthServiceUnavailable, "jwks fetch failed https://auth.internal.example"),
)
CSRF_CASE: tuple[str, type[SessionError], str] = (
    "csrf",
    CsrfFailure,
    "origin https://evil.example rejected allowlist",
)
ALL_CASES = (*UNAUTHENTICATED_CASES, CSRF_CASE)
BODY_LEAK_REASON = "signature mismatch kid=iRAEH8dY tok_fp=9f3ab21c"
HEADER_LEAK_REASON = "revocation absent upstream sid_fp=3ba57ce1"

AppAndObserved = tuple[FastAPI, list[SessionError]]


def needles(reason: str) -> tuple[str, ...]:
    """The whole reason plus every word long enough to be a recognizable fragment."""
    return (reason, *(word for word in reason.split() if len(word) >= 4))


def observable_text(response: httpx2.Response) -> str:
    headers = "\n".join(f"{key}: {value}" for key, value in response.headers.items())
    return f"{headers}\n{response.text}".lower()


def leaked_fragments(reason: str, response: httpx2.Response) -> tuple[str, ...]:
    blob = observable_text(response)
    return tuple(needle for needle in needles(reason) if needle.lower() in blob)


def comparable_headers(response: httpx2.Response) -> dict[str, str]:
    return {k.lower(): v for k, v in response.headers.items() if k.lower() != "date"}


def raising_endpoint(error_cls: type[SessionError], reason: str) -> Callable[[], None]:
    def endpoint() -> None:
        raise error_cls(reason=reason)

    return endpoint


def body_leaking_endpoint(reason: str) -> Callable[[], None]:
    """Control: a hand-rolled 401 that puts the reason straight into the body."""

    def endpoint() -> None:
        raise HTTPException(status_code=401, detail=reason)

    return endpoint


def header_leaking_endpoint(reason: str) -> Callable[[], None]:
    """Control: a uniform body, but the reason smuggled out on a response header."""

    def endpoint() -> None:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer", "X-Auth-Debug": reason},
        )

    return endpoint


def build_app(with_handler: bool) -> AppAndObserved:
    app = FastAPI()
    observed: list[SessionError] = []

    async def record(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, SessionError)
        observed.append(exc)
        return await http_exception_handler(request, exc)

    if with_handler:
        app.add_exception_handler(SessionError, record)
    for path, error_cls, reason in ALL_CASES:
        app.add_api_route(
            f"/{path}", raising_endpoint(error_cls, reason), methods=["GET"], response_model=None
        )
    app.add_api_route(
        "/leak-body", body_leaking_endpoint(BODY_LEAK_REASON), methods=["GET"], response_model=None
    )
    app.add_api_route(
        "/leak-header",
        header_leaking_endpoint(HEADER_LEAK_REASON),
        methods=["GET"],
        response_model=None,
    )
    return app, observed


@pytest.fixture(params=[True, False], ids=["custom-handler", "default-handler"])
def app_and_observed(request: pytest.FixtureRequest) -> AppAndObserved:
    with_handler = request.param
    assert isinstance(with_handler, bool)
    return build_app(with_handler)


@pytest.mark.parametrize(
    ("path", "reason"),
    [("leak-body", BODY_LEAK_REASON), ("leak-header", HEADER_LEAK_REASON)],
)
def test_the_leak_detector_fires_on_both_channels(
    app_and_observed: AppAndObserved, path: str, reason: str
) -> None:
    """Prove the instrument: an oracle that cannot detect a leak proves nothing."""
    app, _ = app_and_observed
    with TestClient(app) as client:
        response = client.get(f"/{path}")

    assert response.status_code == 401
    assert leaked_fragments(reason, response)


def test_no_response_carries_any_fragment_of_its_reason(
    app_and_observed: AppAndObserved,
) -> None:
    app, _ = app_and_observed
    with TestClient(app) as client:
        for path, _error_cls, reason in ALL_CASES:
            response = client.get(f"/{path}")

            assert response.status_code in (401, 403), f"/{path} never reached its handler"
            assert leaked_fragments(reason, response) == (), f"/{path} leaked its reason"


def test_the_401_family_is_indistinguishable_on_the_wire(
    app_and_observed: AppAndObserved,
) -> None:
    app, _ = app_and_observed
    with TestClient(app) as client:
        responses = [client.get(f"/{path}") for path, _cls, _reason in UNAUTHENTICATED_CASES]

    bodies = {response.content for response in responses}
    headers = [comparable_headers(response) for response in responses]

    assert {response.status_code for response in responses} == {401}
    assert bodies == {b'{"detail":"Not authenticated"}'}
    assert all(header == headers[0] for header in headers)
    assert all(response.headers["www-authenticate"] == "Bearer" for response in responses)


def test_csrf_failure_is_a_403_with_no_challenge(app_and_observed: AppAndObserved) -> None:
    app, _ = app_and_observed
    with TestClient(app) as client:
        response = client.get(f"/{CSRF_CASE[0]}")

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}
    assert "www-authenticate" not in response.headers


def test_the_operator_side_still_sees_every_reason() -> None:
    app, observed = build_app(with_handler=True)
    with TestClient(app) as client:
        for path, _error_cls, _reason in ALL_CASES:
            client.get(f"/{path}")

    assert [type(exc) for exc in observed] == [error_cls for _p, error_cls, _r in ALL_CASES]
    assert [exc.reason for exc in observed] == [reason for _p, _cls, reason in ALL_CASES]
    assert all(exc.reason in repr(exc) for exc in observed)
