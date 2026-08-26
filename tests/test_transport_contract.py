"""The transport boundary as a contract: two methods, three obligations, one dumb answer.

`Transport` is the only door this library has onto a network, and everything security-shaped
about it is an obligation on the *implementer* — a redirect is never followed, `max_bytes` is
enforced while the body is being read, and a network failure is left alone for the verifier
above to translate. A protocol whose obligations are not written down is a protocol every
implementer gets to guess at, so the docstring is asserted here too.
"""

from __future__ import annotations

import dataclasses
import inspect
import pickle
from collections.abc import Mapping
from typing import Any, get_type_hints

import pytest
from fastapi import HTTPException

import fastapi_better_auth
from fastapi_better_auth import (
    BetterAuth,
    BetterAuthError,
    ResponseTooLarge,
    SessionError,
    Transport,
    TransportResponse,
)
from tests.fakes import GOOD_CREDENTIAL, OversizeVerifier, client, session_app

HEADER = "x-cred-a"
NEW_EXPORTS = (
    "HttpxTransport",
    "Httpx2Transport",
    "ResponseTooLarge",
    "Transport",
    "TransportResponse",
)


class ConformingTransport:
    """The shape a third party has to hit — nothing here does any work."""

    async def get(
        self, url: str, *, headers: Mapping[str, str] | None = None, max_bytes: int
    ) -> TransportResponse:
        raise NotImplementedError

    async def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        content: bytes = b"",
        max_bytes: int,
    ) -> TransportResponse:
        raise NotImplementedError


class GetOnlyTransport:
    """One of the two methods — the half-written shape."""

    async def get(
        self, url: str, *, headers: Mapping[str, str] | None = None, max_bytes: int
    ) -> TransportResponse:
        raise NotImplementedError


@pytest.mark.parametrize("name", NEW_EXPORTS)
def test_the_transport_boundary_is_public_api(name: str) -> None:
    assert name in fastapi_better_auth.__all__


def test_a_conforming_transport_is_recognized_at_runtime() -> None:
    assert isinstance(ConformingTransport(), Transport)


@pytest.mark.parametrize(
    "candidate",
    [GetOnlyTransport(), object(), "a string", None],
    ids=["get-only", "object", "str", "none"],
)
def test_a_non_conforming_object_is_not_a_transport(candidate: Any) -> None:
    assert not isinstance(candidate, Transport)


def test_the_protocol_is_exactly_two_methods() -> None:
    """A third method is a third thing every implementer has to get right. `aclose` lives
    on the adapters, deliberately outside the protocol: a caller that was handed a transport
    it did not build must not be able to close it."""
    members = {name for name in vars(Transport) if not name.startswith("_")}

    assert members == {"get", "post"}


@pytest.mark.parametrize("method", ["get", "post"])
def test_both_methods_are_asynchronous(method: str) -> None:
    assert inspect.iscoroutinefunction(getattr(Transport, method))


@pytest.mark.parametrize("method", ["get", "post"])
def test_both_methods_answer_with_a_transport_response(method: str) -> None:
    hints = get_type_hints(getattr(Transport, method))

    assert hints["return"] is TransportResponse


@pytest.mark.parametrize("method", ["get", "post"])
def test_the_cap_is_required_and_keyword_only(method: str) -> None:
    """`max_bytes` has no default because the cap is the *caller's* policy: a transport that
    picked one would be deciding how much of an unverified body its caller must hold."""
    parameter = inspect.signature(getattr(Transport, method)).parameters["max_bytes"]

    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty


@pytest.mark.parametrize("method", ["get", "post"])
def test_the_url_is_the_only_positional_argument(method: str) -> None:
    positional = [
        name
        for name, parameter in inspect.signature(getattr(Transport, method)).parameters.items()
        if parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD and name != "self"
    ]

    assert positional == ["url"]


def test_post_defaults_to_an_empty_body() -> None:
    parameter = inspect.signature(Transport.post).parameters["content"]

    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default == b""


@pytest.mark.parametrize(
    "obligation",
    ["redirect", "max_bytes", "Content-Length"],
    ids=["no-redirects", "the-cap", "content-length-is-not-enforcement"],
)
def test_the_docstring_states_the_implementer_obligations(obligation: str) -> None:
    """An implementer reads this docstring and nothing else. Every rule that makes a
    transport safe to hand a pinned URL has to be in it."""
    assert obligation in (Transport.__doc__ or "")


def test_the_docstring_says_failures_are_not_translated_here() -> None:
    doc = Transport.__doc__ or ""

    assert "timeout" in doc.lower()
    assert "AuthServiceUnavailable" in doc


def test_a_response_carries_the_status_headers_and_body() -> None:
    response = TransportResponse(status_code=200, headers={"content-type": "x"}, content=b"body")

    assert response.status_code == 200
    assert response.headers["content-type"] == "x"
    assert response.content == b"body"


def test_header_names_are_lowercased_so_lookups_are_case_insensitive() -> None:
    """HTTP header names are case-insensitive and HTTP/2 lowercases them on the wire. The
    type owns the normalization so no adapter can forget it and no caller has to guess."""
    response = TransportResponse(status_code=200, headers={"Content-Type": "x"}, content=b"")

    assert response.headers["content-type"] == "x"
    assert "Content-Type" not in response.headers


def test_the_headers_mapping_cannot_be_mutated_through_the_response() -> None:
    source = {"content-type": "x"}
    response = TransportResponse(status_code=200, headers=source, content=b"")

    with pytest.raises(TypeError):
        response.headers["content-type"] = "y"  # pyright: ignore[reportIndexIssue]
    source["content-type"] = "y"
    assert response.headers["content-type"] == "x"


def test_a_response_is_frozen() -> None:
    response = TransportResponse(status_code=200, headers={}, content=b"")

    with pytest.raises(dataclasses.FrozenInstanceError):
        response.status_code = 500  # pyright: ignore[reportAttributeAccessIssue]


def test_responses_compare_by_value() -> None:
    first = TransportResponse(status_code=200, headers={"a": "b"}, content=b"x")
    second = TransportResponse(status_code=200, headers={"A": "b"}, content=b"x")

    assert first == second


def test_the_body_stays_out_of_the_repr() -> None:
    """A response repr reaches logs and tracebacks; an unverified body must not ride along."""
    response = TransportResponse(status_code=200, headers={}, content=b"a-secret-key-set")

    assert "a-secret-key-set" not in repr(response)
    assert "200" in repr(response)


def test_the_cap_failure_names_the_cap() -> None:
    error = ResponseTooLarge(max_bytes=1024)

    assert error.max_bytes == 1024
    assert "1024" in str(error)


def test_the_cap_failure_survives_a_pickle() -> None:
    """A keyword-only `__init__` and the default `__reduce__` do not survive one, and an
    error reporter that cannot rebuild an exception reports the wrong thing about it."""
    restored = pickle.loads(pickle.dumps(ResponseTooLarge(max_bytes=7)))

    assert isinstance(restored, ResponseTooLarge)
    assert restored.max_bytes == 7


def test_the_cap_failure_is_not_a_session_error() -> None:
    """The transport has no request context: it cannot know whether an oversized body is a
    401 or a 503, so it does not get to answer a client. The verifier above translates."""
    error = ResponseTooLarge(max_bytes=1)

    assert not isinstance(error, SessionError)
    assert not isinstance(error, HTTPException)


def test_the_cap_failure_is_not_a_better_auth_error() -> None:
    """Deliberate, and load-bearing: `BetterAuthError` is honoured by dispatch and would
    escape as a 500 — the one request-time answer a client can tell apart from every other.
    An oversized key set is an upstream fault, not a configuration fault."""
    error = ResponseTooLarge(max_bytes=1)

    assert not isinstance(error, BetterAuthError)


def test_an_untranslated_cap_failure_is_contained_as_the_uniform_401(client_backend: str) -> None:
    """The consequence of the two assertions above, driven end to end: a verifier that
    forgets to translate fails *closed*, with the same bytes as every other refusal."""
    auth = BetterAuth(verifiers=[OversizeVerifier(HEADER)])

    with client(session_app(auth), client_backend) as http:
        response = http.get("/required", headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}
    assert response.headers["www-authenticate"] == "Bearer"
