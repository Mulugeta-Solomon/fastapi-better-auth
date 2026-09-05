"""D2: two `Authorization` headers is a refusal, not a silent take-the-first (SA-D2).

`Authorization` carries a single credential, not a comma-list, so more than one is a request no
client should send. `extract` used to read `headers.get("authorization")` and take the first of
two silently; it now returns a marker for the >1 case that `verify` turns into a terminal
`InvalidCredential`, the same present-but-malformed shape the cookie side uses. This mirrors B4's
two-`Origin` rule and closes a gap in the PUBLISHED 0.1.0 bearer path.
"""

from __future__ import annotations

import pytest
from starlette.requests import HTTPConnection

from fastapi_better_auth import BetterAuth, InvalidCredential, JwtVerifier, User
from fastapi_better_auth._internal import jwt_verifier as jv
from tests.fakes import resolver_of

AMBIGUOUS = jv._AMBIGUOUS_BEARER  # pyright: ignore[reportPrivateUsage]

BASE_URL = "http://localhost:3100"


def connection(*authorizations: str) -> HTTPConnection:
    headers = [(b"authorization", value.encode()) for value in authorizations]
    return HTTPConnection(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "root_path": "",
            "headers": headers,
            "server": ("api", 443),
            "client": ("1.2.3.4", 5),
        }
    )


def verifier() -> JwtVerifier:
    return JwtVerifier(base_url=BASE_URL)


class TestExtract:
    def test_one_header_is_the_token(self) -> None:
        assert verifier().extract(connection("Bearer the-token")) == "the-token"

    def test_no_header_is_absent(self) -> None:
        assert verifier().extract(connection()) is None

    def test_two_headers_are_the_ambiguous_marker(self) -> None:
        """Not `None` (which would drop the credential and read as anonymous), and not one of the
        two taken silently: a marker dispatch counts as one present credential to be refused."""
        got = verifier().extract(connection("Bearer first-token", "Bearer second-token"))

        assert got is AMBIGUOUS

    def test_two_headers_even_of_differing_schemes_are_ambiguous(self) -> None:
        got = verifier().extract(connection("Bearer real-token", "Basic Zm9vOmJhcg=="))

        assert got is AMBIGUOUS

    def test_the_marker_repr_carries_no_credential(self) -> None:
        """The marker holds nothing, so its repr is safe on any traceback a reporter captures."""
        assert "ambiguous bearer" in repr(AMBIGUOUS)


class TestVerify:
    @pytest.mark.anyio
    async def test_the_marker_is_an_invalid_credential(self) -> None:
        with pytest.raises(InvalidCredential) as caught:
            await verifier().verify(AMBIGUOUS, User)

        assert "more than one Authorization header" in caught.value.reason


class TestThroughDispatch:
    @pytest.mark.anyio
    async def test_two_headers_are_a_terminal_refusal_not_a_fall_through(self) -> None:
        """The marker is one present credential, so dispatch verifies it and its 401 is final -
        it never falls through to be re-checked as anonymous."""
        resolve = resolver_of(BetterAuth(verifiers=[verifier()]).current_session(user_model=User))
        request = connection("Bearer first-token", "Bearer second-token")

        with pytest.raises(InvalidCredential):
            await resolve(request)

    @pytest.mark.anyio
    async def test_a_single_header_still_dispatches_to_verification(self) -> None:
        """One header is unchanged: a bad token still reaches verify and is refused there (not for
        ambiguity), proving the >1 rule did not disturb the ordinary path."""
        resolve = resolver_of(BetterAuth(verifiers=[verifier()]).current_session(user_model=User))

        with pytest.raises(InvalidCredential) as caught:
            await resolve(connection("Bearer not.a.jwt"))

        assert "more than one Authorization header" not in caught.value.reason

    @pytest.mark.anyio
    async def test_no_header_is_absent_not_a_refusal(self) -> None:
        """The absence signal survives: no Authorization header resolves to None (anonymous),
        which `optional_session` returns as None rather than a refusal."""
        resolve = resolver_of(BetterAuth(verifiers=[verifier()]).optional_session(user_model=User))

        assert await resolve(connection()) is None
