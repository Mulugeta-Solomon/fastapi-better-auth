"""Mode B from the outside: how a `JwtVerifier` is built, what `extract` owns, the ground truth.

The golden vector is the point of the file: a real token from a real better-auth 1.7.1 verifying
against the key set it was captured with, on a frozen clock - and the proof that the freeze is
doing something. Around it, the construction rules that refuse a bypass before a request exists
(a cleartext key set, a symmetric algorithm, an hour of leeway), the bearer scheme `extract`
matches and the absences it reports, what stands in for a missing `id`, what an unreachable or
redirected key set does to a request, and D-010 as an executable statement. The negatives, one
edit away from the golden case, are `test_jwt_verifier_refusals.py`; the parser and the leak
channels are `test_jwt_verifier_hygiene.py`; the builders all three share are
`tests/jwt_fixtures.py`.
"""

from __future__ import annotations

import inspect
import sys
from datetime import datetime, timezone
from typing import Any

import pytest
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    AuthServiceUnavailable,
    ConfigurationError,
    Session,
    SessionExpired,
    Transport,
    User,
    Verifier,
)
from fastapi_better_auth._internal.jwks import SUPPORTED_ALGORITHMS
from fastapi_better_auth._internal.jwt_verifier import JwtVerifier
from tests.fakes import connection
from tests.jwt_fixtures import KEY_SET, SIGNER, build, refused
from tests.tokens import (
    ABSENT,
    GOLDEN_CLAIMS,
    GOLDEN_JWKS,
    GOLDEN_KID,
    GOLDEN_TOKEN,
    LIFETIME,
    ORIGIN,
    SUBJECT,
    claims,
    frozen_at,
    inside_the_golden_validity,
)
from tests.transports import NotATransport, Reply, ScriptedTransport, json_reply

# --- construction ---------------------------------------------------------------------


def test_it_is_a_verifier() -> None:
    checked: Verifier = JwtVerifier(base_url=ORIGIN, transport=ScriptedTransport(Reply(b"{}")))

    assert isinstance(checked, Verifier)
    assert checked.credential_source == "header:authorization-bearer"
    assert not inspect.iscoroutinefunction(checked.extract)


def test_the_origin_is_canonicalized_and_pins_the_key_set_url() -> None:
    verifier, _transport = build()
    loud = JwtVerifier(base_url="HTTP://LocalHost:3100/", transport=ScriptedTransport(Reply(b"{}")))

    assert verifier.origin == ORIGIN
    assert verifier.jwks_uri == f"{ORIGIN}/api/auth/jwks"
    assert loud.origin == ORIGIN


@pytest.mark.parametrize(
    "value",
    ["", "auth.example.com", "https://auth.example.com/api", "https://user:pw@auth.example.com"],
)
def test_a_base_url_that_is_not_an_origin_is_refused_at_construction(value: str) -> None:
    with pytest.raises(ConfigurationError):
        JwtVerifier(base_url=value, transport=ScriptedTransport(Reply(b"{}")))


def test_http_is_refused_for_anything_but_a_loopback_host() -> None:
    """The one misconfiguration that is a complete bypass: a key set over cleartext can be
    replaced by anyone on the path, and there is no signature left to fall back on."""
    with pytest.raises(ConfigurationError):
        JwtVerifier(base_url="http://auth.example.com", transport=ScriptedTransport(Reply(b"{}")))


@pytest.mark.parametrize("algorithm", SUPPORTED_ALGORITHMS)
def test_every_algorithm_upstream_can_issue_is_accepted(algorithm: str) -> None:
    verifier, _transport = build(algorithms=(algorithm,))

    assert verifier.algorithms == (algorithm,)


@pytest.mark.parametrize(
    "algorithms",
    [
        ("HS256",),
        ("EdDSA", "HS256"),
        ("HS512",),
        ("none",),
        ("None",),
        ("eddsa",),
        ("ES999",),
        (),
        ("EdDSA", ""),
        ("EdDSA", None),
        (7,),
        "EdDSA",
        None,
    ],
    ids=[
        "hs256",
        "hs256-alongside",
        "hs512",
        "none",
        "None",
        "wrong-case",
        "unknown",
        "empty",
        "empty-entry",
        "null-entry",
        "not-a-string",
        "a-bare-string",
        "none-at-all",
    ],
)
def test_an_algorithm_this_library_will_not_verify_is_refused_at_construction(
    algorithms: Any,
) -> None:
    """`HS256` is the one that matters: a symmetric algorithm on a JWKS path turns a
    *public* key into a signing secret. It is refused here, so no decode ever sees it - and
    a bare string is refused too, because `"EdDSA"` is a sequence of five one-letter algorithms."""
    with pytest.raises(ConfigurationError):
        build(algorithms=algorithms)


@pytest.mark.parametrize("leeway", [0, 0.5, 30, 60])
def test_a_leeway_inside_the_ceiling_is_accepted(leeway: float) -> None:
    verifier, _transport = build(leeway=leeway)

    assert verifier.leeway == float(leeway)


@pytest.mark.parametrize(
    "leeway",
    [-1, 61, 3600, float("inf"), float("nan"), "30", True, None],
    ids=["negative", "over", "an-hour", "inf", "nan", "a-string", "a-bool", "none"],
)
def test_a_leeway_outside_the_ceiling_is_refused_at_construction(leeway: Any) -> None:
    """Sixty seconds covers clock skew. Anything more is a policy decision this library
    will not make quietly: an hour of leeway is an hour of extra session life."""
    with pytest.raises(ConfigurationError):
        build(leeway=leeway)


@pytest.mark.parametrize(
    "lifetime",
    [0, -1, 86401, float("inf"), float("nan"), "900", True],
    ids=["zero", "negative", "over-a-day", "inf", "nan", "a-string", "a-bool"],
)
def test_a_token_lifetime_ceiling_that_is_not_one_is_refused(lifetime: Any) -> None:
    with pytest.raises(ConfigurationError):
        build(max_token_lifetime=lifetime)


@pytest.mark.parametrize(
    ("leeway", "configured", "ceiling"),
    [(0, None, 900.0), (30, None, 930.0), (0, 60, 60.0), (30, 120, 120.0)],
    ids=["default", "default-plus-leeway", "configured", "configured-wins"],
)
def test_the_lifetime_ceiling_is_upstreams_own_token_lifetime_plus_leeway(
    leeway: float, configured: float | None, ceiling: float
) -> None:
    verifier, _transport = build(leeway=leeway, max_token_lifetime=configured)

    assert verifier.max_token_lifetime == ceiling


def test_a_transport_that_is_not_one_is_refused_at_construction() -> None:
    with pytest.raises(ConfigurationError):
        JwtVerifier(base_url=ORIGIN, transport=NotATransport())  # pyright: ignore[reportArgumentType]


def test_the_default_transport_is_built_at_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing HTTP library must stop the application from starting, not surface on the
    first request that needed a key set."""
    monkeypatch.setitem(sys.modules, "httpx", None)

    with pytest.raises(ConfigurationError) as caught:
        JwtVerifier(base_url=ORIGIN)

    assert "httpx" in str(caught.value)


def test_an_injected_transport_is_the_one_that_fetches() -> None:
    verifier, transport = build()

    assert isinstance(transport, Transport)
    assert verifier.jwks_uri.startswith(ORIGIN)


# --- extract --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("Bearer abc.def.ghi", "abc.def.ghi"),
        ("bearer abc.def.ghi", "abc.def.ghi"),
        ("BEARER abc.def.ghi", "abc.def.ghi"),
        ("BeArEr abc.def.ghi", "abc.def.ghi"),
        ("Bearer   abc.def.ghi", "abc.def.ghi"),
        ("Bearer abc.def.ghi   ", "abc.def.ghi"),
    ],
)
def test_the_bearer_scheme_is_matched_case_insensitively(header: str, expected: str) -> None:
    """RFC 7235 says the scheme is case-insensitive, and clients take that literally."""
    verifier, _transport = build()

    assert verifier.extract(connection(authorization=header)) == expected


@pytest.mark.parametrize(
    "header",
    ["", "Bearer", "Bearer ", "Bearer    ", "Basic dXNlcjpwdw==", "Bearerx abc", "abc.def.ghi"],
    ids=["blank", "no-token", "empty-token", "spaces", "basic", "near-miss", "no-scheme"],
)
def test_a_header_this_verifier_does_not_own_extracts_as_absent(header: str) -> None:
    """`None` is the only absence signal: an empty string counts as *present* and would be
    dispatched to `verify`, so a blank Authorization header would 401 instead of 200 for an
    anonymous request that `optional_session` should have let through."""
    verifier, _transport = build()

    assert verifier.extract(connection(authorization=header)) is None


def test_an_absent_header_extracts_as_absent() -> None:
    verifier, _transport = build()

    assert verifier.extract(connection()) is None


def test_extract_touches_neither_the_network_nor_the_clock() -> None:
    """It runs on every verifier on every request, before dispatch has chosen one."""
    verifier, transport = build()

    verifier.extract(connection(authorization=f"Bearer {GOLDEN_TOKEN}"))

    assert transport.calls == 0


def test_extract_never_raises_on_anything_a_client_can_send() -> None:
    verifier, _transport = build()
    hostile = ["Bearer " + chr(0) * 10, "Bearer " + chr(0x202E) * 10, "Bearer " + "x" * 100_000]

    for header in hostile:
        assert verifier.extract(connection(authorization=header)) is not None


# --- the golden vector ------------------------------------------------------------------


@pytest.mark.anyio
async def test_the_captured_token_verifies_against_its_captured_key_set() -> None:
    """Ground truth: a real token from a real better-auth 1.7.1, and the session it proves."""
    verifier, transport = build(json_reply(GOLDEN_JWKS))

    with frozen_at(inside_the_golden_validity()):
        session = await verifier.verify(GOLDEN_TOKEN, User)

    assert isinstance(session, Session)
    assert session.user.id == GOLDEN_CLAIMS["sub"]
    assert session.user.email == GOLDEN_CLAIMS["email"]
    assert session.user.name == GOLDEN_CLAIMS["name"]
    assert session.user.email_verified is False
    assert session.token is None
    assert session.expires_at == datetime.fromtimestamp(GOLDEN_CLAIMS["exp"], tz=timezone.utc)
    assert session.expires_at is not None and session.expires_at.tzinfo is not None
    assert dict(session.raw) == GOLDEN_CLAIMS
    assert transport.calls == 1


@pytest.mark.anyio
async def test_the_captured_token_is_expired_without_the_frozen_clock() -> None:
    """Prove the instrument: if the freeze did nothing, the test above would be verifying a
    token that expired fifteen minutes after it was captured."""
    error, _transport = await refused(GOLDEN_TOKEN, json_reply(GOLDEN_JWKS))

    assert isinstance(error, SessionExpired)


@pytest.mark.anyio
async def test_the_captured_claims_are_the_shape_this_verifier_was_built_for() -> None:
    """If upstream moves any of these, the failure should read as a claim change."""
    verifier, _transport = build(json_reply(GOLDEN_JWKS))

    with frozen_at(inside_the_golden_validity()):
        session = await verifier.verify(GOLDEN_TOKEN, User)

    assert session.raw["iss"] == verifier.origin
    assert session.raw["aud"] == verifier.origin
    assert session.raw["sub"] == GOLDEN_CLAIMS["sub"]
    assert session.raw["exp"] - session.raw["iat"] == LIFETIME
    assert GOLDEN_KID in {key["kid"] for key in GOLDEN_JWKS["keys"]}


@pytest.mark.anyio
async def test_a_user_model_of_our_own_is_the_one_that_comes_back() -> None:
    class Staff(User):
        role: str | None = None

    verifier, _transport = build(json_reply(KEY_SET))
    token = SIGNER.sign(claims(role="admin"))

    session = await verifier.verify(token, Staff)

    assert isinstance(session.user, Staff)
    assert session.user.role == "admin"


# --- the identity -----------------------------------------------------------------------


@pytest.mark.anyio
async def test_the_subject_stands_in_when_a_payload_carries_no_id() -> None:
    """`definePayload` lets an operator mint a slimmer token, and `sub` is the same value
    upstream puts in `id`. Refusing here would be refusing an authentic, signed token."""
    verifier, _transport = build()
    token = SIGNER.sign(claims(id=ABSENT))

    session = await verifier.verify(token, User)

    assert session.user.id == SUBJECT
    assert "id" not in session.raw


@pytest.mark.anyio
async def test_an_id_the_payload_carries_is_never_overwritten() -> None:
    verifier, _transport = build()
    token = SIGNER.sign(claims(id="numeric-id-42"))

    session = await verifier.verify(token, User)

    assert session.user.id == "numeric-id-42"


# --- the key set, from the verifier's side ------------------------------------------------


@pytest.mark.anyio
async def test_an_unreachable_key_set_refuses_the_request() -> None:
    """A session this library cannot verify is a session it must not honour."""
    error, _transport = await refused(SIGNER.sign(claims()), TimeoutError("jwks timed out"))

    assert isinstance(error, AuthServiceUnavailable)


@pytest.mark.anyio
async def test_a_redirected_key_set_refuses_the_request() -> None:
    """The transport does not follow redirects; a 3xx arrives here as the answer it is."""
    error, _transport = await refused(SIGNER.sign(claims()), json_reply(KEY_SET, status=302))

    assert isinstance(error, AuthServiceUnavailable)


def test_the_connection_is_never_a_source_of_an_auth_value() -> None:
    """D-010, as an executable statement: what `iss` is compared against comes from config,
    so a request claiming to be from somewhere else changes nothing at all."""
    verifier, _transport = build()
    hostile: HTTPConnection = connection(
        authorization="Bearer x.y.z", host="evil.example", x_forwarded_host="evil.example"
    )

    assert verifier.extract(hostile) == "x.y.z"
    assert verifier.origin == ORIGIN
    assert verifier.jwks_uri == f"{ORIGIN}/api/auth/jwks"
