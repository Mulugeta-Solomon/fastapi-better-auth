"""Mode B, claim by claim: what verifies, what is refused, and what is refused for free.

The accepted case is the real token from `tests/vectors/jwt_v1.json` — better-auth 1.7.1, an
EdDSA signature, the key set that goes with it. Every other test in this file is that token
with one thing wrong, minted locally because a vector cannot ship a token signed by the wrong
key without shipping the wrong key.

Two properties are asserted over and over and are worth naming once. **Nothing about the
credential reaches a `reason`** - not the token, not its signature, not a `kid` an attacker
chose - because a reason is what error reporters serialize. And **a refusal that can be
decided locally never becomes a network call**: an algorithm outside the allowlist, a missing
`kid`, a token that is not a token are all refused with the transport untouched, which is both
the cheap answer and the one that gives an attacker no way to make this process fetch.
"""

from __future__ import annotations

import functools
import inspect
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Any

import jwt
import pytest
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    AuthServiceUnavailable,
    ConfigurationError,
    InvalidCredential,
    Session,
    SessionError,
    SessionExpired,
    Transport,
    User,
    Verifier,
)
from fastapi_better_auth._internal.jwks import SUPPORTED_ALGORITHMS
from fastapi_better_auth._internal.jwt_verifier import MAX_TOKEN_BYTES, JwtVerifier
from fastapi_better_auth._internal.reasons import fingerprint
from tests.fakes import connection
from tests.tokens import (
    ABSENT,
    GOLDEN_CLAIMS,
    GOLDEN_JWKS,
    GOLDEN_KID,
    GOLDEN_TOKEN,
    LIFETIME,
    ORIGIN,
    OTHER_ORIGIN,
    SUBJECT,
    b64url,
    claims,
    deep_header_token,
    deep_payload_token,
    deepest_depth,
    defeats_the_json_parser,
    ec_signer,
    ed25519_signer,
    exhausted_parse,
    forged,
    frozen_at,
    hmac_signed,
    inside_the_golden_validity,
    key_set,
    nested_arrays,
    payload_of,
    rsa_signer,
    signed_raw,
    tampered,
    unsigned,
)
from tests.transports import NotATransport, Reply, ScriptedTransport, json_reply

SIGNER = ed25519_signer("wp5-1")
KEY_SET = key_set(SIGNER)
OTHER = ed25519_signer("wp5-1")
"""A different key published under the *same* kid - the substituted-key-set attack."""


def build(
    *answers: Reply | BaseException, **settings: Any
) -> tuple[JwtVerifier, ScriptedTransport]:
    transport = ScriptedTransport(*(answers or (json_reply(KEY_SET),)))
    return JwtVerifier(base_url=ORIGIN, transport=transport, **settings), transport


async def refused(
    token: str, *answers: Reply | BaseException, **settings: Any
) -> tuple[SessionError, ScriptedTransport]:
    """Verify a token that must not verify, and hand back the refusal and the transport."""
    verifier, transport = build(*answers, **settings)
    with pytest.raises(SessionError) as caught:
        await verifier.verify(token, User)
    return caught.value, transport


def leaks(error: SessionError, token: str) -> tuple[str, ...]:
    """Every fragment of the credential that survived into the operator-facing reason."""
    segments = token.split(".")
    candidates = (token, *(part for part in segments if len(part) >= 8))
    return tuple(needle for needle in candidates if needle in error.reason)


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


# --- the accepted case, minted ----------------------------------------------------------


@pytest.mark.anyio
async def test_a_freshly_minted_token_verifies() -> None:
    """The baseline every negative below is one edit away from."""
    verifier, transport = build()

    session = await verifier.verify(SIGNER.sign(claims()), User)

    assert session.user.id == SUBJECT
    assert transport.calls == 1


@pytest.mark.anyio
async def test_the_key_set_is_fetched_once_for_many_tokens() -> None:
    verifier, transport = build()

    for _ in range(5):
        await verifier.verify(SIGNER.sign(claims()), User)

    assert transport.calls == 1


# --- signature and algorithm ------------------------------------------------------------


@pytest.mark.anyio
async def test_a_token_signed_by_the_wrong_key_is_refused() -> None:
    """The same kid, a different key: what a substituted key set buys an attacker, and the
    one failure that no amount of claim checking would catch."""
    token = OTHER.sign(claims())

    error, _transport = await refused(token)

    assert isinstance(error, InvalidCredential)
    assert leaks(error, token) == ()


@pytest.mark.anyio
@pytest.mark.parametrize("part", [1, 2], ids=["payload", "signature"])
async def test_a_tampered_token_is_refused(part: int) -> None:
    token = tampered(SIGNER.sign(claims()), part=part)

    error, _transport = await refused(token)

    assert isinstance(error, InvalidCredential)


@pytest.mark.anyio
async def test_a_header_that_lies_about_its_algorithm_is_refused() -> None:
    """An EdDSA signature under an `alg: ES256` header. Both are in the allowlist here, so
    the only thing standing between this token and a decode is the key's own declared alg."""
    token = signed_raw(SIGNER, {"alg": "ES256", "kid": SIGNER.kid}, claims())

    error, _transport = await refused(token, algorithms=("EdDSA", "ES256"))

    assert isinstance(error, InvalidCredential)


@pytest.mark.anyio
async def test_an_algorithm_outside_the_allowlist_is_refused_without_a_fetch() -> None:
    other = ec_signer("wp5-1")
    token = other.sign(claims())

    error, transport = await refused(token, algorithms=("EdDSA",))

    assert isinstance(error, InvalidCredential)
    assert transport.calls == 0


@pytest.mark.anyio
async def test_an_hs256_token_is_refused_without_a_fetch() -> None:
    """The key-confusion attack: sign with the *published* key material as an HMAC secret.
    It never reaches a decode, because a symmetric algorithm cannot be configured at all."""
    token = hmac_signed(claims(), secret=SIGNER.jwk["x"], kid=SIGNER.kid)

    error, transport = await refused(token)

    assert isinstance(error, InvalidCredential)
    assert transport.calls == 0


@pytest.mark.anyio
async def test_an_unsigned_token_is_refused_without_a_fetch() -> None:
    error, transport = await refused(unsigned(claims()))

    assert isinstance(error, InvalidCredential)
    assert transport.calls == 0


@pytest.mark.anyio
async def test_a_key_published_for_one_algorithm_will_not_verify_another() -> None:
    """The confusion the header check alone does not close: one RSA key, two algorithms.

    `PS256` and `RS256` take the same key, so a token signed PS256 verifies against a key
    published as RS256 unless something says otherwise. The key's own declared `alg` is what
    says otherwise - upstream publishes it on every JWK, and it is binding.
    """
    signer = rsa_signer("wp5-1", algorithm="RS256")
    token = signer.sign(claims(), algorithm="PS256")

    error, _transport = await refused(
        token, json_reply(key_set(signer)), algorithms=("RS256", "PS256")
    )

    assert isinstance(error, InvalidCredential)


@pytest.mark.anyio
async def test_a_signature_made_with_an_allowed_but_different_algorithm_is_refused() -> None:
    """`RS256` is allowed here and the key set publishes an RSA key - but the kid on the
    token maps to the Ed25519 one, so the algorithms disagree and nothing is decoded."""
    rsa = rsa_signer("wp5-1")
    token = rsa.sign(claims())

    error, _transport = await refused(token, json_reply(KEY_SET), algorithms=("EdDSA", "RS256"))

    assert isinstance(error, InvalidCredential)


# --- critical header extensions -----------------------------------------------------------


def _with_crit(value: Any, **extras: Any) -> str:
    """A real signature over a header carrying exactly this `crit`, and nothing rewritten.

    `signed_raw` rather than `Signer.sign`, because `jwt.encode` refuses to mint several of
    these shapes - and an attacker's toolchain is under no such obligation.
    """
    header: dict[str, Any] = {"alg": "EdDSA", "kid": SIGNER.kid, "crit": value, **extras}
    return signed_raw(SIGNER, header, claims())


@pytest.mark.anyio
async def test_a_token_declaring_a_critical_extension_is_refused_without_a_fetch() -> None:
    """RFC 7515 4.1.11: a `crit` header names extensions the recipient MUST understand, or
    reject the token. Better Auth emits none, and this library implements none.

    `b64` is the one extension PyJWT itself understands (RFC 7797, an unencoded payload), so
    it is the shape the dependency lets straight through however new it is: before this
    refusal existed, this exact token verified into a live `Session` at the cost of one key-set
    fetch. Leaving it to the library would also mean this verifier's answer depends on which
    PyJWT is installed - which is what the CVE-2026-32597 floor already had to fix once.
    """
    token = _with_crit(["b64"], b64=True)

    error, transport = await refused(token)

    assert isinstance(error, InvalidCredential)
    assert transport.calls == 0
    assert "critical" in error.reason


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("value", "extras"),
    [
        (["b64"], {"b64": True}),
        (["urn:example:x"], {"urn:example:x": True}),
        ([], {}),
        ("b64", {"b64": True}),
        (7, {}),
        (None, {}),
        ({"urn:example:x": True}, {}),
    ],
    ids=["b64", "unknown", "empty-list", "a-string", "a-number", "null", "an-object"],
)
async def test_any_crit_header_at_all_is_a_declaration_this_library_refuses(
    value: Any, extras: dict[str, Any]
) -> None:
    """An empty list is still a declaration, and a `crit` that is not a list is a malformed
    one; neither is a header a verifier understands, so both are refusals, and none of them
    costs a fetch.

    Only the first shape is this library's own answer today - `jwt.get_unverified_header`
    validates the rest itself on the floored version and refuses them as an unreadable header,
    which is the same verdict from the layer below. That is why the *reason* is asserted in
    `test_a_token_declaring_a_critical_extension_is_refused_without_a_fetch` rather than here:
    pinning our wording on a refusal the dependency currently owns would pin the dependency.
    """
    error, transport = await refused(_with_crit(value, **extras))

    assert isinstance(error, InvalidCredential)
    assert transport.calls == 0


@pytest.mark.anyio
async def test_the_crit_refusal_names_the_token_only_by_fingerprint() -> None:
    """D-018/D-100 for the new reason: the marker an operator correlates on, and no token."""
    token = _with_crit(["b64"], b64=True)

    error, _transport = await refused(token)

    assert fingerprint(token) in error.reason
    assert leaks(error, token) == ()


# --- the kid --------------------------------------------------------------------------


@pytest.mark.anyio
async def test_a_token_with_no_kid_is_refused_without_a_fetch() -> None:
    """Trying every published key is how a key set with one weak key becomes a bypass."""
    token = forged({"alg": "EdDSA"}, claims())

    error, transport = await refused(token)

    assert isinstance(error, InvalidCredential)
    assert transport.calls == 0


@pytest.mark.anyio
@pytest.mark.parametrize(
    "kid", [7, None, "", "   ", {"kid": "k"}], ids=["int", "null", "empty", "blank", "dict"]
)
async def test_a_kid_that_is_not_a_usable_identifier_is_refused(kid: Any) -> None:
    token = forged({"alg": "EdDSA", "kid": kid}, claims())

    error, transport = await refused(token)

    assert isinstance(error, InvalidCredential)
    assert transport.calls == 0


@pytest.mark.anyio
async def test_a_kid_the_key_set_does_not_carry_is_refused() -> None:
    token = ed25519_signer("never-published").sign(claims())

    error, _transport = await refused(token)

    assert isinstance(error, InvalidCredential)


@pytest.mark.anyio
async def test_a_kid_an_attacker_chose_cannot_write_into_the_log() -> None:
    """A `kid` is attacker-supplied text that reaches an operator's log line. Anything that
    is not a plain identifier is redacted, so it cannot forge a line, or choose its length."""
    hostile = 'aaa"\n2026-01-01 CRITICAL root logged in\x00' + "x" * 500
    token = SIGNER.sign(claims(), headers={"kid": hostile})

    error, _transport = await refused(token)

    assert "\n" not in error.reason
    assert "CRITICAL" not in error.reason
    assert len(error.reason) < 200


# --- the required claims ----------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize("claim", ["exp", "iat", "iss", "aud", "sub"])
async def test_a_token_missing_a_required_claim_is_refused(claim: str) -> None:
    """PyJWT requires *nothing* by default: without an explicit `require`, a token with no
    `exp` verifies and never expires."""
    token = SIGNER.sign(claims(**{claim: ABSENT}))

    error, _transport = await refused(token)

    assert isinstance(error, InvalidCredential)


@pytest.mark.anyio
@pytest.mark.parametrize("claim", ["exp", "iat", "iss", "aud", "sub"])
async def test_a_required_claim_that_is_null_is_refused(claim: str) -> None:
    """PyJWT counts a null claim as absent; a token that says `"iss": null` is not one that
    `jwt.encode` will even mint, so this one is signed at the JWS layer like a real forger's."""
    token = signed_raw(SIGNER, {"alg": "EdDSA", "kid": SIGNER.kid}, {**claims(), claim: None})

    error, _transport = await refused(token)

    assert isinstance(error, InvalidCredential)


@pytest.mark.anyio
@pytest.mark.parametrize("subject", ["", "   ", 7, ["u1"]], ids=["empty", "blank", "int", "list"])
async def test_a_subject_that_identifies_nobody_is_refused(subject: Any) -> None:
    """`sub` is the identity anchor: an empty one would authorize as *some* user."""
    token = SIGNER.sign(claims(sub=subject))

    error, _transport = await refused(token)

    assert isinstance(error, InvalidCredential)


@pytest.mark.anyio
async def test_a_token_from_another_issuer_is_refused() -> None:
    """The other deployment's token is perfectly valid - for the other deployment."""
    token = SIGNER.sign(claims(issuer=OTHER_ORIGIN, audience=OTHER_ORIGIN))

    error, _transport = await refused(token)

    assert isinstance(error, InvalidCredential)


@pytest.mark.anyio
async def test_a_token_whose_only_fault_is_its_issuer_is_refused() -> None:
    """The audience check is not the issuer check. A token minted *for* us by somebody else
    passes every audience rule there is - a mutation that dropped `issuer=` survived until
    this case existed, because the case above happens to move both claims at once."""
    token = SIGNER.sign(claims(issuer=OTHER_ORIGIN, audience=ORIGIN))

    error, _transport = await refused(token)

    assert isinstance(error, InvalidCredential)


@pytest.mark.anyio
async def test_a_token_minted_for_another_audience_is_refused() -> None:
    token = SIGNER.sign(claims(audience=OTHER_ORIGIN))

    error, _transport = await refused(token)

    assert isinstance(error, InvalidCredential)


# --- time -----------------------------------------------------------------------------


@pytest.mark.anyio
async def test_an_expired_token_is_a_session_expired() -> None:
    token = SIGNER.sign(claims(issued_at=int(time.time()) - 2000))

    error, _transport = await refused(token)

    assert isinstance(error, SessionExpired)


@pytest.mark.anyio
async def test_an_expiry_inside_the_leeway_is_still_accepted() -> None:
    verifier, _transport = build(leeway=60)
    token = SIGNER.sign(claims(issued_at=int(time.time()) - LIFETIME - 30))

    session = await verifier.verify(token, User)

    assert session.user.id == SUBJECT


@pytest.mark.anyio
async def test_a_token_that_is_not_valid_yet_is_refused() -> None:
    token = SIGNER.sign(claims(nbf=int(time.time()) + 3600))

    error, _transport = await refused(token)

    assert isinstance(error, InvalidCredential)


@pytest.mark.anyio
async def test_a_token_issued_in_the_future_is_refused() -> None:
    token = SIGNER.sign(claims(issued_at=int(time.time()) + 3600))

    error, _transport = await refused(token)

    assert isinstance(error, InvalidCredential)


@pytest.mark.anyio
async def test_a_lifetime_beyond_the_ceiling_is_refused() -> None:
    """Upstream mints fifteen-minute tokens. A token claiming a year is a misconfigured -
    or replaced - Node side, and it is refused even though every signature check passes."""
    token = SIGNER.sign(claims(lifetime=LIFETIME + 1))

    error, _transport = await refused(token)

    assert isinstance(error, InvalidCredential)


@pytest.mark.anyio
@pytest.mark.parametrize("claim", ["exp", "iat"])
async def test_a_time_claim_that_is_a_string_is_refused(claim: str) -> None:
    """PyJWT coerces a numeric string through `int()` and validates it happily, so a token
    carrying `"exp": "1787241849"` passes every check it makes. The lifetime ceiling is
    arithmetic, and arithmetic on a claim whose type upstream never emits is not a thing to
    guess at."""
    payload = {**claims(), claim: str(claims()[claim])}
    token = signed_raw(SIGNER, {"alg": "EdDSA", "kid": SIGNER.kid}, payload)

    error, _transport = await refused(token)

    assert isinstance(error, InvalidCredential)


@pytest.mark.anyio
async def test_a_lifetime_exactly_at_the_ceiling_is_accepted() -> None:
    verifier, _transport = build()

    session = await verifier.verify(SIGNER.sign(claims(lifetime=LIFETIME)), User)

    assert session.user.id == SUBJECT


@pytest.mark.anyio
async def test_a_token_whose_lifetime_is_negative_is_refused_even_within_leeway() -> None:
    """B3: `iat` after `exp` is a malformed lifetime the ceiling — which only checks the
    *upper* bound — used to wave through. Inert at leeway=0, because PyJWT's own
    iat<=now<=exp forbids it; live the moment an operator opts into leeway, where a token
    signed by a trusted key can carry iat 20s past exp and still be neither expired nor
    immature."""
    verifier, _transport = build(leeway=60)
    now = int(time.time())
    token = SIGNER.sign(claims(issued_at=now + 10, lifetime=-20))

    with pytest.raises(InvalidCredential):
        await verifier.verify(token, User)


@pytest.mark.anyio
async def test_a_token_with_a_zero_lifetime_is_refused() -> None:
    """`exp == iat` is the boundary of the same defect: a lifetime of nothing is not a
    lifetime, and the ceiling's `>` would let it through."""
    verifier, _transport = build(leeway=60)
    now = int(time.time())
    token = SIGNER.sign(claims(issued_at=now, lifetime=0))

    with pytest.raises(InvalidCredential):
        await verifier.verify(token, User)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("lifetime", "accepted"), [(930, True), (931, False)], ids=["at-the-ceiling", "over"]
)
async def test_the_default_ceiling_follows_the_configured_leeway(
    lifetime: int, accepted: bool
) -> None:
    verifier, _transport = build(leeway=30)
    token = SIGNER.sign(claims(lifetime=lifetime))

    if accepted:
        assert (await verifier.verify(token, User)).user.id == SUBJECT
        return
    with pytest.raises(InvalidCredential):
        await verifier.verify(token, User)


@pytest.mark.anyio
async def test_a_configured_ceiling_replaces_the_default() -> None:
    verifier, _transport = build(max_token_lifetime=60)

    with pytest.raises(InvalidCredential):
        await verifier.verify(SIGNER.sign(claims(lifetime=61)), User)


# --- the shape of the credential itself -------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize(
    "credential",
    ["", "   ", "not-a-jwt", "a.b", "a.b.c.d", "...", "\x00\x01", "x" * 9000],
    ids=["empty", "blank", "no-dots", "two-parts", "four-parts", "dots", "control", "oversized"],
)
async def test_a_credential_that_is_not_a_token_is_refused_without_a_fetch(
    credential: str,
) -> None:
    error, transport = await refused(credential)

    assert isinstance(error, InvalidCredential)
    assert transport.calls == 0


@pytest.mark.anyio
async def test_a_token_that_is_valid_but_far_too_large_is_refused_without_a_fetch() -> None:
    """A correctly signed token with ten kilobytes of padding in a claim nobody reads.

    Every other refusal here would have refused this one too - for its shape, its signature,
    its claims - which is exactly why the case has to be *valid* apart from its size. A
    mutation that removed the cap survived two earlier oversized cases, because both were
    refused for having no dots in them.
    """
    token = SIGNER.sign(claims(padding="p" * 9000))
    assert len(token) > 8192

    error, transport = await refused(token)

    assert isinstance(error, InvalidCredential)
    assert transport.calls == 0


# --- a token the JSON parser cannot survive -----------------------------------------------

DEEP_PAYLOAD_TOKEN = functools.partial(deep_payload_token, SIGNER)
DEEP_HEADER_DEPTH = deepest_depth(deep_header_token, MAX_TOKEN_BYTES)
DEEP_PAYLOAD_DEPTH = deepest_depth(DEEP_PAYLOAD_TOKEN, MAX_TOKEN_BYTES)
DEEP_HEADER = deep_header_token(DEEP_HEADER_DEPTH)
DEEP_PAYLOAD = DEEP_PAYLOAD_TOKEN(DEEP_PAYLOAD_DEPTH)
HEADER_OVERFLOWS = defeats_the_json_parser(nested_arrays(DEEP_HEADER_DEPTH))
PAYLOAD_OVERFLOWS = defeats_the_json_parser(nested_arrays(DEEP_PAYLOAD_DEPTH))


def out_of_reach(what: str, depth: int) -> str:
    """Why a probe test does not run on this interpreter, in the terms that decide it.

    It reads as "the cap admits nothing this scanner cannot survive", never as "untested":
    the containment is pinned by the two monkeypatched guards below, which run everywhere.
    """
    return (
        f"this interpreter's JSON scanner survives {depth} nested arrays, which is the "
        f"deepest {what} MAX_TOKEN_BYTES ({MAX_TOKEN_BYTES}) admits, so the overflow is "
        f"not reachable under the cap here"
    )


@pytest.mark.anyio
async def test_a_header_the_json_parser_gives_up_on_is_a_malformed_token(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """SA-4, by construction rather than by probe, so it is the same proof on every lane.

    `RecursionError` is a `RuntimeError`, so it sat outside this library's except tuple and
    escaped `verify` entirely - past the `token = ""` scrub, and out to the dispatcher, which
    contains it as the uniform 401 *and logs the whole traceback for it*. An unauthenticated
    request that costs an ERROR record is a log-amplification lever. The real deep-header
    probe below reaches this parser only where the size cap admits a body deeper than the
    interpreter's own ceiling, which is a platform fact; this does not depend on one.
    """
    token = SIGNER.sign(claims())

    with caplog.at_level(logging.ERROR), pytest.MonkeyPatch.context() as patch:
        patch.setattr(jwt, "get_unverified_header", exhausted_parse)
        error, transport = await refused(token)

    assert isinstance(error, InvalidCredential)
    assert transport.calls == 0
    assert leaks(error, token) == ()
    assert caplog.records == []


@pytest.mark.anyio
async def test_a_payload_the_json_parser_gives_up_on_is_a_malformed_token(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The decode half of the same escape, pinned the same way. The fetch count is part of
    the assertion: a key set really was loaded, so this is the payload parse giving up and
    not the header one answering early for it."""
    token = SIGNER.sign(claims())

    with caplog.at_level(logging.ERROR), pytest.MonkeyPatch.context() as patch:
        patch.setattr(jwt, "decode", exhausted_parse)
        error, transport = await refused(token)

    assert isinstance(error, InvalidCredential)
    assert transport.calls == 1
    assert leaks(error, token) == ()
    assert caplog.records == []


def test_the_nesting_probes_are_the_deepest_the_cap_admits() -> None:
    """Prove the instrument before the observation, on every interpreter.

    A probe built past `MAX_TOKEN_BYTES` is refused for its *length* before any parser sees
    it, so it would pass every test below while reaching nothing; a probe short of the cap
    understates what an unauthenticated client may send. One level deeper than each of these
    is over the cap, which is what makes them the deepest reachable and not merely small.
    """
    assert len(DEEP_HEADER) <= MAX_TOKEN_BYTES
    assert len(DEEP_PAYLOAD) <= MAX_TOKEN_BYTES
    assert len(deep_header_token(DEEP_HEADER_DEPTH + 1)) > MAX_TOKEN_BYTES
    assert len(DEEP_PAYLOAD_TOKEN(DEEP_PAYLOAD_DEPTH + 1)) > MAX_TOKEN_BYTES


@pytest.mark.skipif(not HEADER_OVERFLOWS, reason=out_of_reach("header", DEEP_HEADER_DEPTH))
def test_the_header_nesting_probe_really_defeats_this_interpreters_json_parser() -> None:
    """Platform evidence: here the cap admits a header this scanner cannot finish reading.

    Whether it does is an interpreter property and not a library one - the ceiling is
    `sys.getrecursionlimit()` up to 3.11, a compile-time constant on 3.12/3.13 (3 000 on
    Windows, 10 000 elsewhere) and stack headroom on 3.14+ - so where it is out of reach
    this skips with the measured depth rather than asserting a fact that is not true there.
    """
    with pytest.raises(RecursionError):
        jwt.get_unverified_header(DEEP_HEADER)


@pytest.mark.skipif(not PAYLOAD_OVERFLOWS, reason=out_of_reach("payload", DEEP_PAYLOAD_DEPTH))
def test_the_payload_nesting_probe_really_defeats_this_interpreters_json_parser() -> None:
    with pytest.raises(RecursionError):
        payload_of(DEEP_PAYLOAD)


@pytest.mark.anyio
async def test_a_header_nested_as_deep_as_the_cap_allows_is_refused_without_a_fetch() -> None:
    """The deepest header an unauthenticated client can send, end to end.

    Where the probe overflows this interpreter, this is SA-4's escape route walked for real;
    where it does not, the scanner returns a list and PyJWT refuses it as "not a json object".
    Both are the same verdict, and asserting the verdict is what makes this true everywhere -
    the `RecursionError` half specifically is owned by the guard above.
    """
    error, transport = await refused(DEEP_HEADER)

    assert isinstance(error, InvalidCredential)
    assert transport.calls == 0
    assert leaks(error, DEEP_HEADER) == ()


@pytest.mark.anyio
async def test_a_payload_nested_as_deep_as_the_cap_allows_is_refused() -> None:
    """The decode half. A payload is parsed only after the signature has verified, so this
    probe is signed by a key the key set really publishes: defence in depth rather than an
    open door, and the identical escape if upstream ever mints one."""
    error, _transport = await refused(DEEP_PAYLOAD)

    assert isinstance(error, InvalidCredential)
    assert leaks(error, DEEP_PAYLOAD) == ()


@pytest.mark.anyio
async def test_the_decode_is_always_made_with_every_guard_turned_on() -> None:
    """The call shape itself, pinned - `algorithms` from configuration and never from the
    token (RFC 8725 2.1), the five required claims spelled out because PyJWT requires none by
    default, and both origins. Every one of these is also asserted behaviourally above; this
    exists so that removing one is a failure *here*, where the reason is legible, rather than
    in whichever behavioural test another guard happens not to cover."""
    captured: dict[str, Any] = {}
    real = jwt.decode

    def spy(token: str, key: Any = None, algorithms: Any = None, **passed: Any) -> Any:
        captured.update({"algorithms": algorithms, **passed})
        return real(token, key=key, algorithms=algorithms, **passed)

    verifier, _transport = build(leeway=30)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(jwt, "decode", spy)
        await verifier.verify(SIGNER.sign(claims()), User)

    assert captured["algorithms"] == ["EdDSA"]
    assert captured["issuer"] == ORIGIN
    assert captured["audience"] == ORIGIN
    assert captured["leeway"] == 30.0
    assert set(captured["options"]["require"]) == {"exp", "iat", "iss", "aud", "sub"}


@pytest.mark.anyio
async def test_a_payload_that_is_not_an_object_is_refused() -> None:
    head = b64url(b'{"alg":"EdDSA","kid":"wp5-1"}')
    body = b64url(b'"not an object"')
    error, _transport = await refused(f"{head}.{body}.{b64url(b'sig')}")

    assert isinstance(error, InvalidCredential)


@pytest.mark.anyio
async def test_a_payload_the_user_model_rejects_is_a_credential_failure() -> None:
    """A `ValidationError` escaping a verifier is a 500 that echoes the payload back."""
    token = SIGNER.sign(claims(email="e" * 400))

    error, _transport = await refused(token)

    assert isinstance(error, InvalidCredential)
    assert "e" * 400 not in error.reason


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


# --- what a reason may carry --------------------------------------------------------------


@pytest.mark.anyio
async def test_no_refusal_carries_any_part_of_the_credential() -> None:
    """Error reporters serialize exception attributes; a token in a reason is a token in a
    third-party store, replayable for as long as it lives."""
    verifier, _transport = build()
    tokens = [
        SIGNER.sign(claims(sub=ABSENT)),
        OTHER.sign(claims()),
        tampered(SIGNER.sign(claims())),
        SIGNER.sign(claims(issuer=OTHER_ORIGIN)),
        SIGNER.sign(claims(issued_at=int(time.time()) - 2000)),
        ed25519_signer("never-published").sign(claims()),
    ]

    for token in tokens:
        with pytest.raises(SessionError) as caught:
            await verifier.verify(token, User)
        assert leaks(caught.value, token) == (), f"a refusal carried part of {token[:12]}..."


@pytest.mark.anyio
async def test_every_refusal_still_tells_an_operator_something() -> None:
    """The other half: a uniform reason would make the whole taxonomy useless in a log."""
    reasons = {
        (await refused(OTHER.sign(claims())))[0].reason,
        (await refused(SIGNER.sign(claims(sub=ABSENT))))[0].reason,
        (await refused(ed25519_signer("never-published").sign(claims())))[0].reason,
        (await refused(SIGNER.sign(claims()), TimeoutError("down")))[0].reason,
    }

    assert len(reasons) == 4
    assert all(reason.strip() for reason in reasons)


LEAK_MARKER = "leaky-credential-9f3ab21c"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("credential", "needle"),
    [
        (LEAK_MARKER + "x" * 9000, LEAK_MARKER),
        (LEAK_MARKER + "-carries-no-dots", LEAK_MARKER),
        ((LEAK_MARKER + "-in-bytes").encode(), LEAK_MARKER),
        (None, None),
    ],
    ids=["over-cap", "wrong-dots", "not-a-string", "deep-path"],
)
async def test_no_raw_credential_survives_in_a_library_frame(
    credential: object, needle: str | None
) -> None:
    """The frame-locals channel, which the reason rules do not cover: a reporter captures
    every frame in the traceback, and this library's frames are the ones it blames us for.

    B1 reopened it on the three *early* refusals — over the size cap, wrong dot count, not a
    string at all — whose own frame held the raw credential while the deep path (a wrong-key
    token) had already been scrubbed. Every shape is driven here, and each must fail before
    the fix.
    """
    verifier, _transport = build()
    if credential is None:
        credential = OTHER.sign(claims())  # the deep path: passes the shape checks, fails at decode

    with pytest.raises(SessionError) as caught:
        await verifier.verify(credential, User)  # pyright: ignore[reportArgumentType]

    rendered = " ".join(repr(frame.f_locals) for frame in _library_frames(caught.value))

    assert rendered, "no library frame was captured; retune this probe"
    if needle is not None:
        assert needle not in rendered
        return
    assert isinstance(credential, str)
    assert credential not in rendered
    assert credential.split(".")[2] not in rendered


def _library_frames(error: BaseException) -> list[Any]:
    frames: list[Any] = []
    traceback = error.__traceback__
    while traceback is not None:
        if "fastapi_better_auth" in traceback.tb_frame.f_code.co_filename:
            frames.append(traceback.tb_frame)
        traceback = traceback.tb_next
    return frames


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
