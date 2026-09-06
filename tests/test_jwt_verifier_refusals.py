"""Mode B, claim by claim: the accepted case, minted, and every negative one edit away from it.

Signature and algorithm (the substituted key, the lying header, the key-confusion attack), the
`crit` header, the `kid`, the five required claims, time and the lifetime ceiling, the shape of
the credential itself, and the decode call pinned with every guard turned on. Most of these are
also refused for free - with the transport untouched - and `refused()` hands the transport back
so each case can say so. The golden vector and construction are `test_jwt_verifier.py`; what a
hostile token cannot do to the process is `test_jwt_verifier_hygiene.py`; the builders are
`tests/jwt_fixtures.py`.
"""

from __future__ import annotations

import time
from typing import Any

import jwt
import pytest

from fastapi_better_auth import InvalidCredential, SessionExpired, User
from fastapi_better_auth._internal.reasons import fingerprint
from tests.jwt_fixtures import KEY_SET, OTHER, SIGNER, build, leaks, refused
from tests.tokens import (
    ABSENT,
    LIFETIME,
    ORIGIN,
    OTHER_ORIGIN,
    SUBJECT,
    b64url,
    claims,
    ec_signer,
    ed25519_signer,
    forged,
    hmac_signed,
    key_set,
    rsa_signer,
    signed_raw,
    tampered,
    unsigned,
)
from tests.transports import json_reply

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
