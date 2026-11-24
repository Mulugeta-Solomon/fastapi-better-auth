"""`exp`, `iat` and `nbf` that are not usable NumericDates, on a token whose signature is good.

RFC 7519 2 defines a NumericDate as a JSON number of seconds. Each case here is the accepted token
with one date claim replaced by something that is not one - a number too large to become a float,
a non-finite one, a bool, a string - and signed for real, so it reaches every check past the
signature. Every one of them must be an ordinary credential refusal: a `SessionError`, the uniform
401, nothing logged at ERROR. Not an exception the dispatcher has to contain as an accident (that
is a 401 too, but with a traceback in the log for a token anyone can mint against a key they do not
hold - and here, for a token the issuer itself signed), and never an accepted session.

Two different checks see these claims. PyJWT validates `exp`, `iat` and `nbf` itself, converting
each with `int()`; this library then reads `iat` and `exp` again for the lifetime ceiling. A value
PyJWT's `int()` survives but `float()` does not - an integer past the float range - used to escape
the second check as a raw `OverflowError`. `nbf` was never read here at all, so whatever PyJWT's
`int()` accepted (`true`, `"1"`, an integer past the float range) was accepted.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import NoReturn

import jwt
import pytest

from fastapi_better_auth import (
    BetterAuth,
    InvalidCredential,
    JwtVerifier,
    Session,
    SessionExpired,
    User,
)
from fastapi_better_auth._internal.jwt_verifier import MAX_TOKEN_BYTES
from tests.fakes import client, session_app
from tests.jwt_fixtures import KEY_SET, SIGNER, build, refused
from tests.tokens import ORIGIN, b64url, claims
from tests.transports import ScriptedTransport, json_reply

BEYOND_FLOAT = 10**400
"""An integer `int()` handles and `float()` cannot: past the largest double, about 1.8e308."""
PLACEHOLDER = "__wp40_literal__"


def _signed(claim: str, literal: str) -> str:
    """A real EdDSA signature over the accepted payload with `claim` set to raw JSON `literal`.

    Spliced in as text rather than through `json.dumps`, so the token carries exactly the
    literal - an integer longer than CPython's int/str digit limit included, which `json.dumps`
    itself would refuse to write.
    """
    head = b64url(json.dumps({"alg": "EdDSA", "kid": SIGNER.kid, "typ": "JWT"}).encode())
    payload = {**claims(), claim: PLACEHOLDER}
    body = b64url(json.dumps(payload).replace(f'"{PLACEHOLDER}"', literal).encode())
    signature = SIGNER.private.sign(f"{head}.{body}".encode())
    return f"{head}.{body}.{b64url(signature)}"


ODD_DATES: tuple[tuple[str, str, str], ...] = (
    ("exp-beyond-float", "exp", str(BEYOND_FLOAT)),
    ("exp-infinity", "exp", "Infinity"),
    ("exp-negative-infinity", "exp", "-Infinity"),
    ("exp-nan", "exp", "NaN"),
    ("exp-string", "exp", '"4102444800"'),
    ("exp-null", "exp", "null"),
    ("iat-beyond-float", "iat", str(-BEYOND_FLOAT)),
    ("iat-far-future", "iat", str(BEYOND_FLOAT)),
    ("iat-infinity", "iat", "Infinity"),
    ("iat-negative-infinity", "iat", "-Infinity"),
    ("iat-nan", "iat", "NaN"),
    ("iat-true", "iat", "true"),
    ("iat-string", "iat", '"1"'),
    ("nbf-beyond-float", "nbf", str(-BEYOND_FLOAT)),
    ("nbf-far-future", "nbf", str(BEYOND_FLOAT)),
    ("nbf-infinity", "nbf", "Infinity"),
    ("nbf-negative-infinity", "nbf", "-Infinity"),
    ("nbf-nan", "nbf", "NaN"),
    ("nbf-true", "nbf", "true"),
    ("nbf-false", "nbf", "false"),
    ("nbf-string", "nbf", '"1"'),
    ("nbf-null", "nbf", "null"),
    ("nbf-object", "nbf", "{}"),
)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("label", "claim", "literal"), ODD_DATES, ids=[name for name, _, _ in ODD_DATES]
)
async def test_a_date_claim_that_is_not_a_usable_number_is_a_credential_refusal(
    label: str, claim: str, literal: str
) -> None:
    """F4.4. RED before the fix: `exp`/`iat` past the float range escaped as `OverflowError`
    from the lifetime check, and a non-numeric or unrepresentable `nbf` verified."""
    error, _transport = await refused(_signed(claim, literal))

    assert isinstance(error, InvalidCredential), f"{label}: {type(error).__name__}"
    assert error.status_code == 401


@pytest.mark.anyio
async def test_an_exp_of_true_is_refused_though_pyjwt_calls_it_expired() -> None:
    """`true` is not a time. PyJWT converts it with `int()` to 1 - the first second of 1970 -
    and reports the token expired before this library sees the claims, so the refusal is a
    `SessionExpired` rather than an `InvalidCredential`. Both are the uniform 401; pinned so
    the classification is a known fact rather than a surprise."""
    error, _transport = await refused(_signed("exp", "true"))

    assert isinstance(error, SessionExpired)
    assert error.status_code == 401


def _overflowing_decode(*_arguments: object, **_keywords: object) -> NoReturn:
    raise OverflowError("int too large to convert")


@pytest.mark.anyio
async def test_an_overflow_inside_pyjwt_is_a_credential_refusal_whatever_its_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """By construction, so it holds on every PyJWT the floor admits. PyJWT 2.15.1 catches the
    `OverflowError` its own `int()` raises on `Infinity` and answers `DecodeError`; a version
    that does not would let it escape `verify` as an accident. RED before `OverflowError` was in
    the decode's except tuple: the patched decode's exception escaped as itself."""
    monkeypatch.setattr(jwt, "decode", _overflowing_decode)

    error, _transport = await refused(SIGNER.sign(claims()))

    assert isinstance(error, InvalidCredential)
    assert error.__context__ is None and error.__cause__ is None


@pytest.mark.anyio
async def test_an_integer_past_the_digit_limit_is_a_credential_refusal() -> None:
    """CPython refuses to parse an integer literal over `sys.get_int_max_str_digits()` digits
    (4300 by default) with a `ValueError`. The token still fits the size cap, so it is a real
    probe of the parse, which runs with the limit in force as it does in production."""
    limit = sys.get_int_max_str_digits()
    assert limit, "the int/str digit limit is switched off; this probe would prove nothing"
    token = _signed("exp", "9" * (limit + 1))
    assert len(token) <= MAX_TOKEN_BYTES, "over the size cap, the parse is never reached"

    error, _transport = await refused(token)

    assert isinstance(error, InvalidCredential)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("claim", "offset"),
    [("nbf", -60.5), ("nbf", -1), ("exp", 600.25)],
    ids=["nbf-float-in-the-past", "nbf-int-in-the-past", "exp-float"],
)
async def test_a_numeric_date_with_a_fraction_or_an_nbf_in_the_past_still_verifies(
    claim: str, offset: float
) -> None:
    """The over-refusal half: RFC 7519 lets a NumericDate carry a fraction, and an `nbf` that
    has passed is the ordinary case."""
    issued = claims()["iat"]
    verifier, _transport = build()

    session = await verifier.verify(_signed(claim, repr(issued + offset)), User)

    assert isinstance(session, Session)


def test_an_unrepresentable_exp_is_the_uniform_401_with_nothing_logged_at_error(
    client_backend: str, caplog: pytest.LogCaptureFixture
) -> None:
    """On the wire: a refusal, not a contained accident. The dispatcher contains an exception
    escaping a verifier as a 401 too, but logs it at ERROR with its traceback - which is what
    separated this token from every other bad credential before the fix."""
    transport = ScriptedTransport(json_reply(KEY_SET))
    auth = BetterAuth(verifiers=[JwtVerifier(base_url=ORIGIN, transport=transport)])
    token = _signed("exp", str(BEYOND_FLOAT))

    with caplog.at_level(logging.ERROR), client(session_app(auth), client_backend) as driver:
        response = driver.get("/required", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert [record for record in caplog.records if record.levelno >= logging.ERROR] == []
