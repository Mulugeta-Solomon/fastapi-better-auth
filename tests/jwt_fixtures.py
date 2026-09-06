"""Shared fixtures for the Mode B suites: the signers, `build()`/`refused()`, and `leaks()`.

Mode B, claim by claim: what verifies, what is refused, and what is refused for free. The
accepted case is the real token from `tests/vectors/jwt_v1.json` - better-auth 1.7.1, an EdDSA
signature, the key set that goes with it. Every other case is that token with one thing wrong,
minted locally because a vector cannot ship a token signed by the wrong key without shipping the
wrong key. The cases are split by what they prove:

* `test_jwt_verifier.py` - construction, `extract`, the golden vector, the identity, the key set;
* `test_jwt_verifier_refusals.py` - the accepted case minted, and every negative one edit away;
* `test_jwt_verifier_hygiene.py` - a token the JSON parser cannot survive, and what a refusal may
  carry.

Two properties are asserted over and over and are worth naming once. **Nothing about the
credential reaches a `reason`** - not the token, not its signature, not a `kid` an attacker
chose - because a reason is what error reporters serialize; `leaks()` is how every suite checks
it. And **a refusal that can be decided locally never becomes a network call**: an algorithm
outside the allowlist, a missing `kid`, a token that is not a token are all refused with the
transport untouched, which is both the cheap answer and the one that gives an attacker no way to
make this process fetch; `refused()` hands the transport back so every case can count.

Split out of `test_jwt_verifier.py` the way `tests/jwks_fixtures.py` came out of the JWKS suite:
one builder the three suites share rather than three that could drift.
"""

from __future__ import annotations

from typing import Any

import pytest

from fastapi_better_auth import SessionError, User
from fastapi_better_auth._internal.jwt_verifier import JwtVerifier
from tests.tokens import ORIGIN, ed25519_signer, key_set
from tests.transports import Reply, ScriptedTransport, json_reply

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
