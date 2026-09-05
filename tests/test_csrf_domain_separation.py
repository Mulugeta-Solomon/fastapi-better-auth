"""D4: the SignedDoubleSubmit CSRF token is domain-separated from the cookie signature (SA-D4).

`_digest` used to be `HMAC(secret, token)` - byte-identical to the session cookie's own signature
over the same secret, so the CSRF token the frontend holds equalled a piece of the credential.
The library owns both sides, so the CSRF HMAC now carries a domain label (`fba-csrf-v1:`). The
token the frontend fetches from its own route round-trips with the labelled digest; a token minted
the old, unlabelled way is refused; and the CSRF token can no longer equal the cookie signature.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

import pytest

from fastapi_better_auth import CsrfFailure, SharedSecret, SignedDoubleSubmit
from fastapi_better_auth._internal.csrf import CSRF_DOMAIN_LABEL, CsrfFacts

SECRET_VALUE = "Qb8Xm2vTz6Lp1RkYd9Wn4Hs7Cj3Fg5Ae"
SECRET = SharedSecret(SECRET_VALUE)
APP = "https://app.example.com"
SESSION_TOKEN = "SBYZ1bzGdkhXcLuqsW70JjhvmIY4PU3B"


def policy() -> SignedDoubleSubmit:
    return SignedDoubleSubmit(secret=SECRET, allowed_origins=[APP])


def unsafe_facts(header_value: str) -> CsrfFacts:
    """An unsafe (POST) request from the allowed origin carrying the csrf header."""
    return CsrfFacts(
        method="POST",
        origin=APP,
        origin_count=1,
        header_name="x-csrf-token",
        header_value=header_value,
    )


def old_unlabelled_token(session_token: str) -> str:
    """The pre-D4 digest: HMAC(secret, token) with no domain label - the cookie signature shape."""
    return hmac.new(
        SECRET_VALUE.encode("utf-8"), session_token.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def cookie_signature(session_token: str) -> str:
    """The session cookie's own signature: standard-base64(HMAC(secret, token))."""
    digest = hmac.new(SECRET_VALUE.encode("utf-8"), session_token.encode("utf-8"), hashlib.sha256)
    return base64.b64encode(digest.digest()).decode()


class TestDomainSeparation:
    def test_the_new_token_round_trips(self) -> None:
        """token_for and check use the same labelled digest, so a freshly minted token passes."""
        built = policy()
        token = built.token_for(SESSION_TOKEN)

        built.check(unsafe_facts(token), SESSION_TOKEN)  # returns None on allow, raises on refuse

    def test_a_token_minted_the_old_unlabelled_way_is_refused(self) -> None:
        """The wire changed: an unlabelled HMAC (the old CSRF token, and the cookie signature's
        own bytes) no longer validates."""
        built = policy()

        with pytest.raises(CsrfFailure):
            built.check(unsafe_facts(old_unlabelled_token(SESSION_TOKEN)), SESSION_TOKEN)

    def test_the_csrf_token_is_not_the_cookie_signature(self) -> None:
        """The whole point of D4: the value the frontend holds is not a piece of the credential."""
        csrf_token = policy().token_for(SESSION_TOKEN)

        assert csrf_token != old_unlabelled_token(SESSION_TOKEN)
        assert csrf_token != cookie_signature(SESSION_TOKEN)
        # And not merely a re-encoding of the same digest bytes.
        assert bytes.fromhex(csrf_token) != base64.b64decode(cookie_signature(SESSION_TOKEN))

    def test_the_digest_carries_the_documented_label(self) -> None:
        """Pin the exact wire so a silent relabel is a red test, not an interop surprise."""
        expected = hmac.new(
            SECRET_VALUE.encode("utf-8"),
            CSRF_DOMAIN_LABEL + SESSION_TOKEN.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        assert policy().token_for(SESSION_TOKEN) == expected
        assert CSRF_DOMAIN_LABEL == b"fba-csrf-v1:"

    def test_the_token_still_does_not_transfer_between_sessions(self) -> None:
        """The binding property is unchanged: a token for one session fails for another."""
        built = policy()
        other_session = "different-session-token-000000000"
        minted_for_other = built.token_for(other_session)

        with pytest.raises(CsrfFailure):
            built.check(unsafe_facts(minted_for_other), SESSION_TOKEN)
