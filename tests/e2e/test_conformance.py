"""Conformance: the wire-format invariants the library depends on, checked against a real,
version-pinned Better Auth server. If upstream changes any of these, this lane fails first."""

import base64
import hashlib
import hmac
import json
import urllib.parse

import httpx
import pytest

from .conftest import SESSION_COOKIE

pytestmark = pytest.mark.e2e


def _split(raw_cookie: str) -> tuple[str, str]:
    decoded = urllib.parse.unquote(raw_cookie)
    token, sep, sig = decoded.rpartition(".")
    assert sep == ".", "session cookie value carries no dot separator"
    return token, sig


class TestSessionCookieWireFormat:
    def test_token_is_32_alnum(self, signed_in):
        token, _ = _split(signed_in["cookie"])
        assert len(token) == 32
        assert token.isalnum()

    def test_signature_is_44_char_padded_standard_base64(self, signed_in):
        _, sig = _split(signed_in["cookie"])
        assert len(sig) == 44
        assert sig.endswith("=")
        # Standard alphabet: decodes with the non-url alphabet, exactly 32 HMAC bytes.
        assert len(base64.b64decode(sig, validate=True)) == 32

    def test_signature_is_hmac_sha256_of_token(self, signed_in, secret):
        token, sig = _split(signed_in["cookie"])
        expected = base64.b64encode(hmac.new(secret, token.encode(), hashlib.sha256).digest())
        assert hmac.compare_digest(sig.encode(), expected)


class TestGetSession:
    def test_roundtrip_returns_user_and_matching_token(self, harness, signed_in):
        resp = httpx.get(
            f"{harness}/api/auth/get-session",
            cookies={SESSION_COOKIE: signed_in["cookie"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        token, _ = _split(signed_in["cookie"])
        assert body["session"]["token"] == token
        assert "@" in body["user"]["email"]

    def test_anonymous_is_200_with_null_body_not_401(self, harness):
        resp = httpx.get(f"{harness}/api/auth/get-session")
        assert resp.status_code == 200
        assert json.loads(resp.text) is None

    def test_tampered_signature_yields_null_session(self, harness, signed_in):
        token, sig = _split(signed_in["cookie"])
        flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
        tampered = urllib.parse.quote(f"{token}.{flipped}")
        resp = httpx.get(
            f"{harness}/api/auth/get-session",
            cookies={SESSION_COOKIE: tampered},
        )
        assert resp.status_code == 200
        assert json.loads(resp.text) is None


class TestJwtPlugin:
    def test_token_endpoint_issues_eddsa_jwt_with_15min_exp(self, harness, signed_in):
        resp = httpx.get(
            f"{harness}/api/auth/token",
            cookies={SESSION_COOKIE: signed_in["cookie"]},
        )
        assert resp.status_code == 200
        token = resp.json()["token"]
        head, payload, _sig = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(head + "=="))
        claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
        assert header["alg"] == "EdDSA"
        assert header["kid"]
        assert claims["iss"] == harness
        assert claims["aud"] == harness
        assert claims["exp"] - claims["iat"] == 900

    def test_jwks_emits_alg_and_never_use(self, harness):
        resp = httpx.get(f"{harness}/api/auth/jwks")
        assert resp.status_code == 200
        keys = resp.json()["keys"]
        assert keys
        for key in keys:
            assert key["alg"] == "EdDSA"
            assert key["crv"] == "Ed25519"
            assert key["kty"] == "OKP"
            assert "use" not in key
