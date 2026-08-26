"""Conformance: the wire-format invariants the library depends on, checked against a real,
version-pinned Better Auth server. If upstream changes any of these, this lane fails first."""

import base64
import hashlib
import hmac
import json
import pathlib
import subprocess
import urllib.parse

import httpx
import pytest

from .conftest import SEED_EMAIL, SEED_PASSWORD, SESSION_COOKIE

pytestmark = pytest.mark.e2e

COMPOSE_FILE = pathlib.Path(__file__).resolve().parents[2] / "harness" / "docker-compose.yml"


def _harness_sql(sql: str) -> None:
    subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE_FILE),
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            "harness",
            "-d",
            "harness",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            sql,
        ],
        check=True,
        capture_output=True,
    )


def _split(raw_cookie: str) -> tuple[str, str]:
    decoded = urllib.parse.unquote(raw_cookie)
    token, sep, sig = decoded.rpartition(".")
    assert sep == ".", "session cookie value carries no dot separator"
    return token, sig


class TestSessionCookieWireFormat:
    def test_token_is_32_alnum(self, signed_in: dict[str, str]) -> None:
        token, _ = _split(signed_in["cookie"])
        assert len(token) == 32
        assert token.isalnum()

    def test_signature_is_44_char_padded_standard_base64(self, signed_in: dict[str, str]) -> None:
        _, sig = _split(signed_in["cookie"])
        assert len(sig) == 44
        assert sig.endswith("=")
        # Standard alphabet: decodes with the non-url alphabet, exactly 32 HMAC bytes.
        assert len(base64.b64decode(sig, validate=True)) == 32

    def test_signature_is_hmac_sha256_of_token(
        self, signed_in: dict[str, str], secret: bytes
    ) -> None:
        token, sig = _split(signed_in["cookie"])
        expected = base64.b64encode(hmac.new(secret, token.encode(), hashlib.sha256).digest())
        assert hmac.compare_digest(sig.encode(), expected)


class TestGetSession:
    def test_roundtrip_returns_user_and_matching_token(
        self, harness: str, signed_in: dict[str, str]
    ) -> None:
        resp = httpx.get(
            f"{harness}/api/auth/get-session",
            cookies={SESSION_COOKIE: signed_in["cookie"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        token, _ = _split(signed_in["cookie"])
        assert body["session"]["token"] == token
        assert "@" in body["user"]["email"]

    def test_anonymous_is_200_with_null_body_not_401(self, harness: str) -> None:
        resp = httpx.get(f"{harness}/api/auth/get-session")
        assert resp.status_code == 200
        assert json.loads(resp.text) is None

    def test_tampered_signature_yields_null_session(
        self, harness: str, signed_in: dict[str, str]
    ) -> None:
        token, sig = _split(signed_in["cookie"])
        flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
        tampered = urllib.parse.quote(f"{token}.{flipped}")
        resp = httpx.get(
            f"{harness}/api/auth/get-session",
            cookies={SESSION_COOKIE: tampered},
        )
        assert resp.status_code == 200
        assert json.loads(resp.text) is None


class TestExpiry:
    def test_route_layer_rejects_expired_session(self, harness: str) -> None:
        """Documents WHY the library must enforce expiresAt itself in Mode A: upstream's route
        layer rejects expired sessions, but a bare store lookup (findSession) does not check."""
        resp = httpx.post(
            f"{harness}/api/auth/sign-in/email",
            json={"email": SEED_EMAIL, "password": SEED_PASSWORD},
        )
        raw = resp.cookies.get(SESSION_COOKIE)
        assert raw is not None, f"no {SESSION_COOKIE} cookie on sign-in"
        token, _ = _split(raw)
        try:
            _harness_sql(
                f"""UPDATE session SET "expiresAt" = now() - interval '1 hour' WHERE token = '{token}'"""
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            pytest.skip(f"cannot reach harness postgres via docker compose: {exc}")
        r = httpx.get(f"{harness}/api/auth/get-session", cookies={SESSION_COOKIE: raw})
        assert r.status_code == 200
        assert json.loads(r.text) is None


class TestJwtPlugin:
    def test_token_endpoint_issues_eddsa_jwt_with_15min_exp(
        self, harness: str, signed_in: dict[str, str]
    ) -> None:
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

    def test_jwks_emits_alg_and_never_use(self, harness: str) -> None:
        resp = httpx.get(f"{harness}/api/auth/jwks")
        assert resp.status_code == 200
        keys = resp.json()["keys"]
        assert keys
        for key in keys:
            assert key["alg"] == "EdDSA"
            assert key["crv"] == "Ed25519"
            assert key["kty"] == "OKP"
            assert "use" not in key
