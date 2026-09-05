"""Conformance: the wire-format invariants the library depends on, checked against a real,
version-pinned Better Auth server. If upstream changes any of these, this lane fails first."""

import base64
import hashlib
import hmac
import importlib.util
import json
import logging
import secrets
import string
import urllib.parse

import httpx
import pytest

from .conftest import SEED_EMAIL, SEED_PASSWORD, SESSION_COOKIE, harness_sql

pytestmark = pytest.mark.e2e

# Mode C landed after 0.1.0, and this module is the lane's floor: it must IMPORT cleanly on the
# oldest published wheel, so the two probe legs below resolve the name at call time and skip.
MODE_C = importlib.util.find_spec("fastapi_better_auth._internal.remote_probe") is not None
needs_mode_c = pytest.mark.skipif(
    not MODE_C, reason="this build of fastapi-better-auth-bridge publishes no remote mode"
)

BEARER_TOKEN_LENGTH = 32
MAX_SESSION_BYTES = 64 * 1024


def _manufactured_bearer() -> str:
    """A dot-less token that exists in no database - never a real credential, never replayed."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(BEARER_TOKEN_LENGTH))


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
        harness_sql(
            f"""UPDATE session SET "expiresAt" = now() - interval '1 hour' WHERE token = '{token}'"""
        )
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


class TestBearerPosture:
    """`bearer({ requireSignature })`, measured in both directions against two live servers.

    The default is `false`, and what that means is the hazard this library documents: upstream
    self-signs a *raw* session token presented as a bearer, so a token in a log, a dump or a
    backup is a credential. `:3102` runs the same image with `requireSignature: true`, so the
    claim "the one-line fix upstream is `bearer({ requireSignature: true })`" is a tested fact
    rather than a reading of the source.

    Each server is only ever shown a credential it issued itself.
    """

    def test_the_default_posture_answers_a_raw_session_token_with_that_session(
        self, harness: str, signed_in: dict[str, str]
    ) -> None:
        token, _ = _split(signed_in["cookie"])

        resp = httpx.get(
            f"{harness}/api/auth/get-session", headers={"Authorization": f"Bearer {token}"}
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body is not None, "the default posture self-signs a raw token into a session"
        assert body["session"]["token"] == token

    def test_the_strict_posture_answers_the_same_raw_session_token_with_null(
        self, strict_harness: str
    ) -> None:
        signed_in = httpx.post(
            f"{strict_harness}/api/auth/sign-in/email",
            json={"email": SEED_EMAIL, "password": SEED_PASSWORD},
        )
        raw = signed_in.cookies.get(SESSION_COOKIE)
        assert raw is not None, f"no {SESSION_COOKIE} cookie on sign-in"
        token, _ = _split(raw)
        # The anti-vacuum control: this token is live on this very server, through its cookie.
        alive = httpx.get(f"{strict_harness}/api/auth/get-session", cookies={SESSION_COOKIE: raw})
        assert alive.json()["session"]["token"] == token

        resp = httpx.get(
            f"{strict_harness}/api/auth/get-session", headers={"Authorization": f"Bearer {token}"}
        )

        assert resp.status_code == 200
        assert json.loads(resp.text) is None, "requireSignature: true ignores a dot-less bearer"

    def test_a_manufactured_bearer_sets_a_cookie_only_in_the_default_posture(
        self, harness: str, strict_harness: str
    ) -> None:
        """The discriminator the advisory probe reads, on the wire and in both postures.

        A token that exists in no database is `200 null` either way, so the body cannot tell the
        postures apart. `Set-Cookie` can: the permissive posture self-signs the manufactured token,
        installs it as the session cookie, fails to find the session, and clears the cookie again;
        the strict posture ignores the header and never touches a cookie. Only the header's
        *presence* is read here, exactly as the probe reads it.
        """
        header = {"Authorization": f"Bearer {_manufactured_bearer()}"}

        permissive = httpx.get(f"{harness}/api/auth/get-session", headers=header)
        strict = httpx.get(f"{strict_harness}/api/auth/get-session", headers=header)

        assert permissive.status_code == 200
        assert json.loads(permissive.text) is None
        assert "set-cookie" in permissive.headers
        assert strict.status_code == 200
        assert json.loads(strict.text) is None
        assert "set-cookie" not in strict.headers
        # And the strict server does emit Set-Cookie when it has one to emit, so its absence
        # above is the posture and not a server that never sets cookies at all.
        signed_in = httpx.post(
            f"{strict_harness}/api/auth/sign-in/email",
            json={"email": SEED_EMAIL, "password": SEED_PASSWORD},
        )
        assert "set-cookie" in signed_in.headers


class TestRequireSignatureAdvisory:
    """The library's advisory probe against both postures - ruling 8's discriminator, live.

    The probe never refuses and never replays a real credential: its bearer is manufactured here
    and exists in no database. What it may do is warn, once per process, and these two legs pin
    both halves of that: it fires against the permissive server and stays silent against the
    strict one. The `Once` latch is replaced per test, so each observation is genuinely its own.
    """

    def uri(self, base: str) -> str:
        return f"{base}/api/auth/get-session?disableCookieCache=true&disableRefresh=true"

    def advisories(self, caplog: pytest.LogCaptureFixture) -> list[str]:
        return [
            record.getMessage()
            for record in caplog.records
            if "requireSignature" in record.getMessage()
        ]

    @needs_mode_c
    @pytest.mark.anyio
    async def test_it_warns_exactly_once_against_the_default_posture(
        self,
        harness: str,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from fastapi_better_auth import HttpxTransport
        from fastapi_better_auth._internal import remote_probe
        from fastapi_better_auth._internal.once import Once

        monkeypatch.setattr(remote_probe, "_advised", Once())

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            async with HttpxTransport() as transport:
                for _ in range(2):
                    await remote_probe.run_probe(
                        transport, uri=self.uri(harness), max_bytes=MAX_SESSION_BYTES
                    )

        fired = self.advisories(caplog)
        assert len(fired) == 1, f"one warning per process, not {len(fired)}"
        assert "bearer({ requireSignature: true })" in fired[0]

    @needs_mode_c
    @pytest.mark.anyio
    async def test_it_stays_silent_against_the_strict_posture(
        self,
        harness: str,
        strict_harness: str,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from fastapi_better_auth import HttpxTransport
        from fastapi_better_auth._internal import remote_probe
        from fastapi_better_auth._internal.once import Once

        monkeypatch.setattr(remote_probe, "_advised", Once())

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            async with HttpxTransport() as transport:
                await remote_probe.run_probe(
                    transport, uri=self.uri(strict_harness), max_bytes=MAX_SESSION_BYTES
                )
                silent = self.advisories(caplog)
                # The same un-fired latch, pointed at the permissive server: the instrument is
                # live, so the silence above is the posture and not a broken probe.
                await remote_probe.run_probe(
                    transport, uri=self.uri(harness), max_bytes=MAX_SESSION_BYTES
                )

        assert silent == []
        assert len(self.advisories(caplog)) == 1
