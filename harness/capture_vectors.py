"""Capture golden vectors from the live harness into tests/vectors/.

Run: uv run python harness/capture_vectors.py  (harness must be up)
Positive vectors are captured from the real server; negatives are synthesized from them so the
corpus stays internally consistent. Regenerating rewrites the files; review the diff.
"""

import base64
import datetime
import hashlib
import hmac
import json
import pathlib
import sys
import urllib.parse

import httpx

HARNESS_URL = "http://localhost:3100"
SECRET = "harness-secret-do-not-use-in-production"
WRONG_SECRET = "wrong-secret-for-negative-vectors"
COOKIE_NAME = "better-auth.session_token"
BETTER_AUTH_VERSION = "1.7.1"
OUT_DIR = pathlib.Path(__file__).resolve().parent.parent / "tests" / "vectors"


def sign(token: str, secret: str) -> str:
    digest = hmac.new(secret.encode(), token.encode(), hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


def encode(token: str, sig: str) -> str:
    return urllib.parse.quote(f"{token}.{sig}")


def capture_cookie() -> str:
    """Sign in until the signature contains a standard-alphabet char ('+' or '/'), so the
    base64url negative vector is guaranteed to differ from the valid signature."""
    for _ in range(30):
        resp = httpx.post(
            f"{HARNESS_URL}/api/auth/sign-in/email",
            json={"email": "seed@example.com", "password": "seed-password-123"},
        )
        resp.raise_for_status()
        raw = resp.cookies.get(COOKIE_NAME)
        if raw is None:
            raise RuntimeError("sign-in returned no session cookie")
        sig = urllib.parse.unquote(raw).rpartition(".")[2]
        if "+" in sig or "/" in sig:
            return raw
    raise RuntimeError("no signature with '+' or '/' after 30 sign-ins")


def build_cookie_vectors(raw: str) -> dict:
    decoded = urllib.parse.unquote(raw)
    token, _, sig = decoded.rpartition(".")
    assert sign(token, SECRET) == sig, "captured cookie does not verify — wrong harness secret?"
    dotted_token = f"prefix.{token}"
    other_token = token[::-1]

    def v(name, value, expect, note, secret=None):
        return {
            "name": name,
            "cookie_value": value,
            "expect": expect,
            "note": note,
            **({"secret": secret} if secret else {}),
        }

    vectors = [
        v("captured-valid", raw, "signature_valid", "as issued by the live server (URL-encoded)"),
        v(
            "wrong-secret",
            encode(token, sign(token, WRONG_SECRET)),
            "signature_invalid",
            "HMAC computed with a different secret",
            secret=None,
        ),
        v("truncated-sig", encode(token, sig[:-1]), "signature_invalid", "43 chars — one short"),
        v("overlong-sig", encode(token, sig + "A"), "signature_invalid", "45 chars — one long"),
        v(
            "base64url-nopad-sig",
            encode(token, base64.urlsafe_b64encode(base64.b64decode(sig)).decode().rstrip("=")),
            "signature_invalid",
            "same HMAC bytes, base64url no-pad — catches verifiers using the wrong alphabet",
        ),
        v("empty-sig", encode(token, ""), "signature_invalid", "token with trailing dot"),
        v("no-dot", urllib.parse.quote(token), "signature_invalid", "bare token, no signature"),
        v(
            "empty-token",
            encode("", sign("", SECRET)),
            "signature_invalid",
            "valid HMAC over the empty string — verifiers must reject empty tokens before comparing",
        ),
        v(
            "swapped-sig",
            encode(token, sign(other_token, SECRET)),
            "signature_invalid",
            "valid signature of a different token",
        ),
        v(
            "dotted-token-valid",
            encode(dotted_token, sign(dotted_token, SECRET)),
            "signature_valid",
            "token containing a dot, correctly signed — catches first-dot splits (must split at LAST dot)",
        ),
        v(
            "double-urlencoded",
            urllib.parse.quote(raw),
            "signature_invalid",
            "URL-encoded twice — a single unquote must not resolve it",
        ),
    ]
    return {
        "schema": "cookie-signature-vectors/1",
        "captured_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "better_auth_version": BETTER_AUTH_VERSION,
        "cookie_name": COOKIE_NAME,
        "secret": SECRET,
        "vectors": vectors,
    }


def build_jwt_vectors(raw_cookie: str) -> dict:
    headers = {"Cookie": f"{COOKIE_NAME}={raw_cookie}"}
    token = httpx.get(f"{HARNESS_URL}/api/auth/token", headers=headers).json()["token"]
    jwks = httpx.get(f"{HARNESS_URL}/api/auth/jwks").json()
    head, payload = (json.loads(base64.urlsafe_b64decode(p + "==")) for p in token.split(".")[:2])
    return {
        "schema": "jwt-vectors/1",
        "captured_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "better_auth_version": BETTER_AUTH_VERSION,
        "issuer": HARNESS_URL,
        "token": token,
        "header": head,
        "claims": payload,
        "jwks": jwks,
    }


def main() -> int:
    raw = capture_cookie()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, doc in (
        ("cookie_v1.json", build_cookie_vectors(raw)),
        ("jwt_v1.json", build_jwt_vectors(raw)),
    ):
        path = OUT_DIR / name
        path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {path.relative_to(OUT_DIR.parent.parent)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
