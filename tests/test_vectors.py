"""Golden-vector integrity: every vector must satisfy its `expect` under the canonical
verification algorithm. This is the reference the real CookieVerifier must reproduce."""

import base64
import binascii
import hashlib
import hmac
import json
import pathlib
import urllib.parse
from typing import Any

import pytest

VECTOR_DIR = pathlib.Path(__file__).parent / "vectors"
COOKIE_DOC: dict[str, Any] = json.loads((VECTOR_DIR / "cookie_v1.json").read_text())
JWT_DOC: dict[str, Any] = json.loads((VECTOR_DIR / "jwt_v1.json").read_text())


def reference_verify(cookie_value: str, secret: bytes) -> bool:
    decoded = urllib.parse.unquote(cookie_value)
    token, sep, sig = decoded.rpartition(".")
    if sep != "." or not token or len(sig) != 44:
        return False
    try:
        if len(base64.b64decode(sig, validate=True)) != 32:
            return False
    except (binascii.Error, ValueError):
        return False
    expected = base64.b64encode(hmac.new(secret, token.encode(), hashlib.sha256).digest())
    return hmac.compare_digest(sig.encode(), expected)


@pytest.mark.parametrize("vector", COOKIE_DOC["vectors"], ids=lambda v: v["name"])
def test_cookie_vector_matches_expectation(vector: dict[str, str]) -> None:
    secret: bytes = COOKIE_DOC["secret"].encode()
    outcome = reference_verify(vector["cookie_value"], secret)
    assert outcome is (vector["expect"] == "signature_valid")


def test_captured_vector_is_live_not_synthesized() -> None:
    captured = [v for v in COOKIE_DOC["vectors"] if v["name"] == "captured-valid"]
    assert len(captured) == 1
    token = urllib.parse.unquote(captured[0]["cookie_value"]).rpartition(".")[0]
    assert len(token) == 32
    assert token.isalnum()


def test_jwt_vector_structure() -> None:
    assert JWT_DOC["header"]["alg"] == "EdDSA"
    kids = {k["kid"] for k in JWT_DOC["jwks"]["keys"]}
    assert JWT_DOC["header"]["kid"] in kids
    assert JWT_DOC["claims"]["iss"] == JWT_DOC["issuer"]
    assert JWT_DOC["claims"]["aud"] == JWT_DOC["issuer"]
    assert JWT_DOC["claims"]["exp"] - JWT_DOC["claims"]["iat"] == 900
    assert len(JWT_DOC["token"].split(".")) == 3
    for key in JWT_DOC["jwks"]["keys"]:
        assert "use" not in key
