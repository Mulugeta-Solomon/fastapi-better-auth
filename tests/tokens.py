"""Keys, key sets and tokens for the JWT lane — the real vector, and everything it cannot say.

`tests/vectors/jwt_v1.json` is one honest token captured from better-auth 1.7.1 together with
the key set that verifies it. It is the ground truth for what an *accepted* token looks like,
and it is the only thing here that was not minted locally.

Every *rejected* shape has to be minted, because a golden vector cannot carry one: a token
signed by the wrong key is only a proof if the wrong key ships with it, and a vector that
shipped a private key would be a vector that verified nothing. So this module owns a small
forge — an Ed25519 signer to mirror upstream, plus an EC and an RSA one for the algorithm
confusion cases — and every negative test is the happy path with exactly one edit.

The clock is here too: the captured token expired fifteen minutes after it was captured, so
the only way to verify the real thing is to move the clock PyJWT reads back to the moment it
was live. `frozen_at` does that, and `test_jwt_verifier.py` proves the instrument by asserting
the same call fails as expired without it.
"""

from __future__ import annotations

import base64
import contextlib
import functools
import json
import pathlib
import time
from collections.abc import Generator, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

VECTOR_PATH = pathlib.Path(__file__).parent / "vectors" / "jwt_v1.json"
VECTOR: dict[str, Any] = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

ORIGIN: str = VECTOR["issuer"]
GOLDEN_TOKEN: str = VECTOR["token"]
GOLDEN_JWKS: dict[str, Any] = VECTOR["jwks"]
GOLDEN_CLAIMS: dict[str, Any] = VECTOR["claims"]
GOLDEN_KID: str = VECTOR["header"]["kid"]

LIFETIME = 900
OTHER_ORIGIN = "https://auth.other.example"
SUBJECT = "cIrUeXmXVG5Kg0Pzt4rCozIxLv3oeOMG"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class Signer:
    """A private key, the JWK its public half publishes, and the `alg` they agree on."""

    kid: str
    algorithm: str
    private: Any
    jwk: Mapping[str, Any]

    def sign(
        self,
        claims: Mapping[str, Any],
        *,
        algorithm: str | None = None,
        headers: Mapping[str, Any] | None = None,
    ) -> str:
        """Mint a token. `algorithm` overrides only the *signing* algorithm; a lie about it
        belongs in `headers`, which is merged over the header PyJWT builds."""
        head: dict[str, Any] = {"kid": self.kid}
        if headers is not None:
            head.update(headers)
        return jwt.encode(
            dict(claims),
            self.private,
            algorithm=self.algorithm if algorithm is None else algorithm,
            headers=head,
        )


def ed25519_signer(kid: str = "ed25519-1") -> Signer:
    """The shape upstream really uses: an OKP/Ed25519 key published exactly as the vector's."""
    private = ed25519.Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    jwk = {"alg": "EdDSA", "crv": "Ed25519", "kid": kid, "kty": "OKP", "x": b64url(raw)}
    return Signer(kid=kid, algorithm="EdDSA", private=private, jwk=jwk)


def ec_signer(kid: str = "es256-1") -> Signer:
    private = ec.generate_private_key(ec.SECP256R1())
    published: dict[str, Any] = dict(ECAlgorithm.to_jwk(private.public_key(), as_dict=True))
    published.update({"alg": "ES256", "kid": kid})
    return Signer(kid=kid, algorithm="ES256", private=private, jwk=published)


@functools.lru_cache(maxsize=1)
def _rsa_key() -> rsa.RSAPrivateKey:
    """Generated once per session: a 2048-bit keygen is the slowest thing in this suite."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def rsa_signer(kid: str = "rs256-1", *, algorithm: str = "RS256") -> Signer:
    private = _rsa_key()
    published: dict[str, Any] = dict(RSAAlgorithm.to_jwk(private.public_key(), as_dict=True))
    published.update({"alg": algorithm, "kid": kid})
    return Signer(kid=kid, algorithm=algorithm, private=private, jwk=published)


def key_set(*signers: Signer, extra: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """The document `/api/auth/jwks` answers with, in upstream's own shape."""
    return {"keys": [dict(signer.jwk) for signer in signers] + [dict(each) for each in extra]}


_ABSENT = object()
ABSENT: Any = _ABSENT
"""Sentinel for `claims(exp=ABSENT)`: a claim that is not in the payload at all."""


def claims(
    *,
    issuer: str = ORIGIN,
    audience: str | None = None,
    subject: str = SUBJECT,
    issued_at: int | None = None,
    lifetime: int = LIFETIME,
    **overrides: Any,
) -> dict[str, Any]:
    """A payload in upstream's shape: the whole user, plus the five required claims.

    `overrides` is applied last, so a test removes a claim with `exp=None` (dropped) or
    replaces one outright. Keeping the default valid is what makes each negative one edit.
    """
    now = int(time.time()) if issued_at is None else issued_at
    payload: dict[str, Any] = {
        "id": subject,
        "sub": subject,
        "name": "Seed User",
        "email": "seed@example.com",
        "emailVerified": False,
        "image": None,
        "createdAt": "2026-08-20T15:34:02.764Z",
        "updatedAt": "2026-08-20T15:34:02.764Z",
        "iat": now,
        "exp": now + lifetime,
        "iss": issuer,
        "aud": issuer if audience is None else audience,
    }
    payload.update(overrides)
    return {key: value for key, value in payload.items() if value is not _ABSENT}


def tampered(token: str, *, part: int = 2) -> str:
    """Flip one character of a token segment — signature by default, payload with `part=1`."""
    segments = token.split(".")
    target = segments[part]
    flipped = ("A" if target[0] != "A" else "B") + target[1:]
    segments[part] = flipped
    return ".".join(segments)


def signed_raw(signer: Signer, header: Mapping[str, Any], payload: Mapping[str, Any]) -> str:
    """A *real* signature over an exact header and an exact payload.

    `jwt.encode` rewrites both on the way past: it prefers a header `alg` over the algorithm
    it actually signs with, and it refuses to encode a null `iss` at all. Neither of those is
    something an attacker's toolchain would do, so the two shapes that matter most - a header
    lying about its algorithm, and a required claim present but null - have to be built here.
    """
    head = b64url(json.dumps(dict(header)).encode())
    body = b64url(json.dumps(dict(payload)).encode())
    algorithm = jwt.get_algorithm_by_name(signer.algorithm)
    signature = algorithm.sign(f"{head}.{body}".encode(), algorithm.prepare_key(signer.private))
    return f"{head}.{body}.{b64url(signature)}"


def forged(
    header: Mapping[str, Any], payload: Mapping[str, Any], *, signature: str = "c2ln"
) -> str:
    """A token assembled by hand: the only way to write a header PyJWT refuses to mint.

    `jwt.encode` validates `kid` before it signs, so an absent or non-string one has to be
    built here. The signature is nonsense on purpose - every token that needs this shape is
    refused before a signature is ever checked, and a test that got that wrong should fail.
    """
    head = b64url(json.dumps(dict(header)).encode())
    body = b64url(json.dumps(dict(payload)).encode())
    return f"{head}.{body}.{signature}"


def unsigned(payload: Mapping[str, Any]) -> str:
    """An `alg: none` token — the attack every JWT library has shipped a bypass for."""
    head = b64url(json.dumps({"alg": "none", "kid": "none-1"}).encode())
    body = b64url(json.dumps(dict(payload)).encode())
    return f"{head}.{body}."


def hmac_signed(payload: Mapping[str, Any], *, secret: str, kid: str) -> str:
    """An HS256 token signed with a *public* value — the key-confusion attack.

    Reaches the verifier only if `HS256` is in the allowlist, which construction refuses;
    this exists to prove the refusal happens before any key is ever loaded.
    """
    return jwt.encode(dict(payload), secret, algorithm="HS256", headers={"kid": kid})


class _FrozenClock:
    """Stands in for PyJWT's module-global `datetime`, which it calls as `datetime.now(tz=)`.

    A `datetime` subclass would be the obvious move and does not type-check: `now()` is
    declared to return `Self`. This carries the one member the claim validator reaches for.
    """

    def __init__(self, instant: datetime) -> None:
        self._instant = instant

    def now(self, tz: Any = None) -> datetime:
        return self._instant if tz is None else self._instant.astimezone(tz)


@contextlib.contextmanager
def frozen_at(epoch_seconds: float) -> Generator[None, None, None]:
    """Move the clock PyJWT validates `exp`/`iat`/`nbf` against to `epoch_seconds`.

    PyJWT reads `datetime.now(tz=timezone.utc).timestamp()` out of its own module globals
    (`jwt.api_jwt`), on 2.10 and on 2.13 alike — verified on both before this was written.
    Signature verification never looks at a clock, so nothing about the cryptography moves.
    """
    module: Any = jwt.api_jwt
    original = module.datetime
    module.datetime = _FrozenClock(datetime.fromtimestamp(epoch_seconds, tz=timezone.utc))
    try:
        yield
    finally:
        module.datetime = original


def inside_the_golden_validity() -> float:
    """A moment the captured token was live: one minute after it was issued."""
    issued: int = GOLDEN_CLAIMS["iat"]
    return float(issued + 60)


class Clock:
    """A hand-wound monotonic clock for the JWKS cache — TTLs are policy, not real waiting."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def payload_of(token: str) -> MutableMapping[str, Any]:
    """The claims a token carries, read without verifying anything."""
    body = token.split(".")[1]
    decoded: dict[str, Any] = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    return decoded
