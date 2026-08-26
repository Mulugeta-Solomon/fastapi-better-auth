"""Mode B: a Better Auth JWT, verified against the key set its own server publishes."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any, TypeVar, cast

import jwt
from starlette.requests import HTTPConnection

from .errors import ConfigurationError, InvalidCredential, SessionExpired
from .httpx_transports import HttpxTransport
from .jwks import CACHE_TTL, SUPPORTED_ALGORITHMS, Jwk, JwksClient
from .models import Session, User
from .parsing import parse_user
from .reasons import fingerprint, safe_label
from .transport import Transport
from .urls import normalize_base_url

UserModelT = TypeVar("UserModelT", bound=User)

CREDENTIAL_SOURCE = "authorization-bearer"
DEFAULT_ALGORITHMS: tuple[str, ...] = ("EdDSA",)
REQUIRED_CLAIMS: tuple[str, ...] = ("exp", "iat", "iss", "aud", "sub")
SCHEME = "bearer"

DEFAULT_LIFETIME = 900.0
MAX_LEEWAY = 60.0
MAX_LIFETIME = 86400.0
MAX_TOKEN_BYTES = 8192
DOT_SEPARATORS = 2


class JwtVerifier:
    """Verifies the JWT Better Auth's `jwt` plugin issues, against that server's JWKS.

    The mode to reach for when the FastAPI service is a *different* origin from the Better
    Auth server: the client asks upstream for a token, sends it as a bearer credential, and
    this verifier checks it offline against a cached key set. There is no session lookup and
    no call to upstream on the request path - which is the point, and also the limit: a token
    stays valid until it expires, so a sign-out is not visible here until then. Upstream mints
    fifteen-minute tokens, which is what makes that acceptable.

        auth = BetterAuth(verifiers=[JwtVerifier(base_url="https://auth.example.com")])

    **`base_url` is the whole of the trust configuration.** Canonicalized once
    (`normalize_base_url`), it is the required `iss`, the required `aud`, and the origin the
    key set is fetched from - all three, because that is what upstream sets them to. Nothing
    is ever derived from the incoming request: a Host header is attacker-controlled, and an
    issuer taken from one would be an issuer an attacker chose (D-010).

    What is refused, and why each one is here rather than left to the JWT library:

    - **An algorithm outside the allowlist**, checked against the token header before any key
      is looked at. The allowlist is asymmetric-only and validated at construction, so `HS256`
      - the attack that signs a token with the *published* public key as an HMAC secret - is
      not configurable at all, and `none` never reaches a decode.
    - **A missing or unusable `kid`.** Every published key is never tried in turn: one weak
      key in a rotated set would otherwise verify anything.
    - **A missing `exp`, `iat`, `iss`, `aud` or `sub`.** PyJWT requires no claim by default,
      so a token with no `exp` verifies and never expires unless the requirement is spelled
      out - it is, on every decode.
    - **A token whose lifetime exceeds `max_token_lifetime`**, even when every signature and
      claim is good. Upstream issues fifteen minutes; a token claiming a year means the Node
      side was misconfigured or replaced, and this is the only place that would notice.

    Every refusal is a `SessionError`, so the response is the uniform 401 whatever went wrong.
    The `reason` carries a fingerprint of the credential and never the credential, because
    error reporters serialize exception attributes and capture frame locals (D-018).

    **On timing.** The responses are byte-identical, but a refusal decided locally returns
    faster than one that had to fetch a key set, so the *latency* of an answer says something
    the body does not. Two things bound it rather than hide it: everything an attacker can
    control locally - the algorithm, the `kid`, the shape of the token - is refused with no
    fetch at all, and a fetch that does happen is bounded by the transport's timeout budget
    and, for an unknown `kid`, by the refetch window. No artificial delay is added: padding a
    security answer to a fixed time would make every legitimate request pay for it, and would
    still be visible under load.

    Args:
        base_url: The Better Auth server's origin, exactly as its own `baseURL` is set.
            Keyword-only, required, canonicalized at construction; `http` is accepted only
            for a loopback host.
        transport: The HTTP client used for the key set. Defaults to a `HttpxTransport`
            built here - so a missing `httpx` stops the application from starting rather
            than surfacing on the first request. An injected one is used as it is, and its
            lifetime stays with whoever built it.
        algorithms: The signature algorithms this deployment accepts, defaulting to
            `("EdDSA",)`, which is what better-auth's `jwt` plugin issues. Every entry must
            be one this library can verify asymmetrically.
        leeway: Seconds of clock skew allowed on `exp` and `nbf`, at most 60. More than that
            is a policy decision this library will not make quietly.
        max_token_lifetime: The largest `exp - iat` a token may declare, in seconds.
            Defaults to 900 plus `leeway`, which is upstream's own token lifetime.
        cache_ttl: How long a fetched key set stays fresh, in seconds; at least 60.

    Raises:
        ConfigurationError: For any unusable configuration, at construction: a `base_url`
            that is not an origin, an algorithm this library will not verify, a leeway or
            lifetime outside its bounds, a transport that is not one, or a missing `httpx`.
    """

    def __init__(
        self,
        *,
        base_url: str,
        transport: Transport | None = None,
        algorithms: Sequence[str] = DEFAULT_ALGORITHMS,
        leeway: float = 0.0,
        max_token_lifetime: float | None = None,
        cache_ttl: float = CACHE_TTL,
    ) -> None:
        self.credential_source = CREDENTIAL_SOURCE
        self._origin = normalize_base_url(base_url)
        self._algorithms = _validated_algorithms(algorithms)
        self._leeway = _validated_leeway(leeway)
        self._max_token_lifetime = _validated_lifetime(max_token_lifetime, self._leeway)
        self._transport = HttpxTransport() if transport is None else transport
        self._keys = JwksClient(
            base_url=self._origin,
            transport=self._transport,
            algorithms=self._algorithms,
            cache_ttl=cache_ttl,
        )

    @property
    def origin(self) -> str:
        """The canonical origin: the required `iss`, the required `aud`, and the JWKS host."""
        return self._origin

    @property
    def jwks_uri(self) -> str:
        """The pinned key-set URL this verifier fetches from, and the only one it will."""
        return self._keys.uri

    @property
    def algorithms(self) -> tuple[str, ...]:
        """The accepted signature algorithms, as validated at construction."""
        return self._algorithms

    @property
    def leeway(self) -> float:
        """Seconds of clock skew allowed on `exp` and `nbf`."""
        return self._leeway

    @property
    def max_token_lifetime(self) -> float:
        """The largest `exp - iat` this verifier will accept, in seconds."""
        return self._max_token_lifetime

    @property
    def transport(self) -> Transport:
        """The HTTP boundary the key set is fetched through."""
        return self._transport

    def extract(self, connection: HTTPConnection) -> str | None:
        """Return the bearer token on this request, or `None` if there is not one.

        Structural only: the `Authorization` header, the `Bearer` scheme matched
        case-insensitively as RFC 7235 requires, and whatever follows it. Nothing is decoded
        and nothing is fetched - this runs on every verifier on every request.

        A blank token is *absent*, not present: an empty `Authorization: Bearer` header would
        otherwise be a credential, and an anonymous request carrying one would be refused by
        `current_session` and made ambiguous for anyone composing two verifiers.
        """
        header = connection.headers.get("authorization")
        if not header:
            return None
        scheme, separator, rest = header.partition(" ")
        if not separator or scheme.lower() != SCHEME:
            return None
        return rest.strip() or None

    async def verify(self, credential: str, user_model: type[UserModelT]) -> Session[UserModelT]:
        """Verify a bearer token and build the session it proves.

        Args:
            credential: The token this verifier's own `extract` returned.
            user_model: The `User` subclass to parse the claims into.

        Returns:
            The verified session. `expires_at` is the `exp` claim as an aware UTC datetime,
            `token` is `None` - JWT mode has no server-side session token to hand back - and
            `raw` is the decoded claims exactly as they arrived.

        Raises:
            InvalidCredential: For anything structurally or cryptographically wrong.
            SessionExpired: When `exp` has elapsed beyond `leeway`.
            AuthServiceUnavailable: When the key set could not be fetched or trusted. Still a
                refusal: a session this library cannot verify is one it must not honour.
        """
        token = credential
        try:
            marker = _checked_shape(token)
            header = _unverified_header(token, marker)
            kid = _usable_kid(header, marker)
            algorithm = _allowed_algorithm(header, self._algorithms, marker)
            key = await self._key_for(kid, algorithm, marker)
            claims = _decoded(token, key, self, marker)
            _check_subject(claims, marker)
            _check_lifetime(claims, self._max_token_lifetime, marker)
            return _session(claims, user_model)
        finally:
            # Reporters capture frame locals; this frame is the one they would blame us for.
            credential = ""
            token = ""

    async def _key_for(self, kid: str, algorithm: str, marker: str) -> Jwk:
        found = await self._keys.key_for(kid)
        if found is None:
            raise InvalidCredential(reason=f"no published key for kid={safe_label(kid)} {marker}")
        if found.algorithm != algorithm:
            raise InvalidCredential(
                reason=f"header says alg={algorithm}, key {safe_label(kid)} is"
                f" {safe_label(found.algorithm)} {marker}"
            )
        return found


def _checked_shape(credential: object) -> str:
    """The cheap refusals, before a parser sees anything: a marker for the reasons, or a no."""
    if not isinstance(credential, str) or not credential:
        raise InvalidCredential(reason=f"credential is not a token: {type(credential).__name__}")
    marker = fingerprint(credential)
    if len(credential) > MAX_TOKEN_BYTES:
        raise InvalidCredential(reason=f"token is {len(credential)} bytes, over the cap {marker}")
    if credential.count(".") != DOT_SEPARATORS:
        raise InvalidCredential(reason=f"token is not three dot-separated segments {marker}")
    return marker


def _unverified_header(token: str, marker: str) -> Mapping[str, Any]:
    """The JOSE header, read *before* anything is verified, and used for nothing else.

    Only two values are taken from it, and both are checked against configuration rather than
    trusted: the `kid` to look up, and the `alg` to match against the key's own.
    """
    try:
        return jwt.get_unverified_header(token)
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        failure = type(exc).__name__
    token = ""
    raise InvalidCredential(reason=f"unreadable token header [{failure}] {marker}") from None


def _usable_kid(header: Mapping[str, Any], marker: str) -> str:
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid.strip():
        raise InvalidCredential(reason=f"token names no key id {marker}")
    return kid


def _allowed_algorithm(header: Mapping[str, Any], allowed: Sequence[str], marker: str) -> str:
    """The header may only *choose among* algorithms configuration already permitted."""
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or algorithm not in allowed:
        raise InvalidCredential(reason=f"alg={safe_label(algorithm)} is not allowed {marker}")
    return algorithm


def _decoded(token: str, key: Jwk, verifier: JwtVerifier, marker: str) -> Mapping[str, Any]:
    """Signature, issuer, audience, expiry and the required claims, in one PyJWT call.

    `algorithms` is the configured allowlist and never the token's own header (RFC 8725 2.1),
    `require` is spelled out because PyJWT requires nothing by default, and `issuer` and
    `audience` are the canonical origin.
    """
    try:
        return jwt.decode(
            token,
            key=key.key,
            algorithms=list(verifier.algorithms),
            options={"require": list(REQUIRED_CLAIMS)},
            issuer=verifier.origin,
            audience=verifier.origin,
            leeway=verifier.leeway,
        )
    except jwt.ExpiredSignatureError:
        expired, failure = True, "ExpiredSignatureError"
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        expired, failure = False, type(exc).__name__
    token = ""
    if expired:
        raise SessionExpired(reason=f"token expired [{failure}] {marker}") from None
    raise InvalidCredential(reason=f"token rejected [{failure}] {marker}") from None


def _check_subject(claims: Mapping[str, Any], marker: str) -> None:
    """`sub` is the identity every authorization decision downstream keys on."""
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise InvalidCredential(reason=f"sub identifies nobody {marker}")


def _check_lifetime(claims: Mapping[str, Any], ceiling: float, marker: str) -> None:
    """A token upstream would never have minted, however well it is signed."""
    issued = _as_number(claims.get("iat"))
    expires = _as_number(claims.get("exp"))
    if issued is None or expires is None:
        raise InvalidCredential(reason=f"iat or exp is not a number {marker}")
    lifetime = expires - issued
    if lifetime > ceiling:
        raise InvalidCredential(
            reason=f"token lifetime {lifetime:.0f}s exceeds the {ceiling:.0f}s ceiling {marker}"
        )


def _session(claims: Mapping[str, Any], user_model: type[UserModelT]) -> Session[UserModelT]:
    return Session(
        user=parse_user(user_model, _identified(claims)),
        expires_at=_expiry(claims),
        token=None,
        raw=claims,
    )


def _expiry(claims: Mapping[str, Any]) -> datetime:
    """`exp` is already proven a number, and bounded by the lifetime ceiling above."""
    expires = _as_number(claims.get("exp"))
    assert expires is not None, "the lifetime check runs first"
    return datetime.fromtimestamp(expires, tz=timezone.utc)


def _identified(claims: Mapping[str, Any]) -> Mapping[str, Any]:
    """`sub` stands in when a payload carries no `id`, and never replaces one that does.

    Upstream's default payload is the whole user, so `id` is normally there - but
    `definePayload` lets an operator ship a slimmer token, and `sub` is the same value.
    Refusing an authentic, signed token because a field was renamed would be refusing the
    deployment, not the credential. `raw` still carries the claims exactly as they arrived.
    """
    if claims.get("id") is not None:
        return claims
    return {**claims, "id": claims.get("sub")}


def _as_number(value: object) -> float | None:
    """`bool` is an `int`, and a claim of `true` is not a time."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _validated_algorithms(algorithms: object) -> tuple[str, ...]:
    """Annotated `Sequence[str]`; a bare string is a sequence of one-letter algorithms."""
    if isinstance(algorithms, (str, bytes, bytearray)) or not isinstance(algorithms, Sequence):
        raise ConfigurationError(
            "algorithms must be a sequence of algorithm names, such as ('EdDSA',); got"
            f" {type(algorithms).__name__}. A bare string is a sequence of its own letters."
        )
    entries = cast("Sequence[object]", algorithms)
    if not entries:
        raise ConfigurationError(
            "algorithms is empty, so no signature could ever verify. Pass at least one of"
            f" {list(SUPPORTED_ALGORITHMS)}."
        )
    checked: list[str] = []
    for entry in entries:
        if not isinstance(entry, str) or entry not in SUPPORTED_ALGORITHMS:
            raise ConfigurationError(
                f"algorithms lists {entry!r}, which this library will not verify. Accepted:"
                f" {list(SUPPORTED_ALGORITHMS)} - asymmetric only, and spelled exactly as JWA"
                " spells them. An HS* entry would let a key set's *public* key be used as a"
                " signing secret, and 'none' is not an algorithm."
            )
        if entry not in checked:
            checked.append(entry)
    return tuple(checked)


def _validated_leeway(leeway: object) -> float:
    if isinstance(leeway, bool) or not isinstance(leeway, (int, float)):
        raise ConfigurationError(
            f"leeway must be a number of seconds; got {type(leeway).__name__}."
        )
    if not math.isfinite(leeway) or leeway < 0 or leeway > MAX_LEEWAY:
        raise ConfigurationError(
            f"leeway must be between 0 and {int(MAX_LEEWAY)} seconds; got {leeway!r}. It is"
            " there for clock skew, and every second of it is a second of extra session life"
            " for an expired token. If you need more, verify the token yourself."
        )
    return float(leeway)


def _validated_lifetime(max_token_lifetime: object, leeway: float) -> float:
    if max_token_lifetime is None:
        return DEFAULT_LIFETIME + leeway
    if isinstance(max_token_lifetime, bool) or not isinstance(max_token_lifetime, (int, float)):
        raise ConfigurationError(
            "max_token_lifetime must be a number of seconds;"
            f" got {type(max_token_lifetime).__name__}."
        )
    if not math.isfinite(max_token_lifetime) or not 0 < max_token_lifetime <= MAX_LIFETIME:
        raise ConfigurationError(
            f"max_token_lifetime must be above 0 and at most {int(MAX_LIFETIME)} seconds; got"
            f" {max_token_lifetime!r}. It is the ceiling that catches a Node side minting"
            " long-lived tokens, so a ceiling of a day already accepts far more than upstream"
            " issues."
        )
    return float(max_token_lifetime)
