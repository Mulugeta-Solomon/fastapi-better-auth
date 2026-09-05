"""The key set: fetched once, capped everywhere, and never asked for twice at the same time."""

from __future__ import annotations

import json
import logging
import math
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

import anyio
from jwt.algorithms import Algorithm, ECAlgorithm, OKPAlgorithm, RSAAlgorithm

from .errors import AuthServiceUnavailable, BetterAuthError, ConfigurationError, SessionError
from .reasons import safe_label
from .transport import Transport, TransportResponse

logger = logging.getLogger("fastapi_better_auth")

JWKS_PATH = "/api/auth/jwks"
MAX_JWKS_BYTES = 64 * 1024
MAX_KEYS = 32
CACHE_TTL = 300.0
MIN_CACHE_TTL = 60.0
MIN_RSA_KEY_BITS = 2048
NEGATIVE_TTL = 60.0
REFETCH_INTERVAL = 10.0
MAX_REMEMBERED_MISSES = 256
JSON_MEDIA_TYPES = frozenset({"application/json", "application/jwk-set+json"})

# The map is the second barrier against HS*: a symmetric algorithm has no entry, so no
# amount of configuration can put a shared secret on the path a signature is checked with.
LOADERS: Mapping[str, type[Algorithm]] = {
    "EdDSA": OKPAlgorithm,
    "ES256": ECAlgorithm,
    "ES512": ECAlgorithm,
    "PS256": RSAAlgorithm,
    "RS256": RSAAlgorithm,
}
SUPPORTED_ALGORITHMS: tuple[str, ...] = tuple(LOADERS)


@dataclass(frozen=True)
class Jwk:
    """One published key, already loaded into the object a signature check needs.

    Attributes:
        kid: The key id exactly as upstream published it, which is what a token is matched on.
        algorithm: The key's own declared `alg`. A token's header must agree with it.
        key: The `cryptography` public key. Always asymmetric - see `LOADERS`.
        jwk: The entry as it arrived, kept for diagnosis.
    """

    kid: str
    algorithm: str
    key: Any
    jwk: Mapping[str, Any]


class JwksClient:
    """The key set behind one origin, and the policy that keeps fetching it from being a lever.

    A JWKS client is a network call whose *timing* an unauthenticated client controls, through
    a `kid` it chose. Every rule here follows from that: the URL is pinned to the operator's
    origin and never rebuilt from anything on a request, the body is capped and must be JSON
    or it is refused unread, concurrent misses collapse into one fetch, a `kid` that a fetch
    did not contain is remembered so it cannot cost a second one, and no more than one fetch
    happens per refetch window however many new `kid`s arrive.

    Availability is bought exactly once: when a refetch fails, keys already fetched keep
    verifying tokens they signed. It buys nothing else - a `kid` that is not in the key set on
    hand is never accepted, and when the set is stale the honest answer is that it cannot be
    confirmed rather than that it is unknown.

    Internal. Nothing here is public API; `JwtVerifier` owns the one instance there is.

    Args:
        base_url: The canonical origin, already through `normalize_base_url`.
        transport: The HTTP boundary. Redirects are not followed, so a 3xx arrives as an
            answer and is refused like any other non-200.
        algorithms: The verifier's allowlist. A published key outside it is ignored rather
            than refused, because upstream may rotate through an algorithm we do not accept.
        cache_ttl: Seconds a fetched key set stays fresh. At least `MIN_CACHE_TTL`.
        negative_ttl: Seconds an unknown `kid` is remembered for.
        refetch_interval: The floor between two upstream fetches.
        max_bytes: The body cap handed to the transport.
        max_keys: The most keys a key set may carry.
        clock: A monotonic clock, replaceable so that cache policy can be tested without
            waiting for it.

    Raises:
        ConfigurationError: If the transport is not one, or `cache_ttl` is below the floor.
    """

    def __init__(
        self,
        *,
        base_url: str,
        transport: Transport,
        algorithms: Sequence[str],
        cache_ttl: float = CACHE_TTL,
        negative_ttl: float = NEGATIVE_TTL,
        refetch_interval: float = REFETCH_INTERVAL,
        max_bytes: int = MAX_JWKS_BYTES,
        max_keys: int = MAX_KEYS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._uri = f"{base_url}{JWKS_PATH}"
        self._transport = _validated_transport(transport)
        self._algorithms = tuple(algorithms)
        self._cache_ttl = _validated_ttl(cache_ttl)
        self._negative_ttl = float(negative_ttl)
        self._refetch_interval = float(refetch_interval)
        self._max_bytes = max_bytes
        self._max_keys = max_keys
        self._clock = clock
        self._lock = anyio.Lock()
        self._keys: Mapping[str, Jwk] | None = None
        self._fetched_at: float | None = None
        self._attempted_at: float | None = None
        self._missing: dict[str, float] = {}

    @property
    def uri(self) -> str:
        """The pinned key-set URL, built once from the canonical origin."""
        return self._uri

    @property
    def waiting(self) -> int:
        """How many callers are queued behind the in-flight fetch. Observability for tests."""
        return self._lock.statistics().tasks_waiting

    @property
    def remembered(self) -> int:
        """How many unknown key ids are currently remembered. Bounded by construction."""
        return len(self._missing)

    async def key_for(self, kid: str) -> Jwk | None:
        """The key published under `kid`, or `None` when a key set we trust does not carry it.

        Raises:
            AuthServiceUnavailable: When there is no key set to answer from - the first fetch
                failed, or the one on hand is stale and does not carry this `kid`.
        """
        hit = self._fresh_hit(kid)
        if hit is not None:
            return hit
        async with self._lock:
            # Re-checked inside the lock: whoever held it may have fetched the answer already.
            hit = self._fresh_hit(kid)
            if hit is not None:
                return hit
            # The window wins over the negative cache (D-095): once it opens, a cached-absent
            # kid is re-fetched (a rotation resolves in refetch_interval, not negative_ttl);
            # inside the window the negative cache still short-circuits, so a flood is bounded.
            if self._may_fetch():
                await self._refresh()
            elif self._is_remembered(kid):
                return None
            return self._answer(kid)

    def _fresh_hit(self, kid: str) -> Jwk | None:
        keys = self._keys
        if keys is None or not self._is_fresh():
            return None
        return keys.get(kid)

    def _is_fresh(self) -> bool:
        return self._fetched_at is not None and self._clock() - self._fetched_at < self._cache_ttl

    def _may_fetch(self) -> bool:
        """One fetch per window, whoever asks. A generated `kid` is not a fetch trigger."""
        if self._attempted_at is None:
            return True
        return self._clock() - self._attempted_at >= self._refetch_interval

    async def _refresh(self) -> None:
        """Attempt a fetch. A failure with keys already on hand is survivable; the first is not."""
        # A cancelled attempt produced no answer, so it must not spend the window a bystander is
        # gated behind; a COMPLETED refusal keeps the stamp so a failing upstream stays rate-
        # limited (D-084/D-196). Only the cancellation exception rolls back - never a refusal.
        previous = self._attempted_at
        self._attempted_at = self._clock()
        try:
            keys = await self._fetched()
        except AuthServiceUnavailable:
            if self._keys is None:
                raise
            logger.warning("jwks refresh failed for %s; serving the key set on hand", self._uri)
            return
        except anyio.get_cancelled_exc_class():
            self._attempted_at = previous
            raise
        self._keys = keys
        self._fetched_at = self._clock()
        self._missing.clear()

    def _answer(self, kid: str) -> Jwk | None:
        keys = self._keys
        found = None if keys is None else keys.get(kid)
        if found is not None:
            return found
        if keys is not None and self._is_fresh():
            self._remember(kid)
            return None
        raise AuthServiceUnavailable(
            reason=f"no fresh key set for {self._uri}; kid={safe_label(kid)} unconfirmed"
        )

    def _is_remembered(self, kid: str) -> bool:
        at = self._missing.get(kid)
        if at is None:
            return False
        if self._clock() - at >= self._negative_ttl:
            del self._missing[kid]
            return False
        return True

    def _remember(self, kid: str) -> None:
        """Bounded, because remembering every `kid` a generator invents is the flood again.

        Eviction is oldest-first, which a dict gives for free through insertion order, and
        which is also the right order: the oldest entry is the one closest to expiring.
        """
        while len(self._missing) >= MAX_REMEMBERED_MISSES:
            self._missing.pop(next(iter(self._missing)))
        self._missing[kid] = self._clock()

    async def _fetched(self) -> Mapping[str, Jwk]:
        try:
            response = await self._transport.get(self._uri, max_bytes=self._max_bytes)
        except (BetterAuthError, SessionError):
            raise
        except Exception as exc:  # noqa: BLE001 - `from None`: a Transport's error may carry the request
            # The type name is already in the reason; `from None` keeps a third-party
            # Transport's exception (which may carry what it failed on) off the chain.
            raise AuthServiceUnavailable(
                reason=f"jwks fetch failed [{type(exc).__name__}] {self._uri}"
            ) from None
        return self._parsed(response)

    def _parsed(self, response: TransportResponse) -> Mapping[str, Jwk]:
        self._check_answer(response)
        document = self._document(response)
        published: object = document.get("keys")
        if not isinstance(published, list):
            raise self._unusable("its 'keys' member is not a list")
        entries = cast("Sequence[object]", published)
        if len(entries) > self._max_keys:
            raise self._unusable(f"it carries {len(entries)} keys, over the {self._max_keys} cap")
        keys: dict[str, Jwk] = {}
        for entry in entries:
            self._collect(entry, keys)
        return keys

    def _check_answer(self, response: TransportResponse) -> None:
        if response.status_code != 200:
            raise AuthServiceUnavailable(
                reason=f"jwks answered {response.status_code} from {self._uri}"
            )
        declared = response.headers.get("content-type", "")
        media = declared.split(";")[0].strip().lower()
        if media not in JSON_MEDIA_TYPES:
            raise self._unusable(f"it is served as {safe_label(media)}, not JSON")

    def _document(self, response: TransportResponse) -> Mapping[str, Any]:
        # The refusal is raised OUTSIDE the except so `__context__` does not chain the
        # `JSONDecodeError` out - its `.doc` is the raw body (the house pattern, D-181).
        parsed: object = None
        try:
            parsed = json.loads(response.content)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError):
            unparseable = True
        else:
            unparseable = False
        if unparseable:
            raise self._unusable("it is not JSON") from None
        if not isinstance(parsed, dict):
            raise self._unusable("it is not a JSON object")
        return cast("Mapping[str, Any]", parsed)

    def _collect(self, entry: object, keys: dict[str, Jwk]) -> None:
        if not isinstance(entry, dict):
            raise self._unusable("one of its keys is not an object")
        published = cast("Mapping[str, Any]", entry)
        kid = published.get("kid")
        algorithm = published.get("alg")
        if not isinstance(kid, str) or not kid.strip():
            raise self._unusable("one of its keys has no usable 'kid'")
        if not isinstance(algorithm, str) or not algorithm:
            raise self._unusable(f"key {safe_label(kid)} declares no 'alg'")
        loader = LOADERS.get(algorithm)
        if loader is None or algorithm not in self._algorithms:
            return
        if kid in keys:
            return
        declared = _not_for_verifying(published)
        if declared is not None:
            self._skipped(kid, declared)
            return
        key = self._loaded(loader, published, kid)
        if loader is RSAAlgorithm and _rsa_bits(key) < MIN_RSA_KEY_BITS:
            self._skipped(kid, "size")
            return
        keys[kid] = Jwk(kid=kid, algorithm=algorithm, key=key, jwk=published)

    def _skipped(self, kid: str, why: str) -> None:
        """One key dropped from an otherwise usable set - the correct blast radius.

        Refusing the whole document would be an outage for every token; dropping this key is
        an outage only for the tokens it signed, which then answer as an unknown `kid`.
        """
        logger.warning(
            "jwks key %s is not usable for signature verification (%s); it is skipped",
            safe_label(kid),
            why,
        )

    def _loaded(self, loader: type[Algorithm], published: Mapping[str, Any], kid: str) -> Any:
        try:
            return loader.from_jwk(dict(published))
        except Exception:  # noqa: BLE001 - every library failure here means the same thing
            raise self._unusable(f"key {safe_label(kid)} did not load") from None

    def _unusable(self, why: str) -> AuthServiceUnavailable:
        return AuthServiceUnavailable(reason=f"jwks at {self._uri} is unusable: {why}")


def _not_for_verifying(published: Mapping[str, Any]) -> str | None:
    """Which of the JWK's own declarations says this key does not check signatures, if either.

    RFC 7517 4.2/4.3: `use` and `key_ops` are both optional, and absent means unrestricted -
    upstream publishes neither, so absence has to stay usable. Present and pointing elsewhere
    is the publisher saying so, and verifying with an encryption key anyway is using a key for
    what its owner said it is not for. A `key_ops` that is not a list is refused rather than
    searched: `"verify" in "verify"` is `True` for a string.
    """
    if "use" in published and published["use"] != "sig":
        return "use"
    if "key_ops" in published:
        operations = published["key_ops"]
        if not isinstance(operations, list) or "verify" not in cast("Sequence[object]", operations):
            return "key_ops"
    return None


def _rsa_bits(key: Any) -> int:
    """The modulus size of a loaded RSA key; 0 when the object cannot say, which skips it.

    Only asked of keys an RSA loader produced - an EC key carries a `key_size` too, and it is
    a curve size, so comparing it against an RSA floor would refuse every EC key published.
    """
    size: object = getattr(key, "key_size", 0)
    return size if isinstance(size, int) else 0


def _validated_transport(transport: object) -> Transport:
    """Annotated `Transport`; the object was built by someone else, at startup, from config."""
    if not isinstance(transport, Transport):
        raise ConfigurationError(
            f"transport must implement the Transport protocol - an async get(url, *,"
            f" headers, max_bytes) and post(...); got {type(transport).__name__}. Pass"
            " HttpxTransport(), Httpx2Transport(), or an adapter of your own."
        )
    return transport


def _validated_ttl(cache_ttl: object) -> float:
    if isinstance(cache_ttl, bool) or not isinstance(cache_ttl, (int, float)):
        raise ConfigurationError(
            f"cache_ttl must be a number of seconds; got {type(cache_ttl).__name__}."
        )
    if not math.isfinite(cache_ttl) or cache_ttl < MIN_CACHE_TTL:
        raise ConfigurationError(
            f"cache_ttl must be at least {int(MIN_CACHE_TTL)} seconds; got {cache_ttl!r}. Below"
            " that a key set is refetched often enough to be a fetch per request wearing a"
            " cache's name, and upstream's rate limit is then part of your auth path."
        )
    return float(cache_ttl)
