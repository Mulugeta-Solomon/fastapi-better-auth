"""Mode C: the Better Auth session cookie, verified by asking the Better Auth server itself.

`RemoteVerifier` takes the session cookie off the request and asks upstream whether it names a live
session, through `GET /api/auth/get-session`. It reads no database, no Redis, and - unless the
operator configures a secret for the local signature pre-check - no shared secret. Its whole
dependency is the 200-null contract (upstream answers `200` with a literal `null` for an
unauthenticated request) and the `{session, user}` shape of an authenticated one.

The pipeline order is the design, and every step through the fetch is pinned:

    isinstance -> resolve named cookie -> rung 1 (structural) -> CSRF -> rung 2 (keyring, only
    when a secret is configured) -> negative cache -> 429 latch -> _ready() (probe) -> limiter
    acquire (bounded) -> GET get-session -> outcome (Q3) -> token compare -> expiry -> ban ->
    parse_user

CSRF runs before the fetch and before rung 2 so a cross-site attacker cannot tell a 403 from a 401
and use the difference as an oracle. Rung 1 runs before CSRF only because a `SignedDoubleSubmit`
policy binds the CSRF token to the session token, which rung 1 is what extracts. Every step through
the 429 latch makes ZERO outbound calls by construction, so a cache hit, a latched instance, and
every pre-fetch refusal are all answered without touching the network.

The four gates before the fetch each buy one property. The **negative cache** collapses a
forged-cookie flood to one upstream call per window. The **429 latch** stops hammering a bucket
upstream said we exhausted. **`_ready()`** runs the boot probe once and fails closed until it passes
- it sits after CSRF and every zero-outbound gate because the probe is itself outbound. The
**limiter** bounds how much of this process one stalled auth service can occupy. The outbound
request is built once at construction and never from anything on an incoming request (D-010): the
URI is `self._uri`, and the headers are a closed set of exactly `cookie` and `accept` - never the
inbound `Authorization`, `Host`, `Origin`, `X-Forwarded-*` or any other header. The header dict
holds a live credential and is scrubbed in `finally` (D-094), and every transport failure is raised
OUTSIDE the `except` with `from None`, because the underlying exception's `.request` carries the
forwarded cookie.

Internal module, public class: `RemoteVerifier` is exported from the package root (WP15), and
`prepare()` makes it a `PreparedVerifier` an operator wires into startup.
"""

from __future__ import annotations

import hmac
import math
import time
import urllib.parse
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import Any, TypeVar, cast

import anyio
from pydantic import SecretStr
from starlette.requests import HTTPConnection

from .cookie_parsing import (
    MAX_COOKIE_BYTES,
    MAX_COOKIE_HEADER_BYTES,
    MAX_COOKIE_PAIRS,
    acceptable_names,
    cookie_pairs,
    parse_signed_value,
    resolve_named_cookie,
)
from .cookie_verifier import (
    DEFAULT_COOKIE_NAME,
    DEFAULT_SECURE_PREFIX,
    ILLEGAL_IN_A_COOKIE_NAME,
)
from .csrf import CsrfFacts, CsrfPolicy, enforce_policy, validated_policy
from .errors import (
    AuthServiceUnavailable,
    BetterAuthError,
    ConfigurationError,
    InvalidCredential,
    SessionError,
    SessionExpired,
    SessionRevoked,
)
from .httpx_transports import HttpxTransport
from .models import Session, User
from .negative_cache import (
    MAX_NEGATIVE_TTL,
    MAX_REMEMBERED,
    MAX_REMEMBERED_MISSES,
    MIN_NEGATIVE_TTL,
    MIN_REMEMBERED,
    NEGATIVE_TTL,
    NegativeCache,
)
from .parsing import parse_user
from .reasons import fingerprint
from .remote_backoff import BackoffLatch
from .remote_probe import run_probe
from .remote_response import is_cacheable_null, null_outcome, session_document_from
from .shared_secret import SharedSecret
from .signing import verify_signature
from .stores.records import StoredSession, StoredUser
from .transport import (
    ContentEncodingRejected,
    ResponseTooLarge,
    Transport,
    TransportResponse,
)
from .urls import normalize_base_url

UserModelT = TypeVar("UserModelT", bound=User)

COOKIE_HEADER = "cookie"
COOKIE_SOURCE_PREFIX = "cookie:"
ACCEPT_JSON = "application/json"

DEFAULT_BASE_PATH = "/api/auth"
GET_SESSION_PATH = "/get-session"
GET_SESSION_QUERY = "?disableCookieCache=true&disableRefresh=true"
MAX_SESSION_BYTES = 65536
MAX_TOKEN_BYTES = 4096

MAX_OUTBOUND_CONCURRENCY = 8
MIN_CONCURRENCY = 1
MAX_CONCURRENCY = 256
QUEUE_TIMEOUT = 2.0
MIN_QUEUE_TIMEOUT = 0.1
PROBE_RETRY_INTERVAL = 10.0

_BASE_PATH_MESSAGE = (
    "RemoteVerifier(base_path=...) must be the path Better Auth is mounted at, starting with '/'"
    " and with no trailing slash, query or fragment - '/api/auth' by default, or '' for a server"
    " mounted at the root; got {got!r}."
)


class RemoteCredential:
    """What `extract` hands `verify`: the matched cookie pairs, and the CSRF snapshot.

    Frozen and repr-safe. `pairs` holds live cookie material, so the repr renders a count and never
    a value; `facts` renders itself safely. `verify` resolves the pairs into one value, forwards it,
    and reads the answer - the fetch is deferred to there so `extract` stays a cheap, non-raising
    presence check. Same shape as `CookieCredential`.
    """

    __slots__ = ("facts", "pairs")

    def __init__(self, *, pairs: tuple[tuple[str, str], ...], facts: CsrfFacts) -> None:
        object.__setattr__(self, "pairs", pairs)
        object.__setattr__(self, "facts", facts)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("RemoteCredential is immutable")

    def __repr__(self) -> str:
        return f"RemoteCredential(pairs=<{len(self.pairs)} redacted>, facts={self.facts!r})"


class RemoteVerifier:
    """Verifies a Better Auth session cookie by forwarding it to that server's get-session route.

    The mode to reach for when the FastAPI service can reach the Better Auth server over the network
    but does not share its database, its Redis, or (unless you opt in) its secret. Revocation is
    instant - `disableCookieCache=true` forces the authoritative read - at the cost of one HTTP call
    per verification that misses the local pre-filter.

        auth = BetterAuth(
            verifiers=[
                RemoteVerifier(
                    base_url="https://auth.example.com",
                    csrf=OriginCheck(allowed_origins=["https://app.example.com"]),
                )
            ]
        )

    **`csrf` is required and has no default.** Mode C reads a cookie, so it is a cookie mode, so a
    deployment with no cross-site answer must not be constructible (D-006).

    **The outbound request is pinned at construction (D-010).** The URI is
    `{base_url}{base_path}/get-session?disableCookieCache=true&disableRefresh=true`, and the headers
    are exactly `cookie` (the one the browser sent, under its own name, value verbatim) and `accept:
    application/json`. Nothing is ever taken from the incoming request - not the `Authorization`
    header (forwarding it would let a client authenticate a bearer token this verifier never
    extracted), not `Origin`, `Host`, or any `X-Forwarded-*`.

    **The optional secret is a local pre-filter, not a signing key.** With `secret=`/`secrets=`
    configured, a forged or tampered cookie is refused locally with zero upstream calls; without one,
    the upstream verdict is unchanged - only a forged cookie then costs one call to reach `200 null`.
    Both are safe, so neither is legal (unlike `CookieVerifier`, which requires exactly one).

    Args:
        base_url: The Better Auth server's origin, canonicalized at construction; `http` only for
            loopback. Keyword-only, required.
        csrf: The cross-site request forgery policy. Required, keyword-only, no default.
        transport: The HTTP boundary. Defaults to a `HttpxTransport` built here, so a missing
            `httpx` stops the application from starting rather than surfacing on the first request.
        secret: A single `SharedSecret` for the optional local signature pre-check. At most one of
            this and `secrets`; neither is legal.
        secrets: A keyring of `SharedSecret`s for a rotation. At most one of this and `secret`.
        cookie_name: The unprefixed cookie name Better Auth sets. Exactly one name is read - the
            `__Secure-`-prefixed form or this plain one, per `secure_cookies` - with its chunk names.
        secure_prefix: The prefix on the hardened cookie name, used only when `secure_cookies`.
        secure_cookies: Whether the single accepted name is the `__Secure-`-prefixed one. `True` by
            default, matching Better Auth's production default; never both names.
        base_path: The path Better Auth is mounted at, `'/api/auth'` by default, `''` for the root.
        concurrency: How many get-session calls may be in flight at once, 8 by default. A
            blast-radius and connection-pool bound, not the rate control - it keeps one stalled
            auth service from parking every worker task, and is not how fast upstream is asked.
        queue_timeout: Seconds to wait for an outbound slot before refusing, 2.0 by default. Covers
            the acquire only; the whole exchange is bounded by `queue_timeout` plus the transport's
            own deadline.
        negative_ttl: Seconds a `200 + null` verdict is remembered so a forged-cookie flood costs
            one upstream call per window, 30.0 by default. `0.0` disables the cache - safe, never a
            bypass.
        max_remembered: The most forged-cookie verdicts held at once, 1024 by default.
        max_bytes: The largest get-session body this verifier will read, 64 KiB by default.
        clock: A monotonic clock, injected so the cache TTL, the backoff latch and the probe-retry
            window are testable without sleeping.

    Raises:
        ConfigurationError: For any unusable configuration, at construction: a `base_url` that is
            not an origin, a `csrf` that is `None` or not a `CsrfPolicy`, a `transport` that is not
            one, both of `secret`/`secrets`, a non-`SharedSecret` entry, a blank or illegal
            `cookie_name`/`secure_prefix`, a non-bool `secure_cookies`, a malformed `base_path`, a
            `concurrency`/`queue_timeout`/`negative_ttl`/`max_remembered`/`max_bytes` out of range,
            or a non-callable `clock`.
    """

    def __init__(
        self,
        *,
        base_url: str,
        csrf: CsrfPolicy,
        transport: Transport | None = None,
        secret: SharedSecret | None = None,
        secrets: Sequence[SharedSecret] | None = None,
        cookie_name: str = DEFAULT_COOKIE_NAME,
        secure_prefix: str = DEFAULT_SECURE_PREFIX,
        secure_cookies: bool = True,
        base_path: str = DEFAULT_BASE_PATH,
        concurrency: int = MAX_OUTBOUND_CONCURRENCY,
        queue_timeout: float = QUEUE_TIMEOUT,
        negative_ttl: float = NEGATIVE_TTL,
        max_remembered: int = MAX_REMEMBERED_MISSES,
        max_bytes: int = MAX_SESSION_BYTES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._origin = normalize_base_url(base_url)
        self._csrf = validated_policy(csrf, where="RemoteVerifier(csrf=...)")
        self._transport = _validated_transport(transport)
        self._secrets = _validated_optional_keyring(secret, secrets)
        self._cookie_name = _validated_cookie_name(cookie_name)
        self._secure_prefix = _validated_prefix(secure_prefix)
        self._secure_cookies = _validated_secure_cookies(secure_cookies)
        self._base = (
            f"{self._secure_prefix}{self._cookie_name}"
            if self._secure_cookies
            else self._cookie_name
        )
        self._acceptable = acceptable_names(self._base)
        self._base_path = _validated_base_path(base_path)
        self._concurrency = _validated_concurrency(concurrency)
        self._queue_timeout = _validated_queue_timeout(queue_timeout)
        self._max_bytes = _validated_cap(max_bytes)
        self._clock = _validated_clock(clock)
        self._uri = f"{self._origin}{self._base_path}{GET_SESSION_PATH}{GET_SESSION_QUERY}"
        self.credential_source = f"{COOKIE_SOURCE_PREFIX}{self._cookie_name}"
        self._cache = NegativeCache(
            ttl=_validated_negative_ttl(negative_ttl),
            max_remembered=_validated_max_remembered(max_remembered),
            clock=self._clock,
        )
        self._backoff = BackoffLatch(clock=self._clock)
        # anyio.CapacityLimiter binds to the running backend at construction and raises
        # AsyncLibraryNotFoundError if built outside a loop (D-198), so it is built lazily on
        # first use; the count is stored here.
        self._limiter_instance: anyio.CapacityLimiter | None = None
        self._probe_lock = anyio.Lock()
        self._probed_ok = False
        self._contract_failure: str | None = None
        self._probe_attempted_at: float | None = None

    @property
    def origin(self) -> str:
        """The canonical origin the get-session URI is built from."""
        return self._origin

    @property
    def uri(self) -> str:
        """The pinned get-session URI, built once and the only one this verifier fetches."""
        return self._uri

    @property
    def cookie_name(self) -> str:
        """The unprefixed cookie name this verifier reads and documents."""
        return self._cookie_name

    @property
    def secure_cookies(self) -> bool:
        """Whether the single accepted name is the `__Secure-`-prefixed one (`True`) or the plain."""
        return self._secure_cookies

    @property
    def csrf(self) -> CsrfPolicy:
        """The cross-site request forgery policy every unsafe request is measured against."""
        return self._csrf

    @property
    def transport(self) -> Transport:
        """The HTTP boundary get-session is fetched through."""
        return self._transport

    @property
    def secrets(self) -> tuple[SharedSecret, ...]:
        """The optional local pre-check keyring; empty when none is configured."""
        return self._secrets

    @property
    def remembered(self) -> int:
        """How many forged-cookie `200 + null` verdicts the negative cache currently holds."""
        return self._cache.remembered

    async def prepare(self) -> None:
        """Run the get-session readiness probe once, at startup, and fail closed if it cannot pass.

        Wire it through a lifespan handler - `FastAPI(lifespan=auth.lifespan)`, or
        `await auth.startup()` - so a deployment whose Better Auth server cannot honour the
        200-null contract, or cannot be reached at boot, stops the application from starting
        instead of refusing its first authenticated request. Idempotent.

        Two failure classes are handled differently. A **contract** failure - a non-200, a
        non-JSON or non-null body, a session document from a bare request - is a permanent fact
        about the deployment: it is remembered, and every later `prepare()` and `verify()`
        re-raises it. A **reachability** failure at startup - a timeout, a refused connection - is
        raised as a `ConfigurationError` too, because an auth service you cannot reach at boot is a
        deployment that should not take traffic; but it is *not* remembered, so wiring the probe
        lazily (never calling `prepare()`) instead lets the first request retry it.

        Raises:
            ConfigurationError: A contract failure (remembered), or an unreachable server at boot.
        """
        try:
            await self._ready()
        except AuthServiceUnavailable as unreachable:
            raise ConfigurationError(
                f"RemoteVerifier could not reach get-session at {self._uri} during startup:"
                f" {unreachable.reason}. An auth service unreachable at boot is a deployment that"
                " should not take traffic. Fix reachability, or omit startup()/lifespan to let the"
                " probe run lazily on the first request instead."
            ) from None

    async def probe(self) -> None:
        """Run the get-session readiness probe once, now, without memoizing the outcome.

        One bare GET (no cookie) proves the deployment answers `200` with a literal `null` body -
        the 200-null contract Mode C's whole outcome mapping rests on - and is also the dead-jar
        detector: a session document from a bare request means the transport is replaying a
        retained cookie. A second, advisory-only request checks whether the bearer plugin is in the
        permissive `requireSignature: false` posture and logs one warning if so; it never refuses.

        This is the raw one-shot probe. `prepare()` is the memoized, fail-closed version an
        operator wires into startup.

        Raises:
            ConfigurationError: A contract failure - a non-200, a non-JSON or non-null body, or a
                session document from a bare request. The reason names the URI.
            AuthServiceUnavailable: A reachability failure - the server could not be reached.
        """
        await run_probe(self._transport, uri=self._uri, max_bytes=self._max_bytes)

    def extract(self, connection: HTTPConnection) -> RemoteCredential | None:
        """Return this verifier's cookie material and CSRF snapshot, or `None` if it is absent.

        Reads the raw joined Cookie header (never `request.cookies`, which collapses duplicates).
        Presence is an acceptable name carrying a non-blank value; a blank reads as absent. A header
        over the cap, or one parsing into too many pairs, reads as absent and is never walked.

        Synchronous, non-raising, and - unlike Mode A - it observes nothing about `session_data`:
        Mode C never parses that cookie and never forwards it.
        """
        header = "; ".join(connection.headers.getlist(COOKIE_HEADER))
        if len(header) > MAX_COOKIE_HEADER_BYTES:
            return None
        pairs = cookie_pairs(header)
        if len(pairs) > MAX_COOKIE_PAIRS:
            return None
        matched = tuple(
            (name, value) for name, value in pairs if name in self._acceptable and value.strip()
        )
        if not matched:
            return None
        facts = CsrfFacts.from_connection(connection, policy=self._csrf)
        return RemoteCredential(pairs=matched, facts=facts)

    async def verify(self, credential: Any, user_model: type[UserModelT]) -> Session[UserModelT]:
        """Verify a cookie `extract` found, in the pinned order, and build the session it proves.

        Args:
            credential: Exactly the `RemoteCredential` this verifier's own `extract` returned.
            user_model: The `User` subclass to parse the upstream user into.

        Returns:
            The verified session. `token` is the raw session token, `expires_at` the upstream
            expiry, and `raw` the get-session session payload - so `impersonatedBy` is reachable.

        Raises:
            InvalidCredential: A malformed cookie, a signature that verifies against no configured
                secret, a `200 null` with no verified signature, or a body naming a different token.
            CsrfFailure: A cross-site unsafe request, decided before the fetch.
            SessionExpired: A session whose upstream `expiresAt` has elapsed.
            SessionRevoked: A banned user, or a `200 null` whose signature a keyring verified.
            AuthServiceUnavailable: Every unreachable or unreadable upstream answer.
        """
        if not isinstance(credential, RemoteCredential):
            raise InvalidCredential(reason="remote credential snapshot is not this verifier's")
        material = name = token = ""
        outbound: dict[str, str] = {}
        try:
            name, material = resolve_named_cookie(credential.pairs, self._base)
            token = _rung_one(material)
            marker = fingerprint(token)
            enforce_policy(self._csrf, credential.facts, token)
            verified = self._rung_two(material, marker)
            if self._cache.holds(material):
                raise null_outcome(verified, marker)
            if self._backoff.latched():
                raise AuthServiceUnavailable(
                    reason=f"get-session is backing off after a recent rate-limit (429) [{marker}]"
                )
            await self._ready()
            outbound = self._outbound(name, material)
            response = await self._fetched(outbound, marker)
            self._backoff.observe(response)
            record = self._document(response, material, marker, verified)
            return self._session(record, token, marker, user_model)
        finally:
            # `credential` is a parameter, and a parameter is a frame local like any other; and
            # `record`/`response` carry the forwarded token when `_session` refuses AFTER the fetch
            # (expired, banned) - this frame holds all of it (D-094, D-180, D-210). The WP15 gates
            # (cache/latch/limiter/ready) each refuse through this frame too, so `material`/`token`
            # are dropped here on every one of their paths.
            credential = None
            material = name = token = ""
            record = response = None
            outbound.clear()

    def _rung_two(self, material: str, marker: str) -> bool:
        """The keyring pre-check, only when a secret is configured. Returns whether it verified.

        A `False` return is "no secret configured", not "verified false" - a bad signature raises.
        The material is scrubbed in `finally`: this frame holds it, and a bad-signature refusal
        from `parse_signed_value` or `verify_signature` is raised through it (D-094).
        """
        if not self._secrets:
            return False
        parsed = None
        try:
            parsed = parse_signed_value(material)
            verify_signature(self._secrets, parsed.token, parsed.signature, marker)
        finally:
            material = ""
            parsed = None
        return True

    def _outbound(self, name: str, value: str) -> dict[str, str]:
        """The closed outbound header set: the cookie under the name the browser sent, and accept."""
        return {"cookie": f"{name}={value}", "accept": ACCEPT_JSON}

    async def _ready(self) -> None:
        """The readiness gate: fail-closed-until-passed, at pipeline step 8 (after every zero-
        outbound gate, because the probe is itself outbound).

        A confirmed probe returns at once. A remembered contract failure re-raises permanently. An
        unconfirmed verifier probes under the lock, throttled to one attempt per
        `PROBE_RETRY_INTERVAL`; between attempts every request is `AuthServiceUnavailable` - never
        fail-open. The lock collapses a first-request burst into one probe.
        """
        if self._probed_ok:
            return
        if self._contract_failure is not None:
            raise ConfigurationError(self._contract_failure)
        async with self._probe_lock:
            if self._probed_ok:
                return
            if self._contract_failure is not None:
                raise ConfigurationError(self._contract_failure)
            if not self._may_probe():
                raise AuthServiceUnavailable(
                    reason="get-session readiness has not been confirmed; the boot probe is retrying"
                )
            await self._attempt_probe()

    def _may_probe(self) -> bool:
        """One probe per window, whoever asks - so a request flood cannot become a probe flood."""
        if self._probe_attempted_at is None:
            return True
        return self._clock() - self._probe_attempted_at >= PROBE_RETRY_INTERVAL

    async def _attempt_probe(self) -> None:
        """One probe attempt under the lock. Contract failures are remembered permanently; a
        cancelled attempt rolls back its stamp so it does not spend the retry window (D-196)."""
        previous = self._probe_attempted_at
        self._probe_attempted_at = self._clock()
        try:
            await run_probe(self._transport, uri=self._uri, max_bytes=self._max_bytes)
        except ConfigurationError as contract:
            self._contract_failure = str(contract)
            raise
        except anyio.get_cancelled_exc_class():
            self._probe_attempted_at = previous
            raise
        self._probed_ok = True

    def _limiter(self) -> anyio.CapacityLimiter:
        """The outbound concurrency limiter, built lazily inside the loop (D-198)."""
        limiter = self._limiter_instance
        if limiter is None:
            limiter = anyio.CapacityLimiter(self._concurrency)
            self._limiter_instance = limiter
        return limiter

    async def _fetched(self, outbound: dict[str, str], marker: str) -> TransportResponse:
        """Acquire an outbound slot (bounded by `queue_timeout`), then fetch get-session.

        The slot is held for the whole exchange and released on every path; the header dict is
        scrubbed in `finally` whether the acquire, the fetch or the read raised (D-094).
        """
        limiter = self._limiter()
        try:
            await self._acquire(limiter)
            try:
                return await self._get(outbound)
            finally:
                limiter.release()
        finally:
            outbound.clear()

    async def _acquire(self, limiter: anyio.CapacityLimiter) -> None:
        """Wait for a slot, bounded by `queue_timeout`. Saturation is a refusal with a reason
        DISTINCT from the transport timeout's, and the `fail_after` scope covers the acquire only."""
        try:
            with anyio.fail_after(self._queue_timeout):
                await limiter.acquire()
        except TimeoutError:
            raise AuthServiceUnavailable(
                reason=f"get-session outbound queue saturated after {self._queue_timeout}s"
            ) from None

    async def _get(self, outbound: dict[str, str]) -> TransportResponse:
        """The transport GET, with every failure translated so no credential rides out on the chain.

        Every transport failure is raised OUTSIDE the `except` with `from None`: the underlying
        exception's `.request` carries the forwarded cookie, so chaining it would put a live
        credential on `__cause__` and into every error reporter (WP10 A1).
        """
        try:
            return await self._transport.get(self._uri, headers=outbound, max_bytes=self._max_bytes)
        except (BetterAuthError, SessionError):
            raise
        except TimeoutError:
            failure = AuthServiceUnavailable(reason=f"get-session timed out [{self._uri}]")
        except ResponseTooLarge:
            failure = AuthServiceUnavailable(
                reason=f"get-session body exceeded the {self._max_bytes}-byte cap"
            )
        except ContentEncodingRejected:
            failure = AuthServiceUnavailable(
                reason="get-session applied a content encoding after identity was requested"
            )
        except Exception as exc:  # noqa: BLE001 - TransportFailure or a third-party transport error
            failure = AuthServiceUnavailable(
                reason=f"get-session fetch failed [{type(exc).__name__}] {self._uri}"
            )
        raise failure from None

    def _document(
        self, response: TransportResponse, material: str, marker: str, verified: bool
    ) -> StoredSession:
        """Map the response to a record, caching the one cacheable outcome on the way through.

        Only a `200 + null` is remembered, and only when that is what this response actually is -
        `is_cacheable_null` re-confirms it, so a token mismatch or an unreadable document (also an
        `InvalidCredential`/`SessionRevoked` family, but not 200-null) is never cached. `material`
        is scrubbed in `finally`: this frame holds it, and the null refusal unwinds through it.
        """
        try:
            if is_cacheable_null(response):
                self._cache.remember(material)
            return session_document_from(
                response, uri=self._uri, marker=marker, signature_verified=verified
            )
        finally:
            material = ""

    def _session(
        self, record: StoredSession, token: str, marker: str, user_model: type[UserModelT]
    ) -> Session[UserModelT]:
        # parse_session_document guarantees the user is present, so the cast keeps that invariant
        # local rather than re-checking a branch no reachable document can take. This frame holds
        # the forwarded token and the record's copy of it; both are dropped before any refusal.
        stored = cast("StoredUser", record.user)
        try:
            if not hmac.compare_digest(record.token.encode("utf-8"), token.encode("utf-8")):
                raise InvalidCredential(
                    reason=f"upstream answered a session naming a different token [{marker}]"
                )
            _check_expiry(record, marker)
            _check_ban(stored, marker)
            return _build_session(record, stored, token, user_model)
        finally:
            token = ""
            del record, stored


def _rung_one(material: str) -> str:
    """The always-on structural rung: the loosest rule that still filters garbage, zero outbound.

    Byte cap, strict `unquote`, a last-dot split into a non-empty token and a non-empty signature,
    and a token byte cap. The 32-alnum token rule is deliberately dropped: `advanced.database`
    makes token shape operator-defined. One frame holds every credential local, scrubbed in
    `finally`; the returned token is the caller's to scrub.
    """
    marker = fingerprint(material)
    decoded = token = signature = ""
    try:
        length = len(material)
        if length > MAX_COOKIE_BYTES:
            raise InvalidCredential(
                reason=f"cookie value is {length} bytes, over the cap [{marker}]"
            )
        try:
            decoded = urllib.parse.unquote(material, errors="strict")
        except UnicodeDecodeError:
            raise InvalidCredential(
                reason=f"cookie value is not valid percent-encoded UTF-8 [{marker}]"
            ) from None
        token, separator, signature = decoded.rpartition(".")
        if not separator:
            raise InvalidCredential(
                reason=f"cookie value carries no signature separator [{marker}]"
            )
        if not token:
            raise InvalidCredential(reason=f"cookie value has an empty token [{marker}]")
        if not signature:
            raise InvalidCredential(reason=f"cookie value has an empty signature [{marker}]")
        length = len(token)
        if length > MAX_TOKEN_BYTES:
            raise InvalidCredential(reason=f"token is {length} bytes, over the cap [{marker}]")
        result = token
    finally:
        material = decoded = token = signature = ""
    return result


def _check_expiry(record: StoredSession, marker: str) -> None:
    """A session whose upstream `expiresAt` has elapsed. The record carries the token, so this
    frame reads the one field it needs and drops the record before the refusal (D-094, D-181)."""
    expires_at = record.expires_at
    del record
    if expires_at <= datetime.now(timezone.utc):
        raise SessionExpired(reason=f"the session upstream returned has expired [{marker}]")


def _check_ban(user: StoredUser, marker: str) -> None:
    """A banned user, unless the ban has lapsed. `banned is None` is unknown, treated as not banned
    (a deployment without the admin plugin has no ban state); `ban_expires is None` on a banned user
    is a permanent ban. Mode A's semantics verbatim (D-182)."""
    if user.banned is None or user.banned is False:
        return
    lapsed = user.ban_expires is not None and user.ban_expires <= datetime.now(timezone.utc)
    if not lapsed:
        raise SessionRevoked(reason=f"the session's user is banned [{marker}]")


def _build_session(
    record: StoredSession, user: StoredUser, token: str, user_model: type[UserModelT]
) -> Session[UserModelT]:
    # The forwarded token, the record's copy of it, and the payload's own `token` column all live
    # in this frame; all must be gone before it exits, on the refusal path as well as the return.
    expires_at = record.expires_at
    raw = record.payload
    del record
    try:
        return Session(
            user=parse_user(user_model, user.payload),
            expires_at=expires_at,
            token=SecretStr(token),
            raw=raw,
        )
    finally:
        token = ""
        raw = {}


def _validated_transport(transport: object) -> Transport:
    if transport is None:
        return HttpxTransport()
    if not isinstance(transport, Transport):
        raise ConfigurationError(
            f"RemoteVerifier(transport=...) is a {type(transport).__name__}, which does not"
            " implement the Transport protocol: it needs async get(url, *, headers, max_bytes)"
            " and post(...) methods. Pass HttpxTransport(), Httpx2Transport(), or an adapter of"
            " your own."
        )
    for method in ("get", "post"):
        if not callable(getattr(transport, method)):
            raise ConfigurationError(
                f"RemoteVerifier(transport=...) has a {method} that is not callable."
            )
    return transport


def _validated_optional_keyring(
    secret: SharedSecret | None, secrets: Sequence[SharedSecret] | None
) -> tuple[SharedSecret, ...]:
    if secret is not None and secrets is not None:
        raise ConfigurationError(
            "RemoteVerifier takes at most one of secret= or secrets=. Both configure the same"
            " optional local signature pre-check; passing both leaves it undecided which keyring"
            " is authoritative."
        )
    if secret is None and secrets is None:
        return ()
    if secret is not None:
        entries: tuple[object, ...] = (secret,)
    else:
        if isinstance(secrets, (str, bytes, bytearray)) or not isinstance(secrets, Sequence):
            raise ConfigurationError(
                "RemoteVerifier(secrets=...) takes a sequence of SharedSecret; got"
                f" {type(secrets).__name__}. A bare string would be iterated one character at a time."
            )
        entries = tuple(cast("Sequence[object]", secrets))
        if not entries:
            raise ConfigurationError(
                "RemoteVerifier(secrets=...) is empty, so no signature could ever be pre-checked."
                " Pass at least one SharedSecret, or neither secret= nor secrets= to skip the"
                " local pre-check entirely."
            )
    for entry in entries:
        if not isinstance(entry, SharedSecret):
            raise ConfigurationError(
                "RemoteVerifier signs nothing, but it pre-checks with SharedSecret, not"
                f" {type(entry).__name__}: SharedSecret is what refuses a weak or placeholder"
                " value at boot and keeps it out of every rendering. Write"
                " SharedSecret(os.environ['BETTER_AUTH_SECRET'])."
            )
    return cast("tuple[SharedSecret, ...]", entries)


def _validated_cookie_name(cookie_name: object) -> str:
    if not isinstance(cookie_name, str) or not cookie_name.strip():
        raise ConfigurationError(
            "RemoteVerifier(cookie_name=...) must be a non-empty string, such as"
            f" 'better-auth.session_token'; got {cookie_name!r}."
        )
    if ILLEGAL_IN_A_COOKIE_NAME.intersection(cookie_name):
        raise ConfigurationError(
            "RemoteVerifier(cookie_name=...) must be a bare cookie name with no whitespace,"
            f" ';', '=' or ','; got {cookie_name!r}."
        )
    return cookie_name


def _validated_prefix(secure_prefix: object) -> str:
    if not isinstance(secure_prefix, str):
        raise ConfigurationError(
            "RemoteVerifier(secure_prefix=...) must be a string, empty to read only the plain"
            f" cookie name; got {type(secure_prefix).__name__}."
        )
    if secure_prefix and ILLEGAL_IN_A_COOKIE_NAME.intersection(secure_prefix):
        raise ConfigurationError(
            "RemoteVerifier(secure_prefix=...) must carry no whitespace, ';', '=' or ','; got"
            f" {secure_prefix!r}."
        )
    return secure_prefix


def _validated_secure_cookies(secure_cookies: object) -> bool:
    if not isinstance(secure_cookies, bool):
        raise ConfigurationError(
            "RemoteVerifier(secure_cookies=...) must be a bool: True to read only the"
            " secure-prefixed cookie name, False to read only the plain one; got"
            f" {type(secure_cookies).__name__}."
        )
    return secure_cookies


def _validated_base_path(base_path: object) -> str:
    if not isinstance(base_path, str):
        raise ConfigurationError(_BASE_PATH_MESSAGE.format(got=type(base_path).__name__))
    if base_path == "":
        return base_path
    malformed = (
        not base_path.startswith("/")
        or base_path.endswith("/")
        or any(char.isspace() or char < "\x20" or char == "\x7f" for char in base_path)
        or "?" in base_path
        or "#" in base_path
        or ".." in base_path
    )
    if malformed:
        raise ConfigurationError(_BASE_PATH_MESSAGE.format(got=base_path))
    return base_path


def _validated_cap(max_bytes: object) -> int:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ConfigurationError(
            "RemoteVerifier(max_bytes=...) must be a positive integer number of bytes; got"
            f" {max_bytes!r}. It bounds the get-session body this verifier will read."
        )
    return max_bytes


def _validated_concurrency(concurrency: object) -> int:
    if (
        isinstance(concurrency, bool)
        or not isinstance(concurrency, int)
        or not MIN_CONCURRENCY <= concurrency <= MAX_CONCURRENCY
    ):
        raise ConfigurationError(
            f"RemoteVerifier(concurrency=...) must be between {MIN_CONCURRENCY} and"
            f" {MAX_CONCURRENCY} outbound get-session calls; got {concurrency!r}. It bounds how"
            " much of this process one stalled auth service can occupy, not how fast upstream is"
            " asked."
        )
    return concurrency


def _validated_queue_timeout(queue_timeout: object) -> float:
    if isinstance(queue_timeout, bool) or not isinstance(queue_timeout, (int, float)):
        raise ConfigurationError(
            "RemoteVerifier(queue_timeout=...) must be a number of seconds; got"
            f" {type(queue_timeout).__name__}."
        )
    if not math.isfinite(queue_timeout) or queue_timeout < MIN_QUEUE_TIMEOUT:
        raise ConfigurationError(
            f"RemoteVerifier(queue_timeout=...) must be at least {MIN_QUEUE_TIMEOUT} seconds; got"
            f" {queue_timeout!r}. Below that a saturated moment refuses every request that arrives"
            " during it."
        )
    return float(queue_timeout)


def _validated_negative_ttl(negative_ttl: object) -> float:
    if isinstance(negative_ttl, bool) or not isinstance(negative_ttl, (int, float)):
        raise ConfigurationError(
            "RemoteVerifier(negative_ttl=...) must be a number of seconds; got"
            f" {type(negative_ttl).__name__}."
        )
    if not math.isfinite(negative_ttl) or not MIN_NEGATIVE_TTL <= negative_ttl <= MAX_NEGATIVE_TTL:
        raise ConfigurationError(
            f"RemoteVerifier(negative_ttl=...) must be between {int(MIN_NEGATIVE_TTL)} and"
            f" {int(MAX_NEGATIVE_TTL)} seconds; 0 disables the cache, which costs one upstream call"
            f" per forged cookie and is safe, never a bypass. Got {negative_ttl!r}."
        )
    return float(negative_ttl)


def _validated_max_remembered(max_remembered: object) -> int:
    if (
        isinstance(max_remembered, bool)
        or not isinstance(max_remembered, int)
        or not MIN_REMEMBERED <= max_remembered <= MAX_REMEMBERED
    ):
        raise ConfigurationError(
            "RemoteVerifier(max_remembered=...) must be a positive number of remembered refusals,"
            f" at most {MAX_REMEMBERED}; got {max_remembered!r}. A garbage-cookie space is the"
            " attacker's imagination, so remembering it is bounded."
        )
    return max_remembered


def _validated_clock(clock: object) -> Callable[[], float]:
    if not callable(clock):
        raise ConfigurationError(
            "RemoteVerifier(clock=...) must be a callable returning monotonic seconds, such as"
            f" time.monotonic; got {type(clock).__name__}."
        )
    return cast("Callable[[], float]", clock)
