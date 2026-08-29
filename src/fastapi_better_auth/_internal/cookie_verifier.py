"""Mode A: a Better Auth session cookie, verified against a keyring and an authoritative store.

The mode to reach for when the browser talks to this service directly with the cookie Better Auth
set on sign-in. It composes the two layers this phase already merged - a `CsrfPolicy` and a
`SessionStore` - into one pinned pipeline, and the ordering of that pipeline is the whole design:

    parse (structure) -> CSRF -> signature -> store -> expiry / ban -> parse_user

CSRF runs **before** the signature is checked, so a cross-site attacker cannot tell a CSRF refusal
(403) from a signature refusal (401) and use the difference as an oracle for whether the cookie
their victim is carrying is currently valid. A bad signature is refused before the store is ever
touched, so a forged cookie spends nothing on a lookup. Neither the keyring's `compare_digest` nor
the store is reached on a CSRF failure. These are named invariants, spy-tested, not hopes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import threading
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any, TypeVar, cast

from pydantic import SecretStr
from starlette.requests import HTTPConnection

from .cookie_parsing import (
    ParsedCookie,
    acceptable_names,
    cookie_pairs,
    parse_signed_value,
    resolve_cookie_value,
    session_data_names,
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
from .models import Session, User
from .parsing import parse_user
from .reasons import fingerprint, safe_label
from .shared_secret import SharedSecret
from .stores.protocol import SessionStore
from .stores.records import StoredSession, StoredUser

logger = logging.getLogger("fastapi_better_auth")

UserModelT = TypeVar("UserModelT", bound=User)

DEFAULT_COOKIE_NAME = "better-auth.session_token"
DEFAULT_SECURE_PREFIX = "__Secure-"
COOKIE_HEADER = "cookie"
COOKIE_SOURCE_PREFIX = "cookie:"
ILLEGAL_IN_A_COOKIE_NAME = frozenset(" \t\r\n;=,")


class _Once:
    """A latch that fires true exactly once across threads, for a warning that must not repeat."""

    __slots__ = ("_fired", "_lock")

    def __init__(self) -> None:
        self._fired = False
        self._lock = threading.Lock()

    def fire(self) -> bool:
        with self._lock:
            if self._fired:
                return False
            self._fired = True
            return True


_SESSION_DATA_ONCE = _Once()


class CookieCredential:
    """What `extract` hands `verify`: the matched cookie pairs, and the CSRF snapshot.

    Frozen and repr-safe. `pairs` holds live cookie material, so the repr renders a count and never
    a value; `facts` renders itself safely. `verify` resolves the pairs into one signed value and
    parses it - the structural work is deferred to there so `extract` stays a cheap, non-raising
    presence check.
    """

    __slots__ = ("facts", "pairs")

    def __init__(self, *, pairs: tuple[tuple[str, str], ...], facts: CsrfFacts) -> None:
        object.__setattr__(self, "pairs", pairs)
        object.__setattr__(self, "facts", facts)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("CookieCredential is immutable")

    def __repr__(self) -> str:
        return f"CookieCredential(pairs=<{len(self.pairs)} redacted>, facts={self.facts!r})"


class CookieVerifier:
    """Verifies the session cookie Better Auth sets, against a shared secret and a session store.

    The cookie is `token + "." + base64(HMAC-SHA256(secret, token))`, URL-encoded. This verifier
    parses that shape, checks the HMAC against a keyring (one or more `SharedSecret`s, so a rotated
    secret still verifies), and then looks the raw token up in the authoritative store the operator
    injected - enforcing expiry and bans itself, because Better Auth's own `findSession()` does not.

        auth = BetterAuth(
            verifiers=[
                CookieVerifier(
                    secret=SharedSecret(os.environ["BETTER_AUTH_SECRET"]),
                    store=SqlAlchemySessionStore(engine=engine),
                    csrf=OriginCheck(allowed_origins=["https://app.example.com"]),
                )
            ]
        )

    **`csrf` is required and has no default.** A cookie-authenticated mode with no cross-site
    request forgery answer is the hole this whole mode has to close, so there is no way to construct
    one without saying what the answer is - `OriginCheck`, `SignedDoubleSubmit`, or, deliberately in
    the source, `CsrfDisabled(reason=...)`.

    The pipeline order is pinned and is a security decision, not an optimization:

    1. **Structural parse** of the cookie - unquote once, split at the last dot, a 44-character
       standard-base64 signature over 32 bytes. Yields the parsed-but-unverified token.
    2. **CSRF**, before the signature is checked, so a cross-origin unsafe request is a uniform 403
       whether or not the token would have verified.
    3. **Signature**, one `compare_digest` per keyring entry with no early return, accepted iff any
       matched. A bad signature is `InvalidCredential` and the store is never reached.
    4. **Store lookup** of the raw token. A miss after a valid signature is `SessionRevoked` - the
       session was signed out or never existed - never a fall-through to anything else.
    5. **Expiry and bans**, which the store does not enforce and this verifier must.
    6. **parse_user** into the requested model, and the `Session` it proves, carrying the raw token.

    Every refusal is a `SessionError`, so the response is the uniform 401 (403 for CSRF) whatever
    went wrong, and every `reason` carries a fingerprint of the token and never the token itself.

    Args:
        secret: The single `SharedSecret` this deployment signs with. Exactly one of this and
            `secrets`.
        secrets: A keyring of `SharedSecret`s, for a `BETTER_AUTH_SECRETS`-style rotation: every
            one is tried with a `compare_digest` and no early return, and a cookie is accepted if
            any matches. Exactly one of this and `secret`.
        store: The authoritative `SessionStore`. Required. A miss is terminal - there is no
            fall-back, because a store configured against Redis that fell back to a database would
            resurrect exactly the sessions a sign-out revoked.
        csrf: The cross-site request forgery policy. Required, keyword-only, no default.
        cookie_name: The unprefixed cookie name Better Auth sets, `better-auth.session_token` by
            default. Its `__Secure-`-prefixed form and its `${name}.${index}` chunk names are read
            as well, and it is the cookie `/docs` shows an Authorize field for.
        secure_prefix: The prefix on the hardened cookie name, `__Secure-` by default. An empty
            string reads only the plain name.

    Raises:
        ConfigurationError: For any unusable configuration, at construction: neither or both of
            `secret`/`secrets`, an empty keyring, a keyring entry or `secret` that is not a
            `SharedSecret`, a `store` that is not a `SessionStore`, a `csrf` that is `None` (which
            points at `CsrfDisabled`) or not a `CsrfPolicy`, or a `cookie_name` that is blank or
            carries a character illegal in a cookie name.
    """

    def __init__(
        self,
        *,
        secret: SharedSecret | None = None,
        secrets: Sequence[SharedSecret] | None = None,
        store: SessionStore,
        csrf: CsrfPolicy,
        cookie_name: str = DEFAULT_COOKIE_NAME,
        secure_prefix: str = DEFAULT_SECURE_PREFIX,
    ) -> None:
        self._secrets = _validated_keyring(secret, secrets)
        self._store = _validated_store(store)
        self._csrf = validated_policy(csrf, where="CookieVerifier(csrf=...)")
        self._cookie_name = _validated_cookie_name(cookie_name)
        self._secure_prefix = _validated_prefix(secure_prefix)
        self._plain_base = self._cookie_name
        prefixed = f"{self._secure_prefix}{self._cookie_name}"
        self._secure_base = None if prefixed == self._cookie_name else prefixed
        self._acceptable = acceptable_names(self._cookie_name, self._secure_prefix)
        self._data_names = session_data_names(self._cookie_name, self._secure_prefix)
        self.credential_source = f"{COOKIE_SOURCE_PREFIX}{self._cookie_name}"

    @property
    def cookie_name(self) -> str:
        """The unprefixed cookie name this verifier reads and documents."""
        return self._cookie_name

    @property
    def secure_prefix(self) -> str:
        """The prefix on the hardened cookie name."""
        return self._secure_prefix

    @property
    def csrf(self) -> CsrfPolicy:
        """The cross-site request forgery policy every unsafe request is measured against."""
        return self._csrf

    @property
    def store(self) -> SessionStore:
        """The authoritative session store this verifier looks a token up in."""
        return self._store

    def extract(self, connection: HTTPConnection) -> CookieCredential | None:
        """Return this verifier's cookie material and CSRF snapshot, or `None` if it is absent.

        Reads the raw Cookie header (never `request.cookies`, which collapses duplicates) - and all
        of them, joined, because HTTP/2 may split cookies across header lines. Presence is an
        acceptable name carrying a NON-BLANK value; a blank or whitespace-only value reads as absent
        (the Verifier Protocol contract), or a planted empty cookie from a sibling subdomain would
        make every composed request `AmbiguousCredentials` before any verify runs - dispatch counts
        presence, and a blank carries no credential. Dropping blanks is safe for the duplicate
        defence: a real cookie beside a planted blank of the same name resolves to the real one,
        while two non-blank same-name cookies still reach the duplicate rejection in `verify`.

        Synchronous and non-raising. The one side effect is a single, once-only warning if the
        out-of-scope `session_data` cookie is seen (CVE-2026-67337); its value is never read.
        """
        pairs = cookie_pairs(_joined_cookie_header(connection))
        self._observe_session_data(pairs)
        matched = tuple(
            (name, value) for name, value in pairs if name in self._acceptable and value.strip()
        )
        if not matched:
            return None
        facts = CsrfFacts.from_connection(connection, policy=self._csrf)
        return CookieCredential(pairs=matched, facts=facts)

    async def verify(self, credential: Any, user_model: type[UserModelT]) -> Session[UserModelT]:
        """Verify a cookie `extract` found, in the pinned order, and build the session it proves.

        Args:
            credential: Exactly the `CookieCredential` this verifier's own `extract` returned.
            user_model: The `User` subclass to parse the stored user into.

        Returns:
            The verified session. `token` is the raw session token, `expires_at` is the stored
            expiry, and `raw` is the stored session payload - so `impersonatedBy` and the rest are
            reachable there.

        Raises:
            InvalidCredential: For a malformed cookie or a signature that verifies against no key.
            CsrfFailure: For a cross-site unsafe request, decided before the signature.
            SessionRevoked: For a valid signature whose session or user is not in the store.
            SessionExpired: For a session past its expiry.
            AuthServiceUnavailable: When the store could not be reached.
        """
        if not isinstance(credential, CookieCredential):
            raise InvalidCredential(reason="cookie credential snapshot is not this verifier's")
        material = token = signature = ""
        parsed: ParsedCookie | None = None
        try:
            material = resolve_cookie_value(credential.pairs, self._plain_base, self._secure_base)
            parsed = parse_signed_value(material)
            token = parsed.token
            signature = parsed.signature
            marker = fingerprint(token)
            enforce_policy(self._csrf, credential.facts, token)
            _verify_signature(self._secrets, token, signature, marker)
            return await self._resolved(token, marker, user_model)
        finally:
            material = token = signature = ""
            parsed = None

    async def _resolved(
        self, token: str, marker: str, user_model: type[UserModelT]
    ) -> Session[UserModelT]:
        # This frame holds the raw token across the store/expiry/ban refusals; scrub it before any
        # of them propagates, so a reporter capturing this frame's locals finds nothing (D-094).
        try:
            record = await self._looked_up(token, marker)
            if record is None:
                raise SessionRevoked(reason=f"no stored session for this token [{marker}]")
            _check_expiry(record, marker)
            stored = record.user
            if stored is None:
                stored = await self._looked_up_user(record.user_id, marker)
                if stored is None:
                    raise SessionRevoked(reason=f"the session's user is absent [{marker}]")
            _check_ban(stored, marker)
            return _session(record, stored, token, user_model)
        finally:
            token = ""

    async def _looked_up(self, token: str, marker: str) -> StoredSession | None:
        try:
            try:
                return await self._store.fetch_session_by_token(token)
            except (BetterAuthError, SessionError):
                raise
            except Exception:  # noqa: BLE001 - a raw store failure becomes the uniform refusal
                failure = _store_unavailable(marker)
            # Raised outside the handler so no __context__ links to the store's exception, and
            # `from None` clears __cause__ (WP10 A1). The two shipped stores answer alike after this
            # - SQL already translates to this, Redis propagated its connection error untranslated.
            raise failure from None
        finally:
            token = ""

    async def _looked_up_user(self, user_id: str, marker: str) -> StoredUser | None:
        # No token here, and `user_id` is not a credential (it is in StoredSession's own repr), so
        # this frame needs no scrub - only the store-parity translation the two stores' divergence
        # requires, raised outside the handler with `from None` as in `_looked_up`.
        try:
            return await self._store.fetch_user_by_id(user_id)
        except (BetterAuthError, SessionError):
            raise
        except Exception:  # noqa: BLE001 - as _looked_up
            failure = _store_unavailable(marker)
        raise failure from None

    def _observe_session_data(self, pairs: tuple[tuple[str, str], ...]) -> None:
        observed = next((name for name, _ in pairs if name in self._data_names), None)
        if observed is not None and _SESSION_DATA_ONCE.fire():
            logger.warning(
                "a %s cookie was observed; the session-data cookie cache is out of scope in this"
                " version (CVE-2026-67337, a 2FA bypass through exactly that cache) and is never"
                " parsed",
                safe_label(observed),
            )


def _joined_cookie_header(connection: HTTPConnection) -> str:
    return "; ".join(connection.headers.getlist(COOKIE_HEADER))


def _store_unavailable(marker: str) -> AuthServiceUnavailable:
    return AuthServiceUnavailable(reason=f"session store lookup could not complete [{marker}]")


def _verify_signature(
    secrets: tuple[SharedSecret, ...], token: str, signature: str, marker: str
) -> None:
    """One `compare_digest` per keyring entry, no early return, accepted iff any matched.

    The keyring is the `BETTER_AUTH_SECRETS` rotation: a cookie signed with any current secret must
    verify. Iterating without an early return keeps the work independent of which key matched, and
    `matched |=` accumulates so a match is never short-circuited away. The token, the signature and
    every derived byte string are scrubbed in `finally` - this is the frame that raises the bad-sig
    refusal, so a reporter capturing its locals must find no credential (D-094).
    """
    message = presented = expected = b""
    digest = None
    try:
        message = token.encode("utf-8")
        presented = signature.encode("ascii")
        matched = False
        for secret in secrets:
            digest = hmac.new(secret.get_secret_value().encode("utf-8"), message, hashlib.sha256)
            expected = base64.b64encode(digest.digest())
            matched |= hmac.compare_digest(presented, expected)
        if not matched:
            raise InvalidCredential(
                reason=f"signature verifies against no configured secret [{marker}]"
            )
    finally:
        token = signature = ""
        message = presented = expected = b""
        digest = None


def _check_expiry(record: StoredSession, marker: str) -> None:
    """A stored session whose `expiresAt` has elapsed - which upstream's findSession does not check."""
    if record.expires_at <= datetime.now(timezone.utc):
        raise SessionExpired(reason=f"the stored session has expired [{marker}]")


def _check_ban(user: StoredUser, marker: str) -> None:
    """A banned user, unless the ban has lapsed. `banned is None` is unknown, treated as not banned.

    `None` means the admin plugin is not installed, so there is no ban state at all - reading its
    absence as "banned" would refuse every user on a deployment without the plugin. A `ban_expires`
    of `None` on a banned user is a permanent ban, not a lapsed one.
    """
    if user.banned is not True:
        return
    lapsed = user.ban_expires is not None and user.ban_expires <= datetime.now(timezone.utc)
    if not lapsed:
        raise SessionRevoked(reason=f"the session's user is banned [{marker}]")


def _session(
    record: StoredSession, user: StoredUser, token: str, user_model: type[UserModelT]
) -> Session[UserModelT]:
    # parse_user may raise InvalidCredential from this frame, which holds the raw token; scrub it in
    # finally. On success the token lives on only as the returned Session's masked SecretStr.
    try:
        return Session(
            user=parse_user(user_model, user.payload),
            expires_at=record.expires_at,
            token=SecretStr(token),
            raw=record.payload,
        )
    finally:
        token = ""


def _validated_keyring(
    secret: SharedSecret | None, secrets: Sequence[SharedSecret] | None
) -> tuple[SharedSecret, ...]:
    if (secret is None) == (secrets is None):
        raise ConfigurationError(
            "CookieVerifier needs exactly one of secret= or secrets=. Pass secret=SharedSecret(...)"
            " for a single secret, or secrets=[SharedSecret(...), ...] for a rotation keyring - not"
            " neither, and not both."
        )
    if secret is not None:
        entries: tuple[object, ...] = (secret,)
    else:
        if isinstance(secrets, (str, bytes, bytearray)) or not isinstance(secrets, Sequence):
            raise ConfigurationError(
                "CookieVerifier(secrets=...) takes a sequence of SharedSecret; got"
                f" {type(secrets).__name__}. A bare string would be iterated one character at a time."
            )
        entries = tuple(cast("Sequence[object]", secrets))
        if not entries:
            raise ConfigurationError(
                "CookieVerifier(secrets=...) is empty, so no signature could ever verify. Pass at"
                " least one SharedSecret."
            )
    for entry in entries:
        if not isinstance(entry, SharedSecret):
            raise ConfigurationError(
                "CookieVerifier signs with SharedSecret, not"
                f" {type(entry).__name__}: SharedSecret is what refuses a weak or placeholder value"
                " at boot and keeps it out of every rendering. Write"
                " SharedSecret(os.environ['BETTER_AUTH_SECRET'])."
            )
    return cast("tuple[SharedSecret, ...]", entries)


def _validated_store(store: object) -> SessionStore:
    if not isinstance(store, SessionStore):
        raise ConfigurationError(
            f"CookieVerifier(store=...) is a {type(store).__name__}, which does not implement the"
            " SessionStore protocol: it needs async fetch_session_by_token(token) and"
            " fetch_user_by_id(user_id) methods."
        )
    for method in ("fetch_session_by_token", "fetch_user_by_id"):
        if not callable(getattr(store, method)):
            raise ConfigurationError(
                f"CookieVerifier(store=...) has a {method} that is not callable."
            )
    return store


def _validated_cookie_name(cookie_name: object) -> str:
    if not isinstance(cookie_name, str) or not cookie_name.strip():
        raise ConfigurationError(
            "CookieVerifier(cookie_name=...) must be a non-empty string, such as"
            f" 'better-auth.session_token'; got {cookie_name!r}."
        )
    if ILLEGAL_IN_A_COOKIE_NAME.intersection(cookie_name):
        raise ConfigurationError(
            "CookieVerifier(cookie_name=...) must be a bare cookie name with no whitespace,"
            f" ';', '=' or ','; got {cookie_name!r}."
        )
    return cookie_name


def _validated_prefix(secure_prefix: object) -> str:
    if not isinstance(secure_prefix, str):
        raise ConfigurationError(
            "CookieVerifier(secure_prefix=...) must be a string, empty to read only the plain"
            f" cookie name; got {type(secure_prefix).__name__}."
        )
    if secure_prefix and ILLEGAL_IN_A_COOKIE_NAME.intersection(secure_prefix):
        raise ConfigurationError(
            "CookieVerifier(secure_prefix=...) must carry no whitespace, ';', '=' or ','; got"
            f" {secure_prefix!r}."
        )
    return secure_prefix
