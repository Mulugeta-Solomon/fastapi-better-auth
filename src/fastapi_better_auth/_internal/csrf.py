"""Cross-site request forgery: the policy a cookie-authenticated unsafe request must pass."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, cast, runtime_checkable

from starlette.requests import HTTPConnection

from .errors import ConfigurationError, CsrfFailure
from .reasons import fingerprint, safe_label, safe_origin
from .shared_secret import SharedSecret
from .urls import normalize_base_url

CROSS_SITE = "cross-site"
DEFAULT_TOKEN_HEADER = "x-csrf-token"
HEADER_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}")
MIN_DISABLED_REASON = 16
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

BROWSER_HEADERS = frozenset(
    {
        "accept",
        "accept-encoding",
        "accept-language",
        "connection",
        "content-language",
        "content-length",
        "content-type",
        "cookie",
        "host",
        "origin",
        "range",
        "referer",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-user",
        "upgrade",
        "user-agent",
    }
)
"""Header names a custom-header requirement may not name.

Each of these is either set by the browser itself or CORS-safelisted, so a cross-site form
POST already carries it. Requiring one would look like a control and enforce nothing.
"""


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class CsrfFacts:
    """The request facts a CSRF decision is made from, captured before verification.

    `Verifier.verify` never sees the connection - by design, so nothing downstream can reach
    for the Host header or the request URL - which means the handful of facts a CSRF policy
    needs have to be taken while the connection is still in hand. This is that snapshot, and
    it is the input half of the `CsrfPolicy` contract: implement a policy, and this is what
    you are handed.

    A cookie-mode verifier builds one inside `extract`:

        facts = CsrfFacts.from_connection(connection, policy=self._csrf)

    Every field is what the request literally carried, uninterpreted: no normalization, no
    canonicalization, no decoding beyond the ASGI server's own. Deciding what a value *means*
    is the policy's job, and the two must not be split across a boundary where one of them
    could quietly become lenient.

    Attributes:
        method: The HTTP method, verbatim. `None` for a WebSocket handshake, whose scope has
            no method at all.
        origin: The `Origin` header, or `None` when the request carried none.
        sec_fetch_site: The `Sec-Fetch-Site` header, or `None`.
        header_name: The custom header this snapshot was captured *for*, lowercased - the
            policy's `required_header`, or `None` when it wants none. A policy refuses a
            snapshot captured for a different header rather than reading a value it did not
            ask for.
        header_value: That header's value, or `None`.
        websocket: Whether this is a WebSocket handshake.
    """

    method: str | None = None
    origin: str | None = None
    sec_fetch_site: str | None = None
    header_name: str | None = None
    header_value: str | None = None
    websocket: bool = False

    @classmethod
    def from_connection(cls, connection: HTTPConnection, *, policy: CsrfPolicy) -> CsrfFacts:
        """Snapshot a live connection for `policy`, reading nothing else.

        Synchronous, allocation-cheap, dictionary reads only, and it does not raise for any
        request whatsoever - it runs inside `extract`, which owes the dispatcher exactly that.

        The policy is passed rather than a header name so the header that is *read* and the
        header that is *checked* cannot drift apart: a snapshot is always captured for the
        policy that will consume it.

        Args:
            connection: The incoming HTTP or WebSocket connection.
            policy: The policy that will be handed this snapshot.

        Returns:
            The facts, frozen.
        """
        scope = connection.scope
        headers = connection.headers
        wanted = policy.required_header
        name = wanted.strip().lower() if isinstance(wanted, str) and wanted.strip() else None
        method = scope.get("method")
        return cls(
            method=method if isinstance(method, str) else None,
            origin=headers.get("origin"),
            sec_fetch_site=headers.get("sec-fetch-site"),
            header_name=name,
            header_value=None if name is None else headers.get(name),
            websocket=scope.get("type") == "websocket",
        )

    @property
    def requires_check(self) -> bool:
        """Whether this request has to pass a CSRF policy at all.

        Every WebSocket handshake does. The handshake is a GET, but it is not covered by the
        same-origin policy: a cross-site page can open one and the browser will attach cookies,
        which is cross-site WebSocket hijacking.

        Otherwise it is the method: `GET`, `HEAD` and `OPTIONS` are the safe ones and skip.
        Anything else - including a request whose method could not be read - is checked.
        """
        if self.websocket:
            return True
        method = self.method
        return not (isinstance(method, str) and method.upper() in SAFE_METHODS)

    def __repr__(self) -> str:
        """Every field an attacker chose, rendered safely - this reaches error reporters."""
        submitted = self.header_value
        return (
            f"{type(self).__name__}(method={safe_label(self.method)},"
            f" origin={safe_origin(self.origin)},"
            f" sec_fetch_site={safe_label(self.sec_fetch_site)},"
            f" header_name={safe_label(self.header_name)},"
            f" header_value={'<absent>' if submitted is None else fingerprint(submitted)},"
            f" websocket={self.websocket})"
        )


@runtime_checkable
class CsrfPolicy(Protocol):
    """What a cookie-authenticated unsafe request has to prove before it is verified.

    Implement this to bring your own cross-site request forgery rule. The shipped policies -
    `OriginCheck`, `SignedDoubleSubmit`, `CsrfDisabled` - implement exactly this and get no
    privileges yours does not.

        class SameOriginOnly:
            required_header = None

            def check(self, facts: CsrfFacts, session_token: str) -> None:
                try:
                    if facts.requires_check and facts.origin != "https://app.example.com":
                        raise CsrfFailure(reason="origin not allowed")
                finally:
                    session_token = ""

    **Your `check` must drop `session_token` from its own frame before it raises**, exactly as
    the `finally` above does. A `CsrfFailure` is raised on an attacker-induced cross-site
    request, so its traceback carries the *victim's* live session token - and an error reporter
    that captures frame locals serializes every local of every frame on it. This library scrubs
    every frame it owns; it cannot reach into yours, so the obligation is yours, and it is a
    `finally` rather than a line before each `raise` because a path that forgets one is a path
    that leaks. The shipped policies all do this; read `OriginCheck.check` for the shape.

    **The check runs before the session token is verified**, and that ordering is a security
    decision rather than an optimization: a cross-site attacker who could tell a CSRF refusal
    from a signature refusal would have an oracle for whether the cookie their victim is
    carrying is currently valid. A cross-origin unsafe request is therefore a uniform 403
    whether the token behind it verifies or not. `session_token` is consequently the
    **parsed-but-unverified** token - use it to bind a value to the session, never as proof
    of anything.

    Configuration is validated eagerly, in `__init__`, raising `ConfigurationError`. A policy
    that cannot decide safely must stop the application from starting, never answer a request
    with a 500.

    The protocol is runtime-checkable, and a cookie-mode verifier checks the policy it is
    handed. Be aware of what that check can see: `isinstance` against a runtime-checkable
    protocol proves the member *names* exist, and nothing about their signatures.

    Attributes:
        required_header: The one custom header this policy reads, lowercased, or `None` if it
            reads none. `CsrfFacts.from_connection` captures exactly this header, so a policy
            that wants a value has to declare it here - there is no way to reach the
            connection from `check`.
    """

    @property
    def required_header(self) -> str | None: ...

    def check(self, facts: CsrfFacts, session_token: str) -> None:
        """Allow the request, or refuse it with `CsrfFailure`.

        Return `None` to allow. There is no boolean answer on purpose: a policy that returned
        `False` would be a policy a caller could forget to read.

        Args:
            facts: The request snapshot, captured at extraction time.
            session_token: The parsed-but-unverified session token, for binding a submitted
                value to this session. Its signature has **not** been checked yet. Drop it from
                your frame in a `finally` before any raise; see the class docstring.

        Raises:
            CsrfFailure: For every refusal. The `reason` reaches operators; the client sees a
                uniform 403 whichever check refused.
        """
        ...


class OriginCheck:
    """Refuse an unsafe request whose `Origin` is not one you named.

    The default cookie-mode policy, and the one most deployments want:

        csrf = OriginCheck(allowed_origins=["https://app.example.com"])

    Three rungs, walked in a fixed order and fail-closed at each:

    1. **`Sec-Fetch-Site: cross-site`** - the browser itself saying the request came from
       another site - is refused outright. Any other value, including a missing header and one
       no browser ships yet, falls through to the allowlist rather than being trusted.
       `same-site` in particular is *not* a pass: a sibling subdomain is same-site, and a
       subdomain takeover or an XSS on one is the exact threat this exists for.
    2. **`Origin` must be present and must exactly equal one of `allowed_origins`.** A missing
       `Origin` on an unsafe method is refused. Every browser sends one; a client that does not
       is not what a CSRF control protects, and it belongs on a bearer-token mode instead.
    3. **The custom header**, if you asked for one, must be present and non-blank.

    The allowlist is canonicalized once, at construction, through the same
    `normalize_base_url` the rest of the package uses, so two spellings of one origin are one
    origin. The `Origin` a request presents is **not** re-canonicalized: browsers serialize it
    canonically already, and running configuration validation over an attacker-supplied header
    would turn a hostile value into a `ConfigurationError`. It is compared verbatim, in
    constant time, against every entry.

    Args:
        allowed_origins: Every origin a browser may legitimately present, as full origins -
            `["https://app.example.com"]`. That is your front end's origin, and it is *this*
            API's own origin when a page served from here posts back to it: a same-origin POST
            still carries `Origin`, and an allowlist that omits it refuses every request. A
            bare string is refused rather than iterated one character at a time.
        require_header: Optionally, a header your front end sets that a cross-site request
            cannot set without a CORS preflight - `"x-requested-with"`. Header names the
            browser sets itself, and the CORS-safelisted ones, are refused: requiring one
            would look like a control and enforce nothing.

    Raises:
        ConfigurationError: For an allowlist that is not a sequence of usable origins, is
            empty, or lists one origin twice under two spellings; and for a `require_header`
            that is not a usable custom header name. All at construction.
    """

    def __init__(
        self, *, allowed_origins: Sequence[str], require_header: str | None = None
    ) -> None:
        self._allowed = _validated_origins(
            allowed_origins, where="OriginCheck(allowed_origins=...)"
        )
        self._encoded = _encoded(self._allowed)
        self._header = _optional_header(require_header, where="OriginCheck(require_header=...)")

    @property
    def allowed_origins(self) -> tuple[str, ...]:
        """The canonicalized allowlist, in declared order."""
        return self._allowed

    @property
    def required_header(self) -> str | None:
        """The custom header this policy requires, lowercased, or `None`."""
        return self._header

    def check(self, facts: CsrfFacts, session_token: str) -> None:
        """Walk the three rungs. See `CsrfPolicy.check`."""
        try:
            if not facts.requires_check:
                return
            _reject_bad_origin(facts, self._encoded)
            if self._header is not None:
                _presented_header(facts, self._header)
        finally:
            # `del`, not `= ""`: this policy never reads the token, so a rebinding would be an
            # unused assignment. Either way the local is gone before the refusal propagates.
            del session_token

    def __repr__(self) -> str:
        return f"{type(self).__name__}(allowed_origins={self._allowed!r})"


class SignedDoubleSubmit:
    """`OriginCheck`, plus a header carrying a token bound to this very session.

    For deployments that cannot rely on `Origin` alone - a front end and an API on sibling
    subdomains with `SameSite=None` cookies, where a compromised sibling is inside the origin
    story:

        csrf = SignedDoubleSubmit(
            secret=SharedSecret(os.environ["BETTER_AUTH_SECRET"]),
            allowed_origins=["https://app.example.com"],
        )

    Every rung of `OriginCheck` runs first and unconditionally - there is no way to construct
    this policy without an allowlist, because double submit *without* an origin check is the
    weaker control, not the stronger one. On top of it, the required header must carry
    `token_for(session_token)`.

    **The token is bound to the session, which is the whole point.** A classic double-submit
    cookie proves only that whoever sent the header could also set a cookie - and a sibling
    subdomain can set a cookie on the parent domain, so it proves nothing against exactly the
    attacker this policy is for. `HMAC(secret, session_token)` cannot be produced without the
    server's secret and does not transfer between sessions: a value planted for one session
    fails for every other.

    Hand the token to your front end from a route of your own and have it send the header back:

        @app.get("/csrf")
        async def csrf(session: Current) -> dict[str, str]:
            return {"token": policy.token_for(session.token.get_secret_value())}

    Args:
        secret: A `SharedSecret` - the same value your Better Auth server signs with, or any
            other secret you keep. A bare `str` is refused: `SharedSecret` is what refuses a
            weak or placeholder value at boot and keeps it out of every rendering.
        allowed_origins: As `OriginCheck`. Required here too.
        header: The header carrying the token. Defaults to `x-csrf-token`.

    Raises:
        ConfigurationError: For a secret that is not a `SharedSecret`, an unusable allowlist,
            or an unusable header name. All at construction.
    """

    def __init__(
        self,
        *,
        secret: SharedSecret,
        allowed_origins: Sequence[str],
        header: str = DEFAULT_TOKEN_HEADER,
    ) -> None:
        self._secret = _validated_secret(secret, where="SignedDoubleSubmit(secret=...)")
        self._allowed = _validated_origins(
            allowed_origins, where="SignedDoubleSubmit(allowed_origins=...)"
        )
        self._encoded = _encoded(self._allowed)
        self._header = _validated_header(header, where="SignedDoubleSubmit(header=...)")

    @property
    def allowed_origins(self) -> tuple[str, ...]:
        """The canonicalized allowlist, in declared order."""
        return self._allowed

    @property
    def required_header(self) -> str:
        """The header the token must arrive in, lowercased. Never `None` for this policy."""
        return self._header

    def token_for(self, session_token: str) -> str:
        """The CSRF token for one session: 64 lowercase hex characters, stable and bound.

        `HMAC-SHA256(secret, session_token)`. Hand it to your front end - in a JSON body, in a
        readable cookie, in a `<meta>` tag - and have every unsafe request echo it back in the
        configured header. It is not a secret in the way the session token is: knowing it does
        not authenticate anything, and it is useless against any other session.

        Args:
            session_token: The raw session token this request is authenticated by.

        Returns:
            The token to send back in the header.

        Raises:
            TypeError: If `session_token` is not a `str`.
        """
        return _digest(self._secret, session_token)

    def check(self, facts: CsrfFacts, session_token: str) -> None:
        """Walk `OriginCheck`'s rungs, then the token. See `CsrfPolicy.check`."""
        presented = ""
        try:
            if not facts.requires_check:
                return
            _reject_bad_origin(facts, self._encoded)
            presented = _presented_header(facts, self._header)
            _reject_forged_token(self._secret, session_token, presented, self._header)
        finally:
            session_token = presented = ""

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(allowed_origins={self._allowed!r},"
            f" header={self._header!r}, secret={self._secret!r})"
        )


class CsrfDisabled:
    """Turn cross-site request forgery protection off, on the record.

    The only way to run cookie mode without a CSRF check, and it is deliberately unpleasant to
    write:

        csrf = CsrfDisabled(reason="Mode B only; this deployment sends no cookies")

    A required, non-trivial `reason` is the whole design. There is no `None` default, no
    configuration flag and no environment variable that skips the check, because every one of
    those turns "we disabled CSRF" into something nobody has to say out loud - and a
    `DEBUG`-conditional bypass is a production bypass one deploy away. Written this way, the
    decision is in the source, in review, in `repr()`, and answerable.

    Args:
        reason: Why this deployment does not need the check, in a sentence someone else can
            evaluate. Refused if it is blank or too short to be one.

    Raises:
        ConfigurationError: If `reason` is not a string of at least 16 characters.
    """

    def __init__(self, *, reason: str) -> None:
        self._reason = _validated_disabled_reason(reason)

    @property
    def reason(self) -> str:
        """Why the check is off, as the operator wrote it."""
        return self._reason

    @property
    def required_header(self) -> None:
        """Nothing: a policy that checks nothing reads nothing."""
        return None

    def check(self, facts: CsrfFacts, session_token: str) -> None:
        """Allow every request, whatever it looks like. See `CsrfPolicy.check`."""
        del session_token

    def __repr__(self) -> str:
        return f"{type(self).__name__}(reason={self._reason!r})"


# ---------------------------------------------------------------- the rungs


def _reject_bad_origin(facts: CsrfFacts, allowed: tuple[bytes, ...]) -> None:
    site = facts.sec_fetch_site
    if isinstance(site, str) and site.strip().casefold() == CROSS_SITE:
        raise CsrfFailure(
            reason="Sec-Fetch-Site is cross-site: the browser reported that this unsafe"
            " request was initiated from another site"
        )
    origin = facts.origin
    if origin is None or not origin.strip():
        raise CsrfFailure(
            reason="no Origin header on an unsafe request. Browsers send one on every unsafe"
            " method and on every WebSocket handshake; a client that does not is refused"
            " rather than exempted"
        )
    presented = origin.encode("utf-8", "replace")
    matched = False
    for candidate in allowed:
        matched |= hmac.compare_digest(presented, candidate)
    if not matched:
        raise CsrfFailure(reason=f"Origin {safe_origin(origin)} is not in allowed_origins")


def _presented_header(facts: CsrfFacts, name: str) -> str:
    if facts.header_name != name:
        captured = safe_label(facts.header_name)
        raise CsrfFailure(
            reason=f"these request facts were captured for header {captured}, not the"
            f" {name!r} this policy requires, so its header was never read"
        )
    value = facts.header_value
    if value is None or not value.strip():
        raise CsrfFailure(reason=f"the required {name!r} header is absent or blank")
    return value


def _reject_forged_token(
    secret: SharedSecret, session_token: object, presented: str, name: str
) -> None:
    # The refusal raised here is the one a cross-site attacker induces, so this frame is on a
    # traceback with the VICTIM's live token in it. `expected` is derived from that token with
    # the server's own secret, so it is scrubbed alongside it (D-094, D-180).
    expected = ""
    try:
        if not isinstance(session_token, str):
            kind = type(session_token).__name__
            raise CsrfFailure(
                reason=f"the session credential handed to this policy is a {kind}, not a str, so"
                " nothing could be bound to it"
            )
        expected = _digest(secret, session_token)
        if not hmac.compare_digest(expected.encode("ascii"), presented.encode("utf-8", "replace")):
            raise CsrfFailure(
                reason=f"the {name!r} header does not carry the CSRF token bound to session"
                f" {fingerprint(session_token)}"
            )
    finally:
        session_token = expected = presented = ""


def _digest(secret: SharedSecret, session_token: object) -> str:
    try:
        if not isinstance(session_token, str):
            kind = type(session_token).__name__
            raise TypeError(f"token_for() takes the session token as a str; got {kind}.")
        return hmac.new(
            secret.get_secret_value().encode("utf-8"),
            session_token.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
    finally:
        session_token = ""


# ---------------------------------------------------------------- eager configuration


def enforce_policy(policy: CsrfPolicy, facts: CsrfFacts, session_token: str) -> None:
    """Run `policy`, and refuse a policy that answered instead of raising.

    The one sanctioned way to consume a `CsrfPolicy`. `check` allows by returning `None`, so a
    policy written to return `False` for "deny" would be a silent fail-open at every call site
    that ignored the answer - the same hazard `core._checked` exists for, answered the same
    way: loudly, as a `ConfigurationError`, rather than by guessing what was meant.
    """
    try:
        answer = policy.check(facts, session_token)
        if answer is not None:
            raise ConfigurationError(
                f"{type(policy).__name__}.check() returned {type(answer).__name__}; a CsrfPolicy"
                " allows a request by returning None and refuses one by raising CsrfFailure. A"
                " returned answer is ignored by every caller, so it would allow the request."
            )
    finally:
        session_token = ""


def validated_policy(policy: object, *, where: str) -> CsrfPolicy:
    """The policy, or a `ConfigurationError` naming what is wrong with it.

    Call this from the constructor of anything that takes a `csrf=` argument. `None` is
    refused with a message pointing at `CsrfDisabled`, because "no policy" and "a policy that
    allows everything" must not be the same keystroke (D-006).
    """
    if policy is None:
        raise ConfigurationError(
            f"{where} is required and has no default: a cookie-authenticated mode with no"
            " CSRF answer is a cross-site request forgery hole, so None is not a value here."
            " Pass OriginCheck(allowed_origins=[...]), SignedDoubleSubmit(secret=...,"
            " allowed_origins=[...]), or - deliberately, in the source - "
            "CsrfDisabled(reason='...')."
        )
    if not isinstance(policy, CsrfPolicy):
        raise ConfigurationError(
            f"{where} is a {type(policy).__name__}, which does not implement the CsrfPolicy"
            " protocol: it needs a `required_header` attribute and a"
            " check(facts, session_token) method."
        )
    if not callable(policy.check):
        raise ConfigurationError(f"{where} has a check that is not callable.")
    _optional_header(policy.required_header, where=f"{where} required_header")
    return policy


def _validated_origins(value: object, *, where: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise ConfigurationError(
            f"{where} takes a sequence of origins, such as ['https://app.example.com']; got"
            f" {type(value).__name__}. A bare string would be iterated one character at a"
            " time, and the application would start looking configured."
        )
    entries = tuple(cast("Sequence[object]", value))
    if not entries:
        raise ConfigurationError(
            f"{where} is empty. An allowlist with no origins refuses every unsafe request,"
            " which is an outage wearing a security control's clothes. Name the origins your"
            " front end is served from."
        )
    normalized: list[str] = []
    for index, entry in enumerate(entries):
        origin = normalize_base_url(cast("str", entry), field=f"{where}[{index}]")
        if origin in normalized:
            raise ConfigurationError(
                f"{where} lists {origin!r} twice: entry {index} canonicalizes onto an earlier"
                " one. Two spellings of one origin are one origin; keep a single entry."
            )
        normalized.append(origin)
    return tuple(normalized)


def _encoded(origins: tuple[str, ...]) -> tuple[bytes, ...]:
    """The allowlist as bytes, so a comparison against a non-ASCII header cannot raise."""
    return tuple(origin.encode("utf-8") for origin in origins)


def _validated_header(value: object, *, where: str) -> str:
    if not isinstance(value, str) or not HEADER_NAME.fullmatch(value.strip()):
        raise ConfigurationError(
            f"{where} must be one HTTP header name - letters, digits and token punctuation,"
            f" with no spaces, colons or control characters; got {value!r}."
        )
    name = value.strip().lower()
    if name in BROWSER_HEADERS:
        raise ConfigurationError(
            f"{where}={name!r} is a header the browser sets itself, or one a cross-site form"
            " POST may carry without a CORS preflight, so requiring it enforces nothing. Name"
            " a header only your own front end sends, such as 'x-csrf-token'."
        )
    return name


def _optional_header(value: object, *, where: str) -> str | None:
    return None if value is None else _validated_header(value, where=where)


def _validated_secret(value: object, *, where: str) -> SharedSecret:
    if not isinstance(value, SharedSecret):
        kind = type(value).__name__
        raise ConfigurationError(
            f"{where} must be a SharedSecret, not a {kind}. SharedSecret is what refuses a"
            " weak or placeholder value at boot and keeps it out of every rendering; a bare"
            " string skips all of it. Write SharedSecret(os.environ['BETTER_AUTH_SECRET'])."
        )
    return value


def _validated_disabled_reason(value: object) -> str:
    if not isinstance(value, str) or len(value.strip()) < MIN_DISABLED_REASON:
        raise ConfigurationError(
            "CsrfDisabled(reason=...) needs a reason of at least"
            f" {MIN_DISABLED_REASON} characters saying why this deployment does not need the"
            f" check - something the next reader can evaluate; got {value!r}. Turning CSRF"
            " protection off is meant to cost a sentence."
        )
    return value
