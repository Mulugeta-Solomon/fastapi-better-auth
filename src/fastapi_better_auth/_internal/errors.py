"""The error taxonomy: what user code catches, and what a client is allowed to see."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Any, ClassVar

from fastapi import HTTPException

BEARER_CHALLENGE: Mapping[str, str] = MappingProxyType({"WWW-Authenticate": "Bearer"})

SANCTIONED_RESPONSES: Mapping[int, tuple[str, Mapping[str, str] | None]] = MappingProxyType(
    {
        400: ("Ambiguous request", None),
        401: ("Not authenticated", BEARER_CHALLENGE),
        403: ("Forbidden", None),
    }
)
SHADOWED_ATTRIBUTES = ("status_code", "detail", "headers")
REFUSAL_STATUSES = frozenset({403, 404})
CHALLENGE_HEADER = "www-authenticate"


def _rebuild(error_cls: type[SessionError], reason: str) -> SessionError:
    return error_cls(reason=reason)


def _refuse_shadowing(cls: type[HTTPException], consequence: str) -> None:
    shadowed = [name for name in SHADOWED_ATTRIBUTES if name in cls.__dict__]
    if shadowed:
        raise TypeError(
            f"{cls.__name__} sets {', '.join(shadowed)} in its class body. Those are"
            f" instance attributes {consequence}"
        )


class BetterAuthError(Exception):
    """Base class for the faults this library raises outside a request.

    These are programming and deployment errors - a misconfigured verifier, a missing
    secret - not answers to a client. They are deliberately not `HTTPException`s: there
    is no status code that makes a broken configuration a client's problem.
    """


class ConfigurationError(BetterAuthError):
    """Configuration that cannot produce a safe verification.

    Raised while the application is being constructed, never while serving a request, so
    a deployment that would silently fail open never finishes starting up.
    """


class SessionError(HTTPException):
    """Base class for request-time authentication failures.

    Subclasses say *what* went wrong; `reason` says *why*. The response says neither.
    Every failure in the 401 family renders a byte-identical response - same status, same
    body, same headers - so a client cannot tell a bad signature from an expired session
    from an unreachable auth service, and cannot use the difference to probe for valid
    identifiers. That guarantee covers the response only; closing the timing channel
    between a local signature check and a timed-out network call is the verifier's
    timeout budget to own, not this class's.

    `reason` reaches operators through a registered exception handler, through `.reason`,
    and through `repr()`. It is absent from `str()` and from every response. Note that a
    bare `logger.exception()` renders `str()` and will *not* carry it - log `exc.reason`
    explicitly.

    Keep `reason` to identifiers and fingerprints: a session id, a key id, a truncated
    hash. Never interpolate a raw credential into it. Error reporters serialize an
    exception's attributes and capture local variables, so a token that reaches `reason`
    reaches them too.

    To add a failure of your own, subclass and override the three response constants -
    `response_status`, `response_detail` and `response_headers`. They are the whole
    extension mechanism, and they are validated when the subclass is created: a status
    outside {400, 401, 403}, a non-uniform detail, or headers that are not
    `BEARER_CHALLENGE` (401) / `None` (400, 403) raises `TypeError`. Setting `status_code`,
    `detail` or `headers` directly in a class body raises for the same reason - those are
    instance attributes, so they would silently win at runtime and ship the wrong shape.

    Args:
        reason: Keyword-only, required. Never rendered to the client.
    """

    response_status: ClassVar[int] = 401
    response_detail: ClassVar[str] = "Not authenticated"
    response_headers: ClassVar[Mapping[str, str] | None] = BEARER_CHALLENGE

    reason: str

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        _refuse_shadowing(
            cls,
            "and would silently win over the response constants;"
            " set response_status / response_detail / response_headers instead.",
        )
        sanctioned = SANCTIONED_RESPONSES.get(cls.response_status)
        if sanctioned is None:
            raise TypeError(
                f"{cls.__name__}.response_status is {cls.response_status!r};"
                f" a SessionError may only answer {sorted(SANCTIONED_RESPONSES)}."
            )
        detail, headers = sanctioned
        if cls.response_detail != detail:
            raise TypeError(
                f"{cls.__name__}.response_detail must be {detail!r} to stay indistinguishable"
                f" from every other {cls.response_status}."
            )
        if cls.response_headers != headers:
            raise TypeError(
                f"{cls.__name__}.response_headers must be"
                f" {'BEARER_CHALLENGE' if headers is not None else 'None'}"
                f" for a {cls.response_status}."
            )

    def __init__(self, *, reason: str) -> None:
        self.reason = reason
        headers = self.response_headers
        super().__init__(
            status_code=self.response_status,
            detail=self.response_detail,
            headers=dict(headers) if headers is not None else None,
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(reason={self.reason!r})"

    def __reduce__(self) -> tuple[Callable[..., SessionError], tuple[type[SessionError], str]]:
        return (_rebuild, (type(self), self.reason))


class InvalidCredential(SessionError):
    """The credential was present but did not verify.

    Bad signature, malformed token, wrong issuer or audience, unknown key id. Covers
    every way a credential can be structurally or cryptographically wrong.
    """


class SessionExpired(SessionError):
    """The credential verified, but its lifetime has run out.

    Raised by whichever layer notices first: an `exp` claim in the past, or a stored
    session whose `expiresAt` has elapsed.
    """


class SessionRevoked(SessionError):
    """The credential verified, but the session behind it is gone.

    Signed out, deleted, or absent from the authoritative store.
    """


class AuthServiceUnavailable(SessionError):
    """The session could not be verified because a dependency was unreachable.

    Answered as 401 on purpose: a session this library cannot verify is a session it
    must not honour, and the state of an internal auth service is not something a client
    gets to learn from a status code.
    """


class MissingCredential(SessionError):
    """No credential was presented at all.

    A separate class so operators can tell anonymous traffic apart from attacks in logs
    and metrics. On the wire it is byte-identical to every other 401: "you sent nothing"
    and "you sent something forged" must not be distinguishable, or an endpoint becomes a
    detector for which credentials this deployment accepts.

    Raised by `current_session` when no verifier found a credential on the request.
    `optional_session` answers that same situation with `None` instead.
    """


class CsrfFailure(SessionError):
    """A cookie-authenticated request failed its cross-site request forgery check.

    403, not 401: the request carried a credential and was refused on policy grounds, so
    there is nothing for the client to re-authenticate. It gets no `WWW-Authenticate`
    challenge for the same reason.
    """

    response_status: ClassVar[int] = 403
    response_detail: ClassVar[str] = "Forbidden"
    response_headers: ClassVar[Mapping[str, str] | None] = None


class NotAuthorized(SessionError):
    """An authenticated session was refused by an authorization rule.

    403, not 401: the request proved who it is and was refused on what it may do, so there is
    nothing for the client to re-authenticate and no `WWW-Authenticate` challenge to offer. It
    is byte-identical to `CsrfFailure` on the wire - both say only "a real credential was
    refused on policy", and neither says which policy.

    Reaching it at all means authentication already succeeded: an anonymous or forged request
    is answered `401` by the session dependency an authorization gate composes on, and never
    reaches the rule. That order is what keeps a 403 from becoming an oracle for which
    credentials this deployment accepts.

    `reason` names the operator's own rule, the user id, and - for a membership refusal - the
    sanitized resource id the request asked about. It is never rendered to the client, and it
    never carries the client's data verbatim.

    Raised by `BetterAuth.require` and `BetterAuth.require_membership`, and available for an
    application's own authorization failures. A rule whose refusal has to explain itself raises
    `AuthorizationRefused` instead, which reaches the client with the status and body it chose.
    """

    response_status: ClassVar[int] = 403
    response_detail: ClassVar[str] = "Forbidden"
    response_headers: ClassVar[Mapping[str, str] | None] = None


class AmbiguousCredentials(SessionError):
    """Two or more credentials arrived on one request.

    400, not 401: what is wrong is the shape of the request, not the identity behind it,
    and there is nothing for the client to re-authenticate - so it gets no
    `WWW-Authenticate` challenge either. A uniform 401 here would instead make a
    legitimate client's own misconfiguration undebuggable.

    What the 400 does disclose, precisely: that this deployment recognizes *both* of the
    credential shapes that were sent. It fires only when two configured verifiers each
    found their credential, so a client can use it to learn which modes are enabled. That
    is deployment configuration rather than identity - normally published in the API's own
    documentation, and discoverable from the sign-in flow - and it says nothing about
    whether any credential was valid.

    It is still a `SessionError`, so `except SessionError` remains "every request-time
    failure this library raises".

    Raised before any verification happens. Picking one of the two credentials to verify
    would let a client choose which verifier answers, and trying both in turn is the
    fallthrough this library refuses to do.
    """

    response_status: ClassVar[int] = 400
    response_detail: ClassVar[str] = "Ambiguous request"
    response_headers: ClassVar[Mapping[str, str] | None] = None


class AuthorizationRefused(HTTPException):
    """A refusal the authorization rule explains itself, raised on purpose from inside the rule.

    `NotAuthorized` is one uniform `403` whatever the rule was - right for the session layer,
    wrong for a product whose design requires a denial that names what was missing: "you may
    not send SMS alerts", "that district is outside the area you cover". Only the rule that
    refused knows which, so raise this - or your own subclass of it - from a `BetterAuth.require`
    predicate or a `BetterAuth.require_membership` lookup, and it reaches the client exactly as
    you built it: its status, its `detail`, its headers. Nothing is logged; it is an answer, not
    an accident.

        class MissingCapability(AuthorizationRefused):
            def __init__(self, capability: str) -> None:
                super().__init__(detail={"code": "missing_capability", "capability": capability})

    **Reachable only after authentication.** Both gates compose on `current_session`, so an
    anonymous or forged request is answered `401` before any rule runs, and this class raised by
    a verifier is contained like any other escape. The body is only ever shown to a caller whose
    credential already verified, so it is never an oracle for which credentials are accepted.

    **What it must never carry:** anything read from the credential - a token, a cookie, a
    signature, a session id - nor the upstream payload. It is the one deliberate exception to
    this library's per-status uniformity, and it is safe only because the application chose
    every byte of it, from its own rules and its own rows.

    **Why a plain `HTTPException` in a rule is still contained.** A rule calls helpers, and a
    helper's stray `404` or `500` is a bug, not a decision. Inside a rule only this class is
    honoured; anything else is logged and answered as the uniform `NotAuthorized`.

    It is not a `SessionError`: per-status uniformity is what it opts out of, so a handler you
    registered for `SessionError` never sees it, and FastAPI's own `HTTPException` handler
    renders it.

    Args:
        status_code: `403` (the default) or `404`, for a rule that would rather not confirm the
            resource exists. A `401` would tell a session that is valid to re-authenticate, a
            `400` is this library's ambiguous-credential answer, and a `5xx` is not a refusal.
        detail: The body's `detail`, any JSON-serializable value, exactly as `HTTPException`
            takes it. `None` renders the status phrase.
        headers: Extra response headers, copied at construction. They may not carry
            `WWW-Authenticate` in any spelling: the challenge belongs to authentication, and
            this session already passed it.

    Raises:
        ValueError: At construction, if `status_code` is not 403 or 404 or `headers` names
            `WWW-Authenticate`. Raised inside a rule, that is an accident like any other.
        TypeError: When a subclass is defined that sets `status_code`, `detail` or `headers`
            in its class body, where `__init__` would silently override them.
    """

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        _refuse_shadowing(
            cls,
            "set by __init__, so a class value would be silently ignored;"
            " pass them to super().__init__() instead.",
        )

    def __init__(
        self,
        status_code: int = 403,
        detail: Any = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(
            status_code=_refusal_status(status_code),
            detail=detail,
            headers=_refusal_headers(headers),
        )


def _refusal_status(status_code: object) -> int:
    if isinstance(status_code, int) and status_code in REFUSAL_STATUSES:
        return int(status_code)
    raise ValueError(
        f"AuthorizationRefused(status_code={status_code!r}) must be 403 or 404. A 401 would tell a"
        " session that already verified to re-authenticate, 400 is the ambiguous-credential"
        " answer, and any other status is not a refusal."
    )


def _refusal_headers(headers: Mapping[str, str] | None) -> dict[str, str] | None:
    if headers is None:
        return None
    copied = dict(headers)
    if any(name.strip().lower() == CHALLENGE_HEADER for name in copied):
        raise ValueError(
            "AuthorizationRefused(headers=...) may not carry WWW-Authenticate. The challenge"
            " belongs to authentication, and a session that reached a rule already passed it."
        )
    return copied
