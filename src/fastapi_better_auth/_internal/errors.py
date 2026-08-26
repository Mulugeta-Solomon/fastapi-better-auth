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


def _rebuild(error_cls: type[SessionError], reason: str) -> SessionError:
    return error_cls(reason=reason)


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
        shadowed = [name for name in SHADOWED_ATTRIBUTES if name in cls.__dict__]
        if shadowed:
            raise TypeError(
                f"{cls.__name__} sets {', '.join(shadowed)} in its class body. Those are"
                " instance attributes and would silently win over the response constants;"
                " set response_status / response_detail / response_headers instead."
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


class AmbiguousCredentials(SessionError):
    """Two or more credentials arrived on one request.

    400, not 401: what is wrong is the shape of the request, not the identity behind it.
    The client already knows it sent two credentials, so being told so teaches it nothing
    it could not have worked out - no oracle is created - and there is nothing for it to
    re-authenticate, so it gets no `WWW-Authenticate` challenge either.

    It is still a `SessionError`, so `except SessionError` remains "every request-time
    failure this library raises".

    Raised before any verification happens. Picking one of the two credentials to verify
    would let a client choose which verifier answers, and trying both in turn is the
    fallthrough this library refuses to do.
    """

    response_status: ClassVar[int] = 400
    response_detail: ClassVar[str] = "Ambiguous request"
    response_headers: ClassVar[Mapping[str, str] | None] = None
