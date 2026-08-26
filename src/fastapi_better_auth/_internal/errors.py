"""The error taxonomy: what user code catches, and what a client is allowed to see."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import ClassVar

from fastapi import HTTPException

BEARER_CHALLENGE: Mapping[str, str] = MappingProxyType({"WWW-Authenticate": "Bearer"})


class BetterAuthError(Exception):
    """Base class for the faults this library raises outside a request.

    These are programming and deployment errors — a misconfigured verifier, a missing
    secret — not answers to a client. They are deliberately not `HTTPException`s: there
    is no status code that makes a broken configuration a client's problem.
    """


class ConfigurationError(BetterAuthError):
    """Configuration that cannot produce a safe verification.

    Raised while the application is being constructed, never while serving a request, so
    a deployment that would silently fail open never finishes starting up.
    """


class SessionError(HTTPException):
    """Base class for request-time authentication failures.

    Subclasses say *what* went wrong; `reason` says *why*, in whatever detail is useful
    to whoever is reading the logs. The response says neither. Every failure in the 401
    family renders the same body and the same headers, so a client cannot tell a bad
    signature from an expired session from an unreachable auth service, and cannot use
    the difference to probe for valid identifiers.

    `reason` is for exception handlers, logging, and metrics. It never reaches a response
    body or header, and a custom handler that renders it gives away the distinction this
    taxonomy exists to hide.

    Args:
        reason: Keyword-only, required. Never rendered to the client.
    """

    response_status: ClassVar[int] = 401
    response_detail: ClassVar[str] = "Not authenticated"
    response_headers: ClassVar[Mapping[str, str] | None] = BEARER_CHALLENGE

    reason: str

    def __init__(self, *, reason: str) -> None:
        self.reason = reason
        headers = self.response_headers
        super().__init__(
            status_code=self.response_status,
            detail=self.response_detail,
            headers=dict(headers) if headers is not None else None,
        )


class InvalidCredential(SessionError):
    """The credential was present but did not verify.

    Bad signature, malformed token, wrong issuer or audience, unknown key id. Covers
    every way a credential can be structurally or cryptographically wrong.
    """


class SessionExpired(SessionError):
    """The credential verified, but its lifetime has run out."""


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


class CsrfFailure(SessionError):
    """A cookie-authenticated request failed its cross-site request forgery check.

    403, not 401: the request carried a credential and was refused on policy grounds, so
    there is nothing for the client to re-authenticate. It gets no `WWW-Authenticate`
    challenge for the same reason.
    """

    response_status: ClassVar[int] = 403
    response_detail: ClassVar[str] = "Forbidden"
    response_headers: ClassVar[Mapping[str, str] | None] = None
