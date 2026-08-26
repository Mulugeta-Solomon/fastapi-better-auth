"""fastapi-better-auth-bridge: verify Better Auth sessions from FastAPI.

A bridge, not a port: sessions are issued by a running TypeScript Better Auth server and
verified here. Everything importable from this module is public API; everything under
`_internal` is not.

See https://github.com/Mulugeta-Solomon/fastapi-better-auth for status.
"""

from ._internal.errors import (
    BEARER_CHALLENGE,
    AuthServiceUnavailable,
    BetterAuthError,
    ConfigurationError,
    CsrfFailure,
    InvalidCredential,
    SessionError,
    SessionExpired,
    SessionRevoked,
)
from ._internal.models import Session, User, UserT

__all__ = [
    "BEARER_CHALLENGE",
    "AuthServiceUnavailable",
    "BetterAuthError",
    "ConfigurationError",
    "CsrfFailure",
    "InvalidCredential",
    "Session",
    "SessionError",
    "SessionExpired",
    "SessionRevoked",
    "User",
    "UserT",
]

__version__ = "0.0.1"
