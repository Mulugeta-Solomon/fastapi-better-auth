"""fastapi-better-auth-bridge: verify Better Auth sessions from FastAPI.

A bridge, not a port: sessions are issued by a running TypeScript Better Auth server and
verified here. Everything importable from this module is public API; everything under
`_internal` is not.

See https://github.com/Mulugeta-Solomon/fastapi-better-auth for status.
"""

from ._internal.core import BetterAuth
from ._internal.errors import (
    BEARER_CHALLENGE,
    AmbiguousCredentials,
    AuthServiceUnavailable,
    BetterAuthError,
    ConfigurationError,
    CsrfFailure,
    InvalidCredential,
    MissingCredential,
    SessionError,
    SessionExpired,
    SessionRevoked,
)
from ._internal.httpx_transports import Httpx2Transport, HttpxTransport
from ._internal.models import Session, User, UserT
from ._internal.parsing import parse_user
from ._internal.transport import (
    ContentEncodingRejected,
    ResponseTooLarge,
    Transport,
    TransportResponse,
    UntrustedResponse,
)
from ._internal.urls import normalize_base_url
from ._internal.verifiers import Verifier

__all__ = [
    "BEARER_CHALLENGE",
    "AmbiguousCredentials",
    "AuthServiceUnavailable",
    "BetterAuth",
    "BetterAuthError",
    "ConfigurationError",
    "ContentEncodingRejected",
    "CsrfFailure",
    "Httpx2Transport",
    "HttpxTransport",
    "InvalidCredential",
    "MissingCredential",
    "ResponseTooLarge",
    "Session",
    "SessionError",
    "SessionExpired",
    "SessionRevoked",
    "Transport",
    "TransportResponse",
    "UntrustedResponse",
    "User",
    "UserT",
    "Verifier",
    "normalize_base_url",
    "parse_user",
]

__version__ = "0.0.1"
