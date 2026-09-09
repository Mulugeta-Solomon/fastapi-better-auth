"""Shared fixtures for the Mode C suites: the document, the doubles, and the builder.

`document()` is the `get-session` body a scripted upstream answers and `sign()` mints the signed
cookie value the way better-auth does. `RecordingTransport` snapshots each outbound header set
before the verifier scrubs it (D-094), `NullStore` is the least `SessionStore` a `CookieVerifier`
needs, and `verifier()` builds a `RemoteVerifier` with the readiness probe already marked passed,
so the suites pin the post-readiness pipeline and `transport.calls` counts fetches alone.
`request()`, `raw_request()`, `run()` and `with_cookie()` drive it the way FastAPI would.

Four suites read one copy of each rather than four that could drift: `test_remote_verifier.py`
(construction, `extract`, composition, the guards), `test_remote_verifier_pipeline.py` (the
outcome table, the closed outbound set, the rungs, bans), `test_remote_verifier_gates.py` (the
WP15 gates: cache, latch, limiter) and `test_remote_verifier_hygiene.py` (chaining, reasons and
frame locals). `test_remote_startup.py` and `test_remote_backoff.py` keep the smaller doubles they
were written with.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any

import anyio
from starlette.requests import HTTPConnection

from fastapi_better_auth import CsrfDisabled, SharedSecret, StoredSession, StoredUser, User
from fastapi_better_auth._internal.remote_verifier import RemoteVerifier
from tests.transports import ScriptedTransport

ORIGIN = "https://auth.example.com"
COOKIE_NAME = "better-auth.session_token"
SECURE_NAME = "__Secure-better-auth.session_token"
APP = "https://app.example.com"
EVIL = "https://evil.example.com"
URI = f"{ORIGIN}/api/auth/get-session?disableCookieCache=true&disableRefresh=true"

SECRET_VALUE = "Zq7Xm2vTz6Lp1RkYd9Wn4Hs7Cj3Fg5Ae"
OTHER_VALUE = "Nf4Wq7zC2mVt9Bs5Kx1Ld8Hj6Yr3Pg0Zx"
SECRET = SharedSecret(SECRET_VALUE)
TOKEN = "SBYZ1bzGdkhXcLuqsW70JjhvmIY4PU3B"
USER_ID = "u1"
FAR_FUTURE = "2999-01-01T00:00:00.000Z"
FAR_PAST = "2000-01-01T00:00:00.000Z"


def sign(token: str, secret_value: str = SECRET_VALUE) -> str:
    digest = hmac.new(secret_value.encode(), token.encode(), hashlib.sha256).digest()
    return f"{token}.{base64.b64encode(digest).decode()}"


COOKIE_VALUE = sign(TOKEN)


def document(
    *, token: str = TOKEN, user_id: str = USER_ID, expires: str = FAR_FUTURE, **user_over: Any
) -> dict[str, Any]:
    session = {
        "id": "sess",
        "token": token,
        "userId": user_id,
        "expiresAt": expires,
        "impersonatedBy": None,
    }
    user: dict[str, Any] = {
        "id": user_id,
        "email": "seed@example.com",
        "banned": False,
        "banExpires": None,
    }
    user.update(user_over)
    return {"session": session, "user": user}


class RecordingTransport(ScriptedTransport):
    """A `ScriptedTransport` that snapshots each request's outbound headers before they are scrubbed.

    The verifier clears the header dict in `finally` (D-094), and the base double appends the *live*
    dict, so `.headers[0]` reads empty after a call. `.sent` holds a copy taken at call time, which
    is what the closed-header-set assertions read.
    """

    def __init__(self, *answers: Any, gate: anyio.Event | None = None) -> None:
        super().__init__(*answers, gate=gate)
        self.sent: list[dict[str, str] | None] = []

    async def get(self, url: str, *, headers: Any = None, max_bytes: int) -> Any:
        self.sent.append(None if headers is None else dict(headers))
        return await super().get(url, headers=headers, max_bytes=max_bytes)


class NullStore:
    """The minimal `SessionStore` a `CookieVerifier` needs so the A+C collision can be built."""

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        return None

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        return None


def verifier(transport: ScriptedTransport, **kwargs: Any) -> RemoteVerifier:
    kwargs.setdefault("csrf", CsrfDisabled(reason="core pipeline tests do not exercise CSRF"))
    kwargs.setdefault("secure_cookies", False)
    built = RemoteVerifier(base_url=ORIGIN, transport=transport, **kwargs)
    # A scripted double answers every request the same, so an unwarmed probe would read the row's
    # own document as a dead jar and never reach the fetch. The probe has its own suite.
    built._probed_ok = True  # pyright: ignore[reportPrivateUsage]
    return built


def request(
    method: str = "GET", *, cookies: tuple[str, ...] = (), **headers: str
) -> HTTPConnection:
    raw = [(b"cookie", value.encode()) for value in cookies]
    raw += [(key.replace("_", "-").encode(), value.encode()) for key, value in headers.items()]
    return HTTPConnection({"type": "http", "method": method, "path": "/x", "headers": raw})


def raw_request(cookies: tuple[str, ...], header_items: list[tuple[str, str]]) -> HTTPConnection:
    raw = [(b"cookie", value.encode()) for value in cookies]
    raw += [(name.encode("latin-1"), value.encode("latin-1")) for name, value in header_items]
    return HTTPConnection({"type": "http", "method": "GET", "path": "/x", "headers": raw})


async def run(v: RemoteVerifier, connection: HTTPConnection, model: type[User] = User) -> Any:
    credential = v.extract(connection)
    if credential is None:
        return None
    return await v.verify(credential, model)


def with_cookie(value: str = COOKIE_VALUE, name: str = COOKIE_NAME) -> HTTPConnection:
    return request(cookies=(f"{name}={value}",))
