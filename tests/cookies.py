"""The cookie lane's shared fixtures: the golden vector, a fake store, and the pipeline drivers.

The peer of `tests/tokens.py` (bearer lane) and `tests/stores.py` (store lane). Everything here
was written for `test_cookie_verifier.py` and lives out here because the ban suite needs the same
seeded store and the same `extract` -> `verify` driver, and a suite file that reaches into another
suite file for its fixtures is one refactor away from breaking both.

`cookie_v1.json` is a real Better Auth cookie captured from the live harness, its secret included,
so `sign` here produces exactly the value upstream's own signer produces - which is what makes a
negative built by editing one character a proof rather than a guess.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import pathlib
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    CsrfDisabled,
    Session,
    SharedSecret,
    StoredSession,
    StoredUser,
    User,
)
from fastapi_better_auth._internal.cookie_verifier import CookieVerifier

VECTOR_DIR = pathlib.Path(__file__).parent / "vectors"
COOKIE_DOC: dict[str, Any] = json.loads((VECTOR_DIR / "cookie_v1.json").read_text())
VECTOR_SECRET_VALUE: str = COOKIE_DOC["secret"]

COOKIE = "better-auth.session_token"
SECURE = "__Secure-better-auth.session_token"
APP = "https://app.example.com"
EVIL = "https://evil.example.com"

SECRET = SharedSecret(VECTOR_SECRET_VALUE)
OTHER_SECRET = SharedSecret("Nf4Wq7zC2mVt9Bs5Kx1Ld8Hj6Yr3Pg0Zx")
CSRF_SECRET = SharedSecret("Qb8Xm2vTz6Lp1RkYd9Wn4Hs7Cj3Fg5Ae")

FAR_FUTURE = datetime(2999, 1, 1, tzinfo=timezone.utc)
FAR_PAST = datetime(2000, 1, 1, tzinfo=timezone.utc)

CAPTURED_TOKEN = "SBYZ1bzGdkhXcLuqsW70JjhvmIY4PU3B"
DOTTED_TOKEN = "prefix.SBYZ1bzGdkhXcLuqsW70JjhvmIY4PU3B"
USER_ID = "u1"
USER_PAYLOAD: Mapping[str, Any] = {"id": USER_ID, "email": "seed@example.com"}


class FakeStore:
    """A `SessionStore` that answers from two dicts and counts every call it is given."""

    def __init__(
        self,
        *,
        sessions: Mapping[str, StoredSession] | None = None,
        users: Mapping[str, StoredUser] | None = None,
        session_error: BaseException | None = None,
        user_error: BaseException | None = None,
    ) -> None:
        self.sessions = dict(sessions or {})
        self.users = dict(users or {})
        self.session_error = session_error
        self.user_error = user_error
        self.session_calls: list[str] = []
        self.user_calls: list[str] = []

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        self.session_calls.append(token)
        if self.session_error is not None:
            raise self.session_error
        return self.sessions.get(token)

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        self.user_calls.append(user_id)
        if self.user_error is not None:
            raise self.user_error
        return self.users.get(user_id)


def stored_user(**overrides: Any) -> StoredUser:
    fields: dict[str, Any] = {"id": USER_ID, "payload": dict(USER_PAYLOAD)}
    fields.update(overrides)
    return StoredUser(**fields)


_UNSET: Any = object()


def stored_session(
    token: str, *, expires_at: datetime = FAR_FUTURE, user: Any = _UNSET, **overrides: Any
) -> StoredSession:
    payload: dict[str, Any] = {"id": "sess", "userId": USER_ID, "token": token}
    payload.update(overrides.pop("payload", {}))
    fields: dict[str, Any] = {
        "token": token,
        "user_id": USER_ID,
        "expires_at": expires_at,
        "payload": payload,
        "user": stored_user() if user is _UNSET else user,
    }
    fields.update(overrides)
    return StoredSession(**fields)


def seeded_store() -> FakeStore:
    return FakeStore(
        sessions={
            CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN),
            DOTTED_TOKEN: stored_session(DOTTED_TOKEN),
        }
    )


def sign(token: str, secret: bytes = b"") -> str:
    key = secret or VECTOR_SECRET_VALUE.encode()
    digest = hmac.new(key, token.encode(), hashlib.sha256).digest()
    return f"{token}.{base64.b64encode(digest).decode()}"


def http(method: str = "GET", *, cookie: str | None = None, **headers: str) -> HTTPConnection:
    raw = [(key.replace("_", "-").encode(), value.encode()) for key, value in headers.items()]
    if cookie is not None:
        raw.append((b"cookie", cookie.encode()))
    return HTTPConnection({"type": "http", "method": method, "path": "/", "headers": raw})


def verifier(*, store: FakeStore | None = None, csrf: Any = None, **kwargs: Any) -> CookieVerifier:
    # The golden vector and the live http harness both set the PLAIN cookie name (better-auth
    # emits `__Secure-` only over https), so the cookie lane models a plain-name deployment:
    # secure_cookies=False. The secure default (True) is exercised in test_secure_cookies.py.
    return CookieVerifier(
        secret=kwargs.pop("secret", SECRET),
        store=seeded_store() if store is None else store,
        csrf=CsrfDisabled(reason="signature tests do not exercise CSRF") if csrf is None else csrf,
        secure_cookies=kwargs.pop("secure_cookies", False),
        **kwargs,
    )


async def run(
    verifier: CookieVerifier, connection: HTTPConnection, model: type[User] = User
) -> Session[User] | None:
    credential = verifier.extract(connection)
    if credential is None:
        return None
    return await verifier.verify(credential, model)
