"""Fake verifiers — WP3 ships the dispatcher, not a mode.

A fake reads its credential from one header and compares it to one expected value, which
exercises every dispatch rule without a key, a clock or a network. Every fake materializes
its user through `parse_user`, so the containment contract is exercised for real rather
than described, and every fake counts its own calls, so "exactly one verification" is an
assertion rather than a hope.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime, timezone
from typing import Any, TypeVar

from fastapi import Depends, FastAPI, params
from starlette.requests import HTTPConnection

from fastapi_better_auth import BetterAuth, InvalidCredential, Session, SessionError, User
from fastapi_better_auth._internal.parsing import parse_user

UserModelT = TypeVar("UserModelT", bound=User)

EXPIRES_AT = datetime(2026, 9, 1, tzinfo=timezone.utc)
GOOD_CREDENTIAL = "good-credential"
BAD_CREDENTIAL = "forged-credential"
VALID_PAYLOAD: Mapping[str, Any] = {"id": "u1", "email": "seed@example.com"}


class FakeVerifier:
    """Extracts one header, accepts one credential value, counts both calls."""

    def __init__(
        self,
        header: str,
        *,
        accepts: str = GOOD_CREDENTIAL,
        payload: Mapping[str, Any] | None = None,
        log: list[str] | None = None,
    ) -> None:
        self.header = header
        self.accepts = accepts
        self.payload: Mapping[str, Any] = VALID_PAYLOAD if payload is None else payload
        self.log = log
        self.extract_calls = 0
        self.verify_calls = 0

    def extract(self, connection: HTTPConnection) -> str | None:
        self.extract_calls += 1
        if self.log is not None:
            self.log.append(f"extract:{self.header}")
        return connection.headers.get(self.header)

    async def verify(self, credential: str, user_model: type[UserModelT]) -> Session[UserModelT]:
        self.verify_calls += 1
        if self.log is not None:
            self.log.append(f"verify:{self.header}")
        if credential != self.accepts:
            raise InvalidCredential(reason=f"fake {self.header} rejected len={len(credential)}")
        return Session(
            user=parse_user(user_model, self.payload),
            expires_at=EXPIRES_AT,
            raw=dict(self.payload),
        )


class FailingVerifier:
    """Always presents a credential, always fails it — the terminal-failure half."""

    def __init__(self, header: str, error_cls: type[SessionError], reason: str) -> None:
        self.header = header
        self.error_cls = error_cls
        self.reason = reason
        self.extract_calls = 0
        self.verify_calls = 0

    def extract(self, connection: HTTPConnection) -> str | None:
        self.extract_calls += 1
        return connection.headers.get(self.header)

    async def verify(self, credential: str, user_model: type[UserModelT]) -> Session[UserModelT]:
        self.verify_calls += 1
        raise self.error_cls(reason=self.reason)


class AsyncExtractVerifier:
    """Structurally a verifier, but `extract` is a coroutine function.

    Every call would return a truthy coroutine object, so every verifier would look
    "present" and every request would be ambiguous. Rejected at construction.
    """

    async def extract(self, connection: HTTPConnection) -> str | None:
        return connection.headers.get("x-async")

    async def verify(self, credential: str, user_model: type[UserModelT]) -> Session[UserModelT]:
        raise NotImplementedError


class SyncVerifyVerifier:
    """`verify` is not awaitable; awaiting it would be a request-time 500."""

    def extract(self, connection: HTTPConnection) -> str | None:
        return connection.headers.get("x-sync")

    def verify(self, credential: str, user_model: type[UserModelT]) -> Session[UserModelT]:
        raise NotImplementedError


class NotAVerifier:
    """Neither method: the shape a typo or a half-written class produces."""


def connection(**headers: str) -> HTTPConnection:
    """A minimal ASGI connection — enough for `extract`, and nothing a verifier may read."""
    raw = [(key.replace("_", "-").encode(), value.encode()) for key, value in headers.items()]
    return HTTPConnection({"type": "http", "method": "GET", "path": "/", "headers": raw})


def resolver_of(dependency: Callable[..., Any]) -> Callable[..., Awaitable[Session[Any] | None]]:
    """The shared cache anchor, read exactly the way FastAPI reads it.

    `current_session` and `optional_session` both hang off one resolver; FastAPI finds it
    through the wrapper's `Depends` default, so reading it the same way means a break here
    is a break in the per-request cache too.
    """
    default = inspect.signature(dependency).parameters["session"].default
    assert isinstance(default, params.Depends), "the wrapper no longer anchors on a resolver"
    anchored = default.dependency
    assert anchored is not None
    return anchored


def session_app(auth: BetterAuth, *, user_model: type[User] = User) -> FastAPI:
    """One app carrying both dependencies, so a dispatch rule is observable on the wire."""
    app = FastAPI()
    required = auth.current_session(user_model=user_model)
    optional = auth.optional_session(user_model=user_model)

    async def read_required(session: Session[User] = Depends(required)) -> dict[str, Any]:
        return {"id": session.user.id, "model": type(session.user).__name__}

    async def read_optional(session: Session[User] | None = Depends(optional)) -> dict[str, Any]:
        if session is None:
            return {"id": None, "model": None}
        return {"id": session.user.id, "model": type(session.user).__name__}

    app.add_api_route("/required", read_required, methods=["GET"])
    app.add_api_route("/optional", read_optional, methods=["GET"])
    return app
