"""Shared pieces for the opt-in 503 suites: a verifier that raises what it is handed, and the wire.

`wire()` is the whole of what a client can observe of a response - status, body bytes and every
header but `date` - so "byte for byte" is one equality rather than three assertions that could
each forget a field.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

import anyio
import httpx2
from fastapi import Depends, FastAPI
from starlette.requests import HTTPConnection

from fastapi_better_auth import BetterAuth, Session, SessionError, User

UserModelT = TypeVar("UserModelT", bound=User)

Wire = tuple[int, bytes, tuple[tuple[str, str], ...]]

UNKNOWN_CREDENTIAL_401: Wire = (
    401,
    b'{"detail":"Not authenticated"}',
    (
        ("content-length", "30"),
        ("content-type", "application/json"),
        ("www-authenticate", "Bearer"),
    ),
)


def wire(response: httpx2.Response) -> Wire:
    headers = tuple(
        sorted((name.lower(), value) for name, value in response.headers.items() if name != "date")
    )
    return response.status_code, response.content, headers


def service_unavailable(retry_after: int) -> Wire:
    """The one 503 the opt-in answers, for a given retry-after."""
    return (
        503,
        b'{"detail":"Service unavailable"}',
        (
            ("content-length", "32"),
            ("content-type", "application/json"),
            ("retry-after", str(retry_after)),
        ),
    )


class RaisingVerifier:
    """Reads one header and refuses every credential with whatever `refusal()` builds."""

    def __init__(
        self,
        header: str,
        refusal: Callable[[], SessionError],
        *,
        in_task_group: bool = False,
    ) -> None:
        self.header = header
        self.credential_source = f"header:{header}"
        self.refusal = refusal
        self.in_task_group = in_task_group
        self.verify_calls = 0

    def extract(self, connection: HTTPConnection) -> str | None:
        return connection.headers.get(self.header)

    async def verify(self, credential: str, user_model: type[UserModelT]) -> Session[UserModelT]:
        self.verify_calls += 1
        if not self.in_task_group:
            raise self.refusal()
        async with anyio.create_task_group() as group:
            group.start_soon(self._refuse)
        raise NotImplementedError

    async def _refuse(self) -> None:
        raise self.refusal()


def gated_app(auth: BetterAuth) -> FastAPI:
    """`session_app`'s two routes plus the two authorization gates, all on one bridge."""
    app = FastAPI()
    required = auth.current_session()
    optional = auth.optional_session()
    allowed = auth.require(lambda _session: True, reason="always allowed")
    refused = auth.require(lambda _session: False, reason="never allowed")

    async def member(org_id: str, session: Session[User]) -> str:
        return "member"

    scoped = auth.require_membership("org_id", member, reason="organization member")

    async def read_required(session: Session[User] = Depends(required)) -> dict[str, Any]:
        return {"id": session.user.id}

    async def read_optional(session: Session[User] | None = Depends(optional)) -> dict[str, Any]:
        return {"id": None if session is None else session.user.id}

    async def read_allowed(session: Session[User] = Depends(allowed)) -> dict[str, Any]:
        return {"id": session.user.id}

    async def read_refused(session: Session[User] = Depends(refused)) -> dict[str, Any]:
        return {"id": session.user.id}

    async def read_scoped(access: Any = Depends(scoped)) -> dict[str, Any]:
        return {"grant": access.grant}

    app.add_api_route("/required", read_required, methods=["GET"])
    app.add_api_route("/optional", read_optional, methods=["GET"])
    app.add_api_route("/allowed", read_allowed, methods=["GET"])
    app.add_api_route("/refused", read_refused, methods=["GET"])
    app.add_api_route("/orgs/{org_id}", read_scoped, methods=["GET"])
    return app


GATED_PATHS = ("/required", "/optional", "/allowed", "/refused", "/orgs/org_a")
