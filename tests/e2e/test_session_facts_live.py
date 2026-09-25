"""`Session.id`, `.cookie` and `.origin` against a live Better Auth, and the forward they exist for.

The unit lane proves where each fact comes from against doubles. This lane asks the server that
issued the session whether they are *its* facts: the id is the one it stored - the Postgres row on
`:3100`, the Redis document on `:3101` - and the cookie, sent back to its own `get-session`, names
the same session. Both cookie modes run in both topologies.

Then the use case the three fields were added for (#83, #85): the README's own `revoke_upstream`,
run against the harness. Better Auth trusts only its own `baseURL` here (the harness configures no
`trustedOrigins`), so the harness origin is put in `allowed_origins` beside a front end it does not
trust. Forwarded with the trusted one, `/revoke-session` deletes the session and the very next
request is a 401; forwarded with the untrusted one, Better Auth refuses and the session lives - the
README's "must be in `trustedOrigins` as well", observed rather than asserted.

Every cookie here is held as a `SecretStr` and revealed only inside the call that sends it, so a
failure rendered with `--tb=long -l` shows masks. Asyncio only: asyncpg and redis-py drive the loop.
"""

from __future__ import annotations

import json
import urllib.parse
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any, cast

import httpx
import pytest
from fastapi import Depends, FastAPI
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from fastapi_better_auth import BetterAuth, HttpxTransport, Session, SharedSecret, User

from .conftest import (
    HARNESS_SECRET,
    POSTGRES_URL,
    REDIS_URL,
    SEED_EMAIL,
    SEED_PASSWORD,
    SESSION_COOKIE,
    sign_in,
    sign_out,
)

try:
    # Every name here post-dates 0.1.0; the canary's published-wheel leg installs the last
    # release, so an unguarded import would kill the lane this guard keeps green.
    from fastapi_better_auth import (
        CookieVerifier,
        OriginCheck,
        RedisSessionStore,
        RemoteVerifier,
        SqlAlchemySessionStore,
    )
    from tests.test_readme import FORWARD, SESSION_FACTS, fences_under
    from tests.test_readme import run as run_fence
except ImportError:
    pytest.skip(
        "this build of fastapi-better-auth-bridge publishes no cookie modes",
        allow_module_level=True,
    )

if not {"id", "cookie", "origin"} <= set(Session.model_fields):
    pytest.skip(
        "this build of fastapi-better-auth-bridge predates Session.id/.cookie/.origin",
        allow_module_level=True,
    )

pytestmark = pytest.mark.e2e

FRONT_END = "https://app.example.com"
"""An origin this side allows and the harness does not trust."""
POSTURES = (("A", "postgres"), ("A", "redis"), ("C", "postgres"), ("C", "redis"))
POSTURE_IDS = [f"mode-{mode}-{topology}" for mode, topology in POSTURES]

Forward = Callable[[httpx.AsyncClient, Session[User], SecretStr], Awaitable[httpx.Response | None]]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass(frozen=True)
class Live:
    """One cookie mode over one harness topology, allowing the harness origin and `FRONT_END`."""

    mode: str
    topology: str
    base: str
    policy: OriginCheck
    auth: BetterAuth


@pytest.fixture(params=POSTURES, ids=POSTURE_IDS)
async def live(request: pytest.FixtureRequest) -> AsyncIterator[Live]:
    mode, topology = cast("tuple[str, str]", request.param)
    base = cast(
        "str", request.getfixturevalue("harness" if topology == "postgres" else "redis_harness")
    )
    policy = OriginCheck(allowed_origins=[base, FRONT_END])
    async with AsyncExitStack() as stack:
        verifier: CookieVerifier | RemoteVerifier
        if mode == "A":
            if topology == "postgres":
                engine = create_async_engine(POSTGRES_URL)
                stack.push_async_callback(engine.dispose)
                store: Any = SqlAlchemySessionStore(engine=engine)
            else:
                store = await stack.enter_async_context(RedisSessionStore(url=REDIS_URL))
            verifier = CookieVerifier(
                secret=SharedSecret(HARNESS_SECRET), store=store, csrf=policy, secure_cookies=False
            )
        else:
            transport = await stack.enter_async_context(HttpxTransport())
            verifier = RemoteVerifier(
                base_url=base, csrf=policy, transport=transport, secure_cookies=False
            )
        yield Live(mode, topology, base, policy, BetterAuth(verifiers=[verifier]))


def facts_app(auth: BetterAuth) -> tuple[FastAPI, list[Session[User]]]:
    """One route on a safe and an unsafe method, keeping every session it is handed."""
    seen: list[Session[User]] = []
    app = FastAPI()
    required = auth.current_session()

    async def facts(session: Session[User] = Depends(required)) -> dict[str, str]:
        seen.append(session)
        return {"id": session.user.id}

    app.add_api_route("/facts", facts, methods=["GET", "POST"])
    return app, seen


async def call(app: FastAPI, method: str, cookie: SecretStr, origin: str | None = None) -> int:
    """The browser's request to this service: the raw cookie header, and an `Origin` if given."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://bridge"
    ) as client:
        response = await client.request(
            method,
            "/facts",
            headers={
                "Cookie": f"{SESSION_COOKIE}={cookie.get_secret_value()}",
                **({} if origin is None else {"Origin": origin}),
            },
        )
    return response.status_code


def signed_in(base: str) -> SecretStr:
    """A fresh session for the seed user, masked from the moment it exists."""
    return SecretStr(sign_in(base, SEED_EMAIL, SEED_PASSWORD))


async def stored_id(live: Live, cookie: SecretStr) -> str | None:
    """The session's id where the server stored it: the Postgres row, or the Redis document."""
    if live.topology == "postgres":
        engine = create_async_engine(POSTGRES_URL)
        try:
            async with engine.connect() as connection:
                found = await connection.execute(
                    text('SELECT "id" FROM "session" WHERE "token" = :token'),
                    {"token": urllib.parse.unquote(cookie.get_secret_value()).rpartition(".")[0]},
                )
                return cast("str | None", found.scalar())
        finally:
            await engine.dispose()
    import redis.asyncio as aioredis

    client = aioredis.from_url(REDIS_URL)
    try:
        stored = await client.get(
            urllib.parse.unquote(cookie.get_secret_value()).rpartition(".")[0]
        )
    finally:
        await client.aclose()
    return None if stored is None else cast("str", json.loads(stored)["session"]["id"])


async def upstream_answer(
    base: str, pair: tuple[str, SecretStr]
) -> tuple[int, str | None, str | None]:
    """`session.cookie`, sent back as `Cookie: {name}={value}` to the server's own get-session."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{base}/api/auth/get-session?disableCookieCache=true",
            headers={"Cookie": f"{pair[0]}={pair[1].get_secret_value()}"},
        )
    document: object = response.json() if response.status_code == 200 else None
    if not isinstance(document, dict):
        return response.status_code, None, None
    found = cast("dict[str, dict[str, str]]", document)
    return response.status_code, found["session"]["id"], found["user"]["id"]


def readme_forward(base: str) -> Forward:
    """The README's own `revoke_upstream`, pointed at this harness instead of the page's example."""
    (fence,) = fences_under(SESSION_FACTS)
    namespace = run_fence(fence)
    namespace["BETTER_AUTH_URL"] = base
    return cast("Forward", namespace[FORWARD])


async def forward(live: Live, session: Session[User]) -> httpx.Response | None:
    assert session.token is not None
    async with httpx.AsyncClient() as client:
        return await readme_forward(live.base)(client, session, session.token)


class TestTheFactsAreTheServers:
    @pytest.mark.anyio
    async def test_id_cookie_and_origin_are_what_better_auth_holds(self, live: Live) -> None:
        cookie = signed_in(live.base)
        app, seen = facts_app(live.auth)

        assert await call(app, "POST", cookie, origin=live.base) == 200
        (session,) = seen
        assert session.cookie is not None
        assert session.cookie == (SESSION_COOKIE, cookie)
        assert session.origin is live.policy.allowed_origins[0]
        assert session.id is not None
        assert session.id == await stored_id(live, cookie)
        assert await upstream_answer(live.base, session.cookie) == (
            200,
            session.id,
            session.user.id,
        )
        sign_out(live.base, cookie.get_secret_value())

    @pytest.mark.anyio
    async def test_a_get_carries_no_origin_and_the_recipe_forwards_nothing(
        self, live: Live
    ) -> None:
        cookie = signed_in(live.base)
        app, seen = facts_app(live.auth)

        assert await call(app, "GET", cookie, origin=live.base) == 200
        assert seen[0].origin is None
        assert seen[0].cookie == (SESSION_COOKIE, cookie)
        assert await forward(live, seen[0]) is None
        assert await call(app, "POST", cookie, origin=live.base) == 200, "nothing was revoked"
        sign_out(live.base, cookie.get_secret_value())


class TestTheReadmeForward:
    @pytest.mark.anyio
    async def test_forwarded_with_the_matched_origin_it_revokes_and_the_next_request_is_401(
        self, live: Live
    ) -> None:
        cookie = signed_in(live.base)
        app, seen = facts_app(live.auth)
        assert await call(app, "POST", cookie, origin=live.base) == 200

        answer = await forward(live, seen[0])

        assert answer is not None
        assert (answer.status_code, answer.json()) == (200, {"status": True})
        assert await call(app, "POST", cookie, origin=live.base) == 401
        assert await upstream_answer(live.base, (SESSION_COOKIE, cookie)) == (200, None, None)

    @pytest.mark.anyio
    async def test_forwarded_with_an_origin_better_auth_does_not_trust_it_is_refused_upstream(
        self, live: Live
    ) -> None:
        """Allowed here, untrusted there: Better Auth's origin check refuses, and the session
        lives on - which is why the README says the origin must be on both lists."""
        cookie = signed_in(live.base)
        app, seen = facts_app(live.auth)
        assert await call(app, "POST", cookie, origin=FRONT_END) == 200
        assert seen[0].origin is live.policy.allowed_origins[1]

        answer = await forward(live, seen[0])

        assert answer is not None
        assert (answer.status_code, answer.json()["code"]) == (403, "INVALID_ORIGIN")
        assert await call(app, "POST", cookie, origin=live.base) == 200, "nothing was revoked"
        sign_out(live.base, cookie.get_secret_value())
