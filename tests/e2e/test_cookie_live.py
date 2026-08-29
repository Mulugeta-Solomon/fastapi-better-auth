"""Mode A against the real thing: a cookie this repository did not sign, in both topologies.

The unit lane proves the pipeline against vectors and a fake store. This lane closes the gap that
leaves - a cookie issued by a running Better Auth, carried through a real FastAPI request, and
verified against the session the same server wrote, in Postgres (`:3100`) and in Redis (`:3101`).
The revocation test is the headline: signing out on the Node side must make the very next request
401, in both topologies, because that is the property upstream's own `findSession()` cannot give
Mode B.

Composition is proven too: `BetterAuth(verifiers=[JwtVerifier(...), CookieVerifier(...)])` accepts a
bearer alone, a cookie alone, refuses both at once as `AmbiguousCredentials`, and publishes both
security schemes so `/docs` can Authorize with either.

Asyncio only: asyncpg and redis-py drive the event loop directly, so there is no trio leg.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from fastapi_better_auth import (
    BetterAuth,
    CsrfDisabled,
    HttpxTransport,
    OriginCheck,
    SharedSecret,
)
from fastapi_better_auth._internal.cookie_verifier import CookieVerifier
from fastapi_better_auth._internal.jwt_verifier import JwtVerifier
from tests.fakes import session_app

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
    from fastapi_better_auth import RedisSessionStore, SqlAlchemySessionStore
except ImportError:
    pytest.skip(
        "this build of fastapi-better-auth-bridge publishes no session stores",
        allow_module_level=True,
    )

pytestmark = pytest.mark.e2e

COOKIE_SCHEME = "BetterAuthCookie-better-auth.session_token"
BEARER_SCHEME = "BetterAuthBearer"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def secret() -> SharedSecret:
    return SharedSecret(HARNESS_SECRET)


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    built = create_async_engine(POSTGRES_URL)
    yield built
    await built.dispose()


def cookie_header(cookie: str) -> dict[str, str]:
    """The raw Cookie header the verifier reads - not httpx's cookie jar, which re-encodes."""
    return {"Cookie": f"{SESSION_COOKIE}={cookie}"}


async def drive(app: Any, **request: Any) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://bridge"
    ) as client:
        return await client.get("/required", **request)


class TestPostgresTopology:
    @pytest.mark.anyio
    async def test_a_live_cookie_authenticates_a_real_route(
        self, harness: str, secret: SharedSecret, engine: AsyncEngine
    ) -> None:
        cookie = sign_in(harness, SEED_EMAIL, SEED_PASSWORD)
        store = SqlAlchemySessionStore(engine=engine)
        await store.connect()
        auth = BetterAuth(
            verifiers=[
                CookieVerifier(
                    secret=secret,
                    store=store,
                    csrf=CsrfDisabled(reason="a GET carries no CSRF risk; the rung is unit-tested"),
                )
            ]
        )
        app = session_app(auth)

        authorized = await drive(app, headers=cookie_header(cookie))
        anonymous = await drive(app)

        assert authorized.status_code == 200, authorized.text
        assert authorized.json()["id"]
        assert anonymous.status_code == 401
        sign_out(harness, cookie)

    @pytest.mark.anyio
    async def test_signing_out_upstream_makes_the_next_request_401(
        self, harness: str, secret: SharedSecret, engine: AsyncEngine
    ) -> None:
        """Revocation, end to end: the same cookie that authenticated a moment ago is refused once
        the Node side has deleted the row - which is exactly what a JWT cannot honour until it
        expires."""
        cookie = sign_in(harness, SEED_EMAIL, SEED_PASSWORD)
        store = SqlAlchemySessionStore(engine=engine)
        auth = BetterAuth(
            verifiers=[
                CookieVerifier(
                    secret=secret, store=store, csrf=CsrfDisabled(reason="GET, unit-tested rung")
                )
            ]
        )
        app = session_app(auth)
        assert (await drive(app, headers=cookie_header(cookie))).status_code == 200

        sign_out(harness, cookie)

        assert (await drive(app, headers=cookie_header(cookie))).status_code == 401


class TestRedisTopology:
    @pytest.fixture
    async def redis_store(self) -> AsyncIterator[RedisSessionStore]:
        async with RedisSessionStore(url=REDIS_URL) as built:
            yield built

    @pytest.mark.anyio
    async def test_a_live_cookie_authenticates_from_the_raw_token_key(
        self, redis_harness: str, secret: SharedSecret, redis_store: RedisSessionStore
    ) -> None:
        cookie = sign_in(redis_harness, SEED_EMAIL, SEED_PASSWORD)
        auth = BetterAuth(
            verifiers=[
                CookieVerifier(
                    secret=secret,
                    store=redis_store,
                    csrf=CsrfDisabled(reason="GET, unit-tested rung"),
                )
            ]
        )
        app = session_app(auth)

        authorized = await drive(app, headers=cookie_header(cookie))

        assert authorized.status_code == 200, authorized.text
        assert authorized.json()["id"]
        sign_out(redis_harness, cookie)

    @pytest.mark.anyio
    async def test_signing_out_upstream_makes_the_next_request_401(
        self, redis_harness: str, secret: SharedSecret, redis_store: RedisSessionStore
    ) -> None:
        """The Redis leg of revocation: sign-out deletes the key, and there is nowhere else to
        look - the defining property of the secondary-storage topology."""
        cookie = sign_in(redis_harness, SEED_EMAIL, SEED_PASSWORD)
        auth = BetterAuth(
            verifiers=[
                CookieVerifier(
                    secret=secret,
                    store=redis_store,
                    csrf=CsrfDisabled(reason="GET, unit-tested rung"),
                )
            ]
        )
        app = session_app(auth)
        assert (await drive(app, headers=cookie_header(cookie))).status_code == 200

        sign_out(redis_harness, cookie)

        assert (await drive(app, headers=cookie_header(cookie))).status_code == 401


class TestComposition:
    @pytest.fixture
    def live_token(self, harness: str, signed_in: dict[str, str]) -> str:
        response = httpx.get(
            f"{harness}/api/auth/token", cookies={SESSION_COOKIE: signed_in["cookie"]}
        )
        assert response.status_code == 200, response.text
        token: str = response.json()["token"]
        return token

    def build(self, harness: str, secret: SharedSecret, engine: AsyncEngine, transport: Any) -> Any:
        return BetterAuth(
            verifiers=[
                JwtVerifier(base_url=harness, transport=transport),
                CookieVerifier(
                    secret=secret,
                    store=SqlAlchemySessionStore(engine=engine),
                    csrf=OriginCheck(allowed_origins=[harness]),
                ),
            ]
        )

    @pytest.mark.anyio
    async def test_bearer_alone_cookie_alone_and_both_at_once(
        self,
        harness: str,
        secret: SharedSecret,
        engine: AsyncEngine,
        signed_in: dict[str, str],
        live_token: str,
    ) -> None:
        cookie = signed_in["cookie"]
        async with HttpxTransport() as transport:
            app = session_app(self.build(harness, secret, engine, transport))
            bearer_only = await drive(app, headers={"Authorization": f"Bearer {live_token}"})
            cookie_only = await drive(app, headers=cookie_header(cookie))
            both = await drive(
                app,
                headers={"Authorization": f"Bearer {live_token}", **cookie_header(cookie)},
            )

        assert bearer_only.status_code == 200, bearer_only.text
        assert cookie_only.status_code == 200, cookie_only.text
        assert both.status_code == 400, "two credentials at once must be AmbiguousCredentials"
        assert bearer_only.json()["id"] == cookie_only.json()["id"]

    @pytest.mark.anyio
    async def test_the_document_publishes_both_schemes_ord(
        self, harness: str, secret: SharedSecret, engine: AsyncEngine
    ) -> None:
        """`/docs` can only offer an Authorize button when the document defines the scheme; both a
        bearer and an apiKey-in-cookie scheme must be published, and required on the route as an
        either/or."""
        async with HttpxTransport() as transport:
            app = session_app(self.build(harness, secret, engine, transport))
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://bridge"
            ) as client:
                document = (await client.get("/openapi.json")).json()
                docs = await client.get("/docs")

        schemes = document["components"]["securitySchemes"]
        assert schemes[BEARER_SCHEME]["type"] == "http"
        assert schemes[COOKIE_SCHEME]["type"] == "apiKey"
        assert schemes[COOKIE_SCHEME]["in"] == "cookie"
        assert schemes[COOKIE_SCHEME]["name"] == SESSION_COOKIE
        required = document["paths"]["/required"]["get"]["security"]
        named = {name for requirement in required for name in requirement}
        assert named == {BEARER_SCHEME, COOKIE_SCHEME}
        assert docs.status_code == 200
