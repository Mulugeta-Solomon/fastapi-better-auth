"""The revocation watermark, live: the bridge and upstream answer the same, on every version.

"Revoke all sessions" deletes each session key and, since better-auth 1.7.16, also writes
`revoked-sessions-before-<userId>`. Upstream's own read refuses a session created before that
watermark even when its key is still in Redis - which is the state the watermark exists for: a
key that outlived the revocation (a failed delete, a replica, a refresh racing it).

Written as a differential, so it is true on every better-auth version without naming one: build
that state against the running Redis-profile server, then ask both readers. On a version with no
watermark both accept the surviving key; on 1.7.16+ both refuse it. What must never happen is
upstream refusing a session the bridge accepts. The plain case - revoke, and put nothing back -
is pinned beside it: both refuse.

Asyncio only: redis-py drives the event loop directly.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import anyio
import httpx
import pytest

from .conftest import (
    PASSWORD,
    REDIS_URL,
    SESSION_COOKIE,
    headers,
    raw_token,
    sign_in,
    sign_up,
)

try:
    from fastapi_better_auth import RedisSessionStore
except ImportError:
    pytest.skip(
        "this build of fastapi-better-auth-bridge publishes no session stores",
        allow_module_level=True,
    )

import redis.asyncio as aioredis

pytestmark = pytest.mark.e2e

DELETE_DEADLINE_SECONDS = 5.0
"""How long upstream gets to delete the revoked key. It deletes in an after-transaction hook, so
putting the document back before that delete lands would test nothing at all."""
POLL_SECONDS = 0.05
FRESH_READ = {"disableCookieCache": "true", "disableRefresh": "true"}
"""Upstream's own read, with neither its cookie cache nor a refresh write in the way."""


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def redis_store() -> AsyncIterator[RedisSessionStore]:
    async with RedisSessionStore(url=REDIS_URL) as built:
        yield built


@pytest.fixture
async def raw() -> AsyncIterator[aioredis.Redis]:
    client = aioredis.from_url(REDIS_URL)
    try:
        yield client
    finally:
        await client.aclose()


def revoke_all(base: str, cookie: str) -> None:
    resp = httpx.post(
        f"{base}/api/auth/revoke-sessions",
        json={},
        cookies={SESSION_COOKIE: cookie},
        headers=headers(base),
    )
    assert resp.status_code == 200, resp.text


def upstream_accepts(base: str, cookie: str, token: str) -> bool:
    resp = httpx.get(
        f"{base}/api/auth/get-session",
        params=FRESH_READ,
        cookies={SESSION_COOKIE: cookie},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    if body is None:
        return False
    assert body["session"]["token"] == token, "upstream answered for a different session"
    return True


async def gone(raw: aioredis.Redis, key: str) -> None:
    with anyio.fail_after(DELETE_DEADLINE_SECONDS):
        while await raw.exists(key):
            await anyio.sleep(POLL_SECONDS)


async def signed_in_session(base: str, raw: aioredis.Redis) -> tuple[str, str, bytes, int]:
    _user_id, email = sign_up(base, "watermark")
    cookie = sign_in(base, email, PASSWORD)
    token = raw_token(cookie)
    document = await raw.get(token)
    lifetime = await raw.pttl(token)
    assert isinstance(document, bytes), "the session is not in secondary storage"
    assert lifetime > 0, "the session key carries no TTL"
    return cookie, token, document, lifetime


class TestRevokeAllSessions:
    @pytest.mark.anyio
    async def test_a_key_that_outlived_the_revocation_gets_upstreams_answer(
        self, redis_harness: str, redis_store: RedisSessionStore, raw: aioredis.Redis
    ) -> None:
        cookie, token, document, lifetime = await signed_in_session(redis_harness, raw)
        assert await redis_store.fetch_session_by_token(token) is not None
        assert upstream_accepts(redis_harness, cookie, token)
        try:
            revoke_all(redis_harness, cookie)
            await gone(raw, token)
            await raw.set(token, document, px=lifetime)
            assert await raw.get(token) == document, "the surviving key was not put back"

            # The bridge first: upstream's refusal path may clean up after itself.
            bridge = await redis_store.fetch_session_by_token(token) is not None
            upstream = upstream_accepts(redis_harness, cookie, token)
        finally:
            await raw.delete(token)

        assert bridge == upstream, (
            f"upstream {'accepts' if upstream else 'refuses'} the surviving session and the"
            f" bridge {'accepts' if bridge else 'refuses'} it"
        )

    @pytest.mark.anyio
    async def test_a_revocation_nothing_survived_is_refused_by_both(
        self, redis_harness: str, redis_store: RedisSessionStore, raw: aioredis.Redis
    ) -> None:
        cookie, token, _document, _lifetime = await signed_in_session(redis_harness, raw)

        revoke_all(redis_harness, cookie)
        await gone(raw, token)

        assert await redis_store.fetch_session_by_token(token) is None
        assert not upstream_accepts(redis_harness, cookie, token)
