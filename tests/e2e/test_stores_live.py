"""The stores against the real thing: sessions this repository did not write, in both topologies.

The unit lane proves the rules against a schema we built and values we invented. This lane closes
the gap that leaves - a session created by a running Better Auth, read back through the store,
and then *revoked* by that same server so the miss is upstream's decision and not ours. Both
topologies run, because they are two different truths: `:3100` keeps sessions in Postgres, and
`:3101` keeps them in Redis and may never write the Postgres row at all.

Asyncio only. `asyncpg` and `redis-py` both drive the event loop directly, so there is no trio
leg of this lane to run; `SyncStoreAdapter`, which has no such constraint, is exercised on both
backends in the unit lane.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from fastapi_better_auth import User, parse_user

from .conftest import (
    ADMIN_EMAIL,
    ADMIN_PASSWORD,
    PASSWORD,
    POSTGRES_URL,
    REDIS_URL,
    SEED_EMAIL,
    SEED_PASSWORD,
    admin_post,
    raw_token,
    sign_in,
    sign_out,
    sign_up,
)

try:
    from fastapi_better_auth import RedisSessionStore, SqlAlchemySessionStore
except ImportError:
    # The canary's published-wheel leg installs the *last release* from PyPI, and every release
    # before 0.2.0 publishes no stores at all. Skipping is the honest answer there and cannot
    # hide a regression in the gating lane, which always runs against this working tree.
    pytest.skip(
        "this build of fastapi-better-auth-bridge publishes no session stores",
        allow_module_level=True,
    )

pytestmark = pytest.mark.e2e


@pytest.fixture
def anyio_backend() -> str:
    """asyncpg and redis-py are asyncio libraries; there is no trio leg of this lane."""
    return "asyncio"


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    built = create_async_engine(POSTGRES_URL)
    yield built
    await built.dispose()


@pytest.fixture
async def store(engine: AsyncEngine) -> SqlAlchemySessionStore:
    return SqlAlchemySessionStore(engine=engine)


@pytest.fixture
async def redis_store() -> AsyncIterator[RedisSessionStore]:
    async with RedisSessionStore(url=REDIS_URL) as built:
        yield built


async def _scalar(engine: AsyncEngine, sql: str, **params: str) -> object:
    async with engine.connect() as connection:
        return (await connection.execute(text(sql), params)).scalar()


class TestPostgresTopology:
    @pytest.mark.anyio
    async def test_the_live_schema_needs_no_configuration_and_reports_no_drift(
        self, harness: str, store: SqlAlchemySessionStore, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The defaults are the migrated schema. If upstream ever renames a column or drops one,
        this is where it says so - and the day it does, the warning names it."""
        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            await store.connect()

        assert caplog.records == [], [entry.getMessage() for entry in caplog.records]

    @pytest.mark.anyio
    async def test_a_session_this_repository_did_not_write_is_read_back_whole(
        self, harness: str, store: SqlAlchemySessionStore
    ) -> None:
        cookie = sign_in(harness, SEED_EMAIL, SEED_PASSWORD)
        token = raw_token(cookie)

        record = await store.fetch_session_by_token(token)

        assert record is not None
        assert record.token == token
        assert record.expires_at.tzinfo is not None
        assert record.payload["userAgent"]
        assert record.impersonated_by is None
        assert record.user is not None
        assert record.user.id == record.user_id
        assert record.user.banned is False
        assert record.user.payload["email"] == SEED_EMAIL
        assert parse_user(User, record.user.payload).email == SEED_EMAIL
        sign_out(harness, cookie)

    @pytest.mark.anyio
    async def test_signing_out_upstream_makes_the_very_next_fetch_a_miss(
        self, harness: str, store: SqlAlchemySessionStore
    ) -> None:
        """Revocation, end to end and in that order: the same token that answered a record a
        moment ago answers nothing once the Node side has deleted the row."""
        cookie = sign_in(harness, SEED_EMAIL, SEED_PASSWORD)
        token = raw_token(cookie)
        assert await store.fetch_session_by_token(token) is not None

        sign_out(harness, cookie)

        assert await store.fetch_session_by_token(token) is None

    @pytest.mark.anyio
    async def test_it_reads_a_user_row_on_its_own(
        self, harness: str, store: SqlAlchemySessionStore
    ) -> None:
        identifier, email = sign_up(harness, "reader")

        record = await store.fetch_user_by_id(identifier)

        assert record is not None
        assert record.id == identifier
        assert record.payload["email"] == email
        assert record.banned is False
        assert record.ban_expires is None

    @pytest.mark.anyio
    async def test_a_forged_token_is_a_miss_and_not_an_error(
        self, harness: str, store: SqlAlchemySessionStore
    ) -> None:
        assert await store.fetch_session_by_token("qsq0Az8RvXbLmT4hNcJyKdEpWfUgV2Bo") is None

    @pytest.mark.anyio
    async def test_reading_a_session_changes_nothing_in_the_database(
        self, harness: str, engine: AsyncEngine, store: SqlAlchemySessionStore
    ) -> None:
        """The read-only invariant against a real database, asserted on the rows themselves.
        `updatedAt` is the one that matters: an upstream `touch` rewrites exactly that column,
        and a store that quietly extended a session would show up here and nowhere else."""
        cookie = sign_in(harness, SEED_EMAIL, SEED_PASSWORD)
        token = raw_token(cookie)
        stamp = 'SELECT "updatedAt" FROM "session" WHERE token = :token'
        before = await _scalar(engine, stamp, token=token)
        rows = await _scalar(engine, 'SELECT count(*) FROM "session"')

        for _ in range(3):
            assert await store.fetch_session_by_token(token) is not None

        assert await _scalar(engine, stamp, token=token) == before
        assert await _scalar(engine, 'SELECT count(*) FROM "session"') == rows
        sign_out(harness, cookie)


class TestAdminPlugin:
    @pytest.mark.anyio
    async def test_a_ban_through_the_admin_api_surfaces_on_the_user_record(
        self, harness: str, store: SqlAlchemySessionStore
    ) -> None:
        """Driven through the plugin's own endpoint, never by writing the column ourselves - a
        fixture that manufactured `banned = true` would prove the column exists and nothing about
        the state Better Auth actually produces.

        Upstream deletes the user's sessions as part of banning them, so the record that carries
        the ban is the *user* record. That is why the store answers users on their own.
        """
        victim, _email = sign_up(harness, "banned")
        cookie = sign_in(harness, _email, PASSWORD)
        token = raw_token(cookie)
        assert await store.fetch_session_by_token(token) is not None
        admin = sign_in(harness, ADMIN_EMAIL, ADMIN_PASSWORD)

        banned = admin_post(
            harness, "ban-user", {"userId": victim, "banReason": "conformance"}, admin
        )

        assert banned.status_code == 200, banned.text
        record = await store.fetch_user_by_id(victim)
        assert record is not None
        assert record.banned is True
        assert record.payload["banReason"] == "conformance"
        assert await store.fetch_session_by_token(token) is None, "upstream revokes on ban"
        sign_out(harness, admin)

    @pytest.mark.anyio
    async def test_an_impersonated_session_names_the_admin_behind_it(
        self, harness: str, store: SqlAlchemySessionStore
    ) -> None:
        """`impersonatedBy` is the other admin-plugin column, and the only way to get a real one
        is to ask the plugin to impersonate somebody."""
        target, _email = sign_up(harness, "impersonated")
        admin = sign_in(harness, ADMIN_EMAIL, ADMIN_PASSWORD)

        assumed = admin_post(harness, "impersonate-user", {"userId": target}, admin)

        assert assumed.status_code == 200, assumed.text
        cookie = assumed.cookies.get("better-auth.session_token")
        assert cookie is not None
        record = await store.fetch_session_by_token(raw_token(cookie))
        assert record is not None
        assert record.user_id == target
        assert record.impersonated_by is not None
        assert record.impersonated_by != target
        assert await store.fetch_user_by_id(record.impersonated_by) is not None


class TestRedisTopology:
    @pytest.mark.anyio
    async def test_a_session_is_read_from_the_raw_token_key(
        self, redis_harness: str, redis_store: RedisSessionStore
    ) -> None:
        """No prefix, no namespace: the key *is* the token. Everything the unit lane asserts
        about that shape is asserted here against the value better-auth actually wrote."""
        cookie = sign_in(redis_harness, SEED_EMAIL, SEED_PASSWORD)
        token = raw_token(cookie)

        record = await redis_store.fetch_session_by_token(token)

        assert record is not None
        assert record.token == token
        assert record.expires_at.tzinfo is not None
        assert record.user is not None
        assert record.user.id == record.user_id
        assert record.user.payload["email"] == SEED_EMAIL
        assert parse_user(User, record.user.payload).email == SEED_EMAIL
        sign_out(redis_harness, cookie)

    @pytest.mark.anyio
    async def test_the_postgres_session_table_never_saw_it(
        self,
        redis_harness: str,
        redis_store: RedisSessionStore,
        store: SqlAlchemySessionStore,
        engine: AsyncEngine,
    ) -> None:
        """The defining fact of this topology, and the whole reason a Redis miss may not fall
        back: with secondary storage configured, upstream's `storeSessionInDatabase` is off, so
        the row is simply never written. The database store therefore *cannot* answer for a
        session that Redis can - asserted for this token rather than by counting rows, because
        the two harness servers share one database and `:3100` has been writing to it.
        """
        cookie = sign_in(redis_harness, SEED_EMAIL, SEED_PASSWORD)
        token = raw_token(cookie)

        assert await redis_store.fetch_session_by_token(token) is not None
        assert await store.fetch_session_by_token(token) is None
        assert (
            await _scalar(
                engine, 'SELECT count(*) FROM "session" WHERE token = :token', token=token
            )
            == 0
        )
        sign_out(redis_harness, cookie)

    @pytest.mark.anyio
    async def test_signing_out_upstream_makes_the_very_next_fetch_a_miss(
        self, redis_harness: str, redis_store: RedisSessionStore
    ) -> None:
        """Sign-out deletes the key. There is nothing left to read, and nowhere else to look."""
        cookie = sign_in(redis_harness, SEED_EMAIL, SEED_PASSWORD)
        token = raw_token(cookie)
        assert await redis_store.fetch_session_by_token(token) is not None

        sign_out(redis_harness, cookie)

        assert await redis_store.fetch_session_by_token(token) is None

    @pytest.mark.anyio
    async def test_reading_writes_no_key_back(
        self, redis_harness: str, redis_store: RedisSessionStore
    ) -> None:
        """Read-only against a real Redis, watched at the one place a write would show: the key's
        TTL. `expires_at` and `payload` do not move under an `EXPIRE`/`GETEX` on read - a planted
        `expire(key, ...)` leaves them identical - so the read-only claim is only really tested by
        reading the PTTL, since a refreshed TTL is exactly how a revoked session outlives its
        revocation. This is the only instrument pointed at a real redis-py client."""
        import redis.asyncio as aioredis

        cookie = sign_in(redis_harness, SEED_EMAIL, SEED_PASSWORD)
        token = raw_token(cookie)
        raw = aioredis.from_url(REDIS_URL)
        try:
            first = await redis_store.fetch_session_by_token(token)
            pttl_before = await raw.pttl(token)
            for _ in range(3):
                await redis_store.fetch_session_by_token(token)
            again = await redis_store.fetch_session_by_token(token)
            pttl_after = await raw.pttl(token)
        finally:
            await raw.aclose()

        assert first is not None
        assert again is not None
        assert again.expires_at == first.expires_at
        assert dict(again.payload) == dict(first.payload)
        # better-auth sets the key's TTL to the session lifetime, so it must be positive - and it
        # only ever *decreases* as time passes. A store that refreshed it on read would raise it.
        assert pttl_before > 0, "the session key carries no TTL; this assertion would prove nothing"
        assert pttl_after <= pttl_before
        sign_out(redis_harness, cookie)
