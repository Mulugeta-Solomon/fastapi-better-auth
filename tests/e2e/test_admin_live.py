"""The admin plugin against the real thing: the four fields and `impersonatedBy`, live.

The unit lane proves `AdminUser` against payloads this repository wrote. This lane closes the gap
that leaves - a user row a running Better Auth created, a ban written straight into its database,
and a session its own `admin/impersonate-user` endpoint minted - read back through all three modes.

Two of the three legs cannot be manufactured through the API and are database-direct on purpose.
Upstream's `admin/ban-user` also *deletes the user's sessions*, so a ban applied that way would
make a "lapsed ban is admitted" leg pass because there was no session left to admit; and no
endpoint backdates `banExpires`. So the ban is an `UPDATE`, on a user this module signed up for
itself and nobody else shares - never the seed user, whose ban would break every other lane.

A module of its own rather than legs added to `test_cookie_live.py` / `test_remote_live.py` /
`test_jwt_live.py`: `AdminUser` is a post-0.3.0 name, and one unguarded import of it in a module
that runs on the published wheel would take that module's whole lane red at the next canary.

Asyncio only: asyncpg drives the event loop directly, as in the other store-backed lanes.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from fastapi_better_auth import HttpxTransport, JwtVerifier, SharedSecret
from tests.fakes import connection

from .conftest import (
    ADMIN_EMAIL,
    ADMIN_PASSWORD,
    HARNESS_SECRET,
    PASSWORD,
    POSTGRES_URL,
    SESSION_COOKIE,
    admin_post,
    harness_sql,
    sign_in,
    sign_out,
    sign_up,
)

try:
    # `AdminUser` is post-0.3.0; every other name here is post-0.1.0. All of them belong under
    # the guard, or the published-wheel lane goes red on the import rather than skipping.
    from fastapi_better_auth import AdminUser, CsrfDisabled, SqlAlchemySessionStore
    from fastapi_better_auth._internal.cookie_verifier import CookieVerifier
    from fastapi_better_auth._internal.remote_verifier import RemoteVerifier
except ImportError:
    pytest.skip(
        "this build of fastapi-better-auth-bridge publishes no AdminUser",
        allow_module_level=True,
    )

pytestmark = pytest.mark.e2e

CSRF_REASON = "a GET carries no CSRF risk; the rung is unit-tested"
LAPSED_BAN = (
    'UPDATE "user" SET banned = true, "banReason" = \'conformance\','
    " \"banExpires\" = now() - interval '1 hour' WHERE id = '{user_id}'"
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    built = create_async_engine(POSTGRES_URL)
    yield built
    await built.dispose()


@pytest.fixture
def admin_token(harness: str) -> str:
    """The JWT upstream hands the admin's own session, straight from its own endpoint."""
    cookie = sign_in(harness, ADMIN_EMAIL, ADMIN_PASSWORD)
    response = httpx.get(f"{harness}/api/auth/token", cookies={SESSION_COOKIE: cookie})
    assert response.status_code == 200, response.text
    token: str = response.json()["token"]
    sign_out(harness, cookie)
    return token


def cookie_connection(cookie: str) -> Any:
    return connection(cookie=f"{SESSION_COOKIE}={cookie}")


async def read_mode_a(engine: AsyncEngine, cookie: str) -> Any:
    """Mode A, driven at the verifier so the whole `Session[AdminUser]` is readable."""
    verifier = CookieVerifier(
        secret=SharedSecret(HARNESS_SECRET),
        store=SqlAlchemySessionStore(engine=engine),
        csrf=CsrfDisabled(reason=CSRF_REASON),
        secure_cookies=False,
    )
    credential = verifier.extract(cookie_connection(cookie))
    assert credential is not None
    return await verifier.verify(credential, AdminUser)


async def read_mode_c(base: str, cookie: str) -> Any:
    async with HttpxTransport() as transport:
        verifier = RemoteVerifier(
            base_url=base,
            csrf=CsrfDisabled(reason=CSRF_REASON),
            transport=transport,
            secure_cookies=False,
        )
        credential = verifier.extract(cookie_connection(cookie))
        assert credential is not None
        return await verifier.verify(credential, AdminUser)


def impersonated(base: str) -> tuple[str, str, str]:
    """Ask the plugin to impersonate a fresh user. Returns its cookie, the target and the admin."""
    target, _email = sign_up(base, "impersonated")
    admin_cookie = sign_in(base, ADMIN_EMAIL, ADMIN_PASSWORD)
    assumed = admin_post(base, "impersonate-user", {"userId": target}, admin_cookie)
    assert assumed.status_code == 200, assumed.text
    cookie = assumed.cookies.get(SESSION_COOKIE)
    assert cookie is not None, "no session cookie on impersonate-user"
    admin_id: str = assumed.json()["session"]["impersonatedBy"]
    sign_out(base, admin_cookie)
    return cookie, target, admin_id


def banned_after_the_fact(base: str) -> tuple[str, str]:
    """Sign a fresh user in, then lapse-ban it in the database. Returns its cookie and id."""
    user_id, email = sign_up(base, "lapsed-ban")
    cookie = sign_in(base, email, PASSWORD)
    harness_sql(LAPSED_BAN.format(user_id=user_id))
    return cookie, user_id


class TestImpersonation:
    """`impersonatedBy` is a session column, so only the two cookie-shaped modes can read it."""

    @pytest.mark.anyio
    async def test_mode_a_names_the_admin_behind_an_impersonated_session(
        self, harness: str, engine: AsyncEngine
    ) -> None:
        cookie, target, admin_id = impersonated(harness)

        session = await read_mode_a(engine, cookie)

        assert session.user.id == target
        assert session.impersonated_by == admin_id
        assert session.impersonated_by != target
        assert session.raw["impersonatedBy"] == admin_id
        sign_out(harness, cookie)

    @pytest.mark.anyio
    async def test_mode_c_names_the_admin_behind_an_impersonated_session(
        self, harness: str
    ) -> None:
        cookie, target, admin_id = impersonated(harness)

        session = await read_mode_c(harness, cookie)

        assert session.user.id == target
        assert session.impersonated_by == admin_id
        assert session.impersonated_by != target
        sign_out(harness, cookie)

    @pytest.mark.anyio
    async def test_an_ordinary_session_reads_none(self, harness: str, engine: AsyncEngine) -> None:
        """Prove the instrument: the field is read from the row, not manufactured by the mode."""
        _user_id, email = sign_up(harness, "not-impersonated")
        cookie = sign_in(harness, email, PASSWORD)

        session = await read_mode_a(engine, cookie)

        assert session.impersonated_by is None
        sign_out(harness, cookie)


class TestLapsedBan:
    """A ban better-auth wrote and then let expire: refused by nobody, and still visible."""

    @pytest.mark.anyio
    async def test_mode_a_admits_it_and_reads_the_ban_as_data(
        self, harness: str, engine: AsyncEngine
    ) -> None:
        cookie, user_id = banned_after_the_fact(harness)

        session = await read_mode_a(engine, cookie)

        assert session.user.id == user_id
        assert session.user.banned is True
        assert session.user.ban_reason == "conformance"
        assert session.user.ban_expires is not None
        assert session.user.ban_expires < datetime.now(timezone.utc)
        sign_out(harness, cookie)

    @pytest.mark.anyio
    async def test_mode_c_admits_it_and_reads_the_ban_as_data(self, harness: str) -> None:
        """Upstream answers `get-session` for a lapsed ban rather than refusing it, so the
        decision is this library's - the same `_check_ban` rule Mode A applies."""
        cookie, user_id = banned_after_the_fact(harness)

        session = await read_mode_c(harness, cookie)

        assert session.user.id == user_id
        assert session.user.banned is True
        assert session.user.ban_reason == "conformance"
        assert session.user.ban_expires is not None
        assert session.user.ban_expires < datetime.now(timezone.utc)
        sign_out(harness, cookie)


class TestModeBToken:
    @pytest.mark.anyio
    async def test_a_live_token_carries_the_admin_plugin_fields(
        self, harness: str, admin_token: str
    ) -> None:
        """`/api/auth/token` puts the whole user row in the payload, plugin columns included -
        which is why Mode B can type `role` and `banned` even though it has no session row."""
        async with HttpxTransport() as transport:
            verifier = JwtVerifier(base_url=harness, transport=transport)
            session = await verifier.verify(admin_token, AdminUser)

        assert session.user.email == ADMIN_EMAIL
        assert session.user.role == "admin"
        assert session.user.banned is False
        assert session.user.ban_reason is None
        assert session.user.ban_expires is None
        assert session.impersonated_by is None, "a JWT carries the user object and no session row"
