"""Least privilege for the SQL store, against the live migrated schema (#68).

The unit lane proves the store never writes by watching the statements its engine emits. This
module makes that a database fact: a LOGIN role holding `SELECT` on `session` and `user` and
nothing else connects, discovers the schema and resolves a real signed-in session, while every
INSERT, UPDATE and DELETE it attempts on either table is refused by Postgres itself. A second role
holding `SELECT` on `session` alone is the under-grant, and what it gets is pinned exactly - the
answer the README documents: the uniform 401, and one WARNING naming SQLSTATE 42501 (R47).

Both roles are created per test under random names and passwords by the harness superuser, and
dropped in a `finally` (`roles.py`, which keeps the password out of every message). Every write attempted as the role carries `WHERE false`, so even a wrongly granted role changes
nothing; privileges are checked when the statement starts, before any row is considered.

Names only 0.5.0 publishes, and the Mode A ones under the post-0.1.0 guard, so the module runs on
the published wheel too; the one leg about R47's warning skips on a build that predates it.
Asyncio only: asyncpg drives the event loop directly.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from importlib.util import find_spec

import httpx
import pytest
from fastapi import Depends, FastAPI, Request, Response
from fastapi.exception_handlers import http_exception_handler
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuth,
    Session,
    SessionError,
    SharedSecret,
    User,
)

from .conftest import (
    HARNESS_SECRET,
    PASSWORD,
    SESSION_COOKIE,
    raw_token,
    sign_in,
    sign_out,
    sign_up,
)
from .roles import READ_BOTH, READ_SESSION_ONLY, engine_as, login_granted

try:
    # Post-0.1.0 names belong under the guard: the published-wheel lane must skip, not raise.
    from fastapi_better_auth import CookieVerifier, OriginCheck, SqlAlchemySessionStore
except ImportError:
    pytest.skip(
        "this build of fastapi-better-auth-bridge publishes no cookie mode",
        allow_module_level=True,
    )

pytestmark = pytest.mark.e2e

# The store's lookup warning (R47) is post-0.5.0; the published-wheel lane skips that one leg.
WARNS_ON_LOOKUP_FAILURE = find_spec("fastapi_better_auth._internal.stores.outage") is not None

FRONT_END = "https://app.example.com"
UNAUTHENTICATED = {"detail": "Not authenticated"}
INSUFFICIENT_PRIVILEGE = "42501"
LIBRARY_LOGGER = "fastapi_better_auth"
FORMATTER = logging.Formatter("%(name)s %(levelname)s %(message)s")
LOOKUP_UNAVAILABLE = "session store lookup could not complete ["

WRITES = {
    "insert-session": """INSERT INTO "session" (id) SELECT 'wp25-never' WHERE false""",
    "update-session": 'UPDATE "session" SET "updatedAt" = "updatedAt" WHERE false',
    "delete-session": 'DELETE FROM "session" WHERE false',
    "insert-user": """INSERT INTO "user" (id) SELECT 'wp25-never' WHERE false""",
    "update-user": 'UPDATE "user" SET "updatedAt" = "updatedAt" WHERE false',
    "delete-user": 'DELETE FROM "user" WHERE false',
}
"""Every write either table could take, each one a no-op if Postgres ever let it through."""


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def signed_in_user(harness: str) -> Iterator[tuple[str, str]]:
    """A user no other lane shares, signed in. Yields its id and its session cookie."""
    user_id, email = sign_up(harness, "wp25-grants")
    cookie = sign_in(harness, email, PASSWORD)
    yield user_id, cookie
    sign_out(harness, cookie)


def recording_app(store: SqlAlchemySessionStore, refusals: list[SessionError]) -> FastAPI:
    """One Mode A route over `store`, answering refusals with FastAPI's own default handler.

    The handler only records the refusal before delegating, so the wire answer is exactly the one
    an application with no handler gives, and the class underneath is observable beside it.
    """
    auth = BetterAuth(
        verifiers=[
            CookieVerifier(
                secret=SharedSecret(HARNESS_SECRET),
                store=store,
                csrf=OriginCheck(allowed_origins=[FRONT_END]),
                secure_cookies=False,
            )
        ]
    )
    required = auth.current_session()

    async def whoami(session: Session[User] = Depends(required)) -> dict[str, str]:
        return {"id": session.user.id}

    async def recorded(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, SessionError)
        refusals.append(exc)
        return await http_exception_handler(request, exc)

    app = FastAPI()
    app.add_api_route("/whoami", whoami, methods=["POST"])
    app.add_exception_handler(SessionError, recorded)
    return app


def written(records: list[logging.LogRecord]) -> str:
    """Every record as a handler writes it - message, arguments and any traceback."""
    return "\n".join(f"{FORMATTER.format(record)} {record.args!r}" for record in records)


async def post_with(app: FastAPI, cookie: str) -> httpx.Response:
    headers = {"Cookie": f"{SESSION_COOKIE}={cookie}", "Origin": FRONT_END}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://bridge"
    ) as client:
        return await client.post("/whoami", headers=headers)


@pytest.mark.anyio
async def test_select_on_both_tables_is_all_a_real_session_needs(
    signed_in_user: tuple[str, str],
) -> None:
    """Connect, discover, resolve by token, resolve by id, and serve a verified route."""
    user_id, cookie = signed_in_user
    refusals: list[SessionError] = []

    async with login_granted(READ_BOTH) as login, engine_as(login) as engine:
        store = SqlAlchemySessionStore(engine=engine)
        await store.connect()
        record = await store.fetch_session_by_token(raw_token(cookie))
        user = await store.fetch_user_by_id(user_id)
        answer = await post_with(recording_app(store, refusals), cookie)

    assert record is not None
    assert record.user is not None
    assert record.user.id == user_id
    assert user is not None
    assert user.id == user_id
    assert answer.status_code == 200, answer.text
    assert answer.json() == {"id": user_id}
    assert refusals == []


@pytest.mark.anyio
@pytest.mark.parametrize("statement", sorted(WRITES))
async def test_every_write_the_role_attempts_is_refused_by_postgres(
    harness: str, statement: str
) -> None:
    """Granting no more is what makes "the store never writes" true of the database as well."""
    async with login_granted(READ_BOTH) as login, engine_as(login) as engine:
        with pytest.raises(DBAPIError) as caught:
            async with engine.connect() as connection:
                await connection.execute(text(WRITES[statement]))

    assert getattr(caught.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE


@pytest.mark.anyio
async def test_select_on_session_alone_is_the_uniform_401(
    signed_in_user: tuple[str, str],
) -> None:
    """The under-grant, as it really answers: not a 500 and not a startup failure.

    `connect()` succeeds - discovery reads the system catalog, which needs no grant - so the
    missing `SELECT` on `user` surfaces on the first lookup, where the joined statement is refused
    and the store turns the database error into `AuthServiceUnavailable`: the uniform 401.
    """
    _, cookie = signed_in_user
    refusals: list[SessionError] = []

    async with login_granted(READ_SESSION_ONLY) as login, engine_as(login) as engine:
        store = SqlAlchemySessionStore(engine=engine)
        await store.connect()
        answer = await post_with(recording_app(store, refusals), cookie)
        with pytest.raises(AuthServiceUnavailable) as underneath:
            await store.fetch_session_by_token(raw_token(cookie))

    assert answer.status_code == 401
    assert answer.json() == UNAUTHENTICATED
    assert answer.headers["www-authenticate"] == "Bearer"
    assert [type(refusal) for refusal in refusals] == [AuthServiceUnavailable]
    assert refusals[0].reason.startswith(LOOKUP_UNAVAILABLE)
    assert underneath.value.reason.startswith(LOOKUP_UNAVAILABLE)
    assert underneath.value.__cause__ is None


@pytest.mark.anyio
@pytest.mark.skipif(not WARNS_ON_LOOKUP_FAILURE, reason="this build predates R47's lookup warning")
async def test_the_under_grant_is_one_warning_naming_its_sqlstate(
    signed_in_user: tuple[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    """R47, live: two refused lookups, one WARNING, and the SQLSTATE Postgres really sent.

    The line names the driver's class and `42501`; the raw token the lookups were keyed by and the
    role's password - both in play while the statement was refused - are nowhere in any record.
    """
    _, cookie = signed_in_user
    token = raw_token(cookie)

    with caplog.at_level(logging.DEBUG, logger=LIBRARY_LOGGER):
        async with login_granted(READ_SESSION_ONLY) as login, engine_as(login) as engine:
            store = SqlAlchemySessionStore(engine=engine)
            await store.connect()
            await post_with(recording_app(store, []), cookie)
            with pytest.raises(AuthServiceUnavailable):
                await store.fetch_session_by_token(token)
            password_logged = login.password in written(caplog.records)

    ours = [record for record in caplog.records if record.name == LIBRARY_LOGGER]
    token_logged = token in written(caplog.records)
    assert [record.levelno for record in ours] == [logging.WARNING]
    assert f"SQLSTATE {INSUFFICIENT_PRIVILEGE}" in ours[0].getMessage()
    assert ours[0].exc_info is None
    assert not token_logged, "the raw session token reached a log record"
    assert not password_logged, "the role's password reached a log record"
