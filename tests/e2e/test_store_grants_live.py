"""Least privilege for the SQL store, against the live migrated schema (#68).

The unit lane proves the store never writes by watching the statements its engine emits. This
module makes that a database fact: a LOGIN role holding `SELECT` on `session` and `user` and
nothing else connects, discovers the schema and resolves a real signed-in session, while every
INSERT, UPDATE and DELETE it attempts on either table is refused by Postgres itself. A second role
holding `SELECT` on `session` alone is the under-grant, and what it gets is pinned exactly - the
answer the README documents.

Both roles are created per test under random names and passwords by the harness superuser, and
dropped in a `finally`. The password never reaches a log, a reason, an assertion or a repr: it
lives in a `Login` whose repr leaves it out, the engine's URL masks it, and every statement that
carries it runs through `as_superuser`, which re-raises a failure without the statement text.
Every write attempted as the role carries `WHERE false`, so even a wrongly granted role changes
nothing; privileges are checked when the statement starts, before any row is considered.

Names only 0.5.0 publishes, and the Mode A ones under the post-0.1.0 guard, so the module runs on
the published wheel too. Asyncio only: asyncpg drives the event loop directly.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import AsyncGenerator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import httpx
import pytest
from fastapi import Depends, FastAPI, Request, Response
from fastapi.exception_handlers import http_exception_handler
from sqlalchemy import URL, make_url, text
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

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
    POSTGRES_URL,
    SESSION_COOKIE,
    raw_token,
    sign_in,
    sign_out,
    sign_up,
)

try:
    # Post-0.1.0 names belong under the guard: the published-wheel lane must skip, not raise.
    from fastapi_better_auth import CookieVerifier, OriginCheck, SqlAlchemySessionStore
except ImportError:
    pytest.skip(
        "this build of fastapi-better-auth-bridge publishes no cookie mode",
        allow_module_level=True,
    )

pytestmark = pytest.mark.e2e

FRONT_END = "https://app.example.com"
UNAUTHENTICATED = {"detail": "Not authenticated"}
INSUFFICIENT_PRIVILEGE = "42501"
LOOKUP_UNAVAILABLE = "session store lookup could not complete ["

READ_BOTH = 'GRANT SELECT ON "session", "user" TO "{role}"'
READ_SESSION_ONLY = 'GRANT SELECT ON "session" TO "{role}"'

WRITES = {
    "insert-session": """INSERT INTO "session" (id) SELECT 'wp25-never' WHERE false""",
    "update-session": 'UPDATE "session" SET "updatedAt" = "updatedAt" WHERE false',
    "delete-session": 'DELETE FROM "session" WHERE false',
    "insert-user": """INSERT INTO "user" (id) SELECT 'wp25-never' WHERE false""",
    "update-user": 'UPDATE "user" SET "updatedAt" = "updatedAt" WHERE false',
    "delete-user": 'DELETE FROM "user" WHERE false',
}
"""Every write either table could take, each one a no-op if Postgres ever let it through."""


@dataclass(frozen=True)
class Login:
    """A throwaway LOGIN role. The password is in no repr, so in no failure message either."""

    name: str
    password: str = field(repr=False)

    @property
    def url(self) -> URL:
        """The harness database's own host, port and name, logged in as this role."""
        return make_url(POSTGRES_URL).set(username=self.name, password=self.password)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def as_superuser(*statements: str, step: str) -> None:
    """Run DDL as the harness superuser, in one transaction, never echoing a statement back.

    SQLAlchemy's error text embeds the statement, and one of these carries a password, so a
    failure is re-raised as its class and SQLSTATE only - outside the `except`, with no chain.
    """
    engine = create_async_engine(POSTGRES_URL)
    failure: RuntimeError | None = None
    try:
        async with engine.begin() as connection:
            for statement in statements:
                await connection.exec_driver_sql(statement)
    except SQLAlchemyError as exc:
        code = getattr(getattr(exc, "orig", None), "sqlstate", None)
        failure = RuntimeError(f"{step} failed: {type(exc).__name__} (SQLSTATE {code})")
    finally:
        await engine.dispose()
    if failure is not None:
        raise failure from None


@asynccontextmanager
async def login_granted(grant: str) -> AsyncGenerator[Login]:
    """A LOGIN role holding exactly `grant`, dropped again however the test ends."""
    login = Login(name=f"wp25_store_{secrets.token_hex(8)}", password=secrets.token_hex(24))
    await as_superuser(
        f"CREATE ROLE \"{login.name}\" LOGIN PASSWORD '{login.password}'",
        grant.format(role=login.name),
        step="creating the least-privilege role",
    )
    try:
        yield login
    finally:
        await as_superuser(
            f'DROP OWNED BY "{login.name}"',
            f'DROP ROLE "{login.name}"',
            step="dropping the least-privilege role",
        )


@asynccontextmanager
async def engine_as(login: Login) -> AsyncGenerator[AsyncEngine]:
    engine = create_async_engine(login.url)
    try:
        yield engine
    finally:
        await engine.dispose()


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
async def test_select_on_session_alone_is_the_uniform_401_and_logs_nothing(
    signed_in_user: tuple[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    """The under-grant, as it really answers: not a 500 and not a startup failure.

    `connect()` succeeds - discovery reads the system catalog, which needs no grant - so the
    missing `SELECT` on `user` surfaces on the first lookup, where the joined statement is refused
    and the store turns the database error into `AuthServiceUnavailable`. The client sees the
    uniform 401, and this library logs nothing: the reason is on the exception, for a handler of
    the deployment's own to log.
    """
    _, cookie = signed_in_user
    refusals: list[SessionError] = []

    with caplog.at_level(logging.DEBUG, logger="fastapi_better_auth"):
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
    logged = len(caplog.records)
    assert logged == 0, f"{logged} log records"
