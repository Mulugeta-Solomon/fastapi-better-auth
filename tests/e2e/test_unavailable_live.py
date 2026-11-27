"""Issue #122 on the wire: a signed-in user, a database that stops answering, and the bridge.

A real user signs up and signs in through the harness auth server. Their user and session rows
are copied into tables of this module's own, and a real FastAPI app reads them through
`CookieVerifier` and `SqlAlchemySessionStore` on the live Postgres, driven over ASGI in this
event loop. A second client then holds `ACCESS EXCLUSIVE` on the copy of `session`, so the
store's lookup queues behind it, which the server itself is asked to confirm.

Two causes end that lookup, both real: the client's own deadline (`lookup_timeout`, the only one
0.7.0 has, and the one #122 was reported on) and the server's bound (`statement_timeout`, SQLSTATE
57014). Two bridges read the same store: the default answers the uniform 401, byte for byte what
a forged cookie gets; the opt-in answers 503 with `Retry-After` and no challenge. Requests that
never reach the store keep their ordinary 401 during the outage, and once the lock goes the same
cookie is accepted again: the session never ended.

The published-wheel lane installs a release that predates the option, so the module skips there
by signature; a lane without asyncpg skips too. Asyncio only: asyncpg drives the event loop.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import secrets
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, cast

import httpx
import pytest
from fastapi import Depends, FastAPI, Request, Response
from fastapi.exception_handlers import http_exception_handler
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import QueuePool

from fastapi_better_auth import BetterAuth, Session, SessionError, User

from .conftest import (
    HARNESS_SECRET,
    PASSWORD,
    POSTGRES_URL,
    raw_token,
    sign_in,
    sign_out,
    sign_up,
)
from .table_copies import table_copies, until

try:
    # Post-0.1.0 names belong under the guard: the published-wheel lane must skip, not raise.
    from fastapi_better_auth import (
        CookieVerifier,
        CsrfDisabled,
        SharedSecret,
        SqlAlchemySessionStore,
    )
    from tests.cookies import COOKIE, sign
    from tests.deadlines import (
        OUTAGE_HEAD,
        OVERRUN_KIND,
        OVERRUN_REASON,
        every_call_ended,
        outage_lines,
    )
    from tests.stores import ASYNCPG_ABSENT
except ImportError:
    pytest.skip(
        "this build of fastapi-better-auth-bridge publishes no session stores",
        allow_module_level=True,
    )

if "unavailable_status" not in inspect.signature(BetterAuth.__init__).parameters:
    pytest.skip(
        "this build of fastapi-better-auth-bridge predates BetterAuth(unavailable_status=...)",
        allow_module_level=True,
    )
if "statement_timeout" not in inspect.signature(SqlAlchemySessionStore.__init__).parameters:
    pytest.skip(
        "this build of fastapi-better-auth-bridge predates SqlAlchemySessionStore(statement_timeout=...)",
        allow_module_level=True,
    )
pytest.importorskip("asyncpg", reason=ASYNCPG_ABSENT)

pytestmark = pytest.mark.e2e

ROUTE = "/me"
RETRY_AFTER = 17
"""Not the default (10), so the header proves the bridge's own value reached the wire."""
POOL_SIZE = 2
QUERY_CANCELED = "57014"
NO_SQLSTATE = "none"
"""What the outage line names in place of a SQLSTATE when the failure carries none."""
LOCK = "LOCK TABLE {schema}.session IN ACCESS EXCLUSIVE MODE"
LOOKUP_WAITING = """
select count(*) from pg_stat_activity
where application_name = :name and state = 'active' and wait_event_type = 'Lock'
  and query ilike 'select%' and position(:schema in query) > 0
"""
OTHER_SECRET = b"Nf4Wq7zC2mVt9Bs5Kx1Ld8Hj6Yr3Pg0Zx"
FORGED = sign("n" * 32, HARNESS_SECRET.encode())
"""Signed with the harness secret, naming no session: refused by the store when it answers."""
BAD_SIGNATURE = sign("x" * 32, OTHER_SECRET)
"""Signed with another secret: refused before the store is asked."""


@dataclass(frozen=True)
class Cause:
    """What ends the queued lookup: the store's server-side bound, or the verifier's deadline."""

    statement_timeout: float | None
    lookup_timeout: float
    reason: str


CAUSES = {
    # The verifier gives up first. Two seconds leaves room to see the lookup wait before then.
    "client-deadline": Cause(statement_timeout=None, lookup_timeout=2.0, reason=OVERRUN_REASON),
    # The server ends it at one second; the verifier's deadline is far away.
    "server-bound": Cause(statement_timeout=1.0, lookup_timeout=20.0, reason=OUTAGE_HEAD),
}
BRIDGES: dict[str, dict[str, Any]] = {
    "default": {},
    "opt-in": {"unavailable_status": 503, "unavailable_retry_after": RETRY_AFTER},
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def observer() -> AsyncIterator[AsyncEngine]:
    built = create_async_engine(POSTGRES_URL)
    yield built
    await built.dispose()


@pytest.fixture
async def blocker() -> AsyncIterator[AsyncEngine]:
    """The second client, which holds the lock the store's lookup queues behind."""
    built = create_async_engine(POSTGRES_URL)
    yield built
    await built.dispose()


@pytest.fixture
async def schema(harness: str, observer: AsyncEngine) -> AsyncIterator[str]:
    async with table_copies(observer, "wp55") as name:
        yield name


@pytest.fixture
def application_name() -> str:
    """How this case's pool is told apart from everyone else's on the server."""
    return f"wp55-pool-{secrets.token_hex(4)}"


@pytest.fixture
async def engine(application_name: str) -> AsyncIterator[AsyncEngine]:
    built = create_async_engine(
        POSTGRES_URL,
        pool_size=POOL_SIZE,
        max_overflow=0,
        connect_args={"server_settings": {"application_name": application_name}},
    )
    yield built
    await built.dispose()


@pytest.fixture
def logs(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    caplog.set_level(logging.DEBUG, logger="fastapi_better_auth")
    return caplog


@pytest.fixture
async def user(harness: str, observer: AsyncEngine, schema: str) -> AsyncIterator[tuple[str, str]]:
    """A real signed-in user, `(id, cookie value)`, copied into this case's tables."""
    identifier, email = sign_up(harness, "wp55")
    cookie = sign_in(harness, email, PASSWORD)
    async with observer.begin() as connection:
        users = await connection.execute(
            text(f'INSERT INTO {schema}."user" SELECT * FROM public."user" WHERE id = :id'),
            {"id": identifier},
        )
        sessions = await connection.execute(
            text(f"INSERT INTO {schema}.session SELECT * FROM public.session WHERE token = :t"),
            {"t": raw_token(cookie)},
        )
    assert (users.rowcount, sessions.rowcount) == (1, 1), "the user was not copied"
    try:
        yield identifier, cookie
    finally:
        sign_out(harness, cookie)


def bridge_app(
    verifier: CookieVerifier, settings: dict[str, Any], seen: list[SessionError]
) -> FastAPI:
    """A route behind `current_session()`, with a handler that keeps every refusal it renders."""
    app = FastAPI()
    current = BetterAuth(verifiers=[verifier], **settings).current_session()

    async def me(session: Session[User] = Depends(current)) -> dict[str, str]:
        return {"id": session.user.id}

    async def record(request: Request, exc: Exception) -> Response:
        seen.append(cast("SessionError", exc))
        return await http_exception_handler(request, cast("SessionError", exc))

    app.add_api_route(ROUTE, me, methods=["GET"])
    app.add_exception_handler(SessionError, record)
    return app


def cookie_header(value: str) -> dict[str, str]:
    return {"cookie": f"{COOKIE}={value}"}


def wire(response: httpx.Response) -> tuple[int, bytes, list[tuple[str, str]]]:
    headers = sorted((k.lower(), v) for k, v in response.headers.items() if k.lower() != "date")
    return response.status_code, response.content, headers


async def lookup_waits(observer: AsyncEngine, name: str, schema: str) -> bool:
    """Whether the server shows this pool's lookup itself queued on a lock: not BEGIN, not setup."""
    async with observer.connect() as connection:
        found = await connection.scalar(text(LOOKUP_WAITING), {"name": name, "schema": schema})
    return int(found or 0) == 1


@dataclass
class Outage:
    refused: httpx.Response
    waited: bool
    anonymous: httpx.Response
    bad_signature: httpx.Response


async def during_the_lock(
    http: httpx.AsyncClient,
    engines: tuple[AsyncEngine, AsyncEngine],
    cookie: str,
    pool: tuple[str, str],
) -> Outage:
    """Lock the copy of `session`, ask with the cookie, and ask twice more without reaching it.

    `engines` is the blocker and the observer; `pool` is this case's application name and schema.
    """
    blocker, observer = engines
    name, schema = pool
    async with blocker.connect() as lock:
        await lock.execute(text(LOCK.format(schema=schema)))
        request = asyncio.ensure_future(http.get(ROUTE, headers=cookie_header(cookie)))
        try:
            waited = False

            async def queued_or_answered() -> bool:
                nonlocal waited
                waited = waited or await lookup_waits(observer, name, schema)
                return waited or request.done()

            await until(queued_or_answered, "the lookup queuing on the lock")
            refused = await request
            anonymous = await http.get(ROUTE)
            bad = await http.get(ROUTE, headers=cookie_header(BAD_SIGNATURE))
        finally:
            request.cancel()
            await lock.rollback()
    return Outage(refused=refused, waited=waited, anonymous=anonymous, bad_signature=bad)


def assert_refused_as_claimed(bridge: str, outage: Outage, forged: httpx.Response) -> None:
    refused = outage.refused
    if bridge == "default":
        assert wire(refused) == wire(forged)
        assert "www-authenticate" in refused.headers
        assert "retry-after" not in refused.headers
        return
    assert refused.status_code == 503, f"refused with {refused.status_code}"
    assert refused.json() == {"detail": "Service unavailable"}
    assert refused.headers["retry-after"] == str(RETRY_AFTER)
    assert "www-authenticate" not in refused.headers


def assert_one_outage_line(cause: str, records: list[logging.LogRecord]) -> None:
    lines = [tuple(record.args or ())[:2] for record in outage_lines(records)]
    if cause == "client-deadline":
        assert lines == [(OVERRUN_KIND, NO_SQLSTATE)], lines
    else:
        assert [state for _kind, state in lines] == [QUERY_CANCELED], lines


@pytest.mark.anyio
@pytest.mark.parametrize("cause", list(CAUSES))
@pytest.mark.parametrize("bridge", list(BRIDGES))
async def test_a_signed_in_user_meets_a_database_that_stops_answering(
    bridge: str,
    cause: str,
    user: tuple[str, str],
    engine: AsyncEngine,
    observer: AsyncEngine,
    blocker: AsyncEngine,
    schema: str,
    application_name: str,
    logs: pytest.LogCaptureFixture,
) -> None:
    identifier, cookie = user
    chosen = CAUSES[cause]
    store = SqlAlchemySessionStore(
        engine=engine, schema=schema, statement_timeout=chosen.statement_timeout
    )
    await store.connect()
    verifier = CookieVerifier(
        secret=SharedSecret(HARNESS_SECRET),
        store=store,
        csrf=CsrfDisabled(reason="this case is about a store outage, not cross-site requests"),
        secure_cookies=False,
        lookup_timeout=chosen.lookup_timeout,
    )
    seen: list[SessionError] = []
    transport = httpx.ASGITransport(app=bridge_app(verifier, BRIDGES[bridge], seen))
    async with httpx.AsyncClient(transport=transport, base_url="http://bridge") as http:
        healthy = await http.get(ROUTE, headers=cookie_header(cookie))
        forged = await http.get(ROUTE, headers=cookie_header(FORGED))
        before = len(seen)
        outage = await during_the_lock(
            http, (blocker, observer), cookie, (application_name, schema)
        )
        outage_refusals = seen[before : before + 1]
        await every_call_ended(store)
        checked_out = cast("QueuePool", engine.pool).checkedout()
        recovered = await http.get(ROUTE, headers=cookie_header(cookie))

    assert healthy.status_code == 200 and healthy.json() == {"id": identifier}
    assert forged.status_code == 401
    answered = outage.refused.status_code
    assert outage.waited, f"the lookup never queued on the lock; it answered {answered}"
    assert_refused_as_claimed(bridge, outage, forged)
    assert [chosen.reason in refusal.reason for refusal in outage_refusals] == [True]
    assert_one_outage_line(cause, logs.records)
    assert wire(outage.anonymous) == wire(forged)
    assert wire(outage.bad_signature) == wire(forged)
    assert checked_out == 0, f"{checked_out} pooled connection(s) still out after the lock went"
    assert recovered.status_code == 200 and recovered.json() == {"id": identifier}
    responses = (healthy, forged, outage.refused, outage.anonymous, outage.bad_signature, recovered)
    assert_no_credential_leaked(cookie, logs.records, responses)


def assert_no_credential_leaked(
    cookie: str, records: list[logging.LogRecord], responses: tuple[httpx.Response, ...]
) -> None:
    needles = (raw_token(cookie), cookie)
    text_seen = [record.getMessage() for record in records]
    text_seen += [repr(record.args) for record in records]
    text_seen += [response.text for response in responses]
    for needle in needles:
        assert not any(needle in seen for seen in text_seen), "a credential reached a log or body"
