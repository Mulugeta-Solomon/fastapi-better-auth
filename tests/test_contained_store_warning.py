"""A store failure the cookie verifier contains tells the operator once, too (R47a).

R47 made the SQL stores report a lookup statement the database refused. Everything else a store
can raise untranslated - a SQL store whose first lookup cannot even discover its schema, a Redis
store on a dead socket, a deployment's own store - reaches `CookieVerifier`, which turns it into
the uniform 401. That arm reports through the same log function, with the same record and the same
latch semantics: one WARNING per verifier per failure kind, re-armed by any store call that
returns. An error the store already translated was reported where it happened (or is a refusal,
not an outage), so it is neither reported again nor allowed to re-arm anything here.

Driven through a real FastAPI app with real drivers wherever one exists: an unreachable SQLite
path, a Redis port nobody listens on. Both anyio backends wherever the store's driver allows; the
async SQL store and redis-py drive asyncio directly, so those legs are asyncio only.
"""

from __future__ import annotations

import logging
import pathlib
import socket
from collections.abc import Awaitable, Callable, Iterator, Sequence
from typing import Any, cast

import pytest
from anyio.from_thread import BlockingPortal
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuth,
    CookieVerifier,
    CsrfDisabled,
    RedisSessionStore,
    SessionStore,
    SqlAlchemySessionStore,
    SyncStoreAdapter,
)
from fastapi_better_auth._internal.reasons import fingerprint
from fastapi_better_auth._internal.stores.outage import MAX_REPORTED_KINDS
from tests.cookies import (
    CAPTURED_TOKEN,
    COOKIE,
    SECRET,
    USER_ID,
    FakeStore,
    http,
    run,
    sign,
    stored_session,
    verifier,
)
from tests.fakes import client, session_app
from tests.log_hygiene import LIBRARY_LOGGER, broken_log_filter, capturing
from tests.stores import (
    AiosqliteStops,
    DeniedError,
    DriverFault,
    ShiftingStateError,
    StoreFixture,
)

TEMPLATE_HEAD = "session store lookup"
REQUESTS = 3
HEADERS = {"Cookie": f"{COOKIE}={sign(CAPTURED_TOKEN)}"}


class StoreDown(Exception):
    """A deployment's own store failing, with no SQLSTATE and nothing SQLAlchemy wrapped."""


class HostileSqlstate(Exception):
    """A deployment's own exception whose `sqlstate` is a property that raises."""

    @property
    def sqlstate(self) -> str:
        raise RuntimeError("a property that raises")


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


def outage_lines(records: list[logging.LogRecord]) -> list[logging.LogRecord]:
    return [
        record
        for record in records
        if record.name == LIBRARY_LOGGER and str(record.msg).startswith(TEMPLATE_HEAD)
    ]


def kinds(records: list[logging.LogRecord]) -> list[tuple[Any, ...]]:
    return [tuple(record.args or ())[:2] for record in outage_lines(records)]


def cookie_verifier(store: SessionStore) -> CookieVerifier:
    return CookieVerifier(
        secret=SECRET,
        store=store,
        csrf=CsrfDisabled(reason="GET routes only; this suite is about store outages"),
        secure_cookies=False,
    )


@pytest.fixture
def aiosqlite_stops(monkeypatch: pytest.MonkeyPatch) -> AiosqliteStops:
    return AiosqliteStops(monkeypatch)


def apps_loop(http: TestClient) -> BlockingPortal:
    """The portal onto the loop a `TestClient` runs the app on - open until its `with` exits."""
    return cast("BlockingPortal", http.portal)  # pyright: ignore[reportUnknownMemberType]


def statuses(
    verifier: CookieVerifier,
    backend: str,
    requests: int = REQUESTS,
    *,
    before_close: Sequence[Callable[[], Awaitable[object]]] = (),
) -> list[int]:
    """`requests` refused-or-served GETs, then each `before_close` step on the app's own loop."""
    app = session_app(BetterAuth(verifiers=[verifier]))
    with client(app, backend) as http:
        answered = [http.get("/required", headers=HEADERS).status_code for _ in range(requests)]
        for step in before_close:
            apps_loop(http).call(step)
    return answered


def closed_port() -> int:
    """A loopback port nothing listens on: bound once to learn it, then released."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


@pytest.mark.parametrize(
    ("flavour", "backend"),
    [("async", "asyncio"), ("sync", "asyncio"), ("sync", "trio")],
)
def test_a_sql_store_that_cannot_reach_its_database_warns_once(
    flavour: str,
    backend: str,
    tmp_path: pathlib.Path,
    records: list[logging.LogRecord],
    aiosqlite_stops: AiosqliteStops,
) -> None:
    """D-373, reproduced: `connect()` never ran, so discovery fails inside the first lookup and
    escapes the store as a raw `SQLAlchemyError` - no statement parameter is bound there. Each
    failed aiosqlite connect leaves a `stop()` behind on the app's loop, so the engine is disposed
    and those are awaited on that loop, before the `TestClient` closes it."""
    url = f"{tmp_path / 'no' / 'such' / 'directory' / 'auth.db'}"
    store: SessionStore
    if flavour == "async":
        async_engine = create_async_engine(f"sqlite+aiosqlite:///{url}")
        store = SqlAlchemySessionStore(engine=async_engine)
        answered = statuses(
            cookie_verifier(store),
            backend,
            before_close=(async_engine.dispose, aiosqlite_stops.drained),
        )
        assert len(aiosqlite_stops.futures) == (REQUESTS if aiosqlite_stops.installed else 0)
    else:
        sync_engine = create_engine(f"sqlite+pysqlite:///{url}")
        store = SyncStoreAdapter(engine=sync_engine)
        answered = statuses(cookie_verifier(store), backend)
        sync_engine.dispose()

    assert answered == [401] * REQUESTS
    assert kinds(records) == [("OperationalError", "none")]


def test_a_redis_store_on_a_closed_port_warns_once(records: list[logging.LogRecord]) -> None:
    """redis-py's `ConnectionError` escapes `RedisSessionStore` untranslated. Two requests, not
    three: a refused loopback connect takes about two seconds on Windows."""
    store = RedisSessionStore(url=f"redis://127.0.0.1:{closed_port()}/0")

    answered = statuses(cookie_verifier(store), "asyncio", requests=2)

    assert answered == [401, 401]
    assert kinds(records) == [("ConnectionError", "none")]


def test_a_deployments_own_store_failure_warns_once(
    client_backend: str, records: list[logging.LogRecord]
) -> None:
    store = FakeStore(session_error=StoreDown("the session service is unreachable"))

    answered = statuses(cookie_verifier(store), client_backend)

    assert answered == [401] * REQUESTS
    assert kinds(records) == [("StoreDown", "none")]
    assert outage_lines(records)[0].args == ("StoreDown", "none", fingerprint(CAPTURED_TOKEN))


def test_a_user_lookup_failure_warns_with_the_users_fingerprint(
    client_backend: str, records: list[logging.LogRecord]
) -> None:
    """Fingerprinted exactly as the store would: the user lookup's subject is the user id."""
    store = FakeStore(
        sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, user=None)},
        user_error=StoreDown("the user service is unreachable"),
    )

    answered = statuses(cookie_verifier(store), client_backend)

    assert answered == [401] * REQUESTS
    (line,) = outage_lines(records)
    assert line.args == ("StoreDown", "none", fingerprint(USER_ID))


def test_a_store_call_that_returns_re_arms_it(
    client_backend: str, records: list[logging.LogRecord]
) -> None:
    """Fail, then a store call that returns - a miss, answered 401 as a revocation - then fail
    again: two lines. The miss is what re-arms; nothing here authenticates anybody."""
    store = FakeStore(session_error=StoreDown("down"))
    app = session_app(BetterAuth(verifiers=[cookie_verifier(store)]))

    with client(app, client_backend) as http:
        first = [http.get("/required", headers=HEADERS).status_code for _ in range(2)]
        store.session_error = None
        recovered = http.get("/required", headers=HEADERS).status_code
        store.session_error = StoreDown("down again")
        again = [http.get("/required", headers=HEADERS).status_code for _ in range(2)]

    assert first + [recovered] + again == [401] * 5
    assert len(store.session_calls) == 5
    assert kinds(records) == [("StoreDown", "none"), ("StoreDown", "none")]


def test_a_user_lookup_that_returns_re_arms_its_own_latch(
    client_backend: str, records: list[logging.LogRecord]
) -> None:
    """The user lookup keeps a latch of its own - the session lookup before it succeeds on every
    request, and re-arming both on that would put a line on every request of a user-side outage."""
    store = FakeStore(
        sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, user=None)},
        user_error=StoreDown("down"),
    )
    app = session_app(BetterAuth(verifiers=[cookie_verifier(store)]))

    with client(app, client_backend) as http:
        for _ in range(2):
            http.get("/required", headers=HEADERS)
        store.user_error = None
        http.get("/required", headers=HEADERS)
        store.user_error = StoreDown("down again")
        for _ in range(2):
            http.get("/required", headers=HEADERS)

    assert len(store.user_calls) == 5
    assert kinds(records) == [("StoreDown", "none"), ("StoreDown", "none")]


def test_an_error_the_store_translated_is_not_reported_again(
    client_backend: str, records: list[logging.LogRecord]
) -> None:
    store = FakeStore(session_error=AuthServiceUnavailable(reason="store lookup [tok_fp=abc]"))

    answered = statuses(cookie_verifier(store), client_backend)

    assert answered == [401] * REQUESTS
    assert outage_lines(records) == []


def test_a_translated_error_does_not_re_arm_the_latch(
    client_backend: str, records: list[logging.LogRecord]
) -> None:
    """A translated error is no proof the store is back: raw, translated, raw is still one line."""
    store = FakeStore(session_error=StoreDown("down"))
    app = session_app(BetterAuth(verifiers=[cookie_verifier(store)]))

    with client(app, client_backend) as http:
        http.get("/required", headers=HEADERS)
        store.session_error = AuthServiceUnavailable(reason="store lookup [tok_fp=abc]")
        http.get("/required", headers=HEADERS)
        store.session_error = StoreDown("down")
        http.get("/required", headers=HEADERS)

    assert kinds(records) == [("StoreDown", "none")]


@pytest.mark.parametrize(
    ("flavour", "backend"),
    [("async", "asyncio"), ("sync", "asyncio"), ("sync", "trio")],
)
def test_a_refused_statement_is_one_line_in_total(
    flavour: str,
    backend: str,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    records: list[logging.LogRecord],
    aiosqlite_stops: AiosqliteStops,
) -> None:
    """The store reports a refused statement and hands the verifier a translated error, so the
    verifier adds nothing: the store's line is the only one. The first request discovers the
    schema on the app's own loop and completes (a miss); only then does the driver refuse."""
    build = StoreFixture(tmp_path, flavour)
    store, _ = build()
    fault = DriverFault(build.engines[-1], monkeypatch)
    app = session_app(BetterAuth(verifiers=[cookie_verifier(store)]))

    with client(app, backend) as http:
        discovered = http.get("/required", headers=HEADERS).status_code
        fault.error = DeniedError
        answered = [http.get("/required", headers=HEADERS).status_code for _ in range(REQUESTS)]
        apps_loop(http).call(build.aclose)
        apps_loop(http).call(aiosqlite_stops.drained)

    assert discovered == 401
    assert answered == [401] * REQUESTS
    assert kinds(records) == [("DeniedError", "42501")]


def test_each_verifier_has_a_latch_of_its_own(records: list[logging.LogRecord]) -> None:
    for _ in range(2):
        statuses(cookie_verifier(FakeStore(session_error=StoreDown("down"))), "asyncio")

    assert kinds(records) == [("StoreDown", "none"), ("StoreDown", "none")]


def test_a_failure_whose_attributes_raise_is_still_reported_and_refused(
    records: list[logging.LogRecord],
) -> None:
    """A deployment's exception is code this library did not write: a property that raises while
    the kind is read must not replace the uniform 401, and the line says there was no SQLSTATE."""
    store = FakeStore(session_error=HostileSqlstate("down"))

    answered = statuses(cookie_verifier(store), "asyncio")

    assert answered == [401] * REQUESTS
    assert kinds(records) == [("HostileSqlstate", "none")]


class HostileName(type):
    """A metaclass whose `__name__` raises - so does reading the class name of its instances."""

    @property
    def __name__(cls) -> str:  # type: ignore[override]
        raise RuntimeError("the class name cannot be read")


class NamelessStoreDown(Exception, metaclass=HostileName):
    """A deployment's own store error whose class name cannot even be read."""


@pytest.mark.anyio
async def test_a_class_whose_name_cannot_be_read_is_still_refused_and_reported(
    records: list[logging.LogRecord],
) -> None:
    store = FakeStore(session_error=NamelessStoreDown("down"))

    escaped = ""
    try:
        await run(verifier(store=store), http(cookie=HEADERS["Cookie"]))
    except AuthServiceUnavailable as refusal:
        assert refusal.__context__ is None
    except Exception:  # noqa: BLE001 - pytest's own reporter reads the class name and would crash
        escaped = "an exception other than AuthServiceUnavailable escaped the verifier"

    assert escaped == ""
    assert kinds(records) == [("UnnamedError", "none")]


@pytest.mark.anyio
async def test_a_report_that_raises_never_changes_the_refusal() -> None:
    """Reporting is best effort at this caller too: a raising log filter leaves the refusal
    `AuthServiceUnavailable`, unchained, and raised as it always was."""
    store = FakeStore(session_error=StoreDown("down"))

    with broken_log_filter(), pytest.raises(AuthServiceUnavailable) as caught:
        await run(verifier(store=store), http(cookie=HEADERS["Cookie"]))

    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_a_store_whose_failures_never_repeat_still_cannot_flood(
    client_backend: str, records: list[logging.LogRecord]
) -> None:
    store = FakeStore(session_error=ShiftingStateError("down"))

    answered = statuses(cookie_verifier(store), client_backend, requests=MAX_REPORTED_KINDS * 3)

    assert answered == [401] * (MAX_REPORTED_KINDS * 3)
    assert len(outage_lines(records)) == MAX_REPORTED_KINDS + 1
