"""What the SQL store's row mapper does with a value a driver can hand it and nobody can read.

`test_sqlalchemy_store.py` drives the store: schemas, statements, drift, translation. This file
drives the two values that break the *record* contract rather than the store's - a `str` carrying
an unpaired surrogate, which no encoder can write and so no constant-time compare can consume
(D-183), and a `banned` column arriving as the integer SQLite and MySQL store a boolean as, which
has to reach the verifier as the refusal a ban is rather than as a `TypeError` (D-182).

Split out of `test_sqlalchemy_store.py` when these rows pushed it past the 800-line cap. The
fixture here is narrower than that file's `build` on purpose: neither subject needs a statement
log or a renamed table, so neither is carried.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import pathlib
from collections.abc import AsyncIterator, Callable
from datetime import datetime, timezone
from typing import Any

import pytest
from sqlalchemy import Engine
from sqlalchemy.ext.asyncio import AsyncEngine
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    CookieVerifier,
    CsrfDisabled,
    SessionError,
    SessionStore,
    SharedSecret,
    SqlAlchemySessionStore,
    SyncStoreAdapter,
    User,
)
from fastapi_better_auth._internal.stores.sqlalchemy_core import (
    SESSION_COLUMNS,
    USER_COLUMNS,
    plan_for,
    session_from,
)
from fastapi_better_auth._internal.stores.upstream import as_db_flag, as_text
from tests.stores import (
    EXPIRES_AT,
    SESSION_ID,
    SESSION_ROW,
    TOKEN,
    USER_ID,
    USER_ROW,
    async_engine,
    build_schema,
    sync_engine,
)

FLAVOURS = ("async", "sync")
FAR_FUTURE = datetime(2999, 1, 1, tzinfo=timezone.utc)
LONE_SURROGATE_TOKEN = chr(0xD800) + "abc"
"""An unpaired surrogate: a `str` Python holds happily and cannot encode as UTF-8.

Spelled with `chr` rather than an escape so this file itself stays encodable.
"""
VERIFIER_SECRET = SharedSecret("Qb8Xm2vTz6Lp1RkYd9Wn4Hs7Cj3Fg5Ae")

Seed = Callable[..., SessionStore]


@pytest.fixture
def anyio_backend() -> str:
    """aiosqlite is an asyncio driver; there is no trio leg of this suite to run."""
    return "asyncio"


@pytest.fixture(params=FLAVOURS)
def flavour(request: pytest.FixtureRequest) -> str:
    kind = request.param
    assert isinstance(kind, str)
    return kind


@pytest.fixture
async def seeded(tmp_path: pathlib.Path, flavour: str) -> AsyncIterator[Seed]:
    """Seed a database, then open a store of the flavour under test over the same file."""
    engines: list[Engine | AsyncEngine] = []

    def factory(**schema: Any) -> SessionStore:
        path = tmp_path / f"records{len(engines)}.sqlite"
        build_schema(path, **schema)
        engine: Engine | AsyncEngine
        store: SessionStore
        if flavour == "async":
            engine = async_engine(path)
            store = SqlAlchemySessionStore(engine=engine)
        else:
            engine = sync_engine(path)
            store = SyncStoreAdapter(engine=engine)
        engines.append(engine)
        return store

    yield factory
    for engine in engines:
        if isinstance(engine, AsyncEngine):
            await engine.dispose()
        else:
            engine.dispose()


class TestUnencodableRowValues:
    """B3. The store contract is "a miss, never an exception". `session_from` compares the stored
    token against the presented one as UTF-8 bytes, and a `str` carrying an unpaired surrogate
    cannot be encoded at all - so before `as_text` refused one, that compare raised
    `UnicodeEncodeError` straight out of `fetch_session_by_token`.

    Driven through the row mapper rather than a real database on purpose: SQLite refuses to store
    a lone surrogate through the DBAPI, so there is no way to seed one into the harness schema.
    The row dict is the honest scope - it is exactly what a driver that *can* carry one would hand
    the mapper, and it is where the guard has to hold.
    """

    def test_a_row_whose_token_carries_a_lone_surrogate_is_a_miss(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        plan = plan_for("session", "user", None, {"session": SESSION_COLUMNS, "user": USER_COLUMNS})
        row: dict[str, Any] = {f"s_{name}": None for name in plan.session_columns}
        row.update({f"u_{name}": None for name in plan.user_columns})
        row["s_id"] = SESSION_ID
        row["s_expiresAt"] = EXPIRES_AT
        row["s_userId"] = USER_ID
        row["s_token"] = LONE_SURROGATE_TOKEN
        row["u_id"] = USER_ID

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            assert session_from([row], plan, LONE_SURROGATE_TOKEN) is None

        assert caplog.records, "an unreadable token was refused silently"

    def test_as_db_flag_passes_a_real_boolean_through(self) -> None:
        """Boy-scout: the unit lane could not reach this branch. SQLite and MySQL encode a
        boolean column as the integer 0/1, so no test over this schema ever hands `as_db_flag`
        a real `bool` - only Postgres does, in the conformance lane. Called directly, so the
        Postgres reading is pinned where the rest of the mapper is."""
        assert as_db_flag(True) is True
        assert as_db_flag(False) is False

    def test_as_text_refuses_a_string_no_encoder_can_write(self) -> None:
        """The boundary both stores already trust. A `str` that is not UTF-8-encodable cannot be
        compared, logged, written or sent anywhere, so it is not text this library will vouch
        for - and answering `None` puts it on the path a blank id already takes."""
        assert as_text(LONE_SURROGATE_TOKEN) is None
        assert as_text("ordinary") == "ordinary"


class TestBannedThroughTheVerifier:
    """B2. `StoredUser` now refuses a `banned` that is not `bool | None` with a `TypeError`, so
    the question is whether a real column value can reach it. It cannot: SQLite and MySQL encode
    a boolean column as the integer 0/1, which `as_db_flag` reads as the bool it is, so a stored
    `1` is a genuine ban and ends in the refusal a ban is - never a 500."""

    @pytest.mark.anyio
    async def test_a_banned_of_one_is_a_refusal_and_never_an_escape(self, seeded: Seed) -> None:
        store = seeded(
            sessions=({**SESSION_ROW, "expiresAt": FAR_FUTURE},),
            users=({**USER_ROW, "banned": 1},),
        )
        verifier = CookieVerifier(
            secret=VERIFIER_SECRET,
            store=store,
            csrf=CsrfDisabled(reason="this row is about the ban check, not CSRF"),
            secure_cookies=False,
        )
        connection = _cookie_connection(TOKEN)
        credential = verifier.extract(connection)
        assert credential is not None

        with pytest.raises(SessionError):
            await verifier.verify(credential, User)


def _cookie_connection(token: str) -> HTTPConnection:
    digest = hmac.new(
        VERIFIER_SECRET.get_secret_value().encode(), token.encode(), hashlib.sha256
    ).digest()
    value = f"{token}.{base64.b64encode(digest).decode()}"
    return HTTPConnection(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"cookie", f"better-auth.session_token={value}".encode())],
        }
    )
