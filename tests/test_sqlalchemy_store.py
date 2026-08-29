"""The SQLAlchemy store, against a real database carrying better-auth's real schema.

SQLite rather than Postgres, deliberately: the truths this store depends on - quoted camelCase
identifiers, `user` as a reserved word, the shape of a row - are checked here against a database
that has them, and the *Postgres* truths (timestamptz, the live migrated schema, the admin
plugin's columns) are checked in the conformance lane against the harness. What SQLite adds that
Postgres cannot is the naive-datetime trap: it hands back a `datetime` with no `tzinfo` at all.

Both flavours run through every case here: the async store over `aiosqlite`, and
`SyncStoreAdapter` over plain `pysqlite` in a worker thread. They share their statements and
their row mapping, so a behaviour proven for one and assumed for the other would be exactly the
half that drifts. The module runs on asyncio only, because `aiosqlite` drives the event loop
directly; `SyncStoreAdapter` has no such constraint and is run on both backends in
`test_sync_store_adapter.py`.
"""

from __future__ import annotations

import importlib
import logging
import pathlib
import sys
from collections.abc import AsyncIterator, Callable
from datetime import datetime, timezone
from typing import Any

import pytest
from sqlalchemy import Engine
from sqlalchemy.ext.asyncio import AsyncEngine

from fastapi_better_auth import (
    ConfigurationError,
    SessionStore,
    SqlAlchemySessionStore,
    SyncStoreAdapter,
)
from fastapi_better_auth._internal.stores.sqlalchemy_core import (
    SESSION_COLUMNS,
    USER_COLUMNS,
    plan_for,
    user_from,
)
from tests.stores import (
    ADMIN_ID,
    EXPIRES_AT,
    NOW,
    SESSION_ID,
    SESSION_ROW,
    TOKEN,
    USER_ID,
    USER_ROW,
    StatementLog,
    async_engine,
    build_schema,
    sync_engine,
)

FLAVOURS = ("async", "sync")
UNKNOWN_TOKEN = "5RmMvJt3xQ8bWfKcApZnUhLd2YeGsT7q"
BAN_EXPIRES = datetime(2026, 12, 1, tzinfo=timezone.utc)
PACKAGE = "fastapi_better_auth._internal.stores"

Build = Callable[..., "tuple[SessionStore, StatementLog]"]


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
async def build(tmp_path: pathlib.Path, flavour: str) -> AsyncIterator[Build]:
    """Seed a database, then open a store of the flavour under test over the same file."""
    engines: list[Engine | AsyncEngine] = []

    def factory(
        store_options: dict[str, Any] | None = None, **schema: Any
    ) -> tuple[SessionStore, StatementLog]:
        names = {key: schema[key] for key in ("session_table", "user_table") if key in schema}
        names.update(store_options or {})
        path = tmp_path / f"harness{len(engines)}.sqlite"
        build_schema(path, **schema)
        log = StatementLog()
        engine: Engine | AsyncEngine
        store: SessionStore
        if flavour == "async":
            engine = async_engine(path)
            store = SqlAlchemySessionStore(engine=engine, **names)
        else:
            engine = sync_engine(path)
            store = SyncStoreAdapter(engine=engine, **names)
        log.attach(engine)
        engines.append(engine)
        return store, log

    yield factory
    for engine in engines:
        if isinstance(engine, AsyncEngine):
            await engine.dispose()
        else:
            engine.dispose()


async def connect(store: SessionStore) -> None:
    """The startup hook, which the Protocol the tests hold does not declare."""
    assert isinstance(store, (SqlAlchemySessionStore, SyncStoreAdapter))
    await store.connect()


def selects(log: StatementLog) -> list[str]:
    return [line for line in log.statements if line.lstrip().upper().startswith("SELECT")]


class TestFetchSessionByToken:
    @pytest.mark.anyio
    async def test_it_answers_the_session_and_embeds_its_user(self, build: Build) -> None:
        store, _log = build()

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.token == TOKEN
        assert record.user_id == USER_ID
        assert record.expires_at == EXPIRES_AT
        assert record.payload["id"] == SESSION_ID
        assert record.payload["userAgent"] == "python-httpx/0.28.1"
        assert record.user is not None
        assert record.user.id == USER_ID
        assert record.user.payload["email"] == "seed@example.com"
        assert record.user.payload["emailVerified"] is False

    @pytest.mark.anyio
    async def test_the_happy_path_costs_one_statement(self, build: Build) -> None:
        """A session and its user in one round trip. Two would double this store's share of
        every authenticated request's latency, for a join the database does for free."""
        store, log = build()
        await connect(store)
        log.statements.clear()

        await store.fetch_session_by_token(TOKEN)

        assert len(selects(log)) == 1

    @pytest.mark.anyio
    async def test_a_naive_stored_expiry_is_read_as_utc(self, build: Build) -> None:
        """The SQLite/MySQL trap: the column carries no offset, so the driver answers a naive
        `datetime`. better-auth writes UTC, so UTC is what it is read back as - and the record's
        own contract refuses to hold a naive value, which is what stops this from being missed."""
        store, _log = build()

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.expires_at.tzinfo is not None
        assert record.expires_at == EXPIRES_AT
        assert record.payload["expiresAt"] == EXPIRES_AT

    @pytest.mark.anyio
    async def test_an_unknown_token_is_a_miss_not_an_error(self, build: Build) -> None:
        store, _log = build()

        assert await store.fetch_session_by_token(UNKNOWN_TOKEN) is None

    @pytest.mark.anyio
    @pytest.mark.parametrize("blank", ["", "   ", "\n"], ids=["empty", "spaces", "newline"])
    async def test_a_blank_token_is_refused_without_touching_the_database(
        self, build: Build, blank: str
    ) -> None:
        """No credential is not a lookup. Answering it from the database would spend a round
        trip, and an oracle's worth of timing, on a request that carried nothing."""
        store, log = build()
        await connect(store)
        log.statements.clear()

        record = await store.fetch_session_by_token(blank)

        assert record is None
        assert log.statements == []

    @pytest.mark.anyio
    async def test_a_session_whose_user_row_is_gone_is_a_miss(self, build: Build) -> None:
        """The foreign key cascades, so this cannot happen upstream; if it ever does, a session
        with no user behind it is not one anybody should be authenticated by."""
        store, _log = build(users=())

        assert await store.fetch_session_by_token(TOKEN) is None

    @pytest.mark.anyio
    async def test_a_row_with_a_null_required_value_is_a_miss_and_a_warning(
        self, build: Build, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A NULL where better-auth's schema says NOT NULL is data this store cannot vouch for.
        It is a miss - the uniform 401 - and never a 500, which is distinguishable on the wire."""
        store, _log = build(
            sessions=({**SESSION_ROW, "expiresAt": None},),
            relax_session_columns=("expiresAt",),
        )

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            record = await store.fetch_session_by_token(TOKEN)

        assert record is None
        assert any("expiresAt" in entry.getMessage() for entry in caplog.records)

    @pytest.mark.anyio
    async def test_no_stored_value_reaches_the_warning_it_causes(
        self, build: Build, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The refusal is an operator-facing log line like any other: it names a fingerprint of
        the token and what was wrong with the row, and never the row."""
        store, _log = build(
            sessions=({**SESSION_ROW, "expiresAt": None},),
            relax_session_columns=("expiresAt",),
        )

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            await store.fetch_session_by_token(TOKEN)

        written = " ".join(entry.getMessage() for entry in caplog.records)
        assert written
        assert TOKEN not in written
        assert SESSION_ID not in written
        assert USER_ID not in written


class TestAdminFields:
    @pytest.mark.anyio
    async def test_the_admin_columns_surface_when_the_plugin_created_them(
        self, build: Build
    ) -> None:
        store, _log = build(
            sessions=({**SESSION_ROW, "impersonatedBy": ADMIN_ID},),
            users=({**USER_ROW, "banned": True, "banExpires": BAN_EXPIRES, "role": "user"},),
        )

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.impersonated_by == ADMIN_ID
        assert record.user is not None
        assert record.user.banned is True
        assert record.user.ban_expires == BAN_EXPIRES
        assert record.user.payload["role"] == "user"

    @pytest.mark.anyio
    async def test_their_absence_is_not_drift(
        self, build: Build, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The admin plugin is optional upstream, so a deployment without it has no such
        columns. Warning every time would train an operator to ignore the warning that matters."""
        store, _log = build(admin=False)

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.impersonated_by is None
        assert record.user is not None
        assert record.user.banned is None
        assert record.user.ban_expires is None
        assert caplog.records == []

    @pytest.mark.anyio
    async def test_a_present_but_false_banned_is_not_unknown(self, build: Build) -> None:
        """`None` means "no such column"; `False` means "upstream says this user is not banned".
        Collapsing them would make a deployment with no admin plugin look like a clean bill."""
        store, _log = build()

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.user is not None
        assert record.user.banned is False


class TestFetchUserById:
    @pytest.mark.anyio
    async def test_it_answers_the_user(self, build: Build) -> None:
        store, _log = build(users=({**USER_ROW, "banned": True},))

        record = await store.fetch_user_by_id(USER_ID)

        assert record is not None
        assert record.id == USER_ID
        assert record.banned is True
        assert record.payload["name"] == "Seed User"
        assert record.payload["createdAt"] == NOW

    @pytest.mark.anyio
    async def test_an_unknown_id_is_a_miss(self, build: Build) -> None:
        store, _log = build()

        assert await store.fetch_user_by_id("nobody") is None

    @pytest.mark.anyio
    @pytest.mark.parametrize("blank", ["", "  "], ids=["empty", "spaces"])
    async def test_a_blank_id_never_reaches_the_database(self, build: Build, blank: str) -> None:
        store, log = build()
        await connect(store)
        log.statements.clear()

        record = await store.fetch_user_by_id(blank)

        assert record is None
        assert log.statements == []


class TestSchemaDrift:
    @pytest.mark.anyio
    async def test_an_absent_table_stops_the_deployment(self, build: Build) -> None:
        """A store pointed at a database with no session table cannot verify anything, and it
        says so while the application is being built rather than on the first request."""
        store, _log = build({"session_table": "sessions_v2"})

        with pytest.raises(ConfigurationError, match="sessions_v2"):
            await connect(store)

    @pytest.mark.anyio
    async def test_a_missing_expected_column_is_a_loud_warning_naming_it(
        self, build: Build, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A default better-auth column that is not there means an upstream schema this library
        has not seen. The store keeps working without it, and says which one is gone."""
        store, _log = build(drop_session_columns=("ipAddress",))

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert "ipAddress" not in record.payload
        assert any("ipAddress" in entry.getMessage() for entry in caplog.records)

    @pytest.mark.anyio
    async def test_a_missing_required_column_stops_the_deployment(self, build: Build) -> None:
        """`token` is how a session is found at all. Warning and carrying on would mean every
        request failing at the database - on the request, rather than at startup."""
        store, _log = build(drop_session_columns=("token",))

        with pytest.raises(ConfigurationError, match="token"):
            await connect(store)

    @pytest.mark.anyio
    async def test_a_missing_user_column_is_reported_too(
        self, build: Build, caplog: pytest.LogCaptureFixture
    ) -> None:
        store, _log = build(drop_user_columns=("image",))

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            await store.fetch_session_by_token(TOKEN)

        assert any("image" in entry.getMessage() for entry in caplog.records)

    @pytest.mark.anyio
    async def test_discovery_happens_once_however_many_fetches_follow(self, build: Build) -> None:
        store, log = build()

        await store.fetch_session_by_token(TOKEN)
        after_first = len(log.statements)
        await store.fetch_session_by_token(TOKEN)
        await store.fetch_user_by_id(USER_ID)

        assert len(log.statements) == after_first + 2

    @pytest.mark.anyio
    async def test_connect_is_idempotent_and_a_fetch_after_it_inspects_nothing(
        self, build: Build
    ) -> None:
        store, log = build()

        await connect(store)
        await connect(store)
        log.statements.clear()
        await store.fetch_session_by_token(TOKEN)

        assert len(log.statements) == 1

    @pytest.mark.anyio
    async def test_the_table_names_are_configurable(self, build: Build) -> None:
        """better-auth lets a deployment rename its tables; a store that hard-coded them would
        be unusable there, with no way to say why."""
        store, _log = build(session_table="auth_session", user_table="auth_user")

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.user is not None


class TestColumnsThisLibraryDoesNotKnow:
    """better-auth's `additionalFields` add columns nobody here has heard of.

    The Redis store reads the whole stored object and could not drop them if it tried, so a
    SQL store that selected only its own list would make two adapters behind one Protocol answer
    different payloads for the same session - a difference nobody would notice until a
    deployment's own field turned up missing on one of them.
    """

    @pytest.mark.anyio
    async def test_an_unknown_session_column_reaches_the_payload(self, build: Build) -> None:
        store, _log = build(
            extra_session_columns=(("tenantId", "TEXT"),),
            sessions=({**SESSION_ROW, "tenantId": "tenant-7"},),
        )

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.payload["tenantId"] == "tenant-7"

    @pytest.mark.anyio
    async def test_an_unknown_user_column_reaches_the_payload_and_parses(
        self, build: Build
    ) -> None:
        """And through to a `User` subclass, which is the whole point of keeping it."""
        store, _log = build(
            extra_user_columns=(("organizationId", "TEXT"),),
            users=({**USER_ROW, "organizationId": "org-3"},),
        )

        record = await store.fetch_user_by_id(USER_ID)

        assert record is not None
        assert record.payload["organizationId"] == "org-3"

    @pytest.mark.anyio
    async def test_the_known_columns_still_come_first(self, build: Build) -> None:
        """Order is not decoration here: it is what keeps a deployment's own column from
        displacing one this library promises, whatever the database lists first."""
        store, _log = build(
            extra_session_columns=(("tenantId", "TEXT"),),
            sessions=({**SESSION_ROW, "tenantId": "tenant-7"},),
        )

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert list(record.payload)[:4] == ["id", "token", "expiresAt", "userId"]
        assert list(record.payload)[-1] == "tenantId"


class TestAmbiguousRows:
    @pytest.mark.anyio
    async def test_two_rows_for_one_token_is_a_miss_and_a_warning(
        self, build: Build, caplog: pytest.LogCaptureFixture
    ) -> None:
        """`session.token` is unique upstream. A schema where it is not - a hand-rolled
        migration, a copied table - can answer one token with two sessions, and picking one of
        them at random is not something a security library gets to do."""
        twin = {**SESSION_ROW, "id": f"{SESSION_ID}-twin"}
        store, _log = build(sessions=(SESSION_ROW, twin), unique_token=False)

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            record = await store.fetch_session_by_token(TOKEN)

        assert record is None
        assert any("more than one row" in entry.getMessage() for entry in caplog.records)

    def test_a_user_row_with_no_usable_id_is_refused_by_the_mapper(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Defence the two shipped statements cannot reach - both match on `user.id`, so a NULL
        one is never selected. The mapper is therefore driven directly, against a plan built the
        way a store builds one: what is pinned is that the mapping refuses a row it cannot
        identify, whoever hands it one."""
        plan = plan_for("session", "user", None, {"session": SESSION_COLUMNS, "user": USER_COLUMNS})
        blank = {f"u_{name}": None for name in plan.user_columns}

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            assert user_from([blank], plan, "probe") is None

        assert any("id is null or blank" in entry.getMessage() for entry in caplog.records)


class TestStatements:
    @pytest.mark.anyio
    async def test_the_reserved_word_and_the_camel_case_columns_are_quoted(
        self, build: Build
    ) -> None:
        """`user` is a reserved word in Postgres and `expiresAt` is not lowercase. Unquoted, the
        first is a syntax error and the second reads a folded name - and neither failure can
        appear against SQLite, which is why the assertion is on the emitted SQL itself."""
        store, log = build()

        await store.fetch_session_by_token(TOKEN)

        emitted = " ".join(log.statements)
        assert '"user"' in emitted
        assert '"expiresAt"' in emitted
        assert '"userId"' in emitted

    @pytest.mark.anyio
    async def test_the_token_travels_as_a_bound_parameter(self, build: Build) -> None:
        store, log = build()

        await store.fetch_session_by_token(TOKEN)

        assert TOKEN not in " ".join(log.statements)


class TestConstruction:
    def test_a_string_url_is_refused_at_construction(self) -> None:
        """A store that accepted a URL would own a connection pool nobody configured."""
        with pytest.raises(ConfigurationError, match="AsyncEngine"):
            SqlAlchemySessionStore(engine="postgresql+asyncpg://localhost/db")  # type: ignore[arg-type]

    @pytest.mark.anyio
    async def test_the_sync_adapter_refuses_an_async_engine(self, tmp_path: pathlib.Path) -> None:
        """The two are one word apart at the call site, and the failure would otherwise be a
        coroutine nobody awaited, at the first request."""
        engine = async_engine(tmp_path / "x.sqlite")

        with pytest.raises(ConfigurationError, match="Engine"):
            SyncStoreAdapter(engine=engine)  # type: ignore[arg-type]
        await engine.dispose()

    def test_the_async_store_refuses_a_sync_engine(self, tmp_path: pathlib.Path) -> None:
        engine = sync_engine(tmp_path / "x.sqlite")

        with pytest.raises(ConfigurationError, match="AsyncEngine"):
            SqlAlchemySessionStore(engine=engine)  # type: ignore[arg-type]
        engine.dispose()

    @pytest.mark.anyio
    @pytest.mark.parametrize("name", ["", "  "], ids=["empty", "blank"])
    async def test_a_blank_table_name_is_refused(self, tmp_path: pathlib.Path, name: str) -> None:
        engine = async_engine(tmp_path / "x.sqlite")

        with pytest.raises(ConfigurationError):
            SqlAlchemySessionStore(engine=engine, session_table=name)
        await engine.dispose()

    @pytest.mark.anyio
    async def test_one_name_for_both_tables_is_refused(self, tmp_path: pathlib.Path) -> None:
        """They would collide in one metadata, and the join would be a table against itself."""
        engine = async_engine(tmp_path / "x.sqlite")

        with pytest.raises(ConfigurationError, match="two different tables"):
            SqlAlchemySessionStore(engine=engine, session_table="auth", user_table="auth")
        await engine.dispose()

    def test_without_sqlalchemy_the_failure_names_the_extra(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Blocked rather than uninstalled, the same way the transports test theirs. The whole
        point of deferring the import is that its absence is a startup refusal saying what to
        install, not an `ImportError` from `import fastapi_better_auth`.

        The attribute has to go as well as the `sys.modules` entry: `from . import x` reads the
        parent package's attribute first, and an earlier test in this session already put it
        there - so blocking only `sys.modules` would leave the import succeeding and this test
        passing for the wrong reason."""
        package = importlib.import_module(PACKAGE)
        monkeypatch.delattr(package, "sqlalchemy_core", raising=False)
        monkeypatch.setitem(sys.modules, f"{PACKAGE}.sqlalchemy_core", None)

        with pytest.raises(ConfigurationError) as caught:
            SqlAlchemySessionStore(engine=object())  # type: ignore[arg-type]

        assert "fastapi-better-auth-bridge[sqlalchemy]" in str(caught.value)
