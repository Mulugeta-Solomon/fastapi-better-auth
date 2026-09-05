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

import base64
import hashlib
import hmac
import importlib
import logging
import pathlib
import sys
from collections.abc import AsyncIterator, Callable
from datetime import datetime, timezone
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.ext.asyncio import AsyncEngine
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    AuthServiceUnavailable,
    ConfigurationError,
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
    user_from,
)
from fastapi_better_auth._internal.stores.upstream import as_db_flag, as_text
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
FAR_FUTURE = datetime(2999, 1, 1, tzinfo=timezone.utc)
LONE_SURROGATE_TOKEN = chr(0xD800) + "abc"
"""An unpaired surrogate: a `str` Python holds happily and cannot encode as UTF-8.

Spelled with `chr` rather than an escape so this file itself stays encodable.
"""
PACKAGE = "fastapi_better_auth._internal.stores"
VERIFIER_SECRET = SharedSecret("Qb8Xm2vTz6Lp1RkYd9Wn4Hs7Cj3Fg5Ae")

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

    @pytest.mark.anyio
    async def test_both_statements_carry_a_row_limit(self, build: Build) -> None:
        """C6. `fetchmany` + the ambiguous-row check preserve the behaviour even without it, so
        the DB-side `LIMIT` is a mutation survivor - but it is what stops the database from
        materializing a large duplicate result before the client caps it. Pinned on the SQL."""
        store, log = build()

        await store.fetch_session_by_token(TOKEN)
        await store.fetch_user_by_id(USER_ID)

        for statement in selects(log):
            assert "LIMIT" in statement.upper()


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


class TestQueryErrorTranslation:
    """A1. SQLAlchemy's `DBAPIError.str()` embeds the bound parameters, so a query-time database
    error - a timeout, a deadlock, a failover mid-query - carries the raw session token unless the
    store translates it. A DB error during auth is routine, not exotic."""

    @pytest.mark.anyio
    async def test_a_query_error_becomes_an_auth_service_unavailable_with_no_token(
        self, build: Build, tmp_path: pathlib.Path
    ) -> None:
        store, _log = build()
        await connect(store)
        # Break the query itself, after the schema was discovered: the next SELECT carries the
        # token as a bound parameter and fails at the driver, the shape a timeout/failover takes.
        breaker = sync_engine(tmp_path / "harness0.sqlite")
        with breaker.begin() as connection:
            connection.execute(text('DROP TABLE "session"'))
        breaker.dispose()

        with pytest.raises(AuthServiceUnavailable) as caught:
            await store.fetch_session_by_token(TOKEN)

        rendered = _leak_surface(caught.value)
        assert TOKEN not in rendered
        assert "tok_fp=" in caught.value.reason
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None

    @pytest.mark.anyio
    async def test_a_user_lookup_error_carries_no_user_id(
        self, build: Build, tmp_path: pathlib.Path
    ) -> None:
        store, _log = build()
        await connect(store)
        breaker = sync_engine(tmp_path / "harness0.sqlite")
        with breaker.begin() as connection:
            connection.execute(text('DROP TABLE "user"'))
        breaker.dispose()

        with pytest.raises(AuthServiceUnavailable) as caught:
            await store.fetch_user_by_id(USER_ID)

        assert USER_ID not in _leak_surface(caught.value)


class TestCollationFolding:
    """A2. Equality was delegated to `WHERE token = :token`, i.e. to the DB collation. On MySQL's
    default `utf8mb4_0900_ai_ci` a folded token matches a different row; WP11 derives the CSRF
    double-submit token from `session_token`, so a `.token` that is not the presented credential
    breaks that binding. The reproduction is the test."""

    @pytest.mark.anyio
    async def test_a_case_folded_token_does_not_return_a_wrong_record(
        self, build: Build, caplog: pytest.LogCaptureFixture
    ) -> None:
        store, _log = build(token_collation="NOCASE")
        asked = TOKEN.swapcase()
        assert asked != TOKEN

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            record = await store.fetch_session_by_token(asked)

        assert record is None
        assert any("different session" in entry.getMessage() for entry in caplog.records)

    @pytest.mark.anyio
    async def test_the_exact_token_still_matches_under_a_folding_collation(
        self, build: Build
    ) -> None:
        """The compare must not reject the legitimate request that the collation also matched."""
        store, _log = build(token_collation="NOCASE")

        record = await store.fetch_session_by_token(TOKEN)

        assert record is not None
        assert record.token == TOKEN


class TestMalformedBanned:
    """A3. The Redis store refuses a present-but-not-boolean `banned`; the SQL store must too, or
    the two answer the same session differently - the exact divergence `plan_for` exists to
    prevent. SQLAlchemy's lenient `Boolean` would coerce a stray `'false'` to `True` unseen, so
    `banned` is read raw and validated."""

    @pytest.mark.anyio
    async def test_a_nonboolean_banned_is_a_miss(
        self, build: Build, caplog: pytest.LogCaptureFixture
    ) -> None:
        store, _log = build(users=({**USER_ROW, "banned": "false"},))

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            record = await store.fetch_user_by_id(USER_ID)

        assert record is None
        assert any("banned field is not a boolean" in e.getMessage() for e in caplog.records)

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("stored", "expected"),
        [(True, True), (False, False), (1, True), (0, False)],
        ids=["bool-true", "bool-false", "int-1", "int-0"],
    )
    async def test_a_native_boolean_encoding_reads_correctly(
        self, build: Build, stored: object, expected: bool
    ) -> None:
        """Postgres answers a real bool; SQLite and MySQL store it as the integer 0/1. Both must
        read as the same bool, and land the same bool on the payload (parity with Redis)."""
        store, _log = build(users=({**USER_ROW, "banned": stored},))

        record = await store.fetch_user_by_id(USER_ID)

        assert record is not None
        assert record.banned is expected
        assert record.payload["banned"] is expected

    @pytest.mark.anyio
    async def test_a_mapper_row_with_a_nonboolean_banned_is_refused(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The mapper directly, the way `test_a_user_row_with_no_usable_id...` drives it - so the
        guard is pinned whatever a future column typing feeds it."""
        plan = plan_for("session", "user", None, {"session": SESSION_COLUMNS, "user": USER_COLUMNS})
        row: dict[str, Any] = {f"u_{name}": None for name in plan.user_columns}
        row["u_id"] = USER_ID
        row["u_banned"] = 2  # neither a bool nor the 0/1 a database boolean encodes to

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            assert user_from([row], plan, "probe") is None

        assert any("banned field is not a boolean" in e.getMessage() for e in caplog.records)


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
    async def test_a_banned_of_one_is_a_refusal_and_never_an_escape(self, build: Build) -> None:
        store, _log = build(
            sessions=({**SESSION_ROW, "expiresAt": FAR_FUTURE},),
            users=({**USER_ROW, "banned": 1},),
        )
        verifier = CookieVerifier(
            secret=VERIFIER_SECRET,
            store=store,
            csrf=CsrfDisabled(reason="this row is about the ban check, not CSRF"),
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


class TestConcurrentDiscovery:
    """C4. The double-checked lock's inner `if self._plan is None:` is the package's only branch a
    single-threaded test cannot exercise. A burst of first fetches must inspect the schema once."""

    @pytest.mark.anyio
    async def test_a_burst_of_first_fetches_inspects_the_schema_once(
        self, build: Build, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import anyio

        from fastapi_better_auth._internal.stores import sqlalchemy_core

        calls = 0
        real = sqlalchemy_core.reflected

        def counting(*args: Any, **kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            return real(*args, **kwargs)

        monkeypatch.setattr(sqlalchemy_core, "reflected", counting)
        store, _log = build()

        async with anyio.create_task_group() as tg:
            for _ in range(20):
                tg.start_soon(store.fetch_session_by_token, TOKEN)

        assert calls == 1


def _leak_surface(exc: BaseException) -> str:
    """Everything an error reporter can reach off an exception - str, args, and the whole
    __cause__/__context__ chain - so a token hiding on a chained DBAPIError is caught."""
    parts: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        parts.append(str(current))
        parts.append(repr(current.args))
        parts.append(getattr(current, "reason", ""))
        current = current.__cause__ or current.__context__
    return "\n".join(parts)
