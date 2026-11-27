"""`SyncStoreAdapter(statement_timeout=...)`: what is refused when the adapter is built, what it
sends for each synchronous Postgres driver, and that leaving it unset changes nothing it sends.

The option is `SqlAlchemySessionStore`'s, with the same name and meaning: every transaction the
adapter opens sets a transaction-local Postgres `statement_timeout` before it reads anything. Its
live proof, on psycopg and psycopg2 and on both anyio backends, is in
`tests/e2e/test_sync_store_statement_timeout_live.py`. This suite has no Postgres. A case that
builds a Postgres engine needs that engine's driver, because SQLAlchemy imports it when the engine
is built, and skips where it is absent. Every other case runs everywhere.

- **The value.** Validated by the function the async store uses, before the dialect is looked at,
  so the refusals need no Postgres driver and say exactly what the async store's say.
- **The dialect.** Postgres only, refused on another engine without quoting its URL.
- **The statements.** Compiled for each sync dialect class, which imports no driver: the texts the
  read-only invariant names for psycopg and psycopg2, and the values they carry.
- **Unset.** Byte for byte what an adapter built without the keyword sends, and one statement per
  lookup.
"""

from __future__ import annotations

import pathlib
from typing import Any, cast

import pytest
from sqlalchemy import Engine, Select
from sqlalchemy.dialects.postgresql.psycopg import PGDialect_psycopg
from sqlalchemy.dialects.postgresql.psycopg2 import PGDialect_psycopg2
from sqlalchemy.engine.interfaces import Dialect

from fastapi_better_auth import ConfigurationError, SqlAlchemySessionStore, SyncStoreAdapter
from fastapi_better_auth._internal.stores.sqlalchemy_core import (
    probe_params,
    readback_statement,
    refuse_autocommit,
    timeout_params,
    timeout_statement,
)
from tests.statement_timeout_cases import (
    ABOVE_THE_MAXIMUM,
    ACCEPTED,
    NOT_SECONDS,
    POSTGRES_MAX_MILLISECONDS,
    ids,
    values,
)
from tests.stores import (
    PROBE_SETTING,
    PSYCOPG2_SETTINGS_STATEMENT,
    PSYCOPG_SETTINGS_STATEMENT,
    SETTING,
    SYNC_DRIVERS,
    TOKEN,
    USER_ID,
    StatementLog,
    async_engine,
    build_schema,
    setting_values,
    sync_engine,
    sync_postgres_engine,
)

USERNAME = "bridge-user"
PASSWORD = "pw-Hunter2-sekrit"
HOST = "db-host.invalid"
POSTGRES_URL = f"postgresql://{USERNAME}:{PASSWORD}@{HOST}:5432/app"
"""Never connected to: a refusal must come before any connection, and must not echo the URL."""

UNKNOWN_TOKEN = "5RmMvJt3xQ8bWfKcApZnUhLd2YeGsT7q"
PROBE = "0123456789abcdef" * 2

DIALECTS: tuple[tuple[str, Dialect, str], ...] = (
    ("psycopg", PGDialect_psycopg(), PSYCOPG_SETTINGS_STATEMENT),
    ("psycopg2", PGDialect_psycopg2(), PSYCOPG2_SETTINGS_STATEMENT),
)
"""Each sync driver's dialect class, which imports no driver, and the settings statement it sends."""


@pytest.fixture(params=SYNC_DRIVERS)
def postgres(request: pytest.FixtureRequest) -> Engine:
    """A never-connected Postgres engine through each sync driver; skipped where it is absent."""
    return sync_postgres_engine(str(request.param), POSTGRES_URL)


@pytest.fixture
def sqlite(tmp_path: pathlib.Path) -> Engine:
    """A sync engine that is not Postgres, with a secret in the one place its URL has for one."""
    return sync_engine(tmp_path / f"{PASSWORD}.sqlite")


def assert_quiet_about_the_url(refusal: ConfigurationError) -> None:
    for leaked in (PASSWORD, USERNAME, HOST):
        assert leaked not in str(refusal)
        assert leaked not in repr(refusal)


def refusals(engine: Engine, tmp_path: pathlib.Path, value: object) -> tuple[str, str]:
    """What the adapter and the async store each say about `value`, both on SQLite."""
    options: dict[str, Any] = {"statement_timeout": value}
    with pytest.raises(ConfigurationError) as sync_refusal:
        SyncStoreAdapter(engine=engine, **options)
    with pytest.raises(ConfigurationError) as async_refusal:
        SqlAlchemySessionStore(engine=async_engine(tmp_path / "async.sqlite"), **options)
    assert_quiet_about_the_url(sync_refusal.value)
    return str(sync_refusal.value), str(async_refusal.value)


class TestTheValue:
    @pytest.mark.parametrize("value", values(NOT_SECONDS), ids=ids(NOT_SECONDS))
    def test_a_value_that_is_not_a_positive_finite_number_of_seconds_is_refused_as_by_the_store(
        self, sqlite: Engine, tmp_path: pathlib.Path, value: object
    ) -> None:
        """Checked before the dialect: on SQLite the value is what is refused, not the engine."""
        said, store_said = refusals(sqlite, tmp_path, value)

        assert "positive, finite number of seconds" in said
        assert said == store_said

    @pytest.mark.parametrize("value", values(ABOVE_THE_MAXIMUM), ids=ids(ABOVE_THE_MAXIMUM))
    def test_a_value_above_the_largest_postgres_accepts_is_refused_as_by_the_store(
        self, sqlite: Engine, tmp_path: pathlib.Path, value: object
    ) -> None:
        said, store_said = refusals(sqlite, tmp_path, value)

        assert str(POSTGRES_MAX_MILLISECONDS) in said
        assert said == store_said

    @pytest.mark.parametrize("value", values(ACCEPTED), ids=ids(ACCEPTED))
    def test_a_positive_value_up_to_the_maximum_is_accepted(
        self, postgres: Engine, value: float
    ) -> None:
        SyncStoreAdapter(engine=postgres, statement_timeout=value)

    def test_none_is_accepted(self, postgres: Engine) -> None:
        SyncStoreAdapter(engine=postgres, statement_timeout=None)


class TestTheDialect:
    def test_another_dialect_is_refused_when_the_adapter_is_built(self, sqlite: Engine) -> None:
        with pytest.raises(ConfigurationError, match="statement_timeout") as caught:
            SyncStoreAdapter(engine=sqlite, statement_timeout=1)

        message = str(caught.value)
        assert "PostgreSQL only" in message
        assert "sqlite" in message
        assert_quiet_about_the_url(caught.value)

    def test_another_dialect_builds_as_before_without_it(self, sqlite: Engine) -> None:
        SyncStoreAdapter(engine=sqlite, statement_timeout=None)
        SyncStoreAdapter(engine=sqlite)


@pytest.mark.parametrize("spelling", ["AUTOCOMMIT", "autocommit", "AutoCommit"])
def test_a_sync_engine_whose_options_say_autocommit_is_refused(
    sqlite: Engine, spelling: str
) -> None:
    """The check reads the engine's options and opens no connection, for a sync engine as for an
    async one, so any dialect shows it."""
    refuse_autocommit(sqlite)
    with pytest.raises(ConfigurationError, match="AUTOCOMMIT"):
        refuse_autocommit(sqlite.execution_options(isolation_level=spelling))


class TestTheStatements:
    """As each sync driver receives them. psycopg renders a cast after each value and psycopg2
    renders none; both name their values, and the read-only invariant names both texts."""

    @pytest.mark.parametrize(("dialect", "expected"), [d[1:] for d in DIALECTS], ids=SYNC_DRIVERS)
    def test_the_bound_is_the_statement_the_invariant_names(
        self, dialect: Dialect, expected: str
    ) -> None:
        compiled = timeout_statement().compile(dialect=dialect)
        params = compiled.construct_params(timeout_params(1500))

        assert str(compiled) == expected
        assert setting_values(str(compiled), params) == (SETTING, "1500")

    @pytest.mark.parametrize(("dialect", "expected"), [d[1:] for d in DIALECTS], ids=SYNC_DRIVERS)
    def test_the_probe_is_the_same_statement(self, dialect: Dialect, expected: str) -> None:
        compiled = timeout_statement().compile(dialect=dialect)
        params = compiled.construct_params(probe_params(PROBE))

        assert str(compiled) == expected
        assert setting_values(str(compiled), params) == (PROBE_SETTING, PROBE)

    @pytest.mark.parametrize("dialect", [d[1] for d in DIALECTS], ids=SYNC_DRIVERS)
    def test_the_readback_reads_the_probe_and_the_bound(self, dialect: Dialect) -> None:
        statement = readback_statement()
        assert isinstance(statement, Select)
        compiled = cast("Select[Any]", statement).compile(dialect=dialect)
        text = str(compiled)

        assert "current_setting(%(probe)s" in text
        assert "FROM pg_catalog.pg_settings" in text
        assert compiled.construct_params() == {"probe": PROBE_SETTING, "setting": SETTING}


class TestUnset:
    """Pinned on SQLite, which this suite has, on both anyio backends. The live module pins the
    same on Postgres for each driver, and that the option set adds its statements and no other."""

    @staticmethod
    async def driven(path: pathlib.Path, options: dict[str, Any]) -> StatementLog:
        engine = sync_engine(path)
        log = StatementLog()
        log.attach(engine)
        store = SyncStoreAdapter(engine=engine, **options)
        try:
            await store.connect()
            await store.fetch_session_by_token(TOKEN)
            await store.fetch_session_by_token(UNKNOWN_TOKEN)
            await store.fetch_user_by_id(USER_ID)
        finally:
            engine.dispose()
        return log

    @pytest.mark.anyio
    async def test_none_sends_exactly_what_an_adapter_without_the_keyword_sends(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "unset.sqlite"
        build_schema(path)

        without = await self.driven(path, {})
        unset = await self.driven(path, {"statement_timeout": None})

        assert without.statements, "nothing was executed; this proves nothing"
        assert unset.statements == without.statements
        assert unset.parameters == without.parameters
        assert unset.settings == []

    @pytest.mark.anyio
    async def test_each_lookup_is_one_statement_with_the_option_unset(
        self, tmp_path: pathlib.Path
    ) -> None:
        path = tmp_path / "count.sqlite"
        build_schema(path)
        engine = sync_engine(path)
        log = StatementLog()
        log.attach(engine)
        store = SyncStoreAdapter(engine=engine, statement_timeout=None)
        try:
            await store.connect()
            before = len(log.statements)
            await store.fetch_session_by_token(TOKEN)
            after_session = len(log.statements)
            await store.fetch_user_by_id(USER_ID)
            after_user = len(log.statements)
        finally:
            engine.dispose()

        assert after_session - before == 1
        assert after_user - after_session == 1
