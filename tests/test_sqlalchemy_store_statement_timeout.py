"""`SqlAlchemySessionStore(statement_timeout=...)`: what is refused when the store is built, and
that leaving it unset changes nothing the store sends (#121).

The option bounds every transaction the store opens with a transaction-local Postgres
`statement_timeout`. What it does on a live server is proven in
`tests/e2e/test_store_statement_timeout_live.py`; this suite has no Postgres, so it holds what can
be decided without one. A Postgres engine is still built here, because building one opens no
connection: nothing below reaches a server.

- **The value.** Seconds, like every other deadline in this library: a positive, finite number.
  Postgres reads `statement_timeout = 0` as no timeout at all, so zero is refused rather than
  passed on, and so is anything above the largest value the server accepts (an int of
  milliseconds).
- **The dialect.** Postgres only. Any other engine is refused with the option set, and built as
  before without it.
- **Unset.** `None` is the default, and the store then sends exactly what it sent before the
  option existed: byte for byte what a store built without the keyword sends, one statement per
  lookup, and no settings statement anywhere.
- **`SyncStoreAdapter`** has no such option, and refuses the keyword as it refuses any unknown one.
"""

from __future__ import annotations

import math
import pathlib
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from fastapi_better_auth import ConfigurationError, SqlAlchemySessionStore, SyncStoreAdapter
from tests.stores import TOKEN, USER_ID, StatementLog, async_engine, build_schema, sync_engine

USERNAME = "bridge-user"
PASSWORD = "pw-Hunter2-sekrit"
HOST = "db-host.invalid"
POSTGRES_URL = f"postgresql+asyncpg://{USERNAME}:{PASSWORD}@{HOST}:5432/app"
"""Never connected to: a refusal must come before any connection, and must not echo the URL."""

POSTGRES_MAX_MILLISECONDS = 2_147_483_647
"""`statement_timeout`'s `max_val` in `pg_settings`: a signed 32-bit int of milliseconds."""

UNKNOWN_TOKEN = "5RmMvJt3xQ8bWfKcApZnUhLd2YeGsT7q"

NOT_SECONDS: tuple[tuple[str, object], ...] = (
    ("true", True),
    ("false", False),
    ("string", "2"),
    ("bytes", b"2"),
    ("zero", 0),
    ("zero-float", 0.0),
    ("negative", -1),
    ("negative-float", -0.5),
    ("inf", math.inf),
    ("negative-inf", -math.inf),
    ("nan", math.nan),
    ("beyond-a-float", 10**400),
)

ABOVE_THE_MAXIMUM: tuple[tuple[str, object], ...] = (
    ("one-millisecond-over", 2_147_483.648),
    ("a-fraction-of-one-over", 2_147_483.6471),
    ("whole-seconds", 2_147_484),
    ("a-billion", 10**9),
)


@pytest.fixture
def anyio_backend() -> str:
    """aiosqlite is an asyncio driver."""
    return "asyncio"


@pytest.fixture
def postgres() -> AsyncEngine:
    return create_async_engine(POSTGRES_URL)


def assert_quiet_about_the_url(refusal: ConfigurationError) -> None:
    for leaked in (PASSWORD, USERNAME, HOST):
        assert leaked not in str(refusal)
        assert leaked not in repr(refusal)


class TestTheValue:
    @pytest.mark.parametrize(
        "value", [case[1] for case in NOT_SECONDS], ids=[c[0] for c in NOT_SECONDS]
    )
    def test_a_value_that_is_not_a_positive_finite_number_of_seconds_is_refused(
        self, postgres: AsyncEngine, value: object
    ) -> None:
        """Zero above all: Postgres reads it as no timeout, so passing it on would configure an
        unbounded store that its operator believes is bounded."""
        options: dict[str, Any] = {"statement_timeout": value}

        with pytest.raises(ConfigurationError, match="statement_timeout") as caught:
            SqlAlchemySessionStore(engine=postgres, **options)

        assert "positive, finite number of seconds" in str(caught.value)
        assert_quiet_about_the_url(caught.value)

    @pytest.mark.parametrize(
        "value", [case[1] for case in ABOVE_THE_MAXIMUM], ids=[c[0] for c in ABOVE_THE_MAXIMUM]
    )
    def test_a_value_above_the_largest_postgres_accepts_is_refused(
        self, postgres: AsyncEngine, value: object
    ) -> None:
        """Rounded up to whole milliseconds first, so a value that would round past the maximum is
        refused here rather than by the server at the first lookup."""
        options: dict[str, Any] = {"statement_timeout": value}

        with pytest.raises(ConfigurationError, match="statement_timeout") as caught:
            SqlAlchemySessionStore(engine=postgres, **options)

        assert str(POSTGRES_MAX_MILLISECONDS) in str(caught.value)
        assert_quiet_about_the_url(caught.value)

    @pytest.mark.parametrize(
        "value",
        [2_147_483.647, 3, 1.5, 0.0001, 1e-9],
        ids=["the-maximum", "int", "float", "a-tenth-of-a-millisecond", "a-nanosecond"],
    )
    def test_a_positive_value_up_to_the_maximum_is_accepted(
        self, postgres: AsyncEngine, value: float
    ) -> None:
        """A value below one millisecond is accepted: it is rounded up to one, never down to the
        zero that would mean no timeout."""
        SqlAlchemySessionStore(engine=postgres, statement_timeout=value)

    def test_none_is_accepted_and_is_the_default(self, postgres: AsyncEngine) -> None:
        SqlAlchemySessionStore(engine=postgres, statement_timeout=None)


class TestTheDialect:
    def test_another_dialect_is_refused_when_the_store_is_built(
        self, tmp_path: pathlib.Path
    ) -> None:
        """Only the dialect's name is quoted, never the engine's URL. A SQLite URL has one place
        for a secret, the file's name, so the secret is put there."""
        engine = async_engine(tmp_path / f"{PASSWORD}.sqlite")

        with pytest.raises(ConfigurationError, match="statement_timeout") as caught:
            SqlAlchemySessionStore(engine=engine, statement_timeout=1)

        message = str(caught.value)
        assert "PostgreSQL only" in message
        assert "sqlite" in message
        assert_quiet_about_the_url(caught.value)

    def test_another_dialect_builds_as_before_without_it(self, tmp_path: pathlib.Path) -> None:
        engine = async_engine(tmp_path / "other.sqlite")

        SqlAlchemySessionStore(engine=engine, statement_timeout=None)
        SqlAlchemySessionStore(engine=engine)


class TestUnset:
    """Pinned on SQLite, the database this suite has: what the store sends with the option unset
    is byte for byte what it sends without the keyword, and each lookup is one statement. The
    live module pins the same on Postgres, and that the option set adds the settings statement
    and nothing else."""

    @staticmethod
    async def driven(path: pathlib.Path, options: dict[str, Any]) -> StatementLog:
        engine = async_engine(path)
        log = StatementLog()
        log.attach(engine)
        store = SqlAlchemySessionStore(engine=engine, **options)
        try:
            await store.connect()
            await store.fetch_session_by_token(TOKEN)
            await store.fetch_session_by_token(UNKNOWN_TOKEN)
            await store.fetch_user_by_id(USER_ID)
        finally:
            await engine.dispose()
        return log

    @pytest.mark.anyio
    async def test_none_sends_exactly_what_a_store_without_the_keyword_sends(
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
        engine = async_engine(path)
        log = StatementLog()
        log.attach(engine)
        store = SqlAlchemySessionStore(engine=engine, statement_timeout=None)
        try:
            await store.connect()
            before = len(log.statements)
            await store.fetch_session_by_token(TOKEN)
            after_session = len(log.statements)
            await store.fetch_user_by_id(USER_ID)
            after_user = len(log.statements)
        finally:
            await engine.dispose()

        assert after_session - before == 1
        assert after_user - after_session == 1


def test_the_sync_adapter_refuses_the_keyword_as_it_refuses_any_unknown_one(
    tmp_path: pathlib.Path,
) -> None:
    """Pinned, not new: the option is `SqlAlchemySessionStore`'s alone. The adapter's lane has no
    synchronous Postgres driver, so an option there would ship unproven."""
    engine = sync_engine(tmp_path / "sync.sqlite")
    options: dict[str, Any] = {"statement_timeout": 1}
    try:
        with pytest.raises(TypeError, match="statement_timeout"):
            SyncStoreAdapter(engine=engine, **options)
    finally:
        engine.dispose()
