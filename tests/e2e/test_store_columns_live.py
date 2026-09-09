"""The column allow-list against the live migrated schema, on a column this module adds itself.

The unit lane proves the rule against a SQLite schema we wrote. What it cannot show is that the
allow-list survives the round trip it exists for: a *real* `user` table, introspected by
`asyncpg` through SQLAlchemy's own inspector, carrying a column Better Auth never heard of - which
is exactly the shape issue #49 came from, a shared database whose `user` table another service
also writes to.

The extra column is `ALTER`ed on at module setup and taken off again in a `finally`, and the value
is set on a user this module signed up for itself. Never the seed user: every other lane reads it.
An unknown column is silent at discovery (D-156), so no other lane can see the window this holds
open either way.

A module of its own: `user_columns` is a post-0.4.0 keyword, and a module that names it must skip
on the published wheel rather than raise - which is what the guard below and the feature-detect
after it do (the `test_cookie_live.py` / `test_remote_gate_live.py` pattern, D-256).

Asyncio only: `asyncpg` drives the event loop directly, as in every other store-backed lane.
"""

from __future__ import annotations

import inspect
from collections.abc import AsyncIterator, Iterator

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

# `ConfigurationError` is a 0.1.0 name, so it needs no guard; the store below does.
from fastapi_better_auth import ConfigurationError

from .conftest import (
    PASSWORD,
    POSTGRES_URL,
    harness_sql,
    sign_in,
    sign_out,
    sign_up,
)

try:
    # The stores are post-0.1.0, so this import belongs under the guard like every other one:
    # an unguarded name here would make the published-wheel lane red instead of skipping.
    from fastapi_better_auth import SqlAlchemySessionStore
except ImportError:
    pytest.skip(
        "this build of fastapi-better-auth-bridge publishes no session stores",
        allow_module_level=True,
    )

if "user_columns" not in inspect.signature(SqlAlchemySessionStore.__init__).parameters:
    pytest.skip(
        "this build of fastapi-better-auth-bridge predates user_columns (added after 0.4.0)",
        allow_module_level=True,
    )

pytestmark = pytest.mark.e2e

COLUMN = "wp24_internal"
ABSENT = "wp24_never_created"
VALUE = "internal-do-not-publish"

ADD_COLUMN = f'ALTER TABLE "user" ADD COLUMN IF NOT EXISTS {COLUMN} text'
REMOVE_COLUMN = f'ALTER TABLE "user" DROP COLUMN IF EXISTS {COLUMN}'
SET_VALUE = "UPDATE \"user\" SET {column} = '{value}' WHERE id = '{user_id}'"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="module")
def internal_column() -> Iterator[str]:
    """The extra column, for this module only. Taken off again however the tests end."""
    harness_sql(ADD_COLUMN)
    try:
        yield COLUMN
    finally:
        harness_sql(REMOVE_COLUMN)


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    built = create_async_engine(POSTGRES_URL)
    yield built
    await built.dispose()


@pytest.fixture
def subject(harness: str, internal_column: str) -> Iterator[str]:
    """A user nobody else's lane shares, carrying a value on the extra column. Yields its id."""
    user_id, email = sign_up(harness, "wp24-columns")
    harness_sql(SET_VALUE.format(column=internal_column, value=VALUE, user_id=user_id))
    cookie = sign_in(harness, email, PASSWORD)
    yield user_id
    sign_out(harness, cookie)


@pytest.mark.anyio
async def test_without_an_allow_list_the_extra_column_reaches_the_payload(
    engine: AsyncEngine, subject: str
) -> None:
    """Prove the instrument, and reproduce the issue: a column another service put on the shared
    `user` table travels to `StoredUser.payload`, and from there to the verified session."""
    store = SqlAlchemySessionStore(engine=engine)

    record = await store.fetch_user_by_id(subject)

    assert record is not None
    assert record.payload[COLUMN] == VALUE


@pytest.mark.anyio
async def test_an_empty_allow_list_keeps_it_out_of_the_payload(
    engine: AsyncEngine, subject: str
) -> None:
    store = SqlAlchemySessionStore(engine=engine, user_columns=[])

    record = await store.fetch_user_by_id(subject)

    assert record is not None
    assert COLUMN not in record.payload
    assert VALUE not in str(dict(record.payload))


@pytest.mark.anyio
async def test_better_auths_own_columns_still_arrive_under_the_allow_list(
    engine: AsyncEngine, subject: str
) -> None:
    """The half that must never narrow. `banned` is read from the live admin column, so a ban is
    still this library's to enforce whatever the deployment asked to hide."""
    store = SqlAlchemySessionStore(engine=engine, user_columns=[])

    record = await store.fetch_user_by_id(subject)

    assert record is not None
    assert record.id == subject
    assert record.banned is False
    assert record.payload["email"]
    assert record.payload["emailVerified"] is False
    assert "banExpires" in record.payload


@pytest.mark.anyio
async def test_a_name_the_live_table_does_not_have_stops_the_deployment(
    engine: AsyncEngine, internal_column: str
) -> None:
    """Against the real inspector, not a schema we declared: the refusal is decided by what
    Postgres answers, at the same point a missing required column would stop the application."""
    store = SqlAlchemySessionStore(engine=engine, user_columns=[internal_column, ABSENT])

    with pytest.raises(ConfigurationError, match=ABSENT) as caught:
        await store.connect()

    assert "user" in str(caught.value)
