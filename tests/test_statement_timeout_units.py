"""The pieces of `statement_timeout=` that need no server: the conversion, the statement, and the
two checks that refuse an engine on which the bound would not hold.

**Milliseconds, rounded up.** Postgres takes `statement_timeout` as an int of milliseconds and reads
zero as no timeout, so seconds are rounded up, never down: below one millisecond is one. The
conversion reads the value as the decimal it was written as, so binary float error does not move
it: `1.1 * 1000` is `1100.0000000000002` in binary, and that must still be 1100 ms, not 1101.

**The statement, as the driver receives it.** One Core `SELECT set_config(...)`, compiled for
asyncpg: the setting's name and its value travel as bound parameters, and the third argument is
the literal `true` that makes the setting last only until the end of the transaction. That `true`
is what keeps the bound out of the pool's other checkouts, and no live test can tell it from
`false` while every transaction the store opens rolls back, so it is pinned here, in the text.
"""

from __future__ import annotations

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql.asyncpg import PGDialect_asyncpg
from sqlalchemy.ext.asyncio import create_async_engine

from fastapi_better_auth import ConfigurationError
from fastapi_better_auth._internal.stores import statement_timeout
from fastapi_better_auth._internal.stores.sqlalchemy_core import (
    confirmed_bound,
    refuse_autocommit,
    timeout_params,
    timeout_statement,
)
from tests.stores import SETTINGS_STATEMENT


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (1, 1000),
        (3, 3000),
        (1.5, 1500),
        (1.1, 1100),
        (2.3, 2300),
        (0.007, 7),
        (0.0015, 2),
        (0.0001, 1),
        (1e-9, 1),
        (2_147_483.647, 2_147_483_647),
        (2_147_483.6471, 2_147_483_648),
    ],
)
def test_seconds_become_whole_milliseconds_rounded_up(seconds: float, expected: int) -> None:
    assert statement_timeout.milliseconds(seconds) == expected


def test_the_maximum_is_postgres_own() -> None:
    """`max_val` of `statement_timeout` in `pg_settings`, read on the harness's Postgres 17."""
    assert statement_timeout.MAX_MILLISECONDS == 2**31 - 1


def test_the_statement_names_the_setting_and_binds_its_value() -> None:
    compiled = timeout_statement().compile(dialect=PGDialect_asyncpg())
    values = {**compiled.params, **timeout_params(1500)}

    assert str(compiled) == SETTINGS_STATEMENT
    assert [values[name] for name in compiled.positiontup or ()] == ["statement_timeout", "1500"]


def test_the_local_flag_is_in_the_text_for_every_postgres_driver() -> None:
    """psycopg renders its parameters differently; the flag is the same literal."""
    compiled = str(timeout_statement().compile(dialect=postgresql.dialect()))

    assert compiled.startswith("SELECT set_config(")
    assert ", true)" in compiled


@pytest.mark.parametrize(
    "rows",
    [
        [("0", "default")],
        [("1500", "user")],
        [("1500", "database")],
        [("1500", "client")],
        [("3000", "session")],
        [],
    ],
    ids=["server-default", "role-equal", "database-equal", "connect-equal", "other-value", "none"],
)
def test_only_the_stores_own_value_set_in_this_session_is_a_bound_that_held(
    rows: list[tuple[str, str]],
) -> None:
    """Read back on an engine in AUTOCOMMIT, the setting has ended, and what is read is someone
    else's - even an equal value, from the role or the database, which would bound the store only
    until it changed. Only the store's value from `session` is its own."""
    with pytest.raises(ConfigurationError, match="AUTOCOMMIT"):
        confirmed_bound(rows, 1500)


def test_the_stores_own_value_set_in_this_session_is_a_bound_that_held() -> None:
    confirmed_bound([("1500", "session")], 1500)


def test_an_engine_whose_options_say_autocommit_is_refused() -> None:
    """No connection is opened: the engine's options are read."""
    engine = create_async_engine("postgresql+asyncpg://bridge@db-host.invalid/app")

    refuse_autocommit(engine)
    with pytest.raises(ConfigurationError, match="AUTOCOMMIT"):
        refuse_autocommit(engine.execution_options(isolation_level="AUTOCOMMIT"))
