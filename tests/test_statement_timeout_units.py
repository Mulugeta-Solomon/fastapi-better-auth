"""The pieces of `statement_timeout=` that need no server: the conversion, the statement, and the
two checks that refuse an engine on which the bound would not hold.

**Milliseconds, rounded up.** Postgres takes `statement_timeout` as an int of milliseconds and reads
zero as no timeout, so seconds are rounded up, never down: below one millisecond is one. The
conversion reads the value as the decimal it was written as, so binary float error does not move
it: `16.1 * 1000` is `16100.000000000002` in binary, and that must still be 16100 ms, not 16101.

**The statement, as the driver receives it.** One Core `SELECT set_config(...)`, compiled for
asyncpg: the setting's name and its value travel as bound parameters, and the third argument is
the literal `true` that makes the setting last only until the end of the transaction. That `true`
is what keeps the bound out of the pool's other checkouts, and no live test can tell it from
`false` while every transaction the store opens rolls back, so it is pinned here, in the text.

**The readback's verdicts.** Discovery sets a random probe, then the bound, then reads both back.
Only this discovery's own probe, with the store's value set in this session, is a bound that held.
"""

from __future__ import annotations

import decimal
import enum
from typing import Any, cast

import pytest
from sqlalchemy import Select
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql.asyncpg import PGDialect_asyncpg

from fastapi_better_auth import ConfigurationError
from fastapi_better_auth._internal.stores import statement_timeout
from fastapi_better_auth._internal.stores.sqlalchemy_core import (
    confirmed_bound,
    new_probe,
    probe_params,
    readback_statement,
    refuse_autocommit,
    settings_in_order,
    timeout_params,
    timeout_statement,
)
from tests.stores import PROBE_SETTING, PROBE_VALUE, SETTINGS_STATEMENT, postgres_engine

PROBE = "0123456789abcdef" * 2
"""This discovery's probe, in the readback cases."""
NEVER_CONNECTED = "postgresql+asyncpg://bridge@db-host.invalid/app"


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (1, 1000),
        (3, 3000),
        (1.5, 1500),
        (1.1, 1100),
        (2.3, 2300),
        (16.1, 16100),
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


class Seconds(float):
    """A float with a `repr` of its own, as NumPy's `float64` has (`np.float64(1.1)`)."""

    def __repr__(self) -> str:
        return f"Seconds({float(self)})"


class Whole(enum.IntEnum):
    """An int with a `repr` of its own: `<Whole.FIVE: 5>`."""

    FIVE = 5


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [(Seconds(1.1), 1100), (Seconds(0.0001), 1), (Whole.FIVE, 5000)],
    ids=["float-subclass", "float-subclass-below-a-millisecond", "int-subclass"],
)
def test_a_number_is_read_by_its_value_not_by_a_repr_of_its_own(
    seconds: float, expected: int
) -> None:
    """The conversion reads the decimal a float was written as, which is the built-in float's
    `repr`. A subclass may print itself as anything; its value is still the number given."""
    assert statement_timeout.milliseconds(seconds) == expected


LOW_PRECISION = 3
"""Fewer significant digits than `1.001` seconds needs in milliseconds."""


@pytest.mark.parametrize(("seconds", "expected"), [(1.001, 1001), (16.1, 16100), (0.0001, 1)])
def test_the_conversion_ignores_the_callers_decimal_precision(
    seconds: float, expected: int
) -> None:
    """The caller's thread may run with any decimal context. The conversion must not use it."""
    with decimal.localcontext() as context:
        context.prec = LOW_PRECISION
        assert statement_timeout.milliseconds(seconds) == expected


def test_the_conversion_raises_nothing_where_the_caller_traps_inexact() -> None:
    with decimal.localcontext() as context:
        context.prec = LOW_PRECISION
        context.traps[decimal.Inexact] = True
        assert statement_timeout.milliseconds(1.001) == 1001


def test_the_maximum_is_postgres_own() -> None:
    """`max_val` of `statement_timeout` in `pg_settings`, read on the harness's Postgres 17."""
    assert statement_timeout.MAX_MILLISECONDS == 2**31 - 1


def test_the_statement_names_the_setting_and_binds_its_value() -> None:
    compiled = timeout_statement().compile(dialect=PGDialect_asyncpg())
    values = {**compiled.params, **timeout_params(1500)}

    assert str(compiled) == SETTINGS_STATEMENT
    assert [values[name] for name in compiled.positiontup or ()] == ["statement_timeout", "1500"]


def test_the_probe_is_the_same_statement_naming_the_probe_setting() -> None:
    """One statement's text for both settings, so the read-only invariant names one statement."""
    compiled = timeout_statement().compile(dialect=PGDialect_asyncpg())
    values = {**compiled.params, **probe_params(PROBE)}

    assert str(compiled) == SETTINGS_STATEMENT
    assert [values[name] for name in compiled.positiontup or ()] == [PROBE_SETTING, PROBE]


def test_a_lookup_sets_the_bound_alone_and_discovery_sets_the_probe_first() -> None:
    """One order for both stores: the probe before the bound, so the readback after them proves
    the bound was set in the transaction that set the probe."""
    assert settings_in_order(1500, None) == (timeout_params(1500),)
    assert settings_in_order(1500, PROBE) == (probe_params(PROBE), timeout_params(1500))


def test_each_probe_is_fresh_random_hex() -> None:
    probes = {new_probe() for _ in range(64)}

    assert len(probes) == 64
    assert all(PROBE_VALUE.fullmatch(probe) for probe in probes)


def test_the_readback_reads_the_probe_without_failing_on_a_name_never_set() -> None:
    """`current_setting(name, true)` answers NULL for a name never set, where the one-argument
    form raises: an engine in AUTOCOMMIT must be refused as configuration, not as an error."""
    statement = readback_statement()
    assert isinstance(statement, Select)
    compiled = cast("Select[Any]", statement).compile(dialect=PGDialect_asyncpg())
    values = [compiled.params[name] for name in compiled.positiontup or ()]

    assert "current_setting($1::VARCHAR, true)" in str(compiled)
    assert "FROM pg_catalog.pg_settings" in str(compiled)
    assert values == [PROBE_SETTING, "statement_timeout"]


def test_the_local_flag_is_in_the_text_for_every_postgres_driver() -> None:
    """psycopg renders its parameters differently; the flag is the same literal."""
    compiled = str(timeout_statement().compile(dialect=postgresql.dialect()))

    assert compiled.startswith("SELECT set_config(")
    assert ", true)" in compiled


@pytest.mark.parametrize(
    "rows",
    [
        [("0", "default", PROBE)],
        [("1500", "user", PROBE)],
        [("1500", "database", PROBE)],
        [("1500", "client", PROBE)],
        [("3000", "session", PROBE)],
        [("1500", "session", None)],
        [("1500", "session", "")],
        [("1500", "session", "fedcba9876543210" * 2)],
        [("1500", "session", PROBE.upper())],
        [("1500", "session")],
        [("1500", "session", PROBE), ("1500", "session", PROBE)],
        [],
    ],
    ids=[
        "server-default",
        "role-equal",
        "database-equal",
        "connect-equal",
        "other-value",
        "probe-never-set",
        "probe-ended",
        "probe-of-another-discovery",
        "probe-in-another-case",
        "no-probe-column",
        "two-rows",
        "none",
    ],
)
def test_only_this_discoverys_probe_and_the_stores_own_value_are_a_bound_that_held(
    rows: list[tuple[str | None, ...]],
) -> None:
    """Read back on an engine in AUTOCOMMIT, both settings have ended. The probe is then NULL on
    a connection that never held it, and an empty string on one that did; the bound read is
    someone else's, even an equal value set in this session by the application. A probe that is
    merely there, or that an earlier discovery set, is not this transaction's."""
    with pytest.raises(ConfigurationError, match="AUTOCOMMIT"):
        confirmed_bound(rows, 1500, PROBE)


def test_this_discoverys_probe_with_the_stores_own_value_is_a_bound_that_held() -> None:
    confirmed_bound([("1500", "session", PROBE)], 1500, PROBE)


@pytest.mark.parametrize("spelling", ["AUTOCOMMIT", "autocommit", "AutoCommit"])
def test_an_engine_whose_options_say_autocommit_is_refused(spelling: str) -> None:
    """No connection is opened: the engine's options are read. SQLAlchemy takes the level in any
    case and keeps it as it was written, so the check cannot depend on the spelling."""
    engine = postgres_engine(NEVER_CONNECTED)

    refuse_autocommit(engine)
    with pytest.raises(ConfigurationError, match="AUTOCOMMIT"):
        refuse_autocommit(engine.execution_options(isolation_level=spelling))


@pytest.mark.parametrize("level", ["READ COMMITTED", "REPEATABLE READ", "SERIALIZABLE"])
def test_an_isolation_level_that_keeps_a_transaction_is_not_refused(level: str) -> None:
    """Only `AUTOCOMMIT` runs without a transaction; the bound holds under every other level."""
    engine = postgres_engine(NEVER_CONNECTED)

    refuse_autocommit(engine.execution_options(isolation_level=level))
