"""`statement_timeout=` as SQL, for both SQLAlchemy stores: the bound set, and proven to hold.

`SqlAlchemySessionStore` and `SyncStoreAdapter` send `timeout_statement` before any read in every
transaction they open (at discovery, just after the probe below), in the order
`settings_in_order` gives. It sets Postgres's `statement_timeout` for that transaction alone. A
function call rather than `SET LOCAL`, because a utility statement takes no bound parameter: the
value would have to be written into the SQL text by this library. Here it is a bound parameter,
and the literal `true` makes the setting transaction-local. asyncpg and psycopg send the value to
the server apart from the text; psycopg2 quotes it into the text on the client, as it does every
parameter. It ends with the transaction, so it never reaches another checkout of the pool the
store shares.

That also means it holds only inside a transaction. On an engine in `AUTOCOMMIT` every statement
is a transaction of its own, the setting ends with the statement that made it, and the lookup
after it runs unbounded. So such an engine is refused, never served without the bound its operator
configured: from its options before every transaction (`refuse_autocommit`), and, at discovery,
by reading the setting back in the same transaction (`confirmed_bound`), which also sees an engine
built that way.

A value read back is not proof on its own: the application may give its connections a
session-level value equal to the store's. So discovery also sets a probe: a random value under a
name of the library's own (`PROBE_SETTING`), set transaction-locally before the bound, and read
back with it. Only this transaction can hold this value.

Imported by `sqlalchemy_core` alone (it names SQLAlchemy, and `sqlalchemy` is an extra).
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from sqlalchemy import Select, String, bindparam, column, func, select, table, true

from ..errors import ConfigurationError

if TYPE_CHECKING:
    from sqlalchemy import Engine, Executable
    from sqlalchemy.ext.asyncio import AsyncEngine

    AnyEngine = Engine | AsyncEngine
    """Either store's engine: the checks read only its dialect's name and its options."""

POSTGRES = "postgresql"
SETTING = "statement_timeout"
PROBE_SETTING = "fastapi_better_auth.discovery_probe"
"""The setting discovery's probe is put in: a custom one, under the library's own prefix."""
PROBE_BYTES = 16
"""The probe's random bytes: 128 bits, so no other value on the connection can equal it."""
SETTING_PARAM = "setting"
VALUE_PARAM = "value"
PROBE_PARAM = "probe"
ISOLATION_LEVEL = "isolation_level"
AUTOCOMMIT = "AUTOCOMMIT"
SESSION_SOURCE = "session"
"""`pg_settings.source` for a value set by `SET` or `set_config` in this session, local or not."""

NOT_POSTGRES = (
    "statement_timeout is for PostgreSQL only; this engine's dialect is {dialect}. Leave it unset"
    " and bound statements on the database server instead (on MySQL, max_execution_time)."
)
NO_TRANSACTION = (
    "statement_timeout cannot bound this engine's statements: it runs in AUTOCOMMIT, where the"
    " store's transaction-local setting ends with the statement that made it, so every lookup"
    " would run unbounded. Lend the store an engine without isolation_level='AUTOCOMMIT', or"
    " leave statement_timeout unset and bound statements on the database server instead."
)


def bounded_engine(engine: AnyEngine, milliseconds: int | None) -> int | None:
    """The store's bound, refused when set on an engine that is not Postgres.

    Only the dialect's name is quoted, never the engine's URL: it can carry a password.
    """
    if milliseconds is not None and engine.dialect.name != POSTGRES:
        raise ConfigurationError(NOT_POSTGRES.format(dialect=engine.dialect.name))
    return milliseconds


def timeout_statement() -> Select[Any]:
    """`SELECT set_config(:setting, :value, true)`: the bound, and at discovery the probe too.

    The setting's name is a parameter, so the bound and the probe are one statement's text."""
    name = bindparam(SETTING_PARAM, SETTING, type_=String)
    value = bindparam(VALUE_PARAM, type_=String)
    return select(func.set_config(name, value, true()))


def timeout_params(milliseconds: int) -> dict[str, str]:
    """What `timeout_statement` binds for the bound: whole milliseconds, as text."""
    return {SETTING_PARAM: SETTING, VALUE_PARAM: str(milliseconds)}


def new_probe() -> str:
    """A fresh probe for one discovery: random hex, never reused."""
    return secrets.token_hex(PROBE_BYTES)


def probe_params(probe: str) -> dict[str, str]:
    """What `timeout_statement` binds for the probe: `PROBE_SETTING`, set to `probe`."""
    return {SETTING_PARAM: PROBE_SETTING, VALUE_PARAM: probe}


def settings_in_order(milliseconds: int, probe: str | None) -> tuple[dict[str, str], ...]:
    """What `timeout_statement` binds in one transaction, in the order the store sends it.

    The bound alone in a lookup. At discovery the probe first, then the bound, so the readback
    that follows proves the bound was set after the probe, in the same transaction. Both stores
    send exactly this; only how a statement runs differs between them.
    """
    bound = timeout_params(milliseconds)
    return (bound,) if probe is None else (probe_params(probe), bound)


def refuse_autocommit(engine: AnyEngine) -> None:
    """Refuse an engine whose options say `AUTOCOMMIT`, before a transaction is opened on it.

    Free, and run for every transaction, so an engine switched after `connect()` is caught too
    (`update_execution_options`). An engine *built* with `isolation_level="AUTOCOMMIT"` does not
    say so in its options; `confirmed_bound` catches that one, at discovery.

    The level is compared as SQLAlchemy reads it, not as it was written: SQLAlchemy takes
    `"autocommit"` in any case and keeps the spelling it was given in the options.
    """
    level = engine.get_execution_options().get(ISOLATION_LEVEL)
    if isinstance(level, str) and level.replace("_", " ").upper() == AUTOCOMMIT:
        raise ConfigurationError(NO_TRANSACTION)


def readback_statement() -> Executable:
    """`statement_timeout` as the transaction now sees it (milliseconds, and where from), and
    the probe. `current_setting(..., true)` answers NULL, not an error, for a name never set."""
    settings = table(
        "pg_settings", column("name"), column("setting"), column("source"), schema="pg_catalog"
    )
    name = bindparam(SETTING_PARAM, SETTING, type_=String)
    probe = func.current_setting(bindparam(PROBE_PARAM, PROBE_SETTING, type_=String), true())
    return select(settings.c.setting, settings.c.source, probe).where(settings.c.name == name)


def confirmed_bound(rows: Sequence[Sequence[Any]], milliseconds: int, probe: str) -> None:
    """Refuse unless the readback ran in the transaction that set the probe and the bound.

    Discovery sets the probe, then the bound, then reads both back, all transaction-locally. The
    rule: the probe read back must equal this discovery's own probe, and the bound must be the
    store's value, set in this session. A probe that merely is there proves nothing. Once a
    transaction that set it has ended, Postgres answers an empty string on that connection, not
    NULL, and a probe of an earlier discovery is not this one's.

    Equal to this transaction's probe, the readback ran in the transaction that set it, and so
    did the bound, sent between the two. On an engine that runs without a transaction both have
    already ended, and the value read is someone else's: the role's, the database's, or the
    application's own session-level value. Even an equal one would bound the store only until
    somebody changed it.
    """
    if [tuple(row) for row in rows] != [(str(milliseconds), SESSION_SOURCE, probe)]:
        raise ConfigurationError(NO_TRANSACTION)
