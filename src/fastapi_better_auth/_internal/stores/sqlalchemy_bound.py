"""`SqlAlchemySessionStore(statement_timeout=...)` as SQL: the bound set, and proven to hold.

The store opens every transaction with `timeout_statement`, which sets Postgres's
`statement_timeout` for that transaction alone. A function call rather than `SET LOCAL`, because a
utility statement takes no bound parameter: the value would have to be written into the SQL text.
Here it travels as a parameter, and the literal `true` makes the setting transaction-local. It
ends with the transaction, so it never reaches another checkout of the pool the store shares.

That also means it holds only inside a transaction. On an engine in `AUTOCOMMIT` every statement
is a transaction of its own, the setting ends with the statement that made it, and the lookup
after it runs unbounded. So such an engine is refused, never served without the bound its operator
configured: from its options before every transaction (`refuse_autocommit`), and, at discovery,
by reading the setting back in the same transaction (`confirmed_bound`), which also sees an engine
built that way.

Imported by `sqlalchemy_core` alone (it names SQLAlchemy, and `sqlalchemy` is an extra).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from sqlalchemy import Select, String, bindparam, column, func, select, table, true
from sqlalchemy.ext.asyncio import AsyncEngine

from ..errors import ConfigurationError

if TYPE_CHECKING:
    from sqlalchemy import Executable

POSTGRES = "postgresql"
SETTING = "statement_timeout"
SETTING_PARAM = "setting"
TIMEOUT_PARAM = "statement_timeout_ms"
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


def bounded_engine(engine: AsyncEngine, milliseconds: int | None) -> int | None:
    """The store's bound, refused when set on an engine that is not Postgres.

    Only the dialect's name is quoted, never the engine's URL: it can carry a password.
    """
    if milliseconds is not None and engine.dialect.name != POSTGRES:
        raise ConfigurationError(NOT_POSTGRES.format(dialect=engine.dialect.name))
    return milliseconds


def timeout_statement() -> Select[Any]:
    """`SELECT set_config('statement_timeout', :ms, true)`, the first statement of a transaction."""
    name = bindparam(SETTING_PARAM, SETTING, type_=String)
    value = bindparam(TIMEOUT_PARAM, type_=String)
    return select(func.set_config(name, value, true()))


def timeout_params(milliseconds: int) -> dict[str, str]:
    """The value `timeout_statement` binds: whole milliseconds, as the text `set_config` takes."""
    return {TIMEOUT_PARAM: str(milliseconds)}


def refuse_autocommit(engine: AsyncEngine) -> None:
    """Refuse an engine whose options say `AUTOCOMMIT`, before a transaction is opened on it.

    Free, and run for every transaction, so an engine switched after `connect()` is caught too
    (`update_execution_options`). An engine *built* with `isolation_level="AUTOCOMMIT"` does not
    say so in its options; `confirmed_bound` catches that one, at discovery.
    """
    if engine.get_execution_options().get(ISOLATION_LEVEL) == AUTOCOMMIT:
        raise ConfigurationError(NO_TRANSACTION)


def readback_statement() -> Executable:
    """`statement_timeout` as the transaction now sees it: whole milliseconds, and where from."""
    settings = table(
        "pg_settings", column("name"), column("setting"), column("source"), schema="pg_catalog"
    )
    name = bindparam(SETTING_PARAM, SETTING, type_=String)
    return select(settings.c.setting, settings.c.source).where(settings.c.name == name)


def confirmed_bound(rows: Sequence[Sequence[Any]], milliseconds: int) -> None:
    """Refuse unless the statement after `timeout_statement` still runs under the store's bound.

    A transaction-local setting holds to the end of its transaction, so read back by the next
    statement it is the store's value, set in this session. On an engine that runs without a
    transaction it has already ended, and what is read is the role's, the database's or the
    server's own value - even one that happens to be equal, which would then bound the store only
    for as long as nobody changed it.
    """
    if [tuple(row) for row in rows] != [(str(milliseconds), SESSION_SOURCE)]:
        raise ConfigurationError(NO_TRANSACTION)
