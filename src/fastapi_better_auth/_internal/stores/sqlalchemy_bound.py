"""`SqlAlchemySessionStore(statement_timeout=...)` as SQL: the bound set, and proven to hold.

The store opens every transaction with `timeout_statement`, which sets Postgres's
`statement_timeout` for that transaction alone. A function call rather than `SET LOCAL`, because a
utility statement takes no bound parameter: the value would have to be written into the SQL text.
Here it travels as a parameter, and the literal `true` makes the setting transaction-local. It
ends with the transaction, so it never reaches another checkout of the pool the store shares.

Imported by `sqlalchemy_core` alone (it names SQLAlchemy, and `sqlalchemy` is an extra).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Select, String, bindparam, func, select, true
from sqlalchemy.ext.asyncio import AsyncEngine

from ..errors import ConfigurationError

POSTGRES = "postgresql"
SETTING = "statement_timeout"
SETTING_PARAM = "setting"
TIMEOUT_PARAM = "statement_timeout_ms"

NOT_POSTGRES = (
    "statement_timeout is for PostgreSQL only; this engine's dialect is {dialect}. Leave it unset"
    " and bound statements on the database server instead (on MySQL, max_execution_time)."
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
