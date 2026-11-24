"""How wide an integer id column is: its reflected type, read on the dialect that reflected it.

The type class alone cannot say. SQLAlchemy reflects a SQLite `INTEGER` and a Postgres `INTEGER`
as the same `INTEGER`, and the first holds 64 bits, the second 32. So the range comes from the
pair, and only where both are known for certain; anywhere else it stays the signed 64-bit bound
every integer bind already keeps, because a narrower guess would turn a real row into a miss.

Imported by `sqlalchemy_core` alone (it names SQLAlchemy types, and `sqlalchemy` is an extra).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import BigInteger, SmallInteger
from sqlalchemy.dialects import mysql
from sqlalchemy.types import TypeEngine

from .sql_ids import INT64_RANGE, IntegerRange

POSTGRESQL = "postgresql"
MYSQL_FAMILY = frozenset({"mysql", "mariadb"})

MYSQL_BITS: tuple[tuple[type[TypeEngine[Any]], int], ...] = (
    (mysql.TINYINT, 8),
    (SmallInteger, 16),
    (mysql.MEDIUMINT, 24),
    (BigInteger, 64),
)
"""MySQL's and MariaDB's integer types by storage width; anything else integer is `INT`, 32."""


def integer_range(column_type: TypeEngine[Any] | None, dialect: str | None) -> IntegerRange:
    """The inclusive range an integer id column of this type holds on this dialect.

    - Postgres has exactly three integer types, and reflects them as `SMALLINT`, `INTEGER` and
      `BIGINT` (`smallserial`/`serial`/`bigserial` are those types with a default), so a
      Postgres integer that is neither big nor small is `int4`.
    - MySQL/MariaDB widths are fixed by the type; `UNSIGNED` moves the range to start at 0.
    - SQLite stores every integer in up to 8 bytes, whatever the declared name, so it is int64.
    - Any other dialect, or none, keeps int64: its widths are not something this library has
      tested, and int64 is the bound that held before widths were read at all.

    Every answer is also held to int64 by `sql_ids`, so an unsigned 64-bit MySQL column binds up
    to 2**63 - 1: ids above that miss rather than reach a driver nobody has checked with them.
    """
    if dialect == POSTGRESQL:
        return _signed(_postgres_bits(column_type))
    if dialect in MYSQL_FAMILY:
        return _mysql_range(column_type)
    return INT64_RANGE


def _postgres_bits(column_type: TypeEngine[Any] | None) -> int:
    if isinstance(column_type, BigInteger):
        return 64
    if isinstance(column_type, SmallInteger):
        return 16
    return 32


def _mysql_range(column_type: TypeEngine[Any] | None) -> IntegerRange:
    bits = next((width for kind, width in MYSQL_BITS if isinstance(column_type, kind)), 32)
    if getattr(column_type, "unsigned", False) is True:
        return (0, 2**bits - 1)
    return _signed(bits)


def _signed(bits: int) -> IntegerRange:
    return (-(2 ** (bits - 1)), 2 ** (bits - 1) - 1)
