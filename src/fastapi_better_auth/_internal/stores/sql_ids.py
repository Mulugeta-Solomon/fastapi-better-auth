"""Ids as a database column holds them, and as the rest of this library reads them: text.

Better Auth's default id is a random string, but a deployment may hand id generation to the
database - serial integers, or the database's own `uuid` type - and the migrated `id` columns (and
the columns that reference them) then carry that type. A driver answers an `int` or a `uuid.UUID`
for those, never the string Better Auth itself puts in its JSON, so the SQL store translates in
both directions here, and only here:

- **Reading** (`read_id`): a value is accepted only if it is what its column's type promises - an
  `int` (never a `bool`) from an integer column, a `uuid.UUID` (or the 32/36-character hex text a
  non-native dialect stores) from a uuid column, a `str` from anything else - and it is rendered
  as the canonical text Better Auth would have written: decimal digits, or lowercase hyphenated.
  Anything else is `None`, the same "does not carry one" a blank string already is.
- **Binding** (`bind_id`): the text a caller looks a user up by becomes the value the column
  holds, and only from its canonical form. `int()` alone would take `" 7"`, `"+7"`, `"0_7"` and
  non-ASCII digits, and `uuid.UUID()` braces, `urn:` prefixes and upper case - every one of them
  a second spelling that would find the same row under an id that is not the row's id.

The text kind defers to the shared `as_text`, so a default deployment's ids are read exactly as
before. No SQLAlchemy import: deciding a column's kind from its reflected type is
`sqlalchemy_core`'s job, and this module is pure so both directions are testable on their own.
"""

from __future__ import annotations

import re
import uuid
from enum import Enum

from .upstream import as_text


class IdKind(Enum):
    """What an id column holds, as far as reading and binding an id is concerned."""

    TEXT = "text"
    INTEGER = "integer"
    UUID = "uuid"


INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1
"""The ceiling on every integer id bind, whatever the column (a Postgres `bigint`, a SQLite integer).

A value outside it is never bound: `sqlite3` raises `OverflowError` for one, which is not a
database error the store translates. A narrower column narrows it further (`IntegerRange`)."""

IntegerRange = tuple[int, int]
"""The inclusive `(low, high)` an integer id column holds, decided from its reflected type and
dialect by `sqlalchemy_core`; this module takes the range, never the type."""

INT64_RANGE: IntegerRange = (INT64_MIN, INT64_MAX)

MAX_INTEGER_TEXT = len(str(INT64_MIN))
"""The longest canonical text of an in-range integer id: 20 characters, minus sign included."""

CANONICAL_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)", re.ASCII)
"""Exactly what `str(int)` produces: no sign but a leading minus, no leading zero, ASCII only."""

STORED_UUID = re.compile(
    r"[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.ASCII | re.IGNORECASE,
)
"""The text forms a uuid column answers in where the dialect has no native type: SQLAlchemy's
`Uuid` stores 32 hex digits, other writers the hyphenated 36. Braces and `urn:` are not stored
forms, so they are not read as one."""


def read_id(kind: IdKind, value: object) -> str | None:
    """The canonical text of an id read from a column of this kind, or `None` if it is not one."""
    if kind is IdKind.INTEGER:
        return _integer_text(value)
    if kind is IdKind.UUID:
        return _uuid_text(value)
    return as_text(value)


def bind_id(
    kind: IdKind, candidate: str, integer_range: IntegerRange = INT64_RANGE
) -> str | int | uuid.UUID | None:
    """The value to compare a column of this kind against, or `None` when no row can hold `candidate`.

    Only the canonical form is accepted, so the id a row is found under is always the id the row
    answers with - which is what lets the store's identity re-check compare the two as text. An
    integer outside `integer_range` (held to int64 as well) is `None` too: bound, it is not a miss
    but a driver error - asyncpg refuses an int4 parameter past int32 before anything is sent.
    """
    if kind is IdKind.INTEGER:
        return _integer_value(candidate, integer_range)
    if kind is IdKind.UUID:
        return _uuid_value(candidate)
    return candidate


def _integer_text(value: object) -> str | None:
    # `bool` is an `int` subclass; a `True` read from an id column is not the id 1.
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return str(value)


def _uuid_text(value: object) -> str | None:
    if isinstance(value, uuid.UUID):
        # Rebuilt from the integer, so a driver's own `UUID` subclass cannot choose the rendering.
        return str(uuid.UUID(int=value.int))
    if isinstance(value, str) and STORED_UUID.fullmatch(value):
        return str(uuid.UUID(value))
    return None


def _integer_value(candidate: str, integer_range: IntegerRange) -> int | None:
    # The length cap runs first: `int()` of a long enough digit string raises `ValueError`
    # (Python's int-from-text limit) instead of answering a number to range-check.
    if (
        len(candidate) > MAX_INTEGER_TEXT
        or not CANONICAL_INTEGER.fullmatch(candidate)
        or candidate == "-0"
    ):
        return None
    value = int(candidate)
    low, high = max(integer_range[0], INT64_MIN), min(integer_range[1], INT64_MAX)
    return value if low <= value <= high else None


def _uuid_value(candidate: str) -> uuid.UUID | None:
    if not STORED_UUID.fullmatch(candidate):
        return None
    value = uuid.UUID(candidate)
    return value if str(value) == candidate else None
