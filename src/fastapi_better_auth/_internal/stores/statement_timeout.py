"""`SqlAlchemySessionStore(statement_timeout=...)`: the value, checked and converted, with no SQLAlchemy.

The option is seconds, like every other deadline in this library. Postgres takes
`statement_timeout` as an int of milliseconds, and reads zero as no timeout at all. So the
conversion rounds up, never down: a value below one millisecond is one, not the zero that would
leave every statement unbounded while its operator believes otherwise. And it reads the value as
the decimal it was written as, so binary float error cannot move it by a millisecond:
`16.1 * 1000` is `16100.000000000002` as a float, and `16.1` seconds is still 16100 ms.

A value the server would refuse is refused here instead, when the store is built: above
`MAX_MILLISECONDS` once rounded, Postgres answers `SET` with an error, and every lookup would be
refused for a reason nobody saw at startup.
"""

from __future__ import annotations

import math
from decimal import Decimal

from ..errors import ConfigurationError
from ..reasons import safe_label
from .seconds import is_seconds

MAX_MILLISECONDS = 2**31 - 1
"""The largest `statement_timeout` Postgres accepts: its `max_val` in `pg_settings`, an int."""

MILLISECONDS_PER_SECOND = 1000

NOT_SECONDS = (
    "statement_timeout must be a positive, finite number of seconds, or None for no bound of the"
    " store's own; got {value}. Postgres reads a timeout of zero as no timeout at all."
)
TOO_LARGE = (
    "statement_timeout is {milliseconds} ms once rounded up to whole milliseconds, above the"
    " {maximum} ms Postgres accepts. Keep it below the verifier's lookup_timeout."
)


def milliseconds(seconds: float) -> int:
    """`seconds` as whole milliseconds, rounded up, read as the decimal it was written as.

    `repr` of a float is the shortest decimal that reads back as the same float, so `Decimal`
    of it is the number the caller wrote. An int is exact already. The built-in types are asked,
    never the value's own class: a subclass may print itself as anything (NumPy's `float64`, an
    `IntEnum`), and its value is still the number given.
    """
    written = int(seconds) if isinstance(seconds, int) else float.__repr__(float(seconds))
    return math.ceil(Decimal(written) * MILLISECONDS_PER_SECOND)


def validated_statement_timeout(seconds: object) -> int | None:
    """The bound in milliseconds, or `None` when the option is unset; refused if unusable."""
    if seconds is None:
        return None
    if not is_seconds(seconds):
        raise ConfigurationError(NOT_SECONDS.format(value=safe_label(repr(seconds))))
    bound = milliseconds(seconds)
    if bound > MAX_MILLISECONDS:
        raise ConfigurationError(TOO_LARGE.format(milliseconds=bound, maximum=MAX_MILLISECONDS))
    return bound
