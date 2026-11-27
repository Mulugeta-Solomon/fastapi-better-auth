"""The `statement_timeout=` values both SQLAlchemy stores refuse and accept, in one place.

Both stores validate the option with the same function, so both suites drive the same cases: two
copies of these tables would be two chances for the stores to stop agreeing unnoticed.
"""

from __future__ import annotations

import math

POSTGRES_MAX_MILLISECONDS = 2_147_483_647
"""`statement_timeout`'s `max_val` in `pg_settings`: a signed 32-bit int of milliseconds."""

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

ACCEPTED: tuple[tuple[str, float], ...] = (
    ("the-maximum", 2_147_483.647),
    ("int", 3),
    ("float", 1.5),
    ("a-tenth-of-a-millisecond", 0.0001),
    ("a-nanosecond", 1e-9),
)
"""Positive values up to the maximum. One below a millisecond is rounded up to one, never down to
the zero that would mean no timeout."""


def values(cases: tuple[tuple[str, object], ...]) -> list[object]:
    return [value for _, value in cases]


def ids(cases: tuple[tuple[str, object], ...]) -> list[str]:
    return [name for name, _ in cases]
