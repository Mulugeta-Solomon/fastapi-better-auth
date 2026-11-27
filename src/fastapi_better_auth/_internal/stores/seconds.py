"""What every store deadline is checked against: a positive, finite number of seconds.

Shared so the stores refuse the same values for the same reasons: `RedisSessionStore`'s socket
deadlines and `SqlAlchemySessionStore`'s `statement_timeout`. A bool is refused although it is an
int, and so is an int too large for a float, which no socket or server timer can be given.
"""

from __future__ import annotations

import math
from typing import TypeGuard


def is_seconds(value: object) -> TypeGuard[float]:
    """A positive, finite number of seconds. `None`, a bool and `nan` are not one."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        as_float = float(value)
    except OverflowError:
        return False
    return math.isfinite(as_float) and as_float > 0
