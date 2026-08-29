"""Reading Better Auth's own values: what a driver hands back, and what `JSON.stringify` wrote."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

UTC_SUFFIXES = ("Z", "z")


def as_moment(value: Any) -> datetime | None:
    """A timezone-aware `datetime`, or `None` when the value is not one at all.

    Two shapes arrive here and neither is negotiable. A database driver answers a `datetime` -
    aware from a Postgres `timestamptz`, **naive** from SQLite and from a MySQL `DATETIME`,
    because those columns carry no offset. Better Auth writes UTC into them, so a naive value is
    read as UTC; the alternative is refusing every SQLite and MySQL deployment outright. Read
    the assumption for what it is: a column holding local time would be misread by exactly its
    offset, which is why this library never writes one and why Postgres is the tested path.

    Redis answers a string, because `JSON.stringify(new Date())` produces one - always UTC,
    always a trailing `Z`, always three fractional digits. `fromisoformat` did not accept that
    `Z` before Python 3.11, so the suffix is rewritten before parsing rather than left to the
    interpreter to disagree about across the supported matrix.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value:
        return None
    text = f"{value[:-1]}+00:00" if value.endswith(UTC_SUFFIXES) else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def as_text(value: Any) -> str | None:
    """A non-blank string, or `None`. An id that is blank is an id nothing should be found by."""
    if not isinstance(value, str) or not value.strip():
        return None
    return value


def as_flag(value: Any) -> bool | None:
    """A real boolean, or `None`. Anything else is a value this library will not guess at."""
    return value if isinstance(value, bool) else None
