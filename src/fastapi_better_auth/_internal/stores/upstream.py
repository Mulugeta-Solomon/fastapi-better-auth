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
    candidate = f"{value[:-1]}+00:00" if value.endswith(UTC_SUFFIXES) else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def as_text(value: Any) -> str | None:
    """A non-blank, UTF-8-encodable string, or `None`.

    An id that is blank is an id nothing should be found by, and a `str` carrying an unpaired
    surrogate is not text this library will vouch for: Python holds one happily, and every use
    a store has for the value - the constant-time compare against the presented token, a log
    line, anything sent anywhere - encodes it and raises `UnicodeEncodeError`. Refusing it here
    closes both stores' compare sites at the boundary they already trust, and puts it on the
    path a blank value already takes: "does not carry one", which is a miss (D-183).
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return value


def as_flag(value: Any) -> bool | None:
    """A real boolean, or `None`. Anything else is a value this library will not guess at.

    This is the JSON reading, for the Redis store: `JSON.stringify` writes `true`/`false`, so a
    boolean arrives as a Python `bool` and nothing else is a boolean. A stored `0`/`1` is *not*
    accepted here on purpose - Better Auth does not write one, so it is a malformed value.
    """
    return value if isinstance(value, bool) else None


def as_db_flag(value: Any) -> bool | None:
    """A boolean from a database column, or `None` when the value is not a readable one.

    The database reading, for the SQLAlchemy store, and deliberately not the same as `as_flag`.
    A `boolean` column answers a real `bool` on Postgres, but SQLite and MySQL have no boolean
    type and store it as the integer `0`/`1` - so a native `0`/`1` is a boolean here and every
    other value (a `2`, a string, a float) is unreadable. Returning `None` for unreadable is
    what lets `user_from` refuse a malformed `banned` the way the Redis store does, instead of
    letting SQLAlchemy's lenient `Boolean` coerce a stray `'false'` into `True` unseen.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    return None
