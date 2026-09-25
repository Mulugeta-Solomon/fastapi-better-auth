"""The two refusals a cookie verifier decides by the wall clock: a session's expiry and a ban's lapse.

`CookieVerifier` and `RemoteVerifier` each hold a record whose `expiresAt` nothing upstream of them
enforces - no store filters on it, and get-session never reads `banned` - so both apply these two
checks themselves, and this module is their one copy.

Both comparisons are inclusive: a session expiring at exactly the check instant has expired, and a
ban has lapsed at exactly its `banExpires`.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .errors import SessionExpired, SessionRevoked
from .stores.records import StoredSession, StoredUser


def wall_clock() -> datetime:
    """The real time, as the refusals read it: aware, UTC."""
    return datetime.now(timezone.utc)


def check_expiry(record: StoredSession, marker: str, *, subject: str) -> None:
    """Refuse a session whose `expires_at` has passed; `subject` names the session in the reason.

    The record carries the raw session token, so this frame reads the one field it needs and
    drops the record before the refusal can put the frame on a traceback (D-094, D-181).
    """
    expires_at = record.expires_at
    del record
    if expires_at <= wall_clock():
        raise SessionExpired(reason=f"{subject} has expired [{marker}]")


def check_ban(user: StoredUser, marker: str) -> None:
    """Refuse a banned user, unless the ban has lapsed.

    `banned is None` is unknown - the admin plugin is not installed, so there is no ban state at
    all - and reading that absence as "banned" would refuse every user on a deployment without the
    plugin. A `ban_expires` of `None` on a banned user is a permanent ban, not a lapsed one.

    Everything but `None` and `False` is banned. `StoredUser` refuses a `banned` that is not
    `bool | None`, but a record can be built outside a store, and a ban check that assumed someone
    else had validated would be a check with a caller it has never met - so the two "not banned"
    values are named here and nothing is inferred from truthiness (D-182).
    """
    if user.banned is None or user.banned is False:
        return
    lapsed = user.ban_expires is not None and user.ban_expires <= wall_clock()
    if not lapsed:
        raise SessionRevoked(reason=f"the session's user is banned [{marker}]")
