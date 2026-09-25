"""The two refusals a cookie verifier decides by the wall clock: a session's expiry and a ban's lapse.

`CookieVerifier` and `RemoteVerifier` each hold a record whose `expiresAt` nothing upstream of them
enforces - no store filters on it, and get-session never reads `banned` - so both apply these two
checks themselves, and this module is their one copy.

Both comparisons are inclusive: a session expiring at exactly the check instant has expired, and a
ban has lapsed at exactly its `banExpires`.

A verifier's `now=` seam is read here too, and only in one direction (R51). Expiry is measured
against the LATER of the real time and the seam, a ban's lapse against the EARLIER, so a seam can
make a verifier stricter and never more lenient: moved forward it expires sessions sooner, moved
back it changes nothing, and it can never shorten a ban. A seam left wired in production can at
worst expire sessions early. What it returns is checked on every read: anything but an aware
`datetime` is a `TypeError`, which the dispatcher contains as the uniform 401 and logs (D-066).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone

from .errors import ConfigurationError, SessionExpired, SessionRevoked
from .stores.records import StoredSession, StoredUser


def wall_clock() -> datetime:
    """The real time, as the refusals read it: aware, UTC."""
    return datetime.now(timezone.utc)


class RefusalClock:
    """The instants one verifier's expiry and ban checks compare against, with its `now=` seam.

    Without a seam both are the real time, read once per check. With one, each check also reads
    the seam once, and takes the later of the two for expiry and the earlier for a ban's lapse.
    """

    __slots__ = ("_owner", "_seam")

    def __init__(self, now: object, *, owner: str) -> None:
        if now is not None and not callable(now):
            raise ConfigurationError(
                f"{owner}(now=...) must be a callable returning an aware datetime - the clock its"
                " expiry and ban checks read, such as"
                " `lambda: datetime.now(timezone.utc) + timedelta(minutes=31)` - or None for the"
                f" real one; got {type(now).__name__}."
            )
        self._owner = owner
        self._seam: Callable[[], object] | None = now

    def for_expiry(self) -> datetime:
        """The instant a session's `expires_at` is compared with: the later of real and seam."""
        real = wall_clock()
        if self._seam is None:
            return real
        return max(real, self._seam_instant(self._seam))

    def for_ban(self) -> datetime:
        """The instant a ban's `ban_expires` is compared with: the earlier of real and seam."""
        real = wall_clock()
        if self._seam is None:
            return real
        return min(real, self._seam_instant(self._seam))

    def _seam_instant(self, seam: Callable[[], object]) -> datetime:
        value = seam()
        if not isinstance(value, datetime):
            raise TypeError(
                f"{self._owner}(now=...) returned {type(value).__name__}; it must return an aware"
                " datetime, such as datetime.now(timezone.utc) moved by a timedelta."
            )
        offset = datetime.utcoffset(value)
        if offset is None:
            raise TypeError(
                f"{self._owner}(now=...) returned a naive datetime; it must return an aware"
                " datetime, such as datetime.now(timezone.utc) moved by a timedelta."
            )
        # Rebuilt as a plain UTC datetime: a subclass's own comparison would run first in max/min
        # and in the check's `<=`, and could bend the one-way rule it is compared under.
        return (
            datetime(
                value.year,
                value.month,
                value.day,
                value.hour,
                value.minute,
                value.second,
                value.microsecond,
                tzinfo=timezone.utc,
            )
            - offset
        )


def check_expiry(record: StoredSession, marker: str, clock: RefusalClock, *, subject: str) -> None:
    """Refuse a session whose `expires_at` has passed; `subject` names the session in the reason.

    The record carries the raw session token, so this frame reads the one field it needs and
    drops the record before the refusal - or a seam's own exception - can put the frame on a
    traceback (D-094, D-181).
    """
    expires_at = record.expires_at
    del record
    if expires_at <= clock.for_expiry():
        raise SessionExpired(reason=f"{subject} has expired [{marker}]")


def check_ban(user: StoredUser, marker: str, clock: RefusalClock) -> None:
    """Refuse a banned user, unless the ban has lapsed.

    `banned is None` is unknown - the admin plugin is not installed, so there is no ban state at
    all - and reading that absence as "banned" would refuse every user on a deployment without the
    plugin. A `ban_expires` of `None` on a banned user is a permanent ban, not a lapsed one, and no
    clock is read for it.

    Everything but `None` and `False` is banned. `StoredUser` refuses a `banned` that is not
    `bool | None`, but a record can be built outside a store, and a ban check that assumed someone
    else had validated would be a check with a caller it has never met - so the two "not banned"
    values are named here and nothing is inferred from truthiness (D-182).
    """
    if user.banned is None or user.banned is False:
        return
    lapsed = user.ban_expires is not None and user.ban_expires <= clock.for_ban()
    if not lapsed:
        raise SessionRevoked(reason=f"the session's user is banned [{marker}]")
