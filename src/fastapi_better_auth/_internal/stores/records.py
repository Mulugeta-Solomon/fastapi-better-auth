"""What a store answers with: the upstream row or value, promoted just far enough to be safe."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any

NAIVE = (
    "{name} must be timezone-aware. Expiry is enforced against the current moment in UTC, and a"
    " value with no offset is read against whichever clock happens to be nearest - which is how"
    " an expired session becomes a live one."
)


def freeze(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """One level deep, the same contract `Session.raw` publishes."""
    return MappingProxyType(dict(payload))


def require_aware(name: str, value: datetime) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(NAIVE.format(name=name))
    return value


@dataclass(frozen=True, slots=True, kw_only=True)
class StoredUser:
    """A user as the session store holds it, before any of it has been believed.

    This is not a `User`. It is the upstream row or JSON object with three things promoted out
    of it - the id, and the admin plugin's two ban fields - and everything else left exactly as
    it arrived. Turning it into the application's user model is `parse_user`'s job, and
    `payload` is what you hand it.

    Attributes:
        id: The user id, as a string. Never empty: a store that read a blank one answers a miss
            instead of a record.
        payload: The row or JSON object as it arrived - camelCase keys, upstream's spelling,
            including every field this library does not know about. Read-only and copied one
            level deep. Kept out of `repr()`, because a record reaches tracebacks and error
            reporters and this carries the user's own data.
        banned: `True` or `False` when the admin plugin's `banned` column exists, and `None`
            when it does not. `None` means *unknown*, never *safe* - a deployment without the
            admin plugin has no ban state at all, and reading its absence as "not banned" is
            the difference between an unbanned user and one nobody asked about.
        ban_expires: When a ban lifts, timezone-aware, or `None` for "no expiry recorded" -
            which for a banned user means the ban is permanent, not that it has lapsed.

    Instances are immutable.

    Raises:
        ValueError: If `ban_expires` is naive.
    """

    id: str
    payload: Mapping[str, Any] = field(repr=False)
    banned: bool | None = None
    ban_expires: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload", freeze(self.payload))
        if self.ban_expires is not None:
            require_aware("ban_expires", self.ban_expires)


@dataclass(frozen=True, slots=True, kw_only=True)
class StoredSession:
    """A session row or stored value, and the user it belongs to when the store had one.

    A store answers with this; a verifier decides what it means. Nothing here has been checked
    against a clock or a ban list - `expires_at` being in the past is a perfectly valid record,
    and refusing it is the verifier's job, because only the verifier knows what leeway this
    deployment allows and what a refusal should look like on the wire.

    Attributes:
        token: The raw session token this record was found by. Kept out of `repr()`: it is a
            live credential, and a record reaches tracebacks and error reporters like anything
            else. A store checks it against the token it was asked for before answering, so a
            stored value that names a *different* session is a miss rather than a login.
        user_id: The owning user's id, from the session itself. Never empty.
        expires_at: When the session expires, timezone-aware and required. Required because
            every session upstream has one, and a record that could omit it would let a
            verifier forget to enforce it; aware because a naive value reads the wrong clock.
            A store that found no usable expiry answers a miss instead of building this.
        payload: The session row or JSON object as it arrived - camelCase keys, upstream's
            spelling, `ipAddress`, `userAgent` and anything a plugin added. Read-only, copied
            one level deep, and out of `repr()`.
        user: The user, when the store could answer both in one lookup. The Redis store always
            can, because the value it reads *is* `{session, user}`; the SQLAlchemy store always
            can, because it joins. `None` means "ask `fetch_user_by_id`", not "no user".
        impersonated_by: The admin's user id when this session was created by the admin
            plugin's impersonation endpoint, and `None` both when the column does not exist and
            when nobody is impersonating. Treat it as *provenance*, not permission.

    Instances are immutable.

    Raises:
        ValueError: If `expires_at` is naive.
    """

    token: str = field(repr=False)
    user_id: str
    expires_at: datetime
    payload: Mapping[str, Any] = field(repr=False)
    user: StoredUser | None = None
    impersonated_by: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload", freeze(self.payload))
        require_aware("expires_at", self.expires_at)
