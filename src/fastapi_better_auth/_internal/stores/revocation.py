"""Better Auth's revocation watermark: "revoke every session" as a key of its own.

Since better-auth 1.7.16, revoking all of a user's sessions in secondary storage does two things
(`internal-adapter.mjs`, `deleteCachedUserSessions`): it deletes every session key it knows about,
and it writes `revoked-sessions-before-<userId>` - `String(<epoch milliseconds>)`, with a TTL of
its own. Upstream's session read then refuses any session whose `createdAt` is strictly before
that watermark (`isRevokedSession`), so a session key that outlived the revocation - a delete that
failed, a replica, a refresh racing the revocation and writing the key back - is refused anyway.

This module is the comparison, kept apart from the store that issues the reads. It is upstream's
comparison with every fail-open branch closed. Upstream reads the watermark with `Number(...)`, so
`"soon"` is `NaN`, `NaN < x` is false, and the session stands; a missing `createdAt` is
`new Date(undefined)`, also `NaN`, also standing. Here both are a refusal: a revocation this
library cannot read is still a revocation somebody asked for.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from .diagnostics import unusable
from .session_document import SESSION_KEY
from .upstream import as_moment

WATERMARK = "revocation watermark"
"""The kind an unreadable watermark is reported as."""

WATERMARK_PREFIX = "revoked-sessions-before-"
"""Upstream's key, `revokedBeforeKey(userId)`, before the deployment's own namespace."""

MAX_DIGITS = 16
"""Epoch milliseconds are 13 digits until the year 2286; anything longer is not one."""

WHOLE_MILLISECONDS = re.compile(rb"[0-9]{1,%d}" % MAX_DIGITS)
"""What upstream writes, and all this reader accepts.

`String(Math.max(Date.now(), previous || 0))` is a run of ASCII digits and nothing else. Wider
grammars disagree: JS `Number()` reads `""` as `0`, `" 12 "` as `12` and `"0x10"` as `16`, and
Python's `int()` reads `"1_000"` and full-width digits. A sign, a fraction, an exponent or
whitespace is a value upstream never wrote, so reading it either way would be a guess - and a
refusal is the only answer that cannot let a revoked session through.
"""

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
MILLISECOND = timedelta(milliseconds=1)


class Verdict(enum.Enum):
    """What the watermark makes of one stored session."""

    STANDING = "standing"
    REVOKED = "revoked"
    UNREADABLE = "unreadable"


def watermark_key(prefix: str, user_id: str) -> str:
    """The watermark's key: the same namespace as the session key, then upstream's own name.

    better-auth hands every key to `secondaryStorage.get` unprefixed. A deployment's storage
    adapter that namespaces keys does it to all of them, so the store's `key_prefix` applies here
    exactly as it does to the token.
    """
    return f"{prefix}{WATERMARK_PREFIX}{user_id}"


def judge(watermark: object, session: Mapping[str, Any], subject: str) -> Verdict:
    """Whether the session stands against the watermark read for its user.

    `watermark` is the raw reply (`None` when the key is absent). `session` is the stored session
    object, read for `createdAt` only when a watermark exists - so a store that has never been
    revoked keeps accepting what it always accepted. Every `UNREADABLE` verdict warns through
    `unusable()`, naming `subject` by fingerprint; a revocation is not news, and warns nothing.
    """
    if watermark is None:
        return Verdict.STANDING
    revoked_before = as_watermark(watermark)
    if revoked_before is None:
        unusable(WATERMARK, "it is not a whole number of milliseconds", subject)
        return Verdict.UNREADABLE
    created = created_ms(session.get("createdAt"))
    if created is None:
        unusable(
            SESSION_KEY,
            "its user has a revocation watermark and its createdAt is missing or unreadable",
            subject,
        )
        return Verdict.UNREADABLE
    return Verdict.REVOKED if created < revoked_before else Verdict.STANDING


def as_watermark(value: object) -> int | None:
    """The watermark as epoch milliseconds, or `None` for any reply upstream would not write.

    `bytes` from a default client, `str` from a `decode_responses=True` one; a `str` that will not
    encode as ASCII is not digits, and neither is any other type a client wrapper might answer.
    """
    if isinstance(value, str):
        try:
            digits = value.encode("ascii")
        except UnicodeEncodeError:
            return None
    elif isinstance(value, (bytes, bytearray)):
        digits = bytes(value)
    else:
        return None
    return int(digits) if WHOLE_MILLISECONDS.fullmatch(digits) else None


def created_ms(value: object) -> int | None:
    """`new Date(createdAt).getTime()` for what upstream stores, or `None`.

    `JSON.stringify` writes a `Date` as an ISO string, which `as_moment` reads. The division is
    exact and floors, as a JS `Date` keeps whole milliseconds - a float `timestamp() * 1000` can
    land one millisecond off at the boundary that decides the comparison.
    """
    moment = as_moment(value)
    if moment is None:
        return None
    return (moment - EPOCH) // MILLISECOND
