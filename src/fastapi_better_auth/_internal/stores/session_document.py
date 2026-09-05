"""The `{session, user}` document, promoted to records - the shape two readers now share.

Better Auth writes one JSON object for a live session: `{session, user}`, the session carrying
`expiresAt`, `userId` and the raw `token`, the user carrying its id and the admin plugin's two
ban fields. `RedisSessionStore` reads that object out of its secondary storage; `RemoteVerifier`
reads the byte-identical object back from `GET /api/auth/get-session`. The promotion from that
object to a `StoredSession`/`StoredUser` is therefore one seam, kept here so both readers refuse
the same malformed shapes with the same warning.

What does **not** live here is the Redis-only question "does the value name the key it was found
under": that compares the stored token against the token the store was asked for, and only a
key-addressed store has a key to compare. `RemoteVerifier` compares the stored token against the
cookie it forwarded instead, in its own frame. Both comparisons stay out of this module so the
one thing a document parser must never do - decide a credential matches - is never its job.

Every refusal answers `None` and warns through `unusable()`, naming the subject by fingerprint
and never by value (D-018). The subject is whatever the caller is keyed by - a Redis key, a
forwarded token's fingerprint - so an operator can correlate the miss.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from .diagnostics import unusable
from .records import StoredSession, StoredUser
from .upstream import as_flag, as_moment, as_text

SESSION_KEY = "session"
USER_KEY = "user"


def parse_session_document(document: Mapping[str, Any], subject: str) -> StoredSession | None:
    """The `{session, user}` object as a `StoredSession`, or `None` with a warning.

    Refuses - and warns once through `unusable()` - a document that does not carry both a session
    and a user object, or a session missing any of `expiresAt`, `userId`, `token`, or whose user
    half does not parse. The `token` is promoted onto the record but **not** checked against
    anything here: whether it names the credential the caller presented is the caller's decision,
    made in the caller's own frame.

    Args:
        document: The parsed JSON object, already known to be a mapping.
        subject: The value to fingerprint in any warning - a store key, or a forwarded token.

    Returns:
        The record, or `None` for any shape this reader cannot promote.
    """
    session = document.get(SESSION_KEY)
    stored_user = document.get(USER_KEY)
    if not isinstance(session, dict) or not isinstance(stored_user, dict):
        unusable(SESSION_KEY, "it does not carry both a session and a user", subject)
        return None
    payload = cast("Mapping[str, Any]", session)
    user = parse_stored_user(cast("Mapping[str, Any]", stored_user), subject)
    expires_at = as_moment(payload.get("expiresAt"))
    user_id = as_text(payload.get("userId"))
    stored_token = as_text(payload.get("token"))
    if expires_at is None or user_id is None or stored_token is None or user is None:
        unusable(SESSION_KEY, "a value it must carry is missing or unreadable", subject)
        return None
    return StoredSession(
        token=stored_token,
        user_id=user_id,
        expires_at=expires_at,
        payload=payload,
        user=user,
        impersonated_by=as_text(payload.get("impersonatedBy")),
    )


def parse_stored_user(payload: Mapping[str, Any], subject: str) -> StoredUser | None:
    """The user half of the document as a `StoredUser`, or `None` with a warning.

    Refuses a user with no readable id, a `banned` that is neither absent nor a real boolean
    (a guess on a ban check is a guess toward letting a banned user through, D-182), or a
    `banExpires` present but unparseable. The `id` is `as_text` and the ban fields are read
    with the JSON-shaped `as_flag`/`as_moment`, so `0`/`1` is a malformed `banned` here on
    purpose - `JSON.stringify` writes `true`/`false`.

    Args:
        payload: The user object, already known to be a mapping.
        subject: The value to fingerprint in any warning.

    Returns:
        The stored user, or `None`.
    """
    identifier = as_text(payload.get("id"))
    if identifier is None:
        unusable(USER_KEY, "its id is missing or blank", subject)
        return None
    banned = payload.get("banned")
    if banned is not None and as_flag(banned) is None:
        unusable(USER_KEY, "its banned field is not a boolean", subject)
        return None
    recorded = payload.get("banExpires")
    ban_expires = None if recorded is None else as_moment(recorded)
    if recorded is not None and ban_expires is None:
        unusable(USER_KEY, "its banExpires is not a date", subject)
        return None
    return StoredUser(
        id=identifier, payload=payload, banned=as_flag(banned), ban_expires=ban_expires
    )
