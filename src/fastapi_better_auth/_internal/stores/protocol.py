"""The store boundary: two reads, and a rule about what a miss means."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .records import StoredSession, StoredUser


@runtime_checkable
class SessionStore(Protocol):
    """Where a cookie-mode verifier looks a session up, and the one thing it must never do.

    Implement this to point the bridge at a session store this library does not ship an adapter
    for - a different database, a cache in front of one, a service that already answers these
    two questions. The shipped stores (`SqlAlchemySessionStore`, `SyncStoreAdapter`,
    `RedisSessionStore`) implement exactly this and get no privileges yours does not:

        class MyStore:
            async def fetch_session_by_token(self, token: str) -> StoredSession | None:
                ...

            async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
                ...

    **A store reads. It never writes.** Not a row, not a key, not a bookkeeping stamp. Better
    Auth's own server owns every write there is - creating a session, extending one, deleting
    one - and the two writes that look harmless are the two that do the damage: a `touch` that
    rewrites `expiresAt` extends a session this side was only asked to read, and an `EXPIRE`
    refreshed on read makes a revoked session outlive its revocation.

    **A miss is an answer, not a question.** `None` means "no such session here", and the
    verifier turns it into a refusal. It does not mean "look somewhere else". A store configured
    against Redis must never fall back to the database on a miss: when Better Auth is running
    with `secondaryStorage`, sign-out deletes the Redis key while a stale replica or an
    un-cascaded row can still be sitting in the database, so the fallback resurrects exactly the
    sessions that were revoked (D-008). Which store is authoritative is the operator's explicit
    configuration, never something inferred at runtime.

    **Data a store cannot vouch for is a miss, never an exception.** A value that will not
    parse, a row with a NULL where the schema says NOT NULL, a stored session that names a
    different token: all of them answer `None`. An exception escaping here would surface as a
    500, which a client can tell apart from the uniform 401 every other refusal renders - so
    malformed stored data would become an oracle. A failure of the *store itself* - an
    unreachable database, a broken connection - is different and does propagate: a store cannot
    know what one means to the request that needed it, and the verifier above translates it into
    a refusal.

    **Neither method verifies anything.** No signature is checked here, no clock is read, no ban
    is enforced. `expires_at` in the past is a valid record. The verifier owns all of it,
    because only the verifier knows this deployment's leeway and what a refusal looks like.

    The protocol is runtime-checkable, so `isinstance` proves the two member *names* exist and
    nothing about their signatures, their callability, or whether they honour a single rule
    above.
    """

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        """The session stored under this raw token, or `None` if there is not one.

        `token` is the raw token - the part of the `better-auth.session_token` cookie *before*
        the dot, with the HMAC signature already verified and stripped by the caller. This
        method does no cryptography and must never be handed a whole cookie value.

        A blank token is a miss and should not become a lookup: a request that carried no
        credential does not deserve a round trip, and answering one from the store spends real
        time on a request that will be refused anyway.

        Args:
            token: The raw session token.

        Returns:
            The stored session, with its user embedded when the store could answer both in one
            lookup, or `None` for a miss - which includes stored data that could not be trusted.

        Raises:
            Exception: Whatever the underlying client raises for a connection or protocol
                failure, untranslated. Malformed *data* is never one of these.
        """
        ...

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        """The user with this id, or `None` if there is not one.

        Called only when `fetch_session_by_token` answered a record whose `user` is `None`. A
        store that always embeds the user - as both shipped Redis and SQLAlchemy stores do - is
        never asked, and may reasonably have nothing to answer with.

        Args:
            user_id: The `userId` from a stored session.

        Returns:
            The stored user, or `None` for a miss.

        Raises:
            Exception: As above - transport failures propagate, malformed data does not.
        """
        ...
