"""The secondary-storage store: one `GET` on the raw token, and never a second question."""

from __future__ import annotations

import hmac
import json
from collections.abc import Mapping
from types import TracebackType
from typing import TYPE_CHECKING, Any, Protocol, TypeVar, cast

from ..errors import ConfigurationError
from .diagnostics import unusable
from .records import StoredSession, StoredUser
from .upstream import as_flag, as_moment, as_text

if TYPE_CHECKING:
    import redis.asyncio

MAX_VALUE_BYTES = 64 * 1024
SESSION_KEY = "session"
USER_KEY = "user"

MISSING = (
    "RedisSessionStore needs the redis package, which is not installed. Install it with:"
    ' pip install "fastapi-better-auth-bridge[redis]" - or build the client yourself and pass'
    " it as client=."
)
NEITHER = (
    "RedisSessionStore needs exactly one of url= or client=, and was given neither. Pass"
    " url='redis://...' to have one built, or client=<your redis.asyncio.Redis> to lend one."
)
BOTH = (
    "RedisSessionStore was given both url= and client=. Which Redis is authoritative for your"
    " sessions is not a question this library will answer by picking one."
)

StoreT = TypeVar("StoreT", bound="RedisSessionStore")


class _Client(Protocol):
    """The one command this store issues. Deliberately the whole protocol.

    A wider one would let a future edit reach for a write without changing the type that says
    what this store is allowed to do.
    """

    async def get(self, name: str) -> Any: ...


def _validated_prefix(key_prefix: object) -> str:
    """Annotated `str`; the value comes from an operator's configuration."""
    if not isinstance(key_prefix, str):
        raise ConfigurationError(
            f"key_prefix must be a string; got {type(key_prefix).__name__}. It is prepended to"
            " the raw token to form the Redis key, and Better Auth itself uses no prefix at all."
        )
    return key_prefix


def _import_redis() -> Any:
    try:
        from redis.asyncio import Redis
    except ImportError as exc:
        raise ConfigurationError(MISSING) from exc
    return Redis


class RedisSessionStore:
    """Better Auth's `secondaryStorage`, read directly - and treated as the only truth there is.

    When Better Auth is configured with `secondaryStorage`, this is where sessions live: keyed
    by the **raw session token** with no namespace in front of it, holding
    `JSON.stringify({session, user})`. The Postgres session table may never receive the row at
    all - upstream's `storeSessionInDatabase` defaults to off - so a store that read the database
    here would be reading somewhere sessions are not.

        store = RedisSessionStore(url="redis://cache:6379/0")

        async with RedisSessionStore(client=my_redis) as store:
            record = await store.fetch_session_by_token(token)

    **A miss is terminal. There is no fallback, and there is no database on this object to fall
    back to** (D-008). Sign-out deletes the Redis key; a stale replica or an un-cascaded row can
    still be sitting in Postgres, so falling back would resurrect exactly the sessions that were
    revoked. Which store is authoritative is your explicit configuration, never inferred here.

    **The user arrives with the session.** The stored value already carries both, so the happy
    path is one round trip and the record's `user` is populated. `fetch_user_by_id` correspondingly
    has nothing to answer from and always answers a miss: secondary storage keys sessions and an
    active-session list, never a user by id, and guessing a key or reaching for a database is the
    fallback above.

    **It never writes.** No `SET`, no `DEL`, no `EXPIRE` refreshed on read - the last would make
    a revoked session outlive its revocation. `GET` is the only command this store knows.

    **A value it cannot read is a miss, with a warning naming a fingerprint of the key.** Not
    JSON, not an object, no session, no user, no usable `expiresAt`, or a stored session naming a
    *different* token than the key it was found under: all of them answer `None`. The last is
    compared in constant time and is the one that matters - honouring it would authenticate
    whoever wrote that key. A failure of Redis itself propagates untranslated, because a store
    cannot know what an unreachable cache means to the request that needed it.

    Args:
        url: A Redis URL to build a client from. Needs the `[redis]` extra. Exactly one of this
            and `client`.
        client: A `redis.asyncio.Redis` to borrow instead. When given, the extra is not needed -
            it buys the client, not the store - and this store never closes it: lifecycle belongs
            to whoever built it. A client built from `url` *is* closed by `aclose()`.
        key_prefix: Prepended to the token to form the key. Empty by default, which is what
            Better Auth itself uses; set it for a deployment whose `secondaryStorage`
            implementation namespaces its keys.
        max_bytes: The largest stored value this store will parse. It bounds the parse and the
            record, not the read - the client has already received the value by the time it gets
            here - so read it as a refusal to believe something absurd, not as a DoS control.

    Raises:
        ConfigurationError: If neither `url` nor `client` is given, if both are, if `key_prefix`
            is not a string, or if `url` was given and the `redis` package is not installed.
    """

    def __init__(
        self,
        *,
        url: str | None = None,
        client: redis.asyncio.Redis | _Client | None = None,
        key_prefix: str = "",
        max_bytes: int = MAX_VALUE_BYTES,
    ) -> None:
        if url is None and client is None:
            raise ConfigurationError(NEITHER)
        if url is not None and client is not None:
            raise ConfigurationError(BOTH)
        built = None if client is not None else _import_redis().from_url(url)
        # Only a client this store BUILT is ever closed; a borrowed pool is not ours to shut.
        self._built: Any | None = built
        self._client: _Client = cast("_Client", client if client is not None else built)
        self._prefix = _validated_prefix(key_prefix)
        self._max_bytes = max_bytes

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        """The session stored under this raw token, with its user.

        See `SessionStore.fetch_session_by_token`. A blank token never reaches Redis.
        """
        if not token.strip():
            return None
        key = f"{self._prefix}{token}"
        value = await self._client.get(key)
        if value is None:
            return None
        document = self._document(value, key)
        if document is None:
            return None
        return self._record(document, token, key)

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        """Always a miss, and never a command.

        Better Auth's secondary storage holds sessions and an `active-sessions-<userId>` list;
        there is no user keyed by id to read. A session fetched from this store always carries
        its user, so the sanctioned flow never asks - and answering by guessing a key, or by
        reaching for a database, is the fallback D-008 forbids.
        """
        return None

    async def aclose(self) -> None:
        """Close the client this store built. A borrowed one is left alone - closing a shared
        pool out from under the application that lent it to us is an outage well beyond us."""
        if self._built is not None:
            await self._built.aclose()

    # `typing.Self` is 3.11+, and typing-extensions is not a runtime dependency of this
    # library; the TypeVar is the 3.10-compatible spelling of the same thing.
    async def __aenter__(self: StoreT) -> StoreT:  # noqa: PYI019
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    def _document(self, value: object, key: str) -> Mapping[str, Any] | None:
        if not isinstance(value, (bytes, bytearray, str)):
            unusable(SESSION_KEY, f"redis answered a {type(value).__name__}", key)
            return None
        if len(value) > self._max_bytes:
            unusable(SESSION_KEY, f"it is over the {self._max_bytes}-byte cap", key)
            return None
        try:
            parsed: object = json.loads(value)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            unusable(SESSION_KEY, "it is not JSON", key)
            return None
        if not isinstance(parsed, dict):
            unusable(SESSION_KEY, "it is not a JSON object", key)
            return None
        return cast("Mapping[str, Any]", parsed)

    def _record(self, document: Mapping[str, Any], token: str, key: str) -> StoredSession | None:
        session = document.get(SESSION_KEY)
        stored_user = document.get(USER_KEY)
        if not isinstance(session, dict) or not isinstance(stored_user, dict):
            unusable(SESSION_KEY, "it does not carry both a session and a user", key)
            return None
        payload = cast("Mapping[str, Any]", session)
        user = self._user(cast("Mapping[str, Any]", stored_user), key)
        expires_at = as_moment(payload.get("expiresAt"))
        user_id = as_text(payload.get("userId"))
        stored_token = as_text(payload.get("token"))
        if expires_at is None or user_id is None or stored_token is None or user is None:
            unusable(SESSION_KEY, "a value it must carry is missing or unreadable", key)
            return None
        if not hmac.compare_digest(stored_token.encode("utf-8"), token.encode("utf-8")):
            unusable(
                SESSION_KEY, "it names a different session than the key it was found under", key
            )
            return None
        return StoredSession(
            token=stored_token,
            user_id=user_id,
            expires_at=expires_at,
            payload=payload,
            user=user,
            impersonated_by=as_text(payload.get("impersonatedBy")),
        )

    def _user(self, payload: Mapping[str, Any], key: str) -> StoredUser | None:
        identifier = as_text(payload.get("id"))
        if identifier is None:
            unusable(USER_KEY, "its id is missing or blank", key)
            return None
        banned = payload.get("banned")
        if banned is not None and as_flag(banned) is None:
            unusable(USER_KEY, "its banned field is not a boolean", key)
            return None
        recorded = payload.get("banExpires")
        ban_expires = None if recorded is None else as_moment(recorded)
        if recorded is not None and ban_expires is None:
            unusable(USER_KEY, "its banExpires is not a date", key)
            return None
        return StoredUser(
            id=identifier, payload=payload, banned=as_flag(banned), ban_expires=ban_expires
        )
