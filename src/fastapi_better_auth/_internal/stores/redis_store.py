"""The secondary-storage store: a `GET` on the raw token, a `GET` on its user's revocation
watermark, and never a question of anywhere else."""

from __future__ import annotations

import hmac
import json
import math
from collections.abc import Mapping
from types import TracebackType
from typing import TYPE_CHECKING, Any, Protocol, TypeGuard, TypeVar, cast

from ..errors import ConfigurationError
from ..reasons import safe_label
from .diagnostics import unusable
from .records import StoredSession, StoredUser
from .revocation import Verdict, judge, watermark_key
from .session_document import SESSION_KEY, parse_session_document

if TYPE_CHECKING:
    import redis.asyncio

MAX_VALUE_BYTES = 64 * 1024

CONNECT_TIMEOUT_SECONDS = 3.0
"""How long a client built from `url=` waits to connect.

A Redis on the same network connects in well under a millisecond, so this only ever decides how
long a request waits on a cache that is down. Three seconds rather than less because a refused
loopback connect takes about two seconds on Windows, and a shorter deadline would report a port
nobody listens on as a timeout instead of the refusal it is.

The default only: the `socket_connect_timeout=` argument replaces it, and a
`?socket_connect_timeout=` in the URL's query string wins over both - held to the same rule, a
positive, finite number of seconds, or the store is refused at construction."""

READ_TIMEOUT_SECONDS = 2.0
"""How long a client built from `url=` waits on one socket operation - a reply to one `GET` of a
value capped at `MAX_VALUE_BYTES`, which a healthy Redis answers in well under a millisecond.

It is a deadline per operation, not per lookup. A lookup issues two `GET`s, a fresh connection
also waits on redis-py's own handshake replies, and a retry policy given in the URL multiplies
all of it - so a silent Redis costs a lookup a few multiples of this, not one, and never an
unbounded wait.

The default only: the `socket_timeout=` argument replaces it, and a `?socket_timeout=` in the
URL's query string wins over both - held to the same rule, a positive, finite number of seconds,
or the store is refused at construction."""

SOCKET_TIMEOUT = "socket_timeout"
SOCKET_CONNECT_TIMEOUT = "socket_connect_timeout"
LENT_DEADLINE = (
    "{name} was given with client=. A lent client is never modified, so the deadline would be"
    " silently ignored; set it on the client you built, or pass url= to have this store build one."
)

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


def _validated_cap(max_bytes: object) -> int:
    """A cap below one refuses every stored value, silently and forever."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ConfigurationError(
            f"max_bytes must be a positive integer number of bytes; got {max_bytes!r}."
        )
    return max_bytes


def _import_redis() -> Any:
    try:
        from redis.asyncio import Redis
    except ImportError as exc:
        raise ConfigurationError(MISSING) from exc
    return Redis


def _is_deadline(seconds: object) -> TypeGuard[float]:
    """A positive, finite number of seconds. `None` is redis-py's "wait forever" - not one."""
    return (
        not isinstance(seconds, bool)
        and isinstance(seconds, (int, float))
        and math.isfinite(seconds)
        and seconds > 0
    )


def _validated_deadline(name: str, seconds: object) -> float:
    if not _is_deadline(seconds):
        raise ConfigurationError(
            f"{name} must be a positive, finite number of seconds; got {safe_label(repr(seconds))}."
            " It bounds how long one Redis socket operation may hold the request that needed it."
        )
    return seconds


def _unbounded_in_url(effective: Mapping[str, object]) -> ConfigurationError | None:
    """The refusal for a deadline the URL's query string set to what the arguments may not be.

    `effective` is what the built pool will connect with. Every value there that is not a valid
    deadline came from the URL: the arguments were validated before the client was built. Only
    the option's name and a `safe_label` of its value are quoted, never the URL around it.
    """
    for name in (SOCKET_TIMEOUT, SOCKET_CONNECT_TIMEOUT):
        seconds = effective.get(name)
        if not _is_deadline(seconds):
            return ConfigurationError(
                f"{name} in the url= query string must be a positive, finite number of seconds;"
                f" got {safe_label(repr(seconds))}. It wins over the {name}= argument, and bounds"
                " how long one Redis socket operation may hold the request that needed it."
            )
    return None


def _deadlines(read: object, connect: object, *, lent: bool) -> dict[str, float]:
    """Both socket deadlines, validated - and refused beside a lent client unless left alone.

    A lent client is never modified, so a deadline given with one would do nothing; the store
    cannot tell a default passed explicitly from one left out, and neither is a change, so only a
    value other than the default is refused.
    """
    deadlines = {
        SOCKET_TIMEOUT: _validated_deadline(SOCKET_TIMEOUT, read),
        SOCKET_CONNECT_TIMEOUT: _validated_deadline(SOCKET_CONNECT_TIMEOUT, connect),
    }
    defaults = {
        SOCKET_TIMEOUT: READ_TIMEOUT_SECONDS,
        SOCKET_CONNECT_TIMEOUT: CONNECT_TIMEOUT_SECONDS,
    }
    changed = [name for name, seconds in deadlines.items() if seconds != defaults[name]]
    if lent and changed:
        raise ConfigurationError(LENT_DEADLINE.format(name=changed[0]))
    return deadlines


def _built_client(url: object, deadlines: Mapping[str, float]) -> Any:
    """Build a client from `url`, refusing a bad one at construction rather than at first fetch.

    The `Raises:` contract promises a `ConfigurationError` for every construction failure, and a
    bare `url=7` would otherwise be an `AttributeError` from `from_url`. Neither the value nor
    redis-py's own error is echoed: a redis URL can carry a password (`redis://user:pass@host`),
    so the refusal names what to check and is raised outside the handler with `from None`, so the
    credential can ride out on neither `__cause__` nor `__context__`.

    `deadlines` go in as keyword arguments, which redis-py's `from_url` overrides with any option
    of the same name in the URL's query string - so `?socket_timeout=10` wins, by redis-py's own
    precedence rather than by a merge this library would have to keep in step with it. What wins
    is then read back from the pool (`connection_pool.connection_kwargs`, the same public
    attribute from redis-py 5.0.1 on) and held to the arguments' rule, so `?socket_timeout=inf`
    is refused here rather than built into a read that never times out. The refused client is
    dropped before the refusal is raised: its pool is lazy and has opened no connection, and no
    frame of the traceback keeps it.
    """
    if not isinstance(url, str) or not url.strip():
        raise ConfigurationError(
            "url must be a non-empty redis URL string, like 'redis://host:6379/0'."
        )
    try:
        client = _import_redis().from_url(url, **deadlines)
    except (ValueError, TypeError):
        failure = ConfigurationError(
            "the url= given was rejected by redis-py; check its scheme, host and port"
        )
    else:
        failure = _unbounded_in_url(client.connection_pool.connection_kwargs)
        if failure is None:
            return client
        del client
    raise failure from None


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

    **"Revoke all sessions" is read too.** Since better-auth 1.7.16 that revocation also writes
    `revoked-sessions-before-<userId>` (epoch milliseconds), and upstream refuses a session whose
    `createdAt` is strictly before it even when the session's key outlived the revocation - a
    failed delete, a replica, a refresh racing it. So once a stored session has been read and has
    named its key, a second `GET` reads that watermark under the same `key_prefix`; on an earlier
    version the key is simply absent. A session it revokes is a miss like an absent key, and logs
    nothing. Where upstream fails open the store does not: a watermark that is not a whole number
    of milliseconds, or a watermark beside a session with no readable `createdAt`, is a miss with
    a warning. There is no switch for it. Two reads rather than one `MGET` or pipeline, because
    the second key is named by the `userId` inside the first value - and reading it second also
    catches a revocation that lands between the two.

    **The user arrives with the session.** The stored value already carries both, so the happy
    path is those two `GET`s and no user lookup, and the record's `user` is populated.
    `fetch_user_by_id` correspondingly has nothing to answer from and always answers a miss:
    secondary storage keys sessions, an active-session list and the watermark, never a user by id,
    and guessing a key or reaching for a database is the fallback above.

    **It never writes.** No `SET`, no `DEL`, no `EXPIRE` refreshed on read - the last would make
    a revoked session outlive its revocation. `GET` is the only command this store issues against
    your keyspace (a client built from `url=` also does redis-py's own `HELLO`/`CLIENT SETINFO`
    handshake on connect, which touches no key).

    **There is no column allow-list here.** The two SQL stores take `user_columns=` /
    `session_columns=` to narrow what a shared `user` table hands a verified request; this one
    reads one stored JSON document whole, and a document has no SELECT to narrow. What Better Auth
    puts in `secondaryStorage` is what a record carries.

    **A value it cannot read is a miss, with a warning naming a fingerprint of the key.** Not
    JSON, not an object, no session, no user, no usable `expiresAt`, or a stored session naming a
    *different* token than the key it was found under: all of them answer `None`. The last is
    compared in constant time and is the one that matters - honouring it would authenticate
    whoever wrote that key. A failure of Redis itself - on either read - propagates untranslated,
    because a store cannot know what an unreachable cache means to the request that needed it;
    the frames it unwinds through here hold neither the token, the key nor the stored document by
    then. The client's own frames are its own: redis-py's hold the key it was asked for.

    The token is compared as UTF-8 bytes. A `str` carrying an unpaired surrogate cannot be
    encoded and raises rather than returning a miss - but it is unreachable through the real entry
    point (Starlette latin-1-decodes the cookie header, which cannot carry a surrogate), so a
    surrogate here is direct API misuse, where a loud error is more use than a silent miss.

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
        socket_timeout: Seconds a client built from `url` waits on one socket operation; 2 by
            default. Per operation, not per lookup: two `GET`s, a new connection's handshake and
            any retry policy each wait up to this. An option of the same name in the URL's query
            string (`?socket_timeout=5`) wins over this argument, which is redis-py's own
            precedence - and is held to the same rule as the argument.
        socket_connect_timeout: Seconds a client built from `url` waits to connect; 3 by
            default, and overridden by the URL's query string the same way, under the same rule.
            Neither deadline may be changed alongside `client`: a lent client is never modified.

    Raises:
        ConfigurationError: If neither `url` nor `client` is given, if both are, if `key_prefix`
            is not a string, if `max_bytes` is not a positive integer, if either deadline - as an
            argument or in the URL's query string - is not a positive finite number of seconds,
            if a deadline argument is changed alongside `client`, if redis-py rejects `url`, or
            if `url` was given and the `redis` package is not installed. Every argument is checked
            before a client is built; a deadline in the URL can only be read from the client
            redis-py built, which is then dropped unused - its pool is lazy, so a refused
            construction leaves no connection behind.
    """

    def __init__(
        self,
        *,
        url: str | None = None,
        client: redis.asyncio.Redis | _Client | None = None,
        key_prefix: str = "",
        max_bytes: int = MAX_VALUE_BYTES,
        socket_timeout: float = READ_TIMEOUT_SECONDS,
        socket_connect_timeout: float = CONNECT_TIMEOUT_SECONDS,
    ) -> None:
        if url is None and client is None:
            raise ConfigurationError(NEITHER)
        if url is not None and client is not None:
            raise ConfigurationError(BOTH)
        # Every argument is checked before a client is built. The one refusal after that point -
        # a deadline the URL's query string set - drops a pool that has opened no connection.
        self._prefix = _validated_prefix(key_prefix)
        self._max_bytes = _validated_cap(max_bytes)
        deadlines = _deadlines(socket_timeout, socket_connect_timeout, lent=client is not None)
        built = None if client is not None else _built_client(url, deadlines)
        # Only a client this store BUILT is ever closed; a borrowed pool is not ours to shut.
        self._built: Any | None = built
        self._client: _Client = cast("_Client", client if client is not None else built)

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        """The session stored under this raw token, with its user.

        See `SessionStore.fetch_session_by_token`. A blank token never reaches Redis.
        """
        if not token.strip():
            return None
        key = f"{self._prefix}{token}"
        value: object = None
        document: Mapping[str, Any] | None = None
        record: StoredSession | None = None
        try:
            value = await self._client.get(key)
            if value is None:
                return None
            document = self._document(value, key)
            if document is None:
                return None
            record = self._record(document, token, key)
            if record is None:
                return None
            return await self._unless_revoked(record, key)
        finally:
            # A client failure propagates through this frame untranslated, and a reporter that
            # captures frame locals would find the token, the key built from it and the stored
            # document here (D-094). The return value is already computed; these are not it.
            token = key = ""
            value = document = record = None

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        """Always a miss, and never a command.

        Better Auth's secondary storage holds sessions, an `active-sessions-<userId>` list and a
        `revoked-sessions-before-<userId>` watermark; there is no user keyed by id to read. A
        session fetched from this store always carries its user, so the sanctioned flow never
        asks - and answering by guessing a key, or by reaching for a database, is the fallback
        D-008 forbids.
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

    async def _unless_revoked(self, record: StoredSession, key: str) -> StoredSession | None:
        """The record, unless its user's revocation watermark says it was revoked.

        Asked only once the document has been read and has named the key it was found under, so
        a miss, a malformed value or a mismatched token never costs this second read. A revoked
        or unreadable verdict is a miss, indistinguishable from an absent key to the caller.
        """
        try:
            watermark = await self._client.get(watermark_key(self._prefix, record.user_id))
            standing = judge(watermark, record.payload, key) is Verdict.STANDING
            return record if standing else None
        finally:
            # A failed watermark read unwinds through here holding the whole record (D-094).
            del record
            key = ""

    def _document(self, value: object, key: str) -> Mapping[str, Any] | None:
        if not isinstance(value, (bytes, bytearray, str)):
            # `safe_label` the type name (D2): it is the only interpolated part of any `unusable`
            # reason, and a crafted `__name__` with a newline would forge a second log line.
            unusable(SESSION_KEY, f"redis answered a {safe_label(type(value).__name__)}", key)
            return None
        # Count bytes, not characters (D1): a `decode_responses=True` client answers `str`, and a
        # multibyte character is more than one byte on the wire the cap is about.
        size = len(value.encode("utf-8")) if isinstance(value, str) else len(value)
        if size > self._max_bytes:
            unusable(SESSION_KEY, f"it is over the {self._max_bytes}-byte cap", key)
            return None
        try:
            parsed: object = json.loads(value)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError):
            # A few kilobytes of nesting exhausts json's recursive scanner well under the byte
            # cap; a stack limit reached is a value this reader cannot read (D-183).
            unusable(SESSION_KEY, "it is not JSON", key)
            return None
        if not isinstance(parsed, dict):
            unusable(SESSION_KEY, "it is not a JSON object", key)
            return None
        return cast("Mapping[str, Any]", parsed)

    def _record(self, document: Mapping[str, Any], token: str, key: str) -> StoredSession | None:
        # The `{session, user}` promotion is the shared seam (session_document); the one check
        # that stays here is the store's own: does the value name the key it was found under.
        # Honouring a mismatch would authenticate whoever wrote that key.
        record = parse_session_document(document, key)
        if record is None:
            return None
        if not hmac.compare_digest(record.token.encode("utf-8"), token.encode("utf-8")):
            unusable(
                SESSION_KEY, "it names a different session than the key it was found under", key
            )
            return None
        return record
