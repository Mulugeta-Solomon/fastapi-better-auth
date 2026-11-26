# Session stores

After reading this page you can point Mode A at the sessions your Better Auth server already
writes, grant the store's database role only what it needs, and write a store of your own.

A store answers two questions for `CookieVerifier`: which session has this raw token, and which
user has this id. It is used by [Mode A](mode-a-cookie.md) only.

## The `SessionStore` protocol

Any object with these two async methods is a `SessionStore`. The shipped stores get no privilege
yours does not.

| Method | Returns |
|---|---|
| `async fetch_session_by_token(token: str)` | A `StoredSession`, or `None` when no session has that token. |
| `async fetch_user_by_id(user_id: str)` | A `StoredUser`, or `None` when no user has that id. |

`StoredSession` takes `token`, `user_id`, `expires_at` (an aware `datetime`) and `payload` (the
session as Better Auth stores it), and optionally `user`, `impersonated_by` and `id`. `StoredUser`
takes `id` and `payload`, and optionally `banned` and `ban_expires`. When `StoredSession.user` is
set, `fetch_user_by_id` is not called. [Mode A](mode-a-cookie.md#quickstart) has a complete
in-memory store.

## The shipped stores

**In production, point the store at the rows Better Auth already writes.** That needs an extra —
`fastapi-better-auth-bridge[sqlalchemy]` or `[redis]` — and a live backend, so it is shown here
rather than executed on this page:

```text
import os

from sqlalchemy.ext.asyncio import create_async_engine

from fastapi_better_auth import (
    BetterAuth, CookieVerifier, OriginCheck, SharedSecret, SqlAlchemySessionStore,
)

engine = create_async_engine(os.environ["DATABASE_URL"])   # the database Better Auth writes sessions to
store = SqlAlchemySessionStore(engine=engine)

auth = BetterAuth(
    verifiers=[
        CookieVerifier(
            secret=SharedSecret(os.environ["BETTER_AUTH_SECRET"]),
            store=store,
            csrf=OriginCheck(allowed_origins=["https://app.example.com"]),
        )
    ]
)

# Where other services also own the `user` table, name the extra columns that may travel:
#   store = SqlAlchemySessionStore(engine=engine, user_columns=["tenantId"])

# Redis secondary-storage instead of SQL:
#   from fastapi_better_auth import RedisSessionStore
#   store = RedisSessionStore(url=os.environ["REDIS_URL"])   # a miss is a 401, never a DB fall-back
```

`SqlAlchemySessionStore` reads the `session` and `user` tables directly; `RedisSessionStore` reads
the raw-token key Better Auth's `secondaryStorage` writes. **A store reads; it never writes** — no
`touch`, no `EXPIRE`-on-read — because a write here would extend or resurrect a session this side was
only asked to verify.

**On Postgres, the SQL store's role needs `SELECT` on `session` and `user` and nothing else**
(`GRANT SELECT ON "session", "user" TO <role>`): the admin plugin's columns and your
`additionalFields` are columns of `user`, not separate grants, and the `USAGE` it needs on their
schema is one `PUBLIC` holds on `public` by default — only a non-default `schema=` needs that
granted. Granting no more is what turns the read-only property into a database guarantee: Postgres
itself refuses every `INSERT`, `UPDATE` and `DELETE` the role attempts. Grant less — `SELECT` on
`session` alone — and `connect()` still succeeds (discovery reads the system catalog, which needs no
grant), then every lookup answers the uniform `401` as `AuthServiceUnavailable`, and the store logs
one `WARNING` naming the driver error and its SQLSTATE (`42501`, insufficient privilege) — once per
kind of failure until a lookup completes again, never the token.
`tests/e2e/test_store_grants_live.py` proves the grant, the refused writes and that answer against a
live Postgres.

**Every column of both tables is read by default**, which is what makes your own `additionalFields`
reach `session.user` — so do not put a secret on either table. Where the `user` table is shared with
services that add internal columns to it, `user_columns=` (and `session_columns=` for the other
table) names the extra columns that may be selected, and nothing else is. Both are opt-in and change
no default, and neither narrows Better Auth's own set: the required columns are how a session is
found at all, and `banned` / `banExpires` / `impersonatedBy` stay selected whatever the list says,
because a ban is this library's business to enforce. A name the live table does not have is a
`ConfigurationError` at `connect()`, beside the missing-column one. `RedisSessionStore` has no
equivalent — it reads one stored JSON document, and a document has no SELECT to narrow.

## SQL store parameters

`SqlAlchemySessionStore` takes an async engine. `SyncStoreAdapter` takes a synchronous SQLAlchemy
`Engine`, for an application that has no async driver, and the same table and column parameters.
Both need the `[sqlalchemy]` extra and a database driver of your choice. Every parameter is
keyword-only.

| Name | Default | Meaning |
|---|---|---|
| `engine` | required | The engine for the database Better Auth writes sessions to. The store never builds one. |
| `session_table` | `"session"` | The session table's name. |
| `user_table` | `"user"` | The user table's name. |
| `schema` | `None` | The schema both tables are in. `None` is the connection's default schema. |
| `session_columns` | `None` | Extra `session` columns that may be selected. `None` selects every column. |
| `user_columns` | `None` | Extra `user` columns that may be selected. `None` selects every column. |
| `max_concurrency` | `None` | `SyncStoreAdapter` only. The most lookups that may run on worker threads at once. `None` uses the engine pool's size plus overflow, or 8 where the pool states no size. |

**Call `await store.connect()` in your lifespan.** It reads the live schema once, so a table or a
required column that is missing stops the application at startup instead of failing the first
request with a `ConfigurationError`. Without it, the first lookup does the same work, inside its
request's `lookup_timeout`.

## The Redis store

`RedisSessionStore` is for a Better Auth server that runs with `secondaryStorage`. It needs the
`[redis]` extra, or a client of your own. Every parameter is keyword-only, and exactly one of `url`
and `client` is given.

| Name | Default | Meaning |
|---|---|---|
| `url` | `None` | A Redis URL. The store builds a client from it and closes that client in `aclose()`. |
| `client` | `None` | Your own `redis.asyncio.Redis`. The store never changes it and never closes it. |
| `key_prefix` | `""` | Put in front of every key the store reads. Better Auth itself uses none. |
| `max_bytes` | `65536` | The largest stored value the store parses. A larger one is a miss, with a `WARNING`. |
| `socket_timeout` | `2.0` | Seconds a client built from `url` waits on one socket operation. |
| `socket_connect_timeout` | `3.0` | Seconds a client built from `url` waits to connect. |

**A lookup is up to two `GET`s.** The first reads the session stored under the token. The second
reads `revoked-sessions-before-<userId>`. Better Auth 1.7.16 and later writes that key when all of
a user's sessions are revoked, or when the user is banned through the admin plugin. A session
created before the time it holds is a miss, as it is for Better Auth itself, even when the
session's own key is still in Redis. An earlier Better Auth does not write the key, and nothing
changes there.

**A Redis ACL must let the store read that key too.** Its full name is
`<key_prefix>revoked-sessions-before-<userId>`, so an ACL that allows `GET` on the whole prefix
already covers it. The second `GET` is sent only when the first found a session the store could
read; a miss stops before it. If the Redis user may not read the key, the store raises redis-py's
error for that lookup. `CookieVerifier` then refuses the request as `AuthServiceUnavailable`, the
uniform `401`. It logs one `WARNING`, and no more until a lookup completes.

**A revocation the store cannot read is still a revocation.** If the key holds anything but a
whole number of milliseconds, or the session has no readable `createdAt` while the key exists,
the lookup is a miss and a `WARNING` is logged. Better Auth's own comparison lets such a session
through. This store does not, so a wrong value in that key refuses every session of that user
until the key is corrected or expires.

**The two deadlines apply to a client built from `url`.** An option of the same name in the URL's
query string, such as `?socket_timeout=5`, wins over the argument. Either way the value must be a
positive, finite number of seconds, or the store raises `ConfigurationError` when it is built.
With `client=`, set the deadlines on your own client: either argument with a value other than its
default raises `ConfigurationError`. A deadline covers one socket operation, so a Redis that has
stopped answering can cost one lookup a few multiples of it. `lookup_timeout` bounds the request
as a whole.

## When the database does not answer

`CookieVerifier` gives one request's store lookups `lookup_timeout` seconds together, 5 by default.
A request that runs out is refused as `AuthServiceUnavailable`, the uniform `401`. One `WARNING` of
the kind `LookupDeadlineExceeded` is logged, and not again until a lookup completes. A lookup is
also cancelled when its request is cancelled, as a server may do when the client has gone.

What happens to the call that was running depends on the store:

- **`SqlAlchemySessionStore`** cancels its database call once and returns to the request at once.
  SQLAlchemy and the driver then cancel the statement on the server and close that connection, and
  a later lookup opens a new one. The connection counts against the engine's pool until that has
  ended, so a database that still answers never has more connections from the store than the pool
  allows. While the pool is full, further lookups wait for a connection and are refused at their
  own deadline. If the server has stopped answering altogether, the store stops waiting for it
  after 5 seconds and frees the connection's place in the pool. When the server answers again, it
  holds no connection of the store beyond the pool's.
- **`SyncStoreAdapter`** cannot interrupt a worker thread. The statement runs on, and its thread and
  its connection stay taken until the database answers or the driver gives up. The adapter never
  runs more threads than `max_concurrency`. Further lookups wait without starting a thread, and are
  refused at their own deadline.
- **`RedisSessionStore`** cancels the `GET` it was waiting for. A reply that arrives afterwards is
  never read by a later lookup, because redis-py closes the connection of a cancelled command.
  `tests/e2e/test_redis_cut_reply_live.py` proves that against a live Redis.

Set these in the database and the driver, for either store:

- **A statement timeout on the server that is shorter than `lookup_timeout`**, so a statement nobody
  waits for ends by itself. On Postgres: `ALTER ROLE <role> SET statement_timeout = '3s'`. It
  applies to connections opened after it, so restart the application or recycle its pool. On
  MySQL: `max_execution_time`.
- **A connect timeout in the driver.** A lookup that finds no idle connection opens one inside its
  own deadline, so keep `lookup_timeout` well above the time a new connection takes.
- **For `SyncStoreAdapter`, a read timeout in the driver**, so a thread waiting on a server that
  never answers is given back.

A SQL store that was not connected at startup reads the schema inside a request, under that
request's `lookup_timeout`. A read that takes longer than that never finishes inside a request.
Call `await store.connect()` in your lifespan, where no such limit applies.

The `[sqlalchemy]` extra needs SQLAlchemy 2.0.38 or newer. Before 2.0.24, a cancelled connection
is dropped without cancelling its statement on the server. Before 2.0.38, a server that stops
answering and then answers again can keep a connection the store has given up.

`tests/e2e/test_store_cancellation_live.py` proves the async store's part against a live Postgres
on `asyncpg`. With the `session` table locked, no statement of a refused lookup is left on the
server. Against a server that stops answering, during a statement or while a connection is being
returned to the pool, the abandoned calls end and their places in the pool come back, by the
store's own 5-second limit where the driver would wait for good. Once the server answers again,
it is asked directly, and it holds only the pool's connections. The same cases were also measured
by hand on `psycopg`. Other drivers are not measured; the statement timeout above covers them.

## Integer and uuid ids

Better Auth can let the database generate ids (`advanced.database.generateId: "serial"` or
`"uuid"`). The SQL stores read the type of the id columns (`session.id`, `session.userId`,
`session.impersonatedBy` and `user.id`) when they read the schema:

- An integer id is handed on as decimal digits, and a uuid as lowercase hyphenated text: the text
  Better Auth itself writes. `Session.id`, `User.id` and `Session.raw` always carry string ids.
- An id is accepted only as the type its column promises. Any other value reads as missing.
- `fetch_user_by_id` binds the id as the column's own type, and only from that canonical text.
  `"07"`, `" 7"` or upper-case hex is a miss, and no query runs.

Text ids, Better Auth's default, are read exactly as before. Integer ids and uuids stored as text
are tested on SQLite. The live Postgres lane uses text ids, so native Postgres `serial` and `uuid`
columns are not yet tested against a live database.
