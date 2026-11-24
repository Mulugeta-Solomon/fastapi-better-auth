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

**Call `await store.connect()` in your lifespan.** It reads the live schema once, so a table or a
required column that is missing stops the application at startup instead of failing the first
request with a `ConfigurationError`. Without it, the first lookup does the same work.

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
