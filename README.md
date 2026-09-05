# fastapi-better-auth-bridge

**A bridge to a TypeScript [Better Auth](https://better-auth.com) server — not a Python port.**
(If you want a full Python re-implementation, this is not it.) Community-maintained; not affiliated
with or endorsed by Better Auth.

> **Status.** Three modes ship, and every change to any of them is conformance-tested in CI against
> a real Better Auth server rather than a mock: Mode B — a JWT verified against your server's JWKS
> — Mode A — the session cookie, verified against a shared session store — and Mode C — the same
> cookie, forwarded to your Better Auth server's own `get-session` route, fail-closed. Both cookie
> modes carry cross-site request forgery protection that is required rather than optional. No dates
> are promised.

## Modes

Better Auth is TypeScript-only: sign-in/up, OAuth and 2FA run on your Node service. This package
makes the sessions that service issues first-class in FastAPI. Three modes ship. They differ in
what they couple to, what a request costs, and — the row that should decide it — what they can
still see once a session goes away.

| | **A — cookie + shared store** | **B — JWT / JWKS** | **C — remote get-session** |
|---|---|---|---|
| **Revocation lag** | instant | ≤ token lifetime (15 min upstream default) | instant |
| **Credential** | the signed session cookie | `Authorization: Bearer <JWT>` | the signed session cookie |
| **Cost per request** | one session-store read | none — verified offline | one HTTPS call upstream, unless the local pre-filter or the negative cache answers first |
| **What it couples to** | the shared secret, the same session store, and Better Auth's internal formats (cookie HMAC + store layout) | reachability of `/api/auth/jwks`, and nothing else | network reach to your Better Auth server, its `200`-with-`null` contract, and its `{session, user}` body shape — plus the signed-cookie envelope *only* if you configure a secret |
| **CSRF** | required, no default | not applicable — a bearer credential is not sent ambiently | required, no default |
| **Expiry** | refused here, because upstream's `findSession` does not check `expiresAt` | refused: `exp`, and a ceiling on the `exp - iat` upstream would never have minted | refused here, for the same reason |
| **Sign-out** | the very next request is `401` | invisible until the token expires | the very next request is `401` |
| **Bans** | refused here — upstream's `get-session` never reads `banned` either | invisible until the token expires | refused here, from the record upstream returns |
| **Algorithm confusion** | not applicable | refused: a pinned algorithm allowlist, and an unknown `kid` is a refusal rather than a search | not applicable |
| **Secret rotation** | a keyring, compared in constant time with no early return | upstream's own `kid` rollover | the same keyring, when you configure one |
| **Auth server down** | keeps verifying — it never calls it | keeps verifying from the cached key set until that needs a refetch | refuses (`401`); guessing here would be the bypass |

**Two caveats behind the "Bans" row.** A ban is enforced *by this library*, from the user record it
already has, because upstream's `get-session` route never reads `banned` — the admin plugin enforces
bans when a session is **created** (`dist/plugins/admin/admin.mjs:33-49`) and deletes the user's
sessions when the ban goes through its own route (`dist/plugins/admin/routes.mjs:305`). So a ban
written straight into the database is still caught here, in Mode A on SQL and in Mode C. It is
**not** caught when Better Auth runs with `secondaryStorage` and the ban is written straight to the
database: the session document in Redis was written before the ban and still says `banned: false`,
and that document is what both Mode A and Mode C read there. On that topology, ban through the
admin route — it deletes the sessions, and then every mode sees a sign-out.

**Picking one.** If FastAPI can share the database or Redis your Node service writes sessions to,
Mode A is the cheapest instant revocation. If it can only reach that service over the network, that
is Mode C. If it has to verify with no dependency on the auth server being reachable at all, that
is Mode B, and the price is a revocation lag equal to the token lifetime. Modes compose — each
request picks the verifier whose credential it actually carries, and two credentials on one request
are a `400` — with one exception: **A and C read the same cookie name, so composing those two is
refused at construction.** It is a choice between modes, not a stack.

Which better-auth and Python versions each lane exercises:
[COMPATIBILITY.md](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/COMPATIBILITY.md).

## Install

Python 3.10+. The distribution is `fastapi-better-auth-bridge` — the shorter spelling collides with
an unrelated package under PyPI's name-similarity rules — and the import is `fastapi_better_auth`.
The two modes that talk to your Better Auth server — `JwtVerifier` for the key set, `RemoteVerifier`
for `get-session` — do it through a pluggable `Transport`: pick the adapter for the client your
project already has, or install neither extra and pass your own `Transport`.

| Extra | Installs | Adapter |
|---|---|---|
| `[httpx]` | `httpx>=0.27` | `HttpxTransport`, used by default when you pass no `transport=` |
| `[httpx2]` | `httpx2>=2.0` | `Httpx2Transport` |

The default client honours the process environment the way `httpx` does — `HTTP_PROXY`,
`HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`/`SSL_CERT_DIR` and `~/.netrc`. That is usually what a
deployment behind an egress proxy or a private CA wants; if it is not, pass your own
`HttpxTransport(client=httpx.AsyncClient(trust_env=False))`. Either way the client never follows a
redirect and never keeps a cookie. [SECURITY.md](SECURITY.md) spells out what the library trusts.

```bash
pip install "fastapi-better-auth-bridge[httpx]"   # or: uv add "fastapi-better-auth-bridge[httpx]"
```

## Quickstart (Mode B)

**Upstream prerequisite:** the [JWT plugin](https://better-auth.com/docs/plugins/jwt) has to be
mounted on your Better Auth server (`plugins: [jwt()]`). It serves `/api/auth/jwks`, the key set
verified against, and `/api/auth/token`, where a signed-in client fetches its token; without it
there is nothing here to verify. Then, in FastAPI:

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from fastapi_better_auth import BetterAuth, JwtVerifier, Session, User

auth = BetterAuth(verifiers=[JwtVerifier(base_url="https://auth.example.com")])
CurrentSession = Annotated[Session[User], Depends(auth.current_session())]

app = FastAPI()


@app.get("/me")
async def me(session: CurrentSession) -> User:
    return session.user
```

`base_url` is the whole of the trust configuration: canonicalized once, it is the required `iss`,
the required `aud`, and the origin the key set is fetched from — and nothing is derived from the
incoming request. If your deployment already sets `BETTER_AUTH_URL` for the Node side,
`BetterAuth.from_env()` reads exactly that one variable, raises if missing, and builds the same:

```python
from fastapi_better_auth import BetterAuth

auth = BetterAuth.from_env()
```

**Call the factory** — `Depends(auth.current_session())`, with the parentheses. Passed bare it would
make the factory itself the dependency, a silent bypass of every route beneath a router, so every
`Depends` and `Security` planting of a bare factory is refused with a `ConfigurationError` while
the route is registered and the application never starts. The one exception is a bare factory
assigned into `app.dependency_overrides`, a plain dict this library has no hook into: there the
application does start, and the same refusal fires on the first request touching that dependency —
still verifying nothing, and still serving nobody.

`/docs` needs no wiring: the security scheme is derived from each verifier's own credential source,
so the Authorize button works out of the box.

### Your own user model, and optional authentication

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from fastapi_better_auth import BetterAuth, JwtVerifier, Session, User


class Member(User):
    role: str | None = None


auth = BetterAuth(verifiers=[JwtVerifier(base_url="https://auth.example.com")])
CurrentMember = Annotated[Session[Member], Depends(auth.current_session(user_model=Member))]
MaybeMember = Annotated[Session[Member] | None, Depends(auth.optional_session(user_model=Member))]

app = FastAPI()


@app.get("/role")
async def role(session: CurrentMember) -> str:
    return session.user.role or "member"


@app.get("/greeting")
async def greeting(session: MaybeMember) -> str:
    return "hello" if session is None else f"hello, {session.user.id}"
```

`optional_session` returns `None` for one situation only: no credential was presented at all. One
that *was* presented and did not verify still fails — a forged or expired token is never downgraded
to "anonymous".

## Quickstart (Mode A — session cookie)

The mode to reach for when the browser talks to FastAPI directly, carrying the cookie Better Auth
set on sign-in. It verifies that cookie's signature against your shared secret, looks the session up
in the store Better Auth writes to, and enforces expiry and revocation the moment the store says the
session is gone — the instant revocation a JWT cannot give you.

A cookie-authenticated mode has to answer cross-site request forgery, so **`csrf=` is required and
has no default.** `OriginCheck` is what most deployments want; `SignedDoubleSubmit` and —
deliberately, spelled out in your own source — `CsrfDisabled(reason="…")` are the alternatives.

**Bring your own store.** Any object with these two async reads is a `SessionStore`, and the shipped
adapters get no privilege yours does not. A dict-backed one is enough to run:

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from fastapi_better_auth import (
    BetterAuth,
    CookieVerifier,
    OriginCheck,
    Session,
    SessionStore,
    SharedSecret,
    StoredSession,
    StoredUser,
    User,
)


class DictSessionStore:
    """A SessionStore backed by two dicts: the whole Protocol, and nothing more.

    A real deployment reads the rows or keys Better Auth already writes (see below); this is
    the shape of the two questions a store answers — a read, never a write.
    """

    def __init__(self, sessions: dict[str, StoredSession], users: dict[str, StoredUser]) -> None:
        self._sessions = sessions
        self._users = users

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        return self._sessions.get(token)

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        return self._users.get(user_id)


store: SessionStore = DictSessionStore(sessions={}, users={})

auth = BetterAuth(
    verifiers=[
        CookieVerifier(
            # A literal only so this page runs; in production read it from the environment —
            # SharedSecret(os.environ["BETTER_AUTH_SECRET"]) — the value the Node side signs with.
            secret=SharedSecret("replace-this-with-your-own-32-plus-character-secret"),
            store=store,
            csrf=OriginCheck(allowed_origins=["https://app.example.com"]),
        )
    ]
)
CurrentSession = Annotated[Session[User], Depends(auth.current_session())]
MaybeSession = Annotated[Session[User] | None, Depends(auth.optional_session())]

# withCredentials lets the /docs "Try it out" button send the browser's own cookie to a same-site API.
app = FastAPI(swagger_ui_parameters={"withCredentials": True})


@app.post("/posts")
async def create_post(session: CurrentSession) -> dict[str, str]:
    return {"author": session.user.id}


@app.post("/reactions")
async def add_reaction(session: MaybeSession) -> dict[str, str | None]:
    return {"author": None if session is None else session.user.id}
```

The protected routes are `POST`s on purpose: cross-site request forgery is a threat to *unsafe*
methods, so a cookie-authenticated write is exactly where `OriginCheck` earns its place. A forged or
absent cookie is a terminal `401`; a cross-site write carrying a real cookie is a `403`, decided
before the signature is even checked.

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

# Redis secondary-storage instead of SQL:
#   from fastapi_better_auth import RedisSessionStore
#   store = RedisSessionStore(url=os.environ["REDIS_URL"])   # a miss is a 401, never a DB fall-back
```

`SqlAlchemySessionStore` reads the `session` and `user` tables directly; `RedisSessionStore` reads
the raw-token key Better Auth's `secondaryStorage` writes. **A store reads; it never writes** — no
`touch`, no `EXPIRE`-on-read — because a write here would extend or resurrect a session this side was
only asked to verify.

### What Mode A refuses, and when

| Check | Behaviour |
|---|---|
| **Revocation** | Instant. Sign-out deletes the session from the store; the very next request reads the miss and is refused (`401`). |
| **Expiry** | Enforced by the verifier. Upstream's `findSession()` does not check `expiresAt`, so a bare DB join honours an expired session forever; this verifier refuses it. |
| **Signature** | `token + "." + base64(HMAC-SHA256(secret, token))`, standard base64, split at the *last* dot, compared in constant time against a keyring — exact wire parity with better-call. |
| **CSRF** | Required, and checked **before** the signature, so a cross-site `403` is never an oracle for whether the cookie behind it is currently valid. |

A **Redis-authoritative** deployment is a hard rule: a store miss is a `401`, never a fall-back to a
database. When Better Auth runs with `secondaryStorage`, sign-out deletes the Redis key while a stale
row can still sit in Postgres, so a fall-back would resurrect exactly the sessions a sign-out
revoked.

### `/docs`

The cookie route publishes an `APIKeyCookie` scheme, so `/docs` shows an Authorize field for it and
the security requirement appears on the operation. Two honest limits:

- **Swagger UI cannot *set* a cookie from the Authorize modal**
  ([swagger-api/swagger-ui#9710](https://github.com/swagger-api/swagger-ui/issues/9710)); the field
  is declarative. What makes "Try it out" work is `FastAPI(swagger_ui_parameters={"withCredentials":
  True})`, which tells Swagger to send the browser's *own* cookie — the one Better Auth already set —
  so a developer signed in on a same-site `/docs` can exercise the route.
- The scheme is documentation only. What it would read is never read; every credential comes from
  the verifier that owns it.

### Deploying across two origins

The common shape is a front end on `app.example.com` and this API on `api.example.com`. For the
browser to send the cookie cross-origin you configure Better Auth to set it `SameSite=None; Secure`
in its `__Secure-` prefixed form — which `CookieVerifier` reads by default.

`SameSite=None` is exactly where CSRF stops being optional. `OriginCheck` is the floor; but a *bare*
double-submit cookie proves only that the sender could set a cookie, and a sibling subdomain can set
one on the shared parent domain — so on a shared parent domain reach for `SignedDoubleSubmit`, whose
token is `HMAC(secret, session_token)`, bound to the session and useless to a sibling. A **non-browser**
client (mobile, server-to-server) has no `Origin` for `OriginCheck` to trust and belongs on **Mode B**
(bearer) instead: compose both verifiers and each request picks its own by which credential it
carries. All of this applies unchanged to Mode C, which reads the same cookie.

## Quickstart (Mode C — remote get-session)

The mode to reach for when FastAPI can *reach* your Better Auth server over the network but does
not share its database, its Redis, or — unless you choose to — its secret. It takes the session
cookie off the request, forwards exactly that one cookie to
`GET /api/auth/get-session?disableCookieCache=true&disableRefresh=true`, and believes the answer:
`disableCookieCache` forces the authoritative read, so revocation is instant, and `disableRefresh`
keeps the call read-only. Everything that could refuse the request without asking — the structural
check, your optional secret, the negative cache, the backoff latch — runs first.

Like Mode A this is a cookie mode, so **`csrf=` is required and has no default**, and the protected
routes below are `POST`s for the same reason: cross-site request forgery is a threat to unsafe
methods.

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from fastapi_better_auth import (
    BetterAuth,
    OriginCheck,
    RemoteVerifier,
    Session,
    SharedSecret,
    User,
)

auth = BetterAuth(
    verifiers=[
        RemoteVerifier(
            base_url="https://auth.example.com",
            csrf=OriginCheck(allowed_origins=["https://app.example.com"]),
            # Optional, and worth it: with a secret configured, a forged cookie is refused
            # locally, before any upstream call. A literal only so this page runs — in
            # production, SharedSecret(os.environ["BETTER_AUTH_SECRET"]).
            secret=SharedSecret("replace-this-with-your-own-32-plus-character-secret"),
        )
    ]
)
CurrentSession = Annotated[Session[User], Depends(auth.current_session())]
MaybeSession = Annotated[Session[User] | None, Depends(auth.optional_session())]

# withCredentials lets the /docs "Try it out" button send the browser's own cookie to a same-site API.
app = FastAPI(swagger_ui_parameters={"withCredentials": True})


@app.post("/articles")
async def publish(session: CurrentSession) -> dict[str, str]:
    return {"author": session.user.id}


@app.post("/claps")
async def clap(session: MaybeSession) -> dict[str, str | None]:
    return {"reader": None if session is None else session.user.id}
```

That snippet is executed by this repository's test suite on every commit, with the network refused
outright — which is exactly the claim it is there to prove. Constructing a `RemoteVerifier` opens no
connection, and because a secret is configured, every forged cookie those two routes are driven with
is refused *here*, with zero upstream calls. Take the secret out and the same forgeries become one
`get-session` call each.

**Wire the startup probe in production.** `RemoteVerifier` has one piece of boot work, and the
snippet above leaves it out only so the page can run offline:

```text
import os

from fastapi import FastAPI

from fastapi_better_auth import BetterAuth, OriginCheck, RemoteVerifier, SharedSecret

auth = BetterAuth(
    verifiers=[
        RemoteVerifier(
            base_url=os.environ["BETTER_AUTH_URL"],
            csrf=OriginCheck(allowed_origins=["https://app.example.com"]),
            secret=SharedSecret(os.environ["BETTER_AUTH_SECRET"]),
        )
    ]
)

# The probe runs once here; a server that fails it never starts serving.
app = FastAPI(lifespan=auth.lifespan)
```

`FastAPI(lifespan=auth.lifespan)` runs `BetterAuth.startup()`, which runs each verifier's `prepare()`
once — for this one, the probe. The probe is a single bare `get-session` request carrying no cookie,
and it asserts the contract Mode C rests on: reachable, `200`, `application/json`, body exactly
`null`. A `base_path` that points at nothing is a `ConfigurationError` naming the URI it tried, at
boot, rather than a 401 per request forever. It is also the backstop against a `Transport` that
retains cookies: both shipped adapters install a dead cookie jar, but a `Transport` you write is
yours, and a session document coming back from a request that carried no cookie means the client is
replaying somebody's. That is refused by name rather than served.

What the probe does **not** prove: that a real cookie will verify, that your secret matches, that
the server will still be up on the next request. It proves the URI and the contract, once.

Without the lifespan, the probe still runs — lazily, on the first request that gets that far. A
contract failure there is remembered permanently, and every later request raises the same
`ConfigurationError`. A *reachability* failure is not remembered: the request is refused with a 401
and the probe is retried at most once every ten seconds, so an auth service that comes up a moment
after yours recovers on its own.

**What one request costs.** The order below is the design, and everything above the fetch makes zero
outbound calls by construction:

1. The cookie is resolved by name, and a structurally impossible one is refused — too long, not
   decodable, no signature separator.
2. The CSRF policy runs, before anything else looks at the credential, so a cross-site `403` is
   never an oracle for whether the cookie behind it is live.
3. If you configured a secret, the signature is verified locally against the keyring. A forgery
   stops here and never becomes traffic.
4. A `200`-with-`null` verdict is remembered for 30 seconds by default, keyed on the whole cookie
   value, so a forgery flood costs one upstream call per window rather than one per request.
5. If upstream has recently answered `429`, the backoff latch refuses without calling it again.
6. Only then the call, through a concurrency limiter (8 in flight by default) so one stalled auth
   service cannot park every worker task.

Then the answer is checked rather than trusted: the returned `session.token` must match the token
that was forwarded, expiry is enforced here, and bans are enforced here. Anything else — a non-200,
a timeout, a body that is not a usable session document — is a refusal, never a pass.

### The shared rate-limit bucket

Read this before Mode C sees real traffic. Better Auth rate-limits its own routes, and the way it
keys the bucket means **every user of your FastAPI service shares one bucket for `/get-session`**,
because they all reach your Node service from one address.

The mechanism, read out of better-auth 1.7.1's own build:

- The limiter is on when you have not set `rateLimit.enabled` and `NODE_ENV === "production"`
  (`dist/context/create-context.mjs:171`, `@better-auth/core/dist/env/env-impl.mjs:30-32`) — off in
  development, on in production, which is the worst order in which to discover it.
- The default bucket is **100 requests per 10 seconds** (`dist/context/create-context.mjs:172-173`),
  and there is no built-in rule for `/get-session` (`dist/api/rate-limiter/index.mjs:302-316`), so
  the default is what applies to it.
- The key is `` `${ip}|${path}` `` (`@better-auth/core/dist/utils/ip.mjs:226-228`, built at
  `dist/api/rate-limiter/index.mjs:245`).
- The only client-IP header read by default is `x-forwarded-for`
  (`@better-auth/core/dist/utils/ip.mjs:194`, walked at `:204`), and when no address can be derived
  the key falls back to the shared sentinel `no-trusted-ip` (`dist/api/rate-limiter/index.mjs:233`,
  used at `:245`). A server-to-server call forwards no such header, so that sentinel is the bucket
  your whole deployment lands in — one bucket per path, for everybody.

In round numbers: about **ten verified requests per second across the entire deployment**, for every
request that misses this library's pre-filter and negative cache. **Nothing in this library raises
that ceiling.** The pre-filter, the cache, the concurrency limiter and the 429 latch all reduce how
often you *reach* the bucket; none of them makes it bigger. The fix is upstream configuration.

**Fix 1 — exempt the route.** The whole rule value is `false`. There is no `max: false` field and no
IP allowlist:

```ts
rateLimit: { customRules: { "/get-session": false } }
```

(`dist/api/rate-limiter/index.mjs:259-276`; `if (resolved === false) return null` at `:274`.)

**Fix 2 — or raise it for that one route**, if you would rather keep a ceiling:

```ts
rateLimit: { customRules: { "/get-session": { window: 10, max: 1000 } } }
```

**Fix 3 — or run Mode A or Mode B**, which make no upstream call per request at all.

When the bucket does refuse, upstream answers `429` with **`X-Retry-After`** — not `Retry-After`
(`dist/api/rate-limiter/index.mjs:64-69`), which is worth knowing before you go hunting for the
standard header in your own logs. Its value is the whole seconds left in the window, measured from
the last request upstream *allowed*: a refused request does not move the bucket
(`dist/api/rate-limiter/index.mjs:47-52`, and the memory backend writes only on an allowed decision
at `:217`). This library reads `Retry-After` and then `X-Retry-After`, clamps to 1–60 seconds, and
latches: while the latch holds every request is refused with zero outbound calls, one warning is
logged, and it clears by time alone. The latch is per verifier instance, so eight worker processes
have eight of them.

### `requireSignature`: a raw session token is a bearer credential

If your Better Auth server mounts the `bearer` plugin, check this option before anything else on
this page. `requireSignature` defaults to **false**, and while it is false a *raw, unsigned* session
token presented as `Authorization: Bearer <token>` is signed by the server with its own secret and
installed as the session cookie (`dist/plugins/bearer/index.mjs:34-38`, then `:46`). It
authenticates. Which means a session token in a log line, a database dump, a backup or an error
report is not an identifier — it is a credential.

The fix is one line upstream:

```ts
bearer({ requireSignature: true })
```

With it set, a dot-less token is ignored outright (`dist/plugins/bearer/index.mjs:36`). That is not
advice taken on faith: the conformance lane runs two live Better Auth servers, one at each setting,
and pins the behaviour in both directions — `tests/e2e/test_conformance.py::TestBearerPosture`.

`RemoteVerifier` checks for the permissive posture at startup, advisory-only. Alongside the probe it
sends one request carrying a manufactured random token and looks at nothing but whether a
`set-cookie` header came back: the permissive posture emits one, the strict posture does not. If it
sees one it logs a single warning naming the fix. It never refuses, never reads that header's value,
and never replays a real credential — your server's posture is yours to set.

### Sessions do not slide on bridge traffic

Every `get-session` call this library makes pins `disableRefresh=true`, so the route takes its
read-only branch (`dist/api/routes/session.mjs:163-170`) instead of the one that calls
`updateSession` and pushes `expiresAt` forward (`:191-195`). That is deliberate — a verifier that
extended sessions would make your API's request rate a factor in how long people stay signed in, and
would be handed a `Set-Cookie` the browser never sees — but the consequence deserves stating plainly:
**traffic to FastAPI does not keep a session alive.**

A session expires `session.expiresIn` after it was issued (7 days by default,
`dist/context/create-context.mjs:147`), however busy your API is. Better Auth normally slides that
forward once a session is older than `session.updateAge` (1 day by default, `:146`) — but
only requests that reach *Better Auth* do it.

Two remedies, and most deployments already have the first:

- **The browser also talks to the Node server** — signing in, refreshing, any Better Auth route at
  all. Sessions then slide there exactly as they always did and nothing here changes.
- **Otherwise raise `expiresIn` upstream** to whatever "signed in" should mean for your product, and
  accept that it is a fixed window from sign-in rather than a sliding one.

Mode A behaves the same way, for the same reason: a store read is a read, never a write.

### Organizations and roles — the recipe

Multi-tenant authorization is deferred as an API to a later release. The rule is not, and it holds in
every mode, because it is about the session document rather than about how the session was verified.

**The organization id comes from the request — its path or its body — and membership is checked with
your own query. Never from `session.raw["session"]["activeOrganizationId"]`.**

That value is written by `POST /organization/set-active`, a route the *client* calls
(`dist/plugins/organization/routes/crud-org.mjs:379`). Upstream does check membership before it
writes (`:420`, a 403 at `:425`), so it is not forgeable — but it is not an answer to *this*
request's question either. It records which organization the client last selected, out of the ones
the user belongs to. The request in front of you names its own organization, and the two are
unrelated.

The failure that produces is not subtle. A handler that **selects data by the path's organization
but authorizes on `activeOrganizationId`** lets any member of any organization read every
organization's data: the check passes because they do have an active organization, and the query
then runs against whatever the path said.

```text
# The organization id comes from the REQUEST. Membership is your query, against the `member`
# table Better Auth already writes. Needs a database, so it is shown rather than executed here.

from typing import Annotated

from fastapi import Depends, HTTPException, status
from sqlalchemy import text


async def require_member(org_id: str, session: CurrentSession) -> str:
    """Authorize this user against THIS request's organization, or refuse with 403."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text('SELECT role FROM "member" WHERE "organizationId" = :org AND "userId" = :user'),
            {"org": org_id, "user": session.user.id},
        )
        membership = result.first()
    if membership is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return membership.role


@app.get("/orgs/{org_id}/invoices")
async def invoices(role: Annotated[str, Depends(require_member)]) -> list[str]:
    ...
```

**The regression case, spelled out — keep it as a test.** Sign in as a user who is a member of
organization A and *not* of organization B. Call `organization.setActive({ organizationId: "A" })`.
Then request `/orgs/B/invoices` with that same session, and expect **403**. The correct handler
refuses because the `member` query for `(B, user)` finds nothing. The broken one returns `200` and
serves B's invoices, because it asked whether the user had an active organization and never asked
which organization this request was about.

### `/docs`, restated for Mode C

Identical to Mode A, because it is the same cookie: the route publishes an `APIKeyCookie` scheme, so
`/docs` shows an Authorize field and the security requirement appears on the operation. The two
honest limits are the same ones. Swagger UI cannot *set* a cookie from the Authorize modal
([swagger-api/swagger-ui#9710](https://github.com/swagger-api/swagger-ui/issues/9710)) — the field is
declarative, and what makes "Try it out" work is
`FastAPI(swagger_ui_parameters={"withCredentials": True})`, which tells Swagger to send the browser's
*own* cookie, the one Better Auth already set. And the scheme is documentation only: what it would
read is never read, because every credential comes from the verifier that owns it.

## Errors

Every request-time failure is an `HTTPException` subclass, so FastAPI answers it with no handler of
yours: `401`, the body `{"detail": "Not authenticated"}`, and a `WWW-Authenticate: Bearer` header.
Missing, malformed, expired, revoked, "the key set could not be fetched" and "the auth service could
not be reached" are byte-identical on the wire, deliberately — a client must not be able to tell them
apart and use the difference to probe. That last one is `AuthServiceUnavailable`, and it is a `401`
rather than a `503` on purpose: an unreachable Better Auth server means this request was not
authenticated, and saying so in a distinct status would be both an oracle and an invitation to
retry. Mode C raises it for every non-`200` upstream answer, every timeout, an unusable body, a
saturated outbound limiter, and a live `429` backoff. Two credentials on one request are a `400`
(`{"detail": "Ambiguous request"}`), decided
before anything is verified. A cookie-mode request that fails its CSRF check is a `403`
(`{"detail": "Forbidden"}`) with no challenge — it carried a credential, so there is nothing to
re-authenticate.

Why a request was refused lives on the exception, as `.reason`, and nowhere else. **This library
does not log ordinary refusals** — a forged, expired or malformed token, an unknown key id, a
missing or ambiguous credential — and that is deliberate rather than an omission: what to record
about a failed authentication, and where, is the deployment's decision. If you want them, register
a FastAPI exception handler for `SessionError` and log `exc.reason` explicitly; note that
`logging.exception()` renders `str(exc)`, which does not carry it. A `reason` holds identifiers and
fingerprints — a key id, a truncated hash — never a raw credential.

What it *does* log — all at `WARNING`, all on the `fastapi_better_auth` logger — is the deployment
telling on itself: a session-cache cookie it was not asked to read, a JWKS key it will not verify
with or a refresh that failed while a usable key set was still on hand, a stored record or a
database table it cannot use, a `429` backoff latch opening (once per latch, never once per refused
request), and the advisory `requireSignature` warning (once per process). None of those lines
carries a raw token, a cookie value or a signature.

## Do I need to run a Node service?

Better Auth itself always runs in a Node/TypeScript process — sign-up, sign-in, OAuth, 2FA, and
session *issuance* stay there; this library makes FastAPI a first-class *consumer* of the sessions
it issues. Two topologies:

- **You have a JS frontend server (Next.js, Nuxt, SvelteKit, …):** no extra service — Better Auth
  is already mounted at `/api/auth/*` inside the frontend you deploy, and FastAPI verifies what it
  issues: nothing shared at all for Mode B, a shared Postgres or Redis for Mode A, and for Mode C
  only a route from FastAPI to that frontend's `/api/auth/get-session`.
- **No JS server (static SPA, mobile app, pure API):** deploy one tiny Node service whose only job
  is mounting Better Auth, and keep 100% of the business logic in FastAPI. This repository's
  conformance harness (`harness/`) is exactly that service, in Hono.

Either way the browser or app performs its login flows against Better Auth, then presents the
resulting credential to FastAPI, where this library verifies it — the session cookie for Modes A
and C, a JWT for Mode B.

## Why a library instead of the snippet

The hand-rolled verifiers circulating in Better Auth issues split the signed cookie on the wrong
dot, miss the `__Secure-` name, compare HMACs non-constant-time, and never enforce `expiresAt`
(upstream's `findSession` doesn't either — the route layer does, so a bare DB join honours expired
sessions forever). Those are Mode A's details, and Mode A handles every one of them: the last-dot
split, the `__Secure-` name, a constant-time keyring compare, and `expiresAt` enforced by the
verifier itself. The wire facts behind them are pinned as golden vectors captured from a running
Better Auth server in `tests/vectors/`, and re-verified against a live server in the conformance
lane — not guessed.

Mode B is held to the same standard: `JwtVerifier` refuses an algorithm the token's own
header chose, refuses an unknown `kid` rather than trying every published key, spells out the five
required claims because PyJWT requires none by default, and refuses a token whose lifetime upstream
would never have minted. A present-but-invalid credential is terminal — no falling through to a
second verifier — and no failure reason ever reaches the client. What Mode B cannot do is see a
ban or a sign-out: a JWT is verified offline and stays valid until it expires, so keep token
lifetimes short and lean on Mode A or Mode C for prompt revocation (see SECURITY.md).

Mode C looks like the easy one and has the sharpest edges, which is why the shape of the request is
fixed at construction and never derived from the one being verified. An unauthenticated
`get-session` answers **`200` with a body of literally `null`**, not a `401`, so a snippet that
checks the status code authenticates everybody. The `bearer` plugin's hook *overwrites* the session
cookie of an outgoing request with whatever `Authorization` header it sees, so a proxy that forwards
the inbound `Authorization` along with the cookie hands a client a targeted denial-of-service on one
victim, and a client who sends a raw session token an authentication this side never checked — which
is why exactly two headers, `cookie` and `accept`, ever go out. `httpx`'s default client keeps
cookies, so an auth server's `Set-Cookie` would be replayed onto the next user's verification: both
shipped transports install a dead jar and the boot probe detects a live one. And the shared
rate-limit bucket above is the one nobody finds until production.

## License

MIT © Mulugeta Solomon
