# fastapi-better-auth-bridge

**A bridge to a TypeScript [Better Auth](https://better-auth.com) server — not a Python port.**
(If you want a full Python re-implementation, this is not it.) Community-maintained; not affiliated
with or endorsed by Better Auth.

> **Status.** Two modes ship today, and every change to either is conformance-tested in CI against a
> real Better Auth server rather than a mock: Mode B — a JWT verified against your server's JWKS —
> and Mode A — the session cookie, verified against a shared session store, with its cross-site
> request forgery protection built in and required. Mode C (remote `get-session`) is not yet
> shipped. No dates are promised.

## Modes

Better Auth is TypeScript-only: sign-in/up, OAuth and 2FA run on your Node service. This package
makes the sessions that service issues first-class in FastAPI.

| Mode | Status | How | Revocation lag |
|---|---|---|---|
| **B — JWT / JWKS** | **available now** | Verify Better Auth JWT-plugin tokens statelessly against `/api/auth/jwks` (EdDSA by default, pinned algorithm allowlist, required claims, token-lifetime ceiling) | ≤ token lifetime (15 min upstream default) |
| **A — Cookie + shared DB/Redis** | **available now** | Verify the signed `session_token` cookie (HMAC-SHA256, exact wire parity with better-call) and read the session store directly, with a required CSRF policy | Instant |
| **C — Remote get-session** | planned | Forward the credential to `GET /api/auth/get-session` with fail-closed semantics | Instant |

Which better-auth and Python versions each lane exercises:
[COMPATIBILITY.md](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/COMPATIBILITY.md).

## Install

Python 3.10+. The distribution is `fastapi-better-auth-bridge` — the shorter spelling collides with
an unrelated package under PyPI's name-similarity rules — and the import is `fastapi_better_auth`.
`JwtVerifier` fetches your key set through a pluggable `Transport`: pick the adapter for the client
your project already has, or install neither extra and pass your own `Transport`.

| Extra | Installs | Adapter |
|---|---|---|
| `[httpx]` | `httpx>=0.27` | `HttpxTransport`, used by default when you pass no `transport=` |
| `[httpx2]` | `httpx2>=2.0` | `Httpx2Transport` |

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
carries.

## Errors

Every request-time failure is an `HTTPException` subclass, so FastAPI answers it with no handler of
yours: `401`, the body `{"detail": "Not authenticated"}`, and a `WWW-Authenticate: Bearer` header.
Missing, malformed, expired, revoked and "the key set could not be fetched" are byte-identical on
the wire, deliberately — a client must not be able to tell them apart and use the difference to
probe. Two credentials on one request are a `400` (`{"detail": "Ambiguous request"}`), decided
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

## Do I need to run a Node service?

Better Auth itself always runs in a Node/TypeScript process — sign-up, sign-in, OAuth, 2FA, and
session *issuance* stay there; this library makes FastAPI a first-class *consumer* of the sessions
it issues. Two topologies:

- **You have a JS frontend server (Next.js, Nuxt, SvelteKit, …):** no extra service — Better Auth
  is already mounted at `/api/auth/*` inside the frontend you deploy, and FastAPI verifies what it
  issues: nothing shared at all for Mode B, a shared Postgres or Redis for Mode A.
- **No JS server (static SPA, mobile app, pure API):** deploy one tiny Node service whose only job
  is mounting Better Auth, and keep 100% of the business logic in FastAPI. This repository's
  conformance harness (`harness/`) is exactly that service, in Hono.

Either way the browser or app performs its login flows against Better Auth, then presents the
resulting credential to FastAPI, where this library verifies it — the session cookie for Mode A, a
JWT for Mode B.

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
second verifier — and no failure reason ever reaches the client.

## License

MIT © Mulugeta Solomon
