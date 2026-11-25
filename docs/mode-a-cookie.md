# Mode A: session cookie and shared store

After reading this page you can verify the Better Auth session cookie in FastAPI with
`CookieVerifier`, reading sessions from the store your Better Auth server writes to, and build it
inside an application factory.

## Quickstart

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

    A real deployment reads the rows or keys Better Auth already writes (docs/stores.md); this is
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

In production, the store reads the rows or keys Better Auth already writes. See
[Session stores](stores.md) for `SqlAlchemySessionStore`, `SyncStoreAdapter` and
`RedisSessionStore`.

## With an application factory

Where a `create_app(settings)` factory owns the engine — the shape a test suite that builds several
applications needs — the store, the verifier and the `BetterAuth` are built inside it too, and the
routes come from a router factory handed that `BetterAuth`:

```python
import contextlib
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field

from fastapi import APIRouter, Depends, FastAPI
from sqlalchemy.ext.asyncio import create_async_engine

from fastapi_better_auth import (
    BetterAuth,
    CookieVerifier,
    OriginCheck,
    Session,
    SharedSecret,
    SqlAlchemySessionStore,
    User,
)


@dataclass(frozen=True)
class Settings:
    database_url: str = field(repr=False)  # it carries the database password
    better_auth_secret: SharedSecret
    front_end_origin: str


def build_router(auth: BetterAuth) -> APIRouter:
    required = auth.current_session()
    optional = auth.optional_session()

    async def create_post(session: Session[User] = Depends(required)) -> dict[str, str]:
        return {"author": session.user.id}

    async def add_reaction(
        session: Session[User] | None = Depends(optional),
    ) -> dict[str, str | None]:
        return {"author": None if session is None else session.user.id}

    router = APIRouter()
    router.add_api_route("/posts", create_post, methods=["POST"])
    router.add_api_route("/reactions", add_reaction, methods=["POST"])
    return router


def create_app(settings: Settings) -> FastAPI:
    engine = create_async_engine(settings.database_url)  # one pool per application, never shared
    store = SqlAlchemySessionStore(engine=engine)
    auth = BetterAuth(
        verifiers=[
            CookieVerifier(
                secret=settings.better_auth_secret,
                store=store,
                csrf=OriginCheck(allowed_origins=[settings.front_end_origin]),
            )
        ]
    )

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncGenerator[None]:
        yield
        await engine.dispose()

    app = FastAPI(lifespan=lifespan)
    app.state.auth = auth  # a test takes its override key off this instance
    app.include_router(build_router(auth))
    return app
```

The quickstart's module-level `CurrentSession` aliases cannot follow the bridge into the factory:
kept at module scope they would need a module-level store over a module-level engine, and every
application the factory returns would share that one pool — the thing `SqlAlchemySessionStore`'s
*always injected, never built here* rule exists to prevent. Moved inside a function, an `Annotated`
alias is no longer a type expression pyright accepts (`reportInvalidTypeForm`), and a nested route
function that is only decorated is reported unused under `strict` (`reportUnusedFunction`) — hence
gates declared as `Depends(...)` defaults and endpoints handed to `add_api_route` by name.

The lifespan closes the pool the factory opened, and is where `await store.connect()` goes before
the `yield` so a database whose schema cannot answer a lookup stops the application from starting;
it is left out here only because this page runs without a database. A test builds its own
application with `create_app(test_settings)` and takes its override key off `app.state.auth` — see
[Testing](testing.md).

## What Mode A refuses, and when

| Check | Behaviour |
|---|---|
| **Revocation** | Instant. Sign-out deletes the session from the store; the very next request reads the miss and is refused (`401`). |
| **Expiry** | Enforced by the verifier. Upstream's `findSession()` does not check `expiresAt`, so a bare DB join honours an expired session forever; this verifier refuses it. |
| **Signature** | `token + "." + base64(HMAC-SHA256(secret, token))`, standard base64, split at the *last* dot, compared in constant time against a keyring — exact wire parity with better-call. |
| **CSRF** | Required, and checked **before** the signature, so a cross-site `403` is never an oracle for whether the cookie behind it is currently valid. |
| **A store that does not answer** | Refused as `AuthServiceUnavailable` (`401`) once the request's store lookups have taken `lookup_timeout` seconds, 5 by default. A store of your own that shields its lookup from cancellation is refused only when that lookup returns. See [When the database does not answer](stores.md#when-the-database-does-not-answer). |

A **Redis-authoritative** deployment is a hard rule: a store miss is a `401`, never a fall-back to a
database. When Better Auth runs with `secondaryStorage`, sign-out deletes the Redis key while a stale
row can still sit in Postgres, so a fall-back would resurrect exactly the sessions a sign-out
revoked.

## Configuration

Every parameter is keyword-only. An unusable value is a `ConfigurationError` at construction.

| Name | Default | Meaning |
|---|---|---|
| `secret` | `None` | The `SharedSecret` your Better Auth server signs with. Exactly one of `secret` and `secrets`. See [Shared secret](shared-secret.md). |
| `secrets` | `None` | A list of `SharedSecret` for a rotation. A cookie signed with any of them is accepted. |
| `store` | required | The `SessionStore` to read sessions from. See [Session stores](stores.md). |
| `csrf` | required | The CSRF policy. There is no default. See [CSRF](csrf.md). |
| `cookie_name` | `"better-auth.session_token"` | The cookie name without its prefix. |
| `secure_prefix` | `"__Secure-"` | The prefix read when `secure_cookies` is `True`. `"__Host-"` is the only prefix a sibling subdomain cannot plant; prefer it where Better Auth can emit it. |
| `secure_cookies` | `True` | `True` reads only `{secure_prefix}{cookie_name}`, Better Auth's production default; `False` reads only `cookie_name`, for a development server over HTTP. Never both. |
| `now` | `None` | The clock for the expiry and ban checks, for tests. It can only make the verifier stricter. See [Testing](testing.md#moving-the-verifiers-clock). |
| `lookup_timeout` | `5.0` | Seconds one request's store lookups may take together. A request that runs out is refused as `AuthServiceUnavailable`. `None` sets no limit. See [When the database does not answer](stores.md#when-the-database-does-not-answer). |
