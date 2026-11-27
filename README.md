# fastapi-better-auth-bridge

Verify [Better Auth](https://better-auth.com) sessions in FastAPI.

**What it is.** A bridge: your Better Auth server (TypeScript, on Node) signs users in and issues
sessions, and this library checks those sessions on every FastAPI request. **What it is not.** It
is not a Python port of Better Auth. Sign-up, sign-in, OAuth and 2FA stay on the Node side.
Community-maintained; not affiliated with or endorsed by Better Auth.

Every change is tested in CI against real Better Auth servers, not mocks. A credential that does
not verify is always refused, with one uniform answer, whatever the reason. An auth service that
cannot answer gets that same answer by default, or a `503` with [the opt-in](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/errors.md#answering-503-while-the-auth-service-is-down).

> **If your Better Auth server mounts `bearer()`, set `requireSignature: true`.** It defaults to
> `false`, and then a raw session token in a log or a backup is a working credential. See
> [Configuring the Better Auth server](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/better-auth-server.md).

## The three modes

| | **Mode A: cookie + shared store** | **Mode B: JWT** | **Mode C: ask the auth server** |
|---|---|---|---|
| **Verifier** | `CookieVerifier` | `JwtVerifier` | `RemoteVerifier` |
| **Reads** | the session cookie | `Authorization: Bearer <JWT>` | the session cookie |
| **Needs** | the Better Auth secret, and read access to its session store (SQL database or Redis) | the JWT plugin on the Better Auth server | network access to the Better Auth server |
| **Trusts** | the cookie signature, then the stored session | the token signature, against the server's published keys | the server's `get-session` answer |
| **Sign-out** | the very next request is `401` | invisible until the token expires | the very next request is `401` |
| **Auth server down** | keeps working; it never calls the server | keeps working from cached keys, for at most one day by default | refuses every request |
| **Cost per request** | one store read | none | one call to the auth server, unless refused locally first |
| **CSRF policy** | required | not needed | required |
| **Pick it when** | FastAPI can read the database or Redis that Better Auth writes sessions to | FastAPI must keep working while the auth server is down, and a sign-out may take up to the token lifetime to apply | FastAPI can only reach the Better Auth server over the network |

**Which mode.** Start from the last row. Mode B can be combined with Mode A or Mode C; each request
is checked by the verifier whose credential it carries. Mode A and Mode C read the same cookie, so
they cannot be combined. The full comparison is in
[Choosing a mode](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/choosing-a-mode.md).

## Install

The distribution is `fastapi-better-auth-bridge`; the import is `fastapi_better_auth`.
`fastapi-betterauth` on PyPI is a different library by another author.

```bash
pip install "fastapi-better-auth-bridge[httpx]"   # or: uv add "fastapi-better-auth-bridge[httpx]"
```

| Extra | Needed for |
|---|---|
| `[httpx]` | Mode B and Mode C, through the default HTTP client |
| `[httpx2]` | Mode B and Mode C, through `Httpx2Transport` instead |
| `[sqlalchemy]` | Mode A with `SqlAlchemySessionStore` or `SyncStoreAdapter` |
| `[redis]` | Mode A with `RedisSessionStore` |

## Quickstart: Mode B

Mount the [JWT plugin](https://better-auth.com/docs/plugins/jwt) on your Better Auth server
(`plugins: [jwt()]`). Then:

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

Call the factory: `Depends(auth.current_session())`, with the parentheses. A bare
`auth.current_session` is refused when the route is registered.

## Quickstart: Mode A

A store answers two reads. This one is a dict, so the example runs anywhere. It starts empty and
Better Auth does not write to it, so as written it refuses every cookie. To sign a real user in,
use the SQL or Redis store that reads what Better Auth writes: see
[Session stores](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/stores.md).

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from fastapi_better_auth import (
    BetterAuth,
    CookieVerifier,
    OriginCheck,
    Session,
    SharedSecret,
    StoredSession,
    StoredUser,
    User,
)


class DictSessionStore:
    def __init__(self) -> None:
        self.sessions: dict[str, StoredSession] = {}
        self.users: dict[str, StoredUser] = {}

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        return self.sessions.get(token)

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        return self.users.get(user_id)


auth = BetterAuth(
    verifiers=[
        CookieVerifier(
            # In production: SharedSecret(os.environ["BETTER_AUTH_SECRET"]).
            secret=SharedSecret("replace-this-with-your-own-32-plus-character-secret"),
            store=DictSessionStore(),
            csrf=OriginCheck(allowed_origins=["https://app.example.com"]),
        )
    ]
)
CurrentSession = Annotated[Session[User], Depends(auth.current_session())]

app = FastAPI()


@app.post("/posts")
async def create_post(session: CurrentSession) -> dict[str, str]:
    return {"author": session.user.id}
```

## Quickstart: Mode C

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from fastapi_better_auth import BetterAuth, OriginCheck, RemoteVerifier, Session, SharedSecret, User

auth = BetterAuth(
    verifiers=[
        RemoteVerifier(
            base_url="https://auth.example.com",
            csrf=OriginCheck(allowed_origins=["https://app.example.com"]),
            # Optional but recommended: only correctly signed cookies are forwarded.
            # In production: SharedSecret(os.environ["BETTER_AUTH_SECRET"]).
            secret=SharedSecret("replace-this-with-your-own-32-plus-character-secret"),
        )
    ]
)
CurrentSession = Annotated[Session[User], Depends(auth.current_session())]

# In production, add lifespan=auth.lifespan so the readiness probe runs before traffic.
app = FastAPI()


@app.post("/articles")
async def publish(session: CurrentSession) -> dict[str, str]:
    return {"author": session.user.id}
```

## Documentation

All pages are in [`docs/`](https://github.com/Mulugeta-Solomon/fastapi-better-auth/tree/main/docs).
They describe the `main` branch; changes not yet released are listed in the
[changelog](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/CHANGELOG.md).

- [Choosing a mode](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/choosing-a-mode.md)
- [Mode A: session cookie and shared store](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/mode-a-cookie.md)
  and [Session stores](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/stores.md)
- [Mode B: JWT verified against the key set](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/mode-b-jwt.md)
- [Mode C: ask the Better Auth server](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/mode-c-remote.md)
- [Shared secret](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/shared-secret.md),
  [CSRF](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/csrf.md) and
  [Deploying across two origins](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/cross-origin.md)
- [User models](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/user-models.md)
  and [The verified session](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/sessions.md)
- [Authorization](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/authorization.md)
- [Errors](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/errors.md)
  and [Logging](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/logging.md)
- [Testing](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/testing.md)
- [OpenAPI and `/docs`](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/openapi.md)
  and [HTTP clients](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/http-clients.md)
- [Configuring the Better Auth server](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/better-auth-server.md)
- [Troubleshooting](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/docs/troubleshooting.md)

Every Python example in this README and in `docs/` is run by the test suite.

## Supported versions

- **Python** 3.10 to 3.14.
- **Better Auth:** the versions each release is tested against are in
  [COMPATIBILITY.md](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/COMPATIBILITY.md),
  and at runtime in `fastapi_better_auth.VERIFIED_BETTER_AUTH`. Run Better Auth 1.4.9 or newer.
- **This library** is pre-1.0. Only the latest release receives fixes.

## Security

Report a vulnerability privately, as described in
[SECURITY.md](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/SECURITY.md). Do not
open a public issue. SECURITY.md also lists what this library trusts and what it cannot fix.

## Contributing

See [CONTRIBUTING.md](https://github.com/Mulugeta-Solomon/fastapi-better-auth/blob/main/CONTRIBUTING.md).

## License

MIT © Mulugeta Solomon
