# fastapi-better-auth-bridge

**A bridge to a TypeScript [Better Auth](https://better-auth.com) server — not a Python port.**
(If you want a full Python re-implementation, this is not it.) Community-maintained; not affiliated
with or endorsed by Better Auth.

> **Status.** Mode B — a JWT verified against your server's JWKS — is shipped, and every change to
> it is conformance-tested in CI against a real Better Auth server rather than a mock. Mode A
> (session cookie + shared session store) ships in one release together with its CSRF protection,
> never before it; Mode C (remote `get-session`) comes after that. No dates are promised.

## Modes

Better Auth is TypeScript-only: sign-in/up, OAuth and 2FA run on your Node service. This package
makes the sessions that service issues first-class in FastAPI.

| Mode | Status | How | Revocation lag |
|---|---|---|---|
| **B — JWT / JWKS** | **available now** | Verify Better Auth JWT-plugin tokens statelessly against `/api/auth/jwks` (EdDSA by default, pinned algorithm allowlist, required claims, token-lifetime ceiling) | ≤ token lifetime (15 min upstream default) |
| **A — Cookie + shared DB/Redis** | planned | Verify the signed `session_token` cookie (HMAC-SHA256, exact wire parity with better-call) and read the session store directly | Instant |
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
make the factory itself the dependency, a silent bypass of every route beneath a router, so it is
refused with a `ConfigurationError` while the route is registered and the application never starts.
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

## Errors

Every request-time failure is an `HTTPException` subclass, so FastAPI answers it with no handler of
yours: `401`, the body `{"detail": "Not authenticated"}`, and a `WWW-Authenticate: Bearer` header.
Missing, malformed, expired, revoked and "the key set could not be fetched" are byte-identical on
the wire, deliberately — a client must not be able to tell them apart and use the difference to
probe. Two credentials on one request are a `400` (`{"detail": "Ambiguous request"}`), decided
before anything is verified.

Why a request was refused lives on the exception and in this library's log, never in the response.
Read it off `.reason`; if you want it in your own logs, register a FastAPI exception handler for
`SessionError` and log that attribute explicitly — `logging.exception()` renders `str(exc)`, which
deliberately does not carry it. A `reason` holds identifiers and fingerprints — a key id, a
truncated hash — never a raw credential.

## Do I need to run a Node service?

Better Auth itself always runs in a Node/TypeScript process — sign-up, sign-in, OAuth, 2FA, and
session *issuance* stay there; this library makes FastAPI a first-class *consumer* of the sessions
it issues. Two topologies:

- **You have a JS frontend server (Next.js, Nuxt, SvelteKit, …):** no extra service — Better Auth
  is already mounted at `/api/auth/*` inside the frontend you deploy, and FastAPI verifies what it
  issues: nothing shared at all for Mode B, a shared Postgres/Redis once Mode A lands.
- **No JS server (static SPA, mobile app, pure API):** deploy one tiny Node service whose only job
  is mounting Better Auth, and keep 100% of the business logic in FastAPI. This repository's
  conformance harness is exactly that service, in under sixty lines of Hono: `harness/`.

Either way the browser or app performs its login flows against Better Auth, then presents the
resulting JWT to FastAPI, where this library verifies it.

## Why a library instead of the snippet

The hand-rolled verifiers circulating in Better Auth issues split the signed cookie on the wrong
dot, miss the `__Secure-` name, compare HMACs non-constant-time, and never enforce `expiresAt`
(upstream's `findSession` doesn't either — the route layer does, so a bare DB join honours expired
sessions forever). Those are Mode A's details, and Mode A is not shipped; the wire facts behind them
are already captured from a running Better Auth server as golden vectors in `tests/vectors/`, so
the mode will arrive with them pinned rather than guessed.

The shipped mode is held to the same standard: `JwtVerifier` refuses an algorithm the token's own
header chose, refuses an unknown `kid` rather than trying every published key, spells out the five
required claims because PyJWT requires none by default, and refuses a token whose lifetime upstream
would never have minted. A present-but-invalid credential is terminal — no falling through to a
second verifier — and no failure reason ever reaches the client.

## License

MIT © Mulugeta Solomon
