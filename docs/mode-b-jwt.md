# Mode B: JWT verified against the key set

After reading this page you can verify Better Auth JWTs in FastAPI with `JwtVerifier`, configure
its key-set cache, and know what happens when the key set cannot be fetched.

Mode B reads an `Authorization: Bearer <JWT>` header and checks the token offline, against the
public keys your Better Auth server publishes. It makes no call to the auth server per request.
The price is that it cannot see a sign-out or a ban until the token expires. See
[Choosing a mode](choosing-a-mode.md) for the comparison.

## Quickstart

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
incoming request. The key set is always fetched from `{base_url}/api/auth/jwks`; unlike
`RemoteVerifier`, `JwtVerifier` has no `base_path`. If your deployment already sets
`BETTER_AUTH_URL` for the Node side, `BetterAuth.from_env()` reads exactly that one variable,
raises if missing, and builds the same:

```python
from fastapi_better_auth import BetterAuth

auth = BetterAuth.from_env()
```

`from_env()` builds Mode B only. Every other setting stays a constructor argument.

## Call the factory

**Call the factory** — `Depends(auth.current_session())`, with the parentheses. Passed bare it would
make the factory itself the dependency, a silent bypass of every route beneath a router, so every
`Depends` and `Security` planting of a bare factory is refused with a `ConfigurationError` while
the route is registered and the application never starts. The one exception is a bare factory
assigned into `app.dependency_overrides`, a plain dict this library has no hook into: there the
application does start, and the same refusal fires on the first request touching that dependency —
still verifying nothing, and still serving nobody. This holds in every mode.

`/docs` needs no wiring: the security scheme is derived from each verifier's own credential source,
so the Authorize button works out of the box. See [OpenAPI and `/docs`](openapi.md).

## Configuration

Every parameter is keyword-only. An unusable value is a `ConfigurationError` at construction.

| Name | Default | Meaning |
|---|---|---|
| `base_url` | required | The Better Auth server's origin, exactly as its own `baseURL` is set. `http` is accepted only for a loopback host. |
| `transport` | `None` | The HTTP client for the key set. `None` builds an `HttpxTransport` at construction, which needs the `[httpx]` extra. See [HTTP clients](http-clients.md). |
| `algorithms` | `("EdDSA",)` | The signature algorithms accepted. Each must be one of `EdDSA`, `ES256`, `ES512`, `PS256`, `RS256`. No symmetric (`HS*`) algorithm can be configured. |
| `leeway` | `0.0` | Seconds of clock skew allowed on `exp` and `nbf`. At most 60. |
| `max_token_lifetime` | `None` | The largest `exp - iat` a token may declare, in seconds. `None` means 900 plus `leeway`, which is upstream's own token lifetime. At most 86400. |
| `cache_ttl` | `300.0` | Seconds a fetched key set stays fresh. At least 60. |
| `max_stale` | `86400.0` | Seconds after the last successful fetch that the key set is still used while refetching fails. Never below `cache_ttl`, always finite. There is no value that switches it off. |

**`cache_ttl` above 86400 needs an explicit `max_stale`** at least as large. Without it,
construction fails, because the default `max_stale` would be below `cache_ttl`.

## When the key set cannot be fetched

The key set is fetched on the first token and kept for `cache_ttl` seconds. These rules decide
what happens after that. All ages are measured on the monotonic clock.

- **Fresh key set.** A token whose `kid` is in the set is verified with no fetch.
- **Older than `cache_ttl`, and the set holds the token's `kid`.** One request refreshes the set.
  Other requests that arrive while it does are answered from the set on hand at once; they do not
  wait for the refresh.
- **Refresh fails.** The set on hand keeps verifying for at most `max_stale` seconds after its last
  successful fetch. One `WARNING` is logged per failed refresh: `jwks refresh failed for <uri>;
  serving the key set on hand`.
- **Older than `max_stale`.** The set is no longer used. Every token is refused as
  `AuthServiceUnavailable`, the uniform `401`, until a refresh succeeds. A key the auth server
  withdrew therefore stops verifying here within `max_stale`, even when this service cannot reach
  the key set.
- **Unknown `kid`.** The request triggers a fetch and waits for it. At most one fetch happens per
  10-second window, however many new `kid` values arrive; inside the window, the token is refused
  without a fetch. A `kid` the fetched set does not hold is remembered as unknown for 60 seconds.
- **One key will not load.** It is skipped, with a `WARNING` naming its `kid` each time the set is
  fetched. The rest of the set is still used. A set in which no key loads is refused.

The key-set body is capped at 64 KiB and 32 keys. A key published with `use` other than `sig`, a
`key_ops` without `verify`, or an RSA key under 2048 bits is skipped and never used to verify.

## What Mode B refuses

Every refusal is a `SessionError`, so the response is the uniform `401` whatever went wrong. See
[Errors](errors.md).

- An algorithm outside the allowlist, checked against the token header before any key is looked
  at.
- A token that declares a `crit` header. Better Auth emits none, and none is supported.
- A missing or unusable `kid`. Published keys are never tried one after another.
- A missing `exp`, `iat`, `iss`, `aud` or `sub`. PyJWT requires no claim by default; this library
  requires all five on every decode.
- An `exp`, `iat` or `nbf` that is not a usable number: a bool, a string, `Infinity`, `NaN`, or an
  integer too large for a float.
- A token whose lifetime (`exp - iat`) is above `max_token_lifetime`, however well it is signed.

What Mode B cannot do is see a ban or a sign-out: a JWT is verified offline and stays valid until
it expires. Keep token lifetimes short, and use [Mode A](mode-a-cookie.md) or
[Mode C](mode-c-remote.md) where revocation must be prompt.
