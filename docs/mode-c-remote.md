# Mode C: ask the Better Auth server

After reading this page you can verify the Better Auth session cookie by forwarding it to your
Better Auth server with `RemoteVerifier`, wire its startup probe, and keep its traffic inside the
auth server's rate limit.

## Quickstart

The mode to reach for when FastAPI can *reach* your Better Auth server over the network but does
not share its database, its Redis, or — unless you choose to — its secret. It takes the session
cookie off the request, forwards exactly that one cookie to
`GET /api/auth/get-session?disableCookieCache=true&disableRefresh=true`, and believes the answer.
`disableCookieCache` switches off the cookie-cache short-circuit so the route always falls through
to the authoritative lookup (`dist/api/routes/session.mjs:48`) — that is where the instant
revocation comes from — and `disableRefresh` keeps the call read-only. Everything that could refuse
the request without asking upstream — the structural check, your optional secret, the negative
cache, the backoff latch — runs first.

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

## Configure the secret

`secret=` is optional, but configure it in production. Without it, Mode C cannot tell a forged
cookie from a real one before it asks the auth server. Every cookie that passes the structural
check (a token, a dot and a signature, all RFC 6265 cookie-octets, within the size caps) is
forwarded to `get-session`.

Those calls come out of the one rate-limit bucket that all your users share; see
[The shared rate-limit bucket](#the-shared-rate-limit-bucket). The negative cache remembers a
`null` answer for 30 seconds *per cookie value*, so a client that sends a new forged value on
every request costs one upstream call per request. Unauthenticated traffic can then use up the
bucket. When upstream answers `429`, the backoff latch refuses every request, real users included,
until it clears.

With `secret=` configured (or `secrets=` during a rotation), the signature is checked locally
first. Only a cookie signed with your secret is forwarded, and a forgery is refused with no
upstream call. Use the same value your Better Auth server signs with, and check that both sides
agree with [the fingerprint](shared-secret.md).

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
            # Refuse to start against a server whose bearer plugin is at requireSignature: false.
            refuse_unsigned_bearer=True,
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
replaying somebody's. That is refused by name rather than served. `refuse_unsigned_bearer=True`
adds one more rung to the same probe — the upstream `bearer` plugin's posture, refused at boot
instead of warned about; see
[`requireSignature`](better-auth-server.md#requiresignature-a-raw-session-token-is-a-bearer-credential).

The probe sorts its failures into two kinds:

- **Contract failure:** a redirect, a `4xx` other than `408`, `425` and `429`, a body that is not
  JSON `null`, a session document from the cookie-less request, and, under
  `refuse_unsigned_bearer=True`, a server that accepts an unsigned bearer token. These are facts
  about the deployment. `prepare()` raises `ConfigurationError`, and the failure is remembered.
- **Temporary failure:** a timeout, a refused connection, an oversized or content-encoded answer,
  or a `408`, `425`, `429` or any `5xx` status. These say the server could not answer *now*, for
  example while it restarts. At startup, `prepare()` raises `ConfigurationError` so the
  application does not take traffic, but nothing is remembered. One `WARNING` names a temporary
  status, once per verifier.

What the probe does **not** prove: that a real cookie will verify, that your secret matches, that
the server will still be up on the next request. It proves the URI and the contract, once.

Without the lifespan, the probe still runs — lazily, on the first request that gets that far. A
contract failure there is remembered permanently, and every later request raises the same
`ConfigurationError`. A temporary failure is not remembered: the request is refused with a 401
(`AuthServiceUnavailable`, or a `503` under [the `503` opt-in](errors.md#answering-503-while-the-auth-service-is-down)) and the probe is retried at most once every ten seconds, so an auth
service that comes up a moment after yours, or answers `503` while it restarts, recovers on its
own.

**What one request costs.** The order below is the design, and everything above the fetch makes zero
outbound calls by construction:

1. The cookie is resolved by name, and a structurally impossible one is refused — too long, a
   byte outside the RFC 6265 cookie-octets (such as CR, LF, a space, a comma, a quote, a backslash,
   a control byte or a non-ASCII byte), not decodable, no signature separator. So a client cannot
   put bytes of its choosing into the outbound `cookie` header.
2. The CSRF policy runs, before anything else looks at the credential, so a cross-site `403` is
   never an oracle for whether the cookie behind it is live.
3. If you configured a secret, the signature is verified locally against the keyring. A forgery
   stops here and never becomes traffic.
4. A `200`-with-`null` verdict is remembered for 30 seconds by default, keyed on the whole cookie
   value, so repeating one forged cookie costs one upstream call per window rather than one per
   request. A new value each time is not in the cache; step 3 is what stops that.
5. If upstream has recently answered `429`, the backoff latch refuses without calling it again.
6. If the readiness probe has not passed yet, it runs now (at most once per ten seconds), and the
   request is refused until it passes.
7. Only then the call, through a concurrency limiter (8 in flight by default) so one stalled auth
   service cannot park every worker task.

Then the answer is checked rather than trusted: the returned `session.token` must match the token
that was forwarded, expiry is enforced here, and bans are enforced here. Anything else — a non-200,
a timeout, a body that is not a usable session document — is a refusal, never a pass.

## The shared rate-limit bucket

Read this before Mode C sees real traffic. Better Auth rate-limits its own routes, and the way it
keys the bucket means **every user of your FastAPI service shares one bucket for `/get-session`**,
because they all reach your Node service from one address.

The mechanism, read out of better-auth 1.7.1's own build and unchanged through 1.7.5 (the limiter
module `dist/api/rate-limiter/index.mjs` and `env-impl.mjs` are byte-identical at 1.7.3 and 1.7.5;
the cited lines of `create-context.mjs` and `ip.mjs` read the same there, one and two lines lower):

- The limiter is on when you have not set `rateLimit.enabled` and `NODE_ENV === "production"`
  (`dist/context/create-context.mjs:171`, `@better-auth/core/dist/env/env-impl.mjs:30-32`) — off in
  development, on in production, which is the worst order in which to discover it.
- The default bucket is **100 requests per 10 seconds** (`dist/context/create-context.mjs:172-173`),
  and there is no built-in rule for `/get-session` (`dist/api/rate-limiter/index.mjs:302-316`), so
  the default is what applies to it.
- The key is `` `${ip}|${path}` `` (`@better-auth/core/dist/utils/ip.mjs:226-228`, built at
  `dist/api/rate-limiter/index.mjs:245`).
- The only client-IP header read by default is `x-forwarded-for`
  (`@better-auth/core/dist/utils/ip.mjs:194`, walked at `:205`), and when no address can be derived
  the key falls back to the shared sentinel `no-trusted-ip` (`dist/api/rate-limiter/index.mjs:233`,
  used at `:245`). A server-to-server call forwards no such header, so that sentinel is the bucket
  your whole deployment lands in — one bucket per path, for everybody.

In round numbers: about **ten verified requests per second across the entire deployment**, for every
request that misses this library's pre-filter and negative cache. **Nothing in this library raises
that ceiling.** The pre-filter, the cache, the concurrency limiter and the 429 latch all reduce how
often you *reach* the bucket; none of them makes it bigger. The fix is upstream configuration.
Without a configured secret, the pre-filter is only the structural check, so forged cookies reach
the bucket too; see [Configure the secret](#configure-the-secret).

**Fix 1 — exempt the route.** The whole rule value is `false`. There is no `max: false` field and no
IP allowlist:

```ts
rateLimit: { customRules: { "/get-session": false } }
```

(`dist/api/rate-limiter/index.mjs:259-276`; `if (resolved === false) return null` at `:274`.) Know
what that buys: it removes the limit for **every** caller of `/get-session` on your Node server — a
browser hitting the route directly included — not only this bridge's server-to-server traffic. If
`/get-session` should keep a ceiling, use Fix 2.

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

## Configuration

Every parameter is keyword-only. An unusable value is a `ConfigurationError` at construction.

| Name | Default | Meaning |
|---|---|---|
| `base_url` | required | The Better Auth server's origin. `http` is accepted only for a loopback host. |
| `csrf` | required | The CSRF policy. There is no default. See [CSRF](csrf.md). |
| `transport` | `None` | The HTTP client. `None` builds an `HttpxTransport` at construction, which needs the `[httpx]` extra. See [HTTP clients](http-clients.md). |
| `secret` | `None` | A `SharedSecret` for the local signature check. Recommended; see [Configure the secret](#configure-the-secret). |
| `secrets` | `None` | A list of `SharedSecret` for a rotation. At most one of `secret` and `secrets`. |
| `cookie_name` | `"better-auth.session_token"` | The cookie name without its prefix. |
| `secure_prefix` | `"__Secure-"` | The prefix read when `secure_cookies` is `True`. |
| `secure_cookies` | `True` | `True` reads only `{secure_prefix}{cookie_name}`; `False` reads only `cookie_name`. Never both. |
| `base_path` | `"/api/auth"` | The path Better Auth is mounted at; `""` for the root. |
| `concurrency` | `8` | How many `get-session` calls may be in flight at once, 1 to 256. |
| `queue_timeout` | `2.0` | Seconds to wait for a free slot before refusing. At least 0.1. |
| `negative_ttl` | `30.0` | Seconds a `200`-with-`null` answer is remembered per cookie value, 0 to 300. `0` turns the cache off. |
| `max_remembered` | `1024` | The most remembered `null` answers, 1 to 65536. |
| `max_bytes` | `65536` | The largest `get-session` body read, in bytes. |
| `refuse_unsigned_bearer` | `False` | `True` makes the probe refuse a server whose `bearer` plugin is at `requireSignature: false`. |
| `clock` | `time.monotonic` | Monotonic seconds for the caches, the backoff latch and the probe retry window. It never decides a refusal. |
| `now` | `None` | The clock for the expiry and ban checks, for tests. It can only make the verifier stricter. See [Testing](testing.md#moving-the-verifiers-clock). |
