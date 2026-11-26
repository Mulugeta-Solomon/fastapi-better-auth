# Choosing a mode

After reading this page you can choose between Mode A, Mode B and Mode C for your deployment, and
know what each one can and cannot see.

## Modes

Better Auth is TypeScript-only: sign-in/up, OAuth and 2FA run on your Node service. This package
makes the sessions that service issues first-class in FastAPI. Three modes ship. They differ in
what they couple to, what a request costs, and — the row that should decide it — what they can
still see once a session goes away.

Each mode has its own page: [Mode A](mode-a-cookie.md), [Mode B](mode-b-jwt.md) and
[Mode C](mode-c-remote.md).

| | **A — cookie + shared store** | **B — JWT / JWKS** | **C — remote get-session** |
|---|---|---|---|
| **Revocation lag** | instant | ≤ token lifetime (15 min upstream default) | instant |
| **Credential** | the signed session cookie | `Authorization: Bearer <JWT>` | the signed session cookie |
| **Cost per request** | one session-store read | none — verified offline | one HTTPS call upstream, unless the local pre-filter or the negative cache answers first |
| **What it couples to** | the shared secret, the same session store, and Better Auth's internal formats (cookie HMAC + store layout) | reachability of `/api/auth/jwks`, and nothing else | network reach to your Better Auth server, its `200`-with-`null` contract, and its `{session, user}` body shape — plus the signed-cookie envelope *only* if you configure a secret |
| **CSRF** | required, no default | not applicable — a bearer credential is not sent ambiently | required, no default |
| **Expiry** | refused here, because upstream's `findSession` does not check `expiresAt` | refused: `exp`, and a ceiling on the `exp - iat` upstream would never have minted | refused upstream — the `get-session` route checks `expiresAt` and answers `null` (`dist/api/routes/session.mjs:148`) — and re-checked here |
| **Sign-out** | the very next request is `401` | invisible until the token expires | the very next request is `401` |
| **Bans** | refused here — upstream's `get-session` never reads `banned` either | invisible until the token expires | refused here, from the record upstream returns |
| **Algorithm confusion** | not applicable | refused: a pinned algorithm allowlist, and an unknown `kid` is a refusal rather than a search | not applicable |
| **Secret rotation** | a keyring, compared in constant time with no early return | upstream's own `kid` rollover | the same keyring, when you configure one |
| **Auth server down** | keeps verifying — it never calls it | keeps verifying from the cached key set for at most `max_stale` (one day by default) after its last successful fetch, then refuses (`401`) | refuses (`401`); guessing here would be the bypass |

**Two caveats behind the "Bans" row.** A ban is enforced *by this library*, from the user record it
already has, because upstream's `get-session` route never reads `banned` — the admin plugin enforces
bans when a session is **created** (`dist/plugins/admin/admin.mjs:33-49`) and deletes the user's
sessions when the ban goes through its own route (`ban-user`, `dist/plugins/admin/routes.mjs:508`,
sessions deleted at `:540`; `update-user` with `banned: true` does the same at `:305`). So a ban
written straight into the database is still caught here, in Mode A on SQL and in Mode C. It is
**not** caught when Better Auth runs with `secondaryStorage` and the ban is written straight to the
database: the session document in Redis was written before the ban and still says `banned: false`,
and that document is what both Mode A and Mode C read there. On that topology, ban through the
admin route, which deletes the user's sessions. A session key that the delete misses still says
`banned: false`. On Better Auth 1.7.16 or later the ban also writes a revocation time, and both
Better Auth and Mode A's Redis store refuse a session created before it. On an earlier Better Auth
nothing refuses such a session, so run 1.7.16 or later with `secondaryStorage`.

**Picking one.** If FastAPI can share the database or Redis your Node service writes sessions to,
Mode A is the cheapest instant revocation. If it can only reach that service over the network, that
is Mode C. If it has to verify with no dependency on the auth server being reachable at all, that
is Mode B, and the price is a revocation lag equal to the token lifetime. Modes compose — each
request picks the verifier whose credential it actually carries, and two credentials on one request
are a `400` — with one exception: **A and C read the same cookie name, so composing those two is
refused at construction.** It is a choice between modes, not a stack.

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
lifetimes short and lean on Mode A or Mode C for prompt revocation (see
[SECURITY.md](../SECURITY.md)).

Mode C looks like the easy one and has the sharpest edges, which is why the shape of the request is
fixed at construction and never derived from the one being verified. An unauthenticated
`get-session` answers **`200` with a body of literally `null`**, not a `401`, so a snippet that
checks the status code authenticates everybody. The `bearer` plugin's hook *overwrites* the session
cookie of an outgoing request with whatever `Authorization` header it sees
(`dist/plugins/bearer/index.mjs:44-46`), so a proxy that forwards
the inbound `Authorization` along with the cookie hands a client a targeted denial-of-service on one
victim, and a client who sends a raw session token an authentication this side never checked — which
is why exactly two headers, `cookie` and `accept`, ever go out. `httpx`'s default client keeps
cookies, so an auth server's `Set-Cookie` would be replayed onto the next user's verification: both
shipped transports install a dead jar and the boot probe detects a live one. And the
[shared rate-limit bucket](mode-c-remote.md#the-shared-rate-limit-bucket) is the one nobody finds
until production.
