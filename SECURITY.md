# Security Policy

## Reporting a vulnerability

Please report vulnerabilities **privately** via GitHub's *Report a vulnerability* button
(Security tab of this repository). Do not open public issues for security problems.

- Acknowledgement target: within 72 hours.
- Coordinated disclosure: we will agree on a timeline with you; default is disclosure after a fix
  is released, or 90 days, whichever comes first.

## Supported versions

Pre-1.0: only the **latest released version** receives fixes.

## Better Auth compatibility floor

This library bridges to a Better Auth (TypeScript) server you operate. Run **Better Auth 1.4.9 or
newer**: earlier versions are affected by CVE-2026-67337, a critical 2FA bypass via the
`session_data` cookie cache. This library never reads that cookie and warns once if it sees one,
but it cannot patch the server side — keeping your Better Auth server current is part of your
deployment's security posture. The versions each release is verified against are listed in
[COMPATIBILITY.md](COMPATIBILITY.md).

## Dependency floors

The declared lower bounds are security floors, not merely API floors. In particular `PyJWT` is
required at **2.12.0 or newer** (CVE-2026-32597: unknown `crit` header extensions were accepted),
and independently of the installed version this library refuses any token that declares a `crit`
header at all, because Better Auth never emits one and no extension is supported here.

## What this library trusts, and what it does not

- **Your configuration.** `base_url`, the shared secret, the session store and the CSRF
  allowlist are trusted as given. Nothing is ever read from the incoming request to decide who
  the auth server is (no `Host`, no `X-Forwarded-*`, no `request.url`).
- **The process environment, through the HTTP client it builds.** When you do not inject a
  client, the default `httpx`/`httpx2` client honours the standard environment: `HTTP_PROXY`,
  `HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`/`SSL_CERT_DIR` and `~/.netrc`. Whoever can set those
  can route or re-trust the JWKS fetch and Mode C's `get-session` call — the same party who can set
  `BETTER_AUTH_URL`. If your process must not honour them, inject your own client:
  `JwtVerifier(..., transport=HttpxTransport(client=httpx.AsyncClient(trust_env=False)))`, and the
  same for `RemoteVerifier`. An injected client with TLS verification disabled is likewise your
  explicit choice; the library does not inspect it.
- **An upstream `Set-Cookie` is never stored or replayed** (the client's cookie jar is disabled on
  construction, for owned and injected clients alike). It matters most in Mode C, whose transport
  talks to a server that sets session cookies: a jar that kept one would replay it on a later
  request and answer a cookie-less one as a logged-in user, so `RemoteVerifier`'s boot probe checks
  for exactly that — a session document coming back from a request that carried no cookie — and
  refuses to start if it finds it.

## Behaviours worth knowing before you deploy

- **Refusals are uniform on the wire.** Every rejected credential answers the same 401 body; the
  reason lives only on the exception's `.reason` and in your logs. Timing is not uniform by design:
  a cookie whose signature does not verify is refused before the session store is consulted, so
  the store is never a lever for unauthenticated traffic.
- **Match `secure_cookies` to what your server actually sets.** `CookieVerifier` reads exactly one
  cookie name: the `__Secure-`-prefixed one when `secure_cookies=True` (the default, and Better
  Auth's own production default), or the plain name when `False` — set `False` for a dev/HTTP
  deployment on the plain name. It never reads both at once: accepting the plain and the prefixed
  name together let a sibling subdomain plant the *other* name and be authenticated as itself, a
  cross-name session fixation. Prefer `secure_prefix="__Host-"` where you can harden Better Auth to
  emit `__Host-` cookies — `__Host-` is the only prefix a sibling subdomain cannot set; `__Secure-`
  does not stop one. The residual same-name risk is bounded: CSRF is required in cookie mode and
  covers every state-changing request, so a planted same-name cookie is at worst a read-only
  exposure or the duplicate-cookie lockout below, never a silent takeover of writes.
- **Duplicate session cookies are refused, not resolved.** A sibling subdomain that plants a
  cookie of the same name locks the victim out of this API until that cookie is gone — a denial
  of service, never a login as someone else. Better Auth uses the `__Secure-` prefix, which does
  not prevent this; only a `__Host-` cookie would, and that is an upstream choice.
- **Bans are enforced locally and fail closed.** A stored `banned` value that is not `true`,
  `false` or absent is treated as banned; a store that hands the verifier a malformed record is a
  refusal, never an exception.
- **Bans take effect immediately in the cookie modes, not in JWT mode.** `CookieVerifier` reads the
  session store on every request and `RemoteVerifier` asks the Better Auth server on every request
  that misses its local pre-filter, so a ban — or a sign-out — is enforced the instant that source
  reflects it. `JwtVerifier` has no store and verifies a bearer token offline against the JWKS, so
  it cannot see a ban (exactly as upstream's own `get-session` cannot): a banned user keeps access
  through a still-valid JWT until it expires. If you compose the two modes, a bearer token is a
  window of continued access after a ban. Keep `max_token_lifetime` — and your upstream token
  lifetime — short, and do not rely on Mode B alone for prompt revocation.
- **On `secondaryStorage`, ban through the admin route, not through the database.** Better Auth's
  `get-session` never reads `banned` at all; every mode here enforces bans from the user record it
  is handed. When Better Auth runs with `secondaryStorage`, that record is the session document
  written to Redis at sign-in, so a ban written straight into the database is invisible to Mode A
  and Mode C alike — the document still says `banned: false` and stays that way until the session
  ends. The admin plugin's own ban route deletes the user's sessions, which every mode sees at once;
  that is the path to use. On a SQL topology the record is read live and a database-direct ban is
  caught. Verified live against better-auth 1.7.1 in both topologies.
- **Mode C forwards one cookie and nothing else.** The outbound request is built at construction —
  a fixed URI, and exactly two headers, `cookie` and `accept`. The inbound `Authorization`, `Origin`,
  `Host` and `X-Forwarded-*` headers are never forwarded, and this is not tidiness: the `bearer`
  plugin's hook overwrites the outgoing session cookie with whatever `Authorization` it sees, so a
  bridge that forwarded it would let a client turn any victim's cookie into a `200 null` (a targeted
  denial of service) or authenticate a raw token this side never extracted, never CSRF-checked and
  never pre-filtered. An auth server that cannot be reached is a `401`, never a pass.
- **Traceback hygiene.** Every frame of this library that holds a raw credential drops it before a
  refusal propagates, so an error reporter that captures frame locals finds nothing. If you write
  your own `Verifier`, `SessionStore` or `CsrfPolicy`, the frames you own are yours to scrub the
  same way — the library cannot reach into them.

## Deployment hazards this library cannot fix

Two properties of a Better Auth deployment are decided on the server, and no configuration on this
side changes either of them. They are stated here rather than in a footnote because both are easy to
carry into production without noticing.

- **A raw session token is a bearer credential in the `bearer` plugin's default posture.**
  `requireSignature` defaults to `false`, and while it is false, a raw unsigned session token
  presented as `Authorization: Bearer <token>` is signed by the server with its own secret and
  installed as the session cookie — it authenticates. A session token in a log line, a database
  dump, a backup or an error report is therefore a credential, and every place your system writes
  one down inherits the blast radius of the session it names. **The fix is upstream and is one
  line: `bearer({ requireSignature: true })`.** This library cannot fix it. What it does do is
  notice: alongside its boot probe, `RemoteVerifier` sends one request carrying a manufactured
  random token and reads nothing but whether a `set-cookie` header came back — the permissive
  posture emits one, the strict posture does not — and logs a single warning naming the fix. It is
  advisory only. It never refuses, never reads that header's value, and never replays a real
  credential; a verifier that refused to start over a server-side option would be this library
  overruling an operator, and a runtime probe that replayed a live token to test the posture would
  be this library forging a request on a user's behalf.
- **Mode C's verification traffic shares one upstream rate-limit bucket.** Better Auth keys its
  limiter on `` `${ip}|${path}` ``, reads only `x-forwarded-for` by default, and falls back to the
  shared sentinel `no-trusted-ip` when it can derive no address — which is exactly what a
  server-to-server call produces. So every user of your FastAPI service shares one bucket for
  `/get-session`: about **100 requests per 10 seconds for the whole deployment**, and the limiter is
  on by default precisely where it matters (`rateLimit.enabled` defaults to `NODE_ENV ===
  "production"`). This library's negative cache, optional local pre-filter, concurrency limiter and
  `429` backoff latch all reduce how often the bucket is reached and **none of them raises it**; a
  library that could raise it would be a library that could disable your rate limiting. The fix is
  upstream configuration — exempt or raise the rule for `/get-session`, or run Mode A or Mode B,
  which make no upstream call per request. README.md carries the exact config and the source
  citations. Note also that upstream answers a refusal with `X-Retry-After`, not `Retry-After`;
  a monitor watching for the standard header will not see these.

## Maintainer inactivity policy

If the maintainer is unresponsive to a reported vulnerability for 90 days, this project should be
considered unmaintained: a banner will be added to the README (by the maintainer returning, or via
PR by any credible reporter referencing this policy), and users should migrate.
