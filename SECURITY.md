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
  can route or re-trust the JWKS fetch — the same party who can set `BETTER_AUTH_URL`. If your
  process must not honour them, inject your own client:
  `JwtVerifier(..., transport=HttpxTransport(client=httpx.AsyncClient(trust_env=False)))`.
  An injected client with TLS verification disabled is likewise your explicit choice; the library
  does not inspect it.
- **Upstream `Set-Cookie` on the JWKS response is never stored or replayed** (the client's cookie
  jar is disabled on construction, for owned and injected clients alike).

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
- **Bans take effect immediately in cookie mode, not in JWT mode.** `CookieVerifier` consults the
  session store on every request, so a ban — or a sign-out — is enforced the instant the store
  reflects it. `JwtVerifier` has no store and verifies a bearer token offline against the JWKS, so
  it cannot see a ban (exactly as upstream's own `get-session` cannot): a banned user keeps access
  through a still-valid JWT until it expires. If you compose the two modes, a bearer token is a
  window of continued access after a ban. Keep `max_token_lifetime` — and your upstream token
  lifetime — short, and do not rely on Mode B alone for prompt revocation.
- **Traceback hygiene.** Every frame of this library that holds a raw credential drops it before a
  refusal propagates, so an error reporter that captures frame locals finds nothing. If you write
  your own `Verifier`, `SessionStore` or `CsrfPolicy`, the frames you own are yours to scrub the
  same way — the library cannot reach into them.

## Maintainer inactivity policy

If the maintainer is unresponsive to a reported vulnerability for 90 days, this project should be
considered unmaintained: a banner will be added to the README (by the maintainer returning, or via
PR by any credible reporter referencing this policy), and users should migrate.
