# Changelog

After reading this page you know what changed in each release of `fastapi-better-auth-bridge`,
and what you have to change when you upgrade.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project is
pre-1.0, so a minor release may change behaviour; each such change is listed under "Upgrade
notes". The full release notes for each version are on the
[GitHub releases page](https://github.com/Mulugeta-Solomon/fastapi-better-auth/releases).

## [Unreleased]

Merged on `main` since 0.6.0, not yet on PyPI.

### Upgrade notes

- **PyJWT 2.15.0 or newer is required** (was 2.12.0). A project that pins an older PyJWT no longer
  resolves.
- **Mode B no longer uses a stale key set forever.** When refreshing the key set fails,
  `JwtVerifier` keeps using the set it has for at most `max_stale` seconds after its last
  successful fetch (default 86400, one day). After that, every token is refused as
  `AuthServiceUnavailable` until a refresh succeeds.
- **Mode B: `cache_ttl` above 86400 now needs an explicit `max_stale`** at least as large.
  Without it, `JwtVerifier(...)` raises `ConfigurationError`.
- **Mode C treats a `408`, `425`, `429` or `5xx` answer to its readiness probe as temporary.**
  Before, any non-`200` answer was remembered as a permanent configuration failure, so a probe that
  hit a restarting auth server failed every request until the process restarted. Now the request
  is refused as `AuthServiceUnavailable`, one `WARNING` is logged, and the probe is retried on its
  ten-second window. At startup, `prepare()` still raises, but nothing is remembered.
- **Mode C refuses a cookie whose value is not all RFC 6265 cookie-octets** (for example CR, LF, a
  space, a comma, a quote, a backslash, a control byte or a non-ASCII byte). It is answered with the
  same `401` as a malformed cookie, and nothing is sent upstream. Better Auth's own cookies always
  pass.
- **The SQL stores read integer and uuid id columns.** With
  `advanced.database.generateId: "serial"` or `"uuid"`, every session used to read as unusable, so
  every request was a `401`. Ids are now handed on as text: decimal digits, or lowercase
  hyphenated uuids.
- **Mode A refuses a request whose store lookups take longer than 5 seconds together.** Before, a
  request waited for as long as the store did. Pass `CookieVerifier(lookup_timeout=...)` to change
  the limit, or `None` for no limit. Keep it well above the time a new database connection takes,
  and set a statement timeout on the server that is shorter than it. See
  [When the database does not answer](docs/stores.md#when-the-database-does-not-answer).
- **The `[sqlalchemy]` extra needs SQLAlchemy 2.0.24 or newer** (was 2.0). Older releases cannot
  cancel a statement on the server when its lookup is cancelled. A project that pins an older
  SQLAlchemy no longer resolves.

### Added

- `Session.id`: the session's own id. Set from the stored session in Mode A and from the
  `get-session` answer in Mode C; always `None` in Mode B. (#84, PR #90)
- `Session.cookie`: the `(name, value)` pair the verifier accepted, in Modes A and C. The value is a
  `SecretStr`. (#83, PR #90)
- `Session.origin`: the `allowed_origins` entry the CSRF check matched, on unsafe methods and
  WebSocket handshakes under `OriginCheck` or `SignedDoubleSubmit`. (#85, PR #90)
- `StoredSession.id`: a new optional field for stores, default `None`. (PR #90)
- `RemoteVerifier.secure_prefix`: a public property, as `CookieVerifier` already had. (PR #90)
- `now=` on `CookieVerifier` and `RemoteVerifier`: the clock the expiry and ban checks read, for
  tests. It can only make a verifier stricter. (#82, PR #89)
- `max_stale=` on `JwtVerifier`, default 86400 seconds. (PR #110)
- `lookup_timeout=` on `CookieVerifier`, default 5.0 seconds, and the `lookup_timeout` property.
  (PR #112)

### Changed

- Mode B: when the cached key set is past `cache_ttl` but still within `max_stale`, and holds the
  token's key, one request refreshes it and the others are answered from the cached set at once
  instead of waiting. (PR #110)
- Mode B: one key in the key set that will not load is skipped with a `WARNING` naming its `kid`,
  instead of refusing the whole set. A set in which no key loads is still refused. (PR #110)
- `uv.lock` updated to current releases; the build backend `uv_build` and the required uv version
  are pinned to the 0.13 line. (PR #107)

### Fixed

- Mode B: an `exp`, `iat` or `nbf` that is a bool, a string, `Infinity`, `NaN` or an integer too
  large for a float is refused with the uniform `401`. Before, some of these raised
  `OverflowError` out of the verifier. (PR #110)
- Mode C: a transient probe status is no longer remembered as a configuration failure; see Upgrade
  notes. (PR #109)
- SQL stores: integer and uuid ids; see Upgrade notes. (PR #111)
- `SqlAlchemySessionStore`: a lookup that was cancelled, by a client disconnect or by the new
  limit, left its statement running on the server and cut its connection. While the database
  hung, each such lookup added one more connection on the server, past the pool's size. The
  statement is now cancelled on the server and the store stays within the engine's pool. (PR #112)
- `SyncStoreAdapter`: a cancelled lookup no longer gives back its place in `max_concurrency` while
  its thread is still running, so the adapter cannot run more threads than its limit. (PR #112)

### Security

- PyJWT floor raised to 2.15.0, so no release before PyJWT's 2.14.0 security release can be
  installed. (#92, PR #107)
- Mode C: a client can no longer put bytes outside the cookie-octets into the outbound `cookie`
  header. (PR #109)
- Mode B: a key the auth server withdrew stops verifying within `max_stale`, even while the key set
  cannot be fetched. (PR #110)

### Project

- A release reaches PyPI only from a tag whose commit is on `main`, and only after the whole test
  workflow, the live conformance lane included, has passed for that commit. (PR #108)
- The conformance harness publishes its ports on `127.0.0.1` only, and each port can be moved with
  a `HARNESS_*_PORT` variable. (PR #108)
- Every CI job has a time limit, and a test that runs for three minutes prints where it is.
  (PR #112)

### Documentation

- The README is now a short front page. Everything else moved to `docs/`, one page per subject, and
  every Python example there is run by the test suite.
- New: this changelog, `CONTRIBUTING.md`, a configuration table on each mode page, and a
  troubleshooting page.

## [0.6.0] - 2026-09-25

### Security

- SECURITY.md corrected: a same-name cookie planted by a sibling subdomain can sign a signed-out
  victim in as the attacker (login CSRF). Neither `OriginCheck`, `SignedDoubleSubmit` nor the
  signature stops it; a `__Host-` session cookie does. SECURITY.md now also states exactly which
  requests CSRF covers. (#72, PR #79)
- No refusal carries the exception it replaced on `__context__`. (PR #81)

### Added

- `AuthorizationRefused`: a `403` or `404` that an authorization rule raises to explain itself.
  (#71, PR #76)
- `SqlAlchemySessionStore` and `SyncStoreAdapter` log one `WARNING` per kind of lookup failure,
  naming the driver error class and SQLSTATE. `CookieVerifier` reports failures of any store the
  same way. (#68, PR #77)

### Changed

- An application's only cookie scheme is published under the OpenAPI key `BetterAuthCookie`. A
  committed OpenAPI snapshot regenerates once. (#70, PR #75)
- Under `secure_cookies=True`, the published cookie scheme names the `__Secure-` cookie the
  verifier reads. Two verifiers that accept the same cookie through different settings are now
  refused at construction. (PR #80)
- `VERIFIED_BETTER_AUTH` is `("1.6.30", "1.7.1", "1.7.5", "1.7.6")`. (#66, PR #78)
- A missing HTTP client is a clearer `ConfigurationError`. (#65, PR #77)

## [0.5.0] - 2026-09-16

### Added

- `VERIFIED_BETTER_AUTH`: the Better Auth versions the release is tested against, readable at
  runtime. (#53, PR #61)
- `user_columns=` and `session_columns=` on `SqlAlchemySessionStore` and `SyncStoreAdapter`: name
  the extra columns a shared table may hand a verified session. (#49, PR #60)

### Documentation

- Your own error envelope, the testing override, deploying across two origins, and the two-sided
  secret fingerprint. (PR #59, PR #61)

## [0.4.0] - 2026-09-09

### Added

- `AdminUser`, for the columns the admin plugin adds. (#42, PR #56)
- `Session.impersonated_by`. (#42, PR #56)
- `BetterAuth.require` and `BetterAuth.require_membership`, with `Membership` and `NotAuthorized`.
  (#47, PR #55)
- `RemoteVerifier(refuse_unsigned_bearer=True)`. (#46, PR #54)
- A `WARNING` once per model when a user model declares a required field the payload does not
  carry. (#43, PR #56)

## [0.3.0] - 2026-09-07

The first release after the 2026-09-05 security audit. 0.2.0 is the pre-audit build; upgrade from
it.

### Added

- Mode C: `RemoteVerifier`, which forwards the session cookie to Better Auth's `get-session`
  route.
- `BetterAuth.startup()`, `BetterAuth.lifespan` and the `PreparedVerifier` protocol.
- Mode C's readiness probe and the advisory `requireSignature` check.

### Security

- Refusals no longer leave the presented credential in traceback frame locals.
- `CookieVerifier` reads exactly one cookie name, chosen with `secure_cookies=`.
- Tokens that declare a `crit` header are refused. PyJWT floor raised to 2.12.0
  (CVE-2026-32597).
- A `banned` value that is not `true`, `false` or absent is a refusal.
- Two `Origin` or two `Authorization` headers on one request are refused.
- JWKS keys with `use` other than `sig`, a `key_ops` without `verify`, or RSA under 2048 bits are
  skipped.
- Both HTTP transports install a dead cookie jar.

## [0.2.0] - 2026-08-29

### Added

- Mode A: `CookieVerifier`, with the `SessionStore` protocol, `SqlAlchemySessionStore`,
  `SyncStoreAdapter` and `RedisSessionStore`.
- Required CSRF policies: `OriginCheck`, `SignedDoubleSubmit` and `CsrfDisabled`.
- Secret rotation with `secrets=[...]`.

## [0.1.0] - 2026-08-29

### Added

- Mode B: `JwtVerifier`, verifying Better Auth JWT-plugin tokens against `/api/auth/jwks`.
- `BetterAuth` with `current_session()` and `optional_session()`, `BetterAuth.from_env()`, and
  `SharedSecret`.

## [0.0.1] - 2026-08-20

Name reservation on PyPI. Not usable.

[Unreleased]: https://github.com/Mulugeta-Solomon/fastapi-better-auth/compare/v0.6.0...main
[0.6.0]: https://github.com/Mulugeta-Solomon/fastapi-better-auth/releases/tag/v0.6.0
[0.5.0]: https://github.com/Mulugeta-Solomon/fastapi-better-auth/releases/tag/v0.5.0
[0.4.0]: https://github.com/Mulugeta-Solomon/fastapi-better-auth/releases/tag/v0.4.0
[0.3.0]: https://github.com/Mulugeta-Solomon/fastapi-better-auth/releases/tag/v0.3.0
[0.2.0]: https://github.com/Mulugeta-Solomon/fastapi-better-auth/releases/tag/v0.2.0
[0.1.0]: https://github.com/Mulugeta-Solomon/fastapi-better-auth/releases/tag/v0.1.0
[0.0.1]: https://github.com/Mulugeta-Solomon/fastapi-better-auth/releases/tag/v0.0.1
