# Compatibility

This file records what is **tested against**, not what is supported. Every row below names a lane
that runs in CI; nothing appears here because it is expected to work.

## Better Auth

The server this library bridges to. The conformance suite runs against real Better Auth servers
(Hono/Node, Postgres, Redis) started from `harness/docker-compose.yml` — four of them, because two
of the behaviours this library documents are *server postures* rather than server versions, and a
posture asserted in only one direction is not asserted at all.

| better-auth | Lane | When | Last green on the published wheel |
|---|---|---|---|
| 1.7.1 | conformance, gating | every pull request, and every push to `main` | — (HEAD only) |
| 1.7.1 with `secondaryStorage` (Redis) | conformance, gating | every pull request, and every push to `main` | — (HEAD only) |
| 1.7.1 with `bearer({ requireSignature: true })` | conformance (strict posture), gating | every pull request, and every push to `main` | — (HEAD only) |
| 1.7.1 with `rateLimit: { enabled: true, customRules: { "/get-session": { window: 10, max: 3 } } }` | conformance (throttled posture), gating | every pull request, and every push to `main` | — (HEAD only) |
| 1.6.30 | conformance, canary (HEAD + published wheel) | weekly, and when better-auth publishes | 0.5.0 on 2026-09-16 (run 35050080161) |
| 1.7.1 | conformance, canary (HEAD + published wheel) | weekly, and when better-auth publishes | 0.5.0 on 2026-09-16 (run 35050080161) |
| 1.7.5 | conformance, canary (HEAD + published wheel) | weekly, and when better-auth publishes | 0.5.0 on 2026-09-16 (run 35050080161, as `latest`) |
| `latest` | conformance, canary (HEAD + published wheel) | weekly, and when better-auth publishes | 0.5.0 on 2026-09-16 (run 35050080161), `latest` = 1.7.5 that day |

That list is readable from a running application as `fastapi_better_auth.VERIFIED_BETTER_AUTH` — the
canary matrix without its `latest` entry, which is a dist-tag rather than a version — and
`tests/test_verified_better_auth.py` fails if this table, the canary workflow, the harness pin and
the constant are ever edited out of sync. Its newest entry is the version `latest` resolved to when
the release was cut: the canary sweeps it as a pinned entry beside `latest`, so it stays tested after
the tag moves on, and each release moves it to whatever `latest` names that day.

The strict posture is what makes "`bearer({ requireSignature: true })` is the fix" a tested claim
rather than a reading of the source: the default-permissive server and the strict one are driven
with the same credentials and asserted to answer differently. The throttled posture is what pins the
one upstream header most likely to drift — a `429` carries `X-Retry-After` and never `Retry-After` —
against a real server rather than a scripted one. Every canary lane runs all four.

The gating lane pins `better-auth@1.7.1`, so no change lands without passing against it. The canary
runs the same suite twice against the matrix above — once from the repository HEAD, and once
against the wheel currently published on PyPI, with a guard that refuses to run unless the
library under test really is that installed wheel. It fires weekly, and again on any day a watch
of npm's registry sees a fresh better-auth release; if the watch itself cannot be answered, the
sweep runs anyway rather than assuming upstream stood still. Before any test runs, every leg reads
the better-auth version each of its four harness servers actually imports and writes it to the
run's summary; a leg named for a concrete version fails if the servers run anything else, so the
leg's name is always what it tested. A failing version on `main` opens an issue in this repository
automatically, named for the artifact that failed — and, for `latest`, for the version the tag
resolved to. A run dispatched on any other branch files nothing; its failures are for whoever
dispatched it.

Better Auth publishes no wire-format stability contract. Cookie signing, session-store layout and
the JWT plugin's claims are internal details, and they have moved across minor releases. That is
the whole reason the canary is weekly rather than a promise in this file: a break should reach an
issue here before it reaches your deployment.

The last column is written by hand from the post-release canary, never from a promise: the wheel
installed from PyPI is guard-verified to be the version named, and every posture above runs
against it. The 2026-09-07 run was the first in which the Mode C live lane executed on a published
wheel rather than on HEAD.

### Between 1.7.1 and 1.7.5

The gating lane pins 1.7.1 and the newest verified version is 1.7.5. Across that gap, three things a
deployment of this library depends on or runs into, each read out of the published packages' `dist/`
at the version cited:

- **The wire format did not move.** The session and user field definitions are byte-identical at
  1.7.1 and 1.7.5 (`@better-auth/core` `dist/db/schema/session.mjs`, `user.mjs`, `shared.mjs`), and
  so are the admin plugin's (`better-auth` `dist/plugins/admin/schema.mjs`). The Redis document is
  still the raw token as key and `JSON.stringify({ session, user })` as value (`better-auth@1.7.1`
  `dist/db/internal-adapter.mjs:303-306`, `better-auth@1.7.5` `:302-305`). Cookie signing lives in
  the peer package `better-call`, which both versions pin exactly to `1.4.0` (`package.json:470` in
  each), and every cookie-mode leg ran green against 1.7.5 (run 35050080161, as `latest`).
- **Schema validation is on by default from 1.7.3**, in every environment, unless
  `advanced.database.validateSchema` is `false` (`@better-auth/core@1.7.5`
  `dist/db/schema-check.mjs:4-9`; the option at `dist/types/init-options.d.mts:391-400`; neither
  exists at 1.7.1). Drift is not a boot failure: the check at init only logs (`better-auth@1.7.5`
  `dist/auth/base.mjs:15-18`), but every HTTP request awaits it (`dist/api/index.mjs:169-170`), so
  does every `auth.api.*` call (`dist/api/to-auth-endpoints.mjs:41-42`), and a mismatch is kept and
  rethrown without asking the database again (`@better-auth/core@1.7.5`
  `dist/db/schema-check.mjs:60-77`) until Better Auth's own migrator clears it (`better-auth@1.7.5`
  `dist/db/get-migration.mjs:668`, the only call site in either package). So the server starts, logs
  one error and fails every auth request, and a schema repaired by another tool is not seen until
  that process restarts. A database migrated under 1.7.1 meets this on upgrade: it keeps
  `account.issuer`, required and uniquely indexed (`@better-auth/core@1.7.1`
  `dist/db/get-tables.mjs:200-209`, created `NOT NULL` by `better-auth@1.7.1`
  `dist/db/get-migration.mjs:607` and `:635`), which 1.7.3 and 1.7.5 no longer define; a required
  column Better Auth never writes is a finding like a missing one (`@better-auth/core@1.7.5`
  `dist/db/schema-diff.mjs:47-53`), the Kysely adapter's check returns every finding
  (`@better-auth/kysely-adapter@1.7.5` `dist/index.mjs:250-261`, registered at `:712`) and any
  finding throws (`schema-check.mjs:70`), so every auth request fails until you follow the
  [1.7 upgrade guide](https://www.better-auth.com/docs/guides/1-7-upgrade-guide) — the link the
  error message itself gives for this column, to follow before removing it
  (`dist/db/schema-diff.mjs:81`). A deployment that owns its migrations (the README's "Who owns the
  database schema") runs its drift check before the deploy, not after it.
- **The rate limiter's client identity did not move.** `dist/api/rate-limiter/index.mjs` is
  byte-identical at 1.7.1, 1.7.3 and 1.7.5. `x-forwarded-for` is still the one header read by default
  (`@better-auth/core@1.7.1` `dist/utils/ip.mjs:194`, `@1.7.5` `:196`); a single-value header is
  trusted with no configuration, and a multi-hop chain needs `advanced.ipAddress.trustedProxies`
  (`@1.7.5` `:180-190`). A request with no usable address still keys on the shared `no-trusted-ip`
  bucket (`rate-limiter/index.mjs:233`, `:245`), and the warning about it fires once per process, on
  the first such request while the limiter is on, never at boot (`:241-244`, `:290`). The README's
  "The shared rate-limit bucket" holds at 1.7.5 as written.

## Python

| Python | Lane |
|---|---|
| 3.10 | unit (Linux), and the declared-floors lane below |
| 3.11 | unit (Linux) |
| 3.12 | unit (Linux) |
| 3.13 | unit (Linux, macOS, Windows), and pyright strict |
| 3.14 | unit (Linux) |
| 3.15 pre-release | unit, advisory only — a failure here never blocks a merge |

`requires-python` is `>=3.10`.

## Dependency floors

Declared in `pyproject.toml` and *installed* by one lane — `unit (declared floors, py3.10)`
resolves every direct dependency to its declared minimum, because every other lane installs the
lockfile and would never exercise a floor.

| Requirement | Floor |
|---|---|
| `fastapi` | `>=0.133` |
| `starlette` | `>=1.3.1` |
| `pydantic` | `>=2.7` |
| `pyjwt[crypto]` | `>=2.12.0` (CVE-2026-32597; `crit` is refused regardless) |
| `anyio` | `>=4.1` |
| `httpx` (extra `[httpx]`) | `>=0.27` |
| `httpx2` (extra `[httpx2]`) | `>=2.0` |
| `sqlalchemy[asyncio]` (extra `[sqlalchemy]`) | `>=2.0` |
| `redis` (extra `[redis]`) | `>=5.0.1` |

The two store extras are what `SqlAlchemySessionStore` / `SyncStoreAdapter` and
`RedisSessionStore` need; neither is imported unless one of those is constructed, so an install
with neither still imports the package and every published name. `sqlalchemy` needs a driver of
its own — `asyncpg` and `psycopg` are what the conformance lane and the docs use. `redis`'s floor
is `5.0.1` rather than `5.0` because `aclose()` arrived there, and the deprecated `close()` it
replaced emits a warning this project treats as an error.

A database driver is deliberately *not* a floor of ours: which one a deployment uses is its own
decision, and pinning one here would be this library choosing it.

`anyio`'s floor moved from `>=4` to `>=4.1` with the stores. `SyncStoreAdapter` is the first thing
here to call `anyio.to_thread.run_sync`, and anyio 4.0's Trio backend passes a `cancellable=`
argument Trio removed in 0.23 — so on Trio it raises `TypeError` rather than running the query.
The floor-resolution lane is what found it.

## What a release of this library may change

- **Mode B (JWT / JWKS)** — semver-style. Within a major version, configuration that verified a
  token keeps verifying it, and no release narrows what is accepted except to close a security
  hole, which is a patch release with an advisory.
- **Mode A (cookie + shared session store)** reads Better Auth's *internal* formats: the signed
  cookie's HMAC construction and the session store's own layout. It is **tested against
  better-auth 1.7.1** — the version the conformance lane pins — verified on **2026-09-16**, and an
  upstream change to either the cookie signing or the store layout may force a change here inside a
  minor release. That coupling is stated rather than hidden: Mode C (remote `get-session`) is the
  path with less of it, because it asks the server instead of reading its internals. The stores read
  three internal shapes, all asserted against a running better-auth in the conformance lane, in both
  of its topologies: the `session` and `user` tables' column names, the secondary-storage key (the
  raw session token, with no namespace), and the JSON that key holds (`{session, user}`).
- **Mode C (remote get-session)** couples to *less*, and the honest word for it is "less", never
  "format-independent". It is **tested against better-auth 1.7.1**, verified live on
  **2026-09-16** across all four harness postures. Its dependencies are exactly these four, and
  each is asserted in the conformance lane:
  1. **The 200-null contract** — `GET /api/auth/get-session` answers `200` with a body of literally
     `null` for a request that carries no valid session, rather than a `401`. The boot probe asserts
     it, and a server wired through `auth.lifespan` does not start if it does not hold.
  2. **The `{session, user}` body shape** of an authenticated answer, and `session.token` within it
     matching the token that was forwarded.
  3. **The `disableCookieCache` and `disableRefresh` query parameters**, which are what make the
     read authoritative and read-only. Both are pinned into the request and neither is configurable.
  4. **Only if you configure a secret**, the signed-cookie envelope — the same coupling Mode A has,
     bought deliberately to refuse forgeries locally. Without a secret Mode C reads no envelope, no
     store, no database and no shared secret at all.

  What it does *not* read: the session store, the store topology, the database schema, or Better
  Auth's ID format (the token's alphabet and length are operator-overridable upstream, so nothing
  here pins them). An upstream change to the cookie HMAC or the store layout does not reach Mode C
  unless you configured a secret; a change to the `get-session` contract does, and that is what the
  weekly canary exists to catch.

Security fixes are released for the latest version only while this project is pre-1.0; see
[SECURITY.md](SECURITY.md).
