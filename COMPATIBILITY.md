# Compatibility

This file records what is **tested against**, not what is supported. Every row below names a lane
that runs in CI; nothing appears here because it is expected to work.

## Better Auth

The server this library bridges to. The conformance suite runs against real Better Auth servers
(Hono/Node, Postgres, Redis) started from `harness/docker-compose.yml` — four of them, because two
of the behaviours this library documents are *server postures* rather than server versions, and a
posture asserted in only one direction is not asserted at all.

| better-auth | Lane | When |
|---|---|---|
| 1.7.1 | conformance, gating | every pull request, and every push to `main` |
| 1.7.1 with `secondaryStorage` (Redis) | conformance, gating | every pull request, and every push to `main` |
| 1.7.1 with `bearer({ requireSignature: true })` | conformance (strict posture), gating | every pull request, and every push to `main` |
| 1.7.1 with `rateLimit: { enabled: true, customRules: { "/get-session": { window: 10, max: 3 } } }` | conformance (throttled posture), gating | every pull request, and every push to `main` |
| 1.6.30 | conformance, canary (HEAD + published wheel) | weekly, and when better-auth publishes |
| 1.7.1 | conformance, canary (HEAD + published wheel) | weekly, and when better-auth publishes |
| `latest` | conformance, canary (HEAD + published wheel) | weekly, and when better-auth publishes |

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
sweep runs anyway rather than assuming upstream stood still. A failing version opens an issue in
this repository automatically, named for the artifact that failed.

Better Auth publishes no wire-format stability contract. Cookie signing, session-store layout and
the JWT plugin's claims are internal details, and they have moved across minor releases. That is
the whole reason the canary is weekly rather than a promise in this file: a break should reach an
issue here before it reaches your deployment.

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
  better-auth 1.7.1** — the version the conformance lane pins — verified on **2026-08-29**, and an
  upstream change to either the cookie signing or the store layout may force a change here inside a
  minor release. That coupling is stated rather than hidden: Mode C (remote `get-session`) is the
  path with less of it, because it asks the server instead of reading its internals. The stores read
  three internal shapes, all asserted against a running better-auth in the conformance lane, in both
  of its topologies: the `session` and `user` tables' column names, the secondary-storage key (the
  raw session token, with no namespace), and the JSON that key holds (`{session, user}`).
- **Mode C (remote get-session)** couples to *less*, and the honest word for it is "less", never
  "format-independent". It is **tested against better-auth 1.7.1**, verified live on
  **2026-09-05** across all four harness postures. Its dependencies are exactly these four, and
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
