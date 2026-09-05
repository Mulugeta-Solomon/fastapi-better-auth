# Conformance harness

A real, version-pinned Better Auth server (`better-auth@1.7.1` on Hono/Node) with Postgres and
Redis. The e2e lane runs against it to prove the wire-format invariants this library depends on —
compatibility is tested, never assumed. `auth-server/` is also the reference implementation of the
"tiny Node sidecar" topology from the main README.

## Run

```bash
docker compose -f harness/docker-compose.yml --profile redis --profile strict --profile throttled up --build -d --wait
uv run pytest -m e2e
```

The auth container migrates the schema (Better Auth CLI), seeds its users, and serves on
`http://localhost:3100` (`/healthz` for readiness). Every profile is optional: drop one and the
legs that need it skip with a reason naming the profile (in CI they fail instead, because a lane
that silently tested nothing is worse than a red one).

## Services

| Service | Port | Notes |
|---|---|---|
| `auth` | 3100 | Sessions in Postgres (default topology) |
| `auth-redis` | 3101 | `--profile redis`: sessions in Redis secondary storage — the Postgres session table may stay empty |
| `auth-strict` | 3102 | `--profile strict`: `bearer({ requireSignature: true })` |
| `auth-throttled` | 3103 | `--profile throttled`: a real rate limit on `/get-session` (3 per 10 s) |
| `postgres` | 55432 | Exposed for vector capture and session manipulation in tests |
| `redis` | 56379 | Used only by the `redis` profile |

Every auth container runs `auth migrate` against the same database on start, so the three optional
ones wait for `auth` to be healthy rather than racing it.

### The two postures

Both are driven by an environment variable `src/auth.mjs` reads, and both default **off**, so
`auth` and `auth-redis` keep exactly the posture every existing test pins.

- `BEARER_REQUIRE_SIGNATURE=1` → `bearer({ requireSignature: true })`. The default is `false`,
  which means upstream self-signs a *raw session token* presented as `Authorization: Bearer`, so
  a token in a log or a dump is a credential. `:3102` is what turns the one-line fix this library
  advises into a tested fact, in both directions — including the `Set-Cookie` discriminator the
  advisory boot probe reads.
- `RATE_LIMIT_GET_SESSION_MAX=3` → `rateLimit: { enabled: true, customRules: { "/get-session":
  { window: 10, max: 3 } } }`. `enabled` is set **explicitly**: upstream defaults it to
  `NODE_ENV === "production"`, and setting `NODE_ENV` would also flip the session cookie to its
  `__Secure-` name over http, which would make `:3103` a different server rather than the same
  one under a rate limit. Upstream answers a refused request `429` with **`X-Retry-After`** in
  whole seconds — not the standard `Retry-After` — which is exactly what the live 429 leg pins.

## Seeded users

| Email | Password | Role |
|---|---|---|
| `seed@example.com` | `seed-password-123` | (default) |
| `admin@example.com` | `admin-password-123` | `admin` |

The admin role is set with a direct `UPDATE` in the seed, because the admin plugin offers no
endpoint that grants the *first* admin — every one of them is gated on an existing admin.

## Plugins

`jwt()`, `bearer({ requireSignature })` and `admin()`. The last is what creates `banned` / `banReason` /
`banExpires` on `user` and `impersonatedBy` on `session`; without it those columns do not exist,
which is a supported deployment and one the stores are tested against too. Enabling it does not
touch the session cookie's wire format, so the golden vectors in `tests/vectors/` are unaffected.

Better Auth refuses a state-changing POST that carries no `Origin` header
(`MISSING_OR_NULL_ORIGIN`), and `sign-out` additionally requires a JSON content type — see the
helpers in `tests/e2e/conftest.py`.

The `BETTER_AUTH_SECRET` here is a fixed, published test value — never reuse it anywhere real.
