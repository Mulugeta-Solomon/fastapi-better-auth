# Conformance harness

A real, version-pinned Better Auth server (`better-auth@1.7.1` on Hono/Node) with Postgres and
Redis. The e2e lane runs against it to prove the wire-format invariants this library depends on —
compatibility is tested, never assumed. `auth-server/` is also the reference implementation of the
"tiny Node sidecar" topology from the main README.

## Run

```bash
docker compose -f harness/docker-compose.yml --profile redis up --build -d --wait
uv run pytest -m e2e
```

The auth container migrates the schema (Better Auth CLI), seeds its users, and serves on
`http://localhost:3100` (`/healthz` for readiness). Dropping `--profile redis` starts only the
default topology; the store conformance tests then skip their Redis half.

## Services

| Service | Port | Notes |
|---|---|---|
| `auth` | 3100 | Sessions in Postgres (default topology) |
| `auth-redis` | 3101 | `--profile redis`: sessions in Redis secondary storage — the Postgres session table may stay empty |
| `postgres` | 55432 | Exposed for vector capture and session manipulation in tests |
| `redis` | 56379 | Used only by the `redis` profile |

Both auth containers run `auth migrate` against the same database on start, so `auth-redis`
waits for `auth` to be healthy rather than racing it.

## Seeded users

| Email | Password | Role |
|---|---|---|
| `seed@example.com` | `seed-password-123` | (default) |
| `admin@example.com` | `admin-password-123` | `admin` |

The admin role is set with a direct `UPDATE` in the seed, because the admin plugin offers no
endpoint that grants the *first* admin — every one of them is gated on an existing admin.

## Plugins

`jwt()`, `bearer()` and `admin()`. The last is what creates `banned` / `banReason` /
`banExpires` on `user` and `impersonatedBy` on `session`; without it those columns do not exist,
which is a supported deployment and one the stores are tested against too. Enabling it does not
touch the session cookie's wire format, so the golden vectors in `tests/vectors/` are unaffected.

Better Auth refuses a state-changing POST that carries no `Origin` header
(`MISSING_OR_NULL_ORIGIN`), and `sign-out` additionally requires a JSON content type — see the
helpers in `tests/e2e/conftest.py`.

The `BETTER_AUTH_SECRET` here is a fixed, published test value — never reuse it anywhere real.
