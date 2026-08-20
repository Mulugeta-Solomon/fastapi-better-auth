# Conformance harness

A real, version-pinned Better Auth server (`better-auth@1.7.1` on Hono/Node) with Postgres and
Redis. The e2e lane runs against it to prove the wire-format invariants this library depends on —
compatibility is tested, never assumed. `auth-server/` is also the reference implementation of the
"tiny Node sidecar" topology from the main README.

## Run

```bash
docker compose -f harness/docker-compose.yml up --build -d
uv run pytest -m e2e
```

The auth container migrates the schema (Better Auth CLI), seeds `seed@example.com` /
`seed-password-123`, and serves on `http://localhost:3100` (`/healthz` for readiness).

## Services

| Service | Port | Notes |
|---|---|---|
| `auth` | 3100 | Sessions in Postgres (default topology) |
| `auth-redis` | 3101 | `--profile redis`: sessions in Redis secondary storage — the Postgres session table may stay empty |
| `postgres` | 55432 | Exposed for vector capture and session manipulation in tests |
| `redis` | 56379 | Used only by the `redis` profile |

The `BETTER_AUTH_SECRET` here is a fixed, published test value — never reuse it anywhere real.
