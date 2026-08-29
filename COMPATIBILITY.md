# Compatibility

This file records what is **tested against**, not what is supported. Every row below names a lane
that runs in CI; nothing appears here because it is expected to work.

## Better Auth

The server this library bridges to. The conformance suite runs against a real Better Auth server
(Hono/Node, Postgres, Redis) started from `harness/docker-compose.yml`.

| better-auth | Lane | When |
|---|---|---|
| 1.7.1 | conformance, gating | every pull request, and every push to `main` |
| 1.6.30 | conformance, canary | weekly |
| 1.7.1 | conformance, canary | weekly |
| `latest` | conformance, canary | weekly |

The gating lane pins `better-auth@1.7.1`, so no change lands without passing against it. The canary
runs the same suite against the matrix above on a schedule and opens an issue in this repository
automatically when a version fails.

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
| `pyjwt[crypto]` | `>=2.10` |
| `anyio` | `>=4` |
| `httpx` (extra `[httpx]`) | `>=0.27` |
| `httpx2` (extra `[httpx2]`) | `>=2.0` |

## What a release of this library may change

- **Mode B (JWT / JWKS)** — semver-style. Within a major version, configuration that verified a
  token keeps verifying it, and no release narrows what is accepted except to close a security
  hole, which is a patch release with an advisory.
- **Mode A (cookie + shared session store)**, when it ships, reads Better Auth's *internal*
  formats: the signed cookie's HMAC construction and the session store's own layout. It will be
  pinned to the better-auth versions the conformance lane exercises, and an upstream change to
  either may force a change here inside a minor release. Stated now rather than discovered later.
- **Mode C (remote get-session)** — after Mode A.

Security fixes are released for the latest version only while this project is pre-1.0; see
[SECURITY.md](SECURITY.md).
