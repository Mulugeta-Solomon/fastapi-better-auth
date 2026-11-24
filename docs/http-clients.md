# HTTP clients

After reading this page you can choose the HTTP client that Mode B and Mode C use to reach your
Better Auth server, and control its proxy, TLS and timeout settings.

Python 3.10+. The distribution is `fastapi-better-auth-bridge` — the shorter spelling collides with
an unrelated package under PyPI's name-similarity rules — and the import is `fastapi_better_auth`.
The two modes that talk to your Better Auth server — `JwtVerifier` for the key set, `RemoteVerifier`
for `get-session` — do it through a pluggable `Transport`: pick the adapter for the client your
project already has, or install neither extra and pass your own `Transport`. Mode A never calls
the Better Auth server and needs no HTTP client.

| Extra | Installs | Adapter |
|---|---|---|
| `[httpx]` | `httpx>=0.27` | `HttpxTransport`, used by default when you pass no `transport=` |
| `[httpx2]` | `httpx2>=2.0` | `Httpx2Transport` |

A verifier built without `transport=` builds an `HttpxTransport` at construction. Without the
`[httpx]` extra that is a `ConfigurationError`, so the application does not start, rather than
failing on its first request. With only `[httpx2]` installed, pass `transport=Httpx2Transport()`.

## Adapter parameters

`HttpxTransport` and `Httpx2Transport` take the same keyword-only parameters.

| Name | Default | Meaning |
|---|---|---|
| `timeout` | `5.0` | Seconds for the whole exchange, not per phase. |
| `client` | `None` | A client you built. `None` builds one. |

The adapter overrules two things on any client, including one you pass in: it never follows a
redirect, and its cookie jar is shut and emptied. A client you lend to an adapter therefore stops
carrying cookies for its other callers too, so give it a client used only for this. Everything else
about your client is left as you built it: proxies, TLS verification, the connection pool, and its
own per-phase timeouts. The whole-exchange `timeout` deadline still applies.

## Proxies and the environment

The default client honours the process environment the way `httpx` does — `HTTP_PROXY`,
`HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`/`SSL_CERT_DIR` and `~/.netrc`. That is usually what a
deployment behind an egress proxy or a private CA wants; if it is not, pass your own
`HttpxTransport(client=httpx.AsyncClient(trust_env=False))`. Either way the client never follows a
redirect and never keeps a cookie. [SECURITY.md](../SECURITY.md) spells out what the library
trusts.
