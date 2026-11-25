# Troubleshooting

After reading this page you can find the usual cause of a symptom and the page that fixes it.

Refusals are not logged by default, and every `401` looks the same on the wire. To see why a
request was refused, log `exc.reason` from an exception handler; see
[Errors](errors.md#why-the-401s-are-identical).

## Every cookie request is `401`

**The two servers use different secrets.** A secret with the right shape and the wrong value is
accepted at startup, then fails every request as a signature mismatch. Log
`SharedSecret.fingerprint` on both sides and compare; see [Shared secret](shared-secret.md).

**`secure_cookies` does not match the cookie Better Auth sets.** A verifier reads exactly one name:
`__Secure-better-auth.session_token` under the default `secure_cookies=True`, or
`better-auth.session_token` under `False`. A request carrying only the other name is anonymous.
Better Auth sets the `__Secure-` name in production and over HTTPS; a local server over plain HTTP
usually sets the plain name.

**The cookie never reaches the API.** A cookie Better Auth sets on another host does not travel to
this one unless its scope allows it, and two hosts under a platform domain such as
`up.railway.app` or `vercel.app` cannot share a cookie at all. See
[Deploying across two origins](cross-origin.md).

## A request with a cookie is `403`

The CSRF policy refused it. Its `Origin` is not in `allowed_origins`, or the browser marked it
`Sec-Fetch-Site: cross-site`. Add every front end's origin, and this API's own origin if its pages
post back to it. See [CSRF](csrf.md). A front end on another site cannot write through a cookie
mode at all, whatever is in `allowed_origins`; see
[Deploying across two origins](cross-origin.md).

## A request is `400` with `{"detail": "Ambiguous request"}`

It carried two credentials, for example the session cookie and an `Authorization: Bearer` header,
and two configured verifiers each found theirs. Send one credential per request.

## Mode C: the application does not start

`prepare()` raised `ConfigurationError`, which names the URL it tried. A `404` or `405` usually
means `base_path` is wrong. A body that is not JSON `null` usually means a proxy answered instead of
Better Auth. Under `refuse_unsigned_bearer=True`, the server's `bearer` plugin is at
`requireSignature: false`. An unreachable server, or a `408`, `425`, `429` or `5xx` answer, also
stops startup but is not remembered: start again once the server answers. See
[Mode C](mode-c-remote.md#quickstart).

## Mode C: every request is `401` for a while

- A `WARNING` that the readiness probe "answered 503 (server error)", or another temporary status:
  the auth server could not answer, for example while it restarted. The probe is retried every ten
  seconds and the service recovers on its own.
- A `WARNING` that `get-session` "is rate-limited upstream (429)": the auth server's shared
  rate-limit bucket is full, and every request is refused until the latch clears. Raise or exempt
  the limit, and configure `secret=` so forged cookies are not forwarded. See
  [The shared rate-limit bucket](mode-c-remote.md#the-shared-rate-limit-bucket).

## Mode B: every token is `401` after an auth-server outage

The cached key set is older than `max_stale` (one day by default) and could not be refreshed. The
reason names `max_stale`. Tokens verify again as soon as one refresh succeeds. If your outages last
longer, pass a longer `max_stale`. See
[Mode B](mode-b-jwt.md#when-the-key-set-cannot-be-fetched).

## Mode B: `ConfigurationError` about `max_stale` at startup

`cache_ttl` is above 86400 seconds, and `max_stale` must be at least `cache_ttl`. Pass an explicit
`max_stale` at least as large.

## `ConfigurationError`: the HTTP client is not installed

`JwtVerifier` and `RemoteVerifier` build their HTTP client at construction. Install
`fastapi-better-auth-bridge[httpx]`, or install `[httpx2]` and pass
`transport=Httpx2Transport()`. See [HTTP clients](http-clients.md).

## SQL store: every lookup fails with a `WARNING`

The `WARNING` names the driver error class and its SQLSTATE. `42501` means the database role lacks
`SELECT` on `session` or `user`. See [Session stores](stores.md#the-shipped-stores).

## Mode A: requests are `401` while the store is slow

One `WARNING` says the session store lookup could not complete and names
`LookupDeadlineExceeded`. A request's store lookups took longer than `lookup_timeout`, 5 seconds by
default. Requests are answered again as soon as the store answers in time. If opening a new
database connection alone takes longer than `lookup_timeout`, no lookup can complete: raise
`lookup_timeout` or shorten the connection time. See
[When the database does not answer](stores.md#when-the-database-does-not-answer).

After a server has stopped answering altogether, the database driver may log a line of its own
about the connection that was closed under it. With `asyncpg`, the `asyncio` logger may show
`Future exception was never retrieved` with `ConnectionError('unexpected connection_lost() call')`.
With `psycopg`, its own logger shows one `WARNING`, "query cancellation interrupted". Neither
carries the token.

## SQL store: every request is `401`, and ids are integers or uuids

Release 0.6.0 reads only text ids. With `advanced.database.generateId: "serial"` or `"uuid"`, every
valid session read as unusable. This is fixed on `main` and not yet released; see the
[changelog](../CHANGELOG.md) and [Session stores](stores.md#integer-and-uuid-ids).

## A field of my user model is always `None`

The Python field name does not match the wire key of your Better Auth `additionalFields` entry. A
`User` subclass generates a camelCase alias from each field name and ignores keys it does not
declare. Declare the field required to make a mismatch fail loudly. See
[User models](user-models.md#additionalfields-make-sure-they-reach-the-wire).

## A test override does nothing

The key must be the called factory, `auth.current_session()`, and it must come from the same
`BetterAuth` instance the routes use. A route that declares `optional_session` or another
`user_model` needs its own entry. See [Testing](testing.md).

## `KeyError` when a module defines `Session[Member]`

pydantic 2.14 looks a module up in `sys.modules` by its `__name__` when a generic model such as
`Session[Member]` is parametrized at module level. A module that is not in `sys.modules` while its
top level runs fails with `KeyError: '<module name>'`. That happens under
`runpy.run_module(..., alter_sys=False)`, with loaders that `exec` a module's source into a fresh
namespace, and with a bare `exec`. This is pydantic's behaviour, not this library's, and a normal
`import` is not affected. Register the module in `sys.modules` before running it, or parametrize
the model inside a function.
