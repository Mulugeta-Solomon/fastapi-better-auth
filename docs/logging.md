# Logging

After reading this page you know what this library writes to its logger, at which level, and how
often, so you can alert on it.

Everything is logged on one logger, `fastapi_better_auth`. No line carries a raw token, a cookie
value or a signature.

## What is not logged

Ordinary refusals are not logged: a forged, expired or malformed token, an unknown key id, a
missing or ambiguous credential. What to record about a failed authentication is your decision.
To log them, register an exception handler for `SessionError` and log `exc.reason`; see
[Errors](errors.md#why-the-401s-are-identical).

## What is logged

What it *does* log, all on the `fastapi_better_auth` logger, is the deployment telling on itself.
At `WARNING`: a session-cache cookie it was not asked to read, a JWKS key it will not verify with or
a refresh that failed while a usable key set was still on hand, a stored record or a database table
it cannot use, a user model that declares a required field the upstream payload does not carry
(once per process per model, naming the model and the missing wire keys), a `429` backoff latch
opening (once per latch, never once per refused request), and the advisory `requireSignature`
warning (once per process). Also at `WARNING`: a session-store lookup that could not complete — a
statement the database refused, a database or Redis server that could not be reached (the first
lookup before any `connect()` included), or a store of your own raising — once per kind of failure
(the cookie verifier counts its session and user lookups apart), where the kind is the driver
error's class and its SQLSTATE when it carries a well-formed one, beside a fingerprint of what was
looked up and none of the error's text. It is said again only after a lookup completes, and past
eight distinct kinds one constant notice says further kinds are held back until then. The request
is answered the uniform `401` either way, like any other dependency that could not be reached, or
the `503` under [the `503` opt-in](errors.md#answering-503-while-the-auth-service-is-down).
At `ERROR`, with the traceback: an
exception that escaped a verifier, and one that escaped an authorization predicate or a membership
lookup — each answered as the uniform refusal rather than a `500`, so the log is the only place the
real exception exists. The `reason` those build names the exception's *type* and not its message.
An `AuthorizationRefused` is an answer rather than an escape, and logs nothing — unless it was
edited after it was built into something it could not have been built as (a `401`, a challenge
header, headers that are not text): that one is logged at `ERROR` with its class and the rule it
broke, never its headers or its `detail`, and answered as the uniform `403`.
None of these lines carries a raw token, a cookie value or a signature.

More lines at `WARNING`, and how often some of the lines named above are logged:

- **Mode C readiness probe answered a temporary status** (`408`, `425`, `429` or any `5xx`). Once
  per `RemoteVerifier`, naming the status and its class and never the body. Every request is
  refused as `AuthServiceUnavailable` until a probe passes.
- **Mode B key that will not load.** One line per skipped key each time the key set is fetched,
  naming its `kid`. The rest of the key set is still used. See [Mode B](mode-b-jwt.md#when-the-key-set-cannot-be-fetched).
- **Mode B key-set refresh failed** while the set on hand was still within `max_stale`: one line
  per failed refresh, which happens at most once per 10 seconds.
- **Mode A store lookups that passed `lookup_timeout`.** The kind is `LookupDeadlineExceeded`, with
  no SQLSTATE. It follows the once-per-kind rule above: one line, then nothing until a lookup
  completes. A lookup cancelled with its request logs nothing.
- **Redis store: a revocation key it cannot read.** One line for each lookup it refuses for that
  reason, with a fingerprint of the session's key. A session that was revoked logs nothing. See
  [The Redis store](stores.md#the-redis-store).

A `now=` clock that raises, or returns anything but an aware `datetime`, is an exception that
escaped a verifier: the request is the uniform `401`, and the exception is logged at `ERROR` with
its traceback.
