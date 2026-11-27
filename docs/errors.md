# Errors

After reading this page you can tell which exception a refusal is, what HTTP answer it gets, and
how to log or reshape refusals without leaking why a request was refused.

## What each exception answers

Every request-time exception below is a subclass of `SessionError`, which is a FastAPI
`HTTPException`. FastAPI answers it with no handler of yours.

| Exception | Status | Body | `WWW-Authenticate` | Raised when |
|---|---|---|---|---|
| `MissingCredential` | `401` | `{"detail": "Not authenticated"}` | `Bearer` | `current_session()` found no credential at all. `optional_session()` returns `None` instead. |
| `InvalidCredential` | `401` | `{"detail": "Not authenticated"}` | `Bearer` | A credential was present and did not verify: malformed, bad signature, wrong issuer or audience, unknown key id. |
| `SessionExpired` | `401` | `{"detail": "Not authenticated"}` | `Bearer` | The credential verified, but its lifetime has run out. |
| `SessionRevoked` | `401` | `{"detail": "Not authenticated"}` | `Bearer` | The credential verified, but the session is gone: signed out, deleted, or the user is banned. |
| `AuthServiceUnavailable` | `401` | `{"detail": "Not authenticated"}` | `Bearer` | A dependency could not answer: the key set, the session store, or the Better Auth server. With [the opt-in](#answering-503-while-the-auth-service-is-down) it is `503`, `{"detail": "Service unavailable"}`, `Retry-After` and no challenge. |
| `AmbiguousCredentials` | `400` | `{"detail": "Ambiguous request"}` | none | Two or more credentials arrived on one request. |
| `CsrfFailure` | `403` | `{"detail": "Forbidden"}` | none | A cookie-mode request failed its CSRF check. |
| `NotAuthorized` | `403` | `{"detail": "Forbidden"}` | none | `require` or `require_membership` refused an authenticated session. |

Two more exceptions are not refusals of this kind:

- **`AuthorizationRefused`** is your own `403` or `404`, raised on purpose inside a `require`
  predicate or a `require_membership` lookup. It is a plain `HTTPException`, not a `SessionError`.
  See [A refusal that explains](authorization.md#a-refusal-that-explains).
- **`ConfigurationError`** (a `BetterAuthError`) is a configuration fault, not an answer to a
  client. It is raised while the application is built, so a deployment that cannot verify safely
  does not start. Some cases can only be found at request time, for example a bare factory planted
  in `app.dependency_overrides`, a Mode C readiness probe that found a contract failure while
  running lazily, or a SQL store that reads a broken schema on its first lookup because
  `connect()` was not called.

## Why the 401s are identical

Every request-time failure is an `HTTPException` subclass, so FastAPI answers it with no handler of
yours: `401`, the body `{"detail": "Not authenticated"}`, and a `WWW-Authenticate: Bearer` header.
Missing, malformed, expired, revoked, "the key set could not be fetched" and "the auth service could
not be reached" are byte-identical on the wire by default, deliberately: a client must not be able
to tell them apart and use the difference to probe. That last one is `AuthServiceUnavailable`, and
by default it is a `401` rather than a `503` on purpose: an unreachable Better Auth server means
this request was not authenticated, and saying so in a distinct status would be both an oracle and
an invitation to retry. A deployment can choose the `503` instead; see
[Answering 503 while the auth service is down](#answering-503-while-the-auth-service-is-down).
Mode C raises it for every non-`200` upstream answer, every timeout, an unusable body, a
saturated outbound limiter, a live `429` backoff, and every request while its readiness probe has
not yet passed. Mode B raises it when there is no usable key set: the first fetch failed, or the
set on hand is older than `max_stale`. Two credentials on one request are a `400`
(`{"detail": "Ambiguous request"}`), decided
before anything is verified. A cookie-mode request that fails its CSRF check is a `403`
(`{"detail": "Forbidden"}`) with no challenge — it carried a credential, so there is nothing to
re-authenticate. So is a request an authorization gate refuses: `NotAuthorized`, raised by
`require` and `require_membership`, is byte-identical to that `403` — the rule it broke lives on
`.reason` (with the user id, and the sanitized resource id for a membership refusal) and never on
the wire. Reaching a `403` at all means authentication already succeeded; an anonymous or forged
request is answered `401` before any rule is asked, so a `403` is never an oracle for which
credentials this deployment accepts.

There is one deliberate exception to per-status uniformity, and it is the application's to make:
an `AuthorizationRefused` raised on purpose inside a `require` predicate or a `require_membership`
lookup reaches the client with the `403` or `404` and the body the application chose
([A refusal that explains](authorization.md#a-refusal-that-explains)). It is reachable only after authentication,
this library puts nothing of its own into it, and it must never carry anything read from the
credential.

Why a request was refused lives on the exception, as `.reason`, and nowhere else. **This library
does not log ordinary refusals** — a forged, expired or malformed token, an unknown key id, a
missing or ambiguous credential — and that is deliberate rather than an omission: what to record
about a failed authentication, and where, is the deployment's decision. If you want them, register
a FastAPI exception handler for `SessionError` and log `exc.reason` explicitly; note that
`logging.exception()` renders `str(exc)`, which does not carry it. A `reason` holds identifiers and
fingerprints — a key id, a truncated hash — never a raw credential. What the library does log is
listed on [Logging](logging.md).

## Answering 503 while the auth service is down

By default an unreachable dependency is the same `401` as a forged credential. A browser reads a
`401` on a request that carried a session as "the session ended". So during a database stall every
signed-in user is shown a sign-in prompt, and the sign-in then meets the same stall. Nothing is let
through, but the prompt is false.

You can answer that one refusal with a `503` instead. It is off by default, and with it off nothing
changes: same status, body, headers and exception classes.

```python
from fastapi_better_auth import BetterAuth, JwtVerifier

auth = BetterAuth(
    verifiers=[JwtVerifier(base_url="https://auth.example.com")],
    unavailable_status=503,
    unavailable_retry_after=10,
)
```

- `unavailable_status` is `401` (the default) or `503`. Nothing else is accepted.
- `unavailable_retry_after` is whole seconds, from 1 to 300. It is accepted only with `503`, where
  it defaults to 10, the longest retry spacing the library uses itself.
- Both are checked when `BetterAuth` is built, as `ConfigurationError`. `BetterAuth.from_env()`
  reads neither from the environment.

With the opt-in, an `AuthServiceUnavailable` answers `503`, the body
`{"detail": "Service unavailable"}`, a `Retry-After` header and no `WWW-Authenticate` challenge. The
challenge is what tells a client to sign in again, so it is left off. Every other refusal keeps its
answer. A `503` is still a refusal: the request is not let through.

**What it covers.** Every dependency `BetterAuth` builds: `current_session()`,
`optional_session()`, `require()` and `require_membership()`. An `AuthServiceUnavailable` raised
inside a `require` predicate or a `require_membership` lookup follows the setting too. A WebSocket
handshake refused for this reason is denied with the same `503`. It does not cover route code that
calls a store or a verifier itself: that code gets the exception as raised, the `401` form. It does
not cover `startup()` either, which answers no client.

**What your handler sees.** The exception is still an `AuthServiceUnavailable`, with the same
`.reason`. It is not your application's own subclass of it, if a store or verifier raised one. Its
`status_code`, `headers` and the three `response_*` constants all say `503`, so the envelope below
needs no new branch. A `503` without freshness information is not stored by default, so no
`Cache-Control` header is added.

**What it costs.**

- Any caller learns that the auth dependency is failing, and that its credential passed the checks
  made before the dependency was asked. Which credentials get that far depends on the mode:
  - Mode A: only a cookie whose signature verified with your secret reaches the store.
  - Mode B: a token whose header is well formed, with an allowed `alg` and a key id the cached key
    set does not hold, reaches the key set before any signature is checked. A forged token can get
    the `503` there.
  - Mode C: without a keyring, any well-formed cookie reaches the Better Auth server. With a
    keyring, only a cookie whose signature verified.
- The `5xx` rate rises during an auth-dependency outage. A load balancer that ejects instances on
  `5xx` may eject every instance at once.

**What a client should do.** Treat the `503` as "try again", not as "signed out". `Retry-After` is
a fixed number from your configuration, not a forecast of when the dependency comes back.

One Mode B effect to expect: the same token can get a `401` and later a `503`. A key id the fresh
key set did not carry is remembered as absent, and once the key set goes stale and cannot be
refetched, that key id is answered `503`.

`tests/e2e/test_unavailable_live.py` proves both settings against a live Postgres that stops
answering. A signed-in user gets the `401` or the `503` while the session table is locked, and is
accepted again once the lock goes.

## Your own error envelope

If your API wraps every response in a house envelope, the same handler that logs `exc.reason` is
where you reshape the body. Read exactly three things off the exception — `exc.response_status`,
`exc.response_detail` and `exc.response_headers` — and the envelope inherits the uniformity the
default body has:

```python
import logging
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from fastapi_better_auth import BetterAuth, JwtVerifier, Session, SessionError, User

logger = logging.getLogger("myapp.auth")

auth = BetterAuth(verifiers=[JwtVerifier(base_url="https://auth.example.com")])
CurrentSession = Annotated[Session[User], Depends(auth.current_session())]

app = FastAPI()


@app.exception_handler(SessionError)
async def envelope(request: Request, exc: SessionError) -> JSONResponse:
    logger.warning("%s: %s", type(exc).__name__, exc.reason)
    return JSONResponse(
        status_code=exc.response_status,
        content={
            "success": False,
            "data": None,
            "error": {"code": exc.response_status, "message": exc.response_detail},
        },
        headers=exc.response_headers,
    )


@app.get("/me")
async def me(session: CurrentSession) -> dict[str, Any]:
    return {"success": True, "data": {"id": session.user.id}, "error": None}
```

Those three constants are per *status*, not per class: every 401 this library raises — missing,
malformed, expired, revoked, unreachable auth service — carries the same `401`, the same
`"Not authenticated"` and the same `WWW-Authenticate: Bearer`, so a handler that reads only them
cannot produce two distinguishable answers however many exception classes it is handed. The
envelope changes the shape of the body, not the number of bodies. With the
[503 opt-in](#answering-503-while-the-auth-service-is-down), an `AuthServiceUnavailable` carries
`503`, `"Service unavailable"` and `Retry-After` on the same three constants, and the same handler
renders it with no change.

An `AuthorizationRefused` never reaches this handler: it is not a `SessionError` but the
application's own `HTTPException`, rendered by FastAPI's `HTTPException` handler — register one for
`AuthorizationRefused` if its body should wear the envelope too.

**The anti-pattern: `type(exc).__name__` or `exc.reason` in the response.** Either one hands a
client the oracle the uniform body exists to remove — one lets an unauthenticated caller sort
"expired" from "forged" from "no such session", the other adds the identifiers and fingerprints a
`reason` is allowed to carry. Both belong in the log line above them, which is why that line takes
the class name and the reason and the response takes neither. The same rule covers branching:
a handler with an `if isinstance(exc, SessionExpired)` arm is distinguishable even if every branch
looks innocent on its own.

**Forward `headers=`.** `WWW-Authenticate: Bearer` is the 401's challenge, and dropping it makes a
correct client stop re-authenticating. `exc.response_headers` is `None` for the `400` and the `403`,
which `JSONResponse` accepts, so the one spelling is right for every status. There is no helper for
any of this on purpose: an envelope is your shape, not one this library could usefully template,
and three constants read off the exception is a handler a reviewer can audit in one sitting.
