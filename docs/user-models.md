# User models and optional sessions

After reading this page you can parse the signed-in user into your own model, use the fields the
admin plugin adds, make sure your `additionalFields` reach FastAPI, and accept requests that may
or may not be signed in.

The examples use Mode B because it needs the least setup. Everything here works the same in every
mode.

## Your own user model, and optional authentication

`User` carries `id`, `email`, `name`, `email_verified`, `image`, `created_at` and `updated_at`.
Subclass it to read more:

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from fastapi_better_auth import BetterAuth, JwtVerifier, Session, User


class Member(User):
    role: str | None = None


auth = BetterAuth(verifiers=[JwtVerifier(base_url="https://auth.example.com")])
CurrentMember = Annotated[Session[Member], Depends(auth.current_session(user_model=Member))]
MaybeMember = Annotated[Session[Member] | None, Depends(auth.optional_session(user_model=Member))]

app = FastAPI()


@app.get("/role")
async def role(session: CurrentMember) -> str:
    return session.user.role or "member"


@app.get("/greeting")
async def greeting(session: MaybeMember) -> str:
    return "hello" if session is None else f"hello, {session.user.id}"
```

`optional_session` returns `None` for one situation only: no credential was presented at all. One
that *was* presented and did not verify still fails — a forged or expired token is never downgraded
to "anonymous".

## Fields the admin plugin adds: `AdminUser`

If your Better Auth server mounts the [admin plugin](https://better-auth.com/docs/plugins/admin) it
adds four columns to `user` — `role`, `banned`, `banReason`, `banExpires` — and one to `session`,
`impersonatedBy` (`dist/plugins/admin/schema.mjs:3-30`). `AdminUser` is the subclass you would otherwise
write for the four:

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from fastapi_better_auth import AdminUser, BetterAuth, JwtVerifier, Session

auth = BetterAuth(verifiers=[JwtVerifier(base_url="https://auth.example.com")])
CurrentAdmin = Annotated[Session[AdminUser], Depends(auth.current_session(user_model=AdminUser))]

app = FastAPI()


@app.get("/role")
async def whoami(session: CurrentAdmin) -> str:
    return session.user.role or "unknown"
```

The plugin declares all five `input: false` (same file), so they are server-controlled and an account
holder can never set one at sign-up — which is what makes them worth typing, unlike an `additionalFields`
entry. Without the plugin the keys are simply absent and every field reads `None`, which means
**unknown** and never *safe*: a missing `banned` is not an unbanned user.

`banned` is a *view*, not a decision. In Modes A and C the ban is enforced by the verifier — from
the store record or the upstream document — before the model is built, so a live ban is a `401` and
your route never runs. A `banned=True` you can actually read is therefore a ban that has **lapsed**
(`ban_expires` in the past), or Mode B data, where a JWT carries whatever was true when it was
minted. It is also a `StrictBool`: a `1` or a `"true"` on the wire is refused rather than guessed at.

The session half sits on the session, not the user. `session.impersonated_by` is the admin's user id
when this session came from the plugin's impersonation endpoint, and `None` otherwise — including in
Mode B, always, because a JWT carries the user object and no session row. It is **provenance, not
permission**: it tells you an administrator is acting as this user, never that the request may do
anything extra.

## `additionalFields`: make sure they reach the wire

A `User` subclass ignores keys it does not declare, and generates a camelCase alias from each Python
name. That is the right default — upstream ships often, and a field you have not declared must not
turn an authentic request into a 500 — but it has one sharp edge worth knowing before you rely on
it: **a name mismatch between your Node-side `additionalFields` key and your Python field is not an
error.** Declare `jurisdiction_scope` (wire key `jurisdictionScope`) while the server sends
`jurisdiction`, and every request reads `None` for ever.

Which way that fails is your choice, and it is the annotation that makes it:

```python
from fastapi_better_auth import User


class Lenient(User):
    """Forward-compatible. A name mismatch reads None, and nothing says so."""

    jurisdiction_scope: str | None = None


class Scoped(User):
    """Fails closed. A name mismatch refuses every request, from the first one."""

    jurisdiction_scope: str
```

A required field is the strict mode; there is no separate switch. The refusal is the same uniform
`401` as everything else, so the client learns nothing — but the diagnosis is on the exception as
`InvalidCredential.reason`, naming the **wire key** the model expected:

    Scoped payload rejected (1): jurisdictionScope: [missing]

and the first time it happens the library logs one `WARNING` per process per user model on the
`fastapi_better_auth` logger, naming the model and the missing wire keys. Nothing the payload
carried appears in either — only the field names your own model declared.

Neither shape can tell you the names are right *before* the first request, so verify them once, as a
smoke test against your real Better Auth server. The check is the same in every mode: sign in, then
assert the key is on the wire where that mode reads it.

```text
# Run against a real Better Auth server, once per deployment, in your own test suite.
EXPECTED = {"jurisdictionScope", "role"}          # the WIRE keys, camelCase

# Mode B — the JWT payload. Fetch a token and decode it WITHOUT verifying; you are
# inspecting shape, not authenticating.
#   POST /api/auth/sign-in/email  ->  cookie
#   GET  /api/auth/token          ->  {"token": "..."}
#   claims = jwt.decode(token, options={"verify_signature": False})
#   assert EXPECTED <= claims.keys()
#
# Mode C — the get-session body.
#   GET /api/auth/get-session with the cookie  ->  {"session": {...}, "user": {...}}
#   assert EXPECTED <= body["user"].keys()
#
# Mode A — the store record, read through the store you configured.
#   record = await store.fetch_session_by_token(raw_token)
#   user = record.user or await store.fetch_user_by_id(record.user_id)
#   assert EXPECTED <= user.payload.keys()
```

There is deliberately no startup gate for this. At boot there is no payload to inspect in any mode —
Mode B has no token, Mode C's readiness probe carries no cookie, and Mode A's store has no
particular user — so a boot check would have to sign in with a real credential, which is exactly the
smoke test above, and the smoke test belongs in your suite rather than in your `lifespan`.

**One trap on the Node side.** A field your server sets itself (`input: false`) with no
`defaultValue` must be declared `required: false`. `required` defaults to `true`
(`@better-auth/core@1.7.5` `dist/db/type.d.mts:32-36`), so the generated column is `NOT NULL`
(`better-auth@1.7.5` `dist/db/get-migration.mjs:616` and `:644`; `:607` and `:635` at 1.7.1), while
sign-up's input check acts only on a `required` that is set explicitly (`dist/db/schema.mjs:103`,
the same file at 1.7.1 and 1.7.5). Unless a hook writes the field before the insert, sign-up gets
past that check and fails on the database's constraint rather than with a clean error.
