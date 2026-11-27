# Authorization: roles and organizations

After reading this page you can gate a route on a rule about the user with `require`, gate it on
the organization or other resource the request names with `require_membership`, and return a
`403` that explains itself with `AuthorizationRefused`.

## Organizations and roles — the recipe

Two helpers, both built on a session that is already verified, and both refusing with the same
uniform `403` this library uses everywhere else. `require(predicate, ...)` gates a route on a rule
about the user; `require_membership(id_param, member, ...)` gates it on *this request's* resource.

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from fastapi_better_auth import BetterAuth, JwtVerifier, Session, User

auth = BetterAuth(verifiers=[JwtVerifier(base_url="https://auth.example.com")])


class Member(User):
    role: str | None = None


def is_editor(session: Session[Member]) -> bool:
    return session.user.role in {"editor", "owner"}


Editor = Annotated[
    Session[Member],
    Depends(auth.require(is_editor, reason="editor role", user_model=Member)),
]

app = FastAPI()


@app.get("/drafts")
async def drafts(session: Editor) -> list[str]:
    return [session.user.id]
```

Build the dependency **once, at module level**, exactly like the `Annotated` alias in it: each
call makes a new one, and a new one per request would defeat FastAPI's per-request cache. Composing
on `current_session` is what makes a route that declares both the session and the gate verify
exactly once.

The predicate is synchronous and **only `True` passes** — compared by identity, so a truthy accident
(a database row, a non-empty error string, the coroutine an `async def` predicate returns) refuses
rather than admits. An `async def` predicate is a `ConfigurationError` rather than a permanent,
silent `403`. Whatever the predicate raises is logged and answered `403`, except a `SessionError` or
`ConfigurationError` it raised on purpose, which keeps its own shape — and an
`AuthorizationRefused`, which is how a rule explains itself ([below](#a-refusal-that-explains)).
One `SessionError` follows the bridge's setting instead: an `AuthServiceUnavailable` raised by a
predicate or a membership lookup answers exactly as one raised by a verifier does, the `401` by
default or the `503` under [the `503` opt-in](errors.md#answering-503-while-the-auth-service-is-down). So a rule that reads a store during a stall does not tell a
verified session to sign in again.

**The organization id comes from the request — its path or its query — and membership is checked with
your own query. Never from `session.raw["activeOrganizationId"]`.**

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from fastapi_better_auth import BetterAuth, JwtVerifier, Membership, Session, User

auth = BetterAuth(verifiers=[JwtVerifier(base_url="https://auth.example.com")])

ROLES = {("org_a", "user_1"): "owner"}


async def member_of(org_id: str, session: Session[User]) -> str | None:
    """Your query. The role, or None for "not a member of THIS organization"."""
    return ROLES.get((org_id, session.user.id))


OrgMember = Annotated[
    Membership[User, str],
    Depends(auth.require_membership("org_id", member_of, reason="organization member")),
]

app = FastAPI()


@app.get("/orgs/{org_id}/invoices")
async def invoices(access: OrgMember) -> dict[str, str]:
    return {"org": access.resource_id, "role": access.grant}
```

`"org_id"` becomes a required `str` parameter of the dependency, so FastAPI binds it from the
**path** when the route declares one by that name — and from the **query string** when it does not,
which is how the same gate serves `GET /invoices?org_id=…`. Either way it is published in
`/openapi.json`. The value is held to the rules a user id is held to (non-blank, at most 255
characters, no control characters); one that fails them is the same `403`, and no query runs.

`member_of` answers the **grant**: anything other than `None` or `False` — a role string, a row, a
set of scopes — reaches the route on `Membership.grant`, typed, next to `Membership.session` and
`Membership.resource_id`. `None` and `False` are the refusal. A lookup that raises is logged and
answered `403` — unless what it raised is an `AuthorizationRefused`
([below](#a-refusal-that-explains)); one that forgot its `async def` is a `ConfigurationError`,
because a value returned from a plain `def` would otherwise have been handed to the route as the
grant.

Why the rule is a rule: `activeOrganizationId` is written by `POST /organization/set-active`, a route
the *client* calls (`dist/plugins/organization/routes/crud-org.mjs:379`). Upstream does check
membership before it writes (`:420`, a 403 at `:425`), so it is not forgeable — but it is not an
answer to *this* request's question either. It records which organization the client last selected,
out of the ones the user belongs to. The request in front of you names its own organization, and the
two are unrelated.

The failure that produces is not subtle. A handler that **selects data by the path's organization but
authorizes on `activeOrganizationId`** lets any member of any organization read every organization's
data: the check passes because they do have an active organization, and the query then runs against
whatever the path said. `require_membership` hands your lookup the id FastAPI resolved from the request and no other,
so the mistake can only be re-created inside the lookup — by ignoring that argument and reading
`session.raw` instead, which is the one thing a `member` coroutine must never do.

The real `member_of` is a query against the `member` table Better Auth already writes. It needs a
database, so it is shown rather than executed here:

```text
from sqlalchemy import text


async def member_of(org_id: str, session: Session[User]) -> str | None:
    """Authorize this user against THIS request's organization. None means no membership."""
    async with engine.connect() as connection:
        result = await connection.execute(
            text('SELECT role FROM "member" WHERE "organizationId" = :org AND "userId" = :user'),
            {"org": org_id, "user": session.user.id},
        )
        membership = result.first()
    return None if membership is None else membership.role
```

**The regression case, spelled out — keep it as a test.** Sign in as a user who is a member of
organization A and *not* of organization B. Call `organization.setActive({ organizationId: "A" })`.
Then request `/orgs/B/invoices` with that same session, and expect **403**. The correct handler
refuses because the `member` query for `(B, user)` finds nothing. The broken one returns `200` and
serves B's invoices, because it asked whether the user had an active organization and never asked
which organization this request was about.

### A refusal that explains

The uniform `403` is right for the session layer and wrong for a product whose design requires a
denial that names what was missing. Only the rule that refused knows which — a capability the role
lacks, a district the grants do not cover — so the rule says so itself: raise an
`AuthorizationRefused`, or your own subclass of it, from the predicate or the lookup, and it reaches
the client with the status, `detail` and headers you built it with.

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from fastapi_better_auth import (
    AuthorizationRefused,
    BetterAuth,
    JwtVerifier,
    Membership,
    Session,
    User,
)

auth = BetterAuth(verifiers=[JwtVerifier(base_url="https://auth.example.com")])


class Staff(User):
    role: str | None = None


class PermissionDenied(AuthorizationRefused):
    """Your refusal and your body, built from your own rules and rows."""

    def __init__(self, code: str, message: str, **context: object) -> None:
        super().__init__(detail={"code": code, "message": message, **context})


CAPABILITIES = {"auditor": {"view_audit_log"}, "dispatcher": {"send_sms_alert"}}
COVERAGE = {"user_1": {"ada-east": "Ada East District"}}


def views_audit_log(session: Session[Staff]) -> bool:
    if "view_audit_log" in CAPABILITIES.get(session.user.role or "", set()):
        return True
    raise PermissionDenied(
        "missing_capability",
        "You do not have permission to view the audit log.",
        capability="view_audit_log",
    )


async def covers(district_id: str, session: Session[Staff]) -> str:
    """Your query. The district's name, or a refusal naming the districts the user does cover."""
    covered = COVERAGE.get(session.user.id, {})
    if district_id in covered:
        return covered[district_id]
    raise PermissionDenied(
        "outside_jurisdiction",
        "That is outside the area you cover.",
        covers=sorted(covered.values()),
    )


AuditLogReader = Annotated[
    Session[Staff],
    Depends(auth.require(views_audit_log, reason="view_audit_log", user_model=Staff)),
]
DistrictStaff = Annotated[
    Membership[Staff, str],
    Depends(
        auth.require_membership("district_id", covers, reason="district coverage", user_model=Staff)
    ),
]

app = FastAPI()


@app.get("/audit-log")
async def audit_log(session: AuditLogReader) -> list[str]:
    return [session.user.id]


@app.get("/districts/{district_id}/incidents")
async def incidents(access: DistrictStaff) -> dict[str, str]:
    return {"district": access.grant}
```

A dispatcher asking for the audit log is answered `403` with this body, and a user asking about a
district they do not cover gets `403` with `"covers": ["Ada East District"]` — explained with the
rows the lookup just read, rather than re-derived by a second query that could answer differently:

```json
{"detail": {"code": "missing_capability",
            "message": "You do not have permission to view the audit log.",
            "capability": "view_audit_log"}}
```

The rules around it:

- **`403` or `404`, nothing else.** `404` is for a rule that would rather not confirm the resource
  exists; with no `detail` its body is the one an unknown path gets. Any other status — a `401`
  would tell a valid session to sign in again — or a `WWW-Authenticate` header in any spelling
  raises `ValueError` at construction. Raised inside a rule, that is an accident like any other:
  logged, and answered with the uniform `403`.
- **Only the marker is honoured.** A plain `HTTPException` raised inside a rule — a helper's stray
  `404` or `500` — is still contained, logged and answered `403`: a bug is not a decision.
- **Reachable only after authentication, and never logged.** An anonymous or forged request is the
  uniform `401` before any rule runs, so the explaining body is only ever shown to a caller whose
  credential verified. The refusal is an answer, not an accident, so nothing is logged for it.
- **Build the body from your own rules and rows** — never from the token, the cookie or the
  upstream payload. It is the one refusal whose every byte is yours.
- **An unusable resource id stays the uniform `403`.** An id that fails the identifier rules above
  is refused before your lookup is ever called, so there is no rule there to explain it.
