"""What a consumer's editor tells them, checked by pyright rather than hoped for.

Every assertion here is written the way the README writes it - an `Annotated[...]` alias over
a called factory, resolved into a route parameter - because that is the only place the generic
chain is actually exercised. A factory checked in isolation can be perfectly typed while the
route body still sees `Any`, and `Any` passes every assignment test ever written.

The failing direction is pinned too. `assert_type` fails when the type is *wider* than asked
for, so a deliberately-wrong assertion carrying `# pyright: ignore[reportAssertTypeFailure]`
says "this is not that type" - and because the repository sets
`reportUnnecessaryTypeIgnoreComment`, the day it silently becomes that type the suppression
turns into an error of its own. Widening `Session[Member].user` back to `User` is caught
from both sides, which no single positive assertion can do.

The runtime half is deliberately thin: `assert_type` is a no-op at runtime, so the requests at
the bottom are here only to prove these are live routes rather than a file pyright reads and
nothing ever loads.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, Any

import pytest
from fastapi import Depends, FastAPI, HTTPException
from pydantic import SecretStr
from typing_extensions import assert_type

from fastapi_better_auth import (
    AdminUser,
    AuthorizationRefused,
    BetterAuth,
    JwtVerifier,
    Membership,
    Session,
    SessionError,
    SharedSecret,
    User,
    Verifier,
    normalize_base_url,
    parse_user,
)
from tests.fakes import GOOD_CREDENTIAL, FakeVerifier, client

HEADER = "x-cred-a"
SECRET = "Zt7Qv1oXbK4mPr9wCyHnLdEuAsJf2Ng6"


class Member(User):
    """The deployment's own model - what `user_model=` is for."""

    role: str | None = None


auth = BetterAuth(verifiers=[FakeVerifier(HEADER, payload={"id": "u1", "role": "admin"})])

CurrentMember = Annotated[Session[Member], Depends(auth.current_session(user_model=Member))]
MaybeMember = Annotated[Session[Member] | None, Depends(auth.optional_session(user_model=Member))]
CurrentUser = Annotated[Session[User], Depends(auth.current_session())]
MaybeUser = Annotated[Session[User] | None, Depends(auth.optional_session())]


class Staff(User):
    """The user model the authorization helpers are parameterized on."""

    role: str | None = None


def is_editor(session: Session[Staff]) -> bool:
    return session.user.role == "editor"


async def member_of(resource_id: str, session: Session[Staff]) -> str | None:
    return f"{session.user.id}:{resource_id}"


Editor = Annotated[
    Session[Staff], Depends(auth.require(is_editor, reason="editor role", user_model=Staff))
]
Scoped = Annotated[
    Membership[Staff, str],
    Depends(auth.require_membership("org_id", member_of, reason="org member", user_model=Staff)),
]


class MissingCapability(AuthorizationRefused):
    """A consumer's own explaining refusal: a subclass with a constructor of its own."""

    def __init__(self, capability: str) -> None:
        super().__init__(detail={"code": "missing_capability", "capability": capability})


def can_send_sms(session: Session[Staff]) -> bool:
    if session.user.role != "dispatcher":
        raise MissingCapability("send_sms")
    return True


async def covers(district_id: str, session: Session[Staff]) -> str:
    if district_id != "ada-east":
        raise AuthorizationRefused(status_code=404, headers={"Cache-Control": "no-store"})
    return f"{session.user.id}:{district_id}"


SmsSender = Annotated[
    Session[Staff], Depends(auth.require(can_send_sms, reason="send_sms", user_model=Staff))
]
District = Annotated[
    Membership[Staff, str],
    Depends(auth.require_membership("district_id", covers, reason="district", user_model=Staff)),
]


# --- the session a route body receives -------------------------------------------------


async def read_member(session: CurrentMember) -> dict[str, str]:
    assert_type(session, Session[Member])
    assert_type(session.user, Member)
    assert_type(session.user.role, str | None)
    assert_type(session.user.id, str)
    assert_type(session.token, SecretStr | None)
    assert_type(session.expires_at, datetime | None)
    assert_type(session.raw, Mapping[str, Any])
    assert_type(session.user, User)  # pyright: ignore[reportAssertTypeFailure]
    return {"id": session.user.id, "role": session.user.role or ""}


async def read_member_maybe(session: MaybeMember) -> dict[str, str | None]:
    assert_type(session, Session[Member] | None)
    if session is None:
        return {"id": None}
    assert_type(session, Session[Member])
    assert_type(session.user, Member)
    return {"id": session.user.id}


async def read_default(session: CurrentUser) -> dict[str, str]:
    """No `user_model`, so the payload is a plain `User` - not `Session[Any]`."""
    assert_type(session, Session[User])
    assert_type(session.user, User)
    assert_type(session.user.email, str | None)
    assert_type(session, Session[Any])  # pyright: ignore[reportAssertTypeFailure]
    return {"id": session.user.id}


async def read_default_maybe(session: MaybeUser) -> dict[str, str | None]:
    assert_type(session, Session[User] | None)
    return {"id": None if session is None else session.user.id}


async def read_editor(session: Editor) -> dict[str, str]:
    """`require` hands the route the same session `current_session` would, parameterized on the
    same user model - so nothing downstream has to re-narrow what it was already given."""
    assert_type(session, Session[Staff])
    assert_type(session.user, Staff)
    assert_type(session.user.role, str | None)
    assert_type(session.user, User)  # pyright: ignore[reportAssertTypeFailure]
    return {"id": session.user.id, "role": session.user.role or ""}


async def read_scoped(access: Scoped) -> dict[str, str]:
    """`require_membership` hands the route the grant its own lookup returned, typed - which is
    the whole reason the result is a container rather than the session again."""
    assert_type(access, Membership[Staff, str])
    assert_type(access.session, Session[Staff])
    assert_type(access.session.user, Staff)
    assert_type(access.resource_id, str)
    assert_type(access.grant, str)
    assert_type(access.grant, str | None)  # pyright: ignore[reportAssertTypeFailure]
    return {"id": access.session.user.id, "grant": access.grant}


async def read_sms_sender(session: SmsSender) -> dict[str, str]:
    """A predicate that raises its own refusal changes nothing about what the route is handed."""
    assert_type(session, Session[Staff])
    return {"id": session.user.id}


async def read_district(access: District) -> dict[str, str]:
    """Nor does a lookup that raises one: its grant is still the type it declared."""
    assert_type(access, Membership[Staff, str])
    assert_type(access.grant, str)
    return {"grant": access.grant}


def takes_an_http_exception(error: HTTPException) -> int:
    return error.status_code


def read_the_refusal_types() -> None:
    """The marker is an `HTTPException` a consumer subclasses - and not a `SessionError`."""
    refusal = MissingCapability("send_sms")

    assert_type(refusal, MissingCapability)
    assert_type(refusal.status_code, int)
    assert_type(refusal.headers, Mapping[str, str] | None)
    assert_type(takes_an_http_exception(refusal), int)
    assert_type(AuthorizationRefused(status_code=404, detail={"k": ["v"]}), AuthorizationRefused)
    assert_type(refusal, SessionError)  # pyright: ignore[reportAssertTypeFailure]
    with pytest.raises(ValueError, match="403 or 404"):
        AuthorizationRefused(status_code="403")  # pyright: ignore[reportArgumentType]


# --- the types around the session -------------------------------------------------------


def takes_a_base_session(session: Session[User]) -> str:
    """`Session` is covariant in its user type, so a subclass session passes here."""
    return session.user.id


def read_the_surrounding_types(session: Session[Member]) -> None:
    assert_type(takes_a_base_session(session), str)
    assert_type(auth.verifiers, tuple[Verifier, ...])
    assert_type(BetterAuth.from_env(), BetterAuth)
    assert_type(parse_user(Member, {"id": "u1"}), Member)
    assert_type(parse_user(User, {"id": "u1"}), User)
    assert_type(normalize_base_url("https://auth.example.com"), str)


def read_the_admin_user_types(session: Session[AdminUser]) -> None:
    """The subclass this library ships, checked the way a consumer's editor checks it."""
    assert_type(session.user, AdminUser)
    assert_type(session.user.role, str | None)
    assert_type(session.user.banned, bool | None)
    assert_type(session.user.ban_reason, str | None)
    assert_type(session.user.ban_expires, datetime | None)
    assert_type(session.impersonated_by, str | None)
    assert_type(session.user, User)  # pyright: ignore[reportAssertTypeFailure]


def read_the_verifier_types(verifier: JwtVerifier) -> None:
    assert_type(verifier.origin, str)
    assert_type(verifier.jwks_uri, str)
    assert_type(verifier.algorithms, tuple[str, ...])
    assert_type(verifier.credential_source, str)


def read_the_secret_types() -> None:
    secret = SharedSecret(SECRET)

    assert_type(secret, SharedSecret)
    assert_type(secret.get_secret_value(), str)
    assert_type(secret.fingerprint, str)
    assert_type(secret.get_secret_value(), SecretStr)  # pyright: ignore[reportAssertTypeFailure]


# --- the routes are real ------------------------------------------------------------------

app = FastAPI()
app.add_api_route("/member", read_member, methods=["GET"])
app.add_api_route("/member-maybe", read_member_maybe, methods=["GET"])
app.add_api_route("/default", read_default, methods=["GET"])
app.add_api_route("/default-maybe", read_default_maybe, methods=["GET"])
app.add_api_route("/editor", read_editor, methods=["GET"])
app.add_api_route("/orgs/{org_id}/invoices", read_scoped, methods=["GET"])
app.add_api_route("/sms", read_sms_sender, methods=["GET"])
app.add_api_route("/districts/{district_id}", read_district, methods=["GET"])


def test_every_asserted_call_site_is_a_route_that_answers() -> None:
    """`assert_type` is a runtime no-op, so without this the file is something pyright reads
    and nothing ever loads - and a call site nobody can reach proves nothing about one."""
    with client(app) as http:
        member = http.get("/member", headers={HEADER: GOOD_CREDENTIAL})
        anonymous = http.get("/member-maybe")
        default = http.get("/default", headers={HEADER: GOOD_CREDENTIAL})

    assert member.json() == {"id": "u1", "role": "admin"}
    assert anonymous.json() == {"id": None}
    assert default.json() == {"id": "u1"}


def test_the_authorization_call_sites_are_routes_that_answer() -> None:
    """`require` refuses the fake's user (its role is `admin`, not `editor`); the membership
    route answers, so both asserted call sites are reachable rather than merely type-checked."""
    with client(app) as http:
        refused = http.get("/editor", headers={HEADER: GOOD_CREDENTIAL})
        scoped = http.get("/orgs/acme/invoices", headers={HEADER: GOOD_CREDENTIAL})

    assert refused.status_code == 403
    assert scoped.json() == {"id": "u1", "grant": "u1:acme"}


def test_the_refusal_call_sites_are_routes_that_answer() -> None:
    """The fake's user is an `admin`, not a `dispatcher`, so the predicate refuses with its own
    body; the lookup refuses an uncovered district and grants a covered one."""
    with client(app) as http:
        sms = http.get("/sms", headers={HEADER: GOOD_CREDENTIAL})
        outside = http.get("/districts/acme", headers={HEADER: GOOD_CREDENTIAL})
        inside = http.get("/districts/ada-east", headers={HEADER: GOOD_CREDENTIAL})

    assert sms.status_code == 403
    assert sms.json() == {"detail": {"code": "missing_capability", "capability": "send_sms"}}
    assert (outside.status_code, outside.json()) == (404, {"detail": "Not Found"})
    assert outside.headers["cache-control"] == "no-store"
    assert inside.json() == {"grant": "u1:ada-east"}
    read_the_refusal_types()


def test_the_surrounding_types_are_exercised_too() -> None:
    session = Session[Member](user=Member(id="u1"), expires_at=None, raw={"id": "u1"})
    admin = Session[AdminUser](
        user=AdminUser(id="u1", role="admin"),
        expires_at=None,
        impersonated_by="admin-1",
        raw={"id": "u1"},
    )

    assert takes_a_base_session(session) == "u1"
    assert takes_a_base_session(admin) == "u1"
    read_the_admin_user_types(admin)
    read_the_secret_types()
