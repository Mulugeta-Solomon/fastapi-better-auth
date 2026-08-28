"""What a consumer's editor tells them, checked by pyright rather than hoped for.

Every assertion here is written the way the README writes it - an `Annotated[...]` alias over
a called factory, resolved into a route parameter - because that is the only place the generic
chain is actually exercised. A factory checked in isolation can be perfectly typed while the
route body still sees `Any`, and `Any` passes every assignment test ever written.

The failing direction is pinned too. `assert_type` fails when the type is *wider* than asked
for, so a deliberately-wrong assertion carrying `# pyright: ignore[reportAssertTypeFailure]`
says "this is not that type" - and because the repository sets
`reportUnnecessaryTypeIgnoreComment`, the day it silently becomes that type the suppression
turns into an error of its own. Widening `Session[AdminUser].user` back to `User` is caught
from both sides, which no single positive assertion can do.

The runtime half is deliberately thin: `assert_type` is a no-op at runtime, so the requests at
the bottom are here only to prove these are live routes rather than a file pyright reads and
nothing ever loads.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, Any

from fastapi import Depends, FastAPI
from pydantic import SecretStr
from typing_extensions import assert_type

from fastapi_better_auth import (
    BetterAuth,
    JwtVerifier,
    Session,
    SharedSecret,
    User,
    Verifier,
    normalize_base_url,
    parse_user,
)
from tests.fakes import GOOD_CREDENTIAL, FakeVerifier, client

HEADER = "x-cred-a"
SECRET = "Zt7Qv1oXbK4mPr9wCyHnLdEuAsJf2Ng6"


class AdminUser(User):
    """The deployment's own model - what `user_model=` is for."""

    role: str | None = None


auth = BetterAuth(verifiers=[FakeVerifier(HEADER, payload={"id": "u1", "role": "admin"})])

CurrentAdmin = Annotated[Session[AdminUser], Depends(auth.current_session(user_model=AdminUser))]
MaybeAdmin = Annotated[
    Session[AdminUser] | None, Depends(auth.optional_session(user_model=AdminUser))
]
CurrentUser = Annotated[Session[User], Depends(auth.current_session())]
MaybeUser = Annotated[Session[User] | None, Depends(auth.optional_session())]


# --- the session a route body receives -------------------------------------------------


async def read_admin(session: CurrentAdmin) -> dict[str, str]:
    assert_type(session, Session[AdminUser])
    assert_type(session.user, AdminUser)
    assert_type(session.user.role, str | None)
    assert_type(session.user.id, str)
    assert_type(session.token, SecretStr | None)
    assert_type(session.expires_at, datetime | None)
    assert_type(session.raw, Mapping[str, Any])
    assert_type(session.user, User)  # pyright: ignore[reportAssertTypeFailure]
    return {"id": session.user.id, "role": session.user.role or ""}


async def read_admin_maybe(session: MaybeAdmin) -> dict[str, str | None]:
    assert_type(session, Session[AdminUser] | None)
    if session is None:
        return {"id": None}
    assert_type(session, Session[AdminUser])
    assert_type(session.user, AdminUser)
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


# --- the types around the session -------------------------------------------------------


def takes_a_base_session(session: Session[User]) -> str:
    """`Session` is covariant in its user type, so a subclass session passes here."""
    return session.user.id


def read_the_surrounding_types(session: Session[AdminUser]) -> None:
    assert_type(takes_a_base_session(session), str)
    assert_type(auth.verifiers, tuple[Verifier, ...])
    assert_type(BetterAuth.from_env(), BetterAuth)
    assert_type(parse_user(AdminUser, {"id": "u1"}), AdminUser)
    assert_type(parse_user(User, {"id": "u1"}), User)
    assert_type(normalize_base_url("https://auth.example.com"), str)


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
app.add_api_route("/admin", read_admin, methods=["GET"])
app.add_api_route("/admin-maybe", read_admin_maybe, methods=["GET"])
app.add_api_route("/default", read_default, methods=["GET"])
app.add_api_route("/default-maybe", read_default_maybe, methods=["GET"])


def test_every_asserted_call_site_is_a_route_that_answers() -> None:
    """`assert_type` is a runtime no-op, so without this the file is something pyright reads
    and nothing ever loads - and a call site nobody can reach proves nothing about one."""
    with client(app) as http:
        admin = http.get("/admin", headers={HEADER: GOOD_CREDENTIAL})
        anonymous = http.get("/admin-maybe")
        default = http.get("/default", headers={HEADER: GOOD_CREDENTIAL})

    assert admin.json() == {"id": "u1", "role": "admin"}
    assert anonymous.json() == {"id": None}
    assert default.json() == {"id": "u1"}


def test_the_surrounding_types_are_exercised_too() -> None:
    session = Session[AdminUser](user=AdminUser(id="u1"), expires_at=None, raw={"id": "u1"})

    assert takes_a_base_session(session) == "u1"
    read_the_secret_types()
