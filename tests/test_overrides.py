"""`app.dependency_overrides[auth.current_session()] = fake_session` — the documented override.

The library's own suite drives real verifiers, so nothing here would otherwise exercise the thing
a *consumer's* test suite does on every single test: replace the session dependency with a fake
and never verify anything. That spelling has one load-bearing detail — the factory is **called**,
because it is memoized and the object it hands back is the one the routes already depend on — and
one silent way to get it wrong, which is to write the factory bare and produce a key nothing
depends on. Both are pinned here, because the README now teaches the first and warns about the
second.

The bypass is asserted with a credential on the request, not without one. An anonymous request
never reaches `verify` anyway, so `verify_calls == 0` would be true for the wrong reason; a
*forged* credential that still produces a 200 is the property the recipe actually promises.

What the override does **not** bypass is authorization. `require` and `require_membership` compose
on this same memoized dependency, so overriding it drives them too — with the fake session handed
to the consumer's own predicate and lookup, which then run for real. A fake that is not an editor
is still refused, and that is the half a test suite must not accidentally switch off.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi import Depends, FastAPI

from fastapi_better_auth import BetterAuth, Membership, Session
from tests.fakes import BAD_CREDENTIAL, FakeVerifier, client
from tests.test_authz import (
    FORBIDDEN,
    HEADER,
    REASON,
    UNAUTHENTICATED,
    Member,
    is_editor,
    one_verifier,
)

FAKE_ID = "u-fake"
"""Deliberately not the id the fake verifier's payload carries, so a 200 names its source."""

ORG = "org_a"
OTHER = "org_b"
PATH = "/orgs/{org_id}/invoices"
GRANTS: dict[tuple[str, str], str] = {(ORG, FAKE_ID): "owner"}

SessionFactory = Callable[[], Awaitable[Session[Member]]]


def fake_session_of(role: str | None) -> SessionFactory:
    """The consumer's `fake_session`: a session built in memory, from no credential at all."""

    async def fake_session() -> Session[Member]:
        return Session(
            user=Member(id=FAKE_ID, role=role),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            raw={"id": FAKE_ID},
        )

    return fake_session


async def member_of(resource_id: str, session: Session[Member]) -> str | None:
    """The consumer's own lookup, answering about whoever the session says they are."""
    return GRANTS.get((resource_id, session.user.id))


def read_session(auth: BetterAuth) -> FastAPI:
    """A route behind `current_session`, the plain case."""
    app = FastAPI()
    required = auth.current_session(user_model=Member)

    async def read(session: Session[Member] = Depends(required)) -> dict[str, Any]:
        return {"id": session.user.id, "role": session.user.role}

    app.add_api_route("/me", read, methods=["GET"], response_model=None)
    return app


def read_optional_session(auth: BetterAuth) -> FastAPI:
    """The same, behind `optional_session` — an override answers for the absence too."""
    app = FastAPI()
    optional = auth.optional_session(user_model=Member)

    async def read(session: Session[Member] | None = Depends(optional)) -> dict[str, Any]:
        if session is None:
            return {"id": None, "role": None}
        return {"id": session.user.id, "role": session.user.role}

    app.add_api_route("/me", read, methods=["GET"], response_model=None)
    return app


def read_behind_predicate(auth: BetterAuth) -> FastAPI:
    """A route behind `require`, which composes on the dependency being overridden."""
    app = FastAPI()
    editors = auth.require(is_editor, reason=REASON, user_model=Member)

    async def read(session: Session[Member] = Depends(editors)) -> dict[str, Any]:
        return {"id": session.user.id, "role": session.user.role}

    app.add_api_route("/me", read, methods=["GET"], response_model=None)
    return app


def read_behind_membership(auth: BetterAuth) -> FastAPI:
    """A route behind `require_membership`, whose lookup runs against the fake session."""
    app = FastAPI()
    scoped = auth.require_membership("org_id", member_of, reason=REASON, user_model=Member)

    async def read(access: Membership[Member, str] = Depends(scoped)) -> dict[str, Any]:
        return {"id": access.session.user.id, "org": access.resource_id, "grant": access.grant}

    app.add_api_route(PATH, read, methods=["GET"], response_model=None)
    return app


Builder = Callable[[BetterAuth], FastAPI]
Key = Callable[[BetterAuth], Callable[..., Any]]


def required_key(auth: BetterAuth) -> Callable[..., Any]:
    return auth.current_session(user_model=Member)


def optional_key(auth: BetterAuth) -> Callable[..., Any]:
    return auth.optional_session(user_model=Member)


BUILDERS: dict[str, Builder] = {
    "current_session": read_session,
    "optional_session": read_optional_session,
    "require": read_behind_predicate,
    "require_membership": read_behind_membership,
}
KEYS: dict[str, Key] = {
    "current_session": required_key,
    "optional_session": optional_key,
    "require": required_key,
    "require_membership": required_key,
}
"""Which dependency each shape's route actually holds.

The two gates compose on `current_session`, so one override reaches them. `optional_session` is
its *own* memoized dependency, not a wrapper around the required one that an override would
travel through — a route behind it needs its own entry in the map, and this table is where that
asymmetry is stated rather than discovered.
"""

ROUTES: dict[str, str] = {
    "current_session": "/me",
    "optional_session": "/me",
    "require": "/me",
    "require_membership": f"/orgs/{ORG}/invoices",
}


def overridden(
    shape: str, *, role: str | None = "editor"
) -> tuple[FakeVerifier, FastAPI, SessionFactory]:
    """One app, built the way a consumer builds it, with the documented override installed."""
    verifier, auth = one_verifier()
    app = BUILDERS[shape](auth)
    fake_session = fake_session_of(role)
    app.dependency_overrides[KEYS[shape](auth)] = fake_session
    return verifier, app, fake_session


@pytest.mark.parametrize("shape", sorted(BUILDERS))
def test_the_documented_override_bypasses_verification(shape: str, client_backend: str) -> None:
    """A forged credential, and a 200 anyway: nothing was extracted and nothing was verified.

    Each shape is overridden on the dependency its own routes hold — which is `current_session`
    for the two authorization gates, because they compose on it rather than owning one, and
    `optional_session` for the route behind that (`KEYS`).
    """
    verifier, app, _ = overridden(shape)

    with client(app, client_backend) as http:
        answer = http.get(ROUTES[shape], headers={HEADER: BAD_CREDENTIAL})

    assert answer.status_code == 200, answer.text
    assert answer.json()["id"] == FAKE_ID
    assert verifier.extract_calls == 0
    assert verifier.verify_calls == 0


def test_the_membership_lookup_runs_against_the_fake_session(client_backend: str) -> None:
    """The grant a route receives is the consumer's own lookup answering about the fake user."""
    _, app, _ = overridden("require_membership")

    with client(app, client_backend) as http:
        answer = http.get(f"/orgs/{ORG}/invoices")

    assert answer.json() == {"id": FAKE_ID, "org": ORG, "grant": "owner"}


@pytest.mark.parametrize("shape", ["require", "require_membership"])
def test_overriding_the_session_does_not_override_the_gate(shape: str, client_backend: str) -> None:
    """Authentication is what a fake session replaces; authorization still decides.

    A suite that installed this override and then found every gated route open would have turned
    off the half it most needs to test. The predicate is handed a reader, and the lookup is asked
    about an organization the fake user is not in; both refuse, with the uniform 403.
    """
    verifier, app, _ = overridden(shape, role="reader")
    path = "/me" if shape == "require" else f"/orgs/{OTHER}/invoices"

    with client(app, client_backend) as http:
        answer = http.get(path, headers={HEADER: BAD_CREDENTIAL})

    assert answer.status_code == 403
    assert answer.json() == FORBIDDEN
    assert "www-authenticate" not in answer.headers
    assert verifier.verify_calls == 0


def test_the_key_is_the_object_the_routes_already_hold() -> None:
    """Why the parentheses work at all: the factory is memoized per user model.

    A factory that built a fresh callable per call would hand back a key no route depends on, and
    the override would be a line of test setup that silently does nothing.
    """
    _, auth = one_verifier()

    assert auth.current_session(user_model=Member) is auth.current_session(user_model=Member)
    assert auth.current_session(user_model=Member) is not auth.current_session()
    assert auth.optional_session(user_model=Member) is not auth.current_session(user_model=Member)


def test_the_optional_dependency_needs_its_own_entry(client_backend: str) -> None:
    """`optional_session` is a second dependency, not a wrapper the required one is reached
    through, so an override written for `current_session` does not travel to it.

    The two share a resolver, which is what makes a route declaring both verify once — but they
    are separate FastAPI cache keys by design, and `dependency_overrides` is keyed the same way.
    A suite that overrides only the required one and then reads a route behind the optional one
    is verifying for real without noticing; it fails closed, but every such test is a 401.
    """
    verifier, auth = one_verifier()
    app = read_optional_session(auth)
    app.dependency_overrides[auth.current_session(user_model=Member)] = fake_session_of("editor")

    with client(app, client_backend) as http:
        answer = http.get("/me", headers={HEADER: BAD_CREDENTIAL})

    assert answer.status_code == 401
    assert answer.json() == UNAUTHENTICATED
    assert verifier.verify_calls == 1


def test_an_override_for_another_user_model_reaches_nothing(client_backend: str) -> None:
    """Two user models are two memoized dependencies, so the key has to name the right one.

    This is the failure a consumer hits by copying the recipe into an application whose routes
    declare `user_model=`: the override is installed, the application starts, and every request
    is verified for real. It fails closed — a forged credential is still a 401 — which is what
    makes it a wasted line rather than a hole.
    """
    verifier, auth = one_verifier()
    app = read_session(auth)
    app.dependency_overrides[auth.current_session()] = fake_session_of("editor")

    with client(app, client_backend) as http:
        answer = http.get("/me", headers={HEADER: BAD_CREDENTIAL})

    assert answer.status_code == 401
    assert answer.json() == UNAUTHENTICATED
    assert verifier.verify_calls == 1


def test_the_key_written_without_its_parentheses_overrides_nothing(client_backend: str) -> None:
    """The mistake the README's Testing section warns about, from the key side.

    `dependency_overrides[auth.current_session]` — the factory itself — is a key nothing depends
    on, so the map is written, the suite runs, and every request is verified for real. The other
    side of the same typo, the bare factory as the override *value*, is `test_bare_factory.py`'s:
    that one is not silent, it is a `ConfigurationError` on the first request. Neither serves a
    request it should not have.
    """
    verifier, auth = one_verifier()
    app = read_session(auth)
    app.dependency_overrides[auth.current_session] = fake_session_of("editor")

    with client(app, client_backend) as http:
        answer = http.get("/me", headers={HEADER: BAD_CREDENTIAL})

    assert answer.status_code == 401
    assert answer.json() == UNAUTHENTICATED
    assert verifier.verify_calls == 1


def test_the_fake_session_carries_the_consumers_own_user_model(client_backend: str) -> None:
    """`Session[Member]` in, `Member` out: the route body is typed exactly as it is in production.

    An override that returned a plain `User` would compile, pass, and hide every use of a field
    the deployment's model added — so the recipe builds the model the routes declare.
    """
    _, app, _ = overridden("current_session")

    with client(app, client_backend) as http:
        answer = http.get("/me")

    assert answer.json() == {"id": FAKE_ID, "role": "editor"}


def test_the_override_is_confined_to_the_application_it_was_written_on(
    client_backend: str,
) -> None:
    """`dependency_overrides` lives on the app, so a second app built from the same `BetterAuth`
    verifies for real. That is why the recipe clears the map in the fixture's teardown rather
    than trusting a fresh `BetterAuth` per test."""
    verifier, auth = one_verifier()
    overridden_app = read_session(auth)
    overridden_app.dependency_overrides[auth.current_session(user_model=Member)] = fake_session_of(
        "editor"
    )
    untouched = read_session(auth)

    with client(untouched, client_backend) as http:
        answer = http.get("/me", headers={HEADER: BAD_CREDENTIAL})

    assert answer.status_code == 401
    assert verifier.verify_calls == 1
