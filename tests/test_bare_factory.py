"""`Depends(auth.current_session)` — the factory passed without being called.

At *route* level the mistake surfaces as a type error and, at runtime, as a route body handed
a callable where it expected a session. At *router* level it surfaced as nothing at all:
FastAPI resolved the factory itself as the dependency, called it, discarded the dependency it
returned, and **no verification happened on any route under that router** — a total, silent
authentication bypass on an application that started up healthy and answered 200.

`test_the_unguarded_shape_is_a_silent_bypass` is that failure, reproduced and kept: it builds
a factory with the same signature minus the guard and shows an anonymous request being
answered 200 with the verifier untouched. The tests after it assert that the real factories no
longer allow it, and that they refuse **while the application is being built** — the whole of
the choice recorded in D-107: an application whose routes carry this bug never finishes
starting up, so there is no window in which it serves unauthenticated traffic.

One planting is outside that guarantee and is pinned here rather than left implied.
`app.dependency_overrides` is a plain dict FastAPI owns and we do not, so the same typo written
as an override *value* is assigned without a hook to refuse it: the application starts healthy
and the guard fires at the first request instead. It still fails closed — an untranslated 500,
nothing extracted, nothing verified, no 2xx — which is what makes it a limit rather than a
second bypass.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from fastapi import APIRouter, Depends, FastAPI, Security, WebSocket
from fastapi.testclient import TestClient

from fastapi_better_auth import BetterAuth, ConfigurationError, Session, User
from fastapi_better_auth._internal.core import BARE_FACTORY
from tests.fakes import GOOD_CREDENTIAL, FakeVerifier, client

HEADER = "x-cred-a"
Factory = Callable[..., Callable[..., Awaitable[Any]]]


def one_verifier() -> tuple[FakeVerifier, BetterAuth]:
    verifier = FakeVerifier(HEADER)
    return verifier, BetterAuth(verifiers=[verifier])


async def read() -> dict[str, str]:
    return {"reached": "yes"}


# --- the bypass, reproduced and kept ---------------------------------------------------


def test_the_unguarded_shape_is_a_silent_bypass() -> None:
    """Prove the instrument. A factory whose only difference is the missing guard is resolved
    by FastAPI, called, and thrown away — and the route under it answers everybody."""
    verifier, auth = one_verifier()

    def unguarded(*, user_model: type[User] = User) -> Callable[..., Awaitable[Any]]:
        return auth.current_session(user_model=user_model)

    router = APIRouter(dependencies=[Depends(unguarded)])
    router.add_api_route("/me", read, methods=["GET"])
    app = FastAPI()
    app.include_router(router)

    with client(app) as http:
        response = http.get("/me")

    assert response.status_code == 200
    assert response.json() == {"reached": "yes"}
    assert verifier.extract_calls == 0
    assert verifier.verify_calls == 0


# --- every place the bare factory can be planted ---------------------------------------


def app_dependencies(factory: Factory) -> None:
    app = FastAPI(dependencies=[Depends(factory)])
    app.add_api_route("/me", read, methods=["GET"])


def router_dependencies(factory: Factory) -> None:
    router = APIRouter(dependencies=[Depends(factory)])
    router.add_api_route("/me", read, methods=["GET"])
    FastAPI().include_router(router)


def router_included_before_its_routes(factory: Factory) -> None:
    app = FastAPI()
    router = APIRouter(dependencies=[Depends(factory)])
    app.include_router(router)
    router.add_api_route("/me", read, methods=["GET"])


def route_dependencies(factory: Factory) -> None:
    FastAPI().add_api_route("/me", read, methods=["GET"], dependencies=[Depends(factory)])


def route_parameter(factory: Factory) -> None:
    async def endpoint(session: Session[User] = Depends(factory)) -> dict[str, str]:
        return {"id": session.user.id}

    FastAPI().add_api_route("/me", endpoint, methods=["GET"], response_model=None)


def route_parameter_via_security(factory: Factory) -> None:
    async def endpoint(session: Session[User] = Security(factory)) -> dict[str, str]:
        return {"id": session.user.id}

    FastAPI().add_api_route("/me", endpoint, methods=["GET"], response_model=None)


def websocket_route(factory: Factory) -> None:
    async def socket(websocket: WebSocket, session: Session[User] = Depends(factory)) -> None:
        await websocket.accept()

    FastAPI().add_api_websocket_route("/ws", socket)


PLANTINGS: tuple[tuple[str, Callable[[Factory], None]], ...] = (
    ("app-dependencies", app_dependencies),
    ("router-dependencies", router_dependencies),
    ("router-included-first", router_included_before_its_routes),
    ("route-dependencies", route_dependencies),
    ("route-parameter", route_parameter),
    ("route-parameter-security", route_parameter_via_security),
    ("websocket-route", websocket_route),
)


@pytest.mark.parametrize("plant", [case[1] for case in PLANTINGS], ids=[c[0] for c in PLANTINGS])
@pytest.mark.parametrize("which", ["current_session", "optional_session"])
def test_a_bare_factory_is_refused_wherever_it_is_planted(
    plant: Callable[[Factory], None], which: str
) -> None:
    """Router level was the silent one, so it is the one that matters — but a guard that only
    covered the shape somebody thought of would be the same mistake in a smaller box."""
    _verifier, auth = one_verifier()
    factory: Factory = getattr(auth, which)

    with pytest.raises(ConfigurationError) as caught:
        plant(factory)

    assert "parentheses" in str(caught.value)


@pytest.mark.parametrize("which", ["current_session", "optional_session"])
def test_the_refusal_names_the_exact_edit(which: str) -> None:
    """A guard that says "invalid dependency" leaves the reader where they started. This one
    is the line they should have written, with the parentheses that were missing."""
    _verifier, auth = one_verifier()

    with pytest.raises(ConfigurationError) as caught:
        app_dependencies(getattr(auth, which))

    message = str(caught.value)
    assert f"Depends(auth.{which}())" in message
    assert "parentheses" in message


def test_the_refusal_happens_before_any_request_is_served() -> None:
    """The property the choice is *for*: nothing is left to a first request to discover, so
    an application carrying this bug cannot boot and then serve unauthenticated traffic."""
    _verifier, auth = one_verifier()
    app = FastAPI()

    with pytest.raises(ConfigurationError):
        app.add_api_route(
            "/me", read, methods=["GET"], dependencies=[Depends(auth.current_session)]
        )

    assert app.routes and all(getattr(route, "path", "") != "/me" for route in app.routes)


# --- the called factory is untouched ----------------------------------------------------


@pytest.mark.parametrize("which", ["current_session", "optional_session"])
def test_calling_the_factory_normally_is_unaffected(which: str) -> None:
    _verifier, auth = one_verifier()
    factory: Factory = getattr(auth, which)

    assert callable(factory())
    assert factory(user_model=User) is factory(user_model=User)


# --- the one planting the build-time guarantee cannot reach ----------------------------


def overridden_app(which: str) -> tuple[FakeVerifier, FastAPI]:
    """A correctly built app, with the missing-parentheses typo written into the override map."""
    verifier, auth = one_verifier()
    required = auth.current_session()

    async def endpoint(session: Session[User] = Depends(required)) -> dict[str, str]:
        return {"id": session.user.id}

    app = FastAPI()
    app.add_api_route("/me", endpoint, methods=["GET"], response_model=None)
    app.dependency_overrides[required] = getattr(auth, which)
    return verifier, app


@pytest.mark.parametrize("which", ["current_session", "optional_session"])
def test_a_bare_factory_in_the_override_map_is_not_seen_until_the_first_request(
    which: str,
) -> None:
    """The limit of the build-time guarantee, pinned rather than implied.

    `app.dependency_overrides` is a plain dict FastAPI owns and we do not. Assigning into it
    runs no code of ours and offers no hook, so the same typo written as an override *value*
    cannot be refused when it is written: the application builds, starts, and reports healthy.
    The guard still fires, with the same message, at the first request that touches the
    overridden dependency - which is why the docstrings claim build-time refusal for every
    `Depends` / `Security` planting and name this one separately (D-107).
    """
    verifier, app = overridden_app(which)

    with client(app) as http, pytest.raises(ConfigurationError) as caught:
        http.get("/me", headers={HEADER: GOOD_CREDENTIAL})

    assert str(caught.value) == BARE_FACTORY
    assert verifier.extract_calls == 0
    assert verifier.verify_calls == 0


@pytest.mark.parametrize("which", ["current_session", "optional_session"])
def test_the_override_planting_still_fails_closed(which: str) -> None:
    """What makes it a limit rather than a bypass. The answer is an untranslated 500 instead of
    this library's refusal shape, and no request is served either way: nothing is extracted,
    nothing is verified, and no 2xx is produced - with a credential or without one. A guarantee
    that degrades to *unavailable* is a limit; one that degrades to *authenticated* would be the
    WP3 bypass again."""
    verifier, app = overridden_app(which)

    with TestClient(app, raise_server_exceptions=False) as http:
        credentialed = http.get("/me", headers={HEADER: GOOD_CREDENTIAL})
        anonymous = http.get("/me")

    assert credentialed.status_code == 500
    assert anonymous.status_code == 500
    assert verifier.extract_calls == 0
    assert verifier.verify_calls == 0


def test_the_guard_default_renders_as_what_it_is() -> None:
    """It is the default of a parameter on a public method, so it is printed by `help()` and
    by every signature dump. A memory address there says nothing and changes every run."""
    signature = inspect.signature(BetterAuth.current_session)

    assert repr(signature.parameters["_guard"].default) == "<not a dependency>"


def test_a_correctly_called_factory_builds_a_working_route(client_backend: str) -> None:
    verifier, auth = one_verifier()
    required = auth.current_session()
    router = APIRouter(dependencies=[Depends(required)])
    router.add_api_route("/me", read, methods=["GET"])
    app = FastAPI()
    app.include_router(router)

    with client(app, client_backend) as http:
        anonymous = http.get("/me")
        authorized = http.get("/me", headers={HEADER: GOOD_CREDENTIAL})

    assert anonymous.status_code == 401
    assert authorized.status_code == 200
    assert verifier.verify_calls == 1
