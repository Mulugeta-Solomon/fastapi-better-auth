"""The dependency factories — and the memoization that makes FastAPI's cache work.

FastAPI keys its per-request dependency cache on the *identity of the callable*. A factory
that built a fresh closure on every call would produce a fresh cache key on every call, so
a router-level dependency and a route-level dependency would verify the same request twice
— two JWKS-cache reads in Mode B, two calls against upstream's 100 req/60s bucket in Mode
C, and two chances to disagree. The spy tests below are the executable form of that rule.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from fastapi import APIRouter, Depends, FastAPI, Request, Response, WebSocket
from fastapi.exception_handlers import http_exception_handler
from typing_extensions import assert_type

from fastapi_better_auth import (
    BetterAuth,
    ConfigurationError,
    MissingCredential,
    Session,
    User,
)
from tests.fakes import (
    BAD_CREDENTIAL,
    GOOD_CREDENTIAL,
    FakeVerifier,
    client,
    resolver_of,
    session_app,
)

HEADER = "x-cred-a"
HEADER_B = "x-cred-b"


class AdminUser(User):
    """A deployment's own model, carried through the dependency unchanged."""

    role: str | None = None


def one_verifier() -> tuple[FakeVerifier, BetterAuth]:
    verifier = FakeVerifier(HEADER)
    return verifier, BetterAuth(verifiers=[verifier])


# --- memoization --------------------------------------------------------------------


def test_the_same_user_model_yields_the_same_callable() -> None:
    _verifier, auth = one_verifier()

    assert auth.current_session(user_model=User) is auth.current_session(user_model=User)
    assert auth.optional_session(user_model=User) is auth.optional_session(user_model=User)


def test_the_default_user_model_memoizes_with_the_explicit_one() -> None:
    _verifier, auth = one_verifier()

    assert auth.current_session() is auth.current_session(user_model=User)


def test_a_different_user_model_yields_a_different_callable() -> None:
    _verifier, auth = one_verifier()

    assert auth.current_session(user_model=AdminUser) is not auth.current_session(user_model=User)


def test_required_and_optional_are_different_callables() -> None:
    _verifier, auth = one_verifier()

    assert auth.current_session(user_model=User) is not auth.optional_session(user_model=User)


def test_both_factories_anchor_on_one_shared_resolver() -> None:
    """The white-box half of the spy tests: read the anchor FastAPI's cache keys on."""
    _verifier, auth = one_verifier()

    required = resolver_of(auth.current_session(user_model=User))
    optional = resolver_of(auth.optional_session(user_model=User))

    assert required is optional


def test_a_different_user_model_gets_its_own_resolver() -> None:
    _verifier, auth = one_verifier()

    assert resolver_of(auth.current_session(user_model=AdminUser)) is not resolver_of(
        auth.current_session(user_model=User)
    )


def test_the_optional_default_user_model_memoizes_with_the_explicit_one() -> None:
    _verifier, auth = one_verifier()

    assert auth.optional_session() is auth.optional_session(user_model=User)


def test_a_rejected_user_model_does_not_poison_the_cache() -> None:
    """The non-obvious half of the memoization contract: a `ConfigurationError` must leave
    nothing half-written, or the next good call would hand out a second callable."""
    _verifier, auth = one_verifier()

    with pytest.raises(ConfigurationError):
        auth.current_session(user_model=str)  # pyright: ignore[reportArgumentType]

    assert auth.current_session(user_model=User) is auth.current_session(user_model=User)


def test_two_apps_never_share_a_cache() -> None:
    _first, one = one_verifier()
    _second, other = one_verifier()

    assert one.current_session(user_model=User) is not other.current_session(user_model=User)


def test_each_factory_is_typed_as_the_user_model_it_was_asked_for() -> None:
    """Checked by pyright, not at runtime, and that is the point: a route body must see
    `Session[AdminUser]` without a cast, and `Session[Any]` would pass every assignment
    test while silently deleting the guarantee."""
    _verifier, auth = one_verifier()

    assert_type(
        auth.current_session(user_model=AdminUser), Callable[..., Awaitable[Session[AdminUser]]]
    )
    assert_type(auth.current_session(), Callable[..., Awaitable[Session[User]]])
    assert_type(
        auth.optional_session(user_model=AdminUser),
        Callable[..., Awaitable["Session[AdminUser] | None"]],
    )
    assert_type(auth.optional_session(), Callable[..., Awaitable["Session[User] | None"]])


# --- the spy tests: exactly one verification per request ------------------------------


def router_and_route_app() -> tuple[FakeVerifier, FastAPI]:
    verifier, auth = one_verifier()
    required = auth.current_session(user_model=User)
    router = APIRouter(dependencies=[Depends(required)])

    async def read(session: Session[User] = Depends(required)) -> dict[str, str]:
        return {"id": session.user.id}

    router.add_api_route("/me", read, methods=["GET"])
    app = FastAPI()
    app.include_router(router)
    return verifier, app


def both_factories_app() -> tuple[FakeVerifier, FastAPI]:
    verifier, auth = one_verifier()
    required = auth.current_session(user_model=User)
    optional = auth.optional_session(user_model=User)

    async def read(
        session: Session[User] = Depends(required),
        maybe: Session[User] | None = Depends(optional),
    ) -> dict[str, Any]:
        return {"id": session.user.id, "same": maybe is session}

    app = FastAPI()
    app.add_api_route("/me", read, methods=["GET"])
    return verifier, app


def test_a_router_level_and_a_route_level_dependency_verify_once(client_backend: str) -> None:
    verifier, app = router_and_route_app()
    with client(app, client_backend) as http:
        response = http.get("/me", headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 200
    assert verifier.verify_calls == 1


def test_required_and_optional_on_one_route_verify_once(client_backend: str) -> None:
    verifier, app = both_factories_app()
    with client(app, client_backend) as http:
        response = http.get("/me", headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 200
    assert verifier.verify_calls == 1
    assert response.json() == {"id": "u1", "same": True}


def test_the_spy_counts_across_requests_rather_than_within_one() -> None:
    """Prove the instrument: a counter stuck at 1 would pass both tests above."""
    verifier, app = router_and_route_app()
    with client(app) as http:
        for _ in range(3):
            http.get("/me", headers={HEADER: GOOD_CREDENTIAL})

    assert verifier.verify_calls == 3


# --- the two contracts ----------------------------------------------------------------


def test_current_session_refuses_an_anonymous_request(client_backend: str) -> None:
    _verifier, auth = one_verifier()
    with client(session_app(auth), client_backend) as http:
        response = http.get("/required")

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}
    assert response.headers["www-authenticate"] == "Bearer"


def test_optional_session_returns_none_for_an_anonymous_request(client_backend: str) -> None:
    _verifier, auth = one_verifier()
    with client(session_app(auth), client_backend) as http:
        response = http.get("/optional")

    assert response.status_code == 200
    assert response.json() == {"id": None, "model": None}


def test_optional_session_never_swallows_an_invalid_credential(client_backend: str) -> None:
    """D-004: `None` means "nobody asked", never "somebody asked badly"."""
    _verifier, auth = one_verifier()
    with client(session_app(auth), client_backend) as http:
        response = http.get("/optional", headers={HEADER: BAD_CREDENTIAL})

    assert response.status_code == 401


def test_optional_session_never_swallows_ambiguity() -> None:
    auth = BetterAuth(verifiers=[FakeVerifier(HEADER), FakeVerifier(HEADER_B)])
    with client(session_app(auth)) as http:
        response = http.get(
            "/optional", headers={HEADER: GOOD_CREDENTIAL, HEADER_B: GOOD_CREDENTIAL}
        )

    assert response.status_code == 400


def test_optional_session_never_swallows_a_malformed_payload() -> None:
    verifier = FakeVerifier(HEADER, payload={"id": ""})
    auth = BetterAuth(verifiers=[verifier])
    with client(session_app(auth)) as http:
        response = http.get("/optional", headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 401


def test_the_missing_credential_reason_names_the_verifiers_that_were_asked() -> None:
    _verifier, auth = one_verifier()
    observed: list[MissingCredential] = []
    app = session_app(auth)

    async def record(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, MissingCredential)
        observed.append(exc)
        return await http_exception_handler(request, exc)

    app.add_exception_handler(MissingCredential, record)
    with client(app) as http:
        response = http.get("/required")

    assert response.status_code == 401
    assert observed
    assert "FakeVerifier" in observed[0].reason


# --- the user model travels through the dependency ------------------------------------


def test_a_subclass_user_model_survives_the_round_trip(client_backend: str) -> None:
    verifier = FakeVerifier(HEADER, payload={"id": "u1", "role": "admin"})
    auth = BetterAuth(verifiers=[verifier])
    with client(session_app(auth, user_model=AdminUser), client_backend) as http:
        response = http.get("/required", headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 200
    assert response.json() == {"id": "u1", "model": "AdminUser"}


# --- websockets are connections too ----------------------------------------------------


def test_the_dependency_resolves_on_a_websocket(client_backend: str) -> None:
    """`HTTPConnection`, not `Request`: the same dependency has to work on both, and
    nothing in the resolver may reach for an HTTP-only attribute."""
    verifier, auth = one_verifier()
    required = auth.current_session(user_model=User)
    app = FastAPI()

    async def socket(
        websocket: WebSocket,
        session: Session[User] = Depends(required),
    ) -> None:
        await websocket.accept()
        await websocket.send_text(session.user.id)
        await websocket.close()

    app.add_api_websocket_route("/ws", socket)
    with (
        client(app, client_backend) as http,
        http.websocket_connect("/ws", headers={HEADER: GOOD_CREDENTIAL}) as ws,
    ):
        received = ws.receive_text()

    assert received == "u1"
    assert verifier.verify_calls == 1


@pytest.mark.parametrize("path", ["/required", "/optional"])
def test_the_connection_parameter_never_becomes_a_documented_query_parameter(path: str) -> None:
    """FastAPI resolves `HTTPConnection` from the ASGI scope; anything it did not
    recognize would surface as a required query parameter and break every route."""
    _verifier, auth = one_verifier()
    with client(session_app(auth)) as http:
        document: dict[str, Any] = http.get("/openapi.json").json()

    operation: dict[str, Any] = document["paths"][path]["get"]
    assert operation.get("parameters", []) == []
    assert "requestBody" not in operation
