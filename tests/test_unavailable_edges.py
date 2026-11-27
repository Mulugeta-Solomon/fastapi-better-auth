"""The opt-in 503 at its edges: the house envelope, a WebSocket handshake, and every path that
reaches a client without passing through the dispatcher.

A rule callable is part of the bridge and follows its setting. Route code that calls a store or a
verifier itself is outside the bridge and keeps the exception as raised: the 401 with its
challenge. Those cases are pinned so a change to them is a decision, not an accident.
"""

from __future__ import annotations

import logging
import pathlib
from typing import Any, cast

import pytest
from exceptiongroup import ExceptionGroup
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse
from starlette.testclient import WebSocketDenialResponse

from fastapi_better_auth import (
    AuthorizationRefused,
    AuthServiceUnavailable,
    BetterAuth,
    ConfigurationError,
    InvalidCredential,
    NotAuthorized,
    Session,
    SessionError,
    User,
)
from fastapi_better_auth._internal.unavailable import AuthServiceUnavailable503
from tests.cookies import FakeStore
from tests.fakes import GOOD_CREDENTIAL, FakeVerifier, TestClient
from tests.remote_fixtures import ORIGIN
from tests.stores import TOKEN, USER_ID, DeniedError, DriverFault, StoreFixture
from tests.transports import ScriptedTransport
from tests.unavailable_support import (
    UNKNOWN_CREDENTIAL_401,
    RaisingVerifier,
    service_unavailable,
    wire,
)

HEADER = "x-cred"
REASON = "session store lookup could not complete [fp=9f3ab21c]"
RETRY_AFTER = 7
OPT_IN: dict[str, Any] = {"unavailable_status": 503, "unavailable_retry_after": RETRY_AFTER}

logger = logging.getLogger("myapp.auth")


def unavailable() -> AuthServiceUnavailable:
    return AuthServiceUnavailable(reason=REASON)


def get(app: FastAPI, path: str = "/required", **headers: str) -> Any:
    with TestClient(app) as http:
        return http.get(path, headers=headers)


# --- the house envelope from docs/errors.md ------------------------------------------------


def enveloped(auth: BetterAuth) -> FastAPI:
    """The docs' handler, verbatim in what it reads: three constants, no `isinstance` branch."""
    app = FastAPI()
    current = auth.current_session()

    async def envelope(request: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, SessionError)
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

    async def me(session: Session[User] = Depends(current)) -> dict[str, Any]:
        return {"success": True, "data": {"id": session.user.id}, "error": None}

    app.add_exception_handler(SessionError, envelope)
    app.add_api_route("/required", me, methods=["GET"])
    return app


def test_the_envelope_renders_the_503_from_the_three_constants() -> None:
    app = enveloped(BetterAuth(verifiers=[RaisingVerifier(HEADER, unavailable)], **OPT_IN))

    response = get(app, **{HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 503
    assert response.json() == {
        "success": False,
        "data": None,
        "error": {"code": 503, "message": "Service unavailable"},
    }
    assert response.headers["retry-after"] == str(RETRY_AFTER)
    assert "www-authenticate" not in response.headers


def test_the_envelope_renders_the_default_401_as_before() -> None:
    app = enveloped(BetterAuth(verifiers=[RaisingVerifier(HEADER, unavailable)]))

    response = get(app, **{HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 401
    assert response.json()["error"] == {"code": 401, "message": "Not authenticated"}
    assert response.headers["www-authenticate"] == "Bearer"
    assert "retry-after" not in response.headers


# --- a WebSocket handshake -----------------------------------------------------------------


def socket_app(auth: BetterAuth) -> FastAPI:
    app = FastAPI()
    current = auth.current_session()

    async def socket(websocket: WebSocket, session: Session[User] = Depends(current)) -> None:
        await websocket.accept()
        await websocket.close()

    app.add_api_websocket_route("/ws", socket)
    return app


def denial(auth: BetterAuth) -> WebSocketDenialResponse:
    with (
        TestClient(socket_app(auth)) as http,
        pytest.raises(WebSocketDenialResponse) as caught,
        http.websocket_connect("/ws", headers={HEADER: GOOD_CREDENTIAL}),
    ):
        pass  # pragma: no cover - the handshake is refused before it is accepted
    return caught.value


def test_a_websocket_handshake_is_denied_with_the_default_401() -> None:
    refused = denial(BetterAuth(verifiers=[RaisingVerifier(HEADER, unavailable)]))

    assert wire(refused) == UNKNOWN_CREDENTIAL_401


def test_a_websocket_handshake_is_denied_with_the_503_under_the_opt_in() -> None:
    refused = denial(BetterAuth(verifiers=[RaisingVerifier(HEADER, unavailable)], **OPT_IN))

    assert wire(refused) == service_unavailable(RETRY_AFTER)


# --- paths that do not pass through the dispatcher -------------------------------------------


def ruled_app(auth: BetterAuth, refusal: Any) -> FastAPI:
    """A predicate and a membership lookup that raise `refusal()` after authentication."""
    app = FastAPI()

    def predicate(session: Session[User]) -> bool:
        raise refusal()

    async def member(org_id: str, session: Session[User]) -> str:
        raise refusal()

    gate = auth.require(predicate, reason="calls the store")
    scoped = auth.require_membership("org_id", member, reason="calls the store")

    async def gated(session: Session[User] = Depends(gate)) -> dict[str, str]:
        return {"id": session.user.id}

    async def membered(access: Any = Depends(scoped)) -> dict[str, str]:
        return {"grant": access.grant}

    app.add_api_route("/gated", gated, methods=["GET"])
    app.add_api_route("/orgs/{org_id}", membered, methods=["GET"])
    return app


RULE_PATHS = ["/gated", "/orgs/org_a"]


@pytest.mark.parametrize("path", RULE_PATHS)
def test_a_rule_raising_unavailable_answers_the_bridge_s_503_with_the_opt_in(path: str) -> None:
    """Rules follow the bridge's setting: a verified session is never told to sign in again."""
    app = ruled_app(BetterAuth(verifiers=[FakeVerifier(HEADER)], **OPT_IN), unavailable)

    assert wire(get(app, path, **{HEADER: GOOD_CREDENTIAL})) == service_unavailable(RETRY_AFTER)


@pytest.mark.parametrize("path", RULE_PATHS)
def test_a_rule_raising_unavailable_in_a_task_group_is_converted_too(path: str) -> None:
    def grouped() -> BaseException:
        return ExceptionGroup("one leaf", [unavailable()])

    app = ruled_app(BetterAuth(verifiers=[FakeVerifier(HEADER)], **OPT_IN), grouped)

    assert wire(get(app, path, **{HEADER: GOOD_CREDENTIAL})) == service_unavailable(RETRY_AFTER)


@pytest.mark.parametrize("path", RULE_PATHS)
def test_a_rule_raising_the_503_form_is_the_401_through_a_default_bridge(path: str) -> None:
    """With the switch off, nothing a bridge built answers 503, the rules included."""

    def foreign() -> AuthServiceUnavailable503:
        return AuthServiceUnavailable503(reason=REASON, retry_after=99)

    app = ruled_app(BetterAuth(verifiers=[FakeVerifier(HEADER)]), foreign)

    assert wire(get(app, path, **{HEADER: GOOD_CREDENTIAL})) == UNKNOWN_CREDENTIAL_401


def rule_seen(auth: BetterAuth, refusal: Any, path: str) -> BaseException:
    app = ruled_app(auth, refusal)
    seen: list[BaseException] = []

    async def record(request: Request, exc: Exception) -> Response:
        seen.append(exc)
        return await http_exception_handler(request, cast("HTTPException", exc))

    app.add_exception_handler(HTTPException, record)
    get(app, path, **{HEADER: GOOD_CREDENTIAL})
    (only,) = seen
    return only


@pytest.mark.parametrize("path", RULE_PATHS)
def test_by_default_a_rule_s_unavailable_reaches_the_handler_as_the_same_object(path: str) -> None:
    raised = unavailable()

    seen = rule_seen(BetterAuth(verifiers=[FakeVerifier(HEADER)]), lambda: raised, path)

    assert seen is raised


@pytest.mark.parametrize("path", RULE_PATHS)
@pytest.mark.parametrize(
    "build",
    [
        lambda: NotAuthorized(reason="rule said no"),
        lambda: AuthorizationRefused(status_code=404, detail={"code": "gone"}),
    ],
    ids=["not-authorized", "authorization-refused"],
)
def test_with_the_opt_in_every_other_rule_refusal_is_the_same_object(path: str, build: Any) -> None:
    raised = build()

    seen = rule_seen(BetterAuth(verifiers=[FakeVerifier(HEADER)], **OPT_IN), lambda: raised, path)

    assert seen is raised


def test_a_refusal_edited_to_503_still_passes_a_default_bridge_as_on_main() -> None:
    """The off-switch guard keys on the private 503 form. A `SessionError` instance a verifier
    edits by hand is re-raised as itself, exactly as `main` does; left for the maintainer."""

    def edited() -> SessionError:
        refusal = InvalidCredential(reason=REASON)
        refusal.status_code = 503
        return refusal

    app = FastAPI()
    current = BetterAuth(verifiers=[RaisingVerifier(HEADER, edited)]).current_session()

    async def me(session: Session[User] = Depends(current)) -> dict[str, str]:
        return {"id": session.user.id}

    app.add_api_route("/required", me, methods=["GET"])

    assert get(app, **{HEADER: GOOD_CREDENTIAL}).status_code == 503


def test_route_code_calling_the_store_answers_the_401_even_with_the_opt_in() -> None:
    store = FakeStore(session_error=unavailable(), user_error=unavailable())
    auth = BetterAuth(verifiers=[FakeVerifier(HEADER)], **OPT_IN)
    current = auth.current_session()
    app = FastAPI()

    async def lookup(session: Session[User] = Depends(current)) -> dict[str, Any]:
        return {"found": await store.fetch_session_by_token("other") is not None}

    async def user(session: Session[User] = Depends(current)) -> dict[str, Any]:
        return {"found": await store.fetch_user_by_id("u2") is not None}

    app.add_api_route("/lookup", lookup, methods=["GET"])
    app.add_api_route("/user", user, methods=["GET"])

    for path in ("/lookup", "/user"):
        assert wire(get(app, path, **{HEADER: GOOD_CREDENTIAL})) == UNKNOWN_CREDENTIAL_401


@pytest.mark.anyio
async def test_the_shipped_sql_store_refuses_route_code_with_the_401_form(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What route code calling the store itself gets during a refused statement: the 401 form,
    which FastAPI answers with the challenge whatever the bridge was built with."""
    build = StoreFixture(tmp_path, "sync")
    store, _ = build()
    fault = DriverFault(build.engines[-1], monkeypatch)
    try:
        assert await store.fetch_session_by_token("not-seeded") is None
        fault.error = DeniedError
        for lookup in (store.fetch_session_by_token(TOKEN), store.fetch_user_by_id(USER_ID)):
            with pytest.raises(AuthServiceUnavailable) as caught:
                await lookup
            assert type(caught.value) is AuthServiceUnavailable
            assert caught.value.status_code == 401
            assert caught.value.headers == {"WWW-Authenticate": "Bearer"}
    finally:
        await build.aclose()


def test_a_verifier_called_directly_answers_the_401_even_with_the_opt_in() -> None:
    verifier = RaisingVerifier(HEADER, unavailable)
    BetterAuth(verifiers=[verifier], **OPT_IN)
    app = FastAPI()

    async def direct(request: Request) -> dict[str, str]:
        credential = verifier.extract(request)
        assert credential is not None
        session = await verifier.verify(credential, User)
        return {"id": session.user.id}

    app.add_api_route("/required", direct, methods=["GET"])

    assert wire(get(app, **{HEADER: GOOD_CREDENTIAL})) == UNKNOWN_CREDENTIAL_401


@pytest.mark.anyio
async def test_startup_turns_an_unreachable_service_into_a_configuration_error() -> None:
    """`startup()` answers no client: an auth service that cannot answer at boot stops it."""
    from fastapi_better_auth import CsrfDisabled, RemoteVerifier

    transport = ScriptedTransport(OSError("connection refused"))
    verifier = RemoteVerifier(
        base_url=ORIGIN,
        transport=transport,
        csrf=CsrfDisabled(reason="the startup lane does not exercise CSRF"),
        secure_cookies=False,
    )
    auth = BetterAuth(verifiers=[verifier], **OPT_IN)

    with pytest.raises(ConfigurationError) as caught:
        await auth.startup()

    assert not isinstance(caught.value, SessionError)
