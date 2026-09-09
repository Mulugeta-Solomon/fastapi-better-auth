"""`require(predicate, ...)` — a policy gate over a session that is already verified.

Authorization is the layer *after* authentication, and the order is the security property: an
anonymous or forged request is answered 401 by the session dependency this gate composes on, and
never reaches the predicate at all. Only a request that proved who it is can be told it may not do
something, so a 403 from here is never an oracle for "does this credential work".

The predicate is a plain synchronous callable the consumer writes, which makes it the one place a
bug of theirs reaches this library's refusal path. Every way that can go wrong is driven here: an
answer that is not exactly `True`, an exception, a refusal the consumer chose on purpose, and an
`async def` predicate whose coroutine object would have been truthy — and so refused — forever.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from typing import Any

import httpx2
import pytest
from fastapi import Depends, FastAPI, Request, Response
from fastapi.exception_handlers import http_exception_handler

from fastapi_better_auth import (
    BetterAuth,
    ConfigurationError,
    CsrfFailure,
    NotAuthorized,
    Session,
    SessionError,
    SessionRevoked,
    User,
)
from fastapi_better_auth._internal.core import BARE_FACTORY
from tests.fakes import BAD_CREDENTIAL, GOOD_CREDENTIAL, FakeVerifier, client
from tests.log_hygiene import capturing, rendered

HEADER = "x-cred-a"
BEARER_SOURCE = "header:authorization-bearer"
REASON = "editor role required"
FORBIDDEN = {"detail": "Forbidden"}
UNAUTHENTICATED = {"detail": "Not authenticated"}
EDITOR: dict[str, Any] = {"id": "u1", "role": "editor"}
READER: dict[str, Any] = {"id": "u2", "role": "reader"}
FRAGMENT = 4
"""A needle shorter than this matches by accident, not by leak."""

FACTORIES = ("current_session", "optional_session", "require", "require_membership")


class Member(User):
    """A deployment's own user model — what `user_model=` is for."""

    role: str | None = None


def one_verifier(
    payload: dict[str, Any] = EDITOR, *, source: str | None = None
) -> tuple[FakeVerifier, BetterAuth]:
    verifier = FakeVerifier(HEADER, payload=payload, source=source)
    return verifier, BetterAuth(verifiers=[verifier])


def is_editor(session: Session[Member]) -> bool:
    return session.user.role == "editor"


def answering(answer: object) -> Callable[[Session[Member]], object]:
    """A predicate that hands back one prepared answer, whatever shape it is."""

    def decide(_session: Session[Member]) -> object:
        return answer

    return decide


async def read_nothing() -> dict[str, str]:
    return {"reached": "yes"}


def guarded_app(auth: BetterAuth, predicate: Any) -> FastAPI:
    """One route behind `require`, so a refusal is observable on the wire."""
    app = FastAPI()
    editors = auth.require(predicate, reason=REASON, user_model=Member)

    async def read(session: Session[Member] = Depends(editors)) -> dict[str, Any]:
        return {"id": session.user.id, "model": type(session.user).__name__}

    app.add_api_route("/editor", read, methods=["GET"], response_model=None)
    return app


def recording_app(auth: BetterAuth, predicate: Any) -> tuple[FastAPI, list[SessionError]]:
    """The operator's side of a refusal: a handler that keeps the exception, then answers
    exactly as FastAPI's own handler would."""
    app = guarded_app(auth, predicate)
    observed: list[SessionError] = []

    async def record(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, SessionError)
        observed.append(exc)
        return await http_exception_handler(request, exc)

    app.add_exception_handler(SessionError, record)
    return app, observed


def observable(response: httpx2.Response) -> str:
    headers = "\n".join(f"{key}: {value}" for key, value in response.headers.items())
    return f"{headers}\n{response.text}".lower()


def leaked(reason: str, response: httpx2.Response) -> tuple[str, ...]:
    """The whole reason plus every word long enough to be a recognizable fragment."""
    blob = observable(response)
    needles = (reason, *(word for word in reason.split() if len(word) >= FRAGMENT))
    return tuple(needle for needle in needles if needle.lower() in blob)


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


# --- the two answers ---------------------------------------------------------------------


def test_a_predicate_that_passes_lets_the_route_run(client_backend: str) -> None:
    verifier, auth = one_verifier()

    with client(guarded_app(auth, is_editor), client_backend) as http:
        response = http.get("/editor", headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 200
    assert response.json() == {"id": "u1", "model": "Member"}
    assert verifier.verify_calls == 1


def test_a_predicate_that_refuses_is_a_uniform_403_with_no_challenge(client_backend: str) -> None:
    """The sanctioned 403 shape: the same body every other 403 renders, and no
    `WWW-Authenticate` — the request carried a credential, so there is nothing to
    re-authenticate."""
    _verifier, auth = one_verifier(READER)

    with client(guarded_app(auth, is_editor), client_backend) as http:
        response = http.get("/editor", headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 403
    assert response.json() == FORBIDDEN
    assert "www-authenticate" not in response.headers


def test_the_refusal_reason_reaches_the_operator_and_never_the_client() -> None:
    """`reason` names the operator's rule and the user id, so the log line is actionable; the
    response says neither. The oracle covers the class; this covers the text built here."""
    _verifier, auth = one_verifier(READER)
    app, observed = recording_app(auth, is_editor)

    with client(app) as http:
        response = http.get("/editor", headers={HEADER: GOOD_CREDENTIAL})

    assert [type(exc) for exc in observed] == [NotAuthorized]
    assert [exc.reason for exc in observed] == [f"{REASON} refused for user u2"]
    assert leaked(observed[0].reason, response) == (), "the reason reached the client"


# --- only True passes --------------------------------------------------------------------


@pytest.mark.parametrize(
    "answer",
    [1, "yes", [1], object(), 0.5],
    ids=["one", "non-empty-string", "non-empty-list", "object", "float"],
)
def test_a_truthy_answer_that_is_not_true_refuses(answer: object) -> None:
    """A predicate states a decision, and `if predicate(...)` would have admitted every
    accidental truthy value: a stray coroutine, a database row, a non-empty error string."""
    _verifier, auth = one_verifier()

    with client(guarded_app(auth, answering(answer))) as http:
        response = http.get("/editor", headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 403
    assert response.json() == FORBIDDEN


@pytest.mark.parametrize("answer", [False, None, 0, ""], ids=["false", "none", "zero", "empty"])
def test_a_falsy_answer_refuses(answer: object) -> None:
    _verifier, auth = one_verifier()

    with client(guarded_app(auth, answering(answer))) as http:
        response = http.get("/editor", headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 403


# --- a predicate that misbehaves ----------------------------------------------------------


def test_a_predicate_that_raises_fails_closed_and_is_logged(
    records: list[logging.LogRecord],
) -> None:
    """A consumer's bug must not become a 500 — the one answer a client can tell apart from
    every other, and under a debug handler a traceback out of this request's frames."""

    def explode(_session: Session[Member]) -> bool:
        raise RuntimeError("policy table unreachable")

    _verifier, auth = one_verifier()

    with client(guarded_app(auth, explode)) as http:
        response = http.get("/editor", headers={HEADER: GOOD_CREDENTIAL})

    written = rendered(records)
    assert response.status_code == 403
    assert response.json() == FORBIDDEN
    assert "policy table unreachable" in written, "the operator lost the real exception"
    assert "policy table unreachable" not in observable(response)


def test_the_reason_for_an_escaped_predicate_names_the_exception_type() -> None:
    """The type is what an operator needs to find the bug; the message is the consumer's own
    text, which may hold anything at all, so it stays in the traceback and out of `reason`."""

    def explode(_session: Session[Member]) -> bool:
        raise ZeroDivisionError("policy divisor was zero")

    _verifier, auth = one_verifier()
    app, observed = recording_app(auth, explode)

    with capturing(), client(app) as http:
        http.get("/editor", headers={HEADER: GOOD_CREDENTIAL})

    assert [type(exc) for exc in observed] == [NotAuthorized]
    assert "ZeroDivisionError" in observed[0].reason
    assert "policy divisor was zero" not in observed[0].reason


@pytest.mark.parametrize("error", [CsrfFailure, SessionRevoked], ids=["csrf-403", "revoked-401"])
def test_a_session_error_raised_by_a_predicate_keeps_its_own_wire_shape(
    error: type[SessionError],
) -> None:
    """Containment is for accidents. A refusal the consumer *chose* — one of ours, or their
    own sanctioned subclass — must keep the status and headers it declared."""

    def refuse(_session: Session[Member]) -> bool:
        raise error(reason="the deployment's own rule refused this session")

    _verifier, auth = one_verifier()

    with capturing(), client(guarded_app(auth, refuse)) as http:
        response = http.get("/editor", headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == error.response_status
    assert ("www-authenticate" in response.headers) is (error.response_headers is not None)


def test_a_configuration_error_raised_by_a_predicate_is_not_degraded_into_a_403() -> None:
    """A broken deployment stays loud. A uniform 403 would hide it forever, and would look
    exactly like a policy that simply says no."""

    def refuse(_session: Session[Member]) -> bool:
        raise ConfigurationError("the policy engine was never configured")

    _verifier, auth = one_verifier()

    with capturing(), client(guarded_app(auth, refuse)) as http, pytest.raises(ConfigurationError):
        http.get("/editor", headers={HEADER: GOOD_CREDENTIAL})


def test_an_async_predicate_is_a_configuration_error_not_a_permanent_403() -> None:
    """A coroutine object is truthy but is never `True`, so an `async def` predicate would
    refuse every request forever — silently, and indistinguishably from a policy that says no.

    `filterwarnings = error` is the second half of this test: the coroutine is closed before
    the refusal, so an unawaited-coroutine warning cannot be what a reader sees instead.
    """

    async def slow(_session: Session[Member]) -> bool:
        return True

    _verifier, auth = one_verifier()

    with client(guarded_app(auth, slow)) as http, pytest.raises(ConfigurationError) as caught:
        http.get("/editor", headers={HEADER: GOOD_CREDENTIAL})

    assert "async" in str(caught.value)


# --- authentication comes first -----------------------------------------------------------


def test_an_anonymous_request_is_401_and_never_reaches_the_predicate(client_backend: str) -> None:
    """401 before 403, always. A request that has not said who it is must not be able to learn
    anything about what it would have been allowed to do."""
    asked: list[str] = []
    _verifier, auth = one_verifier()

    def watching(session: Session[Member]) -> bool:
        asked.append(session.user.id)
        return True

    with client(guarded_app(auth, watching), client_backend) as http:
        response = http.get("/editor")

    assert response.status_code == 401
    assert response.json() == UNAUTHENTICATED
    assert response.headers["www-authenticate"] == "Bearer"
    assert asked == []


def test_a_forged_credential_is_401_and_never_reaches_the_predicate(client_backend: str) -> None:
    asked: list[str] = []
    _verifier, auth = one_verifier()

    def watching(session: Session[Member]) -> bool:
        asked.append(session.user.id)
        return True

    with client(guarded_app(auth, watching), client_backend) as http:
        response = http.get("/editor", headers={HEADER: BAD_CREDENTIAL})

    assert response.status_code == 401
    assert response.json() == UNAUTHENTICATED
    assert asked == []


# --- composition --------------------------------------------------------------------------


def test_a_route_declaring_both_the_session_and_the_gate_verifies_exactly_once(
    client_backend: str,
) -> None:
    """The gate composes on the memoized `current_session`, so FastAPI's per-request cache
    sees one dependency. Two JWKS reads, or two calls against upstream's rate limit, would
    otherwise be the price of asking for authorization."""
    verifier, auth = one_verifier()
    current = auth.current_session(user_model=Member)
    editors = auth.require(is_editor, reason=REASON, user_model=Member)

    async def read(
        session: Session[Member] = Depends(current),
        gated: Session[Member] = Depends(editors),
    ) -> dict[str, Any]:
        return {"same": session is gated}

    app = FastAPI()
    app.add_api_route("/both", read, methods=["GET"], response_model=None)

    with client(app, client_backend) as http:
        response = http.get("/both", headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 200
    assert response.json() == {"same": True}
    assert verifier.verify_calls == 1


def test_each_call_builds_a_new_dependency() -> None:
    """Unlike the session factories, these are not memoized: two calls are two policies, and
    handing back one shared callable would make the second silently be the first."""
    _verifier, auth = one_verifier()

    first = auth.require(is_editor, reason=REASON, user_model=Member)
    second = auth.require(is_editor, reason=REASON, user_model=Member)

    assert first is not second


def test_a_gated_route_declares_the_security_scheme_docs_needs() -> None:
    """A route behind the gate still has to be exercisable from `/docs`: the declaration hangs
    off the shared resolver, so composing on it changes nothing about what is published."""
    _verifier, auth = one_verifier(source=BEARER_SOURCE)

    with client(guarded_app(auth, is_editor)) as http:
        document: dict[str, Any] = http.get("/openapi.json").json()

    assert document["paths"]["/editor"]["get"]["security"] == [{"BetterAuthBearer": []}]


# --- build-time refusals --------------------------------------------------------------------


@pytest.mark.parametrize("which", FACTORIES)
def test_a_bare_factory_is_refused_while_the_route_is_registered(which: str) -> None:
    """The missing-parentheses bypass, now for four factories. Passed bare, the factory itself
    becomes the dependency: FastAPI calls it, discards what it returns, and the gate guards
    nothing at all."""
    _verifier, auth = one_verifier()
    app = FastAPI()

    with pytest.raises(ConfigurationError) as caught:
        app.add_api_route(
            "/x", read_nothing, methods=["GET"], dependencies=[Depends(getattr(auth, which))]
        )

    message = str(caught.value)
    assert message == BARE_FACTORY
    assert f"Depends(auth.{which}(" in message
    assert "parentheses" in message


@pytest.mark.parametrize("model", [object(), str, dict], ids=["instance", "str", "dict"])
def test_a_user_model_that_is_not_a_user_is_refused_at_build(model: object) -> None:
    _verifier, auth = one_verifier()

    with pytest.raises(ConfigurationError):
        auth.require(is_editor, reason=REASON, user_model=model)  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize("predicate", [None, "is_editor", 7], ids=["none", "string", "int"])
def test_a_predicate_that_is_not_callable_is_refused_at_build(predicate: object) -> None:
    """Built at import time, so a typo here stops the deployment rather than refusing every
    request forever with a 403 that looks like policy."""
    _verifier, auth = one_verifier()

    with pytest.raises(ConfigurationError):
        auth.require(predicate, reason=REASON, user_model=Member)  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize("reason", ["", "   ", None, 7], ids=["empty", "blank", "none", "int"])
def test_a_blank_reason_is_refused_at_build(reason: object) -> None:
    """`reason` is the whole of what an operator reads when the gate fires; a blank one makes
    the log line useless at exactly the moment it is needed."""
    _verifier, auth = one_verifier()

    with pytest.raises(ConfigurationError):
        auth.require(is_editor, reason=reason, user_model=Member)  # pyright: ignore[reportArgumentType]
