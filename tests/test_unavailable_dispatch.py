"""The opt-in 503 through a real FastAPI app: the one place it is decided is the dispatcher.

With the switch off, nothing that leaves the dispatcher is a 503, whatever a verifier raised, and
everything else is `main`'s answer byte for byte. With it on, only `AuthServiceUnavailable`
changes, and it changes the same way for every dependency the bridge hands out.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.exception_handlers import http_exception_handler

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuth,
    CsrfFailure,
    InvalidCredential,
    SessionError,
    SessionExpired,
    SessionRevoked,
)
from fastapi_better_auth._internal.unavailable import (
    DEFAULT_RETRY_AFTER,
    AuthServiceUnavailable503,
)
from tests.fakes import (
    BAD_CREDENTIAL,
    GOOD_CREDENTIAL,
    FakeVerifier,
    SessionErrorExtractVerifier,
    TestClient,
)
from tests.unavailable_support import (
    GATED_PATHS,
    UNKNOWN_CREDENTIAL_401,
    RaisingVerifier,
    gated_app,
    service_unavailable,
    wire,
)

HEADER = "x-cred"
OTHER_HEADER = "x-cred-b"
REASON = "session store lookup did not answer within 5.0s [fp=9f3ab21c]"
RETRY_AFTER = 7
OPT_IN: dict[str, Any] = {"unavailable_status": 503, "unavailable_retry_after": RETRY_AFTER}


def unavailable() -> AuthServiceUnavailable:
    return AuthServiceUnavailable(reason=REASON)


def foreign_503() -> AuthServiceUnavailable503:
    return AuthServiceUnavailable503(reason=REASON, retry_after=99)


class OddSignature(AuthServiceUnavailable):
    """A third-party subclass whose constructor takes something other than `reason=`."""

    def __init__(self, code: int) -> None:
        super().__init__(reason=f"upstream code {code}")


def bridge(verifier: Any, **settings: Any) -> BetterAuth:
    return BetterAuth(verifiers=[verifier], **settings)


def get(app: FastAPI, path: str = "/required", **headers: str) -> Any:
    with TestClient(app) as http:
        return http.get(path, headers=headers)


def unknown_credential_wire() -> Any:
    return wire(get(gated_app(bridge(FakeVerifier(HEADER))), **{HEADER: BAD_CREDENTIAL}))


def observing(auth: BetterAuth) -> tuple[FastAPI, list[SessionError]]:
    app = gated_app(auth)
    seen: list[SessionError] = []

    async def record(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, SessionError)
        seen.append(exc)
        return await http_exception_handler(request, exc)

    app.add_exception_handler(SessionError, record)
    return app, seen


# --- the default is main, byte for byte ---------------------------------------------------


def test_the_instrument_reads_the_uniform_401_for_an_unknown_credential() -> None:
    assert unknown_credential_wire() == UNKNOWN_CREDENTIAL_401


@pytest.mark.parametrize("path", GATED_PATHS)
def test_by_default_an_unavailable_service_is_the_unknown_credential_401(path: str) -> None:
    app = gated_app(bridge(RaisingVerifier(HEADER, unavailable)))

    assert wire(get(app, path, **{HEADER: GOOD_CREDENTIAL})) == UNKNOWN_CREDENTIAL_401


def test_by_default_the_handler_sees_the_very_exception_the_verifier_raised() -> None:
    raised = unavailable()
    app, seen = observing(bridge(RaisingVerifier(HEADER, lambda: raised)))

    get(app, **{HEADER: GOOD_CREDENTIAL})

    assert seen == [raised]
    assert seen[0] is raised


@pytest.mark.parametrize("in_task_group", [False, True], ids=["bare", "task-group"])
def test_by_default_the_503_form_from_a_custom_verifier_is_the_unknown_credential_401(
    in_task_group: bool,
) -> None:
    verifier = RaisingVerifier(HEADER, foreign_503, in_task_group=in_task_group)
    app, seen = observing(bridge(verifier))

    assert wire(get(app, **{HEADER: GOOD_CREDENTIAL})) == unknown_credential_wire()
    assert type(seen[0]) is AuthServiceUnavailable
    assert seen[0].reason == REASON


def test_by_default_a_third_party_subclass_passes_as_itself() -> None:
    raised = OddSignature(7)
    app, seen = observing(bridge(RaisingVerifier(HEADER, lambda: raised)))

    assert wire(get(app, **{HEADER: GOOD_CREDENTIAL})) == UNKNOWN_CREDENTIAL_401
    assert seen[0] is raised


# --- the opt-in --------------------------------------------------------------------------


@pytest.mark.parametrize("path", GATED_PATHS)
def test_with_the_opt_in_every_dependency_answers_the_503(path: str) -> None:
    app = gated_app(bridge(RaisingVerifier(HEADER, unavailable), **OPT_IN))

    assert wire(get(app, path, **{HEADER: GOOD_CREDENTIAL})) == service_unavailable(RETRY_AFTER)


def test_the_retry_after_defaults_when_only_the_status_is_given() -> None:
    app = gated_app(bridge(RaisingVerifier(HEADER, unavailable), unavailable_status=503))

    response = get(app, **{HEADER: GOOD_CREDENTIAL})

    assert wire(response) == service_unavailable(DEFAULT_RETRY_AFTER)


def test_with_the_opt_in_the_handler_sees_an_auth_service_unavailable_with_its_reason() -> None:
    app, seen = observing(bridge(RaisingVerifier(HEADER, unavailable), **OPT_IN))

    get(app, **{HEADER: GOOD_CREDENTIAL})

    (refusal,) = seen
    assert isinstance(refusal, AuthServiceUnavailable)
    assert refusal.reason == REASON
    assert refusal.status_code == 503


def test_the_converted_refusal_links_to_nothing() -> None:
    """Raised outside the handler and `from None`: no chain back to what the verifier raised."""
    app, seen = observing(bridge(RaisingVerifier(HEADER, unavailable), **OPT_IN))

    get(app, **{HEADER: GOOD_CREDENTIAL})

    (refusal,) = seen
    assert refusal.__cause__ is None
    assert refusal.__context__ is None
    assert refusal.__suppress_context__ is True


def test_with_the_opt_in_the_bridge_s_own_retry_after_wins_over_a_raised_one() -> None:
    app = gated_app(bridge(RaisingVerifier(HEADER, foreign_503), **OPT_IN))

    assert wire(get(app, **{HEADER: GOOD_CREDENTIAL})) == service_unavailable(RETRY_AFTER)


def test_with_the_opt_in_a_task_group_leaf_is_converted_too() -> None:
    verifier = RaisingVerifier(HEADER, unavailable, in_task_group=True)
    app = gated_app(bridge(verifier, **OPT_IN))

    assert wire(get(app, **{HEADER: GOOD_CREDENTIAL})) == service_unavailable(RETRY_AFTER)


def test_with_the_opt_in_a_third_party_subclass_is_converted_whatever_its_signature() -> None:
    app, seen = observing(bridge(RaisingVerifier(HEADER, lambda: OddSignature(7)), **OPT_IN))

    assert wire(get(app, **{HEADER: GOOD_CREDENTIAL})) == service_unavailable(RETRY_AFTER)
    assert seen[0].reason == "upstream code 7"


def test_with_the_opt_in_an_anonymous_request_is_still_none_on_the_optional_route() -> None:
    app = gated_app(bridge(RaisingVerifier(HEADER, unavailable), **OPT_IN))

    response = get(app, "/optional")

    assert response.status_code == 200
    assert response.json() == {"id": None}


def test_with_the_opt_in_an_unavailable_refusal_from_extract_stays_contained() -> None:
    """`extract` may not refuse; whatever it raises is the uniform `InvalidCredential`."""
    verifier = SessionErrorExtractVerifier(HEADER, AuthServiceUnavailable, REASON)
    app = gated_app(bridge(verifier, **OPT_IN))

    assert wire(get(app, **{HEADER: GOOD_CREDENTIAL})) == UNKNOWN_CREDENTIAL_401


# --- every other refusal is unchanged with the opt-in on ---------------------------------


@pytest.mark.parametrize(
    "error_cls", [InvalidCredential, SessionExpired, SessionRevoked, CsrfFailure]
)
def test_with_the_opt_in_every_other_verifier_refusal_is_unchanged(
    error_cls: type[SessionError],
) -> None:
    def refusal() -> SessionError:
        return error_cls(reason=REASON)

    default = get(gated_app(bridge(RaisingVerifier(HEADER, refusal))), **{HEADER: "x"})
    opted = get(gated_app(bridge(RaisingVerifier(HEADER, refusal), **OPT_IN)), **{HEADER: "x"})

    assert wire(opted) == wire(default)
    assert opted.status_code in (401, 403)


@pytest.mark.parametrize(
    ("path", "headers"),
    [
        ("/required", {}),
        ("/required", {HEADER: BAD_CREDENTIAL}),
        ("/required", {HEADER: GOOD_CREDENTIAL, OTHER_HEADER: GOOD_CREDENTIAL}),
        ("/refused", {HEADER: GOOD_CREDENTIAL}),
        ("/orgs/%20", {HEADER: GOOD_CREDENTIAL}),
        ("/allowed", {HEADER: GOOD_CREDENTIAL}),
    ],
    ids=["missing", "invalid", "ambiguous", "not-authorized", "unusable-id", "allowed"],
)
def test_with_the_opt_in_the_dispatcher_s_own_answers_are_unchanged(
    path: str, headers: dict[str, str]
) -> None:
    def build(**settings: Any) -> FastAPI:
        verifiers = [FakeVerifier(HEADER), FakeVerifier(OTHER_HEADER)]
        return gated_app(BetterAuth(verifiers=verifiers, **settings))

    default, opted = get(build(), path, **headers), get(build(**OPT_IN), path, **headers)

    assert wire(opted) == wire(default)
    assert opted.status_code in (200, 400, 401, 403)


# --- two bridges, one process -------------------------------------------------------------


def test_two_bridges_sharing_one_verifier_answer_each_by_its_own_setting() -> None:
    shared = RaisingVerifier(HEADER, unavailable)
    quiet, loud = bridge(shared), bridge(shared, **OPT_IN)
    longer = bridge(shared, unavailable_status=503, unavailable_retry_after=RETRY_AFTER + 1)

    for _ in range(2):
        assert wire(get(gated_app(quiet), **{HEADER: "x"})) == UNKNOWN_CREDENTIAL_401
        assert wire(get(gated_app(loud), **{HEADER: "x"})) == service_unavailable(RETRY_AFTER)
        assert wire(get(gated_app(longer), **{HEADER: "x"})) == service_unavailable(RETRY_AFTER + 1)
    assert shared.verify_calls == 6
