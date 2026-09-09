"""`require_membership(id_param, member, ...)` — the README's organization recipe, as an API.

The two rules that recipe already stated are what this helper enforces mechanically. **The
resource id comes from the request**, resolved by FastAPI from the path — or from the query, when
the route declares no such path parameter — and from nowhere else, never from a session field the
client last set. And **membership is the consumer's own lookup**: this library owns no database,
so `member` is a coroutine they write, and its answer is the grant the route receives.

Everything that lookup can do wrong is driven here, because it runs inside a refusal path: a miss,
a raise, a refusal it chose on purpose, one raised from inside an `anyio` task group, and a
`member` that forgot its `async def` and would have handed the route a grant by accident. The
resource id is held to the rules a user id is held to, so a path segment nothing could own is a
403 rather than a query nobody wrote for it.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Iterator
from typing import Any

import anyio
import pytest
from fastapi import Depends, FastAPI, Request, Response
from fastapi.exception_handlers import http_exception_handler

from fastapi_better_auth import (
    BetterAuth,
    ConfigurationError,
    CsrfFailure,
    Membership,
    NotAuthorized,
    Session,
    SessionError,
    SessionRevoked,
)
from fastapi_better_auth._internal.reasons import REDACTED
from tests.fakes import BAD_CREDENTIAL, GOOD_CREDENTIAL, client
from tests.log_hygiene import capturing, rendered
from tests.test_authz import (
    EDITOR,
    FORBIDDEN,
    HEADER,
    REASON,
    UNAUTHENTICATED,
    Member,
    leaked,
    observable,
    one_verifier,
)

ID_PARAM = "org_id"
ORG = "org_a"
OTHER = "org_b"
PATH = "/orgs/{org_id}/invoices"
CALLED = "/orgs/org_a/invoices"
MISSED = "/orgs/org_b/invoices"
QUERY_PATH = "/invoices"
GRANTS: dict[str, str] = {ORG: "owner"}
LONG_ID = "o" * 100
"""Usable as an id (non-blank, ≤255, no control characters) and too long for `safe_label`."""


async def lookup(resource_id: str, session: Session[Member]) -> str | None:
    """The in-memory stand-in for the consumer's `member` query."""
    assert session.user.id == EDITOR["id"]
    return GRANTS.get(resource_id)


def membership_app(
    auth: BetterAuth, member: Any, *, id_param: str = ID_PARAM, path: str = PATH
) -> FastAPI:
    app = FastAPI()
    scoped = auth.require_membership(id_param, member, reason=REASON, user_model=Member)

    async def read(access: Membership[Member, str] = Depends(scoped)) -> dict[str, Any]:
        return {
            "user": access.session.user.id,
            "resource": access.resource_id,
            "grant": access.grant,
        }

    app.add_api_route(path, read, methods=["GET"], response_model=None)
    return app


def recording_app(
    auth: BetterAuth, member: Any, *, path: str = PATH
) -> tuple[FastAPI, list[SessionError]]:
    """The operator's side of a refusal, answered exactly as FastAPI's own handler would."""
    app = membership_app(auth, member, path=path)
    observed: list[SessionError] = []

    async def record(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, SessionError)
        observed.append(exc)
        return await http_exception_handler(request, exc)

    app.add_exception_handler(SessionError, record)
    return app, observed


def parameters(document: dict[str, Any], path: str) -> list[dict[str, Any]]:
    operation: dict[str, Any] = document["paths"][path]["get"]
    declared: list[dict[str, Any]] = operation.get("parameters", [])
    return declared


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


# --- a hit, and what the route receives ----------------------------------------------------


def test_a_membership_hit_hands_the_route_the_session_the_id_and_the_grant(
    client_backend: str,
) -> None:
    verifier, auth = one_verifier()

    with client(membership_app(auth, lookup), client_backend) as http:
        response = http.get(CALLED, headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 200
    assert response.json() == {"user": "u1", "resource": ORG, "grant": "owner"}
    assert verifier.verify_calls == 1


def test_the_lookup_is_handed_this_requests_id_and_the_verified_session() -> None:
    """The id comes from the request and the session from the verifier. Nothing else is in
    scope — in particular the lookup never sees the connection (D-010)."""
    seen: list[tuple[str, str]] = []
    _verifier, auth = one_verifier()

    async def watching(resource_id: str, session: Session[Member]) -> str:
        seen.append((resource_id, session.user.id))
        return "owner"

    with client(membership_app(auth, watching)) as http:
        response = http.get(CALLED, headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 200
    assert seen == [(ORG, "u1")]


@pytest.mark.parametrize("grant", [0, "", [], {}], ids=["zero", "empty-string", "list", "dict"])
def test_a_falsy_grant_that_is_not_false_is_still_a_grant(grant: object) -> None:
    """A role of `0` and an empty scope list are answers, not misses. Only `None` and `False`
    mean "no membership"; anything else the lookup returns is handed on untouched."""
    _verifier, auth = one_verifier()

    async def answering(_resource_id: str, _session: Session[Member]) -> object:
        return grant

    with client(membership_app(auth, answering)) as http:
        response = http.get(CALLED, headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 200
    assert response.json()["grant"] == grant


def test_the_membership_result_is_frozen_and_slotted() -> None:
    """It is handed to a route body, which must not be able to edit the authorization answer
    it was given and pass it on to something further down."""
    access: Membership[Member, str] = Membership(
        session=Session[Member](user=Member(id="u1"), expires_at=None, raw={"id": "u1"}),
        resource_id=ORG,
        grant="owner",
    )

    with pytest.raises(AttributeError):
        access.grant = "admin"  # pyright: ignore[reportAttributeAccessIssue]

    assert not hasattr(access, "__dict__")
    assert (access.resource_id, access.grant) == (ORG, "owner")


# --- a miss ---------------------------------------------------------------------------------


@pytest.mark.parametrize("answer", [None, False], ids=["none", "false"])
def test_a_lookup_that_answers_none_or_false_is_a_uniform_403(answer: object) -> None:
    _verifier, auth = one_verifier()

    async def missing(_resource_id: str, _session: Session[Member]) -> object:
        return answer

    with client(membership_app(auth, missing)) as http:
        response = http.get(CALLED, headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 403
    assert response.json() == FORBIDDEN
    assert "www-authenticate" not in response.headers


def test_a_miss_names_the_user_the_parameter_and_the_sanitized_id() -> None:
    _verifier, auth = one_verifier()
    app, observed = recording_app(auth, lookup)

    with client(app) as http:
        response = http.get(MISSED, headers={HEADER: GOOD_CREDENTIAL})

    assert [type(exc) for exc in observed] == [NotAuthorized]
    assert observed[0].reason == f"{REASON}: no membership for user u1 in {ID_PARAM}={OTHER}"
    assert leaked(observed[0].reason, response) == (), "the reason reached the client"


def test_an_id_safe_label_cannot_render_is_redacted_in_the_reason() -> None:
    """The resource id is request-supplied text that reaches an operator's log, so it goes
    through the same sanitizer a `kid` does: a newline that would forge a second log entry, or
    a value long enough to bury one, becomes `<redacted>` (D-069)."""
    _verifier, auth = one_verifier()
    app, observed = recording_app(auth, lookup, path=QUERY_PATH)

    with client(app) as http:
        response = http.get(
            QUERY_PATH, params={ID_PARAM: LONG_ID}, headers={HEADER: GOOD_CREDENTIAL}
        )

    assert response.status_code == 403
    assert observed[0].reason == f"{REASON}: no membership for user u1 in {ID_PARAM}={REDACTED}"
    assert LONG_ID not in observed[0].reason


@pytest.mark.parametrize(
    "resource_id",
    ["", "   ", "a\nb", "a\x7fb", "x" * 256],
    ids=["empty", "blank", "newline", "delete", "too-long"],
)
def test_a_resource_id_nothing_could_own_is_refused_before_the_lookup(resource_id: str) -> None:
    """The id is held to the rules a user id is held to, and a value that fails them is a 403
    rather than a distinguishable answer: a 422, or a query written for an id that cannot
    exist, would each tell the client something about the store behind the route."""
    asked: list[str] = []
    _verifier, auth = one_verifier()

    async def watching(seen: str, _session: Session[Member]) -> str:
        asked.append(seen)
        return "owner"

    with client(membership_app(auth, watching, path=QUERY_PATH)) as http:
        response = http.get(
            QUERY_PATH, params={ID_PARAM: resource_id}, headers={HEADER: GOOD_CREDENTIAL}
        )

    assert response.status_code == 403
    assert response.json() == FORBIDDEN
    assert asked == []


# --- a lookup that misbehaves ----------------------------------------------------------------


def test_a_lookup_that_raises_fails_closed_and_is_logged(
    records: list[logging.LogRecord],
) -> None:
    _verifier, auth = one_verifier()

    async def explode(_resource_id: str, _session: Session[Member]) -> str:
        raise RuntimeError("membership table unreachable")

    with client(membership_app(auth, explode)) as http:
        response = http.get(CALLED, headers={HEADER: GOOD_CREDENTIAL})

    written = rendered(records)
    assert response.status_code == 403
    assert response.json() == FORBIDDEN
    assert "membership table unreachable" in written, "the operator lost the real exception"
    assert "membership table unreachable" not in observable(response)


def test_a_lookup_that_raises_before_returning_its_coroutine_is_still_contained(
    records: list[logging.LogRecord],
) -> None:
    """A plain `def` that raises does so at the call, before any coroutine exists to await.

    The call itself sits inside the containment, not just the `await` (D-064): with only the
    `await` wrapped, this exception would escape as a 500 whose traceback frames hold the
    session - and in cookie mode the raw token with it."""
    _verifier, auth = one_verifier()

    def explode(_resource_id: str, _session: Session[Member]) -> str:
        raise RuntimeError("policy table unreadable")

    with client(membership_app(auth, explode)) as http:
        response = http.get(CALLED, headers={HEADER: GOOD_CREDENTIAL})

    written = rendered(records)
    assert response.status_code == 403
    assert response.json() == FORBIDDEN
    assert "policy table unreadable" in written, "the operator lost the real exception"
    assert "policy table unreadable" not in observable(response)


def test_the_reason_for_an_escaped_lookup_names_the_exception_type() -> None:
    _verifier, auth = one_verifier()

    async def explode(_resource_id: str, _session: Session[Member]) -> str:
        raise ZeroDivisionError("membership divisor was zero")

    app, observed = recording_app(auth, explode)
    with capturing(), client(app) as http:
        http.get(CALLED, headers={HEADER: GOOD_CREDENTIAL})

    assert [type(exc) for exc in observed] == [NotAuthorized]
    assert "ZeroDivisionError" in observed[0].reason
    assert "membership divisor was zero" not in observed[0].reason


@pytest.mark.parametrize("error", [CsrfFailure, SessionRevoked], ids=["csrf-403", "revoked-401"])
def test_a_session_error_raised_by_the_lookup_keeps_its_own_wire_shape(
    error: type[SessionError],
) -> None:
    _verifier, auth = one_verifier()

    async def refuse(_resource_id: str, _session: Session[Member]) -> str:
        raise error(reason="the deployment's own rule refused this session")

    with capturing(), client(membership_app(auth, refuse)) as http:
        response = http.get(CALLED, headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == error.response_status


def test_a_refusal_raised_inside_a_task_group_keeps_its_status() -> None:
    """An `anyio` task group delivers a child's exception wrapped in a `BaseExceptionGroup`,
    and an all-`Exception` group is itself an `Exception` — so without unwrapping, a 401 the
    lookup raised on purpose would leave here as a 403 (D-066)."""
    _verifier, auth = one_verifier()

    async def refuse(_resource_id: str, _session: Session[Member]) -> str:
        async def inner() -> None:
            raise SessionRevoked(reason="the session behind this request is gone")

        async with anyio.create_task_group() as group:
            group.start_soon(inner)
        raise AssertionError("unreachable")

    with capturing(), client(membership_app(auth, refuse)) as http:
        response = http.get(CALLED, headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 401


def test_a_synchronous_lookup_is_a_configuration_error_not_a_grant() -> None:
    """A `def` that forgot its `async` returns a value, and a truthy one would reach the route
    as a grant — the whole authorization answer decided by a missing keyword."""
    _verifier, auth = one_verifier()

    def forgot(_resource_id: str, _session: Session[Member]) -> str:
        return "owner"

    with client(membership_app(auth, forgot)) as http, pytest.raises(ConfigurationError) as caught:
        http.get(CALLED, headers={HEADER: GOOD_CREDENTIAL})

    assert "async" in str(caught.value)


def test_a_configuration_error_raised_by_the_lookup_is_not_degraded_into_a_403() -> None:
    _verifier, auth = one_verifier()

    async def refuse(_resource_id: str, _session: Session[Member]) -> str:
        raise ConfigurationError("the membership store was never configured")

    with (
        capturing(),
        client(membership_app(auth, refuse)) as http,
        pytest.raises(ConfigurationError),
    ):
        http.get(CALLED, headers={HEADER: GOOD_CREDENTIAL})


# --- authentication comes first ---------------------------------------------------------------


@pytest.mark.parametrize("headers", [{}, {HEADER: BAD_CREDENTIAL}], ids=["anonymous", "forged"])
def test_an_unauthenticated_request_is_401_and_never_reaches_the_lookup(
    headers: dict[str, str], client_backend: str
) -> None:
    asked: list[str] = []
    _verifier, auth = one_verifier()

    async def watching(resource_id: str, _session: Session[Member]) -> str:
        asked.append(resource_id)
        return "owner"

    with client(membership_app(auth, watching), client_backend) as http:
        response = http.get(CALLED, headers=headers)

    assert response.status_code == 401
    assert response.json() == UNAUTHENTICATED
    assert asked == []


def test_a_route_declaring_both_the_session_and_the_gate_verifies_exactly_once(
    client_backend: str,
) -> None:
    verifier, auth = one_verifier()
    current = auth.current_session(user_model=Member)
    scoped = auth.require_membership(ID_PARAM, lookup, reason=REASON, user_model=Member)

    async def read(
        session: Session[Member] = Depends(current),
        access: Membership[Member, str] = Depends(scoped),
    ) -> dict[str, Any]:
        return {"same": session is access.session}

    app = FastAPI()
    app.add_api_route(PATH, read, methods=["GET"], response_model=None)

    with client(app, client_backend) as http:
        response = http.get(CALLED, headers={HEADER: GOOD_CREDENTIAL})

    assert response.json() == {"same": True}
    assert verifier.verify_calls == 1


# --- where FastAPI binds the id from -----------------------------------------------------------


def test_the_id_is_published_as_a_path_parameter_when_the_route_declares_one() -> None:
    _verifier, auth = one_verifier()

    with client(membership_app(auth, lookup)) as http:
        document: dict[str, Any] = http.get("/openapi.json").json()

    declared = parameters(document, PATH)
    assert [(p["name"], p["in"], p["required"]) for p in declared] == [(ID_PARAM, "path", True)]
    assert declared[0]["schema"]["type"] == "string"


def test_the_id_is_published_as_a_query_parameter_when_the_route_declares_no_path_one() -> None:
    """The same dependency on a route with no matching path parameter: FastAPI resolves it from
    the query string instead, which the documentation states rather than leaving to be found."""
    _verifier, auth = one_verifier()

    with client(membership_app(auth, lookup, path=QUERY_PATH)) as http:
        document: dict[str, Any] = http.get("/openapi.json").json()
        answered = http.get(QUERY_PATH, params={ID_PARAM: ORG}, headers={HEADER: GOOD_CREDENTIAL})

    declared = parameters(document, QUERY_PATH)
    assert [(p["name"], p["in"], p["required"]) for p in declared] == [(ID_PARAM, "query", True)]
    assert answered.status_code == 200
    assert answered.json()["resource"] == ORG


def test_a_missing_query_id_is_answered_by_fastapis_own_validation() -> None:
    """Nothing about authorization is decided when the parameter is simply absent."""
    _verifier, auth = one_verifier()

    with client(membership_app(auth, lookup, path=QUERY_PATH)) as http:
        response = http.get(QUERY_PATH, headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 422


def test_the_dependency_advertises_the_id_parameter_under_the_configured_name() -> None:
    """The binding *is* the `__signature__`, so it is read here exactly as FastAPI reads it."""
    _verifier, auth = one_verifier()
    scoped = auth.require_membership("district_id", lookup, reason=REASON, user_model=Member)

    declared = inspect.signature(scoped).parameters

    assert list(declared) == ["district_id", "session"]
    assert declared["district_id"].annotation is str


# --- build-time refusals -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "id_param",
    ["", "   ", "1abc", "org id", "org-id", "org.id", "class", "session", "connection"],
    ids=[
        "empty",
        "blank",
        "leading-digit",
        "space",
        "hyphen",
        "dot",
        "keyword",
        "session",
        "connection",
    ],
)
def test_an_id_param_that_cannot_be_a_parameter_name_is_refused_at_build(id_param: str) -> None:
    """It becomes a parameter of the dependency's signature, so a name Python cannot bind would
    fail later in FastAPI's words rather than ours — and one this dependency already uses would
    shadow the session it was composed on."""
    _verifier, auth = one_verifier()

    with pytest.raises(ConfigurationError):
        auth.require_membership(id_param, lookup, reason=REASON, user_model=Member)


@pytest.mark.parametrize("id_param", [None, 7, b"org"], ids=["none", "int", "bytes"])
def test_an_id_param_that_is_not_a_string_is_refused_at_build(id_param: object) -> None:
    _verifier, auth = one_verifier()

    with pytest.raises(ConfigurationError):
        auth.require_membership(id_param, lookup, reason=REASON, user_model=Member)  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize("member", [None, "lookup", 7], ids=["none", "string", "int"])
def test_a_member_that_is_not_callable_is_refused_at_build(member: object) -> None:
    _verifier, auth = one_verifier()

    with pytest.raises(ConfigurationError):
        auth.require_membership(ID_PARAM, member, reason=REASON, user_model=Member)  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize("reason", ["", "   ", None], ids=["empty", "blank", "none"])
def test_a_blank_reason_is_refused_at_build(reason: object) -> None:
    _verifier, auth = one_verifier()

    with pytest.raises(ConfigurationError):
        auth.require_membership(ID_PARAM, lookup, reason=reason, user_model=Member)  # pyright: ignore[reportArgumentType]


def test_a_user_model_that_is_not_a_user_is_refused_at_build() -> None:
    _verifier, auth = one_verifier()

    with pytest.raises(ConfigurationError):
        auth.require_membership(ID_PARAM, lookup, reason=REASON, user_model=dict)  # pyright: ignore[reportArgumentType]


def test_each_call_builds_a_new_dependency() -> None:
    _verifier, auth = one_verifier()

    first = auth.require_membership(ID_PARAM, lookup, reason=REASON, user_model=Member)
    second = auth.require_membership(ID_PARAM, lookup, reason=REASON, user_model=Member)

    assert first is not second
