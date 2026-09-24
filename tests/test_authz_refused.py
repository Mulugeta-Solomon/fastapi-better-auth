"""`AuthorizationRefused` — a refusal the rule explains, from inside the rule (#71).

The two gates refuse with `NotAuthorized`: one uniform 403 whatever the rule was, which is the
right answer at the session layer. A product whose design requires a denial that *names* what was
missing — a capability the role lacks, a district the grants do not cover — needs the rule that
refused to say why, because only it knows. This marker is how it says so: raised on purpose inside
a `require` predicate or a `require_membership` lookup, it reaches the client as built, and nothing
is logged, because it is an answer rather than an accident.

Everything around it is pinned as hard as the honoured path. A plain `HTTPException` inside a rule
is still an accident — a helper's stray 404 or 500 — and stays contained. A marker built with a
status that is not a refusal, or with the challenge that belongs to authentication, raises at
construction, and inside a rule that too is an accident. And the order is untouched: an anonymous
or forged request is a 401 that never reaches the rule, so the explaining body is only ever shown
to a caller whose credential already verified.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterator
from http import HTTPStatus
from typing import Any

import anyio
import httpx2
import pytest
from exceptiongroup import ExceptionGroup
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exception_handlers import http_exception_handler
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    AuthorizationRefused,
    BetterAuth,
    BetterAuthError,
    InvalidCredential,
    Membership,
    MissingCredential,
    NotAuthorized,
    Session,
    SessionError,
    User,
)
from tests.fakes import BAD_CREDENTIAL, GOOD_CREDENTIAL, UserModelT, client
from tests.log_hygiene import capturing, rendered
from tests.test_authz import FORBIDDEN, HEADER, REASON, UNAUTHENTICATED, Member, one_verifier
from tests.test_authz_membership import CALLED, ID_PARAM, PATH, QUERY_PATH
from tests.test_readme import ALL_SNIPPETS, ROOT, Snippet, run

PREDICATE = "predicate"
LOOKUP = "lookup"
WHERE = (PREDICATE, LOOKUP)
URL = {PREDICATE: "/editor", LOOKUP: CALLED}
CONTAINED_AS = {PREDICATE: "authorization predicate", LOOKUP: "membership lookup"}

CAPABILITY_BODY = {"code": "missing_capability", "capability": "send_sms"}
JURISDICTION_BODY = {"code": "outside_jurisdiction", "covers": ["Ada East District"]}
ACCIDENT = "a helper's own words that must never reach the wire"
CLIENT_LOGGERS = frozenset({"httpx2", "asyncio"})

README = ROOT / "README.md"
RECIPE_HEADING = "#### A refusal that explains"
RECIPE_MARKER = "class PermissionDenied(AuthorizationRefused):"
JSON_FENCE = "```json\n"

NOT_REFUSALS: tuple[object, ...] = (
    *(200, 204, 301, 302, 400, 401, 402, 405, 409, 410, 418, 422, 429, 451),
    *(500, 502, 503, 0, -403, 4030, 403.0, "403", None, True),
)
CHALLENGE_SPELLINGS = (
    "WWW-Authenticate",
    "www-authenticate",
    "WWW-AUTHENTICATE",
    "wWw-AuThEnTiCaTe",
    " WWW-Authenticate",
    "WWW-Authenticate\t",
)


class EqualToEverything(int):
    """An int whose comparisons lie: it is `in {403, 404}` whatever its value is."""

    def __eq__(self, other: object) -> bool:
        return True

    def __hash__(self) -> int:
        return hash(403)


class ConvertsToForbidden(int):
    """An int whose conversions lie: `int()` and `operator.index()` both answer 403."""

    def __int__(self) -> int:
        return 403

    def __index__(self) -> int:
        return 403


class HeaderText(str):
    """A `str` subclass, as an enum of header names would be."""

    __slots__ = ()


LYING_INTS = (EqualToEverything(500), ConvertsToForbidden(500))
NOT_TEXT_HEADERS: tuple[object, ...] = (
    {b"WWW-Authenticate": "Bearer"},
    {b"X-Tag": "a"},
    {"X-Tag": b"a"},
    {"X-Tag": 1},
    {1: "a"},
    [("X-Tag", "a")],
    "X-Tag: a",
)
NOT_TEXT_HEADER_IDS = (
    "bytes-challenge",
    "bytes-name",
    "bytes-value",
    "int-value",
    "int-name",
    "pairs",
    "string",
)


class MissingCapability(AuthorizationRefused):
    """What a consumer writes: a refusal whose body names the capability the role lacks."""

    def __init__(self, capability: str) -> None:
        super().__init__(detail={"code": "missing_capability", "capability": capability})


class OutsideJurisdiction(AuthorizationRefused):
    """A lookup's refusal, explained with the rows it just read."""

    def __init__(self, covers: list[str]) -> None:
        super().__init__(status_code=403, detail={"code": "outside_jurisdiction", "covers": covers})


def gated(auth: BetterAuth, predicate: Any, reached: list[str]) -> FastAPI:
    app = FastAPI()
    gate = auth.require(predicate, reason=REASON, user_model=Member)

    async def read(session: Session[Member] = Depends(gate)) -> dict[str, str]:
        reached.append(session.user.id)
        return {"id": session.user.id}

    app.add_api_route(URL[PREDICATE], read, methods=["GET"], response_model=None)
    return app


def scoped(auth: BetterAuth, member: Any, reached: list[str], *, path: str = PATH) -> FastAPI:
    app = FastAPI()
    gate = auth.require_membership(ID_PARAM, member, reason=REASON, user_model=Member)

    async def read(access: Membership[Member, Any] = Depends(gate)) -> dict[str, str]:
        reached.append(access.resource_id)
        return {"resource": access.resource_id}

    app.add_api_route(path, read, methods=["GET"], response_model=None)
    return app


def raising_app(
    where: str, auth: BetterAuth, make: Callable[[], BaseException], asked: list[str]
) -> FastAPI:
    """One rule that records who reached it and then raises what `make` builds."""
    if where == PREDICATE:

        def predicate(session: Session[Member]) -> bool:
            asked.append(session.user.id)
            raise make()

        return gated(auth, predicate, [])

    async def lookup(_resource_id: str, session: Session[Member]) -> str:
        asked.append(session.user.id)
        raise make()

    return scoped(auth, lookup, [])


def recording(app: FastAPI) -> list[SessionError]:
    """The operator's side: a handler that keeps each refusal, then answers as FastAPI would."""
    observed: list[SessionError] = []

    async def record(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, SessionError)
        observed.append(exc)
        return await http_exception_handler(request, exc)

    app.add_exception_handler(SessionError, record)
    return observed


def served(records: list[logging.LogRecord]) -> list[logging.LogRecord]:
    """Every record but the test client's own chatter: its request line, the loop's notice."""
    return [r for r in records if r.name not in CLIENT_LOGGERS or r.levelno >= logging.WARNING]


def explaining(response: httpx2.Response) -> bool:
    """Whether a response carries anything the explaining bodies here are made of."""
    return any(word in response.text for word in ("missing_capability", "send_sms", "Ada East"))


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


# --- the class ------------------------------------------------------------------------------


def test_the_default_is_a_403_whose_body_is_the_status_phrase() -> None:
    refusal = AuthorizationRefused()

    assert (refusal.status_code, refusal.detail, refusal.headers) == (403, "Forbidden", None)


@pytest.mark.parametrize(
    "status",
    [403, 404, HTTPStatus.FORBIDDEN, HTTPStatus.NOT_FOUND],
    ids=["403", "404", "HTTPStatus.FORBIDDEN", "HTTPStatus.NOT_FOUND"],
)
def test_a_refusal_may_answer_403_or_404(status: int) -> None:
    refusal = AuthorizationRefused(status_code=status, detail={"code": "x"})

    assert refusal.status_code == int(status)
    assert type(refusal.status_code) is int
    assert refusal.detail == {"code": "x"}


@pytest.mark.parametrize("status", NOT_REFUSALS, ids=repr)
def test_any_other_status_is_a_value_error_at_construction(status: object) -> None:
    """401 would tell a session that already verified to re-authenticate, 400 is the ambiguous-
    credential answer, and nothing else is a refusal. The whole neighbourhood is swept, not one
    value: a check that admits 401 by accident is exactly the one a single case would miss."""
    with pytest.raises(ValueError, match="403 or 404"):
        AuthorizationRefused(status_code=status)  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize("name", CHALLENGE_SPELLINGS, ids=repr)
def test_the_challenge_header_in_any_spelling_is_a_value_error(name: str) -> None:
    """The challenge belongs to authentication; a session that reached a rule already passed it."""
    with pytest.raises(ValueError, match="WWW-Authenticate"):
        AuthorizationRefused(headers={"X-Required-Capability": "send_sms", name: "Bearer"})


def test_other_headers_are_kept_on_a_copy_of_their_own() -> None:
    """The mapping construction checked must be the one it keeps: a dict the caller still holds
    could otherwise grow the challenge after the check."""
    headers = {"X-Required-Capability": "send_sms"}
    refusal = AuthorizationRefused(headers=headers)

    headers["WWW-Authenticate"] = "Bearer"

    assert refusal.headers == {"X-Required-Capability": "send_sms"}


@pytest.mark.parametrize("status", LYING_INTS, ids=["equal-to-everything-500", "converts-to-403"])
def test_an_int_that_lies_is_judged_by_its_real_value(status: int) -> None:
    """Checking the caller's object and storing `int()` of it are two different reads: one lies
    in `__eq__`/`__hash__` and passes as 403, the other lies in `__int__`. The value is read
    once, by `int`'s own conversion, and that one value is both checked and stored."""
    with pytest.raises(ValueError, match="403 or 404"):
        AuthorizationRefused(status_code=status)


def test_an_int_subclass_that_really_is_403_is_stored_as_a_plain_int() -> None:
    refusal = AuthorizationRefused(status_code=EqualToEverything(403))

    assert type(refusal.status_code) is int
    assert refusal.status_code == 403


@pytest.mark.parametrize("headers", NOT_TEXT_HEADERS, ids=NOT_TEXT_HEADER_IDS)
def test_headers_that_are_not_a_mapping_of_str_to_str_are_a_value_error(headers: object) -> None:
    """Starlette writes every name and value as text. A `bytes` challenge would slip past the
    spelling check and then crash the response mid-write — never the documented error."""
    with pytest.raises(ValueError, match="mapping of str to str"):
        AuthorizationRefused(headers=headers)  # pyright: ignore[reportArgumentType]


def test_str_subclass_names_and_values_are_kept_as_plain_str() -> None:
    """A `str` subclass can answer `strip()` or `lower()` differently from what is written to the
    wire, so what is kept is plain text, and the check at honour time accepts nothing else."""
    refusal = AuthorizationRefused(headers={HeaderText("X-Tag"): HeaderText("kept")})

    assert refusal.headers == {"X-Tag": "kept"}
    assert refusal.headers is not None
    assert all(type(name) is str and type(value) is str for name, value in refusal.headers.items())


@pytest.mark.parametrize("attribute", ["status_code", "detail", "headers"])
def test_a_subclass_may_not_set_a_response_attribute_in_its_class_body(attribute: str) -> None:
    """Instance attributes set by `__init__` win over the class body, so `status_code = 404`
    there would be silently ignored and the subclass would ship a 403 its author never meant."""
    with pytest.raises(TypeError, match="super"):
        type("Shadowing", (AuthorizationRefused,), {attribute: 404})


def test_it_is_an_http_exception_and_neither_error_family() -> None:
    """Not a `SessionError`: per-status uniformity is exactly what it opts out of. And not a
    `BetterAuthError`, which is a deployment fault rather than an answer."""
    assert issubclass(AuthorizationRefused, HTTPException)
    assert not issubclass(AuthorizationRefused, SessionError)
    assert not issubclass(AuthorizationRefused, BetterAuthError)


# --- honoured, from a predicate -----------------------------------------------------------------


def test_a_predicate_refusal_reaches_the_client_as_built(
    client_backend: str, records: list[logging.LogRecord]
) -> None:
    reached: list[str] = []
    _verifier, auth = one_verifier()

    def can_send_sms(_session: Session[Member]) -> bool:
        raise MissingCapability("send_sms")

    with client(gated(auth, can_send_sms, reached), client_backend) as http:
        response = http.get(URL[PREDICATE], headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 403
    assert response.json() == {"detail": CAPABILITY_BODY}
    assert "www-authenticate" not in response.headers
    assert reached == []
    assert served(records) == [], "an honoured refusal is an answer, and answers are not logged"


def test_a_404_refusal_is_honoured_and_can_look_like_no_route_at_all(client_backend: str) -> None:
    """A rule that would rather not confirm the resource exists: with no detail, the body is
    byte-identical to the one an unknown path gets."""
    _verifier, auth = one_verifier()

    def hidden(_session: Session[Member]) -> bool:
        raise AuthorizationRefused(status_code=404)

    with client(gated(auth, hidden, []), client_backend) as http:
        refused = http.get(URL[PREDICATE], headers={HEADER: GOOD_CREDENTIAL})
        unknown = http.get("/no-such-route", headers={HEADER: GOOD_CREDENTIAL})

    assert refused.status_code == unknown.status_code == 404
    assert refused.content == unknown.content


def test_headers_the_refusal_carries_reach_the_client() -> None:
    _verifier, auth = one_verifier()

    def can_send_sms(_session: Session[Member]) -> bool:
        raise AuthorizationRefused(headers={"X-Required-Capability": "send_sms"})

    with client(gated(auth, can_send_sms, [])) as http:
        response = http.get(URL[PREDICATE], headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 403
    assert response.headers["x-required-capability"] == "send_sms"
    assert "www-authenticate" not in response.headers


@pytest.mark.parametrize("depth", [1, 2], ids=["group", "nested-group"])
def test_a_refusal_delivered_as_a_single_leaf_group_is_honoured(depth: int) -> None:
    """A single-leaf group is that leaf — the same unwrap the others get (D-066)."""
    _verifier, auth = one_verifier()

    def wrapped(_session: Session[Member]) -> bool:
        delivered: Exception = MissingCapability("send_sms")
        for level in range(depth):
            leaves: list[Exception] = [delivered]
            delivered = ExceptionGroup(f"level {level}", leaves)
        raise delivered

    with client(gated(auth, wrapped, [])) as http:
        response = http.get(URL[PREDICATE], headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 403
    assert response.json() == {"detail": CAPABILITY_BODY}


def test_a_group_of_two_refusals_is_nobodys_single_answer_and_is_contained(
    records: list[logging.LogRecord],
) -> None:
    _verifier, auth = one_verifier()

    def split(_session: Session[Member]) -> bool:
        raise ExceptionGroup("two", [MissingCapability("send_sms"), MissingCapability("export")])

    app = gated(auth, split, [])
    observed = recording(app)
    with client(app) as http:
        response = http.get(URL[PREDICATE], headers={HEADER: GOOD_CREDENTIAL})

    assert response.json() == FORBIDDEN
    assert [exc.reason for exc in observed] == [
        "ExceptionGroup escaped the authorization predicate"
    ]
    assert "the authorization predicate raised" in rendered(records)


# --- honoured, from a membership lookup ---------------------------------------------------------


def test_a_lookup_refusal_reaches_the_client_and_the_route_never_runs(
    client_backend: str, records: list[logging.LogRecord]
) -> None:
    """The lookup explains with the rows it just read; no grant exists, so no `Membership` is
    built and the route body is never entered."""
    reached: list[str] = []
    _verifier, auth = one_verifier()

    async def covers(_district_id: str, _session: Session[Member]) -> str:
        raise OutsideJurisdiction(["Ada East District"])

    with client(scoped(auth, covers, reached), client_backend) as http:
        response = http.get(CALLED, headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 403
    assert response.json() == {"detail": JURISDICTION_BODY}
    assert "www-authenticate" not in response.headers
    assert reached == []
    assert served(records) == [], "an honoured refusal is an answer, and answers are not logged"


def test_a_lookup_refusal_raised_inside_a_task_group_is_honoured() -> None:
    _verifier, auth = one_verifier()

    async def covers(_district_id: str, _session: Session[Member]) -> str:
        async def inner() -> None:
            raise OutsideJurisdiction(["Ada East District"])

        async with anyio.create_task_group() as group:
            group.start_soon(inner)
        raise AssertionError("unreachable")

    with client(scoped(auth, covers, [])) as http:
        response = http.get(CALLED, headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 403
    assert response.json() == {"detail": JURISDICTION_BODY}


def test_a_lookup_that_refuses_before_returning_its_coroutine_is_honoured() -> None:
    """A plain `def` raises at the call, before any coroutine exists — inside the same `try`."""
    _verifier, auth = one_verifier()

    def covers(_district_id: str, _session: Session[Member]) -> Any:
        raise OutsideJurisdiction(["Ada East District"])

    with client(scoped(auth, covers, [])) as http:
        response = http.get(CALLED, headers={HEADER: GOOD_CREDENTIAL})

    assert response.json() == {"detail": JURISDICTION_BODY}


# --- a marker that breaks its own rules is an accident --------------------------------------------


@pytest.mark.parametrize("where", WHERE)
@pytest.mark.parametrize(
    "arguments",
    [
        {"status_code": 401},
        {"status_code": 400},
        {"status_code": 500},
        {"headers": {"www-authenticate": "Bearer"}},
        {"status_code": EqualToEverything(500)},
        {"headers": {b"WWW-Authenticate": "Bearer"}},
    ],
    ids=["401", "400", "500", "challenge", "lying-int", "bytes-challenge"],
)
def test_a_marker_built_wrong_inside_a_rule_is_contained_and_logged(
    where: str, arguments: dict[str, Any], client_backend: str, records: list[logging.LogRecord]
) -> None:
    """Each of these is a `ValueError` at construction, and inside a rule that is an accident.
    The last two reached the wire before the fix: the lying int as a 500, the `bytes` challenge
    as a crash while Starlette wrote the response."""
    _verifier, auth = one_verifier()
    app = raising_app(where, auth, lambda: AuthorizationRefused(**arguments), [])
    observed = recording(app)

    with client(app, client_backend) as http:
        response = http.get(URL[where], headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 403
    assert response.json() == FORBIDDEN
    assert "www-authenticate" not in response.headers
    assert [type(exc) for exc in observed] == [NotAuthorized]
    assert observed[0].reason == f"ValueError escaped the {CONTAINED_AS[where]}"
    assert f"the {CONTAINED_AS[where]} raised" in rendered(records)


# --- the contrast: a plain HTTPException is still an accident --------------------------------------


@pytest.mark.parametrize("where", WHERE)
@pytest.mark.parametrize(
    "error",
    [HTTPException, StarletteHTTPException],
    ids=["fastapi", "starlette"],
)
@pytest.mark.parametrize("status", [403, 404, 500])
def test_a_plain_http_exception_inside_a_rule_is_contained_and_logged(
    where: str,
    error: type[StarletteHTTPException],
    status: int,
    records: list[logging.LogRecord],
) -> None:
    """Option 2 narrowed: a helper's accidental 404 or 500 is not a decision, so only the marker
    is honoured. Were a bare `HTTPException` honoured, every one of these would reach the wire."""
    _verifier, auth = one_verifier()
    app = raising_app(where, auth, lambda: error(status, ACCIDENT), [])
    observed = recording(app)

    with client(app) as http:
        response = http.get(URL[where], headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 403
    assert response.json() == FORBIDDEN
    assert ACCIDENT not in response.text
    assert [type(exc) for exc in observed] == [NotAuthorized]
    assert observed[0].reason == f"HTTPException escaped the {CONTAINED_AS[where]}"
    assert ACCIDENT in rendered(records), "the operator lost the real exception"


# --- authentication comes first -------------------------------------------------------------------


@pytest.mark.parametrize("where", WHERE)
def test_only_an_authenticated_session_ever_sees_the_explaining_body(
    where: str, client_backend: str
) -> None:
    """401 before 403, always: the anonymous and the forged request are the uniform 401 and never
    reach the rule, so the body a rule chose is shown only to a credential that verified."""
    asked: list[str] = []
    _verifier, auth = one_verifier()
    app = raising_app(where, auth, lambda: MissingCapability("send_sms"), asked)
    observed = recording(app)

    with client(app, client_backend) as http:
        anonymous = http.get(URL[where])
        forged = http.get(URL[where], headers={HEADER: BAD_CREDENTIAL})
        verified = http.get(URL[where], headers={HEADER: GOOD_CREDENTIAL})

    for refused in (anonymous, forged):
        assert refused.status_code == 401
        assert refused.json() == UNAUTHENTICATED
        assert refused.headers["www-authenticate"] == "Bearer"
        assert not explaining(refused)
    assert [type(exc) for exc in observed] == [MissingCredential, InvalidCredential]
    assert asked == ["u1"]
    assert verified.status_code == 403
    assert verified.json() == {"detail": CAPABILITY_BODY}


class RefusingVerifier:
    """A verifier that raises the marker: authentication has no rule to explain, so it may not."""

    credential_source = f"header:{HEADER}"

    def extract(self, connection: HTTPConnection) -> str | None:
        return connection.headers.get(HEADER)

    async def verify(self, credential: str, user_model: type[UserModelT]) -> Session[UserModelT]:
        raise MissingCapability("send_sms")


def allow(_session: Session[Member]) -> bool:
    return True


def test_the_marker_raised_by_a_verifier_is_the_uniform_401(
    records: list[logging.LogRecord],
) -> None:
    """Honoured only inside a rule. Raised during authentication it is contained like any other
    escape, so it cannot become a way to answer an unauthenticated request with a chosen body."""
    auth = BetterAuth(verifiers=[RefusingVerifier()])
    app = gated(auth, allow, [])

    with client(app) as http:
        response = http.get(URL[PREDICATE], headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 401
    assert response.json() == UNAUTHENTICATED
    assert not explaining(response)
    assert "RefusingVerifier.verify raised" in rendered(records)


@pytest.mark.parametrize("resource_id", ["", "a\nb", "x" * 256], ids=["empty", "newline", "long"])
def test_an_unusable_resource_id_stays_the_uniform_403_and_nothing_is_looked_up(
    resource_id: str,
) -> None:
    asked: list[str] = []
    _verifier, auth = one_verifier()

    async def covers(district_id: str, _session: Session[Member]) -> str:
        asked.append(district_id)
        raise OutsideJurisdiction(["Ada East District"])

    app = scoped(auth, covers, [], path=QUERY_PATH)
    observed = recording(app)
    with client(app) as http:
        response = http.get(
            QUERY_PATH, params={ID_PARAM: resource_id}, headers={HEADER: GOOD_CREDENTIAL}
        )

    assert response.status_code == 403
    assert response.json() == FORBIDDEN
    assert asked == []
    assert [type(exc) for exc in observed] == [NotAuthorized]
    assert observed[0].reason.endswith("nothing was looked up")


def test_a_route_with_the_session_and_a_refusing_gate_verifies_exactly_once(
    client_backend: str,
) -> None:
    verifier, auth = one_verifier()
    current = auth.current_session(user_model=Member)

    def can_send_sms(_session: Session[Member]) -> bool:
        raise MissingCapability("send_sms")

    gate = auth.require(can_send_sms, reason=REASON, user_model=Member)

    async def read(
        _session: Session[Member] = Depends(current),
        _gated: Session[Member] = Depends(gate),
    ) -> dict[str, str]:
        raise AssertionError("unreachable")

    app = FastAPI()
    app.add_api_route("/both", read, methods=["GET"], response_model=None)

    with client(app, client_backend) as http:
        response = http.get("/both", headers={HEADER: GOOD_CREDENTIAL})

    assert response.json() == {"detail": CAPABILITY_BODY}
    assert verifier.verify_calls == 1


# --- the README's recipe, driven ------------------------------------------------------------------


def the_recipe() -> Snippet:
    found = [snippet for snippet in ALL_SNIPPETS if RECIPE_MARKER in snippet.code]
    assert len(found) == 1, f"{len(found)} fences define the documented refusal"
    return found[0]


def documented_body() -> Any:
    """The `json` block the README shows under the recipe, parsed — so the page cannot drift."""
    text = README.read_text(encoding="utf-8")
    section = text[text.index(RECIPE_HEADING) :]
    opened = section.index(JSON_FENCE) + len(JSON_FENCE)
    return json.loads(section[opened : section.index("```", opened)])


def as_user(staff: type[User], role: str) -> Callable[[], Any]:
    """The documented override: a session of the fence's own user model, with one role."""
    payload = {"id": "user_1", "role": role}

    async def fake() -> Session[Any]:
        return Session(user=staff.model_validate(payload), expires_at=None, raw=payload)

    return fake


def test_the_readme_recipe_answers_with_the_bodies_it_documents(client_backend: str) -> None:
    """The forged-credential rungs in `test_readme.py` prove the fence refuses; this proves it
    explains. The session is overridden, so only the rules decide — and the body the page shows
    is the body the fence answers."""
    namespace = run(the_recipe())
    app: FastAPI = namespace["app"]
    auth: BetterAuth = namespace["auth"]
    staff: type[User] = namespace["Staff"]
    current = auth.current_session(user_model=staff)

    with client(app, client_backend) as http:
        app.dependency_overrides[current] = as_user(staff, "dispatcher")
        audit = http.get("/audit-log")
        outside = http.get("/districts/ada-west/incidents")
        inside = http.get("/districts/ada-east/incidents")
        app.dependency_overrides[current] = as_user(staff, "auditor")
        auditor = http.get("/audit-log")

    assert audit.status_code == 403
    assert audit.json() == documented_body()
    assert outside.status_code == 403
    assert outside.json()["detail"]["covers"] == ["Ada East District"]
    assert inside.json() == {"district": "Ada East District"}
    assert auditor.json() == ["user_1"]
