"""The security schemes a route inherits from our dependencies, and what they may not do.

`/docs` grows an Authorize button only when the operation carries a security requirement and
the document defines the scheme it names. Both come from the dependency tree, so declaring
them is this library's job — and the whole of it: the scheme is *documentation*, never an
extraction. Every verifier keeps reading the connection itself, so there is exactly one place
a credential is read from and exactly one place a request is refused.

Three properties are asserted here rather than assumed. The schemes are **derived** from each
verifier's declared `credential_source`, so Phase 2's cookie mode documents itself without
this module learning about it, and a label nothing recognizes documents *nothing* rather than
a guess. The declaration is **inert**: a request carrying the scheme's own credential and
nothing the verifier reads is still a 401, which is the executable form of "the scheme never
feeds verification". And it is **connection-shaped**: FastAPI's own `HTTPBearer` takes a
`Request`, so wiring it in as a live dependency would have raised `TypeError` on every
WebSocket route — the one shape our dependencies exist to keep serving.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import Depends, FastAPI, WebSocket

from fastapi_better_auth import BetterAuth, ConfigurationError, Session, User
from tests.fakes import GOOD_CREDENTIAL, FakeVerifier, client, session_app

BEARER_SOURCE = "header:authorization-bearer"
COOKIE_SOURCE = "cookie:better-auth.session_token"
BEARER_NAME = "BetterAuthBearer"
COOKIE_NAME = "BetterAuthCookie-better-auth.session_token"
HEADER = "x-cred-a"
HEADER_B = "x-cred-b"

BEARER_DEFINITION = {"type": "http", "scheme": "bearer"}
COOKIE_DEFINITION = {"type": "apiKey", "in": "cookie", "name": "better-auth.session_token"}


def bearer_auth() -> tuple[FakeVerifier, BetterAuth]:
    """A verifier that reads `x-cred-a` and *declares* the bearer source.

    The label and the read are deliberately different: the label is what the document is
    derived from, the read is what actually authenticates. Splitting them is what makes
    "the scheme is never consulted" observable on the wire.
    """
    verifier = FakeVerifier(HEADER, source=BEARER_SOURCE)
    return verifier, BetterAuth(verifiers=[verifier])


def document(auth: BetterAuth) -> dict[str, Any]:
    with client(session_app(auth)) as http:
        body: dict[str, Any] = http.get("/openapi.json").json()
    return body


def schemes(auth: BetterAuth) -> dict[str, Any]:
    components: dict[str, Any] = document(auth).get("components", {})
    definitions: dict[str, Any] = components.get("securitySchemes", {})
    return definitions


def security(auth: BetterAuth, path: str) -> list[dict[str, list[str]]]:
    operation: dict[str, Any] = document(auth)["paths"][path]["get"]
    declared: list[dict[str, list[str]]] = operation.get("security", [])
    return declared


def comparable_headers(headers: Any) -> dict[str, str]:
    return {key.lower(): value for key, value in headers.items() if key.lower() != "date"}


# --- the bearer scheme reaches the document ------------------------------------------


def test_a_bearer_verifier_publishes_exactly_one_bearer_scheme() -> None:
    _verifier, auth = bearer_auth()
    published = schemes(auth)

    assert set(published) == {BEARER_NAME}
    assert {key: published[BEARER_NAME][key] for key in BEARER_DEFINITION} == BEARER_DEFINITION


def test_the_scheme_carries_a_description_for_the_authorize_dialog() -> None:
    """The Authorize dialog renders it, and it is the only place a reader is told what to
    paste. It names where the credential goes and never which verifier is configured."""
    _verifier, auth = bearer_auth()
    description = schemes(auth)[BEARER_NAME]["description"]

    assert description
    assert "FakeVerifier" not in description


@pytest.mark.parametrize("path", ["/required", "/optional"])
def test_both_dependencies_carry_the_requirement(path: str) -> None:
    """`optional_session` is marked too: OpenAPI cannot say "optional" from inside a
    dependency, and a route Swagger will not send a credential to cannot be exercised from
    `/docs` at all — which is the failure that matters to the person reading the page."""
    _verifier, auth = bearer_auth()

    assert security(auth, path) == [{BEARER_NAME: []}]


def test_a_cookie_verifier_publishes_an_api_key_cookie_scheme() -> None:
    """Phase 2's mode, documented today: the label already says where the credential lives."""
    auth = BetterAuth(verifiers=[FakeVerifier(HEADER, source=COOKIE_SOURCE)])
    published = schemes(auth)

    assert set(published) == {COOKIE_NAME}
    assert {key: published[COOKIE_NAME][key] for key in COOKIE_DEFINITION} == COOKIE_DEFINITION


def test_two_verifiers_publish_two_schemes_as_alternatives() -> None:
    """OpenAPI reads a `security` list as OR: either credential authenticates the request,
    which is exactly what presence-dispatch does with them."""
    auth = BetterAuth(
        verifiers=[
            FakeVerifier(HEADER, source=BEARER_SOURCE),
            FakeVerifier(HEADER_B, source=COOKIE_SOURCE),
        ]
    )

    assert set(schemes(auth)) == {BEARER_NAME, COOKIE_NAME}
    assert security(auth, "/required") == [{BEARER_NAME: []}, {COOKIE_NAME: []}]


def test_two_schemes_are_declared_as_or_not_and() -> None:
    """Ruling 11: the structural property that distinguishes OR from AND, pinned in the unit lane
    alongside the exact equality above. OR is a list of single-key requirement objects
    (`[{A: []}, {B: []}]`); AND would fold them into one (`[{A: [], B: []}]`). A `declaring()` that
    merged every scheme into one Security requirement passes the flatten-into-a-set-of-names test
    the e2e lane used to rely on, and fails only this - so this is the assertion that catches it."""
    auth = BetterAuth(
        verifiers=[
            FakeVerifier(HEADER, source=BEARER_SOURCE),
            FakeVerifier(HEADER_B, source=COOKIE_SOURCE),
        ]
    )
    declared = security(auth, "/required")

    assert len(declared) == 2
    assert all(len(requirement) == 1 for requirement in declared), "an AND fold merged the schemes"


def test_a_chain_of_schemes_still_serves_a_request(client_backend: str) -> None:
    """A set of schemes whose size is only known at construction is declared as a chain of
    dependencies. Building it is not running it: this drives a real request through one."""
    first = FakeVerifier(HEADER, source=BEARER_SOURCE)
    second = FakeVerifier(HEADER_B, source=COOKIE_SOURCE)
    auth = BetterAuth(verifiers=[first, second])

    with client(session_app(auth), client_backend) as http:
        response = http.get("/required", headers={HEADER_B: GOOD_CREDENTIAL})

    assert response.status_code == 200
    assert first.verify_calls == 0
    assert second.verify_calls == 1


@pytest.mark.parametrize(
    "source",
    [
        "Header:Authorization-Bearer",
        "  header:authorization-bearer  ",
        "COOKIE:better-auth.session_token",
    ],
    ids=["mixed-case", "surrounding-space", "upper-cookie"],
)
def test_a_label_is_read_the_way_the_collision_check_reads_it(source: str) -> None:
    """`BetterAuth` compares `credential_source` stripped and casefolded; a derivation that
    read it any other way would document one spelling and refuse a different one."""
    auth = BetterAuth(verifiers=[FakeVerifier(HEADER, source=source)])

    assert schemes(auth)


def test_the_cookie_name_survives_into_the_scheme_name() -> None:
    """Two cookie verifiers on different cookies must not collapse onto one definition."""
    auth = BetterAuth(
        verifiers=[
            FakeVerifier(HEADER, source=COOKIE_SOURCE),
            FakeVerifier(HEADER_B, source="cookie:__Secure-better-auth.session_token"),
        ]
    )

    assert set(schemes(auth)) == {
        COOKIE_NAME,
        "BetterAuthCookie-__Secure-better-auth.session_token",
    }


# --- a label nothing recognizes documents nothing --------------------------------------


@pytest.mark.parametrize(
    "source",
    ["header:x-cred-a", "cookie:", "cookie:   ", "gateway assertion", "header:authorization"],
    ids=["other-header", "empty-cookie", "blank-cookie", "prose", "bare-authorization"],
)
def test_an_unrecognized_label_publishes_no_scheme(source: str) -> None:
    """Never guess. A label this module cannot read is a verifier it cannot document, and a
    scheme invented for it would tell every reader of the document the wrong place to put a
    credential — which is worse than no Authorize button at all."""
    auth = BetterAuth(verifiers=[FakeVerifier(HEADER, source=source)])

    assert schemes(auth) == {}
    assert security(auth, "/required") == []


def test_a_documented_verifier_beside_an_undocumented_one_publishes_only_its_own() -> None:
    auth = BetterAuth(
        verifiers=[
            FakeVerifier(HEADER, source=BEARER_SOURCE),
            FakeVerifier(HEADER_B, source="header:x-gateway-assertion"),
        ]
    )

    assert set(schemes(auth)) == {BEARER_NAME}
    assert security(auth, "/required") == [{BEARER_NAME: []}]


def test_two_labels_that_collapse_to_one_scheme_name_are_refused_at_construction() -> None:
    """Distinct `credential_source` values are already enforced; sanitizing a cookie name into
    the character set an OpenAPI component key allows can still collapse two of them. Silently
    publishing one definition under a name the other also claims documents the wrong cookie."""
    with pytest.raises(ConfigurationError) as caught:
        BetterAuth(
            verifiers=[
                FakeVerifier(HEADER, source="cookie:session token"),
                FakeVerifier(HEADER_B, source="cookie:session/token"),
            ]
        )

    assert "BetterAuthCookie-session-token" in str(caught.value)


# --- the declaration is inert ----------------------------------------------------------


def test_the_scheme_never_authenticates_anything(client_backend: str) -> None:
    """The credential the *scheme* would extract is not the credential the verifier reads.

    A bearer token on a request whose verifier reads `x-cred-a` is a 401, because nothing
    ever asks the scheme what it found. If the scheme's value were wired into verification
    this would be a 200 — a deployment authenticated by its own documentation.
    """
    verifier, auth = bearer_auth()
    with client(session_app(auth), client_backend) as http:
        response = http.get("/required", headers={"Authorization": f"Bearer {GOOD_CREDENTIAL}"})

    assert response.status_code == 401
    assert verifier.verify_calls == 0


def test_the_verifiers_own_credential_still_authenticates(client_backend: str) -> None:
    """The other direction: no `Authorization` header at all, and the request still verifies.
    A scheme that refused on its own absence would be a second gate in front of dispatch."""
    verifier, auth = bearer_auth()
    with client(session_app(auth), client_backend) as http:
        response = http.get("/required", headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 200
    assert verifier.verify_calls == 1


def test_an_anonymous_request_is_refused_by_us_and_not_by_the_scheme() -> None:
    """`MissingCredential`, our reason and our challenge — never `HTTPBearer`'s own 403."""
    _verifier, auth = bearer_auth()
    with client(session_app(auth)) as http:
        response = http.get("/required")

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}
    assert response.headers["www-authenticate"] == "Bearer"


def test_the_refusal_is_byte_identical_with_and_without_a_scheme() -> None:
    """The error-response oracle, applied to this work package: publishing a scheme changed
    the document and nothing at all that a client can observe on a refusal."""
    _documented, documented_auth = bearer_auth()
    plain_auth = BetterAuth(verifiers=[FakeVerifier(HEADER)])

    with (
        client(session_app(documented_auth)) as documented,
        client(session_app(plain_auth)) as plain,
    ):
        first = documented.get("/required")
        second = plain.get("/required")

    assert first.status_code == second.status_code
    assert first.content == second.content
    assert comparable_headers(first.headers) == comparable_headers(second.headers)


def test_a_scheme_does_not_cost_a_second_verification(client_backend: str) -> None:
    """The per-request cache anchor still holds with a declaration in the tree."""
    verifier, auth = bearer_auth()
    required = auth.current_session(user_model=User)
    optional = auth.optional_session(user_model=User)

    async def read(
        session: Session[User] = Depends(required),
        maybe: Session[User] | None = Depends(optional),
    ) -> dict[str, Any]:
        return {"same": maybe is session}

    app = FastAPI()
    app.add_api_route("/me", read, methods=["GET"])
    with client(app, client_backend) as http:
        response = http.get("/me", headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 200
    assert response.json() == {"same": True}
    assert verifier.verify_calls == 1


# --- the WebSocket shape the design exists for -----------------------------------------


def test_a_documented_dependency_still_resolves_on_a_websocket(client_backend: str) -> None:
    """`fastapi.security.HTTPBearer.__call__` takes a `Request`, and FastAPI fills a `Request`
    parameter only on an HTTP connection — so wiring the scheme object in as a live dependency
    raises `TypeError: missing 1 required positional argument: 'request'` on every WebSocket
    route. Our dependencies are `HTTPConnection`-shaped precisely so they serve both.
    """
    verifier, auth = bearer_auth()
    required = auth.current_session(user_model=User)
    app = FastAPI()

    async def socket(websocket: WebSocket, session: Session[User] = Depends(required)) -> None:
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


# --- nothing new becomes a documented parameter ----------------------------------------


@pytest.mark.parametrize("path", ["/required", "/optional"])
def test_the_declaration_never_becomes_a_documented_parameter(path: str) -> None:
    """A scheme declares itself under `security`; anything FastAPI did not recognize would
    surface as a required query parameter instead and break every route."""
    _verifier, auth = bearer_auth()
    operation: dict[str, Any] = document(auth)["paths"][path]["get"]

    assert operation.get("parameters", []) == []
    assert "requestBody" not in operation


def test_the_docs_page_renders_for_a_documented_app() -> None:
    _verifier, auth = bearer_auth()
    with client(session_app(auth)) as http:
        response = http.get("/docs")

    assert response.status_code == 200
    assert "swagger" in response.text.lower()
