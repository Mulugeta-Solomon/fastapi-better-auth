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

from typing import Any, cast

import pytest
from fastapi import Depends, FastAPI, Security, WebSocket
from fastapi.security import APIKeyCookie

from fastapi_better_auth import (
    BetterAuth,
    ConfigurationError,
    CsrfDisabled,
    JwtVerifier,
    RemoteVerifier,
    Session,
    User,
)
from tests.cookies import verifier as cookie_verifier
from tests.fakes import GOOD_CREDENTIAL, FakeVerifier, client, session_app
from tests.transports import ScriptedTransport

BEARER_SOURCE = "header:authorization-bearer"
COOKIE_SOURCE = "cookie:better-auth.session_token"
BEARER_NAME = "BetterAuthBearer"
COOKIE_NAME = "BetterAuthCookie"
DERIVED_COOKIE_NAME = "BetterAuthCookie-better-auth.session_token"
HEADER = "x-cred-a"
HEADER_B = "x-cred-b"

DEFAULT_COOKIE = "better-auth.session_token"
SECURE_COOKIE = "__Secure-better-auth.session_token"
PROD_COOKIE = "sorapredict-prod.session_token"
STAGING_COOKIE = "sorapredict-staging.session_token"
ORIGIN = "https://auth.example.com"

BEARER_DEFINITION = {"type": "http", "scheme": "bearer"}
COOKIE_DEFINITION = {"type": "apiKey", "in": "cookie"}
ABSENT = object()


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


def never_fetched() -> ScriptedTransport:
    return ScriptedTransport(AssertionError("building a document must not fetch anything"))


def remote_verifier(cookie: str, transport: ScriptedTransport) -> RemoteVerifier:
    return RemoteVerifier(
        base_url=ORIGIN,
        csrf=CsrfDisabled(reason="only the published document is read here"),
        transport=transport,
        cookie_name=cookie,
        secure_cookies=False,
    )


def leaves(node: object, path: tuple[str, ...] = ()) -> dict[tuple[str, ...], object]:
    """Every leaf of a JSON document, keyed by its path. An empty container is a leaf too, or a
    requirement such as `{"BetterAuthCookie": []}` would drop out of a diff along with its key."""
    children: tuple[tuple[str, object], ...] = ()
    if isinstance(node, dict):
        children = tuple(cast("dict[str, object]", node).items())
    elif isinstance(node, list):
        items = cast("list[object]", node)
        children = tuple((str(index), item) for index, item in enumerate(items))
    if not children:
        return {path: node}
    return {
        leaf: value
        for key, child in children
        for leaf, value in leaves(child, (*path, key)).items()
    }


def differing(first: object, second: object) -> dict[tuple[str, ...], tuple[object, object]]:
    """Every path at which two documents disagree, with what each side holds there."""
    left, right = leaves(first), leaves(second)
    return {
        path: (left.get(path, ABSENT), right.get(path, ABSENT))
        for path in left.keys() | right.keys()
        if left.get(path, ABSENT) != right.get(path, ABSENT)
    }


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


@pytest.mark.parametrize(
    "cookie", [DEFAULT_COOKIE, SECURE_COOKIE], ids=["plain", "secure-prefixed"]
)
def test_a_cookie_verifier_publishes_an_api_key_cookie_scheme(cookie: str) -> None:
    """The label already says where the credential lives. The application's only cookie is
    published under the one stable key, and the scheme's `name` is that cookie, verbatim - the
    `__Secure-` form included, since a cookie name is case- and prefix-exact."""
    auth = BetterAuth(verifiers=[FakeVerifier(HEADER, source=f"cookie:{cookie}")])
    published = schemes(auth)

    assert set(published) == {COOKIE_NAME}
    assert {key: published[COOKIE_NAME][key] for key in COOKIE_DEFINITION} == COOKIE_DEFINITION
    assert published[COOKIE_NAME]["name"] == cookie
    assert cookie in published[COOKIE_NAME]["description"]


@pytest.mark.parametrize("sole", [True, False], ids=["sole-cookie", "one-of-two"])
def test_only_the_key_differs_from_what_fastapis_own_api_key_cookie_publishes(sole: bool) -> None:
    """Choosing the key must not hand-assemble the definition: it stays byte-for-byte what a
    plain FastAPI application publishes for `APIKeyCookie` on the same cookie."""
    others = [] if sole else [FakeVerifier(HEADER_B, source=f"cookie:{SECURE_COOKIE}")]
    auth = BetterAuth(verifiers=[FakeVerifier(HEADER, source=COOKIE_SOURCE), *others])
    key = COOKIE_NAME if sole else DERIVED_COOKIE_NAME
    published = schemes(auth)[key]
    reference = APIKeyCookie(
        name=DEFAULT_COOKIE, description=published["description"], auto_error=False
    )

    async def plain(_credential: str | None = Security(reference)) -> None:
        return None

    app = FastAPI()
    app.add_api_route("/plain", plain, methods=["GET"])
    (expected,) = app.openapi()["components"]["securitySchemes"].values()

    assert published == expected


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
    """Two cookie verifiers on different cookies must not collapse onto one definition, so each
    keeps a key derived from its own cookie."""
    auth = BetterAuth(
        verifiers=[
            FakeVerifier(HEADER, source=COOKIE_SOURCE),
            FakeVerifier(HEADER_B, source=f"cookie:{SECURE_COOKIE}"),
        ]
    )

    assert set(schemes(auth)) == {
        DERIVED_COOKIE_NAME,
        "BetterAuthCookie-__Secure-better-auth.session_token",
    }


# --- one cookie, one stable key --------------------------------------------------------


def test_one_cookie_publishes_one_contract_whatever_the_cookie_is_called() -> None:
    """#70: a per-environment `cookiePrefix` must not make the contract per-environment.

    Two deployments that differ only in the cookie's name publish the same component key and the
    same requirement on every operation. Diffed leaf by leaf, the documents disagree in exactly
    two places, the scheme's `name` and its description: the two that must name the cookie."""
    prod = document(BetterAuth(verifiers=[cookie_verifier(cookie_name=PROD_COOKIE)]))
    staging = document(BetterAuth(verifiers=[cookie_verifier(cookie_name=STAGING_COOKIE)]))
    scheme = ("components", "securitySchemes", COOKIE_NAME)

    assert set(prod["components"]["securitySchemes"]) == {COOKIE_NAME}
    assert set(staging["components"]["securitySchemes"]) == {COOKIE_NAME}
    for path in ("/required", "/optional"):
        assert prod["paths"][path]["get"]["security"] == [{COOKIE_NAME: []}]
        assert staging["paths"][path]["get"]["security"] == [{COOKIE_NAME: []}]
    diff = differing(prod, staging)
    assert set(diff) == {(*scheme, "name"), (*scheme, "description")}
    assert diff[(*scheme, "name")] == (PROD_COOKIE, STAGING_COOKIE)
    prod_description, staging_description = diff[(*scheme, "description")]
    assert PROD_COOKIE in str(prod_description)
    assert STAGING_COOKIE in str(staging_description)


@pytest.mark.parametrize(
    "order", [("cookie", "bearer"), ("bearer", "cookie")], ids=["cookie-first", "bearer-first"]
)
def test_mode_a_beside_mode_b_publishes_both_stable_keys_in_declaration_order(
    order: tuple[str, str],
) -> None:
    """A bearer is not a cookie: Mode A + Mode B is still one cookie, so its key stays stable."""
    transport = never_fetched()
    modes = {
        "cookie": (cookie_verifier(), COOKIE_NAME),
        "bearer": (JwtVerifier(base_url=ORIGIN, transport=transport), BEARER_NAME),
    }
    auth = BetterAuth(verifiers=[modes[mode][0] for mode in order])

    assert set(schemes(auth)) == {COOKIE_NAME, BEARER_NAME}
    assert security(auth, "/required") == [{modes[mode][1]: []} for mode in order]
    assert transport.calls == 0


def test_two_distinct_cookies_each_keep_a_key_derived_from_their_name() -> None:
    """The one case a single key cannot name: two different cookies. Each is published as
    `BetterAuthCookie-<name>`, which means a second cookie verifier renames the first one's key."""
    transport = never_fetched()
    alone = BetterAuth(verifiers=[cookie_verifier(cookie_name=PROD_COOKIE)])
    together = BetterAuth(
        verifiers=[
            cookie_verifier(cookie_name=PROD_COOKIE),
            remote_verifier(STAGING_COOKIE, transport),
        ]
    )
    published = schemes(together)

    assert set(schemes(alone)) == {COOKIE_NAME}
    assert security(together, "/required") == [
        {f"BetterAuthCookie-{PROD_COOKIE}": []},
        {f"BetterAuthCookie-{STAGING_COOKIE}": []},
    ]
    assert {key: published[key]["name"] for key in published} == {
        f"BetterAuthCookie-{PROD_COOKIE}": PROD_COOKIE,
        f"BetterAuthCookie-{STAGING_COOKIE}": STAGING_COOKIE,
    }
    assert transport.calls == 0


def test_one_cookie_behind_two_labels_is_still_refused_at_construction() -> None:
    """Two labels, one cookie. They are distinct `credential_source` values, so the duplicate
    label check lets them through; counted as two cookie declarations, each takes the derived key,
    the keys collide, and construction refuses with the message it always gave."""
    with pytest.raises(ConfigurationError) as caught:
        BetterAuth(
            verifiers=[
                FakeVerifier(HEADER, source="cookie:session"),
                FakeVerifier(HEADER_B, source="cookie: session"),
            ]
        )

    assert "'BetterAuthCookie-session'" in str(caught.value)


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
