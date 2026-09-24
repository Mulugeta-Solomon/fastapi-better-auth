"""Where the CSRF policy runs: inside the cookie verifier, and nowhere else.

The policy is a step of `CookieVerifier` and of `RemoteVerifier`, not of the application, so it
runs exactly where a verifier runs - on a route that depends on a session dependency (or a gate
composed on one), and there only when the request carries that verifier's cookie. The README's
`### Where the CSRF check runs` states the consequences; these are its pins.

Every request here is shaped the way a browser sends a cross-site one - an `Origin` on another
registrable domain and `Sec-Fetch-Site: cross-site` - and the cookie is real: the same header is
served by every guarded route when it arrives from the allowed origin instead, which is what makes
the exemptions and the refusals facts about CSRF rather than about a cookie that never verified.
Each refusal is also pinned *before* the backend: a 403 that left the store unread (Mode A) or the
transport unused (Mode C) can only be the CSRF step, because an authorization 403 needs a
verified session first.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi import Depends, FastAPI

from fastapi_better_auth import BetterAuth, OriginCheck, Session, User
from fastapi_better_auth._internal.remote_verifier import RemoteVerifier
from tests import remote_fixtures as remote
from tests.cookies import APP, CAPTURED_TOKEN, COOKIE, USER_ID, seeded_store, sign, verifier
from tests.fakes import client
from tests.transports import ScriptedTransport, json_reply

CROSS_SITE = "https://attacker.example.net"
"""A registrable domain other than `APP`'s, so a browser calls the request cross-site."""

SIBLING = "https://blog.example.com"
"""`APP`'s registrable domain, so same-site: a `Lax` cookie rides on its requests. Not allowed."""

PUBLIC = "/access-requests"
OPTIONAL = "/reactions"
REQUIRED = "/posts"
GUARDED = (OPTIONAL, REQUIRED, "/drafts")
"""`optional_session`, `current_session`, and a `require` gate composed on it."""

UNSAFE_BEYOND_POST = ("PUT", "DELETE")
"""Unsafe methods other than the POST every other case uses; `REQUIRED` answers both."""

FORBIDDEN = {"detail": "Forbidden"}


@dataclass(frozen=True)
class Deployment:
    """One application, the session cookie its verifier reads, and a count of backend calls.

    The cookie is kept out of the repr: pytest renders an object it walked through on the way
    to a failed comparison, and a signed session cookie must not reach a failure message.
    """

    app: FastAPI
    cookie: str = field(repr=False)
    backend_calls: Callable[[], int] = field(repr=False)


def anyone(session: Session[User]) -> bool:
    """A rule every verified session passes, so a 403 behind it cannot be authorization."""
    return bool(session.user.id)


def routes(auth: BetterAuth) -> FastAPI:
    """A public POST beside three routes that depend on the verifier in the three ways it can be."""
    app = FastAPI()
    optional = auth.optional_session()
    required = auth.current_session()
    gated = auth.require(anyone, reason="any verified session")

    async def public() -> dict[str, bool]:
        return {"received": True}

    async def react(session: Session[User] | None = Depends(optional)) -> dict[str, Any]:
        return {"author": None if session is None else session.user.id}

    async def post(session: Session[User] = Depends(required)) -> dict[str, Any]:
        return {"author": session.user.id}

    async def draft(session: Session[User] = Depends(gated)) -> dict[str, Any]:
        return {"author": session.user.id}

    app.add_api_route(PUBLIC, public, methods=["POST"])
    app.add_api_route(OPTIONAL, react, methods=["POST"])
    for method in ("POST", *UNSAFE_BEYOND_POST):
        app.add_api_route(REQUIRED, post, methods=[method])
    app.add_api_route("/drafts", draft, methods=["POST"])
    return app


def mode_a() -> Deployment:
    store = seeded_store()
    built = verifier(store=store, csrf=OriginCheck(allowed_origins=[APP]))
    return Deployment(
        app=routes(BetterAuth(verifiers=[built])),
        cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}",
        backend_calls=lambda: len(store.session_calls),
    )


def mode_c(*, probed: bool) -> Deployment:
    """A first request, unprobed: one that reaches no outbound call reaches no probe either.

    The unprobed script would pass the probe (a `null` for the bare GET and for the bearer rung)
    and then serve the session, so a verifier that checked CSRF only after the network answers
    a real 403 and is caught by the count, not by a probe failure. The served control is probed.
    """
    session = json_reply(remote.document())
    csrf = OriginCheck(allowed_origins=[APP])
    if probed:
        transport = ScriptedTransport(session)
        built = remote.verifier(transport, csrf=csrf)
    else:
        transport = ScriptedTransport(json_reply(None), json_reply(None), session)
        built = RemoteVerifier(
            base_url=remote.ORIGIN, transport=transport, csrf=csrf, secure_cookies=False
        )
    return Deployment(
        app=routes(BetterAuth(verifiers=[built])),
        cookie=f"{remote.COOKIE_NAME}={remote.COOKIE_VALUE}",
        backend_calls=lambda: transport.calls,
    )


DEPLOYMENTS: dict[str, Callable[[], Deployment]] = {
    "mode-a": mode_a,
    "mode-c": lambda: mode_c(probed=False),
}
SERVED: dict[str, Callable[[], Deployment]] = {
    "mode-a": mode_a,
    "mode-c": lambda: mode_c(probed=True),
}


def cross_site(cookie: str | None = None) -> dict[str, str]:
    headers = {"Origin": CROSS_SITE, "Sec-Fetch-Site": "cross-site"}
    if cookie is not None:
        headers["Cookie"] = cookie
    return headers


def allowed(cookie: str) -> dict[str, str]:
    return {"Origin": APP, "Sec-Fetch-Site": "same-site", "Cookie": cookie}


@pytest.mark.parametrize("mode", SERVED)
@pytest.mark.parametrize("path", GUARDED)
def test_the_cookie_is_served_on_every_guarded_route_from_the_allowed_origin(
    mode: str, path: str, client_backend: str
) -> None:
    """The control: the cookie the refusals below carry is a real, verifying session."""
    deployment = SERVED[mode]()
    with client(deployment.app, client_backend) as http:
        served = http.post(path, headers=allowed(deployment.cookie))

    assert served.status_code == 200
    assert served.json() == {"author": USER_ID}
    calls = deployment.backend_calls()
    assert calls == 1


@pytest.mark.parametrize("mode", DEPLOYMENTS)
def test_a_public_route_that_reads_no_cookie_gets_no_csrf_answer(
    mode: str, client_backend: str
) -> None:
    """No session dependency, so no verifier: the cookie rides along and nothing reads it."""
    deployment = DEPLOYMENTS[mode]()
    with client(deployment.app, client_backend) as http:
        answered = http.post(PUBLIC, headers=cross_site(deployment.cookie))

    assert answered.status_code == 200
    assert answered.json() == {"received": True}
    calls = deployment.backend_calls()
    assert calls == 0


@pytest.mark.parametrize("mode", DEPLOYMENTS)
def test_an_optional_session_request_without_the_cookie_is_anonymous_and_unchecked(
    mode: str, client_backend: str
) -> None:
    """No credential, so the verifier is never dispatched and its policy never consulted."""
    deployment = DEPLOYMENTS[mode]()
    with client(deployment.app, client_backend) as http:
        answered = http.post(OPTIONAL, headers=cross_site())

    assert answered.status_code == 200
    assert answered.json() == {"author": None}
    calls = deployment.backend_calls()
    assert calls == 0


@pytest.mark.parametrize("mode", DEPLOYMENTS)
@pytest.mark.parametrize("path", GUARDED)
def test_a_guarded_route_carrying_the_cookie_is_refused_cross_site_before_the_backend(
    mode: str, path: str, client_backend: str
) -> None:
    """The cookie dispatches the verifier, and its CSRF step refuses before anything is read.

    For Mode C that is zero outbound traffic: neither the get-session fetch nor the readiness
    probe runs for a request the policy has already refused.
    """
    deployment = DEPLOYMENTS[mode]()
    with client(deployment.app, client_backend) as http:
        refused = http.post(path, headers=cross_site(deployment.cookie))

    assert refused.status_code == 403
    assert refused.json() == FORBIDDEN
    assert "www-authenticate" not in refused.headers
    calls = deployment.backend_calls()
    assert calls == 0


@pytest.mark.parametrize("mode", DEPLOYMENTS)
def test_a_same_site_sibling_carrying_the_cookie_is_refused_before_the_backend(
    mode: str, client_backend: str
) -> None:
    """`SameSite=Lax` does nothing against a sibling, so the policy is what refuses it.

    The browser attaches the cookie to a sibling's write because the request is same-site, and
    says so in `Sec-Fetch-Site`; `same-site` is not a pass, and the sibling's `Origin` is not on
    the allowlist, so the request stops at the CSRF step like a cross-site one.
    """
    deployment = DEPLOYMENTS[mode]()
    sibling = {"Origin": SIBLING, "Sec-Fetch-Site": "same-site", "Cookie": deployment.cookie}
    with client(deployment.app, client_backend) as http:
        refused = http.post(REQUIRED, headers=sibling)

    assert refused.status_code == 403
    assert refused.json() == FORBIDDEN
    calls = deployment.backend_calls()
    assert calls == 0


@pytest.mark.parametrize("mode", SERVED)
@pytest.mark.parametrize("method", UNSAFE_BEYOND_POST)
def test_every_unsafe_method_is_checked_not_only_post(
    mode: str, method: str, client_backend: str
) -> None:
    """Refused cross-site before the backend, then served from the allowed origin.

    The served half is what makes the refusal about CSRF: the same route, method and cookie
    verify and answer once the request comes from the front end.
    """
    deployment = SERVED[mode]()
    with client(deployment.app, client_backend) as http:
        refused = http.request(method, REQUIRED, headers=cross_site(deployment.cookie))
        before = deployment.backend_calls()
        served = http.request(method, REQUIRED, headers=allowed(deployment.cookie))

    assert refused.status_code == 403
    assert before == 0
    assert served.status_code == 200
    assert served.json() == {"author": USER_ID}
