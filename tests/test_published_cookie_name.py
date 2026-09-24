"""The cookie `/docs` names is the one cookie the verifier accepts (R46).

A cookie verifier's `credential_source` is the label every other part of the package reads: the
OpenAPI scheme's `name`, the operator-facing text naming the verifier, and the collision check. Under
the default `secure_cookies=True` the label used to carry the unprefixed name, while the verifier
reads only `{secure_prefix}{cookie_name}`. The document told a reader to send a cookie the verifier
refuses. Every `(secure_cookies, secure_prefix)` a verifier accepts is covered here, on the wire:
a validly signed cookie sent under the published name authenticates, and every other spelling of
the same base name does not.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI

from fastapi_better_auth import (
    AmbiguousCredentials,
    BetterAuth,
    ConfigurationError,
    User,
    Verifier,
)
from tests.cookies import CAPTURED_TOKEN, sign
from tests.cookies import verifier as cookie_verifier
from tests.fakes import GOOD_CREDENTIAL, FakeVerifier, client, connection, resolver_of, session_app
from tests.remote_fixtures import COOKIE_VALUE, document
from tests.remote_fixtures import verifier as remote_verifier
from tests.transports import ScriptedTransport, json_reply

COOKIE = "better-auth.session_token"
SPELLINGS = (COOKIE, f"__Secure-{COOKIE}", f"__Host-{COOKIE}")
SETTINGS = [
    (True, "__Secure-", f"__Secure-{COOKIE}"),
    (True, "__Host-", f"__Host-{COOKIE}"),
    (True, "", COOKIE),
    (False, "__Secure-", COOKIE),
    (False, "__Host-", COOKIE),
]
SETTING_IDS = ["secure", "host", "secure-empty-prefix", "plain", "plain-host-prefix"]
MODES = ["cookie", "remote"]


def built(mode: str, secure_cookies: bool, secure_prefix: str) -> tuple[Verifier, str]:
    """A verifier of either mode, and a validly signed value its own lookup accepts."""
    settings: dict[str, Any] = {"secure_cookies": secure_cookies, "secure_prefix": secure_prefix}
    if mode == "cookie":
        return cookie_verifier(**settings), sign(CAPTURED_TOKEN)
    return remote_verifier(ScriptedTransport(json_reply(document())), **settings), COOKIE_VALUE


def published_name(app: FastAPI) -> str:
    schemes: dict[str, Any] = app.openapi()["components"]["securitySchemes"]
    (scheme,) = schemes.values()
    name: str = scheme["name"]
    return name


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(("secure", "prefix", "accepted"), SETTINGS, ids=SETTING_IDS)
def test_the_published_name_is_the_one_cookie_read(
    mode: str, secure: bool, prefix: str, accepted: str
) -> None:
    verifier, _value = built(mode, secure, prefix)
    app = session_app(BetterAuth(verifiers=[verifier]))

    assert published_name(app) == accepted
    assert verifier.credential_source == f"cookie:{accepted}"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(("secure", "prefix", "accepted"), SETTINGS, ids=SETTING_IDS)
def test_a_signed_cookie_under_the_published_name_authenticates_and_no_other_spelling_does(
    mode: str, secure: bool, prefix: str, accepted: str, client_backend: str
) -> None:
    verifier, value = built(mode, secure, prefix)
    app = session_app(BetterAuth(verifiers=[verifier]))
    published = published_name(app)

    with client(app, client_backend) as http:
        answers = {
            name: http.get("/required", headers={"Cookie": f"{name}={value}"}).status_code
            for name in SPELLINGS
        }

    assert answers == {name: 200 if name == published else 401 for name in SPELLINGS}
    assert published == accepted


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
async def test_the_operator_text_naming_the_verifier_names_the_cookie_it_reads(mode: str) -> None:
    """`core._named` is what an ambiguity or a missing-credential reason names a verifier by."""
    verifier, value = built(mode, True, "__Secure-")
    auth = BetterAuth(verifiers=[verifier, FakeVerifier("x-other")])
    resolve = resolver_of(auth.current_session(user_model=User))
    presented = connection(cookie=f"__Secure-{COOKIE}={value}", x_other=GOOD_CREDENTIAL)

    with pytest.raises(AmbiguousCredentials) as caught:
        await resolve(presented)

    assert f"{type(verifier).__name__}(cookie:__Secure-{COOKIE})" in caught.value.reason


def test_two_verifiers_accepting_the_very_same_cookie_are_refused() -> None:
    """One reads `__Secure-X` because `cookie_name` says so, the other because `secure_cookies`
    does. Both would claim every request carrying it, so every such request is ambiguous: a total
    outage for that cookie that construction must refuse rather than call healthy."""
    with pytest.raises(ConfigurationError):
        BetterAuth(
            verifiers=[
                cookie_verifier(cookie_name=f"__Secure-{COOKIE}", secure_cookies=False),
                cookie_verifier(cookie_name=COOKIE, secure_cookies=True),
            ]
        )


def test_a_prefix_no_browser_enforces_is_part_of_an_unrelated_name() -> None:
    """Only `__Secure-` and `__Host-` mean anything to a browser (RFC 6265bis §4.1.3). A custom
    `secure_prefix` makes a different cookie, as unrelated to the plain one as `my.session` is to
    `session`, so the two compose and each is documented under its own name."""
    auth = BetterAuth(
        verifiers=[
            cookie_verifier(secure_cookies=True, secure_prefix="myapp-"),
            cookie_verifier(secure_cookies=False),
        ]
    )
    schemes: dict[str, Any] = session_app(auth).openapi()["components"]["securitySchemes"]

    assert sorted(scheme["name"] for scheme in schemes.values()) == [COOKIE, f"myapp-{COOKIE}"]
