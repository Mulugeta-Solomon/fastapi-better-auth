"""Which cookie verifiers compose in one application, decided by the cookies they accept.

A cookie verifier accepts exactly one name: `{secure_prefix}{cookie_name}` under the default
`secure_cookies=True`, the plain `cookie_name` otherwise (D-189). Two verifiers that accept one base
name under different browser prefixes (plain beside `__Secure-`, or `__Secure-` beside `__Host-`)
read one Better Auth session cookie under two names. That is the configuration D-189 refuses inside a
single verifier, rebuilt out of two, so `BetterAuth` refuses it at construction. Cookies that only
share a suffix are unrelated, and they compose.

Everything here was green before WP30 changed what a cookie verifier's label says, and it is still
green after. The label changed; which compositions are refused did not.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from fastapi_better_auth import BetterAuth, ConfigurationError, Verifier
from tests.cookies import verifier as cookie_verifier
from tests.fakes import session_app
from tests.remote_fixtures import document
from tests.remote_fixtures import verifier as remote_verifier
from tests.transports import ScriptedTransport, json_reply

COOKIE = "better-auth.session_token"


def cookie_mode(**settings: Any) -> Verifier:
    return cookie_verifier(**settings)


def remote_mode(**settings: Any) -> Verifier:
    return remote_verifier(ScriptedTransport(json_reply(document())), **settings)


MODES: dict[str, Callable[..., Verifier]] = {"cookie": cookie_mode, "remote": remote_mode}
PAIRS = [("cookie", "cookie"), ("remote", "cookie"), ("cookie", "remote"), ("remote", "remote")]
PAIR_IDS = ["A+A", "C+A", "A+C", "C+C"]


def refusal(verifiers: list[Verifier]) -> str:
    with pytest.raises(ConfigurationError) as caught:
        BetterAuth(verifiers=verifiers)
    return str(caught.value)


def documented_cookies(auth: BetterAuth) -> int:
    schemes: dict[str, Any] = session_app(auth).openapi()["components"]["securitySchemes"]
    return sum(scheme["in"] == "cookie" for scheme in schemes.values())


# --- one base name under two prefixes is refused ----------------------------------------


@pytest.mark.parametrize(("first", "second"), PAIRS, ids=PAIR_IDS)
@pytest.mark.parametrize("secure_first", [True, False], ids=["secure-first", "plain-first"])
def test_one_cookie_read_plain_and_secure_prefixed_is_refused(
    first: str, second: str, secure_first: bool
) -> None:
    message = refusal(
        [
            MODES[first](secure_cookies=secure_first),
            MODES[second](secure_cookies=not secure_first),
        ]
    )

    assert {f"{first.title()}Verifier", f"{second.title()}Verifier"} <= set(message.split())


@pytest.mark.parametrize(("first", "second"), PAIRS, ids=PAIR_IDS)
def test_one_cookie_read_under_secure_and_host_prefixes_is_refused(first: str, second: str) -> None:
    message = refusal(
        [
            MODES[first](secure_cookies=True),
            MODES[second](secure_cookies=True, secure_prefix="__Host-"),
        ]
    )

    assert {f"{first.title()}Verifier", f"{second.title()}Verifier"} <= set(message.split())


@pytest.mark.parametrize(("first", "second"), PAIRS, ids=PAIR_IDS)
@pytest.mark.parametrize("secure_first", [True, False], ids=["secure-first", "plain-first"])
@pytest.mark.parametrize("configured", ["__Host-x", "__Secure-x"])
def test_a_configured_name_that_carries_a_browser_prefix_is_still_one_base(
    first: str, second: str, secure_first: bool, configured: str
) -> None:
    """A `cookie_name` may itself begin with a browser prefix. Plain, `__Host-x` is read as
    `__Host-x`; secure, as `__Secure-__Host-x`. That is still one configured base read plain and
    prefixed, the pair above."""
    message = refusal(
        [
            MODES[first](cookie_name=configured, secure_cookies=secure_first),
            MODES[second](cookie_name=configured, secure_cookies=not secure_first),
        ]
    )

    assert {f"{first.title()}Verifier", f"{second.title()}Verifier"} <= set(message.split())


@pytest.mark.parametrize("prefix", ["__SECURE-", "__secure-", "__HOST-", "__host-"])
def test_a_prefix_in_another_case_is_still_that_prefix(prefix: str) -> None:
    """RFC 6265bis §5.4: a user agent matches `__Secure-` and `__Host-` case-insensitively, so a
    `__secure-` cookie is a secure-prefixed cookie to the browser, and beside the plain one it is
    the same pair as above."""
    refusal(
        [
            cookie_mode(secure_cookies=True, secure_prefix=prefix),
            remote_mode(secure_cookies=False),
        ]
    )


# --- unrelated cookies still compose ------------------------------------------------------


@pytest.mark.parametrize(
    ("first_name", "second_name"),
    [(COOKIE, "other.session_token"), ("session", "my.session"), ("my.session", "session")],
)
@pytest.mark.parametrize(
    ("first_secure", "second_secure"),
    [(True, True), (True, False), (False, True), (False, False)],
    ids=["both-secure", "secure-plain", "plain-secure", "both-plain"],
)
def test_two_unrelated_cookies_compose(
    first_name: str, second_name: str, first_secure: bool, second_secure: bool
) -> None:
    auth = BetterAuth(
        verifiers=[
            cookie_mode(cookie_name=first_name, secure_cookies=first_secure),
            remote_mode(cookie_name=second_name, secure_cookies=second_secure),
        ]
    )

    assert documented_cookies(auth) == 2
