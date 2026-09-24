"""What a `credential_source` label means: the key two labels share when they name one credential.

`collision_key` is what `BetterAuth` refuses on. A cookie label is reduced to its cookie's base
name, and the base is what is left once every leading browser prefix is gone: a configured name can
itself begin with `__Host-`, and the secure posture then reads `__Secure-__Host-x`, which is still
the plain `__Host-x`'s base read prefixed. Only `__Secure-` and `__Host-` are browser prefixes; any
other leading text is part of an unrelated name.
"""

from __future__ import annotations

import pytest

from fastapi_better_auth._internal.labels import collision_key


@pytest.mark.parametrize(
    "source",
    [
        "cookie:x",
        "cookie:__Secure-x",
        "cookie:__Host-x",
        "cookie:__Secure-__Host-x",
        "cookie:__Host-__Secure-x",
        "cookie:__Host-__Secure-__Host-x",
        "COOKIE:__sEcUrE-__HoSt-X",
        "  cookie:  __HOST-__SECURE-x  ",
    ],
)
def test_every_leading_browser_prefix_is_removed_in_any_case(source: str) -> None:
    assert collision_key(source) == "cookie:x"


@pytest.mark.parametrize(
    ("source", "key"),
    [
        ("cookie:myapp-__Host-x", "cookie:myapp-__host-x"),
        ("cookie:x__Secure-", "cookie:x__secure-"),
        ("cookie:__Secure", "cookie:__secure"),
        ("cookie:my.session", "cookie:my.session"),
    ],
)
def test_a_prefix_that_does_not_lead_is_part_of_the_name(source: str, key: str) -> None:
    assert collision_key(source) == key


@pytest.mark.parametrize(
    ("source", "key"),
    [
        ("header:authorization-bearer", "header:authorization-bearer"),
        ("  Header:X-Gateway-Assertion ", "header:x-gateway-assertion"),
        ("cookie:", "cookie:"),
    ],
)
def test_a_label_that_names_no_cookie_is_compared_casefolded_and_stripped(
    source: str, key: str
) -> None:
    assert collision_key(source) == key
