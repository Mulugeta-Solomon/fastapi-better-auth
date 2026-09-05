"""`resolve_named_cookie` - the (name, value) form Mode C forwards, over the one configured base.

`resolve_cookie_value` is now its `.value` projection, so the existing byte-unchanged suite in
`test_cookie_parsing.py` also pins the value half of this. These rows pin the name half and the
one-base rule the audit's D-189 fix put in place: the resolved name is the configured base, never
a second accept-both name.
"""

from __future__ import annotations

import pytest

from fastapi_better_auth import InvalidCredential
from fastapi_better_auth._internal.cookie_parsing import (
    resolve_cookie_value,
    resolve_named_cookie,
)

COOKIE = "better-auth.session_token"
SECURE = "__Secure-better-auth.session_token"


def pairs(*items: tuple[str, str]) -> tuple[tuple[str, str], ...]:
    return items


def test_a_whole_cookie_resolves_to_its_base_name_and_value() -> None:
    assert resolve_named_cookie(pairs((COOKIE, "value")), COOKIE) == (COOKIE, "value")


def test_reassembled_chunks_resolve_under_the_base_name() -> None:
    """A chunked arrival reassembles to one value forwarded under the base name, never a chunk."""
    resolved = resolve_named_cookie(pairs((f"{COOKIE}.1", "BB"), (f"{COOKIE}.0", "AA")), COOKIE)

    assert resolved == (COOKIE, "AABB")


def test_only_the_configured_base_is_resolved() -> None:
    """D-189: the plain base resolves the plain value; a `__Secure-` cookie beside it is not read."""
    name, value = resolve_named_cookie(pairs((COOKIE, "plain"), (SECURE, "secure")), COOKIE)

    assert (name, value) == (COOKIE, "plain")


def test_resolve_cookie_value_is_the_value_projection() -> None:
    both = pairs((COOKIE, "value"))

    assert resolve_cookie_value(both, COOKIE) == resolve_named_cookie(both, COOKIE)[1]


def test_a_duplicate_base_name_is_refused() -> None:
    with pytest.raises(InvalidCredential) as caught:
        resolve_named_cookie(pairs((COOKIE, "one"), (COOKIE, "two")), COOKIE)

    assert "more than once" in caught.value.reason


def test_no_material_is_refused_defensively() -> None:
    with pytest.raises(InvalidCredential) as caught:
        resolve_named_cookie(pairs(("unrelated", "x")), COOKIE)

    assert "no session cookie material" in caught.value.reason
