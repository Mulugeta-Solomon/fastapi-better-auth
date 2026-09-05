"""B4: more than one `Origin` header on an unsafe request is a refusal, not a first-wins choice.

RFC 6454 gives a request exactly one `Origin`. `headers.get("origin")` answers the first of
however many arrived, so a request carrying an allow-listed origin beside a hostile one passed
on the strength of whichever the attacker arranged to arrive first. `CsrfFacts` counts the header
lines in `from_connection` and `_reject_bad_origin` judges the count - before the allowlist
compare, and inside `requires_check` like every other rung (D-184).

Its own file because `test_csrf.py`'s `http()` builds a scope from a keyword mapping and so
cannot express the one thing this subject is about: the same header name arriving twice. The
constants and policy factories are local for the same reason `test_refusal_frames.py`'s are -
a suite file that has to reach into another suite file for its fixtures is one refactor away
from breaking both.
"""

from __future__ import annotations

from typing import Any

import pytest
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    CsrfFacts,
    CsrfFailure,
    OriginCheck,
    SharedSecret,
    SignedDoubleSubmit,
)
from fastapi_better_auth._internal.csrf import DEFAULT_TOKEN_HEADER

APP = "https://app.example.com"
API = "https://api.example.com"
EVIL = "https://evil.example.com"
SECRET = SharedSecret("Qb8Xm2vTz6Lp1RkYd9Wn4Hs7Cj3Fg5Ae")
TOKEN = "vGm1nQ7bLxPd4Ks9.QkR2wYt6Zc8Ah5Vf0Bj3Nu7Md1Lp4Xe6Sg9Ry2Tw8Cq5="


def origin_check(**kwargs: Any) -> OriginCheck:
    kwargs.setdefault("allowed_origins", [APP])
    return OriginCheck(**kwargs)


def double_submit(**kwargs: Any) -> SignedDoubleSubmit:
    kwargs.setdefault("secret", SECRET)
    kwargs.setdefault("allowed_origins", [APP])
    return SignedDoubleSubmit(**kwargs)


def repeated_origins(*origins: str, method: str = "POST", **headers: str) -> HTTPConnection:
    """A scope carrying one `origin` header line per value - which `http()` cannot express."""
    raw = [(b"origin", origin.encode()) for origin in origins]
    raw += [(key.replace("_", "-").encode(), value.encode()) for key, value in headers.items()]
    return HTTPConnection({"type": "http", "method": method, "path": "/", "headers": raw})


@pytest.mark.parametrize(
    ("origins", "expected"),
    [((), 0), ((APP,), 1), ((APP, APP), 2), ((APP, EVIL), 2), ((APP, API, EVIL), 3)],
    ids=["none", "one", "twice-the-same", "one-of-each", "three"],
)
def test_the_snapshot_counts_the_origin_header_lines(
    origins: tuple[str, ...], expected: int
) -> None:
    captured = CsrfFacts.from_connection(repeated_origins(*origins), policy=origin_check())

    assert captured.origin_count == expected


@pytest.mark.parametrize("policy_of", [origin_check, double_submit], ids=["origin", "double"])
def test_two_origin_headers_are_refused_even_when_both_are_allowed(
    policy_of: Any,
) -> None:
    """RFC 6454 gives a request exactly one `Origin`. Two is a request no browser sends, and
    reading the first is a choice made on behalf of whoever arranged for the second - so it is
    refused before the allowlist is consulted, with both of them on the allowlist."""
    policy = policy_of(allowed_origins=[APP, API])
    captured = CsrfFacts.from_connection(repeated_origins(APP, API), policy=policy)

    with pytest.raises(CsrfFailure) as caught:
        policy.check(captured, TOKEN)

    assert "more than one Origin" in caught.value.reason
    assert caught.value.status_code == 403


@pytest.mark.parametrize(
    "origins", [(APP, EVIL), (EVIL, APP)], ids=["allowed-first", "hostile-first"]
)
def test_an_allowed_origin_beside_a_hostile_one_is_refused_in_either_order(
    origins: tuple[str, str],
) -> None:
    policy = origin_check()
    captured = CsrfFacts.from_connection(repeated_origins(*origins), policy=policy)

    with pytest.raises(CsrfFailure):
        policy.check(captured, TOKEN)


def test_one_origin_header_is_unchanged() -> None:
    """The control: the same request with a single `Origin` still passes both policies."""
    policy = origin_check()
    captured = CsrfFacts.from_connection(repeated_origins(APP), policy=policy)

    policy.check(captured, TOKEN)

    signed = double_submit()
    both = CsrfFacts.from_connection(
        repeated_origins(APP, **{DEFAULT_TOKEN_HEADER.replace("-", "_"): signed.token_for(TOKEN)}),
        policy=signed,
    )
    signed.check(both, TOKEN)


def test_a_second_origin_never_makes_the_snapshot_raise() -> None:
    """`from_connection` runs inside `extract` and owes the dispatcher a method no request can
    make raise; the count is recorded there and judged in `check`, where refusals belong."""
    captured = CsrfFacts.from_connection(
        repeated_origins("\x00 not a url", "x" * 9000), policy=double_submit()
    )

    assert captured.origin_count == 2


def test_two_origins_on_a_safe_method_are_not_a_refusal() -> None:
    """The rung is inside `requires_check`, like every other one: a GET carrying two `Origin`
    headers is odd, and refusing it would break reads no CSRF control is about."""
    policy = origin_check()
    captured = CsrfFacts.from_connection(repeated_origins(APP, EVIL, method="GET"), policy=policy)

    policy.check(captured, TOKEN)
