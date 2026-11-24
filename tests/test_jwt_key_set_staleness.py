"""How long a held key set is honoured, and who waits for its refresh - from `JwtVerifier`'s side.

`test_jwks_cache.py` pins the client's fetch policy directly; this file drives the same rules the
way a deployment meets them, through `JwtVerifier.verify` built by its public constructor, with the
scripted transport standing in for upstream and the key-set client's monotonic clock wound by hand
(`wind_jwks_clock`). PyJWT's own clock is the real one, so every token here is minted live and
only the key set ages.
"""

from __future__ import annotations

import inspect
import logging
from typing import Any

import pytest

from fastapi_better_auth import AuthServiceUnavailable, ConfigurationError, User
from fastapi_better_auth._internal.jwks import CACHE_TTL, MAX_STALE, REFETCH_INTERVAL
from fastapi_better_auth._internal.jwt_verifier import JwtVerifier
from tests.jwks_fixtures import wind_jwks_clock
from tests.jwt_fixtures import KEY_SET, SIGNER, build
from tests.tokens import claims
from tests.transports import json_reply

DAY = 86_400.0
"""The default bound on a held key set's age: tokens live fifteen minutes, so a stale set only
helps while this service cannot reach the JWKS but browsers can still reach the auth server - a
day covers a real outage, and forever would keep a withdrawn key verifying through one."""
DOWN = TimeoutError("jwks unreachable")
SERVING = "jwks refresh failed for %s; serving the key set on hand"


def _serving_lines(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.msg == SERVING]


@pytest.mark.anyio
async def test_the_key_set_cache_ages_on_the_wound_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prove the instrument: the verifier's key set is refetched exactly when the wound clock
    says its TTL has passed, and not a moment before - so the tests below measure policy."""
    clock = wind_jwks_clock(monkeypatch)
    verifier, transport = build()
    token = SIGNER.sign(claims())

    await verifier.verify(token, User)
    clock.advance(CACHE_TTL - 1)
    await verifier.verify(token, User)
    assert transport.calls == 1

    clock.advance(2)
    await verifier.verify(token, User)
    assert transport.calls == 2


# --- the bound on staleness ---------------------------------------------------------------


@pytest.mark.anyio
async def test_a_held_key_set_is_still_honoured_just_before_the_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The availability the stale set exists for: upstream unreachable, a valid token verifies."""
    clock = wind_jwks_clock(monkeypatch)
    verifier, transport = build(json_reply(KEY_SET), DOWN)
    token = SIGNER.sign(claims())

    await verifier.verify(token, User)
    clock.advance(DAY - 1)

    session = await verifier.verify(token, User)

    assert session.user.id == claims()["sub"]
    assert transport.calls == 2, "the stale set must have been refreshed for, and failed"


@pytest.mark.anyio
async def test_a_held_key_set_is_still_honoured_at_exactly_the_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`max_stale` is how long a set is honoured *at most*: at exactly that age it still is."""
    clock = wind_jwks_clock(monkeypatch)
    verifier, _transport = build(json_reply(KEY_SET), DOWN)
    token = SIGNER.sign(claims())

    await verifier.verify(token, User)
    clock.advance(DAY)

    assert (await verifier.verify(token, User)).user.id == claims()["sub"]


@pytest.mark.anyio
async def test_a_held_key_set_past_the_bound_is_no_longer_honoured(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """F4.1: a set fetched a day ago and never confirmed since may carry a key the auth server
    withdrew after a compromise. Past the bound it is not honoured, and the answer is that the
    keys cannot be known - unavailable, not a credential refusal. RED before the bound: the set
    on hand was honoured for as long as the refresh kept failing.

    The failed refresh is not reported as "serving the key set on hand" either: past the bound
    nothing is served, and a line saying otherwise would mislead the operator reading it."""
    clock = wind_jwks_clock(monkeypatch)
    verifier, transport = build(json_reply(KEY_SET), DOWN)
    token = SIGNER.sign(claims())

    await verifier.verify(token, User)
    clock.advance(DAY + 1)

    with caplog.at_level(logging.WARNING), pytest.raises(AuthServiceUnavailable):
        await verifier.verify(token, User)
    assert transport.calls == 2, "the refresh must have been attempted, and failed"
    assert _serving_lines(caplog) == []


@pytest.mark.anyio
async def test_a_refresh_failing_inside_the_bound_says_it_serves_the_set_on_hand(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The control for the assertion above: inside the bound the line is logged."""
    clock = wind_jwks_clock(monkeypatch)
    verifier, _transport = build(json_reply(KEY_SET), DOWN)
    token = SIGNER.sign(claims())

    await verifier.verify(token, User)
    clock.advance(DAY)

    with caplog.at_level(logging.WARNING):
        await verifier.verify(token, User)
    assert len(_serving_lines(caplog)) == 1


@pytest.mark.anyio
async def test_the_bound_holds_while_the_refetch_window_is_shut(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bound is not decided by the refresh failing: a request that crosses it inside the
    refetch window, with no fetch made at all, is refused just the same."""
    clock = wind_jwks_clock(monkeypatch)
    verifier, transport = build(json_reply(KEY_SET), DOWN)
    token = SIGNER.sign(claims())

    await verifier.verify(token, User)
    clock.advance(DAY)
    await verifier.verify(token, User)  # refreshes, fails, serves: the window is now shut
    clock.advance(1)

    with pytest.raises(AuthServiceUnavailable):
        await verifier.verify(token, User)
    assert transport.calls == 2, "the window was shut; no fetch should have been made"


@pytest.mark.anyio
async def test_past_the_bound_refresh_attempts_keep_their_schedule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Past the bound every request is unavailable, and still at most one fetch per refetch
    window - an outage must not turn into one JWKS call per request."""
    clock = wind_jwks_clock(monkeypatch)
    verifier, transport = build(json_reply(KEY_SET), DOWN)
    token = SIGNER.sign(claims())

    await verifier.verify(token, User)
    clock.advance(DAY + 1)
    for _ in range(5):
        with pytest.raises(AuthServiceUnavailable):
            await verifier.verify(token, User)
    assert transport.calls == 2

    clock.advance(REFETCH_INTERVAL)
    with pytest.raises(AuthServiceUnavailable):
        await verifier.verify(token, User)
    assert transport.calls == 3


@pytest.mark.anyio
async def test_a_key_set_past_the_bound_recovers_on_the_next_successful_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bound is a state, not a latch: once upstream answers again, the fresh set verifies."""
    clock = wind_jwks_clock(monkeypatch)
    verifier, transport = build(json_reply(KEY_SET), DOWN, json_reply(KEY_SET))
    token = SIGNER.sign(claims())

    await verifier.verify(token, User)
    clock.advance(DAY + 1)
    with pytest.raises(AuthServiceUnavailable):
        await verifier.verify(token, User)
    clock.advance(REFETCH_INTERVAL)

    assert (await verifier.verify(token, User)).user.id == claims()["sub"]
    assert transport.calls == 3


@pytest.mark.anyio
async def test_an_explicit_max_stale_is_the_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bound is configurable next to `cache_ttl`, both shorter and longer than a day."""
    clock = wind_jwks_clock(monkeypatch)
    short, _ = build(json_reply(KEY_SET), DOWN, max_stale=3600)
    long, _ = build(json_reply(KEY_SET), DOWN, max_stale=3 * DAY)
    token = SIGNER.sign(claims())

    await short.verify(token, User)
    await long.verify(token, User)
    clock.advance(3601)

    with pytest.raises(AuthServiceUnavailable):
        await short.verify(token, User)
    clock.advance(2 * DAY)
    assert (await long.verify(token, User)).user.id == claims()["sub"]


def test_max_stale_defaults_to_a_day() -> None:
    assert inspect.signature(JwtVerifier).parameters["max_stale"].default == DAY
    assert MAX_STALE == DAY


@pytest.mark.parametrize(
    ("cache_ttl", "max_stale"),
    [(300, 300), (300, 301), (60, 60.0), (3600, DAY)],
    ids=["equal", "just-above", "float", "an-hour-ttl"],
)
def test_a_max_stale_no_shorter_than_the_cache_ttl_is_accepted(
    cache_ttl: float, max_stale: float
) -> None:
    build(cache_ttl=cache_ttl, max_stale=max_stale)


@pytest.mark.parametrize(
    ("cache_ttl", "max_stale"),
    [
        (300, 299),
        (300, 0),
        (300, -1),
        (2 * DAY, None),
        (300, None),
        (300, float("inf")),
        (300, float("nan")),
        (300, "86400"),
        (300, True),
    ],
    ids=[
        "below-the-ttl",
        "zero",
        "negative",
        "a-ttl-over-the-default-bound",
        "none-is-not-unbounded",
        "inf",
        "nan",
        "a-string",
        "a-bool",
    ],
)
def test_a_max_stale_that_is_not_a_finite_bound_at_least_the_ttl_is_refused(
    cache_ttl: float, max_stale: Any
) -> None:
    """There is no way to switch the bound off - not `None`, not infinity - and a bound below
    the TTL contradicts it. A `cache_ttl` above the one-day default needs an explicit bound."""
    with pytest.raises(ConfigurationError) as caught:
        build(cache_ttl=cache_ttl, max_stale=max_stale)

    assert "max_stale" in str(caught.value)


def test_the_default_bound_refuses_a_cache_ttl_longer_than_a_day() -> None:
    """The upgrade edge, stated: a deployment that set `cache_ttl` above a day and nothing else
    no longer starts, and the message says which option to set."""
    with pytest.raises(ConfigurationError) as caught:
        build(cache_ttl=2 * DAY)

    assert "max_stale" in str(caught.value)
    assert "cache_ttl" in str(caught.value)
