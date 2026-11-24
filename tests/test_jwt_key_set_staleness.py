"""How long a held key set is honoured, and who waits for its refresh - from `JwtVerifier`'s side.

`test_jwks_cache.py` pins the client's fetch policy directly; this file drives the same rules the
way a deployment meets them, through `JwtVerifier.verify` built by its public constructor, with the
scripted transport standing in for upstream and the key-set client's monotonic clock wound by hand
(`wind_jwks_clock`). PyJWT's own clock is the real one, so every token here is minted live and
only the key set ages.
"""

from __future__ import annotations

import pytest

from fastapi_better_auth import AuthServiceUnavailable, User
from fastapi_better_auth._internal.jwks import CACHE_TTL, REFETCH_INTERVAL
from tests.jwks_fixtures import wind_jwks_clock
from tests.jwt_fixtures import KEY_SET, SIGNER, build
from tests.tokens import claims
from tests.transports import json_reply

DAY = 86_400.0
"""The default bound on a held key set's age: tokens live fifteen minutes, so a stale set only
helps while this service cannot reach the JWKS but browsers can still reach the auth server - a
day covers a real outage, and forever would keep a withdrawn key verifying through one."""
DOWN = TimeoutError("jwks unreachable")


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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F4.1: a set fetched a day ago and never confirmed since may carry a key the auth server
    withdrew after a compromise. Past the bound it is not honoured, and the answer is that the
    keys cannot be known - unavailable, not a credential refusal. RED before the bound: the set
    on hand was honoured for as long as the refresh kept failing."""
    clock = wind_jwks_clock(monkeypatch)
    verifier, _transport = build(json_reply(KEY_SET), DOWN)
    token = SIGNER.sign(claims())

    await verifier.verify(token, User)
    clock.advance(DAY + 1)

    with pytest.raises(AuthServiceUnavailable):
        await verifier.verify(token, User)


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
