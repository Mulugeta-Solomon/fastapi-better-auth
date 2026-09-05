"""The JWKS client's cache and staleness policy: how many fetches, in what window, behind the lock.

The wire and key-loading rules live in `test_jwks_client.py`; this file is the other half — the
freshness cache, the single-flight lock (proven on both backends, including a leader cancelled
mid-fetch), the bounded negative cache for unknown kids, the refetch window, and the one bargain
staleness buys: a key we hold verifies what it signed, while a kid we cannot confirm is unavailable
rather than unknown. The transport is a double (see `tests/transports.py`) because what is under
test is the policy, not the socket.
"""

from __future__ import annotations

import anyio
import anyio.lowlevel
import pytest

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuthError,
    ConfigurationError,
    SessionError,
)
from fastapi_better_auth._internal.jwks import CACHE_TTL, MAX_REMEMBERED_MISSES, Jwk
from tests.jwks_fixtures import KEY_SET, ROTATED, SIGNER, client
from tests.tokens import Clock, key_set
from tests.transports import json_reply


@pytest.mark.anyio
async def test_a_second_lookup_is_served_from_the_cache() -> None:
    keys, transport = client(json_reply(KEY_SET))

    assert await keys.key_for(SIGNER.kid) is not None
    assert await keys.key_for(SIGNER.kid) is not None
    assert transport.calls == 1


@pytest.mark.anyio
async def test_the_cache_is_refetched_once_it_has_expired() -> None:
    clock = Clock()
    keys, transport = client(json_reply(KEY_SET), clock=clock)

    await keys.key_for(SIGNER.kid)
    clock.advance(CACHE_TTL + 1)
    await keys.key_for(SIGNER.kid)

    assert transport.calls == 2


@pytest.mark.anyio
async def test_a_rotated_kid_is_picked_up_without_waiting_for_the_ttl() -> None:
    """A rotation is exactly the case a fresh cache would answer wrongly: the key set is
    young and the kid is new. What bounds the refetch is the ten-second window, not the
    five-minute TTL - so a rotated key is live in seconds, at one fetch per window."""
    clock = Clock()
    keys, transport = client(json_reply(KEY_SET), json_reply(key_set(SIGNER, ROTATED)), clock=clock)

    assert await keys.key_for(SIGNER.kid) is not None
    clock.advance(11)

    assert await keys.key_for(ROTATED.kid) is not None
    assert transport.calls == 2


@pytest.mark.anyio
async def test_a_rotation_inside_the_refetch_window_waits_for_it() -> None:
    """The other half of the same rule, stated so nobody has to discover it in production."""
    clock = Clock()
    keys, transport = client(json_reply(KEY_SET), json_reply(key_set(SIGNER, ROTATED)), clock=clock)

    await keys.key_for(SIGNER.kid)

    assert await keys.key_for(ROTATED.kid) is None
    assert transport.calls == 1


@pytest.mark.anyio
async def test_concurrent_misses_coalesce_behind_one_fetch() -> None:
    """Two requests arriving on a cold cache must produce one fetch, not two: upstream has
    a rate limit, and two answers that disagree is a state this library cannot resolve."""
    gate = anyio.Event()
    keys, transport = client(json_reply(KEY_SET), gate=gate)
    found: list[object] = []

    async def look_up() -> None:
        found.append(await keys.key_for(SIGNER.kid))

    async with anyio.create_task_group() as group:
        group.start_soon(look_up)
        group.start_soon(look_up)
        with anyio.fail_after(2):
            while keys.waiting < 1 or transport.calls < 1:
                await anyio.lowlevel.checkpoint()
        gate.set()

    assert transport.calls == 1
    assert len(found) == 2
    assert all(entry is not None for entry in found)


@pytest.mark.anyio
async def test_a_cancelled_cold_fetch_does_not_burn_the_refetch_window() -> None:
    """E1 (D-196), the inverse of the reverted R12 rule. A fetch cancelled mid-flight on a cold
    cache produced no answer, so it must not spend the window: `_attempted_at` is rolled back to
    what it was and the next lookup is free to dial again. RED before the rollback: `_may_fetch()`
    stayed False and the next lookup raised AuthServiceUnavailable with no second call.

    This does NOT reopen the D-084 flood the R12 revert guarded: a fetch that *finished* badly
    keeps its stamp (see `test_a_fetch_that_finished_badly_is_still_an_attempt`). Only a genuinely
    abandoned attempt, which rate-limited nothing, is rolled back - the cancellation exception,
    never a completed refusal.

    Cut on a *signal*, not a stopwatch: the scope is cancelled only once the transport has
    recorded the call, so the stamp under test is provably the one the fetch set.
    """
    clock = Clock()
    gate = anyio.Event()
    keys, transport = client(json_reply(KEY_SET), clock=clock, gate=gate)
    scopes: list[anyio.CancelScope] = []

    async def look_up() -> None:
        with anyio.CancelScope() as scope:
            scopes.append(scope)
            await keys.key_for(SIGNER.kid)

    async with anyio.create_task_group() as group:
        group.start_soon(look_up)
        with anyio.fail_after(2):
            while transport.calls < 1 or not scopes:
                await anyio.lowlevel.checkpoint()
        scopes[0].cancel()

    assert transport.calls == 1, "the fetch never started; this probe proves nothing"
    assert keys._may_fetch() is True  # pyright: ignore[reportPrivateUsage]

    gate.set()
    assert await keys.key_for(SIGNER.kid) is not None
    assert transport.calls == 2


@pytest.mark.anyio
async def test_a_cancelled_cold_fetch_frees_a_queued_bystander() -> None:
    """E1 (D-196), the headline. On a cold cache a leader holding the single-flight lock and
    cancelled mid-fetch used to poison a bystander queued behind it: the leader had stamped
    `_attempted_at` before the await, so when the bystander acquired the lock it saw `_may_fetch()`
    False, fell through to `_answer` with no key set on hand, and got a spurious
    AuthServiceUnavailable - a 401 for a legitimate request that could have fetched. The cancelled
    attempt produced no answer, so rolling the stamp back lets the bystander try. RED before the
    rollback: the bystander raised AuthServiceUnavailable and never dialled.
    """
    clock = Clock()
    gate = anyio.Event()
    keys, transport = client(json_reply(KEY_SET), clock=clock, gate=gate)
    scopes: list[anyio.CancelScope] = []
    outcome: list[object] = []

    async def leader() -> None:
        with anyio.CancelScope() as scope:
            scopes.append(scope)
            await keys.key_for(SIGNER.kid)

    async def bystander() -> None:
        try:
            outcome.append(await keys.key_for(SIGNER.kid))
        except BaseException as exc:  # noqa: BLE001 - the outcome itself is under test
            outcome.append(exc)

    async with anyio.create_task_group() as group:
        group.start_soon(leader)
        with anyio.fail_after(2):
            while transport.calls < 1 or not scopes:
                await anyio.lowlevel.checkpoint()
        group.start_soon(bystander)
        with anyio.fail_after(2):
            while keys.waiting < 1:
                await anyio.lowlevel.checkpoint()
        scopes[0].cancel()
        with anyio.fail_after(2):
            while not scopes[0].cancelled_caught:
                await anyio.lowlevel.checkpoint()
        gate.set()

    assert len(outcome) == 1
    found = outcome[0]
    assert not isinstance(found, BaseException), f"the bystander was poisoned: {found!r}"
    assert isinstance(found, Jwk) and found.kid == SIGNER.kid
    assert transport.calls == 2


@pytest.mark.anyio
async def test_a_cancelled_rotation_refetch_does_not_negative_cache_the_new_kid() -> None:
    """E1 (D-196), the rotation half. A fresh key set is on hand and the refetch window is open,
    so a lookup for a just-rotated kid opens a refetch to pick it up (D-095). The old code stamped
    `_attempted_at` before the await, so when that refetch was cancelled the window stayed shut -
    and the next lookup fell through to `_answer`, saw the fresh-but-pre-rotation set, and
    NEGATIVE-CACHED the rotated kid: a valid token signed by the new key refused for the whole
    negative TTL. Rolling the stamp back on cancellation keeps the window open, so the next lookup
    fetches the rotation instead of caching the kid as absent.
    """
    clock = Clock()
    keys, transport = client(
        json_reply(KEY_SET),  # t0: pre-rotation, only SIGNER
        json_reply(key_set(SIGNER, ROTATED)),  # the rotation, once it is fetched
        clock=clock,
    )

    assert await keys.key_for(SIGNER.kid) is not None  # warm the cache
    assert transport.calls == 1
    clock.advance(11)  # past the 10s window; the set is still fresh (cache_ttl 300)

    gate = anyio.Event()
    transport.gate = gate  # hold the rotation refetch open so it can be cancelled mid-flight
    scopes: list[anyio.CancelScope] = []

    async def look_up() -> None:
        with anyio.CancelScope() as scope:
            scopes.append(scope)
            await keys.key_for(ROTATED.kid)

    async with anyio.create_task_group() as group:
        group.start_soon(look_up)
        with anyio.fail_after(2):
            while transport.calls < 2 or not scopes:
                await anyio.lowlevel.checkpoint()
        scopes[0].cancel()

    assert transport.calls == 2, "the refetch never started; this probe proves nothing"

    gate.set()  # the next lookup's fetch may complete
    found = await keys.key_for(ROTATED.kid)
    assert found is not None, "the cancelled refetch negative-cached the rotated kid"
    assert found.kid == ROTATED.kid
    assert keys.remembered == 0
    assert transport.calls == 3


@pytest.mark.anyio
@pytest.mark.parametrize(
    "failure",
    [TimeoutError("upstream down"), ConfigurationError("the injected client was never opened")],
    ids=["unavailable", "misconfigured"],
)
async def test_a_fetch_that_finished_badly_is_still_an_attempt(failure: BaseException) -> None:
    """The other side of the same rule, and the reason it is not simply "stamp on success":
    a failing upstream must not become one fetch per request. Both of these *finished*."""
    clock = Clock()
    keys, transport = client(failure, clock=clock)

    with pytest.raises((SessionError, BetterAuthError)):
        await keys.key_for(SIGNER.kid)
    assert keys._may_fetch() is False  # pyright: ignore[reportPrivateUsage]

    with pytest.raises((SessionError, BetterAuthError)):
        await keys.key_for(SIGNER.kid)
    assert transport.calls == 1


# --- the unknown kid ------------------------------------------------------------------


@pytest.mark.anyio
async def test_an_unknown_kid_is_not_refetched_for_inside_the_window() -> None:
    """Within the refetch window, a kid nobody has published is refused without a second
    upstream call - otherwise it would cost one fetch per request."""
    clock = Clock()
    keys, transport = client(json_reply(KEY_SET), clock=clock)

    assert await keys.key_for("never-published") is None
    assert await keys.key_for("never-published") is None
    assert transport.calls == 1


@pytest.mark.anyio
async def test_a_kid_cached_as_absent_is_rechecked_at_the_window_not_the_negative_ttl() -> None:
    """B2: a kid a fetch did not contain is cached as absent - but a rotation routinely lands
    the first token bearing a new kid before this process has fetched the rotation. The
    re-check has to open with the 10s refetch window, not stay shut for the 60s negative TTL,
    or every real rotation refuses valid tokens six times longer than advertised.

    RED before the reorder: at t=11 the negative cache short-circuits and returns None for a
    kid that is now published, for the full 60s.
    """
    clock = Clock()
    keys, transport = client(
        json_reply(KEY_SET),  # t=0: the rotated kid is not published yet
        json_reply(key_set(SIGNER, ROTATED)),  # by t=11 it is
        clock=clock,
        negative_ttl=60.0,
    )

    assert await keys.key_for(ROTATED.kid) is None  # cached as absent
    clock.advance(11)  # past the 10s window, far under the 60s TTL

    assert await keys.key_for(ROTATED.kid) is not None
    assert transport.calls == 2


@pytest.mark.anyio
async def test_the_flood_defense_survives_the_window_winning_over_the_negative_cache() -> None:
    """The other side of B2's reorder: letting the window override the negative cache must
    not reopen the flood. Distinct unknown kids inside one window still cost a single fetch."""
    clock = Clock()
    keys, transport = client(json_reply(KEY_SET), clock=clock, negative_ttl=60.0)

    assert await keys.key_for(ROTATED.kid) is None
    for index in range(50):
        assert await keys.key_for(f"flood-{index}") is None
    assert await keys.key_for(ROTATED.kid) is None

    assert transport.calls == 1


@pytest.mark.anyio
async def test_a_confirmed_absent_verdict_does_not_outlive_its_ttl_into_a_stale_key_set() -> None:
    """A kid confirmed absent by a fresh fetch may answer None while that verdict is young.
    Once it is older than negative_ttl AND the key set has gone stale, the verdict expires and
    the honest answer becomes AuthServiceUnavailable (D-083): the kid can no longer be told
    apart from one freshly rotated in. A long refetch window keeps a fetch from papering over
    the transition, so the expiry is what is under test."""
    clock = Clock()
    keys, _transport = client(
        json_reply(KEY_SET),
        clock=clock,
        cache_ttl=60.0,
        negative_ttl=30.0,
        refetch_interval=1000.0,
    )

    assert await keys.key_for("gone") is None  # confirmed absent, verdict fresh, keys fresh
    clock.advance(20)
    assert await keys.key_for("gone") is None  # still inside negative_ttl and cache_ttl
    clock.advance(50)  # now past BOTH negative_ttl and cache_ttl, window still shut

    with pytest.raises(AuthServiceUnavailable):
        await keys.key_for("gone")
    assert keys.remembered == 0  # the expired verdict was dropped, not re-served as None


@pytest.mark.anyio
async def test_a_flood_of_unknown_kids_costs_one_fetch_per_window() -> None:
    """The negative cache alone does not bound this - each kid is new, so each one misses
    it. The refetch window is what turns a kid generator into one fetch every ten seconds."""
    clock = Clock()
    keys, transport = client(
        json_reply(KEY_SET), clock=clock, negative_ttl=0.0, refetch_interval=10.0
    )

    for index in range(50):
        assert await keys.key_for(f"flood-{index}") is None
    assert transport.calls == 1

    clock.advance(11)
    assert await keys.key_for("flood-later") is None
    assert transport.calls == 2


@pytest.mark.anyio
async def test_what_the_client_remembers_about_unknown_kids_is_bounded() -> None:
    """Remembering is what stops the flood; remembering without a bound *is* the flood.

    Asserted as an equality rather than a ceiling: a client that remembered nothing would
    also satisfy `<=`, and would be one fetch per unknown kid the moment the window opened.
    """
    clock = Clock()
    keys, transport = client(json_reply(KEY_SET), clock=clock)

    for index in range(MAX_REMEMBERED_MISSES * 3):
        assert await keys.key_for(f"flood-{index}") is None

    assert keys.remembered == MAX_REMEMBERED_MISSES
    assert transport.calls == 1


# --- staleness ------------------------------------------------------------------------


@pytest.mark.anyio
async def test_a_stale_key_set_still_verifies_the_kids_it_carries() -> None:
    """Upstream being unreachable must not log out every user holding a valid token."""
    clock = Clock()
    keys, transport = client(json_reply(KEY_SET), TimeoutError("upstream down"), clock=clock)

    assert await keys.key_for(SIGNER.kid) is not None
    clock.advance(CACHE_TTL + 1)

    assert await keys.key_for(SIGNER.kid) is not None
    assert transport.calls == 2


@pytest.mark.anyio
async def test_a_stale_key_set_never_turns_an_unknown_kid_into_an_accepted_one() -> None:
    """Availability buys the keys we already fetched, and nothing else. A kid we cannot
    confirm is unavailable - not unknown - because a rotation we missed looks the same."""
    clock = Clock()
    keys, _transport = client(json_reply(KEY_SET), TimeoutError("upstream down"), clock=clock)

    await keys.key_for(SIGNER.kid)
    clock.advance(CACHE_TTL + 1)

    with pytest.raises(AuthServiceUnavailable):
        await keys.key_for(ROTATED.kid)


@pytest.mark.anyio
async def test_a_cold_cache_that_cannot_be_filled_is_unavailable() -> None:
    keys, _transport = client(TimeoutError("upstream down"))

    with pytest.raises(AuthServiceUnavailable):
        await keys.key_for(SIGNER.kid)
