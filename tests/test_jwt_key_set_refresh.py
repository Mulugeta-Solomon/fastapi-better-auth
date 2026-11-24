"""Who waits while a stale key set is refreshed - driven through `JwtVerifier.verify`.

Once the cache TTL has passed, a request whose `kid` is in the held set needs no network answer to
be verified: the set is still honoured (`max_stale`, see `test_jwt_key_set_staleness.py`). So
exactly one such request performs the refresh and every other one is answered from the held set at
once, rather than queueing behind a JWKS endpoint that may hang until the transport times out. A
request whose `kid` is *not* in the held set has nothing to be answered from, and still waits for
the refresh - behind the same refetch window and negative cache that keep a stream of invented
kids from becoming a stream of fetches.

The refresh is held open by the scripted transport's gate; every wait ends on a signal (all other
tasks blocked, or a count reached), never on a stopwatch.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import anyio
import pytest

from fastapi_better_auth import InvalidCredential, Session, User
from fastapi_better_auth._internal.jwks import CACHE_TTL, REFETCH_INTERVAL
from fastapi_better_auth._internal.jwt_verifier import JwtVerifier
from tests.jwks_fixtures import wind_jwks_clock
from tests.jwt_fixtures import KEY_SET, SIGNER, build
from tests.tokens import ORIGIN, claims, ed25519_signer, key_set
from tests.transports import ScriptedTransport, json_reply

ROTATED = ed25519_signer("wp40-rotated")
STALE = CACHE_TTL + 1
"""Past the cache TTL, far inside the one-day bound: the set is stale and still honoured."""
CROWD = 5

Outcome = Session[User] | BaseException


async def _outcome(verify: Callable[[], Awaitable[Session[User]]]) -> Outcome:
    try:
        return await verify()
    except BaseException as exc:  # noqa: BLE001 - the outcome itself is under test
        return exc


async def _settled() -> None:
    """Returns once every other task is blocked: on the gate, on the lock, or finished."""
    with anyio.fail_after(5):
        await anyio.wait_all_tasks_blocked()


def _hold_the_next_fetch(transport: ScriptedTransport) -> anyio.Event:
    gate = anyio.Event()
    transport.gate = gate
    return gate


@pytest.mark.anyio
async def test_one_request_refreshes_a_stale_set_and_the_rest_are_answered_from_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F4.2: a hung refresh must not hold every valid token hostage. RED before the fix: every
    request past the TTL queued on the refresh lock, so none completed until the fetch did."""
    clock = wind_jwks_clock(monkeypatch)
    verifier, transport = build(json_reply(KEY_SET), json_reply(KEY_SET))
    token = SIGNER.sign(claims())
    await verifier.verify(token, User)
    clock.advance(STALE)
    gate = _hold_the_next_fetch(transport)
    outcomes: list[Outcome] = []

    async def request() -> None:
        outcomes.append(await _outcome(lambda: verifier.verify(token, User)))

    async with anyio.create_task_group() as group:
        for _ in range(CROWD):
            group.start_soon(request)
        await _settled()

        assert transport.calls == 2, "exactly one refresh is in flight"
        assert len(outcomes) == CROWD - 1, "the others must not wait on the hung refresh"
        assert all(isinstance(each, Session) for each in outcomes), outcomes
        gate.set()

    assert len(outcomes) == CROWD
    assert all(isinstance(each, Session) for each in outcomes), outcomes
    assert transport.calls == 2


@pytest.mark.anyio
async def test_the_refresher_answers_from_the_set_it_fetched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Being answered from the held set is for the *bystanders*. The request that refreshed is
    answered by what the refresh brought back - so a key withdrawn upstream stops verifying the
    moment a refresh says so, for the refresher and everyone after it."""
    clock = wind_jwks_clock(monkeypatch)
    verifier, transport = build(json_reply(KEY_SET), json_reply(key_set(ROTATED)))
    token = SIGNER.sign(claims())
    await verifier.verify(token, User)
    clock.advance(STALE)

    with pytest.raises(InvalidCredential):
        await verifier.verify(token, User)
    with pytest.raises(InvalidCredential):
        await verifier.verify(token, User)
    assert transport.calls == 2


@pytest.mark.anyio
async def test_a_stale_hit_inside_a_shut_refetch_window_does_not_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refresh that just failed shuts the window; the held set answers with no fetch."""
    clock = wind_jwks_clock(monkeypatch)
    verifier, transport = build(json_reply(KEY_SET), TimeoutError("jwks unreachable"))
    token = SIGNER.sign(claims())
    await verifier.verify(token, User)
    clock.advance(STALE)

    for _ in range(CROWD):
        await verifier.verify(token, User)
    assert transport.calls == 2

    clock.advance(REFETCH_INTERVAL)
    await verifier.verify(token, User)
    assert transport.calls == 3


@pytest.mark.anyio
async def test_an_unknown_kid_still_waits_for_the_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    """A kid the held set does not carry has nothing to be answered from: it waits for the
    refresh, while held kids arriving during that refresh are answered at once. Two unknown-kid
    requests still cost one fetch between them."""
    clock = wind_jwks_clock(monkeypatch)
    verifier, transport = build(json_reply(KEY_SET), json_reply(key_set(SIGNER, ROTATED)))
    known = SIGNER.sign(claims())
    rotated = ROTATED.sign(claims())
    await verifier.verify(known, User)
    clock.advance(STALE)
    gate = _hold_the_next_fetch(transport)
    unknown_outcomes: list[Outcome] = []
    known_outcomes: list[Outcome] = []

    async def unknown() -> None:
        unknown_outcomes.append(await _outcome(lambda: verifier.verify(rotated, User)))

    async def held() -> None:
        known_outcomes.append(await _outcome(lambda: verifier.verify(known, User)))

    async with anyio.create_task_group() as group:
        group.start_soon(unknown)
        group.start_soon(unknown)
        await _settled()
        assert transport.calls == 2, "the first unknown kid opened one refresh"
        for _ in range(CROWD):
            group.start_soon(held)
        await _settled()

        assert unknown_outcomes == [], "an unknown kid must wait for the refresh"
        assert len(known_outcomes) == CROWD
        assert all(isinstance(each, Session) for each in known_outcomes), known_outcomes
        gate.set()

    assert len(unknown_outcomes) == 2
    assert all(isinstance(each, Session) for each in unknown_outcomes), unknown_outcomes
    assert transport.calls == 2


def test_the_single_refresher_holds_for_a_verifier_built_outside_the_loop(
    anyio_backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Production builds `JwtVerifier` at import time, before any event loop exists, so its
    lock is created loop-less; the non-blocking acquire must work on that lock too, on both
    backends."""
    clock = wind_jwks_clock(monkeypatch)
    transport = ScriptedTransport(json_reply(KEY_SET), json_reply(KEY_SET))
    verifier = JwtVerifier(base_url=ORIGIN, transport=transport)
    token = SIGNER.sign(claims())
    outcomes: list[Outcome] = []

    async def scenario() -> None:
        await verifier.verify(token, User)
        clock.advance(STALE)
        gate = _hold_the_next_fetch(transport)

        async def request() -> None:
            outcomes.append(await _outcome(lambda: verifier.verify(token, User)))

        async with anyio.create_task_group() as group:
            for _ in range(CROWD):
                group.start_soon(request)
            await _settled()
            assert len(outcomes) == CROWD - 1
            gate.set()

    anyio.run(scenario, backend=anyio_backend)

    assert len(outcomes) == CROWD
    assert all(isinstance(each, Session) for each in outcomes), outcomes
    assert transport.calls == 2
