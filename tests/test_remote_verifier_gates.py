"""The WP15 gates before the fetch, each making zero outbound calls: cache, latch, limiter.

`verifier()` marks the readiness probe passed, so `transport.calls` counts fetches only and the
probe's own calls are out of the way. The negative cache: a remembered forgery costs nothing more,
twelve identical ones cost one call, `negative_ttl=0` disables it, `max_remembered` bounds it and
the injected clock expires it. The 429 latch: the next request refuses without a fetch until the
clock clears it. The limiter (ruling 7): saturation and a transport timeout carry distinct reasons,
the slot is released, and the `CapacityLimiter` is built inside the loop rather than at
construction (D-198). And the invariant on a cold verifier: a CSRF failure runs neither the probe,
the keyring nor the cache. The frame hygiene of these same refusals is
`test_remote_verifier_hygiene.py`; the builders are `tests/remote_fixtures.py`.
"""

from __future__ import annotations

import contextlib
from typing import Any

import anyio
import pytest
from starlette.requests import HTTPConnection

from fastapi_better_auth import AuthServiceUnavailable, CsrfFailure, InvalidCredential, OriginCheck
from fastapi_better_auth._internal import remote_verifier as rv
from fastapi_better_auth._internal.remote_verifier import RemoteVerifier
from tests.remote_fixtures import (
    APP,
    COOKIE_NAME,
    COOKIE_VALUE,
    EVIL,
    ORIGIN,
    SECRET,
    RecordingTransport,
    document,
    request,
    run,
    verifier,
    with_cookie,
)
from tests.transports import Reply, ScriptedTransport, json_reply

# ---------------------------------------------------------------- WP15 zero-outbound gate spies


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def garbage() -> HTTPConnection:
    """A cookie that passes rung 1 (has a separator) but upstream will call `200 null`."""
    return with_cookie("garbage-token.garbage-signature-value")


class TestZeroOutboundGates:
    """The gates before the fetch make ZERO outbound calls, RED-first. `verifier()` marks the probe
    passed, so `transport.calls` counts fetches only - the probe's own calls are out of the way."""

    @pytest.mark.anyio
    async def test_a_negative_cache_hit_makes_zero_additional_outbound(self) -> None:
        transport = RecordingTransport(Reply(b"null"))
        v = verifier(transport)

        with pytest.raises(InvalidCredential):
            await run(v, garbage())
        assert transport.calls == 1, "the first forged cookie cost one upstream call"

        with pytest.raises(InvalidCredential):
            await run(v, garbage())
        assert transport.calls == 1, "the cache hit made zero additional outbound calls"
        assert v.remembered == 1

    @pytest.mark.anyio
    async def test_n_identical_garbage_cookies_make_exactly_one_outbound(self) -> None:
        transport = RecordingTransport(Reply(b"null"))
        v = verifier(transport)

        for _ in range(12):
            with pytest.raises(InvalidCredential):
                await run(v, garbage())

        assert transport.calls == 1, "twelve identical forged cookies cost one upstream call"

    @pytest.mark.anyio
    async def test_a_disabled_cache_costs_one_call_per_forged_cookie(self) -> None:
        transport = RecordingTransport(Reply(b"null"))
        v = verifier(transport, negative_ttl=0.0)

        for _ in range(3):
            with pytest.raises(InvalidCredential):
                await run(v, garbage())

        assert transport.calls == 3, "negative_ttl=0 disables the cache; each forgery costs a call"
        assert v.remembered == 0

    @pytest.mark.anyio
    async def test_max_remembered_bounds_the_cache_through_the_constructor(self) -> None:
        # The `max_remembered` knob reaches the cache: distinct forgeries past the bound evict the
        # oldest, so `remembered` never exceeds it (a mutation dropping the knob leaves this RED).
        transport = RecordingTransport(Reply(b"null"))
        v = verifier(transport, max_remembered=2)

        for i in range(5):
            with pytest.raises(InvalidCredential):
                await run(v, with_cookie(f"forged-{i}.signature-{i}"))

        assert v.remembered == 2, "max_remembered=2 caps the cache at two remembered verdicts"

    @pytest.mark.anyio
    async def test_the_injected_clock_expires_a_cached_verdict(self) -> None:
        # The verifier's own `clock` drives the cache TTL, not just the backoff latch: past the TTL
        # the same forged cookie costs a second call (a mutation dropping the clock leaves this RED).
        clock = Clock()
        transport = RecordingTransport(Reply(b"null"))
        v = verifier(transport, negative_ttl=30.0, clock=clock)

        with pytest.raises(InvalidCredential):
            await run(v, garbage())
        with pytest.raises(InvalidCredential):
            await run(v, garbage())
        assert transport.calls == 1, "within the TTL the cache serves the verdict, zero outbound"

        clock.advance(31.0)
        with pytest.raises(InvalidCredential):
            await run(v, garbage())
        assert transport.calls == 2, "past the TTL the cached verdict expired and cost a fresh call"

    @pytest.mark.anyio
    async def test_a_latched_instance_makes_zero_outbound(self) -> None:
        clock = Clock()
        transport = RecordingTransport(Reply(b"", status=429))
        v = verifier(transport, clock=clock)

        with pytest.raises(AuthServiceUnavailable) as first:
            await run(v, with_cookie())
        assert "429" in first.value.reason
        assert transport.calls == 1

        with pytest.raises(AuthServiceUnavailable) as second:
            await run(v, with_cookie())
        assert transport.calls == 1, "a latched instance made zero outbound calls"
        assert "backing off" in second.value.reason

        clock.advance(30.0)
        with pytest.raises(AuthServiceUnavailable):
            await run(v, with_cookie())
        assert transport.calls == 2, "the latch cleared by time and the next request went out"

    @pytest.mark.anyio
    async def test_a_cold_csrf_failure_reaches_neither_probe_keyring_nor_cache(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The zero-outbound invariant on a COLD verifier: CSRF is before `_ready`, so the probe
        never runs; the keyring is never consulted and the cache is untouched."""
        compares: list[int] = []
        real = rv.verify_signature

        def spy(*args: Any, **kwargs: Any) -> None:
            compares.append(1)
            real(*args, **kwargs)

        monkeypatch.setattr(rv, "verify_signature", spy)
        transport = RecordingTransport(json_reply(document()))
        built = RemoteVerifier(
            base_url=ORIGIN,
            csrf=OriginCheck(allowed_origins=[APP]),
            transport=transport,
            secret=SECRET,
            secure_cookies=False,
        )
        assert built._probed_ok is False, "this verifier is cold - the probe has not run"  # pyright: ignore[reportPrivateUsage]
        connection = request(
            "POST",
            cookies=(f"{COOKIE_NAME}={COOKIE_VALUE}",),
            origin=EVIL,
            sec_fetch_site="cross-site",
        )

        with pytest.raises(CsrfFailure):
            await run(built, connection)

        assert transport.calls == 0, "a cold CSRF failure ran the probe or a fetch"
        assert compares == [], "a CSRF failure reached the keyring"
        assert built.remembered == 0, "a CSRF failure touched the cache"


class TestLimiter:
    """The outbound concurrency limiter, and its saturation reason (ruling 7)."""

    @pytest.mark.anyio
    async def test_saturation_and_transport_timeout_reasons_are_distinct(self) -> None:
        gate = anyio.Event()
        held = RecordingTransport(Reply(b"null"), gate=gate)
        saturating = verifier(held, concurrency=1, queue_timeout=0.1)
        saturation: list[AuthServiceUnavailable] = []

        async def hold_the_only_slot() -> None:
            with contextlib.suppress(InvalidCredential):
                await run(saturating, with_cookie())

        async with anyio.create_task_group() as tg:
            tg.start_soon(hold_the_only_slot)
            await anyio.sleep(0.02)
            with pytest.raises(AuthServiceUnavailable) as caught:
                await run(saturating, garbage())
            saturation.append(caught.value)
            gate.set()

        timed_out = verifier(RecordingTransport(TimeoutError("slow")))
        with pytest.raises(AuthServiceUnavailable) as caught:
            await run(timed_out, with_cookie())

        assert "saturated" in saturation[0].reason
        assert "timed out" in caught.value.reason
        assert saturation[0].reason != caught.value.reason

    @pytest.mark.anyio
    async def test_the_slot_is_released_so_later_requests_still_go_out(self) -> None:
        transport = RecordingTransport(json_reply(document()))
        v = verifier(transport, concurrency=1)

        assert (await run(v, with_cookie())) is not None
        assert (await run(v, with_cookie())) is not None
        assert transport.calls == 2, "the slot was released after the first exchange"

    def test_the_limiter_is_not_built_at_construction(self) -> None:
        """D-198: `anyio.CapacityLimiter(n)` must be built lazily inside the loop, not in
        `__init__`; only the count is stored at construction."""
        v = verifier(ScriptedTransport(Reply(b"null")))

        assert v._limiter_instance is None  # pyright: ignore[reportPrivateUsage]

    @pytest.mark.anyio
    async def test_the_limiter_is_built_on_first_fetch(self) -> None:
        transport = RecordingTransport(json_reply(document()))
        v = verifier(transport)
        assert v._limiter_instance is None  # pyright: ignore[reportPrivateUsage]

        await run(v, with_cookie())

        assert v._limiter_instance is not None  # pyright: ignore[reportPrivateUsage]
