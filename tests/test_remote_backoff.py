"""The 429 backoff latch (ruling 7): trips only on a 429, clears by time only, warns once.

The latch is the one piece of circuit-breaker machinery that ships, and only because a 429 is
upstream telling us the wait. This suite pins that a non-429 never trips it, that it reads the
backoff upstream named (standard header first, then the one upstream actually sends), that it clears
by time alone, and that it warns once per latch rather than once per request.
"""

from __future__ import annotations

import logging

import pytest

from fastapi_better_auth import TransportResponse
from fastapi_better_auth._internal.remote_backoff import BackoffLatch


class Clock:
    def __init__(self) -> None:
        self.now = 500.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def reply(status: int, **headers: str) -> TransportResponse:
    return TransportResponse(status_code=status, headers=dict(headers), content=b"")


def test_a_non_429_never_trips_the_latch() -> None:
    latch = BackoffLatch(clock=Clock())
    for status in (200, 401, 403, 500, 503):
        latch.observe(reply(status))
        assert not latch.latched()


def test_a_429_latches_then_clears_by_time() -> None:
    clock = Clock()
    latch = BackoffLatch(clock=clock)

    latch.observe(reply(429, **{"x-retry-after": "10"}))

    assert latch.latched()
    clock.advance(9.999)
    assert latch.latched()
    clock.advance(0.001)
    assert not latch.latched(), "the latch clears the instant its window elapses"


def test_the_latch_reads_the_standard_header_first() -> None:
    clock = Clock()
    latch = BackoffLatch(clock=clock)

    latch.observe(reply(429, **{"retry-after": "5", "x-retry-after": "40"}))

    clock.advance(5.0)
    assert not latch.latched(), "retry-after (5s) won over x-retry-after (40s)"


def test_the_latch_falls_back_to_the_upstream_header() -> None:
    clock = Clock()
    latch = BackoffLatch(clock=clock)

    latch.observe(reply(429, **{"x-retry-after": "7"}))

    clock.advance(6.999)
    assert latch.latched()
    clock.advance(0.001)
    assert not latch.latched()


def test_an_absent_header_uses_the_default_backoff() -> None:
    clock = Clock()
    latch = BackoffLatch(clock=clock)

    latch.observe(reply(429))

    clock.advance(4.999)
    assert latch.latched(), "the default backoff is 5s"
    clock.advance(0.001)
    assert not latch.latched()


def test_a_hostile_backoff_is_clamped() -> None:
    clock = Clock()
    latch = BackoffLatch(clock=clock)

    latch.observe(reply(429, **{"x-retry-after": "99999"}))

    clock.advance(60.0)
    assert not latch.latched(), "clamped to the 60s ceiling, not trusted"


def test_the_latch_warns_once_per_latch_not_once_per_observe(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = Clock()
    latch = BackoffLatch(clock=clock)
    with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
        latch.observe(reply(429, **{"x-retry-after": "10"}))
        # A concurrent fetch that raced past the gate and also 429'd must not re-log or extend.
        latch.observe(reply(429, **{"x-retry-after": "10"}))

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "429" in warnings[0].getMessage()


def test_a_fresh_429_after_the_window_warns_again(caplog: pytest.LogCaptureFixture) -> None:
    clock = Clock()
    latch = BackoffLatch(clock=clock)
    with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
        latch.observe(reply(429, **{"x-retry-after": "5"}))
        clock.advance(5.0)
        assert not latch.latched()
        latch.observe(reply(429, **{"x-retry-after": "5"}))

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 2, "a new latch after the window is a new warning"
