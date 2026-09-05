"""The negative cache (ruling 6): one remembered outcome, keyed by the whole cookie value.

The cache is a pure, synchronous, bounded, expiring set. This suite pins the four invariants that
make a remembered `200 + null` verdict safe to trust - a hit only for a remembered value, a bound
that is never exceeded, a TTL boundary that expires lazily, and `0.0` disabling it - as hypothesis
properties, and pins the two structural decisions the design turns on: every method is a plain
function (no `anyio.Lock`), and the key is the whole value, not the token.
"""

from __future__ import annotations

import inspect

import pytest

from fastapi_better_auth._internal.negative_cache import (
    MAX_NEGATIVE_TTL,
    MAX_REMEMBERED,
    MAX_REMEMBERED_MISSES,
    MIN_NEGATIVE_TTL,
    NEGATIVE_TTL,
    NegativeCache,
)

pytest.importorskip("hypothesis")
from hypothesis import given, settings
from hypothesis import strategies as st


class Clock:
    """A monotonic clock the tests advance by hand, so TTL boundaries need no sleep."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def cache(
    *, ttl: float = NEGATIVE_TTL, max_remembered: int = 8, clock: Clock | None = None
) -> NegativeCache:
    return NegativeCache(ttl=ttl, max_remembered=max_remembered, clock=clock or Clock())


# ---------------------------------------------------------------- the four invariants


def test_a_remembered_value_is_held() -> None:
    c = cache()
    c.remember("token.sig")

    assert c.holds("token.sig")


def test_an_unremembered_value_is_not_held() -> None:
    c = cache()
    c.remember("token.sig")

    assert not c.holds("other.sig")


def test_the_verdict_expires_at_the_ttl_boundary() -> None:
    clock = Clock()
    c = cache(ttl=30.0, clock=clock)
    c.remember("token.sig")

    clock.advance(29.999)
    assert c.holds("token.sig")
    clock.advance(0.001)
    assert not c.holds("token.sig"), "at exactly the TTL the verdict is stale"


def test_a_zero_ttl_disables_the_cache() -> None:
    c = cache(ttl=MIN_NEGATIVE_TTL)
    c.remember("token.sig")

    assert not c.holds("token.sig")
    assert c.remembered == 0, "a disabled cache remembers nothing"


def test_expiry_evicts_lazily_on_read() -> None:
    clock = Clock()
    c = cache(ttl=10.0, clock=clock)
    c.remember("token.sig")
    clock.advance(11.0)

    assert not c.holds("token.sig")
    assert c.remembered == 0, "a read past the TTL drops the entry"


# ---------------------------------------------------------------- the bound


def test_the_bound_is_never_exceeded_and_evicts_oldest_first() -> None:
    c = cache(max_remembered=3)
    for index in range(5):
        c.remember(f"cookie-{index}.sig")

    assert c.remembered == 3
    assert not c.holds("cookie-0.sig"), "the oldest was evicted"
    assert not c.holds("cookie-1.sig")
    assert c.holds("cookie-2.sig")
    assert c.holds("cookie-4.sig")


def test_re_remembering_a_held_value_does_not_grow_the_cache() -> None:
    c = cache(max_remembered=3)
    for _ in range(10):
        c.remember("same.sig")

    assert c.remembered == 1


# ---------------------------------------------------------------- the key is the whole value


def test_two_cookies_sharing_a_token_do_not_share_a_verdict() -> None:
    """The airtight-availability property: keying on the full value, a correctly-signed
    presentation of a token a tampered cookie was refused under is a different key and a miss."""
    c = cache()
    c.remember("live-token.forged-signature")

    assert not c.holds("live-token.correct-signature")


# ---------------------------------------------------------------- structural pins


def test_every_method_is_a_plain_function_no_lock() -> None:
    """Ruling 6: no `anyio.Lock`. Every method is synchronous and holds no await, so a future
    refactor that adds one must consciously revisit this - a lock with no await is decoration."""
    for name in ("holds", "remember"):
        method = getattr(NegativeCache, name)
        assert not inspect.iscoroutinefunction(method), f"{name} is async"
    source = inspect.getsource(NegativeCache)
    assert "await" not in source, "a method acquired something; the no-lock invariant is broken"
    assert "anyio" not in source


def test_the_pinned_defaults() -> None:
    assert NEGATIVE_TTL == 30.0
    assert MIN_NEGATIVE_TTL == 0.0
    assert MAX_NEGATIVE_TTL == 300.0
    assert MAX_REMEMBERED_MISSES == 1024
    assert MAX_REMEMBERED == 65536


# ---------------------------------------------------------------- hypothesis properties


@settings(max_examples=200, derandomize=True)
@given(
    values=st.lists(st.text(min_size=1, max_size=40), min_size=1, max_size=30),
    bound=st.integers(1, 8),
)
def test_the_bound_holds_over_any_sequence(values: list[str], bound: int) -> None:
    c = cache(max_remembered=bound)
    for value in values:
        c.remember(value)
        assert c.remembered <= bound, "the bound was exceeded"


@settings(max_examples=200, derandomize=True)
@given(value=st.text(min_size=1, max_size=60))
def test_a_freshly_remembered_value_is_always_held(value: str) -> None:
    c = cache(max_remembered=MAX_REMEMBERED, clock=Clock())
    c.remember(value)

    assert c.holds(value)


@settings(max_examples=200, derandomize=True)
@given(
    remembered=st.text(min_size=1, max_size=40),
    other=st.text(min_size=1, max_size=40),
)
def test_only_the_remembered_value_is_held(remembered: str, other: str) -> None:
    c = cache(max_remembered=MAX_REMEMBERED)
    c.remember(remembered)

    assert c.holds(other) == (other == remembered)


@settings(max_examples=200, derandomize=True)
@given(value=st.text(min_size=1, max_size=40), ttl=st.floats(min_value=1.0, max_value=300.0))
def test_a_value_is_never_held_past_its_ttl(value: str, ttl: float) -> None:
    clock = Clock()
    clock.now = 0.0  # avoid float cancellation at the exact boundary from a large clock offset
    c = cache(ttl=ttl, clock=clock)
    c.remember(value)
    clock.advance(ttl)

    assert not c.holds(value)
