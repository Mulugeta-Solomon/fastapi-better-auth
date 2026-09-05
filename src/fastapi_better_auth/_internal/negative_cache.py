"""One remembered outcome, and nothing else: upstream answered a dead cookie with 200 + null.

A `RemoteVerifier` with no local secret pays one upstream call to learn that a forged cookie names
no session. `NegativeCache` is what keeps a flood of the same forged cookie from paying that call
every time: the "200 + null" verdict is remembered for a short window, keyed by the whole cookie
value, and a hit refuses locally with zero outbound.

Three properties make the remembered verdict safe to trust:

- **The key is the full cookie value, not the token, and not the 8-hex fingerprint.** A better-auth
  session token is minted once from a CSPRNG and never revived, so a cookie upstream called dead can
  never later name a live session - except the one corner where a tampered cookie's token half
  equals a live token, and there the *full value* differs, so a correctly-signed presentation of
  that token is a different key and a miss. Keying on the token would poison that presentation;
  keying on the 8-hex fingerprint would drive a denial off a 32-bit key (a false 401 for a real
  user on a birthday collision). The key is a 32-byte sha256 of the value, internal and never
  rendered.
- **Exactly one outcome is cached.** Never `AuthServiceUnavailable` (caching a blip would amplify
  an outage into `ttl` seconds of refusals), never a structural refusal (free to redo), never
  expired/banned/mismatch (those are real sessions whose state can change).
- **The window is how long a flood is absorbed, not a correctness bound.** Nothing can revive the
  key, so a longer TTL only holds the flood longer; `0.0` disables the cache entirely - a
  representable "no cache" that costs one call per forged cookie and is never a bypass.

Every method is synchronous and holds no `await`, so under a single-threaded event loop there is no
preemption point to protect and no `anyio.Lock` (a lock with no await inside it is decoration).
Request coalescing is deliberately not done: the `CapacityLimiter` bounds concurrency, this bounds
repetition, and a waiter map whose failure mode delivers one caller's exception to another is worse
than one extra upstream call. `JwksClient` is deliberately not refactored onto this: its negative
cache is entangled with a refetch-window rule this has no analogue for.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

NEGATIVE_TTL = 30.0
MIN_NEGATIVE_TTL = 0.0
MAX_NEGATIVE_TTL = 300.0
MAX_REMEMBERED_MISSES = 1024
MIN_REMEMBERED = 1
MAX_REMEMBERED = 65536


class NegativeCache:
    """A bounded, expiring set of cookie values upstream has answered `200 + null` about.

    Args:
        ttl: Seconds a remembered verdict stays live. `0.0` disables the cache: every method then
            no-ops, so a forged cookie always costs its one upstream call and the cache never holds
            anything. Validated by the verifier that builds this.
        max_remembered: The most verdicts held at once. Oldest-first eviction, correct because the
            oldest entry is the one closest to expiring.
        clock: A monotonic clock, injected so TTL boundaries are tested without sleeping.
    """

    __slots__ = ("_clock", "_entries", "_max", "_ttl")

    def __init__(self, *, ttl: float, max_remembered: int, clock: Callable[[], float]) -> None:
        self._ttl = ttl
        self._max = max_remembered
        self._clock = clock
        self._entries: dict[bytes, float] = {}

    @property
    def remembered(self) -> int:
        """How many verdicts are currently held. Bounded by `max_remembered` at all times."""
        return len(self._entries)

    def holds(self, material: str) -> bool:
        """Whether this cookie value has a live `200 + null` verdict, expiring it lazily if not."""
        if self._ttl <= MIN_NEGATIVE_TTL:
            return False
        key = _key(material)
        remembered_at = self._entries.get(key)
        if remembered_at is None:
            return False
        if self._clock() - remembered_at >= self._ttl:
            del self._entries[key]
            return False
        return True

    def remember(self, material: str) -> None:
        """Record that upstream answered `200 + null` for this cookie value.

        Oldest-first eviction keeps the set bounded; a garbage-cookie space is the attacker's
        imagination, so the bound is what makes remembering it safe. A disabled cache (`ttl <= 0`)
        remembers nothing.
        """
        if self._ttl <= MIN_NEGATIVE_TTL:
            return
        key = _key(material)
        while key not in self._entries and len(self._entries) >= self._max:
            self._entries.pop(next(iter(self._entries)))
        self._entries[key] = self._clock()


def _key(material: str) -> bytes:
    """The 32-byte sha256 of the whole cookie value. Internal, never rendered, retains no material."""
    return hashlib.sha256(material.encode("utf-8", "replace")).digest()
