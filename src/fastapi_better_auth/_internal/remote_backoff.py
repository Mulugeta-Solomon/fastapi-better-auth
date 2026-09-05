"""The 429-only backoff latch: when upstream says it is rate-limited, stop asking until it clears.

A general circuit breaker is refused - open/half-open/probe state whose classic failure mode is
"the auth path is down and the library is the reason". A 429 is different from a 5xx: it is upstream
telling us the wait. So the one piece of that machinery that ships is a latch that trips only on a
429, reads the wait upstream named, and refuses every request with zero outbound until the wait
elapses - because continuing to hammer a bucket you were told you exhausted is what turns a brief
overload into a sustained outage.

The latch clears by time only: no half-open probe, no consecutive-failure counter, no 5xx
participation. It is per-verifier-instance and per-process - N replicas latch independently - and
the client never learns any of it: latched or not, the answer is the same 401. One
`logger.warning` fires per latch, never per request, so an outage does not become a log flood.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from .remote_response import RATE_LIMITED, retry_after_seconds
from .transport import TransportResponse

logger = logging.getLogger("fastapi_better_auth")


class BackoffLatch:
    """A time-only latch tripped by a 429, cleared when the backoff it read has elapsed.

    Args:
        clock: A monotonic clock, injected so the latch window is tested without sleeping.
    """

    __slots__ = ("_blocked_until", "_clock")

    def __init__(self, *, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._blocked_until: float | None = None

    def latched(self) -> bool:
        """Whether a backoff is currently in force, clearing it the moment its window elapses."""
        blocked_until = self._blocked_until
        if blocked_until is None:
            return False
        if self._clock() >= blocked_until:
            self._blocked_until = None
            return False
        return True

    def observe(self, response: TransportResponse) -> None:
        """Trip the latch when this response is a 429, reading the backoff and warning once.

        A non-429 is ignored. A 429 that arrives while already latched is ignored too, so a burst
        of concurrent fetches that each raced past the gate and each got a 429 still logs once and
        does not extend an existing window; only a 429 seen while unlatched sets a fresh one.
        """
        if response.status_code != RATE_LIMITED:
            return
        if self.latched():
            return
        backoff = retry_after_seconds(response.headers)
        self._blocked_until = self._clock() + backoff
        logger.warning(
            "get-session is rate-limited upstream (429); backing off %ss before the next call",
            backoff,
        )
