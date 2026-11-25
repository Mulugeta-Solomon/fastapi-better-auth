"""How long a cookie-mode request may wait on its session store, and what an overrun is called.

Every authenticated cookie request awaits the store. A store that never answers - a dropped
connection with no reset, a lock, a pool with no checkout timeout, a caller-written store that
hangs - would hold the request open until the client or the server gave up. `CookieVerifier`
bounds the whole lookup phase of a request by one budget: it reads the deadline once, before the
first store call, and every store call that request makes runs in a cancel scope with that same
absolute deadline, so two slow calls cannot take twice the limit.

Only the timing lives here; the scopes, the reporting and the refusal stay in `cookie_verifier`,
beside the store-error path they mirror.
"""

from __future__ import annotations

import math

import anyio

from .errors import ConfigurationError

DEFAULT_LOOKUP_TIMEOUT = 5.0
"""Seconds one request's store lookups may take, together, before the request is refused."""


class LookupDeadlineExceeded(Exception):
    """What an overrun is reported as: the stand-in `report_once` is handed for a store that did
    not answer, so a hung store shares the store-error latch - one line per outage, re-armed by
    the next lookup that completes - under a kind of its own. It carries nothing: no message, no
    token, no store frame, because it is never raised.
    """


def validated_lookup_timeout(lookup_timeout: object) -> float | None:
    """`lookup_timeout` is annotated `float | None`; the value comes from an operator's config."""
    if lookup_timeout is None:
        return None
    if isinstance(lookup_timeout, bool) or not isinstance(lookup_timeout, (int, float)):
        raise ConfigurationError(
            "CookieVerifier(lookup_timeout=...) must be a number of seconds, or None to leave the"
            f" deadline to a caller that enforces its own; got {type(lookup_timeout).__name__}."
            " Pass something like lookup_timeout=5.0."
        )
    if not math.isfinite(lookup_timeout) or lookup_timeout <= 0:
        raise ConfigurationError(
            "CookieVerifier(lookup_timeout=...) must be a positive, finite number of seconds, or"
            f" None; got {lookup_timeout!r}. Zero or less would refuse every request, and an"
            " infinite one is spelled lookup_timeout=None."
        )
    return float(lookup_timeout)


def lookup_deadline(lookup_timeout: float | None) -> float:
    """The absolute anyio clock time this request's store lookups must finish by.

    Infinite when the deadline is disabled: a cancel scope with no deadline still costs nothing
    to enter, so the pipeline takes one shape whether or not the operator set one.
    """
    if lookup_timeout is None:
        return math.inf
    return anyio.current_time() + lookup_timeout
