"""Freezing the wall clock the expiry and ban rungs read, for the tests that need an exact instant.

Only a frozen clock tells `<=` from `<`: a session expiring at EXACTLY the check instant is the one
case a running clock never produces. Where the two rungs read the clock is this module's business
alone, so a suite freezes it through `freeze_wall_clock` and never names the patch point itself.

`wire` renders an instant the way `JSON.stringify(new Date())` does - UTC, three fractional digits,
a trailing `Z` - which is the only shape a get-session body or a Redis value ever carries.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from fastapi_better_auth._internal import cookie_verifier, remote_verifier

INSTANT = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
"""A frozen check instant, millisecond-aligned so `wire` renders it exactly."""


class FrozenWallClock:
    """Stands in for the `datetime` a rung reads `now(tz)` from."""

    def __init__(self, instant: datetime) -> None:
        self._instant = instant

    def now(self, tz: Any = None) -> datetime:
        return self._instant


def freeze_wall_clock(monkeypatch: pytest.MonkeyPatch, instant: datetime = INSTANT) -> None:
    """Every expiry and ban rung reads `instant` as the real time, until the test ends."""
    for module in (cookie_verifier, remote_verifier):
        monkeypatch.setattr(module, "datetime", FrozenWallClock(instant))


def wire(moment: datetime) -> str:
    """`moment` as upstream serialises a `Date`: `2026-06-01T12:00:00.000Z`."""
    utc = moment.astimezone(timezone.utc)
    return utc.isoformat(timespec="milliseconds").replace("+00:00", "Z")
