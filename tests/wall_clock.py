"""Freezing the wall clock the expiry and ban rungs read, for the tests that need an exact instant.

Only a frozen clock tells `<=` from `<`: a session expiring at EXACTLY the check instant is the one
case a running clock never produces. Where the two rungs read the clock is this module's business
alone, so a suite freezes it through `freeze_wall_clock` and never names the patch point itself.

`wire` renders an instant the way `JSON.stringify(new Date())` does - UTC, three fractional digits,
a trailing `Z` - which is the only shape a get-session body or a Redis value ever carries.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from fastapi_better_auth._internal import refusal_clock

INSTANT = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
"""A frozen check instant, millisecond-aligned so `wire` renders it exactly."""


def freeze_wall_clock(
    monkeypatch: pytest.MonkeyPatch, instant: datetime = INSTANT
) -> list[datetime]:
    """Every expiry and ban rung reads `instant` as the real time, until the test ends.

    Returns the list of instants handed out, one per read, so a test can count the reads.
    """
    reads: list[datetime] = []

    def frozen() -> datetime:
        reads.append(instant)
        return instant

    monkeypatch.setattr(refusal_clock, "wall_clock", frozen)
    return reads


def wire(moment: datetime) -> str:
    """`moment` as upstream serialises a `Date`: `2026-06-01T12:00:00.000Z`."""
    utc = moment.astimezone(timezone.utc)
    return utc.isoformat(timespec="milliseconds").replace("+00:00", "Z")
