"""`now=`: the clock seam on `CookieVerifier` and `RemoteVerifier`, which can only make them stricter.

#82 asked for a clock a consumer's test can move, to prove its own expiry rule is enforced. R51 makes
it one-way: expiry is checked against the LATER of the real time and `now()`, and a ban's lapse
against the EARLIER. Moving the seam forward expires sessions sooner, moving it back changes
nothing, and no seam can shorten a ban - so left wired in production, its worst case is early expiry.

Every property is proven over a range of offsets, from one microsecond - `datetime`'s resolution -
to thirty days, in both directions, for both verifiers and on both backends: a mutation one offset
lets through, its neighbours catch, and a seam honoured only past some threshold is caught below
it. The record sits still at a millisecond-aligned instant and the real clock (frozen,
`tests/wall_clock.py`) and the seam are placed around it, so each offset is exact on Mode C's wire
too. A seam that raises or returns something unusable is `test_refusal_clock_contained.py`.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from fastapi_better_auth import (
    ConfigurationError,
    CookieVerifier,
    CsrfDisabled,
    RemoteVerifier,
    SessionExpired,
    SessionRevoked,
)
from tests import cookies, remote_fixtures
from tests.transports import ScriptedTransport, json_reply
from tests.wall_clock import INSTANT, freeze_wall_clock, wire

RESOLUTION = timedelta(microseconds=1)
OFFSETS = (
    RESOLUTION,
    timedelta(microseconds=2),
    timedelta(milliseconds=1),
    timedelta(milliseconds=500),
    timedelta(microseconds=999_999),
    timedelta(seconds=1),
    timedelta(seconds=59),
    timedelta(minutes=31),
    timedelta(hours=6),
    timedelta(days=1),
    timedelta(days=30),
)
OFFSET_IDS = ("1us", "2us", "1ms", "500ms", "999999us", "1s", "59s", "31min", "6h", "1d", "30d")
MODES = ("cookie", "remote")
MILLISECOND = timedelta(milliseconds=1)
RECORD = INSTANT
"""Where a range leg's `expires_at` or `ban_expires` sits. Millisecond-aligned, because Mode C's
wire carries milliseconds (`JSON.stringify`): the clocks move around the record, never it."""
LONG_LIVED = INSTANT + timedelta(days=3650)
"""A session expiry beyond every seam here, for the legs about bans."""

JST = timezone(timedelta(hours=9))
UTC = timezone.utc

Now = Callable[[], datetime]


def at(instant: datetime) -> Now:
    """A seam stopped at `instant`."""
    return lambda: instant


class CountingSeam:
    """A seam stopped at `instant` that counts how often it is read."""

    def __init__(self, instant: datetime) -> None:
        self.instant = instant
        self.reads = 0

    def __call__(self) -> datetime:
        self.reads += 1
        return self.instant


async def outcome(
    mode: str,
    *,
    now: Any,
    expires_at: datetime,
    banned: bool | None = False,
    ban_expires: datetime | None = None,
) -> str:
    """What one verification answers - `admitted`, `expired` or `banned` - in `mode`.

    Mode A reads the record from a store, Mode C from a get-session body carrying the same values;
    `now` is passed only when it is not `None`, so the `None` legs are the default construction.
    The cookie and the body carry the token, so neither is bound to a local `pytest -l` would print.
    """
    extra: dict[str, Any] = {} if now is None else {"now": now}
    try:
        if mode == "cookie":
            user = cookies.stored_user(banned=banned, ban_expires=ban_expires)
            record = cookies.stored_session(
                cookies.CAPTURED_TOKEN, expires_at=expires_at, user=user
            )
            store = cookies.FakeStore(sessions={cookies.CAPTURED_TOKEN: record})
            session = await cookies.run(
                cookies.verifier(store=store, **extra),
                cookies.http(cookie=f"{cookies.COOKIE}={cookies.sign(cookies.CAPTURED_TOKEN)}"),
            )
        else:
            upstream = remote_fixtures.RecordingTransport(
                json_reply(
                    remote_fixtures.document(
                        expires=wire(expires_at),
                        banned=banned,
                        banExpires=None if ban_expires is None else wire(ban_expires),
                    )
                )
            )
            session = await remote_fixtures.run(
                remote_fixtures.verifier(upstream, **extra), remote_fixtures.with_cookie()
            )
    except SessionExpired:
        return "expired"
    except SessionRevoked as refused:
        assert "banned" in refused.reason, "a revocation that is not the ban rung"
        return "banned"
    assert session is not None
    return "admitted"


async def banned_outcome(mode: str, *, now: Any, ban_expires: datetime | None) -> str:
    """`outcome` for a banned user on a session that outlives every seam here."""
    return await outcome(mode, now=now, expires_at=LONG_LIVED, banned=True, ban_expires=ban_expires)


@pytest.fixture(autouse=True)
def frozen(monkeypatch: pytest.MonkeyPatch) -> list[datetime]:
    """The real clock reads `INSTANT` for every test here; the list counts its reads."""
    return freeze_wall_clock(monkeypatch)


Freeze = Callable[[datetime], list[datetime]]


@pytest.fixture
def real_clock(monkeypatch: pytest.MonkeyPatch) -> Freeze:
    """Re-freezes the real clock at a leg's own instant; the list it returns counts the reads."""
    return lambda instant: freeze_wall_clock(monkeypatch, instant)


def inside(offset: timedelta) -> timedelta:
    """How far past the earlier clock the record sits: half the gap, and at least 1 us.

    From 2 us up that is strictly between the two clocks, so a range leg never rests on the `<=`
    the boundary legs pin. At 1 us - the resolution - the window `(earlier, later]` holds exactly
    one instant, the later clock's, and the record has to sit on it.
    """
    return max(RESOLUTION, offset // 2)


# ---------------------------------------------------------------- expiry: the later of the two


@pytest.mark.anyio
@pytest.mark.parametrize("offset", OFFSETS, ids=OFFSET_IDS)
@pytest.mark.parametrize("mode", MODES)
class TestExpiryReadsTheLaterClock:
    async def test_a_seam_ahead_refuses_a_session_the_real_clock_admits(
        self, mode: str, offset: timedelta, real_clock: Freeze
    ) -> None:
        """The whole of #82: move the clock past the consumer's own cap and see the refusal."""
        real = RECORD - inside(offset)
        reads = real_clock(real)

        assert await outcome(mode, now=None, expires_at=RECORD) == "admitted"
        assert await outcome(mode, now=at(real + offset), expires_at=RECORD) == "expired"
        assert reads, "the frozen real clock was never read"

    async def test_a_seam_behind_leaves_a_live_session_live(
        self, mode: str, offset: timedelta, real_clock: Freeze
    ) -> None:
        real = RECORD - inside(offset)
        reads = real_clock(real)

        assert await outcome(mode, now=at(real - offset), expires_at=RECORD) == "admitted"
        assert reads, "the frozen real clock was never read"

    async def test_a_seam_behind_cannot_revive_an_expired_session(
        self, mode: str, offset: timedelta, real_clock: Freeze
    ) -> None:
        """The seam alone would admit this session; the real clock still refuses it."""
        seam = RECORD - inside(offset)
        reads = real_clock(seam + offset)

        assert await outcome(mode, now=None, expires_at=RECORD) == "expired"
        assert await outcome(mode, now=at(seam), expires_at=RECORD) == "expired"
        assert reads, "the frozen real clock was never read"


# ---------------------------------------------------------------- a ban's lapse: the earlier of the two


@pytest.mark.anyio
@pytest.mark.parametrize("offset", OFFSETS, ids=OFFSET_IDS)
@pytest.mark.parametrize("mode", MODES)
class TestBanLapseReadsTheEarlierClock:
    async def test_a_seam_ahead_cannot_lapse_a_ban_early(
        self, mode: str, offset: timedelta, real_clock: Freeze
    ) -> None:
        """A temporary ban still holds: the seam alone would read it as lapsed."""
        real = RECORD - inside(offset)
        reads = real_clock(real)

        assert await banned_outcome(mode, now=None, ban_expires=RECORD) == "banned"
        assert await banned_outcome(mode, now=at(real + offset), ban_expires=RECORD) == "banned"
        assert reads, "the frozen real clock was never read"

    async def test_a_seam_ahead_leaves_a_lapsed_ban_lapsed(
        self, mode: str, offset: timedelta, real_clock: Freeze
    ) -> None:
        real = RECORD + inside(offset)
        reads = real_clock(real)

        assert await banned_outcome(mode, now=at(real + offset), ban_expires=RECORD) == "admitted"
        assert reads, "the frozen real clock was never read"

    async def test_a_seam_behind_keeps_a_ban_the_real_clock_would_let_lapse(
        self, mode: str, offset: timedelta, real_clock: Freeze
    ) -> None:
        seam = RECORD - inside(offset)
        reads = real_clock(seam + offset)

        assert await banned_outcome(mode, now=None, ban_expires=RECORD) == "admitted"
        assert await banned_outcome(mode, now=at(seam), ban_expires=RECORD) == "banned"
        assert reads, "the frozen real clock was never read"

    async def test_a_seam_behind_leaves_an_active_ban_active(
        self, mode: str, offset: timedelta, real_clock: Freeze
    ) -> None:
        real = RECORD - inside(offset)
        reads = real_clock(real)

        assert await banned_outcome(mode, now=at(real - offset), ban_expires=RECORD) == "banned"
        assert reads, "the frozen real clock was never read"


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
class TestSeamEdges:
    async def test_no_seam_lifts_a_permanent_ban(self, mode: str) -> None:
        for seam in (at(INSTANT - timedelta(days=3650)), at(LONG_LIVED - MILLISECOND)):
            assert await banned_outcome(mode, now=seam, ban_expires=None) == "banned"

    async def test_expiry_is_inclusive_at_the_seams_instant(self, mode: str) -> None:
        """The same `<=` as the real clock's, now reachable without freezing anything."""
        expires_at = INSTANT + timedelta(hours=1)

        assert await outcome(mode, now=at(expires_at), expires_at=expires_at) == "expired"
        assert await outcome(mode, now=at(expires_at - MILLISECOND), expires_at=expires_at) == (
            "admitted"
        )

    async def test_a_ban_lapses_at_exactly_the_seams_instant(self, mode: str) -> None:
        until = INSTANT - timedelta(hours=1)

        assert await banned_outcome(mode, now=at(until), ban_expires=until) == "admitted"
        assert await banned_outcome(mode, now=at(until - MILLISECOND), ban_expires=until) == (
            "banned"
        )

    async def test_a_seam_in_another_timezone_is_the_same_instant(self, mode: str) -> None:
        """Compared as instants, not as wall-clock digits: 21:00 in Tokyo is 12:00 in UTC."""
        expires_at = INSTANT + timedelta(hours=1)

        assert await outcome(mode, now=at(expires_at.astimezone(JST)), expires_at=expires_at) == (
            "expired"
        )
        assert await outcome(
            mode, now=at((expires_at - MILLISECOND).astimezone(JST)), expires_at=expires_at
        ) == ("admitted")

    async def test_now_none_is_the_default(self, mode: str) -> None:
        """Passed explicitly, `None` is today's behaviour: the real clock alone."""
        assert await outcome(mode, now=None, expires_at=INSTANT) == "expired"
        assert await outcome(mode, now=None, expires_at=INSTANT + MILLISECOND) == "admitted"


# ---------------------------------------------------------------- a seam cannot bend the comparison


class Later(datetime):
    """Claims to be later than anything, so `max()` picks it, then denies that a session expired."""

    def __gt__(self, other: object) -> bool:
        return True

    def __ge__(self, other: object) -> bool:
        return False


class Earlier(datetime):
    """Claims to be earlier than anything, so `min()` picks it and `max()` passes it over, then
    says every ban has lapsed."""

    def __lt__(self, other: object) -> bool:
        return True

    def __gt__(self, other: object) -> bool:
        return False

    def __ge__(self, other: object) -> bool:
        return True


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
class TestASeamIsReadAsAnInstant:
    """A `datetime` subclass may override its comparisons, and the reflected one runs first. The
    seam's value is rebuilt as a plain `datetime` before it is compared, so all a seam decides is
    which instant it names - the one power it is meant to have."""

    async def test_a_comparison_override_cannot_revive_an_expired_session(self, mode: str) -> None:
        liar = Later(2000, 1, 1, tzinfo=timezone.utc)
        expires_at = INSTANT - timedelta(hours=1)

        assert await outcome(mode, now=lambda: liar, expires_at=expires_at) == "expired"

    async def test_a_comparison_override_cannot_lapse_an_active_ban(self, mode: str) -> None:
        named = INSTANT + timedelta(minutes=30)
        liar = Earlier(named.year, named.month, named.day, named.hour, named.minute, tzinfo=UTC)
        until = INSTANT + timedelta(hours=1)

        assert await banned_outcome(mode, now=lambda: liar, ban_expires=until) == "banned"


# ---------------------------------------------------------------- one read of each clock per check


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    ("banned", "ban_expires", "checks"),
    [
        (False, None, 1),
        (None, None, 1),
        (True, INSTANT - timedelta(hours=1), 2),
        (True, None, 1),
    ],
    ids=["not-banned", "ban-unknown", "temporary-ban", "permanent-ban"],
)
async def test_each_check_reads_the_real_clock_once_and_the_seam_once(
    mode: str,
    banned: bool | None,
    ban_expires: datetime | None,
    checks: int,
    frozen: list[datetime],
) -> None:
    """Expiry always reads a clock; the ban rung reads one only for a ban with an expiry to lapse.
    Each read takes the real time and the seam's once, and nothing else asks for either."""
    seam = CountingSeam(INSTANT)

    await outcome(mode, now=seam, expires_at=LONG_LIVED, banned=banned, ban_expires=ban_expires)

    assert seam.reads == checks
    assert len(frozen) == checks


@pytest.mark.anyio
@pytest.mark.parametrize("mode", MODES)
async def test_no_seam_reads_the_real_clock_once_per_check(
    mode: str, frozen: list[datetime]
) -> None:
    await banned_outcome(mode, now=None, ban_expires=INSTANT - timedelta(hours=1))

    assert len(frozen) == 2


# ---------------------------------------------------------------- construction


def cookie_verifier(**kwargs: Any) -> CookieVerifier:
    return CookieVerifier(
        secret=cookies.SECRET,
        store=cookies.FakeStore(),
        csrf=CsrfDisabled(reason="construction only, no request is verified"),
        **kwargs,
    )


def remote_verifier(**kwargs: Any) -> RemoteVerifier:
    return RemoteVerifier(
        base_url=remote_fixtures.ORIGIN,
        csrf=CsrfDisabled(reason="construction only, no request is verified"),
        transport=ScriptedTransport(json_reply(remote_fixtures.document())),
        **kwargs,
    )


BUILDERS: dict[str, Callable[..., Any]] = {
    "CookieVerifier": cookie_verifier,
    "RemoteVerifier": remote_verifier,
}


@pytest.mark.parametrize("owner", list(BUILDERS))
class TestConstruction:
    @pytest.mark.parametrize(
        "now",
        [INSTANT, "2026-06-01T12:00:00Z", 1780315200.0, object()],
        ids=["an-instant-not-a-callable", "str", "float", "object"],
    )
    def test_a_now_that_is_not_callable_is_refused_naming_the_verifier(
        self, owner: str, now: object
    ) -> None:
        """`now=datetime.now(timezone.utc)` - the instant, not the callable - is the likely slip."""
        with pytest.raises(ConfigurationError) as caught:
            BUILDERS[owner](now=now)

        message = str(caught.value)
        assert f"{owner}(now=...)" in message
        assert type(now).__name__ in message

    def test_none_and_a_callable_are_accepted(self, owner: str) -> None:
        BUILDERS[owner](now=None)
        BUILDERS[owner](now=at(INSTANT))

    def test_the_seam_is_not_read_at_construction(self, owner: str) -> None:
        """It may depend on state a test sets up later, so nothing calls it before a request."""
        seam = CountingSeam(INSTANT)

        BUILDERS[owner](now=seam)

        assert seam.reads == 0

    def test_now_is_keyword_only(self, owner: str) -> None:
        target = CookieVerifier if owner == "CookieVerifier" else RemoteVerifier
        parameter = inspect.signature(target.__init__).parameters["now"]

        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is None
