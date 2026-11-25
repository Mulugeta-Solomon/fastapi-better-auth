"""A Redis lookup cut by the verifier's deadline leaves no reply for a later lookup to read.

If a command cancelled mid-flight left its reply unread on a pooled connection, the next command
on that connection would read it instead of its own. A swapped session document is refused - it
names the token it was stored under - but a watermark reply is only digits or nil: a revoked
user's watermark `GET` that read a stale nil would ACCEPT the revoked session. redis-py guards
against this by dropping a connection whose command was cancelled. This pins that, live, so a
redis-py that stopped doing it fails here rather than in production.

Real Redis behind a relay that can stop forwarding (`relay.py`), the real `RedisSessionStore(url=)`
and the real `CookieVerifier` deadline. Three users under a key prefix of this module's own:

    A  standing, no watermark                (its watermark GET answers nil)
    B  revoked: watermark after createdAt    (refused, every time)
    C  standing, watermark before createdAt  (its watermark GET answers digits)

Each case stalls the relay just before one chosen `GET` - a session or a watermark read, of one
user - is sent, with lookups for all three in flight. The deadline lands by order, not by a timer
(`LeapingClock`): the lookups run under `LONG`, and the loop's clock is moved past it only once
the relay holds the chosen `GET` and every lookup in flight has reached the store. The relay then
forwards again and all three users are asked, concurrently and one by one: at once - with no
yield in between, so most likely before the replies to the cut commands have come back, which is
when a pooled connection cannot yet see it has an unread reply - and then a second pass, once the
relay is provably holding nothing. Every answer must be exactly right, and no line may say a
stored session or watermark is unusable - that line is what a swapped reply looks like.

The control repeats the scenario with redis-py stopped from dropping a cancelled command's
connection, and must see at least one wrong answer or unusable line, at every cut point. It is
what makes the main case's "nothing wrong" mean something - the timing of the rounds above is
likely rather than guaranteed, and the control is the proof that it is sensitive enough.

Asyncio only: redis-py drives the event loop directly.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import secrets
import time
import urllib.parse
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import anyio
import pytest

from .conftest import REDIS_URL
from .relay import StallingRelay

try:
    # The test helpers import post-0.1.0 names too, so they belong under the guard as well: the
    # canary's published-wheel leg installs the last release, and must skip here, not raise.
    from fastapi_better_auth import (
        AuthServiceUnavailable,
        CookieVerifier,
        RedisSessionStore,
        SessionError,
    )
    from tests.cookies import COOKIE, http, run, sign
    from tests.deadlines import GUARD, LONG, OVERRUN_REASON, LeapingClock, verifier
    from tests.stores import stored, wire_session, wire_user
except ImportError:
    pytest.skip(
        "this build of fastapi-better-auth-bridge publishes no session stores",
        allow_module_level=True,
    )

if "lookup_timeout" not in inspect.signature(CookieVerifier.__init__).parameters:
    pytest.skip(
        "this build of fastapi-better-auth-bridge predates CookieVerifier(lookup_timeout=...)",
        allow_module_level=True,
    )
if "socket_timeout" not in inspect.signature(RedisSessionStore.__init__).parameters:
    pytest.skip(
        "this build of fastapi-better-auth-bridge predates RedisSessionStore(socket_timeout=...)",
        allow_module_level=True,
    )

import redis.asyncio as aioredis
from redis.exceptions import RedisError

pytestmark = pytest.mark.e2e

LIBRARY_LOGGER = "fastapi_better_auth"
UNUSABLE = "is unusable"
"""What every `unusable()` line says: the store refused a value it read - a swapped reply."""

WATERMARK_PREFIX = "revoked-sessions-before-"

REDIS_DEADLINE = 3600.0
"""`socket_timeout` and `socket_connect_timeout` for the store under test. redis-py's own
deadlines run on the loop's clock too, and the cut leaps that clock by `LONG`; at an hour they are
nowhere near expiry when it does, so the verifier's deadline - not redis-py's read timeout - is
what cuts a lookup. This is by construction, not by assertion: the held lookup must answer
`DEADLINE`, but with a read timeout under the leap it still does (measured: both are due in the
same loop pass, and the verifier's cancellation is the one delivered), so that outcome cannot tell
the two apart - the size of this constant is what does."""

IN_FLIGHT_PER_USER = 2
"""Lookups of each user in flight beside the one whose `GET` is held."""
ASKED_PER_USER = 4
"""Lookups of each user asked at once, after the cut, in each round."""
WARM_PER_USER = 2 * (IN_FLIGHT_PER_USER + 1)
"""Lookups of each user run at once before each cut, so the pool holds a connected connection for
every lookup in flight: one made while the relay is stalled would hold its handshake, and the
chosen `GET` would never be sent."""

SETTLE_BACKSTOP = 10.0
"""How long a condition may take to come true before the case fails. Healthy runs take
milliseconds; this only ever runs out red."""
POLL = 0.01

ACCEPTED = "accepted"
DEADLINE = "cut by the lookup deadline"
STORE_ERROR = "unavailable: the store raised"
REVOKED = "SessionRevoked"

CREATED = datetime.now(timezone.utc) - timedelta(minutes=1)
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
CREATED_MS = (CREATED - EPOCH) // timedelta(milliseconds=1)
WATERMARK_SKEW_MS = 5000
KEY_TTL_SECONDS = 600
"""A backstop only: every key this module writes is deleted when its case ends."""

KINDS = ("session", "watermark")
NAMES = ("A", "B", "C")
CUT_POINTS = [(kind, name) for kind in KINDS for name in NAMES]


@dataclass(frozen=True)
class Who:
    """One user of the scenario, and the one right answer for its session."""

    name: str
    token: str
    user_id: str
    watermark: int | None
    expected: str


def fresh(name: str, watermark: int | None, expected: str) -> Who:
    user_id = f"user-{name}-{secrets.token_hex(4)}"
    return Who(name, secrets.token_hex(16), user_id, watermark, expected)


def people() -> tuple[Who, ...]:
    return (
        fresh("A", None, ACCEPTED),
        fresh("B", CREATED_MS + WATERMARK_SKEW_MS, REVOKED),
        fresh("C", CREATED_MS - WATERMARK_SKEW_MS, ACCEPTED),
    )


def iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def document(who: Who) -> str:
    session = wire_session(
        id=f"session-{who.name}", token=who.token, userId=who.user_id, createdAt=iso(CREATED)
    )
    return stored(session=session, user=wire_user(id=who.user_id))


@dataclass
class Scenario:
    prefix: str
    users: tuple[Who, ...]

    def by_name(self, name: str) -> Who:
        (found,) = [who for who in self.users if who.name == name]
        return found

    def key(self, kind: str, who: Who) -> str:
        suffix = who.token if kind == "session" else f"{WATERMARK_PREFIX}{who.user_id}"
        return f"{self.prefix}{suffix}"

    def keys(self) -> list[str]:
        return [self.key(kind, who) for kind in KINDS for who in self.users]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def unreachable(message: str) -> None:
    """Skip locally when the harness Redis is down; fail in CI, where a silent skip is worse."""
    if os.environ.get("CI"):
        pytest.fail(message)
    pytest.skip(message)


@pytest.fixture
async def scenario() -> AsyncIterator[Scenario]:
    """The three users' keys, written straight to Redis, and removed however the case ends."""
    raw = aioredis.from_url(REDIS_URL)
    built = Scenario(f"cut-reply-{secrets.token_hex(6)}:", people())
    try:
        await raw.exists(built.prefix)
    except (RedisError, OSError) as exc:
        # Probed before anything is written, so there is nothing to remove from a Redis that
        # is not there - a clean-up here would turn the skip into a second connection error.
        await raw.aclose()
        unreachable(f"harness redis not reachable at {REDIS_URL}: {type(exc).__name__}")
    try:
        for who in built.users:
            await raw.set(built.key("session", who), document(who), ex=KEY_TTL_SECONDS)
            if who.watermark is not None:
                watermark_key = built.key("watermark", who)
                await raw.set(watermark_key, str(who.watermark), ex=KEY_TTL_SECONDS)
        yield built
    finally:
        await raw.delete(*built.keys())
        await raw.aclose()


@pytest.fixture
async def relay() -> AsyncIterator[StallingRelay]:
    target = urllib.parse.urlsplit(REDIS_URL)
    built = StallingRelay(target.hostname or "127.0.0.1", target.port or 6379)
    await built.start()
    try:
        yield built
    finally:
        built.resume()
        await built.close()


@pytest.fixture
async def store(relay: StallingRelay, scenario: Scenario) -> AsyncIterator[RedisSessionStore]:
    database = urllib.parse.urlsplit(REDIS_URL).path or "/0"
    async with RedisSessionStore(
        url=f"redis://127.0.0.1:{relay.port}{database}",
        key_prefix=scenario.prefix,
        socket_timeout=REDIS_DEADLINE,
        socket_connect_timeout=REDIS_DEADLINE,
    ) as built:
        yield built


class Gate:
    """Wraps the built client's `get`: stalls the relay just before the armed key's `GET` is sent,
    and counts every session `GET` - one per lookup that has reached the store."""

    def __init__(self, store: RedisSessionStore, relay: StallingRelay) -> None:
        client: Any = vars(store)["_built"]
        self._get: Callable[[str], Any] = client.get
        self._relay = relay
        self.armed: str | None = None
        self.session_gets = 0
        client.get = self.get

    async def get(self, name: str) -> Any:
        if WATERMARK_PREFIX not in name:
            self.session_gets += 1
        if name == self.armed:
            self.armed = None
            self._relay.stall()
        return await self._get(name)


async def asked(steady: CookieVerifier, who: Who) -> str:
    try:
        session = await run(steady, http(cookie=f"{COOKIE}={sign(who.token)}"))
    except AuthServiceUnavailable as exc:
        return DEADLINE if exc.reason.startswith(OVERRUN_REASON) else STORE_ERROR
    except SessionError as exc:
        return type(exc).__name__
    if session is None:
        return "no credential"
    return ACCEPTED if session.user.id == who.user_id else f"accepted as {session.user.id}"


async def every_user_asked(steady: CookieVerifier, users: tuple[Who, ...]) -> list[str]:
    """All three asked at once, then one by one: the wrong answers, as lines."""
    together = [who for who in users for _ in range(ASKED_PER_USER)]
    outcomes = await asyncio.gather(*(asked(steady, who) for who in together))
    answers = list(zip(together, outcomes))
    for who in users:
        answers.append((who, await asked(steady, who)))
    return [f"{who.name}: {got}" for who, got in answers if got != who.expected]


async def until(condition: Callable[[], bool], what: str) -> None:
    """Poll `condition` until it holds, or fail the case naming `what` once the backstop is out."""
    give_up = time.monotonic() + SETTLE_BACKSTOP
    while not condition():
        if time.monotonic() > give_up:
            pytest.fail(f"{what} did not happen within {SETTLE_BACKSTOP}s")
        await asyncio.sleep(POLL)


@dataclass
class Rig:
    scenario: Scenario
    relay: StallingRelay
    gate: Gate
    clock: LeapingClock
    steady: CookieVerifier


async def cut(rig: Rig, kind: str, name: str) -> list[str]:
    """One cut, and every wrong answer it led to, each naming where it was seen."""
    users = rig.scenario.users
    armed = rig.scenario.by_name(name)
    warm = [who for who in users for _ in range(WARM_PER_USER)]
    warmed = await asyncio.gather(*(asked(rig.steady, who) for who in warm))
    wrong = [f"warm-up {who.name}: {got}" for who, got in zip(warm, warmed) if got != who.expected]

    entered = rig.gate.session_gets
    rig.gate.armed = rig.scenario.key(kind, armed)
    in_flight = [armed, *(who for who in users for _ in range(IN_FLIGHT_PER_USER))]
    lookups = [asyncio.ensure_future(asked(rig.steady, who)) for who in in_flight]
    try:
        await until(lambda: rig.relay.holds(rig.scenario.key(kind, armed).encode()), "the hold")
        await until(lambda: rig.gate.session_gets - entered >= len(lookups), "every lookup")
        rig.clock.leap(LONG)
        with anyio.fail_after(GUARD):
            outcomes = await asyncio.gather(*lookups)
    finally:
        rig.relay.resume()
        for lookup in lookups:
            lookup.cancel()

    assert outcomes[0] == DEADLINE, f"the held lookup was not cut by the deadline: {outcomes[0]}"
    wrong += [
        f"cut {who.name}: {got}"
        for who, got in zip(in_flight, outcomes)
        if got not in (DEADLINE, who.expected)
    ]
    wrong += [f"at once {line}" for line in await every_user_asked(rig.steady, users)]
    await until(lambda: rig.relay.held == 0, "the relay passing on what it held")
    wrong += [f"settled {line}" for line in await every_user_asked(rig.steady, users)]
    return [f"cut {kind} of {name}, {line}" for line in wrong]


def rig_for(
    scenario: Scenario,
    relay: StallingRelay,
    store: RedisSessionStore,
    monkeypatch: pytest.MonkeyPatch,
) -> Rig:
    return Rig(
        scenario,
        relay,
        Gate(store, relay),
        LeapingClock(monkeypatch),
        verifier(store, lookup_timeout=LONG),
    )


def unusable_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        entry.getMessage()
        for entry in caplog.records
        if entry.name == LIBRARY_LOGGER and UNUSABLE in entry.getMessage()
    ]


@pytest.mark.anyio
@pytest.mark.parametrize(("kind", "name"), CUT_POINTS, ids=[f"{k}-{n}" for k, n in CUT_POINTS])
async def test_a_cut_lookup_leaves_no_reply_for_a_later_one(
    kind: str,
    name: str,
    scenario: Scenario,
    relay: StallingRelay,
    store: RedisSessionStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    rig = rig_for(scenario, relay, store, monkeypatch)

    with caplog.at_level(logging.WARNING, logger=LIBRARY_LOGGER):
        wrong = await cut(rig, kind, name)

    assert wrong == []
    assert unusable_lines(caplog) == []


def keep_cancelled_connections(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop redis-py from dropping a connection whose command was cancelled.

    redis-py drops it with `disconnect(nowait=True)` from the handler that sees the cancellation;
    every other disconnect - a close, a reconnect - waits, and is let through. The keyword moved
    between releases, so both spellings are read.
    """
    from redis.asyncio import connection

    original = vars(connection.AbstractConnection).get("disconnect")
    if original is None:
        pytest.skip("this redis-py has no AbstractConnection.disconnect to hold back")

    async def disconnect(self: Any, *args: Any, **kwargs: Any) -> None:
        nowait = kwargs.get("nowait", args[0] if args else False)
        if nowait:
            return
        await original(self, *args, **kwargs)

    monkeypatch.setattr(connection.AbstractConnection, "disconnect", disconnect)


@pytest.mark.anyio
@pytest.mark.parametrize(("kind", "name"), CUT_POINTS, ids=[f"{k}-{n}" for k, n in CUT_POINTS])
async def test_the_control_sees_a_stale_reply_when_redis_py_keeps_the_connection(
    kind: str,
    name: str,
    scenario: Scenario,
    relay: StallingRelay,
    store: RedisSessionStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Per cut point, so each main case has a control of its own: the same cut, with the one
    protection under test removed, is seen."""
    keep_cancelled_connections(monkeypatch)
    rig = rig_for(scenario, relay, store, monkeypatch)

    with caplog.at_level(logging.WARNING, logger=LIBRARY_LOGGER):
        wrong = await cut(rig, kind, name)

    assert wrong or unusable_lines(caplog), "the control saw no stale reply: the case is blind"
