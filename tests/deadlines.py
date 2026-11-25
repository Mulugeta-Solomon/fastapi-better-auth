"""What the cookie lookup-deadline suites share: a store that can be told to hang, and the reader.

The peer of `tests/cookies.py`: the deadline suite and the cancellation suite drive the same
scripted store through the same verifier and count the same outage lines, and two copies of any
of that would be two chances to stop agreeing.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import threading
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

import anyio
import anyio.to_thread
import pytest

if TYPE_CHECKING:
    from sqlalchemy import Engine
    from sqlalchemy.ext.asyncio import AsyncEngine

from fastapi_better_auth import (
    CookieVerifier,
    CsrfDisabled,
    SessionStore,
    SqlAlchemySessionStore,
    StoredSession,
    StoredUser,
    SyncStoreAdapter,
)
from tests.cookies import CAPTURED_TOKEN, COOKIE, SECRET, sign, stored_session, stored_user
from tests.log_hygiene import LIBRARY_LOGGER

GUARD = 2.0
"""Seconds a test waits before it calls a request hung. Generous on purpose: a lookup that
honours its deadline is back in tens of milliseconds, so the guard only ever fires red."""

DEADLINE = 0.02
"""The `lookup_timeout` the overrun cases configure: short enough to keep the suite fast, and
above Windows' ~15 ms timer granularity so it is a deadline rather than a coin toss."""

LONG = 60.0
"""A `lookup_timeout` no case waits out, for a lookup that a test abandons itself."""

WEDGE_BACKSTOP = 30.0
"""How long a `DriverGate` holds a statement before giving up on the test that should have
released it. This is a backstop against a wedged suite, never a margin a test relies on: every
step of a test that holds the gate is bounded by its own, much shorter `GUARD`, so a test that
reaches this has already failed."""

CREDENTIAL = f"{COOKIE}={sign(CAPTURED_TOKEN)}"

OUTAGE_HEAD = "session store lookup could not complete"
OVERRUN_KIND = "LookupDeadlineExceeded"
OVERRUN_REASON = "session store lookup did not answer within"


class ScriptedStore:
    """A `SessionStore` each lookup of which can be told to answer, raise, or never return.

    Every call records the deadline it ran under (`anyio.current_effective_deadline()`), which is
    how a test proves which budget a lookup was given without waiting for it to run out.
    """

    def __init__(self, *, embed_user: bool = True) -> None:
        self.embed_user = embed_user
        self.hang_session = False
        self.hang_user = False
        self.session_error: Exception | None = None
        self.session_calls = 0
        self.user_calls = 0
        self.completed = 0
        self.deadlines: list[float] = []

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        self.session_calls += 1
        self.deadlines.append(anyio.current_effective_deadline())
        if self.session_error is not None:
            raise self.session_error
        if self.hang_session:
            await anyio.sleep_forever()
        self.completed += 1
        return stored_session(token, user=stored_user() if self.embed_user else None)

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        self.user_calls += 1
        self.deadlines.append(anyio.current_effective_deadline())
        if self.hang_user:
            await anyio.sleep_forever()
        self.completed += 1
        return stored_user()


def hung_store() -> ScriptedStore:
    store = ScriptedStore()
    store.hang_session = True
    return store


def verifier(store: SessionStore, **options: Any) -> CookieVerifier:
    """The cookie lane's plain-name deployment (`tests/cookies.py::verifier`), over any store."""
    return CookieVerifier(
        secret=SECRET,
        store=store,
        csrf=CsrfDisabled(reason="deadline tests do not exercise CSRF"),
        secure_cookies=False,
        **options,
    )


async def abandoned_once_inside(arrived: Callable[[], Awaitable[object]], lookup: Any) -> None:
    """Start `lookup`, wait until the driver has seen it arrive, then cancel its caller."""
    with anyio.fail_after(GUARD), anyio.CancelScope() as caller:
        async with anyio.create_task_group() as group:
            group.start_soon(lookup)
            await arrived()
            caller.cancel()
    assert caller.cancelled_caught


class DriverGate:
    """Holds every statement a sync engine sends in `do_execute` until released, and counts.

    This stands in for a database that has stopped answering, met exactly where a worker thread
    meets one. `entries` counts every call that ever reached the driver, `inside` the calls held
    right now, and `peak` the most held at once. `entered(n)` is how a test knows, by an event
    and not by a timer, that `n` calls have reached the driver.
    """

    def __init__(self, engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
        self.release = threading.Event()
        self._changed = threading.Condition()
        self.entries = 0
        self.inside = 0
        self.peak = 0
        original = engine.dialect.do_execute

        def do_execute(cursor: Any, statement: str, parameters: Any, context: Any = None) -> None:
            with self._changed:
                self.entries += 1
                self.inside += 1
                self.peak = max(self.peak, self.inside)
                self._changed.notify_all()
            try:
                if not self.release.wait(WEDGE_BACKSTOP):
                    raise RuntimeError("DriverGate was never released; the test wedged")
                original(cursor, statement, parameters, context)
            finally:
                with self._changed:
                    self.inside -= 1
                    self._changed.notify_all()

        monkeypatch.setattr(engine.dialect, "do_execute", do_execute)

    async def entered(self, count: int) -> None:
        """Wait until `count` calls in all have reached the driver, or fail the test."""

        def reached() -> bool:
            with self._changed:
                return self._changed.wait_for(lambda: self.entries >= count, GUARD)

        if not await anyio.to_thread.run_sync(reached):
            pytest.fail(f"only {self.entries} of {count} calls reached the driver in {GUARD}s")


async def every_slot_returned(store: SyncStoreAdapter) -> None:
    """Wait until every one of the adapter's slots is back, or fail the test saying so.

    A slot is held for a worker thread's whole life, so all of them back means every thread has
    ended: its DBAPI call returned, its rows were read and its connection went back to the pool.
    Taking every slot is the proof, since a thread still running holds one and the acquire waits
    for it. The probes are then released, so the adapter is left as found.
    """
    limiter = store._get_limiter()  # pyright: ignore[reportPrivateUsage]
    probes = [object() for _ in range(int(limiter.total_tokens))]
    try:
        with anyio.fail_after(GUARD):
            for probe in probes:
                await limiter.acquire_on_behalf_of(probe)
    except TimeoutError:
        pytest.fail(
            f"{limiter.borrowed_tokens} adapter slot(s) still held {GUARD}s after the database"
            " was released: a worker thread did not end, or a slot leaked"
        )
    finally:
        held = limiter.statistics().borrowers
        for probe in probes:
            if probe in held:
                limiter.release_on_behalf_of(probe)


class AsyncDriverGate:
    """`DriverGate`'s twin for an async engine: holds every statement until released, and records
    what a cancellation does to the statement it lands on.

    SQLAlchemy runs `do_execute` in a greenlet on the event loop, and `await_only` is the bridge
    the driver itself awaits through, so the hold is a real await a cancellation can land on. A
    statement that is cancelled behaves as SQLAlchemy does with a cancelled `execute`: it runs a
    clean-up under `asyncio.shield` - where asyncpg would send the server its cancel request -
    and only then lets the cancellation go. The clean-up ends when `acknowledged` is set, which is
    how a test holds an abandoned call open for as long as it needs to look at it.

    A second cancellation landing on that shielded wait interrupts the clean-up, as it would
    interrupt SQLAlchemy's graceful close, and is counted in `interrupted`. `late_error`, when set,
    is what the statement raises once its clean-up has ended, in place of the cancellation.
    """

    def __init__(self, engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch) -> None:
        from sqlalchemy.util import await_only

        self.release = asyncio.Event()
        self.acknowledged = asyncio.Event()
        self.arrived = asyncio.Event()
        self.entries = 0
        self.cancellations = 0
        self.cleaned_up = 0
        self.interrupted = 0
        self.late_raised = 0
        self.late_error: type[sqlite3.Error] | None = None
        dialect = engine.sync_engine.dialect
        original = dialect.do_execute

        def do_execute(cursor: Any, statement: str, parameters: Any, context: Any = None) -> None:
            if not self.release.is_set():
                await_only(self._held())
            original(cursor, statement, parameters, context)

        monkeypatch.setattr(dialect, "do_execute", do_execute)

    async def _held(self) -> None:
        self.entries += 1
        self.arrived.set()
        try:
            # No timeout of its own: a test that holds the gate bounds every wait on it by
            # `GUARD`, and releases it in a `finally`.
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancellations += 1
            await self._cleaned_up()
            raise

    async def _cleaned_up(self) -> None:
        try:
            await asyncio.shield(self.acknowledged.wait())
        except asyncio.CancelledError:
            self.interrupted += 1
            raise
        self.cleaned_up += 1
        if self.late_error is not None:
            self.late_raised += 1
            raise self.late_error(f"the statement failed late while matching ({CAPTURED_TOKEN})")

    def open(self) -> None:
        """Let every statement through, and end every clean-up that is waiting."""
        self.release.set()
        self.acknowledged.set()


class LeapingClock:
    """The running loop's clock, made to leap forward when a test says so.

    A deadline that must land at a known point - after the statement has reached the database,
    never before - cannot be a short timer: a busy machine can fire it anywhere. So the test
    configures a deadline it would never wait out (`LONG`), waits for the event that says the
    statement is held, and then moves the loop's clock past it. anyio's deadlines are read from
    `loop.time()`, so the deadline fires through anyio's own timer, on the next loop iteration.

    Every other timer on the loop sees the leap too. A `fail_after(GUARD)` entered before it
    would expire with it, so a guard is entered only after the leap, or exited before.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        loop = asyncio.get_running_loop()
        original = loop.time
        self._offset = 0.0
        monkeypatch.setattr(loop, "time", lambda: original() + self._offset)

    def leap(self, seconds: float) -> None:
        self._offset += seconds


async def every_call_ended(store: SqlAlchemySessionStore) -> None:
    """Wait until every database call the store abandoned has ended, or fail the test saying so.

    An abandoned call keeps its pooled connection while SQLAlchemy and the driver wind it down;
    disposing the engine or closing the loop before then cuts that short. The store keeps the
    tasks itself, so this asks it rather than guessing from the pool.
    """
    handoff = store._handoff  # pyright: ignore[reportPrivateUsage]
    try:
        with anyio.fail_after(GUARD):
            await handoff.settled()
    except TimeoutError:
        pytest.fail(
            f"{handoff.winding_down} abandoned database call(s) still winding down {GUARD}s"
            " after the database was released"
        )


def outage_lines(records: list[logging.LogRecord]) -> list[logging.LogRecord]:
    """The library's store-outage WARNINGs among `records`, in order."""
    return [
        record
        for record in records
        if record.name == LIBRARY_LOGGER and str(record.msg).startswith(OUTAGE_HEAD)
    ]


def kinds(records: list[logging.LogRecord]) -> list[object]:
    """The failure kind (driver error class) each outage line names, in order."""
    found: list[object] = []
    for record in outage_lines(records):
        driver_error, *_ = tuple(record.args or ())
        found.append(driver_error)
    return found
