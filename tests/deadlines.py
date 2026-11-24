"""What the cookie lookup-deadline suites share: a store that can be told to hang, and the reader.

The peer of `tests/cookies.py`: the deadline suite and the cancellation suite drive the same
scripted store through the same verifier and count the same outage lines, and two copies of any
of that would be two chances to stop agreeing.
"""

from __future__ import annotations

import logging
from typing import Any

import anyio
import pytest

from fastapi_better_auth import (
    CookieVerifier,
    CsrfDisabled,
    SessionStore,
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
