"""The lookup deadline catches its own cancellation and nothing else, and what a thread does to it.

A cancellation from outside the verifier - the client disconnected, the server is shutting down,
an enclosing deadline fired - must reach the caller as a cancellation. Turned into
`AuthServiceUnavailable` it would be a refusal answered to nobody, logged as a store outage that
never happened, and on asyncio a task that no longer knows it was cancelled. Each case runs on
asyncio and trio; the native `Task.cancel()` case is asyncio's alone.

A store that blocks a worker thread cannot be interrupted at all. Without `abandon_on_cancel` the
request waits for the thread, and its late answer is still refused; the shipped SQL stores, the
sync adapter's abandoned thread included, are `test_cookie_lookup_sql_stores.py`'s.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Iterator

import anyio
import anyio.to_thread
import pytest

from fastapi_better_auth import (
    AuthServiceUnavailable,
    CookieVerifier,
    CsrfDisabled,
    StoredSession,
    StoredUser,
)
from tests.cookies import http, run, stored_session
from tests.deadlines import (
    CREDENTIAL,
    DEADLINE,
    GUARD,
    OVERRUN_KIND,
    OVERRUN_REASON,
    hung_store,
    kinds,
    outage_lines,
    verifier,
)
from tests.log_hygiene import capturing
from tests.refusal_frames import COOKIE_NAME, COOKIE_VALUE, TOKEN, holding, refused, request
from tests.refusal_frames import SECRET as FRAMES_SECRET
from tests.refusal_frames import stored_session as frames_session

LONG = 60.0
"""A `lookup_timeout` no case waits out: the cancellation under test always comes first."""

THREAD_DELAY = 0.06
"""How long the non-abandonable thread blocks: well past `DEADLINE`, still tens of milliseconds."""


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


# ---------------------------------------------------------------- cancellation from outside


@pytest.mark.anyio
async def test_an_outer_cancel_propagates_as_cancellation(
    records: list[logging.LogRecord],
) -> None:
    """The client went away while the store hung: the request is cancelled, not refused."""
    store = hung_store()
    built = verifier(store, lookup_timeout=LONG)

    with anyio.fail_after(GUARD), anyio.CancelScope() as outer:
        async with anyio.create_task_group() as group:

            async def disconnect() -> None:
                await anyio.wait_all_tasks_blocked()
                outer.cancel()

            group.start_soon(disconnect)
            await run(built, http(cookie=CREDENTIAL))

    assert outer.cancelled_caught
    assert store.session_calls == 1
    assert outage_lines(records) == []


@pytest.mark.anyio
async def test_an_enclosing_deadline_is_the_callers_not_ours(
    records: list[logging.LogRecord],
) -> None:
    """A deadline of the caller's own, shorter than the lookup's, fires as the caller's."""
    store = hung_store()
    built = verifier(store, lookup_timeout=LONG)

    with anyio.move_on_after(GUARD) as guard, pytest.raises(TimeoutError):
        with anyio.fail_after(DEADLINE):
            await run(built, http(cookie=CREDENTIAL))

    assert not guard.cancelled_caught
    assert outage_lines(records) == []


@pytest.mark.anyio
async def test_an_outer_cancel_landing_with_the_deadline_is_still_a_cancellation(
    records: list[logging.LogRecord],
) -> None:
    """The race: the outer scope is cancelled and the lookup's own deadline has passed by the
    time the store first yields, so both are due at one checkpoint. The lookup's scope must not
    absorb it - the caller sees a cancellation, not a refusal, and no outage line is written."""

    class CancellingStore:
        def __init__(self, outer: anyio.CancelScope) -> None:
            self.outer = outer

        async def fetch_session_by_token(self, token: str) -> StoredSession | None:
            self.outer.cancel()
            # Holding the loop on purpose, so both are due before the store's first await.
            time.sleep(DEADLINE * 2)  # noqa: ASYNC251
            await anyio.sleep_forever()
            return None

        async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
            return None

    with anyio.fail_after(GUARD), anyio.CancelScope() as outer:
        await run(
            verifier(CancellingStore(outer), lookup_timeout=DEADLINE), http(cookie=CREDENTIAL)
        )

    assert outer.cancelled_caught
    assert outage_lines(records) == []


class TestNativeAsyncioCancel:
    """`Task.cancel()` is asyncio's own API, with no trio equivalent to drive, so this class pins
    the backend rather than skipping half a parameterization."""

    @pytest.fixture
    def anyio_backend(self) -> str:
        return "asyncio"

    @pytest.mark.anyio
    async def test_a_native_task_cancel_propagates(self, records: list[logging.LogRecord]) -> None:
        """What an asyncio server does to a request it abandons is not ours to refuse."""
        store = hung_store()
        built = verifier(store, lookup_timeout=LONG)

        task = asyncio.ensure_future(run(built, http(cookie=CREDENTIAL)))
        with anyio.fail_after(GUARD):
            await anyio.wait_all_tasks_blocked()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        assert outage_lines(records) == []


# ---------------------------------------------------------------- stores that block a thread


@pytest.mark.anyio
async def test_a_thread_that_cannot_be_abandoned_holds_the_request_and_is_still_refused(
    records: list[logging.LogRecord],
) -> None:
    """A caller-written store that hands off WITHOUT `abandon_on_cancel` cannot be cut off: the
    request waits for the thread whatever the deadline says. When the answer does come, after the
    deadline, it is not honoured - an overrun is the overrun, whether or not the store could be
    interrupted."""

    class PinnedThreadStore:
        def __init__(self) -> None:
            self.completed = 0

        async def fetch_session_by_token(self, token: str) -> StoredSession | None:
            release = threading.Event()
            timer = threading.Timer(THREAD_DELAY, release.set)
            timer.start()
            await anyio.to_thread.run_sync(release.wait, GUARD)
            self.completed += 1
            return stored_session(token)

        async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
            return None

    store = PinnedThreadStore()
    started = anyio.current_time()

    with anyio.fail_after(GUARD), pytest.raises(AuthServiceUnavailable) as caught:
        await run(verifier(store, lookup_timeout=DEADLINE), http(cookie=CREDENTIAL))

    assert anyio.current_time() - started >= THREAD_DELAY - 0.016  # held for the whole thread
    assert store.completed == 1
    assert OVERRUN_REASON in caught.value.reason
    assert kinds(records) == [OVERRUN_KIND]


@pytest.mark.anyio
async def test_a_refused_late_answer_leaves_the_token_in_no_frame() -> None:
    """The late record carries the raw token, and the lookup frame held it when the refusal was
    raised; D-094 walked from the outside, through the resolver FastAPI awaits, finds it gone."""

    class LateRecordStore:
        async def fetch_session_by_token(self, token: str) -> StoredSession | None:
            await anyio.to_thread.run_sync(time.sleep, DEADLINE * 2)
            return frames_session()

        async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
            return None

    store = LateRecordStore()
    connection = request(cookies=[f"{COOKIE_NAME}={COOKIE_VALUE}"])
    built = CookieVerifier(
        secret=FRAMES_SECRET,
        store=store,
        csrf=CsrfDisabled(reason="this row is not about cross-site request forgery"),
        secure_cookies=False,
        lookup_timeout=DEADLINE,
    )

    with anyio.fail_after(GUARD):
        refusal = await refused(built, connection)

    assert type(refusal) is AuthServiceUnavailable
    assert OVERRUN_REASON in refusal.reason
    assert holding(refusal, TOKEN, ignore=[connection, store]) == []
