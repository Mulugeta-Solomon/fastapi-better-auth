"""A blocking call on a worker thread that holds its slot for as long as the thread lives.

`anyio.to_thread.run_sync(..., abandon_on_cancel=True, limiter=...)` frees the caller when it is
cancelled, but the backends disagree about the limiter token. Trio returns it when the thread
ends. anyio's asyncio backend returns it as soon as the caller stops awaiting, while the thread
is still blocked in the database. A limiter meant to bound threads, and with them pooled
connections, then bounds only the callers still waiting, and a database hang turns every request
into one more stuck thread.

So the slot is taken here, on the event loop and cancellably, and given back by whoever is last:
- by the caller, if the thread never started or has already finished;
- by the thread itself, from its own `finally`, if the caller left first.

The thread cannot touch an anyio limiter directly, because that belongs to the loop. It posts the
release to the loop without blocking (`call_soon_threadsafe` on asyncio, `run_sync_soon` on trio).
If the loop has already gone, there is no limiter left to give back to.
"""

from __future__ import annotations

import asyncio
import enum
import threading
from collections.abc import Callable
from typing import TypeVar

import anyio
from anyio.to_thread import run_sync

T = TypeVar("T")

Post = Callable[[Callable[[], object]], object]


class _State(enum.Enum):
    PENDING = "pending"
    """Slot taken; the thread has not started the call."""
    RUNNING = "running"
    """The thread is inside the call and the caller is still waiting for it."""
    ABANDONED = "abandoned"
    """The thread is inside the call and the caller has left: the thread gives the slot back."""
    DONE = "done"
    """The call returned or raised."""
    WITHDRAWN = "withdrawn"
    """The caller left before the thread started and gave the slot back; the call never runs."""


class AbandonedBeforeStartError(Exception):
    """What the worker raises instead of running a call its caller already withdrew.

    The result has no reader: the caller is gone and the slot is already back.
    """


async def run_in_worker(limiter: anyio.CapacityLimiter, call: Callable[[], T]) -> T:
    """Run `call` on a worker thread holding one of `limiter`'s tokens until the thread is done.

    Waiting for the token is cancellable and starts no thread. A cancellation while the call
    runs frees the caller at once (`abandon_on_cancel`); the token stays with the thread.
    """
    slot = _Slot(limiter, _post_to_this_loop())
    await limiter.acquire_on_behalf_of(slot)
    try:
        # A one-token limiter of its own, so this call is not also counted against (and queued
        # behind) the process-wide default thread limiter: `limiter` is the bound.
        return await run_sync(
            slot.run, call, abandon_on_cancel=True, limiter=anyio.CapacityLimiter(1)
        )
    finally:
        slot.settle()


def _post_to_this_loop() -> Post:
    """How a worker thread hands a callback to the running loop without blocking on it."""
    try:
        return asyncio.get_running_loop().call_soon_threadsafe
    except RuntimeError:  # no asyncio loop in this thread: anyio is running on trio
        import trio

        return trio.lowlevel.current_trio_token().run_sync_soon


class _Slot:
    """One token's ownership, handed between the caller and its worker thread under a lock."""

    __slots__ = ("_limiter", "_lock", "_post", "_state")

    def __init__(self, limiter: anyio.CapacityLimiter, post: Post) -> None:
        self._limiter = limiter
        self._post = post
        self._lock = threading.Lock()
        self._state = _State.PENDING

    def run(self, call: Callable[[], T]) -> T:
        """The worker thread's side: run `call`, unless it was withdrawn before it began."""
        with self._lock:
            if self._state is _State.WITHDRAWN:
                raise AbandonedBeforeStartError
            self._state = _State.RUNNING
        try:
            return call()
        finally:
            with self._lock:
                # The caller may have left while `call` ran: read what it left behind.
                abandoned = self._swap(_State.DONE) is _State.ABANDONED
            if abandoned:
                self._post_release()

    def settle(self) -> None:
        """The caller's side, on the loop, however the await ended."""
        with self._lock:
            if self._state is _State.RUNNING:
                self._state = _State.ABANDONED
                return
            if self._state is _State.PENDING:
                self._state = _State.WITHDRAWN
        self._release()

    def _swap(self, state: _State) -> _State:
        """Move to `state` and return the one it replaced; call with the lock held."""
        previous = self._state
        self._state = state
        return previous

    def _post_release(self) -> None:
        try:
            self._post(self._release)
        except RuntimeError:
            # The loop is closed or its run has finished (trio's `RunFinishedError` is a
            # RuntimeError): the limiter went with it, so there is nobody left to give back to.
            return

    def _release(self) -> None:
        self._limiter.release_on_behalf_of(self)
