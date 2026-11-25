"""A database call on an asyncio task of its own, which a caller that leaves cancels exactly once.

anyio cancels level-triggered: while a cancel scope is cancelled, every await inside it is
cancelled again. SQLAlchemy's asyncio layer and its drivers are written for asyncio's own,
deliver-once cancellation. A cancellation that lands in `execute` makes SQLAlchemy invalidate the
connection and close it gracefully under `asyncio.shield` - asyncpg sends the server a cancel
request on the way - and a second delivery interrupts that close, so SQLAlchemy cuts the socket
instead. The cancel request never goes out, and the server keeps running the abandoned statement,
holding a backend and whatever lock it queued for, while the client-side pool looks healthy.

So the call runs here, on a task outside the caller's cancel scope, and the caller waits for it
behind `asyncio.shield`. A caller that is cancelled - a deadline, a client gone - returns at once
and cancels the task once; SQLAlchemy and the driver then wind the call down in order. The
connection stays checked out of the engine's pool until they have, so the pool's own size bounds
the calls winding down. Nothing after that cancel is awaited on the caller's side: its scope would
cancel the await. The rest happens in callbacks.

A driver need not bound its own clean-up (asyncpg before 0.32 waits on a server that stopped
answering for as long as it does not answer), so the backstop is this module's: a call still
running `WIND_DOWN_SECONDS` after it was abandoned is cancelled again, and again at every further
interval until it ends. That second cancellation is the forced close - bounded, if not graceful.

The call's outcome is always consumed and never shown. A driver error's text can embed the bound
parameters, a session token among them (A1), and asyncio prints a task's unretrieved exception -
from the task's finalizer, or at `asyncio.run` shutdown for a task that ends with one after being
cancelled there. So the task never ends with an exception at all: the call's error is returned to
it as a value and raised again in the caller's task, where the store translates it. An abandoned
call's outcome is dropped unread.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")

WIND_DOWN_SECONDS = 5.0
"""How long an abandoned call may take to wind down before it is cancelled again.

Longer than SQLAlchemy's own two-second bound on a graceful close, so a driver that bounds its
clean-up finishes it cleanly - the statement cancelled on the server - before anything is forced.
"""

TASK_NAME = "fastapi-better-auth store call"


@dataclass(frozen=True)
class _Returned(Generic[T]):
    value: T


@dataclass(frozen=True)
class _Raised:
    error: Exception


_Outcome = _Returned[T] | _Raised


async def _captured(call: Callable[[], Awaitable[T]]) -> _Outcome[T]:
    """Run `call`, and end with its outcome as a value - never with its exception."""
    try:
        return _Returned(await call())
    except Exception as exc:  # noqa: BLE001 - handed to the caller's task, which raises it
        return _Raised(exc)


class TaskHandoff:
    """The database calls one store has handed to tasks of their own.

    Holds every abandoned call's task until it ends: asyncio keeps only weak references to its
    tasks, and a call whose clean-up waits on something only it can reach would otherwise be
    collected mid-clean-up, its connection with it.
    """

    __slots__ = ("_abandoned", "_wind_down")

    def __init__(self, wind_down: float = WIND_DOWN_SECONDS) -> None:
        self._wind_down = wind_down
        self._abandoned: dict[asyncio.Task[object], asyncio.TimerHandle] = {}

    @property
    def winding_down(self) -> int:
        """How many abandoned calls have not ended yet."""
        return len(self._abandoned)

    async def run(self, call: Callable[[], Awaitable[T]]) -> T:
        """Await `call()` on a task of its own; a cancellation of the caller cancels it once.

        Its result is returned and its exception raised here, as if it had been awaited directly.
        """
        task = asyncio.get_running_loop().create_task(_captured(call), name=TASK_NAME)
        try:
            outcome = await asyncio.shield(task)
        except asyncio.CancelledError:
            self._abandon(task)
            raise
        if isinstance(outcome, _Raised):
            raise outcome.error
        return outcome.value

    async def settled(self) -> None:
        """Wait until every abandoned call has ended.

        For tests, which must not dispose an engine or close a loop under a call still winding
        down. A store has no close of its own to hang this on: its engine is the application's.
        """
        while self._abandoned:
            await asyncio.wait(tuple(self._abandoned))

    def _abandon(self, task: asyncio.Task[_Outcome[T]]) -> None:
        """The caller left: cancel its call once, and own the task until it ends."""
        if task.done():
            # It finished before the caller could read it: no connection is held, and its outcome
            # is a value, so there is nothing to wind down and nothing to retrieve.
            return
        task.cancel()
        self._abandoned[task] = self._backstop(task)
        task.add_done_callback(self._ended)

    def _backstop(self, task: asyncio.Task[object]) -> asyncio.TimerHandle:
        return task.get_loop().call_later(self._wind_down, self._cancel_again, task)

    def _cancel_again(self, task: asyncio.Task[object]) -> None:
        if task not in self._abandoned:
            return
        task.cancel()
        self._abandoned[task] = self._backstop(task)

    def _ended(self, task: asyncio.Task[object]) -> None:
        # Dropping the task is all that consuming its outcome takes: `_captured` makes that a
        # value, and a task that ends with a value - or cancelled - has nothing asyncio reports.
        backstop = self._abandoned.pop(task, None)
        if backstop is not None:
            backstop.cancel()
