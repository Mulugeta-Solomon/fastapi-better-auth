"""A lock whose turn goes to the newest waiter, for work a waiter restarts from nothing.

First-use schema discovery runs inside a request, under that request's `lookup_timeout`, one read
at a time. A read that overruns is abandoned with its caller, and the next holder starts it again
from nothing. `anyio.Lock` hands over first-in-first-out, so the next holder is the oldest waiter:
the one with the least budget left, only the gap between two arrivals. While requests arrive
faster than one read takes, every read is cut short by its holder's deadline and none completes,
on a database that is answering again (F22). Handed to the newest waiter instead, the next read
has close to a whole deadline to finish in.

Waiters are ordered by arrival alone; no deadline is read. Built on `anyio.Event`, so it runs on
asyncio and on trio, and it is constructible outside a running loop: each waiter's event is made
inside `acquire`. A waiter cancelled while it waits leaves the line. One cancelled just as it is
handed the turn passes it on at once, without an `await` its own cancellation could interrupt, so
the turn is never lost and nobody is left waiting for it.
"""

from __future__ import annotations

from types import TracebackType

import anyio


class NewestFirstLock:
    """One holder at a time; on release, the turn goes to the waiter that arrived last."""

    __slots__ = ("_held", "_waiters")

    def __init__(self) -> None:
        self._held = False
        self._waiters: list[anyio.Event] = []

    async def acquire(self) -> None:
        """Take the turn, waiting behind the current holder if there is one."""
        if not self._held:
            self._held = True
            return
        turn = anyio.Event()
        self._waiters.append(turn)
        try:
            await turn.wait()
        except BaseException:
            if turn.is_set():
                # Handed the turn as it was cancelled: give it straight on, so it is not lost.
                self.release()
            else:
                self._waiters.remove(turn)
            raise

    def release(self) -> None:
        """Hand the turn to the newest waiter, or leave it free if nobody waits."""
        if self._waiters:
            self._waiters.pop().set()
        else:
            self._held = False

    async def __aenter__(self) -> None:
        await self.acquire()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()
