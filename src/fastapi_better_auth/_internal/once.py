"""A once-only latch, shared by the warnings that must fire exactly once."""

from __future__ import annotations

import threading


class Once:
    """A latch that fires true exactly once across threads, for a warning that must not repeat."""

    __slots__ = ("_fired", "_lock")

    def __init__(self) -> None:
        self._fired = False
        self._lock = threading.Lock()

    def fire(self) -> bool:
        with self._lock:
            if self._fired:
                return False
            self._fired = True
            return True
