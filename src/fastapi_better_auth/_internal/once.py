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


class OnceByKey:
    """One `Once` per key: a warning that must fire once for each of several subjects.

    The keyed form exists because "once per process" is the wrong grain for a warning about a
    *model*: a process serving two user models would tell the operator about whichever failed
    first and stay silent about the other forever.
    """

    __slots__ = ("_latches", "_lock")

    def __init__(self) -> None:
        self._latches: dict[object, Once] = {}
        self._lock = threading.Lock()

    def fire(self, key: object) -> bool:
        with self._lock:
            latch = self._latches.get(key)
            if latch is None:
                latch = Once()
                self._latches[key] = latch
        return latch.fire()
