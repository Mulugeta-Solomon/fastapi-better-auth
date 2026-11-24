"""A test that takes the interpreter to its recursion limit must not let the collector run there.

Several tests drive a parser to the recursion limit on purpose (a nested-JSON bomb, the deepest
token header the size cap admits). If the cyclic garbage collector runs while the stack is at its
deepest, it finalizes whatever unrelated garbage is waiting - in this suite, dead event loops that
starlette's `TestClient` leaves in reference cycles - and a finalizer that calls even one more
function raises `RecursionError`. Python reports that as an unraisable exception, and pytest, with
warnings as errors, fails whichever test happened to be running.

The reproduction below makes the timing deterministic instead of waiting for it: it plants a
closed event loop in a cycle, stops one frame short of the limit, and allocates enough tracked
objects there to force an automatic collection.
"""

from __future__ import annotations

import asyncio
import gc
import itertools
import sys

import pytest

from tests.recursion_limit import collector_paused

COLLECTION_DEFERRED = 10_000
"""Gen-0 threshold while descending, so no collection happens on the way down.

On 3.10 every frame is a tracked object, so the descent itself would otherwise trigger an early
collection at a shallow depth and free the planted loop before the limit is reached.
"""


def dead_loop_in_a_cycle() -> None:
    """What a `TestClient` leaves behind: a closed loop reachable only through a cycle."""
    loop = asyncio.new_event_loop()
    loop.close()
    holder: dict[str, object] = {"loop": loop}
    holder["self"] = holder


def collection_one_frame_short_of_the_limit() -> None:
    """Descend until the next call fails, then force a collection with one frame of headroom.

    One frame is what `BaseEventLoop.__del__` takes; its call to `self.is_closed()` is the one
    that does not fit, which is the traceback CI recorded. The allocation is C calls only, so it
    takes no Python frame of its own on any supported version.
    """

    def descend() -> int:
        try:
            below = descend()
        except RecursionError:
            return 0
        if below == 0:
            list(map(list, itertools.repeat((), COLLECTION_DEFERRED + 1)))
        return below + 1

    gc.collect()
    dead_loop_in_a_cycle()
    threshold = gc.get_threshold()
    gc.set_threshold(COLLECTION_DEFERRED, *threshold[1:])
    try:
        descend()
    finally:
        gc.set_threshold(*threshold)


def test_without_the_pause_the_collector_finalizes_a_dead_loop_at_the_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove the instrument: unpaused, the reproduction really raises inside the finalizer.

    The unraisable exception is caught here rather than by pytest's own hook, so this test
    observes the failure instead of being failed by it. A reproduction that stopped reaching
    the limit would make the test below pass by vacuum; this one would fail instead.
    """
    seen: list[sys.UnraisableHookArgs] = []
    monkeypatch.setattr(sys, "unraisablehook", seen.append)

    collection_one_frame_short_of_the_limit()

    assert [type(hook.exc_value) for hook in seen] == [RecursionError]
    finalizer = seen[0].object
    assert getattr(finalizer, "__qualname__", None) == "BaseEventLoop.__del__"


@pytest.mark.reaches_recursion_limit
def test_with_the_pause_a_dead_loop_waits_for_a_shallow_collection() -> None:
    """The same descent under the marker: nothing is finalized at the limit, so pytest's hook
    sees no unraisable exception, and the loop is collected when the pause ends."""
    collection_one_frame_short_of_the_limit()


def test_the_pause_restores_the_collector_and_finalizes_what_it_deferred() -> None:
    finalized: list[str] = []

    class Garbage:
        cycle: object = None

        def __del__(self) -> None:
            finalized.append("finalized")

    with collector_paused():
        assert not gc.isenabled()
        garbage = Garbage()
        garbage.cycle = garbage
        del garbage
        assert finalized == []

    assert gc.isenabled()
    assert finalized == ["finalized"]
