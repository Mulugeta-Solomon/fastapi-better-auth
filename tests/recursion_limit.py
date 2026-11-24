"""The one way a test in this suite goes to the interpreter's recursion limit.

Some tests drive a parser to the limit on purpose: a nested-JSON bomb, the deepest token
header or key-set body a size cap admits. While the stack is that deep, nothing else may run
Python code. The cyclic garbage collector would: an automatic collection at that moment
finalizes whatever unrelated garbage is waiting, and this suite always has some (starlette's
`TestClient` leaves each dead event loop in a reference cycle). A finalizer that makes one
more call raises `RecursionError`. Python reports it as an unraisable exception, and pytest,
with warnings as errors, fails whichever test is running.

On Python 3.10 and 3.11, `json`'s C scanner counts against the same limit as Python frames,
so a finalizer can run out of room at the scanner's deepest point. On 3.12+ the scanner has a
limit of its own. The pause costs nothing there, so it is applied everywhere.

Use `collector_paused()` around code that reaches the limit, or mark a test with
`@pytest.mark.reaches_recursion_limit` (the fixture in `conftest.py` applies it).
`tests/test_recursion_limit.py` reproduces the failure deterministically and proves the pause.
"""

from __future__ import annotations

import gc
from collections.abc import Generator
from contextlib import contextmanager

REACHES_RECURSION_LIMIT = "reaches_recursion_limit"
"""The marker name; registered in `conftest.py`."""


@contextmanager
def collector_paused() -> Generator[None, None, None]:
    """Run the body with no automatic garbage collection, then collect at a shallow depth.

    Collecting first gives garbage left by earlier tests a chance to be finalized now, when it
    has the whole stack. Collecting afterwards does the same for garbage the body made, so it is
    finalized here and not during a later test. An explicit `gc.collect()` inside the body still
    runs; only the automatic collections are paused.
    """
    was_enabled = gc.isenabled()
    gc.collect()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()
        gc.collect()
