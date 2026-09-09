"""What an `anyio` task group does to an exception on its way out, and how to undo it."""

from __future__ import annotations

import sys

if sys.version_info >= (3, 11):  # pragma: no cover - one branch per interpreter
    from builtins import BaseExceptionGroup
else:  # pragma: no cover - one branch per interpreter
    from exceptiongroup import BaseExceptionGroup

GROUP_TYPES: tuple[type[BaseException], ...] = (BaseExceptionGroup,)


def unwrapped(exc: BaseException) -> BaseException:
    """A task group with one failing child delivers a group whose single leaf is the answer.

    `anyio` task groups are the concurrency tool this library mandates, and a group whose leaves
    are all `Exception` is itself an `Exception` - so a deliberate refusal raised inside one
    arrives at every caller as something that is not the class it was raised as. A single-leaf
    group is that leaf; a group with more than one leaf is nobody's single answer and is handed
    back untouched, to be contained rather than guessed at.
    """
    leaf = exc
    while isinstance(leaf, GROUP_TYPES):
        nested: tuple[BaseException, ...] = getattr(leaf, "exceptions", ())
        if len(nested) != 1:
            break
        leaf = nested[0]
    return leaf
