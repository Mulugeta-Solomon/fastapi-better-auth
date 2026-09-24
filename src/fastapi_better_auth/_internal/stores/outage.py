"""What a SQL store tells an operator about a failing lookup: once per kind, until one completes.

An under-granted role or a database gone away turns every request into the uniform 401, and the
refusal's `reason` reaches only a handler the deployment wrote - so the store warns itself (R47).
Not once per request: an outage fails every request, and a line per request would bury the log in
exactly the event it reports. The latch holds one entry per distinct failure kind and is emptied
by the next lookup that completes, so a second kind is still news and a recovered outage that
comes back is announced again. There is no clock in it on purpose: an outage that never ends is
still one line.

A kind is the driver error's class name and its SQLSTATE - never its text. SQLAlchemy's
`DBAPIError.__str__` embeds the bound parameters, which for a session lookup is the raw token
(A1, D-160), and a driver's own message can repeat them; so neither `str(error)`, its `args`, nor
anything of `error.orig` beyond its class and one validated code ever leaves this module.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass

SQLSTATE = re.compile(r"[0-9A-Z]{5}")
SQLSTATE_ATTRIBUTES = ("sqlstate", "pgcode")
"""Where drivers put it: psycopg 3 and SQLAlchemy's asyncpg adapter set `sqlstate` on the error
`DBAPIError.orig` holds; psycopg2 and the same asyncpg adapter set `pgcode`. SQLite has none."""


@dataclass(frozen=True)
class FailureKind:
    """A lookup failure as an operator can act on it: which driver error, and which SQLSTATE."""

    driver_error: str
    sqlstate: str | None


def failure_kind(error: BaseException) -> FailureKind:
    """The kind of `error`, read off the driver's own exception where SQLAlchemy wrapped one.

    Never raises: the verifier reads this off whatever a deployment's own store threw, and an
    attribute that raises while it is read must not replace the refusal being built.
    """
    driver = _attribute(error, "orig")
    source = error if driver is None else driver
    return FailureKind(driver_error=type(source).__name__, sqlstate=_sqlstate(source))


def _sqlstate(driver: object) -> str | None:
    """A five-character SQLSTATE, or `None`: a driver attribute is still text from outside."""
    for name in SQLSTATE_ATTRIBUTES:
        value = _attribute(driver, name)
        if isinstance(value, str) and SQLSTATE.fullmatch(value):
            return value
    return None


def _attribute(value: object, name: str) -> object:
    try:
        return getattr(value, name, None)
    except Exception:  # noqa: BLE001 - third-party code; an attribute that raises carries nothing
        return None


class OutageLatch:
    """The failure kinds one store has already reported since its last completed lookup.

    Locked because `SyncStoreAdapter` reports from worker threads while its lookups complete on
    the event loop.
    """

    __slots__ = ("_lock", "_reported")

    def __init__(self) -> None:
        self._reported: set[FailureKind] = set()
        self._lock = threading.Lock()

    def first(self, kind: FailureKind) -> bool:
        """Whether this is the first failure of `kind` since the last completed lookup."""
        with self._lock:
            if kind in self._reported:
                return False
            self._reported.add(kind)
            return True

    def rearm(self) -> None:
        """A lookup completed: every kind is news again the next time it happens."""
        if not self._reported:
            return
        with self._lock:
            self._reported.clear()
