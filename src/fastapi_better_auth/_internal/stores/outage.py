"""What a store lookup that could not complete tells an operator: once per kind, until one completes.

An under-granted role or a database gone away turns every request into the uniform 401, and the
refusal's `reason` reaches only a handler the deployment wrote - so the store warns itself (R47),
and so does `CookieVerifier` for a failure a store did not translate (R47a). Not once per request:
an outage fails every request, and a line per request would bury the log in exactly the event it
reports. The latch holds one entry per distinct failure kind and is emptied by the next lookup
that completes, so a second kind is still news and a recovered outage that comes back is announced
again. There is no clock in it on purpose: an outage that never ends is still one line. The kinds
one latch will report are capped too (`MAX_REPORTED_KINDS`), because a store can make every
failure a new kind, and "never floods" has to hold for any store.

A kind is the driver error's class name and its SQLSTATE - never its text. SQLAlchemy's
`DBAPIError.__str__` embeds the bound parameters, which for a session lookup is the raw token
(A1, D-160), and a driver's own message can repeat them; so neither `str(error)`, its `args`, nor
anything of `error.orig` beyond its class and one validated code ever leaves this module.
Reporting is best effort and never changes the answer: `report_once` raises nothing, whatever the
error, the store or a deployment's own logging configuration does.
"""

from __future__ import annotations

import enum
import re
import threading
from dataclasses import dataclass

from .diagnostics import lookup_failed, lookup_kinds_suppressed

MAX_REPORTED_KINDS = 8
"""The most distinct failure kinds one latch reports between two completed lookups."""

UNNAMED = "UnnamedError"
"""The class name a line carries when an exception's class name cannot be read as text."""

SQLSTATE = re.compile(r"[0-9A-Z]{5}")
SQLSTATE_ATTRIBUTES = ("sqlstate", "pgcode")
"""Where drivers put it: psycopg 3 and SQLAlchemy's asyncpg adapter set `sqlstate` on the error
`DBAPIError.orig` holds; psycopg2 and the same asyncpg adapter set `pgcode`. SQLite has none."""


@dataclass(frozen=True)
class FailureKind:
    """A lookup failure as an operator can act on it: which driver error, and which SQLSTATE."""

    driver_error: str
    sqlstate: str | None


class Admission(enum.Enum):
    """What one latch makes of a failure: a new kind to report, the one suppression notice, or
    nothing - a kind already reported, or anything after the cap was reached."""

    REPORT = "report"
    OVERFLOW = "overflow"
    SILENT = "silent"


def report_once(latch: OutageLatch, error: BaseException, marker: str) -> None:
    """Tell the operator about `error` if `latch` has not already; never raise.

    Both callers hand over the exception they are about to turn into the uniform refusal, and
    call this from inside their `except` - so anything raised here would replace that refusal and
    chain to an error that can carry the token. Nothing is: reporting may not change the answer.
    """
    try:
        kind = failure_kind(error)
        admission = latch.admit(kind)
        if admission is Admission.REPORT:
            lookup_failed(kind.driver_error, kind.sqlstate, marker)
        elif admission is Admission.OVERFLOW:
            lookup_kinds_suppressed(MAX_REPORTED_KINDS)
    except Exception:  # noqa: BLE001, S110 - best effort by ruling (R47a); the refusal must not change
        pass


def failure_kind(error: BaseException) -> FailureKind:
    """The kind of `error`, read off the driver's own exception where SQLAlchemy wrapped one.

    Everything read here is third-party code - a deployment's store, a driver - so every read is
    guarded, and what is kept is plain `str`, never a subclass whose methods could run later.
    """
    driver = _attribute(error, "orig")
    source = error if driver is None else driver
    return FailureKind(driver_error=_class_name(source), sqlstate=_sqlstate(source))


def _class_name(value: object) -> str:
    try:
        name: object = getattr(type(value), "__name__", None)
    except Exception:  # noqa: BLE001 - a metaclass can make the name itself raise
        return UNNAMED
    return str.__str__(name) if isinstance(name, str) else UNNAMED


def _sqlstate(driver: object) -> str | None:
    """A five-character SQLSTATE, or `None`: a driver attribute is still text from outside."""
    for name in SQLSTATE_ATTRIBUTES:
        value = _attribute(driver, name)
        if isinstance(value, str) and SQLSTATE.fullmatch(value):
            return str.__str__(value)
    return None


def _attribute(value: object, name: str) -> object:
    try:
        return getattr(value, name, None)
    except Exception:  # noqa: BLE001 - third-party code; an attribute that raises carries nothing
        return None


class OutageLatch:
    """The failure kinds one store (or one verifier lookup) has reported since its last success.

    Locked because `SyncStoreAdapter` reports from worker threads while its lookups complete on
    the event loop.
    """

    __slots__ = ("_lock", "_overflowed", "_reported")

    def __init__(self) -> None:
        self._reported: set[FailureKind] = set()
        self._overflowed = False
        self._lock = threading.Lock()

    def admit(self, kind: FailureKind) -> Admission:
        """Whether `kind` is news: new and within the cap, the first kind past it, or neither."""
        with self._lock:
            if self._overflowed or kind in self._reported:
                return Admission.SILENT
            if len(self._reported) >= MAX_REPORTED_KINDS:
                self._overflowed = True
                return Admission.OVERFLOW
            self._reported.add(kind)
            return Admission.REPORT

    def rearm(self) -> None:
        """A lookup completed: every kind is news again the next time it happens."""
        if not self._reported:
            return
        with self._lock:
            self._reported.clear()
            self._overflowed = False
