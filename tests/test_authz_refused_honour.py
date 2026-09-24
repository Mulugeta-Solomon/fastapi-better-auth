"""An `AuthorizationRefused` is judged again when it leaves the rule, not only when it is built.

The constructor refuses an honest mistake early and clearly, but an exception is a mutable object:
`exc.headers["WWW-Authenticate"] = ...`, `exc.status_code = 401` or a reassigned `exc.headers`
after construction would otherwise ride the honoured path straight to the wire. So the gate checks
the refusal as it leaves the rule, with the same predicate the constructor uses: a plain `int`
403 or 404, and headers that are `None` or exactly a plain `dict` of plain `str` to plain `str`,
naming no challenge, every name an RFC 9110 token and every value only tabs, spaces and visible
US-ASCII. The headers are read once, and that read — a fresh plain `dict` — is what is written, so
a mapping that answers differently the second time cannot smuggle anything past the check.
Anything else is an accident — logged with the class and the broken invariant, never a header
value and never the `detail`, and answered as the uniform `NotAuthorized`.

Every refusal here is built *valid* and tampered with afterwards, so none of these cases can be
caught by the constructor: what catches them is the check at the honour point, or nothing.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, ItemsView, Iterator, Mapping
from types import MappingProxyType
from typing import Any

import pytest
from exceptiongroup import ExceptionGroup

from fastapi_better_auth import AuthorizationRefused, NotAuthorized, Session
from fastapi_better_auth._internal.authz import permitted
from tests.fakes import GOOD_CREDENTIAL, client
from tests.log_hygiene import LIBRARY_LOGGER, capturing, rendered
from tests.test_authz import FORBIDDEN, HEADER, Member, one_verifier
from tests.test_authz_refused import (
    PREDICATE,
    URL,
    WHERE,
    EqualToEverything,
    HeaderText,
    gated,
    raising_app,
    recording,
)

HEADER_VALUE = "Bearer realm=tampered-9f3ab21c"
DETAIL_MARKER = "detail-marker-7c1de90f"
STATUS = "status_code"
CHALLENGE = "WWW-Authenticate"
NOT_TEXT = "of str to str"
NOT_FIELD = "RFC 9110"
SPLIT = f"a\r\nWWW-Authenticate: {HEADER_VALUE}"
OBS_TEXT = (0x80, 0x85, 0xE9, 0xFF)
"""The obs-text octets the round-3 ruling names: the range's ends, NEL, and a letter with an accent."""

Tamper = Callable[[Any], None]


class Tampered(AuthorizationRefused):
    """A refusal built valid: a sound status, a sound header, and a `detail` the log must not see."""

    def __init__(self) -> None:
        super().__init__(detail={"marker": DETAIL_MARKER}, headers={"X-Tag": "sound"})


class LiesOnSecondRead(Mapping[str, str]):
    """Clean the first time it is read, a challenge every time after: the #76 round-2 repro."""

    def __init__(self) -> None:
        self.reads = 0

    def _current(self) -> dict[str, str]:
        self.reads += 1
        return {"X-Tag": "sound"} if self.reads == 1 else {"WWW-Authenticate": HEADER_VALUE}

    def items(self) -> ItemsView[str, str]:
        return self._current().items()

    def __getitem__(self, key: str) -> str:
        return self._current()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._current())

    def __len__(self) -> int:
        return len(self._current())


class DictThatLiesOnSecondRead(dict[str, str]):
    """The same lie from a `dict` subclass: `isinstance(..., dict)` is not "a plain dict"."""

    def __init__(self) -> None:
        super().__init__({"X-Tag": "sound"})
        self.reads = 0

    def items(self) -> Any:
        self.reads += 1
        return (dict(self) if self.reads == 1 else {"WWW-Authenticate": HEADER_VALUE}).items()


class UnreadableHeaders(Mapping[str, str]):
    """A mapping that cannot be read: the check must answer it, not crash on it."""

    def __getitem__(self, key: str) -> str:
        raise RuntimeError("these headers cannot be read")

    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("these headers cannot be read")

    def __len__(self) -> int:
        return 1


def setting(attribute: str, value: object) -> Tamper:
    def tamper(refusal: Any) -> None:
        setattr(refusal, attribute, value)

    return tamper


def adding(name: str, value: str = HEADER_VALUE) -> Tamper:
    def tamper(refusal: Any) -> None:
        refusal.headers[name] = value

    return tamper


def reading_twice(make: Callable[[], object]) -> Tamper:
    """Assign a lying mapping built fresh for this request, so no read is shared across legs."""

    def tamper(refusal: Any) -> None:
        refusal.headers = make()

    return tamper


BROKEN: dict[str, tuple[Tamper, str]] = {
    "added-challenge": (adding("WWW-Authenticate"), CHALLENGE),
    "added-padded-challenge": (adding(" www-authenticate"), CHALLENGE),
    "status-401": (setting("status_code", 401), STATUS),
    "status-500": (setting("status_code", 500), STATUS),
    "status-true": (setting("status_code", True), STATUS),
    "status-lying-int": (setting("status_code", EqualToEverything(403)), STATUS),
    "status-text": (setting("status_code", "403"), STATUS),
    "reassigned-challenge": (setting("headers", {"WWW-Authenticate": HEADER_VALUE}), CHALLENGE),
    "reassigned-bytes-name": (setting("headers", {b"X-Tag": HEADER_VALUE}), NOT_TEXT),
    "reassigned-int-value": (setting("headers", {"X-Tag": 403}), NOT_TEXT),
    "reassigned-str-subclass": (setting("headers", {HeaderText("X-Tag"): HEADER_VALUE}), NOT_TEXT),
    "reassigned-pairs": (setting("headers", [("X-Tag", HEADER_VALUE)]), NOT_TEXT),
    "reassigned-unreadable": (setting("headers", UnreadableHeaders()), NOT_TEXT),
    "reassigned-lying-mapping": (reading_twice(LiesOnSecondRead), NOT_TEXT),
    "reassigned-lying-dict-subclass": (reading_twice(DictThatLiesOnSecondRead), NOT_TEXT),
    "reassigned-read-only-mapping": (
        setting("headers", MappingProxyType({"X-Tag": "proxy"})),
        NOT_TEXT,
    ),
    "added-split-value": (adding("X-Tag", SPLIT), NOT_FIELD),
    "reassigned-split-value": (setting("headers", {"X-Tag": SPLIT}), NOT_FIELD),
    "reassigned-nul-value": (setting("headers", {"X-Tag": f"{HEADER_VALUE}\x00"}), NOT_FIELD),
    "reassigned-non-token-name": (setting("headers", {"X Tag": HEADER_VALUE}), NOT_FIELD),
    **{
        f"reassigned-obs-text-{code:02x}": (
            setting("headers", {"X-Tag": f"a{chr(code)}b"}),
            NOT_FIELD,
        )
        for code in OBS_TEXT
    },
}

SOUND: dict[str, tuple[Tamper, int, dict[str, str]]] = {
    "added-sound-header": (adding("X-Other"), 403, {"x-tag": "sound", "x-other": HEADER_VALUE}),
    "status-404": (setting("status_code", 404), 404, {"x-tag": "sound"}),
    "reassigned-plain-dict": (setting("headers", {"X-Tag": "plain"}), 403, {"x-tag": "plain"}),
    "added-tab-and-space": (adding("X-Other", "a\tb c"), 403, {"x-tag": "sound"}),
}


def tampered(tamper: Tamper) -> Callable[[], BaseException]:
    def make() -> BaseException:
        refusal = Tampered()
        tamper(refusal)
        return refusal

    return make


def library(records: list[logging.LogRecord]) -> list[logging.LogRecord]:
    return [record for record in records if record.name == LIBRARY_LOGGER]


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


@pytest.mark.parametrize("where", WHERE)
@pytest.mark.parametrize("case", list(BROKEN), ids=list(BROKEN))
def test_a_refusal_broken_after_construction_is_contained_and_logged(
    where: str, case: str, client_backend: str, records: list[logging.LogRecord]
) -> None:
    tamper, invariant = BROKEN[case]
    _verifier, auth = one_verifier()
    app = raising_app(where, auth, tampered(tamper), [])
    observed = recording(app)

    with client(app, client_backend) as http:
        response = http.get(URL[where], headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == 403
    assert response.json() == FORBIDDEN
    assert "www-authenticate" not in response.headers
    assert [type(exc) for exc in observed] == [NotAuthorized]
    assert "Tampered" in observed[0].reason
    assert invariant in observed[0].reason
    logged = library(records)
    assert [record.levelno for record in logged] == [logging.ERROR]
    assert logged[0].exc_info is None, "a traceback would render str(exc), which is the detail"
    assert "Tampered" in logged[0].getMessage()
    assert invariant in logged[0].getMessage()
    written = rendered(records)
    assert HEADER_VALUE not in written, "a header value reached the log"
    assert DETAIL_MARKER not in written, "the detail reached the log"


@pytest.mark.parametrize("case", list(SOUND), ids=list(SOUND))
def test_a_refusal_edited_within_its_rules_is_still_honoured(
    case: str, client_backend: str, records: list[logging.LogRecord]
) -> None:
    """The check is the invariants, not "was it touched": a sound edit is still an answer."""
    tamper, status, headers = SOUND[case]
    _verifier, auth = one_verifier()
    app = raising_app(PREDICATE, auth, tampered(tamper), [])

    with client(app, client_backend) as http:
        response = http.get(URL[PREDICATE], headers={HEADER: GOOD_CREDENTIAL})

    assert response.status_code == status
    assert response.json() == {"detail": {"marker": DETAIL_MARKER}}
    assert {name: response.headers[name] for name in headers} == headers
    assert library(records) == []


def test_a_broken_refusal_delivered_as_a_single_leaf_group_is_contained(
    client_backend: str, records: list[logging.LogRecord]
) -> None:
    """A group's single leaf is judged by the same check: there is one honour point, not two."""
    _verifier, auth = one_verifier()

    def wrapped(_session: Session[Member]) -> bool:
        refusal = Tampered()
        refusal.headers = {"WWW-Authenticate": HEADER_VALUE}
        raise ExceptionGroup("one", [refusal])

    app = gated(auth, wrapped, [])
    observed = recording(app)
    with client(app, client_backend) as http:
        response = http.get(URL[PREDICATE], headers={HEADER: GOOD_CREDENTIAL})

    assert response.json() == FORBIDDEN
    assert "www-authenticate" not in response.headers
    assert [type(exc) for exc in observed] == [NotAuthorized]
    assert [record.levelno for record in library(records)] == [logging.ERROR]


def test_an_honoured_refusal_leaves_with_the_very_headers_it_was_judged_by() -> None:
    """The check reads the headers once, and what is rendered must be that read rather than the
    object it was read from: the gate hands on a fresh plain dict of the pairs it judged."""
    reassigned = {"X-Tag": "reassigned"}
    session = Session[Member](user=Member(id="u1"), expires_at=None, raw={"id": "u1"})

    def refuse(_session: Session[Member]) -> bool:
        refusal = Tampered()
        refusal.headers = reassigned
        raise refusal

    with pytest.raises(AuthorizationRefused) as caught:
        permitted(refuse, session)

    kept = caught.value.headers
    assert kept == {"X-Tag": "reassigned"}
    assert kept is not reassigned
    assert type(kept) is dict
