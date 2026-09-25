"""No exception the gate raises carries the rule's own exception behind it.

`raise X from None` inside an `except` clears `__cause__` and hides the chain from a default
traceback, but Python still records `__context__` - so a uniform `NotAuthorized` raised inside the
handler kept the rule's exception one attribute away: a refusal broken after construction, with
its `detail` and its header values, or an accident with whatever its message quotes. Anything that
walks the chain without honouring `__suppress_context__` - a reporter, a debugging handler - would
read it. The gate now decides the failure inside the handler, where `_contained` still logs the
accident with its traceback (D-066), and raises it after the handler has closed.

Driven for every shape the gate raises - a broken refusal answered as `NotAuthorized`, a contained
accident, a refusal honoured as itself - from a predicate and from a lookup, raised bare and as the
single leaf of a group, on both backends. The assertions are bool-first on purpose: a failing
`assert exc.__context__ is None` would print the chained refusal, `detail` and all.
"""

from __future__ import annotations

import logging
import traceback
from collections.abc import Callable, Iterator

import pytest
from exceptiongroup import ExceptionGroup
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exception_handlers import http_exception_handler

from fastapi_better_auth import AuthorizationRefused, NotAuthorized, SessionError
from tests.fakes import GOOD_CREDENTIAL, client
from tests.log_hygiene import LIBRARY_LOGGER, capturing
from tests.test_authz import HEADER, one_verifier
from tests.test_authz_refused import CONTAINED_AS, URL, WHERE, raising_app

HEADER_VALUE = "Bearer realm=chained-9f3ab21c"
DETAIL_MARKER = "detail-marker-5e2a61c0"
ACCIDENT = "the policy table said something private-7d41"


def broken() -> Exception:
    """A refusal built sound and then given the challenge: a breach, answered as NotAuthorized."""
    refusal = AuthorizationRefused(detail={"marker": DETAIL_MARKER}, headers={"X-Tag": "sound"})
    refusal.headers = {"X-Tag": "sound", "WWW-Authenticate": HEADER_VALUE}
    return refusal


def accident() -> Exception:
    return RuntimeError(ACCIDENT)


def honoured() -> Exception:
    return AuthorizationRefused(detail={"marker": DETAIL_MARKER}, headers={"X-Tag": "sound"})


SHAPES: dict[str, tuple[Callable[[], Exception], type[HTTPException]]] = {
    "breach": (broken, NotAuthorized),
    "accident": (accident, NotAuthorized),
    "honoured": (honoured, AuthorizationRefused),
}
DELIVERIES: dict[str, Callable[[Exception], Exception]] = {
    "bare": lambda raised: raised,
    "single-leaf-group": lambda raised: ExceptionGroup("one", [raised]),
}


def observing(app: FastAPI) -> list[HTTPException]:
    """Keep whatever the gate raised - the uniform refusal or the honoured one - then answer it."""
    observed: list[HTTPException] = []

    async def record(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, HTTPException)
        observed.append(exc)
        return await http_exception_handler(request, exc)

    app.add_exception_handler(SessionError, record)
    app.add_exception_handler(AuthorizationRefused, record)
    return observed


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


@pytest.mark.parametrize("where", WHERE)
@pytest.mark.parametrize("delivery", list(DELIVERIES))
@pytest.mark.parametrize("shape", list(SHAPES))
def test_the_exception_the_gate_raises_carries_no_chain(
    where: str, delivery: str, shape: str, client_backend: str
) -> None:
    make, expected = SHAPES[shape]
    wrap = DELIVERIES[delivery]
    _verifier, auth = one_verifier()
    app = raising_app(where, auth, lambda: wrap(make()), [])
    observed = observing(app)

    with capturing(), client(app, client_backend) as http:
        http.get(URL[where], headers={HEADER: GOOD_CREDENTIAL})

    assert [type(exc) for exc in observed] == [expected]
    has_cause = observed[0].__cause__ is not None
    has_context = observed[0].__context__ is not None
    assert not has_cause, "the raised exception carries a __cause__"
    assert not has_context, "the raised exception carries the rule's exception on __context__"


@pytest.mark.parametrize("where", WHERE)
@pytest.mark.parametrize("delivery", list(DELIVERIES))
def test_a_contained_accident_is_still_logged_with_its_traceback(
    where: str, delivery: str, client_backend: str, records: list[logging.LogRecord]
) -> None:
    """Raising outside the handler must not cost the operator the real exception: the decision,
    and with it `_contained`'s `logger.exception`, still happens while the accident is in hand."""
    wrap = DELIVERIES[delivery]
    _verifier, auth = one_verifier()
    app = raising_app(where, auth, lambda: wrap(accident()), [])

    with client(app, client_backend) as http:
        http.get(URL[where], headers={HEADER: GOOD_CREDENTIAL})

    logged = [r for r in records if r.name == LIBRARY_LOGGER and r.exc_info is not None]
    assert [r.getMessage() for r in logged] == [f"the {CONTAINED_AS[where]} raised"]
    exc_info = logged[0].exc_info
    assert exc_info is not None
    rendered_traceback = "".join(traceback.format_exception(*exc_info))
    assert ACCIDENT in rendered_traceback, "the operator lost the real exception"
