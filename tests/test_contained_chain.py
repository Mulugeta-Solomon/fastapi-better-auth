"""The uniform 401 for an exception that escaped a verifier carries nothing behind it.

The dispatcher contains whatever a verifier's `extract` or `verify` lets out - answering the
uniform `InvalidCredential` rather than a 500 - and it raised that answer with `from None` *inside*
the `except`. `from None` clears `__cause__` and hides the chain from a default traceback, but
Python still records `__context__`, so the 401 kept the verifier's own exception one attribute
away: here, as in the fake `RaisingVerifyVerifier`, an exception whose message quotes the
credential it failed on. `traceback` and Sentry honour `__suppress_context__`; anything that walks
`__context__` does not. The answer is now decided inside the handler - where `_contained` still
logs the accident with its traceback (D-066) - and raised after it.

Driven through a real application for an escaping `extract` and an escaping `verify`, raised bare
and as the single leaf of a group, on both backends; plus the honoured answers the same code path
hands back - a `SessionError` a verifier raised inside a group, and a `ConfigurationError` from
`extract` - which must leave with no chain either. Assertions are bool-first, so a failure never
prints the chained exception.
"""

from __future__ import annotations

import logging
import traceback
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from exceptiongroup import ExceptionGroup
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exception_handlers import http_exception_handler
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    BetterAuth,
    ConfigurationError,
    InvalidCredential,
    SessionError,
    SessionRevoked,
)
from tests.fakes import UserModelT, client, connection, resolver_of, session_app
from tests.log_hygiene import LIBRARY_LOGGER, capturing

HEADER = "x-escaping"
CREDENTIAL = "tok-escaping-9f3ab21c-credential"
ACCIDENT = "the jwt library failed on"
WHERE = ("extract", "verify")
DELIVERIES: dict[str, Callable[[Exception], Exception]] = {
    "bare": lambda raised: raised,
    "single-leaf-group": lambda raised: ExceptionGroup("one", [raised]),
}


class EscapingVerifier:
    """Lets a third-party error out of `extract` or `verify`, quoting the credential - the shape
    of the documented boundary: the verifier's own message is its author's leak, but the chain
    this library hangs on its 401 must not carry it any further."""

    credential_source = f"header:{HEADER}"

    def __init__(self, where: str, deliver: Callable[[Exception], Exception]) -> None:
        self.where = where
        self.deliver = deliver

    def extract(self, connection: HTTPConnection) -> str | None:
        credential = connection.headers.get(HEADER)
        if self.where == "extract" and credential is not None:
            raise self.deliver(RuntimeError(f"{ACCIDENT} {credential}"))
        return credential

    async def verify(self, credential: str, user_model: type[UserModelT]) -> Any:
        raise self.deliver(RuntimeError(f"{ACCIDENT} {credential}"))


class AnsweringVerifier(EscapingVerifier):
    """Raises an answer rather than an accident: one the dispatcher honours as itself."""

    def __init__(self, where: str, answer: Callable[[], Exception]) -> None:
        super().__init__(where, lambda _raised: ExceptionGroup("one", [answer()]))


def observing(app: FastAPI) -> list[HTTPException]:
    observed: list[HTTPException] = []

    async def record(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, HTTPException)
        observed.append(exc)
        return await http_exception_handler(request, exc)

    app.add_exception_handler(SessionError, record)
    return observed


def chained(exc: BaseException) -> bool:
    return exc.__context__ is not None or exc.__cause__ is not None


def logged_with_traceback(records: list[logging.LogRecord], where: str) -> bool:
    """Whether the one escape line was written with the accident's traceback.

    A bool, so no test frame keeps the accident - whose message quotes the credential - as a
    local that `pytest -l` would print on failure.
    """
    logged = [r for r in records if r.name == LIBRARY_LOGGER and r.exc_info is not None]
    if [r.getMessage() for r in logged] != [f"EscapingVerifier.{where} raised"]:
        return False
    exc_info = logged[0].exc_info
    return exc_info is not None and ACCIDENT in "".join(traceback.format_exception(*exc_info))


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


@pytest.mark.parametrize("where", WHERE)
@pytest.mark.parametrize("delivery", list(DELIVERIES))
def test_the_uniform_401_for_an_escaped_verifier_carries_no_chain(
    where: str, delivery: str, client_backend: str, records: list[logging.LogRecord]
) -> None:
    auth = BetterAuth(verifiers=[EscapingVerifier(where, DELIVERIES[delivery])])
    app = session_app(auth)
    observed = observing(app)

    with client(app, client_backend) as http:
        response = http.get("/required", headers={HEADER: CREDENTIAL})

    assert response.status_code == 401
    assert [type(exc) for exc in observed] == [InvalidCredential]
    assert not chained(observed[0]), "the 401 carries the verifier's exception on its chain"
    assert logged_with_traceback(records, where), "the operator lost the real exception (D-066)"


def test_a_session_error_a_verifier_raised_inside_a_group_leaves_with_no_chain(
    client_backend: str,
) -> None:
    """Honoured, so it answers as itself - and the group it arrived in stays behind."""
    answer = AnsweringVerifier("verify", lambda: SessionRevoked(reason="gone upstream"))
    app = session_app(BetterAuth(verifiers=[answer]))
    observed = observing(app)

    with client(app, client_backend) as http:
        response = http.get("/required", headers={HEADER: CREDENTIAL})

    assert response.status_code == 401
    assert [type(exc) for exc in observed] == [SessionRevoked]
    assert not chained(observed[0]), "the honoured answer carries the group on its chain"


@pytest.mark.anyio
async def test_a_configuration_error_extract_raised_inside_a_group_leaves_with_no_chain() -> None:
    """`extract` honours only `BetterAuthError`: a broken deployment stays loud, and unchained."""
    answer = AnsweringVerifier("extract", lambda: ConfigurationError("the verifier is misbuilt"))
    resolve = resolver_of(BetterAuth(verifiers=[answer]).current_session())

    with pytest.raises(ConfigurationError) as caught:
        await resolve(connection(x_escaping=CREDENTIAL))

    assert not chained(caught.value), "the honoured answer carries the group on its chain"
