"""A `now=` seam on the wire: moved forward it refuses, and broken it fails closed.

R51 adds no refusal type for a broken seam. One that raises, or returns anything but an aware
`datetime`, escapes `verify` as an ordinary exception, and the dispatcher's existing containment
answers it as it answers any verifier's accident (D-066): the uniform 401, with the real exception
logged at ERROR with its traceback. Driven through a real application for both verifiers on both
backends, with the credential nowhere in the log, the reason, the chain, or the frames the logged
traceback keeps. A non-callable `now` never gets this far: construction refuses it
(`test_refusal_clock.py`).

Assertions are bool-first and the helpers return names, never values, so a failure here cannot
print the credential; the cookie and the get-session body are built inline for the same reason.
"""

from __future__ import annotations

import logging
import traceback
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any

import httpx2
import pytest
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exception_handlers import http_exception_handler

from fastapi_better_auth import BetterAuth, InvalidCredential, SessionError
from tests import cookies, remote_fixtures
from tests.fakes import client, session_app
from tests.log_hygiene import LIBRARY_LOGGER, capturing
from tests.refusal_frames import holding
from tests.transports import json_reply
from tests.wall_clock import wire

UNIFORM = {"detail": "Not authenticated"}
LIFETIME = timedelta(minutes=30)
PAST_THE_CAP = timedelta(minutes=31)

COOKIE_SIGNED = cookies.sign(cookies.CAPTURED_TOKEN)
NEEDLES = {
    "CookieVerifier": {
        "token": cookies.CAPTURED_TOKEN,
        "cookie": COOKIE_SIGNED,
        "signature": COOKIE_SIGNED.rpartition(".")[2],
    },
    "RemoteVerifier": {
        "token": remote_fixtures.TOKEN,
        "cookie": remote_fixtures.COOKIE_VALUE,
        "signature": remote_fixtures.COOKIE_VALUE.rpartition(".")[2],
    },
}
"""What must never leak, per verifier. Module constants, which `pytest -l` never renders."""


class SeamBroke(RuntimeError):
    """What a test clock that raises raises: a type the log must name."""


def raising() -> datetime:
    raise SeamBroke("the test clock broke")


BROKEN: dict[str, tuple[Callable[[], Any], type[Exception]]] = {
    "raises": (raising, SeamBroke),
    "naive": (lambda: datetime.now(timezone.utc).replace(tzinfo=None), TypeError),
    "none": (lambda: None, TypeError),
    "date": (lambda: date(2026, 6, 1), TypeError),
    "str": (lambda: "2026-06-01T12:00:00.000Z", TypeError),
}


class MovableClock:
    """A seam that follows the real clock, `ahead` of it."""

    def __init__(self) -> None:
        self.ahead = timedelta()

    def __call__(self) -> datetime:
        return datetime.now(timezone.utc) + self.ahead


@dataclass
class Deployment:
    """One verifier behind a real app: who it is, what it holds, and what must never leak."""

    owner: str
    app: FastAPI
    held: list[object] = field(repr=False)
    needles: dict[str, str] = field(repr=False)
    observed: list[HTTPException]

    def request(self, backend: str) -> httpx2.Response:
        with client(self.app, backend) as http:
            return http.get("/required", headers={"cookie": self._cookie()})

    def _cookie(self) -> str:
        if self.owner == "CookieVerifier":
            return f"{cookies.COOKIE}={COOKIE_SIGNED}"
        return f"{remote_fixtures.COOKIE_NAME}={remote_fixtures.COOKIE_VALUE}"


def observing(app: FastAPI, observed: list[HTTPException]) -> None:
    async def record(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, HTTPException)
        observed.append(exc)
        return await http_exception_handler(request, exc)

    app.add_exception_handler(SessionError, record)


def deployed(mode: str, now: Callable[[], Any]) -> Deployment:
    """A live session, a verifier reading it through `now`, and the app that dispatches to it."""
    expires_at = datetime.now(timezone.utc) + LIFETIME
    if mode == "cookie":
        record = cookies.stored_session(cookies.CAPTURED_TOKEN, expires_at=expires_at)
        store = cookies.FakeStore(sessions={cookies.CAPTURED_TOKEN: record})
        auth = BetterAuth(verifiers=[cookies.verifier(store=store, now=now)])
        deployment = Deployment(
            "CookieVerifier", session_app(auth), [store], NEEDLES["CookieVerifier"], []
        )
    else:
        upstream = remote_fixtures.RecordingTransport(
            json_reply(remote_fixtures.document(expires=wire(expires_at)))
        )
        auth = BetterAuth(verifiers=[remote_fixtures.verifier(upstream, now=now)])
        deployment = Deployment(
            "RemoteVerifier", session_app(auth), [upstream], NEEDLES["RemoteVerifier"], []
        )
    observing(deployment.app, deployment.observed)
    return deployment


# ---------------------------------------------------------------- the instruments


def escapes(records: list[logging.LogRecord]) -> list[tuple[str, str]]:
    """Every library ERROR carrying a traceback, as (message, exception type name)."""
    return [
        (record.getMessage(), record.exc_info[0].__name__)
        for record in records
        if record.name == LIBRARY_LOGGER
        and record.levelno == logging.ERROR
        and record.exc_info is not None
        and record.exc_info[0] is not None
    ]


def escaped(records: list[logging.LogRecord]) -> BaseException:
    [exc] = [
        record.exc_info[1]
        for record in records
        if record.exc_info is not None and record.exc_info[1] is not None
    ]
    return exc


def rendered(records: list[logging.LogRecord]) -> str:
    """What a handler would write: every message, and every traceback in full."""
    parts: list[str] = []
    for record in records:
        parts.append(record.getMessage())
        if record.exc_info is not None and record.exc_info[0] is not None:
            parts.append("".join(traceback.format_exception(*record.exc_info)))
    return "\n".join(parts)


def leaked_into(text: str, needles: dict[str, str]) -> list[str]:
    """Which credential parts `text` carries, by name."""
    return sorted(name for name, needle in needles.items() if needle in text)


def held_in_frames(exc: BaseException, deployment: Deployment) -> list[str]:
    """Every `file:function.local` on the escaped traceback carrying any credential part."""
    return sorted(
        {
            where
            for needle in deployment.needles.values()
            for where in holding(exc, needle, ignore=deployment.held)
        }
    )


def chained(exc: BaseException) -> bool:
    return exc.__cause__ is not None or exc.__context__ is not None


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


# ---------------------------------------------------------------- a broken seam


@pytest.mark.parametrize("kind", list(BROKEN))
@pytest.mark.parametrize("mode", ["cookie", "remote"])
def test_a_broken_seam_is_the_uniform_401_and_one_error_naming_its_type(
    mode: str, kind: str, client_backend: str, records: list[logging.LogRecord]
) -> None:
    seam, expected = BROKEN[kind]
    deployment = deployed(mode, seam)

    response = deployment.request(client_backend)

    assert response.status_code == 401
    assert response.json() == UNIFORM
    assert response.headers["www-authenticate"] == "Bearer"
    assert escapes(records) == [(f"{deployment.owner}.verify raised", expected.__name__)]
    assert expected.__name__ in rendered(records), "the log does not name the exception's type"
    assert [type(exc) for exc in deployment.observed] == [InvalidCredential]
    reason = getattr(deployment.observed[0], "reason", "")
    assert reason == f"{expected.__name__} escaped {deployment.owner}.verify"


@pytest.mark.parametrize("kind", list(BROKEN))
@pytest.mark.parametrize("mode", ["cookie", "remote"])
def test_a_broken_seam_leaks_nothing_and_chains_nothing(
    mode: str, kind: str, client_backend: str, records: list[logging.LogRecord]
) -> None:
    seam, expected = BROKEN[kind]
    deployment = deployed(mode, seam)

    status = deployment.request(client_backend).status_code

    assert (status, len(deployment.observed)) == (401, 1), "the broken seam was never read"
    assert escapes(records) == [(f"{deployment.owner}.verify raised", expected.__name__)]
    assert leaked_into(rendered(records), deployment.needles) == []
    assert leaked_into(str(getattr(deployment.observed[0], "reason", "")), deployment.needles) == []
    assert leaked_into(repr(deployment.observed[0]), deployment.needles) == []
    assert not chained(deployment.observed[0]), "the 401 carries the escaped exception"
    assert not chained(escaped(records)), "the escaped exception carries a chain"
    assert held_in_frames(escaped(records), deployment) == []


@pytest.mark.parametrize("mode", ["cookie", "remote"])
def test_the_type_error_says_what_the_seam_returned_and_what_it_must(
    mode: str, client_backend: str, records: list[logging.LogRecord]
) -> None:
    deployment = deployed(mode, BROKEN["naive"][0])

    deployment.request(client_backend)

    assert escapes(records) == [(f"{deployment.owner}.verify raised", "TypeError")]
    message = str(escaped(records))
    assert f"{deployment.owner}(now=...)" in message
    assert "naive" in message
    assert "aware datetime" in message


# ---------------------------------------------------------------- a working seam


@pytest.mark.parametrize("mode", ["cookie", "remote"])
def test_a_seam_moved_past_the_cap_turns_a_200_into_a_401(
    mode: str, client_backend: str, records: list[logging.LogRecord]
) -> None:
    """#82 on the wire: a thirty-minute session, served, then refused once `now` is 31 min on."""
    clock = MovableClock()
    deployment = deployed(mode, clock)

    served = deployment.request(client_backend)
    clock.ahead = PAST_THE_CAP
    refused = deployment.request(client_backend)
    clock.ahead = timedelta()
    served_again = deployment.request(client_backend)

    assert (served.status_code, refused.status_code, served_again.status_code) == (200, 401, 200)
    assert refused.json() == UNIFORM
    assert [type(exc).__name__ for exc in deployment.observed] == ["SessionExpired"]
    assert escapes(records) == [], "an expiry is a refusal, not an escaped exception"
