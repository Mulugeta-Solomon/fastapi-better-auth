"""The readiness probe's status classes: which answers are a contract verdict, which are an outage.

The probe asks get-session a question whose answer it knows - a bare request must answer `200` with
a literal `null` - and an upstream that answers something else for "no session" cannot be told
apart from one that says "session", so a wrong answer is remembered as a permanent configuration
failure. But some statuses are not an answer at all: `408`, `425`, `429` and every `5xx` mean the
upstream could not answer *right now* (restarting, overloaded, rate-limiting). Remembering one of
those as a contract verdict would turn a few seconds of upstream restart into an outage that lasts
until the Python process is restarted.

So this suite pins the split. A transient status fails the request that triggered the probe as
`AuthServiceUnavailable` (the uniform 401), is never remembered, and is re-probed on the same
retry window a timeout or refused connection already uses - one probe per window, whoever asks.
Everything else that is not `200 null` stays a remembered `ConfigurationError`. Throughout, no
request is verified while the contract is unproven.
"""

from __future__ import annotations

import logging
from typing import Any

import anyio
import pytest
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    AuthServiceUnavailable,
    ConfigurationError,
    CsrfDisabled,
    RemoteVerifier,
    Session,
    TransportResponse,
    User,
)
from fastapi_better_auth._internal import remote_probe
from fastapi_better_auth._internal.once import Once
from fastapi_better_auth._internal.remote_verifier import PROBE_RETRY_INTERVAL
from tests.transports import json_reply

pytestmark = pytest.mark.anyio

ORIGIN = "https://auth.example.com"
COOKIE_NAME = "better-auth.session_token"
TOKEN = "SBYZ1bzGdkhXcLuqsW70JjhvmIY4PU3B"
COOKIE_VALUE = f"{TOKEN}.c2lnbmF0dXJlLXRoYXQtaXMtNDQtY2hhcnMtbG9uZy1wYWRkZWQtb28"
FAR_FUTURE = "2999-01-01T00:00:00.000Z"
BODY_SENTINEL = b"UPSTREAM-BODY-SENTINEL-7f3a"
"""What every non-200 bare answer carries as its body, so a test can prove no line echoes it."""

TRANSIENT = [408, 425, 429, 500, 502, 503, 504, 599]
PERMANENT_STATUSES = [301, 302, 303, 307, 308, 400, 401, 403, 404, 405, 409, 410, 415, 418, 422]
HEALTHY = 200


def document() -> dict[str, Any]:
    return {
        "session": {"id": "s", "token": TOKEN, "userId": "u1", "expiresAt": FAR_FUTURE},
        "user": {"id": "u1", "email": "seed@example.com", "banned": False, "banExpires": None},
    }


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class StatusScript:
    """An upstream whose bare probe GET answers a scripted status sequence, then repeats the last.

    `200` in the script is the healthy answer, `200 null`; any other status comes back with
    `BODY_SENTINEL` as its body. The advisory bearer GET answers per `bearer` (healthy by default)
    and a cookie'd request - the real fetch - answers the session document. Each kind is counted
    on its own, so a test can tell "no probe ran" from "no request was verified".
    """

    def __init__(
        self, *statuses: int, bearer: int = HEALTHY, gate: anyio.Event | None = None
    ) -> None:
        assert statuses, "a script with no statuses can only mislead"
        self._statuses = list(statuses)
        self.bearer = bearer
        self._gate = gate
        self.bare = 0
        self.bearer_calls = 0
        self.fetches = 0

    @property
    def calls(self) -> int:
        return self.bare + self.bearer_calls + self.fetches

    async def get(self, url: str, *, headers: Any = None, max_bytes: int) -> TransportResponse:
        headers = dict(headers or {})
        if "cookie" in headers:
            self.fetches += 1
            return json_reply(document()).response()
        if "authorization" in headers:
            self.bearer_calls += 1
            return _answer(self.bearer)
        self.bare += 1
        status = self._statuses[min(self.bare - 1, len(self._statuses) - 1)]
        if self._gate is not None:
            await self._gate.wait()
        return _answer(status)

    async def post(self, *args: Any, **kwargs: Any) -> TransportResponse:
        raise AssertionError("get-session is a GET")  # pragma: no cover


def _answer(status: int) -> TransportResponse:
    if status == HEALTHY:
        return TransportResponse(
            status_code=200, headers={"content-type": "application/json"}, content=b"null"
        )
    return TransportResponse(
        status_code=status, headers={"content-type": "text/plain"}, content=BODY_SENTINEL
    )


class BodyScript(StatusScript):
    """A bare probe answered `200` with a fixed body and content type - the two 200 contract
    failures - while the bearer and fetch answers stay healthy."""

    def __init__(self, body: bytes, content_type: str) -> None:
        super().__init__(HEALTHY)
        self._body = body
        self._content_type = content_type

    async def get(self, url: str, *, headers: Any = None, max_bytes: int) -> TransportResponse:
        if headers and ("cookie" in headers or "authorization" in headers):
            return await super().get(url, headers=headers, max_bytes=max_bytes)
        self.bare += 1
        return TransportResponse(
            status_code=200, headers={"content-type": self._content_type}, content=self._body
        )


def verifier(transport: Any, **kwargs: Any) -> RemoteVerifier:
    kwargs.setdefault("csrf", CsrfDisabled(reason="probe status tests, no cross-site request"))
    kwargs.setdefault("secure_cookies", False)
    return RemoteVerifier(base_url=ORIGIN, transport=transport, **kwargs)


def connection() -> HTTPConnection:
    raw = [(b"cookie", f"{COOKIE_NAME}={COOKIE_VALUE}".encode())]
    return HTTPConnection({"type": "http", "method": "GET", "path": "/x", "headers": raw})


async def run(v: RemoteVerifier) -> Session[User]:
    credential = v.extract(connection())
    assert credential is not None
    return await v.verify(credential, User)


@pytest.fixture(autouse=True)
def reset_advisory(monkeypatch: pytest.MonkeyPatch) -> None:
    """The advisory warning latch is per-process; reset it so each backend run starts unfired."""
    monkeypatch.setattr(remote_probe, "_advised", Once())


# ---------------------------------------------------------------- the reproduction


async def test_a_503_at_the_first_request_is_not_remembered_and_the_verifier_recovers() -> None:
    """F2, reproduced: the auth server is restarting when the first request arrives, answers the
    probe 503, and is healthy seconds later. The first request is refused as an outage; once the
    retry window has passed the probe runs again, passes, and the request is verified. Before the
    fix the 503 was stored as a permanent contract failure and every later request raised
    `ConfigurationError` until the process restarted."""
    clock = Clock()
    transport = StatusScript(503, HEALTHY)
    v = verifier(transport, clock=clock)

    with pytest.raises(AuthServiceUnavailable):
        await run(v)

    clock.advance(PROBE_RETRY_INTERVAL)
    session = await run(v)

    assert session.user.id == "u1"
    assert transport.bare == 2, "the probe ran once per window: once failed, once passed"


# ---------------------------------------------------------------- the transient class


@pytest.mark.parametrize("status", TRANSIENT)
async def test_a_transient_status_is_an_outage_that_is_retried(status: int) -> None:
    clock = Clock()
    transport = StatusScript(status, HEALTHY)
    v = verifier(transport, clock=clock)

    with pytest.raises(AuthServiceUnavailable) as caught:
        await run(v)
    assert str(status) in caught.value.reason
    assert BODY_SENTINEL.decode() not in caught.value.reason
    assert transport.fetches == 0, "no request is verified while the contract is unproven"

    clock.advance(PROBE_RETRY_INTERVAL)
    session = await run(v)

    assert session.user.id == "u1"
    assert transport.fetches == 1


@pytest.mark.parametrize("status", TRANSIENT)
async def test_the_raw_probe_maps_a_transient_status_to_service_unavailable(status: int) -> None:
    with pytest.raises(AuthServiceUnavailable) as caught:
        await verifier(StatusScript(status)).probe()

    assert str(status) in caught.value.reason


async def test_inside_the_window_a_transient_failure_is_not_re_probed() -> None:
    """The second request inside the window is refused without a probe call, exactly the way the
    window already throttles a timeout - a request flood does not become a probe flood."""
    clock = Clock()
    transport = StatusScript(503)
    v = verifier(transport, clock=clock)

    with pytest.raises(AuthServiceUnavailable):
        await run(v)
    clock.advance(PROBE_RETRY_INTERVAL / 2)
    with pytest.raises(AuthServiceUnavailable) as caught:
        await run(v)

    assert transport.bare == 1, "no second probe inside the window"
    assert "retrying" in caught.value.reason
    assert transport.fetches == 0


async def test_an_upstream_that_stays_down_is_probed_once_per_window_and_never_served() -> None:
    clock = Clock()
    transport = StatusScript(503)
    v = verifier(transport, clock=clock)

    for _ in range(3):
        with pytest.raises(AuthServiceUnavailable):
            await run(v)
        with pytest.raises(AuthServiceUnavailable):
            await run(v)
        clock.advance(PROBE_RETRY_INTERVAL)

    assert transport.bare == 3, "one probe per elapsed window, never one per request"
    assert transport.fetches == 0, "nothing was verified while the contract was unproven"


async def test_concurrent_requests_during_a_transient_failure_share_one_probe() -> None:
    gate = anyio.Event()
    transport = StatusScript(503, gate=gate)
    v = verifier(transport, clock=Clock())
    refusals: list[AuthServiceUnavailable] = []

    async def attempt() -> None:
        # Caught inside the task: an escaping exception would cancel the siblings mid-wait.
        try:
            await run(v)
        except AuthServiceUnavailable as refusal:
            refusals.append(refusal)

    async with anyio.create_task_group() as tg:
        for _ in range(5):
            tg.start_soon(attempt)
        await anyio.sleep(0.05)
        gate.set()

    assert transport.bare == 1, "five requests during the outage triggered exactly one probe"
    assert len(refusals) == 5, "every one of them was refused as an outage"
    assert transport.fetches == 0


async def test_the_bearer_rung_under_the_gate_treats_a_transient_status_as_an_outage() -> None:
    """With `refuse_unsigned_bearer=True` the bearer posture is part of what the probe proves, so
    a `503` on that request leaves the posture unproven. It must not pass the probe (an unproven
    contract never opens the door), and it must not be remembered either."""
    clock = Clock()
    transport = StatusScript(HEALTHY, bearer=503)
    v = verifier(transport, clock=clock, refuse_unsigned_bearer=True)

    with pytest.raises(AuthServiceUnavailable) as caught:
        await run(v)
    assert "503" in caught.value.reason
    assert transport.fetches == 0

    transport.bearer = HEALTHY
    clock.advance(PROBE_RETRY_INTERVAL)
    session = await run(v)

    assert session.user.id == "u1"


async def test_the_advisory_bearer_rung_still_ignores_a_transient_status() -> None:
    """Off (the default), the bearer rung is advisory and swallows its own failures, so a `503`
    there neither refuses nor delays: the bare null contract alone passes the probe."""
    transport = StatusScript(HEALTHY, bearer=503)
    session = await run(verifier(transport))

    assert session.user.id == "u1"


# ---------------------------------------------------------------- prepare()


async def test_prepare_on_a_transient_status_fails_boot_without_remembering_it() -> None:
    """`prepare()` treats a transient status the way it treats an unreachable server: an auth
    service that cannot answer at boot should not take traffic, so it raises `ConfigurationError`;
    but it is not a verdict on the deployment, so a later `prepare()` past the window re-probes and
    passes once the upstream answers."""
    clock = Clock()
    transport = StatusScript(503, HEALTHY)
    v = verifier(transport, clock=clock)

    with pytest.raises(ConfigurationError) as caught:
        await v.prepare()
    message = str(caught.value)
    assert "startup" in message
    assert "503" in message
    assert BODY_SENTINEL.decode() not in message

    clock.advance(PROBE_RETRY_INTERVAL)
    await v.prepare()
    session = await run(v)

    assert session.user.id == "u1"


async def test_a_second_prepare_inside_the_window_fails_without_probing() -> None:
    """Pinned as it already is for an unreachable server: the window throttles `prepare()` too,
    so a supervisor retrying boot in a tight loop cannot become a probe flood."""
    clock = Clock()
    transport = StatusScript(503, HEALTHY)
    v = verifier(transport, clock=clock)

    with pytest.raises(ConfigurationError):
        await v.prepare()
    with pytest.raises(ConfigurationError) as caught:
        await v.prepare()

    assert transport.bare == 1
    assert "startup" in str(caught.value)


# ---------------------------------------------------------------- the permanent class


@pytest.mark.parametrize("status", PERMANENT_STATUSES)
async def test_a_contract_status_is_remembered_permanently(status: int) -> None:
    clock = Clock()
    transport = StatusScript(status, HEALTHY)
    v = verifier(transport, clock=clock)

    with pytest.raises(ConfigurationError) as caught:
        await run(v)
    assert str(status) in str(caught.value)
    assert BODY_SENTINEL.decode() not in str(caught.value)

    clock.advance(PROBE_RETRY_INTERVAL * 10)
    with pytest.raises(ConfigurationError):
        await run(v)
    with pytest.raises(ConfigurationError):
        await v.prepare()

    assert transport.bare == 1, "a remembered contract failure is never re-probed"
    assert transport.fetches == 0


@pytest.mark.parametrize(
    ("body", "content_type", "needle"),
    [
        (b"<html>login</html>", "text/html", "not JSON"),
        (b"not really json", "application/json", "not JSON"),
        (b'{"anything": 1}', "application/json", "non-null"),
    ],
    ids=["html", "unparseable-json", "non-null-json"],
)
async def test_a_200_that_breaks_the_contract_is_remembered_permanently(
    body: bytes, content_type: str, needle: str
) -> None:
    clock = Clock()
    transport = BodyScript(body, content_type)
    v = verifier(transport, clock=clock)

    with pytest.raises(ConfigurationError) as caught:
        await run(v)
    assert needle in str(caught.value)

    clock.advance(PROBE_RETRY_INTERVAL * 10)
    with pytest.raises(ConfigurationError):
        await run(v)

    assert transport.bare == 1
    assert transport.fetches == 0


# ---------------------------------------------------------------- reporting


async def test_a_transient_probe_failure_is_reported_once_per_verifier(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """One warning names the status and its class, however many windows the outage spans - a line
    per probe attempt would bury the log in the event it reports. The response body is never read
    into it."""
    clock = Clock()
    transport = StatusScript(503, 502, HEALTHY)
    v = verifier(transport, clock=clock)

    with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
        for _ in range(2):
            with pytest.raises(AuthServiceUnavailable):
                await run(v)
            clock.advance(PROBE_RETRY_INTERVAL)
        await run(v)

    lines = [r.getMessage() for r in caplog.records if "readiness probe" in r.getMessage()]
    assert len(lines) == 1, lines
    assert "503" in lines[0]
    assert "server error" in lines[0]
    assert BODY_SENTINEL.decode() not in caplog.text


async def test_two_verifiers_each_report_their_own_outage(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The latch is per verifier, not per process: a second upstream going down is still news."""
    with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
        for _ in range(2):
            with pytest.raises(AuthServiceUnavailable):
                await run(verifier(StatusScript(429), clock=Clock()))

    lines = [r.getMessage() for r in caplog.records if "readiness probe" in r.getMessage()]
    assert len(lines) == 2, lines
    assert all("rate limited" in line for line in lines)


async def test_a_contract_failure_logs_no_outage_line(caplog: pytest.LogCaptureFixture) -> None:
    """A contract failure is raised, remembered and seen on every request; it is not an outage,
    so the outage line does not fire for it."""
    with (
        caplog.at_level(logging.WARNING, logger="fastapi_better_auth"),
        pytest.raises(ConfigurationError),
    ):
        await run(verifier(StatusScript(404)))

    assert not [r for r in caplog.records if "readiness probe" in r.getMessage()]
