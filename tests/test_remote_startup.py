"""The probe, prepare/readiness, the PreparedVerifier protocol, and BetterAuth startup (rulings 8-9).

`RemoteVerifier` fails closed until a boot probe proves the deployment honours the 200-null
contract. This suite pins the probe's honest scope (reachable -> 200 -> json -> null, plus the
dead-jar detector and the advisory requireSignature warning), the two failure classes prepare
distinguishes (contract remembered permanently, reachability retried), the lazy fail-closed path
and its throttle, and the startup()/lifespan integration through the separate PreparedVerifier
protocol.
"""

from __future__ import annotations

import logging
from typing import Any, TypeVar

import anyio
import pytest
from fastapi import Depends, FastAPI
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuth,
    ConfigurationError,
    ContentEncodingRejected,
    CsrfDisabled,
    InvalidCredential,
    PreparedVerifier,
    RemoteVerifier,
    ResponseTooLarge,
    Session,
    SessionRevoked,
    TransportResponse,
    User,
    Verifier,
)
from fastapi_better_auth._internal import remote_probe
from fastapi_better_auth._internal.once import Once
from tests.transports import Reply, ScriptedTransport, json_reply

UserModelT = TypeVar("UserModelT", bound=User)


class PlainVerifier:
    """A `Verifier` with no `prepare()`, so `PreparedVerifier` does not match it and startup()
    skips it."""

    credential_source = "header:x-plain"

    def extract(self, connection: HTTPConnection) -> None:
        return None

    async def verify(self, credential: Any, user_model: type[UserModelT]) -> Session[UserModelT]:
        raise InvalidCredential(reason="never")  # pragma: no cover


pytestmark = pytest.mark.anyio

ORIGIN = "https://auth.example.com"
COOKIE_NAME = "better-auth.session_token"
TOKEN = "SBYZ1bzGdkhXcLuqsW70JjhvmIY4PU3B"
COOKIE_VALUE = f"{TOKEN}.c2lnbmF0dXJlLXRoYXQtaXMtNDQtY2hhcnMtbG9uZy1wYWRkZWQtb28"
FAR_FUTURE = "2999-01-01T00:00:00.000Z"


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


class SplitTransport:
    """Answers `null` to a cookieless request (the probe's bare and advisory GETs) and the given
    reply to a request carrying a cookie (the real fetch). A realistic double: a bare get-session
    is null, a cookie'd one is the session.
    """

    def __init__(self, fetch: Reply, *, set_cookie_on_bearer: bool = False) -> None:
        self._fetch = fetch
        self._set_cookie_on_bearer = set_cookie_on_bearer
        self.calls = 0
        self.bare = 0

    async def get(self, url: str, *, headers: Any = None, max_bytes: int) -> TransportResponse:
        self.calls += 1
        headers = headers or {}
        if "cookie" in headers:
            return self._fetch.response()
        self.bare += 1
        extra = {}
        if self._set_cookie_on_bearer and "authorization" in headers:
            extra = {"set-cookie": "better-auth.session_token=CLEARED; Max-Age=0"}
        return TransportResponse(
            status_code=200, headers={"content-type": "application/json", **extra}, content=b"null"
        )

    async def post(self, *args: Any, **kwargs: Any) -> TransportResponse:
        raise AssertionError("get-session is a GET")  # pragma: no cover


def verifier(transport: Any, **kwargs: Any) -> RemoteVerifier:
    kwargs.setdefault("csrf", CsrfDisabled(reason="startup tests, no cross-site request"))
    kwargs.setdefault("secure_cookies", False)
    return RemoteVerifier(base_url=ORIGIN, transport=transport, **kwargs)


def connection(*, cookie: str | None = COOKIE_VALUE) -> HTTPConnection:
    raw = [] if cookie is None else [(b"cookie", f"{COOKIE_NAME}={cookie}".encode())]
    return HTTPConnection({"type": "http", "method": "GET", "path": "/x", "headers": raw})


async def run(v: RemoteVerifier) -> Session[User]:
    credential = v.extract(connection())
    assert credential is not None
    return await v.verify(credential, User)


@pytest.fixture(autouse=True)
def reset_advisory(monkeypatch: pytest.MonkeyPatch) -> None:
    """The advisory warning latch is per-process; reset it so each backend run starts unfired."""
    monkeypatch.setattr(remote_probe, "_advised", Once())


# ---------------------------------------------------------------- probe()


async def test_probe_passes_on_a_null_contract() -> None:
    await verifier(ScriptedTransport(Reply(b"null"))).probe()


async def test_probe_refuses_a_wrong_base_path_naming_the_uri() -> None:
    v = verifier(ScriptedTransport(Reply(b"", status=404)), base_path="/api/nope")

    with pytest.raises(ConfigurationError) as caught:
        await v.probe()

    assert "/api/nope" in str(caught.value)
    assert "base_path" in str(caught.value)


async def test_probe_refuses_a_non_json_body() -> None:
    with pytest.raises(ConfigurationError) as caught:
        await verifier(ScriptedTransport(Reply(b"null", content_type="text/html"))).probe()

    assert "not JSON" in str(caught.value)


async def test_probe_refuses_a_non_null_body() -> None:
    with pytest.raises(ConfigurationError) as caught:
        await verifier(ScriptedTransport(Reply(b'{"anything": 1}'))).probe()

    assert "non-null" in str(caught.value)


async def test_probe_detects_the_dead_jar_naming_the_transport() -> None:
    """A bare request answered with a live session document means the transport is replaying a
    retained cookie - the second dead-jar detector, distinct from a plain contract failure."""
    with pytest.raises(ConfigurationError) as caught:
        await verifier(ScriptedTransport(json_reply(document()))).probe()

    assert "ScriptedTransport" in str(caught.value)
    assert "replaying" in str(caught.value)


async def test_probe_refuses_a_json_content_type_with_an_unparseable_body() -> None:
    with pytest.raises(ConfigurationError) as caught:
        await verifier(ScriptedTransport(Reply(b"not really json"))).probe()

    assert "not JSON" in str(caught.value)


async def test_probe_refuses_a_non_routing_status() -> None:
    with pytest.raises(ConfigurationError) as caught:
        await verifier(ScriptedTransport(Reply(b"", status=500))).probe()

    assert "500" in str(caught.value)
    assert "must answer 200" in str(caught.value)


@pytest.mark.parametrize(
    ("answer", "needle"),
    [
        (ResponseTooLarge(max_bytes=65536), "over the"),
        (ContentEncodingRejected(encoding="gzip"), "content encoding"),
        (RuntimeError("boom"), "could not reach"),
    ],
    ids=["too-large", "content-encoding", "generic"],
)
async def test_probe_maps_each_reachability_failure_to_service_unavailable(
    answer: Any, needle: str
) -> None:
    with pytest.raises(AuthServiceUnavailable) as caught:
        await verifier(ScriptedTransport(answer)).probe()

    assert needle in caught.value.reason


async def test_probe_maps_a_reachability_failure_to_service_unavailable() -> None:
    with pytest.raises(AuthServiceUnavailable):
        await verifier(ScriptedTransport(TimeoutError("slow"))).probe()


async def test_probe_re_raises_a_session_error_from_the_transport_verbatim() -> None:
    """A transport should not raise a SessionError, but if it does the probe honours it as the
    answer rather than masking it - the same passthrough the fetch site keeps."""
    with pytest.raises(SessionRevoked) as caught:
        await verifier(ScriptedTransport(SessionRevoked(reason="scripted passthrough"))).probe()

    assert caught.value.reason == "scripted passthrough"


async def test_the_advisory_probe_swallows_its_own_failure() -> None:
    """The advisory rung never refuses: if its own request fails, the probe still passes on the
    strength of the bare null contract."""
    await verifier(_AdvisoryFailingTransport()).probe()


class _AdvisoryFailingTransport:
    """Answers `null` to the bare probe, but fails the advisory (bearer) request."""

    async def get(self, url: str, *, headers: Any = None, max_bytes: int) -> TransportResponse:
        headers = headers or {}
        if "authorization" in headers:
            raise TimeoutError("advisory rung is down")
        return TransportResponse(
            status_code=200, headers={"content-type": "application/json"}, content=b"null"
        )

    async def post(self, *args: Any, **kwargs: Any) -> TransportResponse:
        raise AssertionError("get-session is a GET")  # pragma: no cover


async def test_the_advisory_probe_warns_once_on_a_set_cookie(
    caplog: pytest.LogCaptureFixture,
) -> None:
    transport = SplitTransport(json_reply(document()), set_cookie_on_bearer=True)
    v = verifier(transport)
    with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
        await v.probe()
        await v.probe()

    warnings = [r for r in caplog.records if "requireSignature" in r.getMessage()]
    assert len(warnings) == 1, "the advisory warning is once per process"


async def test_the_advisory_probe_is_silent_without_a_set_cookie(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
        await verifier(SplitTransport(json_reply(document()))).probe()

    assert not [r for r in caplog.records if "requireSignature" in r.getMessage()]


# ---------------------------------------------------------------- prepare()


async def test_prepare_passes_and_verify_then_makes_no_probe_call() -> None:
    transport = SplitTransport(json_reply(document()))
    v = verifier(transport)

    await v.prepare()
    probe_calls = transport.calls
    session = await run(v)

    assert session.user.id == "u1"
    assert transport.calls == probe_calls + 1, "one fetch; the probe did not run again"


async def test_prepare_is_idempotent() -> None:
    transport = SplitTransport(json_reply(document()))
    v = verifier(transport)

    await v.prepare()
    calls = transport.calls
    await v.prepare()

    assert transport.calls == calls, "a second prepare() re-probes nothing"


async def test_prepare_remembers_a_contract_failure_permanently() -> None:
    """A contract failure is a permanent deployment fact: every later prepare() and verify()
    re-raises it as ConfigurationError, with no further outbound call."""
    transport = ScriptedTransport(Reply(b'{"not": "null"}'))
    v = verifier(transport)

    with pytest.raises(ConfigurationError):
        await v.prepare()
    calls = transport.calls

    with pytest.raises(ConfigurationError):
        await v.prepare()
    with pytest.raises(ConfigurationError):
        await run(v)
    assert transport.calls == calls, "a remembered contract failure makes no further outbound call"


async def test_prepare_turns_an_unreachable_server_into_a_configuration_error() -> None:
    with pytest.raises(ConfigurationError) as caught:
        await verifier(ScriptedTransport(TimeoutError("down"))).prepare()

    assert "startup" in str(caught.value)


async def test_a_reachability_failure_at_startup_is_not_remembered() -> None:
    """Unlike a contract failure, an unreachable server at boot is not remembered as a permanent
    contract fault: the lazy path can still retry it on a later request."""
    v = verifier(ScriptedTransport(TimeoutError("down")))

    with pytest.raises(ConfigurationError):
        await v.prepare()

    assert v._contract_failure is None, "reachability was not remembered as a contract failure"  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------- the lazy path


async def test_a_cold_verify_probes_once_then_serves() -> None:
    transport = SplitTransport(json_reply(document()))
    v = verifier(transport)

    session = await run(v)

    assert session.user.id == "u1"
    assert transport.bare >= 1, "the lazy probe ran"


async def test_the_lazy_probe_is_throttled_after_a_reachability_failure() -> None:
    clock = Clock()
    transport = _CountingTimeout()
    v = verifier(transport, clock=clock)

    with pytest.raises(AuthServiceUnavailable):
        await run(v)
    after_first = transport.calls

    # Immediately again: throttled, no new probe call.
    with pytest.raises(AuthServiceUnavailable) as caught:
        await run(v)
    assert transport.calls == after_first, "a request flood did not become a probe flood"
    assert "retrying" in caught.value.reason

    clock.advance(10.0)
    with pytest.raises(AuthServiceUnavailable):
        await run(v)
    assert transport.calls == after_first + 1, "after the interval the probe is retried once"


class _CountingTimeout:
    def __init__(self) -> None:
        self.calls = 0

    async def get(self, url: str, *, headers: Any = None, max_bytes: int) -> TransportResponse:
        self.calls += 1
        raise TimeoutError("still down")

    async def post(self, *args: Any, **kwargs: Any) -> TransportResponse:
        raise AssertionError("get-session is a GET")  # pragma: no cover


async def test_concurrent_cold_verifies_share_one_probe() -> None:
    """The probe lock collapses a first-request burst into one probe attempt."""
    gate = anyio.Event()
    transport = _GatedProbe(document(), gate)
    v = verifier(transport)

    async with anyio.create_task_group() as tg:
        for _ in range(5):
            tg.start_soon(run, v)
        await anyio.sleep(0.05)
        gate.set()

    assert transport.probes == 1, "five cold verifies triggered exactly one probe"


class _GatedProbe:
    """Holds the first bare probe GET open on a gate, so a burst piles up behind the lock."""

    def __init__(self, doc: dict[str, Any], gate: anyio.Event) -> None:
        self._doc = doc
        self._gate = gate
        self.probes = 0

    async def get(self, url: str, *, headers: Any = None, max_bytes: int) -> TransportResponse:
        headers = headers or {}
        if "cookie" in headers:
            return json_reply(self._doc).response()
        if "authorization" not in headers:
            self.probes += 1
            await self._gate.wait()
        return TransportResponse(
            status_code=200, headers={"content-type": "application/json"}, content=b"null"
        )

    async def post(self, *args: Any, **kwargs: Any) -> TransportResponse:
        raise AssertionError("get-session is a GET")  # pragma: no cover


async def test_a_contract_failure_is_seen_by_a_request_queued_behind_the_lock() -> None:
    """The lock's double-check: while one request probes and fails the contract, another that was
    already queued behind the lock re-raises the remembered failure rather than probing again."""
    gate = anyio.Event()
    transport = _GatedContractFail(gate)
    v = verifier(transport)
    errors: list[ConfigurationError] = []

    async def attempt() -> None:
        with pytest.raises(ConfigurationError) as caught:
            await run(v)
        errors.append(caught.value)

    async with anyio.create_task_group() as tg:
        tg.start_soon(attempt)
        await anyio.sleep(0.05)  # let the first acquire the lock and block in its probe
        tg.start_soon(attempt)
        await anyio.sleep(0.05)  # let the second reach the lock and wait
        gate.set()  # the first probe returns a non-null body, fails, releases the lock

    assert len(errors) == 2, "both requests were refused; the second saw the remembered failure"


class _GatedContractFail:
    """The bare probe waits on a gate, then answers a non-null body (a contract failure)."""

    def __init__(self, gate: anyio.Event) -> None:
        self._gate = gate

    async def get(self, url: str, *, headers: Any = None, max_bytes: int) -> TransportResponse:
        headers = headers or {}
        if "cookie" not in headers and "authorization" not in headers:
            await self._gate.wait()
            return TransportResponse(
                status_code=200,
                headers={"content-type": "application/json"},
                content=b'{"not": "null"}',
            )
        return TransportResponse(
            status_code=200, headers={"content-type": "application/json"}, content=b"null"
        )

    async def post(self, *args: Any, **kwargs: Any) -> TransportResponse:
        raise AssertionError("get-session is a GET")  # pragma: no cover


async def test_a_cancelled_probe_does_not_spend_the_retry_window() -> None:
    """A cancelled probe (a disconnected first request) rolls back its attempt stamp, so it is not
    mistaken for a completed attempt that would gate the next request out (D-196)."""
    gate = anyio.Event()  # never set, so the probe blocks until cancelled
    v = verifier(_GatedNull(gate))

    with anyio.move_on_after(0.05):
        await run(v)

    assert v._probe_attempted_at is None, "the cancelled attempt did not spend the window"  # pyright: ignore[reportPrivateUsage]


class _GatedNull:
    """The bare probe blocks forever on a gate, so the surrounding scope can cancel it."""

    def __init__(self, gate: anyio.Event) -> None:
        self._gate = gate

    async def get(self, url: str, *, headers: Any = None, max_bytes: int) -> TransportResponse:
        await self._gate.wait()
        return TransportResponse(  # pragma: no cover - the gate is never set
            status_code=200, headers={"content-type": "application/json"}, content=b"null"
        )

    async def post(self, *args: Any, **kwargs: Any) -> TransportResponse:
        raise AssertionError("get-session is a GET")  # pragma: no cover


# ---------------------------------------------------------------- PreparedVerifier + startup


def test_remote_verifier_is_a_prepared_verifier() -> None:
    v = verifier(ScriptedTransport(Reply(b"null")))

    assert isinstance(v, PreparedVerifier)
    assert isinstance(v, Verifier)


def test_a_plain_verifier_is_not_a_prepared_verifier() -> None:
    assert not isinstance(PlainVerifier(), PreparedVerifier)
    assert isinstance(PlainVerifier(), Verifier)


async def test_startup_runs_prepare_on_the_remote_verifier() -> None:
    transport = SplitTransport(json_reply(document()))
    v = verifier(transport)
    auth = BetterAuth(verifiers=[v])

    await auth.startup()

    assert v._probed_ok, "startup() ran the probe"  # pyright: ignore[reportPrivateUsage]


async def test_startup_skips_a_verifier_without_prepare() -> None:
    await BetterAuth(verifiers=[PlainVerifier()]).startup()  # does not raise


async def test_startup_propagates_a_contract_failure_unwrapped() -> None:
    v = verifier(ScriptedTransport(Reply(b'{"not": "null"}')))
    auth = BetterAuth(verifiers=[v])

    with pytest.raises(ConfigurationError):
        await auth.startup()


async def test_lifespan_runs_startup() -> None:
    transport = SplitTransport(json_reply(document()))
    v = verifier(transport)
    auth = BetterAuth(verifiers=[v])

    async with auth.lifespan(FastAPI()):
        assert v._probed_ok  # pyright: ignore[reportPrivateUsage]


async def test_lifespan_surfaces_a_probe_failure() -> None:
    v = verifier(ScriptedTransport(Reply(b"", status=404)), base_path="/api/nope")
    auth = BetterAuth(verifiers=[v])

    with pytest.raises(ConfigurationError):
        async with auth.lifespan(FastAPI()):
            pass  # pragma: no cover


def test_lifespan_wires_into_fastapi_and_a_probe_failure_stops_startup() -> None:
    """The operator-facing shape: FastAPI(lifespan=auth.lifespan). A contract failure makes the
    ASGI lifespan startup fail, so the server never begins serving."""
    from fastapi.testclient import TestClient

    v = verifier(ScriptedTransport(Reply(b'{"not": "null"}')))
    auth = BetterAuth(verifiers=[v])
    app = FastAPI(lifespan=auth.lifespan)

    required = auth.current_session(user_model=User)

    async def me(session: Session[User] = Depends(required)) -> str:
        return session.user.id  # pragma: no cover

    app.add_api_route("/me", me)

    with pytest.raises(ConfigurationError), TestClient(app):
        pass
