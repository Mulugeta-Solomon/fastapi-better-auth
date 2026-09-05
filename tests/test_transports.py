"""One conformance suite, run against every adapter this library ships.

`httpx` and `httpx2` are the same API under two names, so the adapters differ by an import
and nothing else — which is exactly the situation where a fix lands in one and not the other.
Every obligation in the `Transport` docstring is asserted here once and parameterized over
both, against a real socket: an in-process ASGI double cannot show that a redirect was not
followed, that an oversized body was abandoned mid-stream, or that a stalled read raises a
timeout.
"""

from __future__ import annotations

import gc
import gzip
import inspect
import pickle
import sys
import tracemalloc
import warnings
from collections.abc import AsyncIterator, Callable, Iterable, Mapping
from dataclasses import dataclass
from types import TracebackType
from typing import TYPE_CHECKING, Any, Protocol, cast

import anyio
import httpx
import httpx2
import pytest
from typing_extensions import Self

from fastapi_better_auth import (
    ConfigurationError,
    ContentEncodingRejected,
    Httpx2Transport,
    HttpxTransport,
    ResponseTooLarge,
    Transport,
)
from fastapi_better_auth._internal.httpx_transports import (
    _capped,  # pyright: ignore[reportPrivateUsage]
)
from fastapi_better_auth._internal.transport import TransportFailure
from tests.scripted_server import (
    encoded,
    hangup,
    replaying,
    replying,
    scripted_server,
    stalling,
    trickling,
    unframed,
)

CAP = 4096
OVERSIZED = 8 * 1024 * 1024
REDIRECTS = (301, 302, 303, 307, 308)
STALL_TIMEOUT = 0.25
TRICKLE_CEILING = 5.0
TRICKLE_INTERVAL = 0.05
TRICKLE_TIMEOUT = 0.5
# A gzip stream that expands ~1000x: the wire body is tiny, the decoded body is not.
BOMB_DECODED = 64 * 1024 * 1024
GZIP_BOMB = gzip.compress(b"\0" * BOMB_DECODED)
GIANT_CHUNK = b"x" * (16 * 1024 * 1024)


class Adapter(Transport, Protocol):
    """A shipped adapter: the protocol, plus the lifecycle the protocol deliberately omits."""

    async def aclose(self) -> None: ...

    async def __aenter__(self) -> Self: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...


@dataclass(frozen=True)
class Library:
    """One adapter and the library behind it."""

    name: str
    build: Callable[..., Adapter]
    connect: Callable[..., Any]
    timeout_error: type[Exception]
    disconnect_error: type[Exception]


LIBRARIES = (
    Library(
        name="httpx",
        build=HttpxTransport,
        connect=httpx.AsyncClient,
        timeout_error=httpx.TimeoutException,
        disconnect_error=httpx.RemoteProtocolError,
    ),
    Library(
        name="httpx2",
        build=Httpx2Transport,
        connect=httpx2.AsyncClient,
        timeout_error=httpx2.TimeoutException,
        disconnect_error=httpx2.RemoteProtocolError,
    ),
)


@pytest.fixture(params=LIBRARIES, ids=[each.name for each in LIBRARIES])
def library(request: pytest.FixtureRequest) -> Library:
    chosen = request.param
    assert isinstance(chosen, Library)
    return chosen


class _OneChunk:
    """A response whose whole body arrives in a single `aiter_raw()` chunk — the shape a
    socket never produces (it reads in blocks) but the cap must survive anyway."""

    status_code = 200

    def __init__(self, chunk: bytes) -> None:
        self._chunk = chunk
        self.headers: dict[str, str] = {}

    def aiter_raw(self) -> AsyncIterator[bytes]:
        async def _one() -> AsyncIterator[bytes]:
            yield self._chunk

        return _one()


def _max_bytes_is_required_by_type(
    protocol: Transport, one: HttpxTransport, two: Httpx2Transport
) -> None:
    """B5 typing pin: calling `get`/`post` without `max_bytes` must be a type error on the
    Protocol AND both adapters. Under `reportUnnecessaryTypeIgnoreComment`, a default creeping
    onto `max_bytes` makes the call valid, both suppressed codes vanish, and the now-unused
    ignore fails the type gate. Never executed — accessed under `TYPE_CHECKING` below."""
    _ = protocol.get("x")  # pyright: ignore[reportCallIssue, reportUnknownVariableType]
    _ = protocol.post("x")  # pyright: ignore[reportCallIssue, reportUnknownVariableType]
    _ = one.get("x")  # pyright: ignore[reportCallIssue, reportUnknownVariableType]
    _ = one.post("x")  # pyright: ignore[reportCallIssue, reportUnknownVariableType]
    _ = two.get("x")  # pyright: ignore[reportCallIssue, reportUnknownVariableType]
    _ = two.post("x")  # pyright: ignore[reportCallIssue, reportUnknownVariableType]


if TYPE_CHECKING:
    _ = _max_bytes_is_required_by_type  # accessed so pyright does not call it unused


def test_both_adapters_are_shipped() -> None:
    """A suite parameterized over one adapter would prove nothing about the other."""
    assert {each.name for each in LIBRARIES} == {"httpx", "httpx2"}


def test_an_adapter_satisfies_the_protocol(library: Library) -> None:
    assert isinstance(library.build(), Transport)


@pytest.mark.parametrize("method", ["get", "post"])
def test_the_adapters_require_max_bytes_at_runtime_too(library: Library, method: str) -> None:
    """B5, the runtime half of the typing pin: `max_bytes` has no default on either adapter,
    so an accidental default is caught even where pyright is not run."""
    parameter = inspect.signature(getattr(library.build, method)).parameters["max_bytes"]

    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty


@pytest.mark.anyio
async def test_the_status_headers_and_body_come_back_intact(library: Library) -> None:
    answer = replying(200, headers={"X-Key-Set": "yes"}, body=b'{"keys": []}')

    async with scripted_server(answer) as served, library.build() as transport:
        response = await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)

    assert response.status_code == 200
    assert response.headers["x-key-set"] == "yes"
    assert response.content == b'{"keys": []}'


@pytest.mark.anyio
async def test_the_method_target_and_headers_reach_the_server(library: Library) -> None:
    async with scripted_server(replying(200)) as served, library.build() as transport:
        await transport.get(
            f"{served.origin()}/api/auth/jwks", headers={"X-Probe": "value"}, max_bytes=CAP
        )

    request = served.requests[0]
    assert request.method == "GET"
    assert request.target == "/api/auth/jwks"
    assert request.headers["x-probe"] == "value"


@pytest.mark.anyio
async def test_the_body_is_never_compressed(library: Library) -> None:
    """`identity` is asked for so that the cap counts the bytes that actually arrive: a
    decompressing read would let a small response expand past the cap after it was checked."""
    async with scripted_server(replying(200)) as served, library.build() as transport:
        await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)

    assert served.requests[0].headers["accept-encoding"] == "identity"


@pytest.mark.anyio
@pytest.mark.parametrize("status", REDIRECTS)
async def test_a_redirect_is_returned_unfollowed(library: Library, status: int) -> None:
    """The pinned URL is the whole security of the fetch. A transport that followed a
    `Location` header would let whoever answers that origin move the fetch somewhere else."""
    answer = replying(status, headers={"Location": "http://127.0.0.1:1/elsewhere"})

    async with scripted_server(answer) as served, library.build() as transport:
        response = await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)

    assert response.status_code == status
    assert response.headers["location"] == "http://127.0.0.1:1/elsewhere"
    assert len(served.requests) == 1


@pytest.mark.anyio
async def test_an_injected_client_that_follows_redirects_is_still_forced_off(
    library: Library,
) -> None:
    """The one piece of an injected client's configuration the adapter overrules. It is
    passed per request, so no amount of client-level configuration can turn it back on."""
    answer = replying(302, headers={"Location": "http://127.0.0.1:1/elsewhere"})
    client = library.connect(follow_redirects=True)

    try:
        async with scripted_server(answer) as served:
            transport = library.build(client=client)
            response = await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)
    finally:
        await client.aclose()

    assert response.status_code == 302
    assert len(served.requests) == 1


@pytest.mark.anyio
async def test_a_body_exactly_at_the_cap_is_accepted(library: Library) -> None:
    """Off-by-one in the safe direction is a refused key set and a dead deployment."""
    answer = replying(200, body=b"x" * CAP)

    async with scripted_server(answer) as served, library.build() as transport:
        response = await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)

    assert len(response.content) == CAP


@pytest.mark.anyio
async def test_an_oversized_body_that_arrives_all_at_once_is_still_refused(
    library: Library,
) -> None:
    """The other half of the abort: a framed body one byte over the cap arrives in a single
    chunk and the stream ends immediately, so the cancellation is never actually delivered.
    The refusal has to come from the scope having been *asked* to cancel, not from catching
    the cancellation."""
    answer = replying(200, body=b"x" * (CAP + 1))

    async with scripted_server(answer) as served, library.build() as transport:
        with pytest.raises(ResponseTooLarge):
            await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)


@pytest.mark.anyio
async def test_an_oversized_body_with_no_content_length_aborts_the_read(library: Library) -> None:
    """The response is framed by the connection close, so there is no `Content-Length` to
    consult: only a cap counted *during* the read can stop this. `written` proves the server
    never finished sending, which is what "the read was abandoned" has to mean."""
    written: list[int] = []
    answer = unframed(total=OVERSIZED, written=written)

    async with scripted_server(answer) as served, library.build() as transport:
        with pytest.raises(ResponseTooLarge) as caught:
            await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)

    assert caught.value.max_bytes == CAP
    assert written and written[0] < OVERSIZED


@pytest.mark.anyio
async def test_a_gzip_bomb_is_refused_without_ever_decompressing(library: Library) -> None:
    """B1: the cap counts WIRE bytes and a Content-Encoding we did not ask for is refused
    before any decode, so a tiny compressed stream cannot expand to exhaust memory. Reproduced
    at 260 KB wire -> ~400 MB peak before this fix. `accept-encoding: identity` is only a
    request hint; both libraries decode off the RESPONSE's Content-Encoding regardless."""
    bomb = scripted_server(encoded(body=GZIP_BOMB, encoding="gzip"))
    tracemalloc.start()
    try:
        async with bomb as served, library.build() as transport:
            with pytest.raises(ContentEncodingRejected) as caught:
                await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert caught.value.encoding == "gzip"
    assert peak < BOMB_DECODED // 8, f"peaked at {peak} bytes — the bomb was decompressed"


@pytest.mark.anyio
async def test_capped_holds_the_buffer_to_the_cap_even_on_one_giant_chunk() -> None:
    """B2: the cap is checked AFTER `body += chunk`, so a single chunk far larger than the cap
    blows the bound before the check lands. Slicing each chunk to `cap - len + 1` keeps the
    buffer at cap+1 whatever the chunk size. The giant chunk is allocated OUTSIDE the traced
    region, so what tracemalloc sees is `_capped`'s own buffer, not the source."""
    tracemalloc.start()
    try:
        with pytest.raises(ResponseTooLarge):
            await _capped(_OneChunk(GIANT_CHUNK), CAP)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert peak < len(GIANT_CHUNK) // 8, f"buffer grew to {peak} bytes — the chunk was not sliced"


@pytest.mark.anyio
async def test_duplicate_headers_arrive_comma_joined(library: Library) -> None:
    """B3: both libraries comma-join repeated header names, and `TransportResponse` keeps that.
    It is correct for a `WWW-Authenticate` a caller reads as one value, and it is exactly why
    `Set-Cookie` must never be read off this mapping — a join hides a smuggled second cookie
    behind a comma."""
    answer = replaying(
        [
            ("www-authenticate", "Bearer"),
            ("www-authenticate", 'Basic realm="x"'),
            ("set-cookie", "a=1"),
            ("set-cookie", "b=2"),
        ],
        body=b"{}",
    )

    async with scripted_server(answer) as served, library.build() as transport:
        response = await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)

    assert response.headers["www-authenticate"] == 'Bearer, Basic realm="x"'
    assert response.headers["set-cookie"] == "a=1, b=2"


@pytest.mark.anyio
async def test_an_upstream_set_cookie_is_never_replayed_owned(library: Library) -> None:
    """Phase-3 R10. Both libraries keep a live cookie jar on the client, so a `Set-Cookie`
    from the pinned origin was stored and sent back on every later fetch.

    Nothing this adapter does has a session: a key set is public, and a get-session call
    carries its credential in the body. So a cookie coming *back* from upstream is state this
    library never asked for, and replaying it means a compromised or misbehaving auth origin
    can pin per-process state onto the auth path itself.
    """
    answer = replying(200, headers={"Set-Cookie": "a=b; Path=/"}, body=b"{}")

    async with scripted_server(answer) as served, library.build() as transport:
        await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)
        await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)

    assert len(served.requests) == 2, "the second fetch never happened; this proves nothing"
    assert "cookie" not in served.requests[1].headers


@pytest.mark.anyio
async def test_an_upstream_set_cookie_is_never_replayed_injected(library: Library) -> None:
    """The same, on a client the adapter did not build. An injected client is the case that
    matters most: its jar outlives any one fetch and is shared with whatever else the
    application does with it, so a cookie stored through the auth path would leak sideways."""
    answer = replying(200, headers={"Set-Cookie": "a=b; Path=/"}, body=b"{}")
    client = library.connect()

    try:
        async with scripted_server(answer) as served:
            transport = library.build(client=client)
            await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)
            await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)
    finally:
        await client.aclose()

    assert len(served.requests) == 2, "the second fetch never happened; this proves nothing"
    assert "cookie" not in served.requests[1].headers
    assert len(client.cookies.jar) == 0


@pytest.mark.anyio
async def test_a_stalled_response_before_headers_raises_builtin_timeout_error(
    library: Library,
) -> None:
    """B4: a per-phase read timeout fires before any header arrives. The adapter translates
    the library's own `TimeoutException` into a builtin `TimeoutError`, so the Protocol's
    timeout contract does not leak which library is underneath. The verifier above turns the
    builtin into `AuthServiceUnavailable`."""
    stalled = library.build(timeout=STALL_TIMEOUT)

    async with scripted_server(stalling()) as served, stalled as transport:
        with pytest.raises(TimeoutError):
            await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)


@pytest.mark.anyio
async def test_a_timeout_is_never_the_libraries_own_exception_type(library: Library) -> None:
    """The other half of B4, stated as a negative so it cannot silently regress: the thing a
    caller catches is `TimeoutError`, and never `httpx(2).TimeoutException`."""
    stalled = library.build(timeout=STALL_TIMEOUT)

    async with scripted_server(stalling()) as served, stalled as transport:
        with pytest.raises(TimeoutError) as caught:
            await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)

    assert not isinstance(caught.value, library.timeout_error)


@pytest.mark.anyio
async def test_a_non_timeout_network_error_becomes_a_transport_failure(library: Library) -> None:
    """R13 (fix round 2). A server that disconnects without answering used to propagate the
    library's own `RemoteProtocolError` - whose `.request` holds every outbound header. Now
    every non-timeout failure is translated to a `TransportFailure` raised OUTSIDE the failing
    `except`, so the exception a caller sees names only the failure's type and the URL, is
    never the library's own error type, and chains nothing (no `__cause__`, no `__context__`)
    that could carry the request out."""
    async with scripted_server(hangup()) as served, library.build() as transport:
        url = f"{served.origin()}/api/auth/jwks"
        with pytest.raises(TransportFailure) as caught:
            await transport.get(url, max_bytes=CAP)

    assert not isinstance(caught.value, library.disconnect_error)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert url in caught.value.reason
    assert library.disconnect_error.__name__ in caught.value.reason


# The outbound header a failing fetch must never let out. Distinctive enough that any
# appearance anywhere in a raised exception is this cookie and nothing incidental.
OUTBOUND_COOKIE = "session=leak-canary-" + "z" * 48


def _getattr(obj: object, name: str) -> object:
    """`getattr` guarded: httpx's `.request` is a property that raises `RuntimeError` when
    unset rather than returning a default, so a bare `getattr(exc, "request", None)` throws."""
    try:
        return getattr(obj, name, None)
    except Exception:  # noqa: BLE001 - an attribute that cannot be read carries nothing
        return None


def _appears_in(secret: str, obj: object, seen: set[int]) -> bool:
    """Whether `secret` shows up in how an error reporter would serialize `obj`: strings and
    bytes searched directly, containers walked, everything else taken as its `repr` - which is
    what a Sentry-style frame-locals capture records for it."""
    if id(obj) in seen:
        return False
    seen.add(id(obj))
    if isinstance(obj, str):
        return secret in obj
    if isinstance(obj, (bytes, bytearray)):
        return secret.encode() in bytes(obj)
    if isinstance(obj, Mapping):
        mapping = cast("Mapping[object, object]", obj)
        return any(
            _appears_in(secret, key, seen) or _appears_in(secret, value, seen)
            for key, value in mapping.items()
        )
    if isinstance(obj, (list, tuple, set, frozenset)):
        members = cast("Iterable[object]", obj)
        return any(_appears_in(secret, item, seen) for item in members)
    try:
        return secret in repr(obj)
    except Exception:  # noqa: BLE001 - an object whose repr raises hides nothing
        return False


def _carried_request_leaks(secret: str, carried: object) -> bool:
    """A carried httpx request/response redacts sensitive headers in its `repr`, so the raw,
    undecoded header list and the body are what have to be searched - that is where a `cookie`
    header actually lives once it is on a `Request`."""
    headers = _getattr(carried, "headers")
    raw = _getattr(headers, "raw")
    if raw is not None and _appears_in(secret, raw, set()):
        return True
    if raw is None and headers is not None and _appears_in(secret, headers, set()):
        return True
    content = _getattr(carried, "content")
    return content is not None and _appears_in(secret, content, set())


def _request_reachable(secret: str, error: BaseException) -> bool:
    """Walk everything an error reporter would touch that the *transport* is responsible for:
    the whole `__cause__`/`__context__` chain, every exception's `.request`/`.response`, and
    every traceback frame's locals - except this test module's own frames. The caller of a
    fetch legitimately holds the credential it is verifying (and the scripted server holds the
    request it received), so a frame in this file carrying the secret is not a transport leak."""
    seen: set[int] = set()
    chain: list[BaseException] = []
    exc: BaseException | None = error
    while exc is not None and all(exc is not link for link in chain):
        chain.append(exc)
        exc = exc.__cause__ or exc.__context__
    for link in chain:
        if _appears_in(secret, link.args, seen):
            return True
        for name in ("request", "response"):
            carried = _getattr(link, name)
            if carried is not None and _carried_request_leaks(secret, carried):
                return True
        frame = link.__traceback__
        while frame is not None:
            if frame.tb_frame.f_code.co_filename != __file__ and _appears_in(
                secret, frame.tb_frame.f_locals, seen
            ):
                return True
            frame = frame.tb_next
    return False


@pytest.mark.anyio
@pytest.mark.parametrize("scenario", ["stalling", "hangup", "connect-refused", "over-cap"])
async def test_no_fetch_failure_carries_the_outbound_request(
    library: Library, scenario: str
) -> None:
    """R13 (fix round 2), the phase-3 prerequisite. The JWKS fetch sends `accept` only, but
    the day `RemoteVerifier` posts get-session it sends `cookie: <session>` through this same
    transport. A fetch that fails must not smuggle that outbound header out in the exception it
    raises - not as a chained httpx exception whose `.request` holds every header verbatim, and
    not in a frame local a Sentry-style capture would serialize. Reproduced 4/4 before the fix:
    the timeout chained the httpx error as `__cause__`; the non-timeout failures propagated the
    raw httpx error; every path left the outbound `headers` in `_fetch`'s frame unscrubbed.
    """
    # The cookie is passed *inline*, never bound to a local here: the caller legitimately holds
    # the credential it is verifying, so this test's own frame holding it would be a false
    # positive. What is under test is that the transport does not retain or chain it out.
    error: BaseException | None = None

    if scenario == "connect-refused":
        async with library.build() as transport:
            try:
                await transport.get(
                    "http://127.0.0.1:1/api/auth/jwks",
                    headers={"cookie": OUTBOUND_COOKIE},
                    max_bytes=CAP,
                )
            except Exception as exc:  # noqa: BLE001 - inspect whatever the fetch raised
                error = exc
    else:
        responder = {
            "stalling": stalling(),
            "hangup": hangup(),
            "over-cap": replying(200, body=b"x" * (CAP + 1)),
        }[scenario]
        built = library.build(timeout=STALL_TIMEOUT) if scenario == "stalling" else library.build()
        async with scripted_server(responder) as served, built as transport:
            try:
                await transport.get(
                    f"{served.origin()}/api/auth/jwks",
                    headers={"cookie": OUTBOUND_COOKIE},
                    max_bytes=CAP,
                )
            except Exception as exc:  # noqa: BLE001 - inspect whatever the fetch raised
                error = exc

    assert error is not None, f"{scenario}: the fetch was supposed to fail and did not"
    assert not _request_reachable(OUTBOUND_COOKIE, error), (
        f"{scenario}: the outbound cookie is reachable from the raised {type(error).__name__}"
    )


def test_a_transport_failure_names_only_its_reason_and_survives_a_pickle() -> None:
    """The internal `TransportFailure` carries only a `[type] url` reason - never the request -
    and, like the untrusted-response errors, keeps it through the pickle an error reporter does
    (a keyword-only `__init__` and the default `__reduce__` would not)."""
    error = TransportFailure(reason="[ConnectError] https://auth.example.com/api/auth/jwks")

    assert "ConnectError" in error.reason
    assert "ConnectError" in repr(error)
    restored = pickle.loads(pickle.dumps(error))
    assert isinstance(restored, TransportFailure)
    assert restored.reason == error.reason


@pytest.mark.anyio
async def test_a_trickling_response_is_cut_off_by_the_whole_exchange_deadline(
    library: Library,
) -> None:
    """The library's own timeouts are per operation and reset on every byte that arrives, so
    a server dribbling one byte at a time is never late by their reckoning and holds the
    request that needed the fetch open for as long as it likes. `TimeoutError`, not the
    library's error, because this deadline is ours.

    The ceiling is what makes the failure *visible*: without a deadline this fetch never
    returns at all, and a hung job is a worse test result than a red one."""
    dribbling = scripted_server(trickling(interval=TRICKLE_INTERVAL))

    with anyio.move_on_after(TRICKLE_CEILING) as ceiling:
        async with dribbling as served, library.build(timeout=TRICKLE_TIMEOUT) as transport:
            with pytest.raises(TimeoutError):
                await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)

    assert not ceiling.cancelled_caught, "the fetch outlived the deadline it was given"


@pytest.mark.anyio
async def test_post_sends_its_content_bytes(library: Library) -> None:
    async with scripted_server(replying(200, body=b"ok")) as served, library.build() as transport:
        response = await transport.post(
            f"{served.origin()}/api/auth/get-session", content=b'{"token": "t"}', max_bytes=CAP
        )

    request = served.requests[0]
    assert request.method == "POST"
    assert request.body == b'{"token": "t"}'
    assert request.headers["content-length"] == "14"
    assert response.content == b"ok"


@pytest.mark.anyio
async def test_post_defaults_to_an_empty_body(library: Library) -> None:
    async with scripted_server(replying(200)) as served, library.build() as transport:
        await transport.post(f"{served.origin()}/api/auth/get-session", max_bytes=CAP)

    assert served.requests[0].body == b""


@pytest.mark.parametrize(
    "timeout",
    [0, -1.0, float("nan"), float("inf"), "5", True, None],
    ids=["zero", "negative", "nan", "infinite", "string", "bool", "none"],
)
def test_an_unusable_timeout_is_refused_at_construction(library: Library, timeout: Any) -> None:
    """A verifier's dependencies are validated while the application is being built, never
    on the request that would have needed them."""
    with pytest.raises(ConfigurationError):
        library.build(timeout=timeout)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "cap", [0, -1, 1.5, True, None], ids=["zero", "negative", "float", "bool", "none"]
)
async def test_an_unusable_cap_is_refused_before_anything_is_sent(
    library: Library, cap: Any
) -> None:
    """A cap of zero would refuse every response; a negative one would refuse them faster.
    Both fail closed, which is exactly why they would go unnoticed."""
    async with scripted_server(replying(200)) as served, library.build() as transport:
        with pytest.raises(ValueError):
            await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=cap)

    assert served.requests == []


def test_constructing_without_the_library_names_the_extra_to_install(
    library: Library, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tested by blocking the import rather than by uninstalling: the failure has to be a
    startup `ConfigurationError` that says what to do, not an `ImportError` at first fetch."""
    monkeypatch.setitem(sys.modules, library.name, None)

    with pytest.raises(ConfigurationError) as caught:
        library.build()

    assert f"fastapi-better-auth-bridge[{library.name}]" in str(caught.value)


def test_an_injected_client_needs_no_import_at_all(
    library: Library, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The extra buys the client, not the adapter. A deployment that brings its own is not
    made to install a second copy of the same library."""
    client = library.connect()
    monkeypatch.setitem(sys.modules, library.name, None)

    assert isinstance(library.build(client=client), Transport)


@pytest.mark.anyio
async def test_closing_the_adapter_leaves_an_injected_client_open(library: Library) -> None:
    """Lifecycle belongs to whoever built the client. Closing a shared pool out from under
    the application that lent it to us would be an outage well beyond this library."""
    client = library.connect()

    async with library.build(client=client) as transport:
        assert isinstance(transport, Transport)
    assert not client.is_closed

    await client.aclose()


@pytest.mark.anyio
async def test_closing_the_adapter_closes_the_client_it_built(library: Library) -> None:
    """A fetch on the closed client fails. Under the fix-round-2 contract every non-timeout
    failure - the library's `RuntimeError` for a closed client included - is translated to a
    `TransportFailure`, so what proves the client is shut is the failure, not its exact type."""
    transport = library.build()
    await transport.aclose()

    with pytest.raises(TransportFailure) as caught:
        await transport.get("http://127.0.0.1:1/api/auth/jwks", max_bytes=CAP)
    assert "RuntimeError" in caught.value.reason


@pytest.mark.anyio
async def test_a_finished_adapter_leaves_nothing_behind(library: Library) -> None:
    """`filterwarnings = error` turns a leaked socket into a failure in whichever unlucky
    test the collector happens to be running when it is finally garbage-collected."""
    answer = replying(200, body=b"ok")

    async with scripted_server(answer) as served, library.build() as transport:
        await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        gc.collect()
