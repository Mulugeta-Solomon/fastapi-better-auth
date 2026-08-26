"""One conformance suite, run against every adapter this library ships.

`httpx` and `httpx2` are the same API under two names, so the adapters differ by an import
and nothing else — which is exactly the situation where a fix lands in one and not the other.
Every obligation in the `Transport` docstring is asserted here once and parameterized over
both, against a real socket: an in-process ASGI double cannot show that a redirect was not
followed, that an oversized body was abandoned mid-stream, or that a stalled read raises the
adapter library's own timeout error.
"""

from __future__ import annotations

import gc
import sys
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Protocol

import anyio
import httpx
import httpx2
import pytest
from typing_extensions import Self

from fastapi_better_auth import (
    ConfigurationError,
    Httpx2Transport,
    HttpxTransport,
    ResponseTooLarge,
    Transport,
)
from tests.scripted_server import replying, scripted_server, stalling, trickling, unframed

CAP = 4096
OVERSIZED = 8 * 1024 * 1024
REDIRECTS = (301, 302, 303, 307, 308)
STALL_TIMEOUT = 0.25
TRICKLE_CEILING = 5.0
TRICKLE_INTERVAL = 0.05
TRICKLE_TIMEOUT = 0.5


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


LIBRARIES = (
    Library(
        name="httpx",
        build=HttpxTransport,
        connect=httpx.AsyncClient,
        timeout_error=httpx.TimeoutException,
    ),
    Library(
        name="httpx2",
        build=Httpx2Transport,
        connect=httpx2.AsyncClient,
        timeout_error=httpx2.TimeoutException,
    ),
)


@pytest.fixture(params=LIBRARIES, ids=[each.name for each in LIBRARIES])
def library(request: pytest.FixtureRequest) -> Library:
    chosen = request.param
    assert isinstance(chosen, Library)
    return chosen


def test_both_adapters_are_shipped() -> None:
    """A suite parameterized over one adapter would prove nothing about the other."""
    assert {each.name for each in LIBRARIES} == {"httpx", "httpx2"}


def test_an_adapter_satisfies_the_protocol(library: Library) -> None:
    assert isinstance(library.build(), Transport)


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
async def test_a_stalled_response_raises_the_libraries_own_timeout(library: Library) -> None:
    """Untranslated on purpose: the verifier above turns this into `AuthServiceUnavailable`,
    because only it knows what a failed fetch means to the request that caused it."""
    stalled = library.build(timeout=STALL_TIMEOUT)

    async with scripted_server(stalling()) as served, stalled as transport:
        with pytest.raises(library.timeout_error):
            await transport.get(f"{served.origin()}/api/auth/jwks", max_bytes=CAP)


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
    transport = library.build()
    await transport.aclose()

    with pytest.raises(RuntimeError):
        await transport.get("http://127.0.0.1:1/api/auth/jwks", max_bytes=CAP)


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
