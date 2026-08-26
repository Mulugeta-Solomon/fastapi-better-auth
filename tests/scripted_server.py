"""A scripted HTTP/1.1 server on a real localhost socket.

The transport boundary is the one place in this library where an in-process double proves
nothing. An ASGI transport never opens a socket, so it cannot show that a redirect was not
followed, that an oversized body was abandoned *mid-stream*, or that a stalled read raises
the adapter library's own timeout error — all three live below the ASGI line, in the
connection the adapter really opens.

The server is deliberately dumb: it reads one request, writes exactly the bytes the test
scripted, and closes. It records what it saw, so the assertions are about the wire rather
than about a mock. It is `anyio`-native, so the whole suite still runs on both backends.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from http import HTTPStatus
from types import MappingProxyType

import anyio
from anyio.abc import SocketAttribute, SocketStream

BLOCK = 64 * 1024
CRLF = b"\r\n"
HEADER_END = b"\r\n\r\n"
MAX_REQUEST_BYTES = 64 * 1024
NO_HEADERS: Mapping[str, str] = MappingProxyType({})

Responder = Callable[["Received", SocketStream], Awaitable[None]]


@dataclass(frozen=True)
class Received:
    """One request, as the bytes on the socket described it."""

    method: str
    target: str
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class Served:
    """A running server: where to reach it, and everything it has been asked for."""

    port: int
    requests: list[Received]

    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"


def _head(status: int, headers: Mapping[str, str]) -> bytes:
    lines = [f"HTTP/1.1 {status} {HTTPStatus(status).phrase}"]
    lines.extend(f"{key}: {value}" for key, value in headers.items())
    return (CRLF.join(line.encode() for line in lines)) + HEADER_END


def replying(
    status: int, *, headers: Mapping[str, str] = NO_HEADERS, body: bytes = b""
) -> Responder:
    """An ordinary framed answer: `Content-Length` set, connection closed after it."""

    async def respond(request: Received, stream: SocketStream) -> None:
        framing = {"content-length": str(len(body)), "connection": "close"}
        await stream.send(_head(status, {**headers, **framing}) + body)

    return respond


def encoded(*, body: bytes, encoding: str) -> Responder:
    """A body carrying a `Content-Encoding` — the header a server must not send under identity.

    Connection-close framed (no `Content-Length`), so a transport that read the *decoded*
    stream would decompress the whole thing before any cap could compare a length.
    """

    async def respond(request: Received, stream: SocketStream) -> None:
        head = _head(
            200,
            {
                "content-type": "application/json",
                "content-encoding": encoding,
                "connection": "close",
            },
        )
        await stream.send(head + body)

    return respond


def replaying(pairs: Sequence[tuple[str, str]], *, body: bytes = b"") -> Responder:
    """Emit header lines verbatim, duplicates and all — what a `Mapping` cannot express.

    The only way to prove how repeated `WWW-Authenticate` / `Set-Cookie` lines land in
    `TransportResponse.headers`, since a dict would collapse them before the wire.
    """

    async def respond(request: Received, stream: SocketStream) -> None:
        lines = [f"HTTP/1.1 200 {HTTPStatus.OK.phrase}"]
        lines.extend(f"{name}: {value}" for name, value in pairs)
        lines.append(f"content-length: {len(body)}")
        lines.append("connection: close")
        head = (CRLF.join(line.encode() for line in lines)) + HEADER_END
        await stream.send(head + body)

    return respond


def unframed(*, total: int, written: list[int]) -> Responder:
    """A body with NO `Content-Length`: framing is the connection close (RFC 9112 §6.3).

    A cap that consulted `Content-Length` would sail straight past this, which is why the
    oversize test uses it. `written` records how much the server managed to send before the
    client hung up, so "the read was abandoned" is an assertion rather than an inference.
    """

    async def respond(request: Received, stream: SocketStream) -> None:
        await stream.send(
            _head(200, {"content-type": "application/octet-stream", "connection": "close"})
        )
        sent = 0
        try:
            while sent < total:
                block = min(BLOCK, total - sent)
                await stream.send(b"x" * block)
                sent += block
        finally:
            written.append(sent)

    return respond


def stalling() -> Responder:
    """Reads the request and never answers — the read timeout is the only way out."""

    async def respond(request: Received, stream: SocketStream) -> None:
        await anyio.sleep_forever()

    return respond


def hangup() -> Responder:
    """Reads the request and closes without a byte of response.

    A deterministic, cross-platform NON-timeout network failure - the client's own library
    raises "server disconnected" - for proving what the adapter leaves untranslated.
    """

    async def respond(request: Received, stream: SocketStream) -> None:
        return

    return respond


def trickling(*, interval: float) -> Responder:
    """Answers, then dribbles one byte at a time, forever.

    Every byte resets a read timeout, so a per-operation budget alone never fires: this is
    the shape only a deadline over the whole exchange can end.
    """

    async def respond(request: Received, stream: SocketStream) -> None:
        await stream.send(
            _head(200, {"content-type": "application/octet-stream", "connection": "close"})
        )
        while True:
            await anyio.sleep(interval)
            await stream.send(b"x")

    return respond


async def _read_request(stream: SocketStream) -> Received:
    buffer = bytearray()
    while HEADER_END not in buffer:
        buffer += await stream.receive()
        assert len(buffer) <= MAX_REQUEST_BYTES, "scripted server was sent an oversized request"
    head, _, rest = bytes(buffer).partition(HEADER_END)
    lines = head.split(CRLF)
    method, target, _version = lines[0].decode().split(" ", 2)
    headers: dict[str, str] = {}
    for line in lines[1:]:
        key, _, value = line.decode().partition(":")
        headers[key.strip().lower()] = value.strip()
    body = bytearray(rest)
    declared = int(headers.get("content-length", "0"))
    while len(body) < declared:
        body += await stream.receive()
    return Received(
        method=method,
        target=target,
        headers=MappingProxyType(headers),
        body=bytes(body),
    )


def _handler(served: Served, respond: Responder) -> Callable[[SocketStream], Awaitable[None]]:
    async def handle(stream: SocketStream) -> None:
        async with stream:
            with contextlib.suppress(anyio.EndOfStream, anyio.BrokenResourceError):
                request = await _read_request(stream)
                served.requests.append(request)
                await respond(request, stream)

    return handle


@contextlib.asynccontextmanager
async def scripted_server(respond: Responder) -> AsyncGenerator[Served, None]:
    """Serve `respond` on an ephemeral loopback port for the duration of the block."""
    listener = await anyio.create_tcp_listener(local_host="127.0.0.1")
    served = Served(port=listener.extra(SocketAttribute.local_port), requests=[])
    async with listener, anyio.create_task_group() as group:
        group.start_soon(listener.serve, _handler(served, respond))
        try:
            yield served
        finally:
            group.cancel_scope.cancel()
