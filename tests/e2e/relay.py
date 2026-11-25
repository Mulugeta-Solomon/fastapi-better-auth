"""An in-process TCP relay between a client and a server that can stop forwarding, both ways.

A server that has stopped answering - paused, partitioned, wedged - is what a store's abandoned
calls must still wind down against, and `docker pause` is not something a test lane can lean on.
This stands in for it, for any server spoken to over plain TCP (Postgres and Redis here): every
connection to the relay is forwarded to the real server until `stall()`, after which every byte
read from either side is held, new connections included (Postgres's cancel request among them).
`resume()` lets the held bytes through and forwarding go on.

What is held right now can be asked: `holds()` says whether bytes a client sent are being held,
and `held` counts every chunk held either way. That is how a test knows, by a condition rather
than a timer, that a command reached the relay and went no further - or, once resumed, that
everything held has been passed on.

A connection the client gave up on while the relay was stalled stays open on the relay's side
until it resumes, as it would in a kernel's backlog, so how many connections the relay holds says
nothing about how many the client has; a test reads that from the client's own pool.
"""

from __future__ import annotations

import asyncio
import contextlib

CHUNK_BYTES = 65536


class _Chunk:
    """Bytes read from one side and not yet written to the other. Compared by identity."""

    __slots__ = ("data", "from_client")

    def __init__(self, data: bytes, *, from_client: bool) -> None:
        self.data = data
        self.from_client = from_client


class StallingRelay:
    """Forwards 127.0.0.1:`port` to `host`:`target_port` until stalled."""

    def __init__(self, host: str, target_port: int) -> None:
        self._target = (host, target_port)
        self._flowing = asyncio.Event()
        self._flowing.set()
        self._connections: set[asyncio.Task[None]] = set()
        self._held: list[_Chunk] = []
        self._server: asyncio.Server | None = None
        self.port = 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._accepted, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    def stall(self) -> None:
        self._flowing.clear()

    def resume(self) -> None:
        self._flowing.set()

    @property
    def held(self) -> int:
        """How many chunks, either way, are read and not yet passed on."""
        return len(self._held)

    def holds(self, needle: bytes) -> bool:
        """Whether bytes a client sent that contain `needle` are being held right now."""
        return any(chunk.from_client and needle in chunk.data for chunk in self._held)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
        for connection in tuple(self._connections):
            connection.cancel()
        await asyncio.gather(*self._connections, return_exceptions=True)

    async def _accepted(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        self._connections.add(task)
        upstream: asyncio.StreamWriter | None = None
        try:
            from_server, upstream = await asyncio.open_connection(*self._target)
            await asyncio.gather(
                self._pump(reader, upstream, from_client=True),
                self._pump(from_server, writer, from_client=False),
            )
        except OSError:
            return  # the server refused or dropped the connection: the client sees it closed
        finally:
            for side in (writer, upstream):
                if side is not None:
                    side.close()
            self._connections.discard(task)

    async def _pump(
        self, source: asyncio.StreamReader, sink: asyncio.StreamWriter, *, from_client: bool
    ) -> None:
        with contextlib.suppress(OSError):
            while data := await source.read(CHUNK_BYTES):
                await self._passable(_Chunk(data, from_client=from_client))
                sink.write(data)
                await sink.drain()
        sink.close()

    async def _passable(self, chunk: _Chunk) -> None:
        """Return at once while forwarding; while stalled, hold `chunk` until resumed."""
        if self._flowing.is_set():
            return
        self._held.append(chunk)
        try:
            await self._flowing.wait()
        finally:
            self._held.remove(chunk)
