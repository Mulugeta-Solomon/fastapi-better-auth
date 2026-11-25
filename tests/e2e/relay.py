"""An in-process TCP relay between a client and Postgres that can stop forwarding, both ways.

A server that has stopped answering - paused, partitioned, wedged - is what a store's abandoned
calls must still wind down against, and `docker pause` is not something a test lane can lean on.
This stands in for it: every connection to the relay is forwarded to the real server until
`stall()`, after which every byte read from either side is held, new connections included (the
driver's cancel request among them). `resume()` lets the held bytes through and forwarding go on.

A connection the client gave up on while the relay was stalled stays open on the relay's side
until it resumes, as it would in a kernel's backlog, so how many connections the relay holds says
nothing about how many the client has; a test reads that from the client's own pool.
"""

from __future__ import annotations

import asyncio
import contextlib


class StallingRelay:
    """Forwards 127.0.0.1:`port` to `host`:`target_port` until stalled."""

    def __init__(self, host: str, target_port: int) -> None:
        self._target = (host, target_port)
        self._flowing = asyncio.Event()
        self._flowing.set()
        self._connections: set[asyncio.Task[None]] = set()
        self._server: asyncio.Server | None = None
        self.port = 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._accepted, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    def stall(self) -> None:
        self._flowing.clear()

    def resume(self) -> None:
        self._flowing.set()

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
            await asyncio.gather(self._pump(reader, upstream), self._pump(from_server, writer))
        except OSError:
            return  # the server refused or dropped the connection: the client sees it closed
        finally:
            for side in (writer, upstream):
                if side is not None:
                    side.close()
            self._connections.discard(task)

    async def _pump(self, source: asyncio.StreamReader, sink: asyncio.StreamWriter) -> None:
        with contextlib.suppress(OSError):
            while data := await source.read(65536):
                await self._flowing.wait()
                sink.write(data)
                await sink.drain()
        sink.close()
