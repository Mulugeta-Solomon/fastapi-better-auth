"""An in-process TCP relay between a client and a server that can stop forwarding, both ways.

A server that has stopped answering - paused, partitioned, wedged - is what a store's abandoned
calls must still wind down against, and `docker pause` is not something a test lane can lean on.
This stands in for it, for any server spoken to over plain TCP (Postgres and Redis here): every
connection to the relay is forwarded to the real server until `stall()`, after which every byte
read from either side is held, new connections included (Postgres's cancel request among them).
`resume()` lets the held bytes through, in the order they were read, and forwarding go on.

While stalled the relay goes on reading both sides of every connection and holds all of it, so
what a client sent can be asked about as one stream per connection, however the network split it
into reads. A hang-up or a reset read from a side is held behind that side's bytes, and acted on
only once they have been passed on.

What is held right now can be asked, by a condition rather than a timer: `holds()` says whether
a client is being kept from sending some bytes, and `held` counts every chunk held either way.
That is how a test knows that a command reached the relay and went no further - or, once
resumed, that everything held has been passed on.

A connection the client gave up on while the relay was stalled stays open on the relay's side
until it resumes, as it would in a kernel's backlog, so how many connections the relay holds says
nothing about how many the client has; a test reads that from the client's own pool.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib

CHUNK_BYTES = 65536
TAIL_BYTES = CHUNK_BYTES
"""How much of what each client has had passed on is remembered, so that `holds()` can find bytes
that began before a stall and end in what it holds. A needle may be one byte longer than this."""


class _Stream:
    """One direction of one connection: what was read and is not yet written, in order, and - for
    a client's direction - the last `TAIL_BYTES` that were written."""

    __slots__ = ("arrived", "ended", "from_client", "held", "tail")

    def __init__(self, *, from_client: bool) -> None:
        self.from_client = from_client
        self.held: collections.deque[bytes] = collections.deque()
        self.tail = b""
        self.ended = False
        self.arrived = asyncio.Event()

    def hold(self, data: bytes) -> None:
        self.held.append(data)
        self.arrived.set()

    def end(self) -> None:
        self.ended = True
        self.arrived.set()

    def passed(self, data: bytes) -> None:
        if self.from_client:
            self.tail = (self.tail + data)[-TAIL_BYTES:]

    def holds(self, needle: bytes) -> bool:
        """Whether `needle` is in this client's stream with at least its last byte held.

        Only the last `len(needle) - 1` bytes passed on are searched beside the held ones, so a
        match always ends in held bytes: one wholly passed on is never found.
        """
        if not self.from_client or not self.held:
            return False
        before = self.tail[max(0, len(self.tail) - (len(needle) - 1)) :]
        return needle in before + b"".join(self.held)


class StallingRelay:
    """Forwards 127.0.0.1:`port` to `host`:`target_port` until stalled."""

    def __init__(self, host: str, target_port: int) -> None:
        self._target = (host, target_port)
        self._flowing = asyncio.Event()
        self._flowing.set()
        self._connections: set[asyncio.Task[None]] = set()
        self._streams: set[_Stream] = set()
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
        """How many chunks, either way, are read and not yet passed on. A chunk is one read, so
        a side that sent more while stalled can account for several; 0 means nothing is held."""
        return sum(len(stream.held) for stream in self._streams)

    def holds(self, needle: bytes) -> bool:
        """Whether a client is being kept from sending `needle` right now.

        Each connection's client bytes are read as one stream, so a needle split across reads is
        found. It is held when its last byte is: a needle that began in bytes passed on before the
        stall and ends in held ones counts, because the server cannot have all of it - the relay
        is what keeps that command from completing. A needle wholly passed on does not count,
        bytes from the server never do, and nothing joins one connection's bytes to another's.
        """
        if not needle or len(needle) > TAIL_BYTES + 1:
            raise ValueError(f"a needle must be 1 to {TAIL_BYTES + 1} bytes; got {len(needle)}")
        return any(stream.holds(needle) for stream in self._streams)

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
                self._pump(reader, upstream, _Stream(from_client=True)),
                self._pump(from_server, writer, _Stream(from_client=False)),
            )
        except OSError:
            return  # the server refused or dropped the connection: the client sees it closed
        finally:
            for side in (writer, upstream):
                if side is not None:
                    side.close()
            self._connections.discard(task)

    async def _pump(
        self, source: asyncio.StreamReader, sink: asyncio.StreamWriter, stream: _Stream
    ) -> None:
        """Forward one direction until its end has been passed on, or `sink` has failed."""
        self._streams.add(stream)
        reading = asyncio.ensure_future(self._read(source, sink, stream))
        try:
            await self._flush(sink, stream)
        finally:
            reading.cancel()
            await asyncio.gather(reading, return_exceptions=True)
            self._streams.discard(stream)
            sink.close()

    async def _read(
        self, source: asyncio.StreamReader, sink: asyncio.StreamWriter, stream: _Stream
    ) -> None:
        """Read `source` to its end. A read is written straight on while forwarding with nothing
        held; otherwise it is held, behind what already is, for `_flush` to pass on."""
        # A reset is the end of what this side sends, as a hang-up is; it is held like one. A
        # failed write is `sink` gone, which `_flush` meets too and ends the pump on.
        with contextlib.suppress(OSError):
            while data := await source.read(CHUNK_BYTES):
                if self._flowing.is_set() and not stream.held:
                    stream.passed(data)
                    sink.write(data)
                    await sink.drain()
                else:
                    stream.hold(data)
        stream.end()

    async def _flush(self, sink: asyncio.StreamWriter, stream: _Stream) -> None:
        """Pass on what `stream` holds, in order, whenever forwarding; return once its end has
        been passed on, or once `sink` has failed. A chunk stops counting as held as it is
        written, with no wait in between."""
        with contextlib.suppress(OSError):
            while True:
                await self._flowing.wait()
                if stream.held:
                    data = stream.held.popleft()
                    stream.passed(data)
                    sink.write(data)
                    await sink.drain()
                elif stream.ended:
                    return
                else:
                    stream.arrived.clear()
                    await stream.arrived.wait()
