"""What the live lane's stalling relay (`tests/e2e/relay.py`) holds, and what it says it holds.

Two live modules wait on it by condition: the Redis cut-reply module until `holds()` finds the
key of the `GET` it stalled before, and then until `held` is 0. A command that reached the relay
in two reads must still be found, or that wait runs into its backstop and the case fails for a
reason that is not the store's. Loopback usually delivers two writes as one read, so each split
here is made by hand: the first part is written, the relay is seen to hold it, and only then is
the second part written - which the relay can then only read on its own.

A plain local TCP server stands in for the real one; no harness is needed.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import AsyncIterator, Callable

import anyio
import pytest

from tests.e2e.relay import CHUNK_BYTES, StallingRelay

NEEDLE = b"GET cut-reply:revoked-sessions-before-user-B"
SPLIT = len(NEEDLE) // 2
FIRST, SECOND = NEEDLE[:SPLIT], NEEDLE[SPLIT:]
OTHER = b"PING"
BULK_BYTES = 3 * CHUNK_BYTES + 17
"""More than one read's worth, so a resumed relay has several held chunks to pass on in order."""

BACKSTOP = 5.0
"""How long a condition may take to come true before the case fails. Healthy runs take
milliseconds; this only ever runs out red."""
POLL = 0.005


@pytest.fixture
def anyio_backend() -> str:
    """The relay is asyncio's streams; it does not run under trio."""
    return "asyncio"


async def until(condition: Callable[[], bool], what: str) -> None:
    """Poll `condition` until it holds, or fail naming `what` once the backstop is out."""
    give_up = time.monotonic() + BACKSTOP
    while not condition():
        if time.monotonic() > give_up:
            pytest.fail(f"{what} did not happen within {BACKSTOP}s")
        await asyncio.sleep(POLL)


class Upstream:
    """The real server's stand-in: keeps every byte each connection sent, and whether it ended."""

    def __init__(self) -> None:
        self.received: list[bytearray] = []
        self.ended: list[bool] = []
        self.writers: list[asyncio.StreamWriter] = []
        self._server: asyncio.Server | None = None
        self.port = 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._accepted, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def close(self) -> None:
        for writer in self.writers:
            writer.close()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    def got(self, index: int) -> bytes:
        return bytes(self.received[index]) if index < len(self.received) else b""

    async def _accepted(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        index = len(self.received)
        self.received.append(bytearray())
        self.ended.append(False)
        self.writers.append(writer)
        try:
            while data := await reader.read(CHUNK_BYTES):
                self.received[index] += data
            self.ended[index] = True
        except OSError:
            return


class Client:
    """One connection through the relay."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def close(self) -> None:
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except OSError:
            return  # the relay closed it first; it is closed either way


class Rig:
    def __init__(self, upstream: Upstream, relay: StallingRelay) -> None:
        self.upstream = upstream
        self.relay = relay
        self.clients: list[Client] = []

    async def connect(self) -> Client:
        client = Client(*await asyncio.open_connection("127.0.0.1", self.relay.port))
        self.clients.append(client)
        index = len(self.clients) - 1
        await until(lambda: len(self.upstream.received) > index, "the relay connecting upstream")
        return client


@pytest.fixture
async def rig() -> AsyncIterator[Rig]:
    upstream = Upstream()
    await upstream.start()
    relay = StallingRelay("127.0.0.1", upstream.port)
    await relay.start()
    built = Rig(upstream, relay)
    try:
        yield built
    finally:
        relay.resume()
        for client in built.clients:
            await client.close()
        await relay.close()
        await upstream.close()


async def held_in_two_reads(rig: Rig, client: Client) -> None:
    """`FIRST` then `SECOND` from `client`, held as two reads: the second is written only once
    the relay is seen holding the first."""
    rig.relay.stall()
    await client.send(FIRST)
    await until(lambda: rig.relay.holds(FIRST), "the relay holding the first part")
    await client.send(SECOND)


@pytest.mark.anyio
async def test_a_needle_split_across_two_held_reads_is_held(rig: Rig) -> None:
    client = await rig.connect()

    await held_in_two_reads(rig, client)

    await until(lambda: rig.relay.holds(NEEDLE), "holds() finding the needle across two reads")
    assert rig.upstream.got(0) == b""


@pytest.mark.anyio
async def test_a_needle_begun_before_the_stall_and_ending_in_held_bytes_is_held(rig: Rig) -> None:
    """The server has only a prefix of the command: the relay is what keeps it from completing."""
    client = await rig.connect()
    await client.send(FIRST)
    await until(lambda: rig.upstream.got(0) == FIRST, "the first part passing")

    rig.relay.stall()
    await client.send(SECOND)
    await until(lambda: rig.relay.held == 1, "the relay holding the second part")

    assert rig.relay.holds(NEEDLE)


@pytest.mark.anyio
async def test_a_needle_wholly_passed_before_the_stall_is_not_held(rig: Rig) -> None:
    client = await rig.connect()
    await client.send(NEEDLE)
    await until(lambda: rig.upstream.got(0) == NEEDLE, "the needle passing")

    rig.relay.stall()
    await client.send(OTHER)
    await until(lambda: rig.relay.holds(OTHER), "the relay holding what came next")

    assert not rig.relay.holds(NEEDLE)


@pytest.mark.anyio
async def test_bytes_from_the_server_never_match(rig: Rig) -> None:
    await rig.connect()
    rig.relay.stall()

    server_side = rig.upstream.writers[0]
    server_side.write(NEEDLE)
    await server_side.drain()
    await until(lambda: rig.relay.held == 1, "the relay holding the server's bytes")

    assert not rig.relay.holds(NEEDLE)


@pytest.mark.anyio
async def test_one_connection_is_never_joined_to_another(rig: Rig) -> None:
    first, second = await rig.connect(), await rig.connect()
    rig.relay.stall()

    await first.send(FIRST)
    await until(lambda: rig.relay.holds(FIRST), "the relay holding the first connection's part")
    await second.send(SECOND)
    await until(lambda: rig.relay.holds(SECOND), "the relay holding the second connection's part")

    assert not rig.relay.holds(NEEDLE)


@pytest.mark.anyio
async def test_resumed_every_held_byte_reaches_the_server_in_order(rig: Rig) -> None:
    client = await rig.connect()
    bulk = os.urandom(BULK_BYTES)
    await held_in_two_reads(rig, client)
    await until(lambda: rig.relay.holds(NEEDLE), "holds() finding the needle across two reads")
    await client.send(bulk)
    await until(lambda: rig.relay.holds(bulk[-CHUNK_BYTES:]), "the relay holding the bulk")

    rig.relay.resume()

    expected = NEEDLE + bulk
    await until(lambda: len(rig.upstream.got(0)) >= len(expected), "every held byte passing")
    assert rig.upstream.got(0) == expected
    assert rig.relay.held == 0
    assert not rig.relay.holds(NEEDLE)
    assert not rig.relay.holds(FIRST)


@pytest.mark.anyio
async def test_a_hang_up_while_stalled_reaches_the_server_after_what_was_held(rig: Rig) -> None:
    client = await rig.connect()
    await held_in_two_reads(rig, client)
    await until(lambda: rig.relay.holds(NEEDLE), "holds() finding the needle across two reads")

    await client.close()
    await until(lambda: rig.relay.ended == 1, "the relay reading the hang-up while stalled")
    rig.relay.resume()

    await until(lambda: rig.upstream.ended[0], "the hang-up reaching the server")
    assert rig.upstream.got(0) == NEEDLE
    assert rig.relay.held == 0


@pytest.mark.anyio
async def test_a_server_hang_up_while_stalled_reaches_the_client_after_what_was_held(
    rig: Rig,
) -> None:
    client = await rig.connect()
    rig.relay.stall()
    server_side = rig.upstream.writers[0]
    server_side.write(NEEDLE)
    await server_side.drain()
    await until(lambda: rig.relay.held == 1, "the relay holding the server's bytes")

    server_side.close()
    await until(lambda: rig.relay.ended == 1, "the relay reading the server's hang-up")
    rig.relay.resume()

    with anyio.fail_after(BACKSTOP):
        assert await client.reader.read() == NEEDLE
    assert rig.relay.held == 0


@pytest.mark.anyio
async def test_bytes_a_resume_passed_on_still_begin_a_needle(rig: Rig) -> None:
    """Resumed, the relay remembers what it passed on, as it does for bytes never held."""
    client = await rig.connect()
    rig.relay.stall()
    await client.send(FIRST)
    await until(lambda: rig.relay.holds(FIRST), "the relay holding the first part")
    rig.relay.resume()
    await until(lambda: rig.upstream.got(0) == FIRST, "the first part passing")

    rig.relay.stall()
    await client.send(SECOND)
    await until(lambda: rig.relay.held == 1, "the relay holding the second part")

    assert rig.relay.holds(NEEDLE)


@pytest.mark.parametrize("needle", [b"", b"x" * (CHUNK_BYTES + 2)], ids=["empty", "too long"])
def test_a_needle_it_cannot_answer_for_is_refused(needle: bytes) -> None:
    relay = StallingRelay("127.0.0.1", 1)

    with pytest.raises(ValueError, match="a needle must be"):
        relay.holds(needle)
