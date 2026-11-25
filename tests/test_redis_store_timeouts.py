"""A client the store builds from `url=` has a deadline on every socket operation.

redis-py's floor here is 5.0.1, whose connections default to no socket timeout at all: a Redis
that accepts the connection and then stops answering holds the request - and the worker serving
it - forever. So the store sets both deadlines itself, the caller may override them, and an
option written into the URL's query string wins over both, which is redis-py's own precedence in
`from_url` (`kwargs.update(parse_url(url))`). What wins is held to the same rule as the arguments:
`?socket_timeout=inf` would otherwise build exactly the unbounded wait the deadlines exist to rule
out. A client the caller lends is never touched.
"""

from __future__ import annotations

import asyncio
import gc
import math
import time
import weakref
from collections.abc import Iterator
from typing import Any

import pytest
from redis.exceptions import TimeoutError as RedisTimeoutError

from fastapi_better_auth import ConfigurationError, RedisSessionStore
from fastapi_better_auth._internal.stores import redis_store as redis_store_module
from tests.stores import BuiltRedis, RecordingRedis

URL = "redis://localhost:6379/0"
DEFAULT_CONNECT_SECONDS = 3.0
DEFAULT_READ_SECONDS = 2.0


class Capturing:
    """Stands in for `redis.asyncio.Redis`, keeping what `from_url` was handed."""

    calls: list[tuple[str, dict[str, Any]]]

    def __init__(self) -> None:
        self.calls = []

    def from_url(self, url: str, **kwargs: Any) -> BuiltRedis:
        self.calls.append((url, kwargs))
        return BuiltRedis(kwargs)


@pytest.fixture
def capturing(monkeypatch: pytest.MonkeyPatch) -> Iterator[Capturing]:
    fake = Capturing()
    monkeypatch.setattr(redis_store_module, "_import_redis", lambda: fake)
    yield fake


class TestTheDefaults:
    def test_a_built_client_gets_both_deadlines(self, capturing: Capturing) -> None:
        RedisSessionStore(url=URL)

        ((url, kwargs),) = capturing.calls
        assert url == URL
        assert kwargs == {
            "socket_connect_timeout": DEFAULT_CONNECT_SECONDS,
            "socket_timeout": DEFAULT_READ_SECONDS,
        }

    def test_the_caller_overrides_either(self, capturing: Capturing) -> None:
        RedisSessionStore(url=URL, socket_timeout=0.5, socket_connect_timeout=10)

        ((_url, kwargs),) = capturing.calls
        assert kwargs == {"socket_connect_timeout": 10, "socket_timeout": 0.5}


class TestTheUrlWins:
    """Against the installed redis-py, building the pool and reading what it will connect with.

    Nothing connects: a pool opens its first connection on the first command."""

    @pytest.mark.anyio
    @pytest.mark.parametrize("anyio_backend", ["asyncio"])
    async def test_without_a_query_the_defaults_reach_the_pool(self) -> None:
        async with RedisSessionStore(url=URL) as store:
            options = _pool_options(store)

        assert options["socket_timeout"] == DEFAULT_READ_SECONDS
        assert options["socket_connect_timeout"] == DEFAULT_CONNECT_SECONDS

    @pytest.mark.anyio
    @pytest.mark.parametrize("anyio_backend", ["asyncio"])
    async def test_query_options_win_over_the_defaults_and_over_the_caller(self) -> None:
        url = f"{URL}?socket_timeout=7&socket_connect_timeout=8"

        async with RedisSessionStore(url=url, socket_timeout=1, socket_connect_timeout=1) as store:
            options = _pool_options(store)

        assert options["socket_timeout"] == 7
        assert options["socket_connect_timeout"] == 8

    @pytest.mark.anyio
    @pytest.mark.parametrize("anyio_backend", ["asyncio"])
    async def test_a_query_naming_one_leaves_the_other_at_its_default(self) -> None:
        async with RedisSessionStore(url=f"{URL}?socket_timeout=7") as store:
            options = _pool_options(store)

        assert options["socket_timeout"] == 7
        assert options["socket_connect_timeout"] == DEFAULT_CONNECT_SECONDS


PASSWORD = "pw-Hunter2-sekrit"
USERNAME = "bridge-user"
HOST = "cache-host.invalid"
SECRET_URL = f"redis://{USERNAME}:{PASSWORD}@{HOST}:6379/0"
"""Nothing connects: every case here is refused, or closed, before a first command."""

DEADLINE_OPTIONS = ("socket_timeout", "socket_connect_timeout")


class TestTheUrlIsHeldToTheSameRule:
    """What the URL's query string sets is what the pool uses, so it passes the arguments' rule.

    redis-py parses each of these into a float without complaint: `inf` and `1e999` are a read
    that never times out, `nan` one no comparison can end, `-1` a deadline in the past and `0` a
    read that times out at once - every request refused. Refused at construction instead, naming
    the option and the URL as its source, and echoing neither the URL nor redis-py's own text: a
    Redis URL can carry a password.
    """

    @pytest.mark.parametrize("value", ["inf", "1e999", "nan", "0", "-1"])
    @pytest.mark.parametrize("name", DEADLINE_OPTIONS)
    def test_a_query_deadline_that_is_not_a_positive_number_of_seconds_is_refused(
        self, name: str, value: str
    ) -> None:
        (other,) = [option for option in DEADLINE_OPTIONS if option != name]

        with pytest.raises(ConfigurationError) as caught:
            RedisSessionStore(url=f"{SECRET_URL}?{name}={value}")

        message = str(caught.value)
        assert name in message
        assert other not in message
        assert "query string" in message
        for leaked in (PASSWORD, USERNAME, HOST):
            assert leaked not in message
            assert leaked not in repr(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None

    def test_a_refused_url_leaves_no_client_behind(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The pool is lazy, so the refused client holds no socket; and nothing of this library
        keeps it either - a client still referenced from the traceback would keep the parsed
        password alive in its pool's `connection_kwargs` for as long as the error is."""
        real: Any = redis_store_module._import_redis()  # pyright: ignore[reportPrivateUsage]
        built: list[weakref.ref[Any]] = []

        class Watching:
            @staticmethod
            def from_url(url: str, **kwargs: Any) -> Any:
                client = real.from_url(url, **kwargs)
                built.append(weakref.ref(client))
                return client

        monkeypatch.setattr(redis_store_module, "_import_redis", lambda: Watching)

        with pytest.raises(ConfigurationError):
            RedisSessionStore(url=f"{SECRET_URL}?socket_timeout=inf")
        gc.collect()

        assert len(built) == 1
        assert built[0]() is None, "the refused client is still referenced"


class TestASilentRedis:
    @pytest.mark.anyio
    @pytest.mark.parametrize("anyio_backend", ["asyncio"])
    async def test_a_server_that_accepts_and_never_answers_cannot_hold_a_lookup(self) -> None:
        """The behaviour the deadlines exist for, against a real socket: a listener that accepts
        the connection and then says nothing. Without a read deadline this awaits forever."""
        held: list[asyncio.StreamWriter] = []

        async def silent(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            held.append(writer)

        server = await asyncio.start_server(silent, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        url = f"redis://127.0.0.1:{port}/0"
        started = time.monotonic()
        try:
            async with RedisSessionStore(url=url, socket_timeout=0.2) as store:
                with pytest.raises(RedisTimeoutError) as caught:
                    await asyncio.wait_for(store.fetch_session_by_token("t" * 32), timeout=10)
        finally:
            for writer in held:
                writer.close()
            server.close()
            await server.wait_closed()

        # redis-py's TimeoutError, not the outer `wait_for`'s: the store's own deadline fired.
        assert isinstance(caught.value, RedisTimeoutError)
        assert time.monotonic() - started < 5


class TestRefusals:
    @pytest.mark.parametrize(
        "seconds",
        [0, -1, math.inf, math.nan, True, "2", None],
        ids=["zero", "negative", "inf", "nan", "bool", "string", "none"],
    )
    @pytest.mark.parametrize("name", ["socket_timeout", "socket_connect_timeout"])
    def test_a_deadline_that_is_not_a_positive_number_of_seconds_is_refused(
        self, name: str, seconds: Any, capturing: Capturing
    ) -> None:
        """`None` included: it is redis-py's spelling of "wait forever", the one value this
        option exists to rule out."""
        with pytest.raises(ConfigurationError, match=name):
            RedisSessionStore(url=URL, **{name: seconds})

        assert capturing.calls == [], "a refused argument still built a client"

    @pytest.mark.parametrize("name", ["socket_timeout", "socket_connect_timeout"])
    def test_a_deadline_beside_a_lent_client_is_refused(self, name: str) -> None:
        """A lent client is never modified, so a deadline given with one would be silently
        ignored - and a deadline somebody believes is set is worse than none."""
        changed: dict[str, Any] = {name: 1.0}
        with pytest.raises(ConfigurationError, match=name):
            RedisSessionStore(client=RecordingRedis(), **changed)

    def test_a_lent_client_is_left_exactly_as_it_was(self) -> None:
        client = RecordingRedis()

        RedisSessionStore(client=client)

        assert client.calls == []
        assert vars(client) == vars(RecordingRedis())


def _pool_options(store: RedisSessionStore) -> dict[str, Any]:
    built: Any = vars(store)["_built"]
    return dict(built.connection_pool.connection_kwargs)
