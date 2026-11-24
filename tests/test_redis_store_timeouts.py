"""A client the store builds from `url=` has a deadline on every socket operation.

redis-py's floor here is 5.0.1, whose connections default to no socket timeout at all: a Redis
that accepts the connection and then stops answering holds the request - and the worker serving
it - forever. So the store sets both deadlines itself, the caller may override them, and an
option written into the URL's query string wins over both, which is redis-py's own precedence in
`from_url` (`kwargs.update(parse_url(url))`). A client the caller lends is never touched.
"""

from __future__ import annotations

import math
from collections.abc import Iterator
from typing import Any

import pytest

from fastapi_better_auth import ConfigurationError, RedisSessionStore
from fastapi_better_auth._internal.stores import redis_store as redis_store_module
from tests.stores import RecordingRedis

URL = "redis://localhost:6379/0"
DEFAULT_CONNECT_SECONDS = 3.0
DEFAULT_READ_SECONDS = 2.0


class Capturing:
    """Stands in for `redis.asyncio.Redis`, keeping what `from_url` was handed."""

    calls: list[tuple[str, dict[str, Any]]]

    def __init__(self) -> None:
        self.calls = []

    def from_url(self, url: str, **kwargs: Any) -> RecordingRedis:
        self.calls.append((url, kwargs))
        return RecordingRedis()


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
