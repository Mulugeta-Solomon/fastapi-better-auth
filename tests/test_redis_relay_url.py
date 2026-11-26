"""The relayed Redis URL names the same user and database as the harness URL, and nothing else.

The live cut-reply module points its store at a relay rather than at the harness Redis, and
seeds its keys through the harness URL itself. If the relayed URL lost the credentials or the
database, the store would read another database, or as another user, than the one seeded; if it
kept an option such as `socket_timeout`, that option would win over the deadline the module
passes the store. Each case is read back through redis-py's own URL parser, so "the same" means
what the installed redis-py makes of the two URLs, whichever version that is.
"""

from __future__ import annotations

from typing import Any

import pytest
from redis.asyncio.connection import parse_url

from tests.e2e.redis_relay_url import relay_url

RELAY_PORT = 40123
RELAY_HOST = "127.0.0.1"
DEFAULT_DB = 0
"""What redis-py connects to when a URL names no database."""

WHO_AND_WHERE = ("username", "password", "db")
ADDRESS = ("host", "port")

HARNESS_URLS = {
    "path db": "redis://localhost:56379/3",
    "query db, no path": "redis://localhost:56379?db=1",
    "query db beats path db": "redis://localhost:56379/2?db=5",
    "username and password": "redis://alice:s3cret@localhost:56379/1",
    "password only": "redis://:s3cret@localhost:56379/1",
    "percent-encoded credentials": "redis://al%40ice:p%3Ass%2Fw%25rd@localhost:56379/4",
    "credentials in the query": "redis://localhost:56379/0?username=alice&password=s%26cret",
    # 5.0.1 decodes a query value twice ("a b") and later releases once ("a%20b"): either way, the
    # two URLs must agree under the redis-py installed.
    "a query value encoded twice": "redis://localhost:56379?password=a%2520b&db=1",
    "userinfo beside query credentials": (
        "redis://bob:pw@localhost:56379?username=alice&password=other&db=2"
    ),
    "options beside the database": (
        "redis://localhost:56379/6?socket_timeout=0.5&socket_connect_timeout=0.5"
        "&health_check_interval=3&max_connections=2&retry_on_timeout=true&client_name=x"
    ),
    "no database at all": "redis://localhost:56379",
}


def resolved(url: str) -> dict[str, Any]:
    kwargs: dict[str, Any] = dict(parse_url(url))
    return kwargs


def who_and_where(kwargs: dict[str, Any]) -> tuple[object, ...]:
    return (kwargs.get("username"), kwargs.get("password"), kwargs.get("db", DEFAULT_DB))


@pytest.mark.parametrize("harness_url", HARNESS_URLS.values(), ids=HARNESS_URLS.keys())
def test_the_relayed_url_names_the_same_user_and_database(harness_url: str) -> None:
    harness = resolved(harness_url)
    relayed = resolved(relay_url(harness_url, RELAY_PORT))

    assert who_and_where(relayed) == who_and_where(harness)


@pytest.mark.parametrize("harness_url", HARNESS_URLS.values(), ids=HARNESS_URLS.keys())
def test_the_relayed_url_carries_nothing_else(harness_url: str) -> None:
    relayed = resolved(relay_url(harness_url, RELAY_PORT))

    assert relayed["host"] == RELAY_HOST
    assert relayed["port"] == RELAY_PORT
    assert set(relayed) <= {*ADDRESS, *WHO_AND_WHERE}


@pytest.mark.parametrize("scheme", ["rediss", "unix"])
def test_a_scheme_the_relay_cannot_carry_is_refused_by_name(scheme: str) -> None:
    harness_url = f"{scheme}://alice:s3cret@localhost:56379/0"

    with pytest.raises(ValueError, match=f"'{scheme}'") as refused:
        relay_url(harness_url, RELAY_PORT)

    assert "s3cret" not in str(refused.value)
