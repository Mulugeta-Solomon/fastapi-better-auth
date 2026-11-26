"""The URL a store dials to reach the harness Redis through a relay.

A relay (`relay.py`) stands between the store and the harness Redis, so the store is given the
relay's address instead of the server's. Everything else in the harness URL that decides what the
store reads must travel with it, or the store reads another database, as another user, than the
one a test seeded: the credentials and the database. Nothing else does. An option such as
`socket_timeout` in the harness URL would win over a deadline a test passes the store as an
argument (redis-py's own precedence), so what travels is allow-listed, never copied wholesale.

Where redis-py reads each one, at 5.0.1 (the declared floor) and at the locked version alike:

- credentials from the userinfo (`redis://user:password@host`), or from `username` and
  `password` query options, which a non-empty userinfo part overrides;
- the database from a `db` query option, or else from the path (`/1`).

What travels is carried verbatim, still percent-encoded and in its order, so the harness URL and
the relay URL are decoded by the same redis-py in the same way, whichever version that is. (5.0.1
decodes a query value twice and later releases once; carrying the text, not a decoded value,
keeps the two URLs in agreement under both.)
"""

from __future__ import annotations

import urllib.parse

RELAY_HOST = "127.0.0.1"
PLAIN_SCHEME = "redis"
"""The only scheme the relay can stand in for: it forwards plain TCP, and cannot speak TLS."""
CARRIED_OPTIONS = frozenset({"db", "username", "password"})
"""The query options that say which database, as which user. No other option travels."""


def relay_url(harness_url: str, relay_port: int) -> str:
    """`harness_url`'s credentials and database, at the relay on 127.0.0.1:`relay_port`.

    Raises `ValueError` for a scheme other than `redis`, naming the scheme and never the URL,
    which can carry a password.
    """
    parsed = urllib.parse.urlparse(harness_url)
    if parsed.scheme != PLAIN_SCHEME:
        raise ValueError(
            f"the relay forwards plain TCP and cannot carry a {parsed.scheme!r} Redis URL;"
            f" give the harness a {PLAIN_SCHEME}:// URL"
        )
    userinfo, at, _ = parsed.netloc.rpartition("@")
    query = "&".join(_carried(parsed.query))
    relayed = f"{PLAIN_SCHEME}://{userinfo}{at}{RELAY_HOST}:{relay_port}{parsed.path}"
    return f"{relayed}?{query}" if query else relayed


def _carried(query: str) -> list[str]:
    """The fields of `query` that name a carried option, verbatim and in order."""
    return [field for field in query.split("&") if _option_name(field) in CARRIED_OPTIONS]


def _option_name(field: str) -> str:
    """A query field's decoded name, as `urllib.parse.parse_qs` - and so redis-py - reads it."""
    pairs = urllib.parse.parse_qsl(field, keep_blank_values=True)
    return pairs[0][0] if pairs else ""
