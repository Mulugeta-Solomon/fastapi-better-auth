"""The URL a store dials to reach the harness Redis through a relay (`relay.py`)."""

from __future__ import annotations

import urllib.parse

RELAY_HOST = "127.0.0.1"


def relay_url(harness_url: str, relay_port: int) -> str:
    """`harness_url`'s database, at the relay on 127.0.0.1:`relay_port`."""
    database = urllib.parse.urlsplit(harness_url).path or "/0"
    return f"redis://{RELAY_HOST}:{relay_port}{database}"
