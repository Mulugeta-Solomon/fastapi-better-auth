"""Shared fixtures for the JWKS suites: the scripted `client()` builder and the golden signers.

Split out of `test_jwks_client.py` so the wire/key-loading tests there and the cache/staleness
tests in `test_jwks_cache.py` share one builder rather than two that could drift. The transport is
a double on purpose (see `tests/transports.py`): what these suites prove is the client's *policy*
- how many fetches, in what window, behind which lock - not the socket the adapter owns.
"""

from __future__ import annotations

from typing import Any

import anyio

from fastapi_better_auth._internal.jwks import JwksClient
from tests.tokens import ORIGIN, Clock, ed25519_signer, key_set
from tests.transports import Reply, ScriptedTransport

SIGNER = ed25519_signer("cached-1")
ROTATED = ed25519_signer("cached-2")
KEY_SET = key_set(SIGNER)


def client(
    *answers: Reply | BaseException,
    clock: Clock | None = None,
    gate: anyio.Event | None = None,
    algorithms: tuple[str, ...] = ("EdDSA",),
    **settings: Any,
) -> tuple[JwksClient, ScriptedTransport]:
    transport = ScriptedTransport(*answers, gate=gate)
    return (
        JwksClient(
            base_url=ORIGIN,
            transport=transport,
            algorithms=algorithms,
            clock=Clock() if clock is None else clock,
            **settings,
        ),
        transport,
    )
