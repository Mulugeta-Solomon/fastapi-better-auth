"""Shared fixtures for the JWKS suites: the scripted `client()` builder and the golden signers.

Split out of `test_jwks_client.py` so the wire/key-loading tests there and the cache/staleness
tests in `test_jwks_cache.py` share one builder rather than two that could drift. The transport is
a double on purpose (see `tests/transports.py`): what these suites prove is the client's *policy*
- how many fetches, in what window, behind which lock - not the socket the adapter owns.
"""

from __future__ import annotations

from typing import Any

import anyio
import pytest

from fastapi_better_auth._internal import jwks
from fastapi_better_auth._internal.jwks import JwksClient
from tests.tokens import ORIGIN, Clock, ed25519_signer, key_set
from tests.transports import Reply, ScriptedTransport

SIGNER = ed25519_signer("cached-1")
ROTATED = ed25519_signer("cached-2")
KEY_SET = key_set(SIGNER)


def wind_jwks_clock(monkeypatch: pytest.MonkeyPatch, start: float = 1000.0) -> Clock:
    """The monotonic clock every `JwksClient` built without `clock=` reads, wound by hand.

    For a `JwtVerifier` built through its public constructor, which takes no clock: the cache
    and staleness rules are then driven by `Clock.advance` until the test ends, with no real
    waiting. Only the key-set client's clock moves - the event loop's and PyJWT's do not - and
    where that clock is read is `jwks.py`'s business, so no suite names the patch point itself.
    """
    clock = Clock(start)
    monkeypatch.setattr(jwks, "monotonic_clock", clock)
    return clock


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
