"""The shipped transports against the live Better Auth server.

The conformance suite drives a scripted socket, which is enough to pin every rule the
`Transport` docstring states — but it is a socket this repository wrote both ends of. This
lane fetches the harness's real JWKS with both adapters, so "it works against a real server"
is a test rather than an extrapolation.
"""

import json

import pytest

from fastapi_better_auth import Httpx2Transport, HttpxTransport, ResponseTooLarge

pytestmark = pytest.mark.e2e

ADAPTERS = (HttpxTransport, Httpx2Transport)
MAX_JWKS_BYTES = 64 * 1024
TINY_CAP = 8


@pytest.mark.anyio
@pytest.mark.parametrize("adapter", ADAPTERS, ids=["httpx", "httpx2"])
async def test_the_live_key_set_is_fetched_and_parses(
    harness: str, adapter: type[HttpxTransport] | type[Httpx2Transport]
) -> None:
    async with adapter() as transport:
        response = await transport.get(f"{harness}/api/auth/jwks", max_bytes=MAX_JWKS_BYTES)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert json.loads(response.content)["keys"]


@pytest.mark.anyio
@pytest.mark.parametrize("adapter", ADAPTERS, ids=["httpx", "httpx2"])
async def test_the_cap_holds_against_a_real_server(
    harness: str, adapter: type[HttpxTransport] | type[Httpx2Transport]
) -> None:
    """A cap smaller than the real key set, against the real server that serves it."""
    async with adapter() as transport:
        with pytest.raises(ResponseTooLarge):
            await transport.get(f"{harness}/api/auth/jwks", max_bytes=TINY_CAP)
