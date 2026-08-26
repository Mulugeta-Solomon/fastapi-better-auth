"""Async test infrastructure for every lane.

`anyio_backend` is parameterized, so a single `@pytest.mark.anyio` test runs twice —
once per backend. Starlette supports Trio, so an asyncio-only suite would leave half
of our supported surface untested.
"""

from __future__ import annotations

import pytest

ANYIO_BACKENDS = ("asyncio", "trio")


@pytest.fixture(params=ANYIO_BACKENDS)
def anyio_backend(request: pytest.FixtureRequest) -> str:
    backend = request.param
    assert isinstance(backend, str)
    return backend
