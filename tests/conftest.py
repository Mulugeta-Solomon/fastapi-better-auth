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


@pytest.fixture(params=ANYIO_BACKENDS)
def client_backend(request: pytest.FixtureRequest) -> str:
    """The backend a `TestClient` runs the app on.

    Separate from `anyio_backend` because a `TestClient` test is synchronous — it drives
    the app from a worker thread rather than running inside the loop, so it cannot take
    the async fixture. Without this the whole FastAPI integration surface, which is where
    a backend difference would actually show up, would be asyncio-only.
    """
    backend = request.param
    assert isinstance(backend, str)
    return backend
