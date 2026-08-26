"""Proves the async lane actually executes on both backends, not just that pytest
collected two parameterizations: an asyncio loop is running iff the backend says so."""

from __future__ import annotations

import asyncio

import anyio
import anyio.lowlevel
import pytest


def asyncio_loop_is_running() -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


@pytest.mark.anyio
async def test_backend_under_test_is_the_one_running(anyio_backend: str) -> None:
    await anyio.lowlevel.checkpoint()
    assert asyncio_loop_is_running() is (anyio_backend == "asyncio")


@pytest.mark.anyio
async def test_anyio_primitives_work_on_both_backends() -> None:
    lock = anyio.Lock()
    async with lock:
        assert lock.locked()
