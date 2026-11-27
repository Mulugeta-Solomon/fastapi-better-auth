"""Copies of the two auth tables in a schema of a case's own, and a poll that waits on the server.

A live case that locks a table must never lock `public.session`: the auth server and every other
lane read it. It locks a copy instead, in a schema nobody else reads, dropped however the case
ends. `until` waits for a condition the server reports, with a backstop, rather than sleeping for
a guess.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

TABLES = ('"user"', "session")
BACKSTOP = 10.0
"""How long a wait for a condition may take before the case fails. Healthy runs take tens of
milliseconds; this only ever runs out red."""
POLL = 0.05


@asynccontextmanager
async def table_copies(observer: AsyncEngine, prefix: str) -> AsyncGenerator[str, None]:
    """Empty copies of `user` and `session` in a new schema, yielded by name, then dropped.

    `INCLUDING ALL` copies the column defaults, and a default is what makes discovery wait on a
    lock of the table (`pg_get_expr` opens it)."""
    name = f"{prefix}_{secrets.token_hex(6)}"
    async with observer.begin() as connection:
        await connection.execute(text(f"CREATE SCHEMA {name}"))
        for table in TABLES:
            await connection.execute(
                text(f"CREATE TABLE {name}.{table} (LIKE public.{table} INCLUDING ALL)")
            )
    try:
        yield name
    finally:
        async with observer.begin() as connection:
            await connection.execute(text(f"DROP SCHEMA {name} CASCADE"))


async def until(condition: Callable[[], Awaitable[bool]], what: str) -> None:
    """Poll `condition` until it holds; fail, naming `what`, if `BACKSTOP` runs out first."""
    give_up = time.monotonic() + BACKSTOP
    while not await condition():
        if time.monotonic() > give_up:
            pytest.fail(f"{what} did not happen within {BACKSTOP}s")
        await asyncio.sleep(POLL)
