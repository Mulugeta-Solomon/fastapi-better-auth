"""`SyncStoreAdapter` on both anyio backends, and the one property that is its whole reason.

Everything the adapter *answers* is covered alongside the async store in
`test_sqlalchemy_store.py`, which runs both flavours through the same cases. What that suite
cannot show is what this module exists for: the adapter uses no async driver, so unlike the
async store it runs under trio as well as asyncio - and it must never run the query on the event
loop, because a synchronous DBAPI call there stops every other task in the process for the
duration of the round trip.
"""

from __future__ import annotations

import pathlib
import threading
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine

from fastapi_better_auth import SyncStoreAdapter
from tests.stores import TOKEN, USER_ID, StatementLog, build_schema, sync_engine


@pytest.fixture
def engine(tmp_path: pathlib.Path) -> Iterator[Engine]:
    path = tmp_path / "harness.sqlite"
    build_schema(path)
    built = sync_engine(path)
    yield built
    built.dispose()


@pytest.mark.anyio
async def test_it_answers_on_every_supported_backend(engine: Engine) -> None:
    """asyncio and trio both, through `anyio.to_thread` - which is what makes this adapter the
    answer for a deployment whose database has no async driver at all."""
    adapter = SyncStoreAdapter(engine=engine)

    record = await adapter.fetch_session_by_token(TOKEN)
    user = await adapter.fetch_user_by_id(USER_ID)

    assert record is not None
    assert record.user_id == USER_ID
    assert record.user is not None
    assert user is not None


@pytest.mark.anyio
async def test_no_statement_runs_on_the_event_loop(engine: Engine) -> None:
    """The thread each statement was executed on is the evidence. Schema discovery counts too:
    it is a round trip like any other, and it happens on the first request."""
    log = StatementLog()
    log.attach(engine)
    adapter = SyncStoreAdapter(engine=engine)

    await adapter.fetch_session_by_token(TOKEN)

    assert log.threads, "no statement was executed; this proves nothing"
    assert all(ident != threading.get_ident() for ident in log.threads)
