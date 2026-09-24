"""A SQL store's failing lookups tell the operator once per failure kind, until one succeeds (R47).

An under-granted role or a database gone away answers every request with the uniform 401, and the
refusal's `reason` reaches only a handler the deployment wrote. So the store itself warns - but a
database that is down fails every request, and a line per request would bury the log in exactly
the outage it reports. One WARNING per store instance per distinct (driver error class, SQLSTATE);
the next lookup that completes re-arms it. No clock: an outage that never ends is still one line,
and one that ends is announced again only if it comes back.

The failures are the driver's own, wrapped by SQLAlchemy exactly as a live refusal is
(`tests/stores.py::DriverFault`), run through both flavours. Asyncio only: aiosqlite drives the
event loop directly, and `SyncStoreAdapter`'s backend-agnosticism is `test_sync_store_adapter.py`'s.
What the line may carry is `test_log_hygiene_sites.py`'s scenario; this suite counts lines.
"""

from __future__ import annotations

import logging
import pathlib
import sqlite3
from collections.abc import AsyncIterator, Iterator

import pytest

from fastapi_better_auth import AuthServiceUnavailable, SqlAlchemySessionStore, SyncStoreAdapter
from fastapi_better_auth._internal.stores.outage import MAX_REPORTED_KINDS
from tests.log_hygiene import LIBRARY_LOGGER, broken_log_filter, capturing
from tests.stores import (
    FLAVOURS,
    TOKEN,
    USER_ID,
    DeniedError,
    DriverFault,
    ForgedStateError,
    ShiftingStateError,
    StalledError,
    StoreFixture,
)

TEMPLATE_HEAD = "session store lookup could not complete"
SUPPRESSED_HEAD = "session store lookups are failing in more than"
FAILURES = 5

Store = SqlAlchemySessionStore | SyncStoreAdapter


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(params=FLAVOURS)
def flavour(request: pytest.FixtureRequest) -> str:
    kind = request.param
    assert isinstance(kind, str)
    return kind


@pytest.fixture
async def build(tmp_path: pathlib.Path, flavour: str) -> AsyncIterator[StoreFixture]:
    fixture = StoreFixture(tmp_path, flavour)
    yield fixture
    await fixture.aclose()


@pytest.fixture
def warnings() -> Iterator[list[logging.LogRecord]]:
    """Every record emitted during the test; `outage_lines` picks this store's lines out."""
    with capturing() as collected:
        yield collected


def outage_lines(records: list[logging.LogRecord]) -> list[logging.LogRecord]:
    return [
        record
        for record in records
        if record.name == LIBRARY_LOGGER and str(record.msg).startswith(TEMPLATE_HEAD)
    ]


async def broken(build: StoreFixture, monkeypatch: pytest.MonkeyPatch) -> tuple[Store, DriverFault]:
    """A store whose schema is already discovered, over a driver that can be made to refuse."""
    store, _ = build()
    await store.connect()
    return store, DriverFault(build.engines[-1], monkeypatch)


async def fail(store: Store, fault: DriverFault, error: type[sqlite3.Error], times: int) -> None:
    fault.error = error
    for _ in range(times):
        with pytest.raises(AuthServiceUnavailable):
            await store.fetch_session_by_token(TOKEN)


@pytest.mark.anyio
async def test_a_failing_lookup_warns_once_however_often_it_fails(
    build: StoreFixture, monkeypatch: pytest.MonkeyPatch, warnings: list[logging.LogRecord]
) -> None:
    store, fault = await broken(build, monkeypatch)

    await fail(store, fault, DeniedError, FAILURES)

    lines = outage_lines(warnings)
    assert len(lines) == 1
    assert lines[0].levelno == logging.WARNING
    assert lines[0].args is not None
    assert tuple(lines[0].args)[:2] == ("DeniedError", "42501")


@pytest.mark.anyio
async def test_a_lookup_that_completes_re_arms_it(
    build: StoreFixture, monkeypatch: pytest.MonkeyPatch, warnings: list[logging.LogRecord]
) -> None:
    """A miss is a lookup that completed: the database answered, so the outage is over."""
    store, fault = await broken(build, monkeypatch)

    await fail(store, fault, DeniedError, 2)
    fault.error = None
    assert await store.fetch_user_by_id("no-such-user") is None
    await fail(store, fault, DeniedError, 2)

    assert len(outage_lines(warnings)) == 2


@pytest.mark.anyio
async def test_a_different_failure_kind_warns_on_its_own(
    build: StoreFixture, monkeypatch: pytest.MonkeyPatch, warnings: list[logging.LogRecord]
) -> None:
    """A second kind while the first is latched is news; the first coming back is not."""
    store, fault = await broken(build, monkeypatch)

    await fail(store, fault, DeniedError, 2)
    await fail(store, fault, StalledError, 2)
    await fail(store, fault, DeniedError, 2)

    kinds = [tuple(record.args or ())[:2] for record in outage_lines(warnings)]
    assert kinds == [("DeniedError", "42501"), ("StalledError", "none")]


@pytest.mark.anyio
async def test_both_lookups_share_the_latch(
    build: StoreFixture, monkeypatch: pytest.MonkeyPatch, warnings: list[logging.LogRecord]
) -> None:
    store, fault = await broken(build, monkeypatch)

    await fail(store, fault, DeniedError, 1)
    with pytest.raises(AuthServiceUnavailable):
        await store.fetch_user_by_id(USER_ID)

    assert len(outage_lines(warnings)) == 1


@pytest.mark.anyio
async def test_each_store_has_a_latch_of_its_own(
    build: StoreFixture, monkeypatch: pytest.MonkeyPatch, warnings: list[logging.LogRecord]
) -> None:
    """Two stores are two deployments' worth of database: one's line must not silence the other."""
    first, first_fault = await broken(build, monkeypatch)
    second, second_fault = await broken(build, monkeypatch)

    await fail(first, first_fault, DeniedError, 2)
    await fail(second, second_fault, DeniedError, 2)

    assert len(outage_lines(warnings)) == 2


@pytest.mark.anyio
async def test_a_sqlstate_that_is_not_one_is_never_reported(
    build: StoreFixture, monkeypatch: pytest.MonkeyPatch, warnings: list[logging.LogRecord]
) -> None:
    """A driver attribute is still text from outside this package: five characters and a forged
    second log line is not a SQLSTATE, so the line says there was none."""
    store, fault = await broken(build, monkeypatch)

    await fail(store, fault, ForgedStateError, 1)

    (line,) = outage_lines(warnings)
    assert tuple(line.args or ())[:2] == ("ForgedStateError", "none")
    assert "forged" not in line.getMessage()


@pytest.mark.anyio
async def test_a_store_whose_failures_never_repeat_still_cannot_flood(
    build: StoreFixture, monkeypatch: pytest.MonkeyPatch, warnings: list[logging.LogRecord]
) -> None:
    """A SQLSTATE that differs on every read is a new kind every time: the latch reports at most
    `MAX_REPORTED_KINDS` of them, says once that it is holding the rest back, and then is quiet
    until a lookup completes - after which a kind is news again."""
    store, fault = await broken(build, monkeypatch)

    await fail(store, fault, ShiftingStateError, MAX_REPORTED_KINDS * 3)
    fault.error = None
    assert await store.fetch_user_by_id("no-such-user") is None
    await fail(store, fault, ShiftingStateError, 1)

    suppressed = [r for r in warnings if str(r.msg).startswith(SUPPRESSED_HEAD)]
    assert len(outage_lines(warnings)) == MAX_REPORTED_KINDS + 1
    assert [record.args for record in suppressed] == [(MAX_REPORTED_KINDS,)]


@pytest.mark.anyio
async def test_a_report_that_raises_never_changes_the_refusal(
    build: StoreFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reporting is best effort. A log filter that raises inside `logger.warning` must neither
    replace `AuthServiceUnavailable` nor chain it to the `DBAPIError` - whose `str()` carries the
    bound token - as its `__context__`."""
    store, fault = await broken(build, monkeypatch)
    fault.error = DeniedError

    with broken_log_filter(), pytest.raises(AuthServiceUnavailable) as caught:
        await store.fetch_session_by_token(TOKEN)

    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
