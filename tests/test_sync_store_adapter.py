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
import time
from collections.abc import Iterator, Mapping, Sequence
from types import SimpleNamespace
from typing import Any

import anyio
import pytest
from sqlalchemy import Engine

from fastapi_better_auth import ConfigurationError, SyncStoreAdapter
from fastapi_better_auth._internal.stores.sqlalchemy_store import (
    DEFAULT_MAX_CONCURRENCY,
    _pool_ceiling,  # pyright: ignore[reportPrivateUsage]
)
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


# --- concurrency: cancellation and the worker-thread ceiling (E3) ----------------------

FAKE_COLUMNS: dict[str, tuple[str, ...] | None] = {
    "session": (
        "id",
        "token",
        "expiresAt",
        "userId",
        "createdAt",
        "updatedAt",
        "ipAddress",
        "userAgent",
    ),
    "user": ("id", "name", "email", "emailVerified", "image", "createdAt", "updatedAt"),
}
"""The columns `plan_for` needs to build both statements, so a `GatedSyncAdapter` never has to
touch the real database - the gate, not a slow query, is what makes the worker thread block."""


class GatedSyncAdapter(SyncStoreAdapter):
    """A `SyncStoreAdapter` whose worker-thread query blocks on a gate we hold and counts how many
    threads are inside it at once, so `abandon_on_cancel` and the limiter ceiling are observable
    without a real slow database. The `run_sync` wiring (the limiter, the abandon flag) is the
    parent's; only the two sync functions it runs are replaced."""

    def __init__(
        self,
        engine: Engine,
        *,
        max_concurrency: int,
        gate: threading.Event,
        max_wait: float,
    ) -> None:
        super().__init__(engine=engine, max_concurrency=max_concurrency)
        self._gate = gate
        self._max_wait = max_wait
        self._counter_lock = threading.Lock()
        self._entered = 0
        self._peak = 0

    def _inspected(self) -> dict[str, tuple[str, ...] | None]:
        return dict(FAKE_COLUMNS)

    def _queried(self, statement: Any, params: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        with self._counter_lock:
            self._entered += 1
            self._peak = max(self._peak, self._entered)
        try:
            self._gate.wait(self._max_wait)
        finally:
            with self._counter_lock:
                self._entered -= 1
        return []

    @property
    def peak(self) -> int:
        with self._counter_lock:
            return self._peak

    @property
    def entered(self) -> int:
        with self._counter_lock:
            return self._entered


@pytest.mark.anyio
async def test_a_cancelled_lookup_returns_promptly_and_is_honoured(engine: Engine) -> None:
    """E3 (D-198). A lookup runs its DBAPI call on a worker thread; cancelled - a client
    disconnect, a request deadline - the caller must return promptly rather than block until the
    sync call finishes, which is `run_sync(..., abandon_on_cancel=True)`. RED before the fix: the
    default `abandon_on_cancel=False` makes the thread uncancellable, so the cancel scope cannot
    fire and the lookup blocks on the worker thread to completion (~`max_wait`)."""
    gate = threading.Event()  # never set: the "DB call" hangs for the whole max_wait
    adapter = GatedSyncAdapter(engine, max_concurrency=4, gate=gate, max_wait=2.0)
    await adapter.connect()  # discover the schema up front, so only the query path is under test

    start = time.perf_counter()
    with anyio.move_on_after(0.3) as scope:
        await adapter.fetch_session_by_token(TOKEN)
    elapsed = time.perf_counter() - start

    assert scope.cancelled_caught, "the lookup was not cancellable; abandon_on_cancel is not set"
    assert elapsed < 1.5, "the cancelled lookup blocked on the worker thread instead of returning"
    gate.set()  # release the abandoned worker thread so it exits cleanly


@pytest.mark.anyio
async def test_concurrent_lookups_are_bounded_by_the_adapter_limiter(engine: Engine) -> None:
    """E3 (D-198). The adapter's own `CapacityLimiter` caps how many lookups run on worker threads
    at once, so a flood of concurrent (or cancelled) lookups cannot exceed the connection pool and
    starve a legitimate request with a checkout timeout. With K tokens, K+1 concurrent lookups run
    at most K threads and queue the last on the limiter. RED before the fix: without
    `limiter=self._limiter` the process-wide thread pool (40) lets all K+1 run at once."""
    ceiling = 3
    gate = threading.Event()  # held until every worker is accounted for
    adapter = GatedSyncAdapter(engine, max_concurrency=ceiling, gate=gate, max_wait=10.0)
    await adapter.connect()  # schema discovery uses a token too; get it out of the way first

    async def look_up() -> None:
        await adapter.fetch_session_by_token(TOKEN)

    async with anyio.create_task_group() as group:
        for _ in range(ceiling + 1):
            group.start_soon(look_up)
        try:
            with anyio.fail_after(5):
                while adapter.peak < ceiling:
                    await anyio.sleep(0.02)
            await anyio.sleep(0.2)  # give a would-be (K+1)th thread time to (wrongly) enter
            assert adapter.entered == ceiling, (
                f"{adapter.entered} threads ran at once, over {ceiling}"
            )
            assert adapter.peak == ceiling, f"peak {adapter.peak} exceeded the limiter's {ceiling}"
        finally:
            gate.set()  # release every worker so the group can finish

    assert adapter.peak == ceiling


# --- limiter sizing (E3) ----------------------------------------------------------------


@pytest.mark.parametrize(
    "bad", [0, -1, "8", 8.0, True], ids=["zero", "negative", "str", "float", "bool"]
)
def test_max_concurrency_must_be_a_positive_int_or_none(engine: Engine, bad: object) -> None:
    with pytest.raises(ConfigurationError):
        SyncStoreAdapter(engine=engine, max_concurrency=bad)  # type: ignore[arg-type]


def test_the_default_bound_is_sized_to_the_engine_pool(engine: Engine) -> None:
    """A `QueuePool` states its size and overflow, so the limiter matches what the pool can serve
    and a flood queues on the limiter, not on a pool checkout that times out. The count is fixed
    at construction; the `CapacityLimiter` itself is built lazily inside the loop (it binds to the
    backend on construction, and the adapter is built in synchronous setup)."""
    adapter = SyncStoreAdapter(engine=engine)

    tokens = adapter._limiter_tokens  # pyright: ignore[reportPrivateUsage]
    assert tokens == _pool_ceiling(engine)
    assert tokens == 15  # QueuePool default: size 5 + overflow 10


def test_an_explicit_bound_wins_over_the_pool(engine: Engine) -> None:
    adapter = SyncStoreAdapter(engine=engine, max_concurrency=2)

    tokens = adapter._limiter_tokens  # pyright: ignore[reportPrivateUsage]
    assert tokens == 2


def test_the_adapter_is_constructable_outside_an_event_loop(engine: Engine) -> None:
    """Regression: an `anyio.CapacityLimiter` binds to the backend at construction, so building it
    in `__init__` raises outside a loop on the anyio floor - and operators build stores in
    synchronous setup. Construction must not touch the loop; the limiter is created lazily on first
    use. This test runs outside any event loop, so it fails if construction is made eager again."""
    adapter = SyncStoreAdapter(engine=engine)

    assert adapter._limiter is None  # pyright: ignore[reportPrivateUsage]  # not built until first use


def test_a_pool_that_cannot_state_its_size_falls_back_to_the_default() -> None:
    """`NullPool`/`StaticPool` expose no `size()`, and a pool whose `size()` is unusable is treated
    the same: the bound is the conservative default rather than an unbounded thread count."""
    no_size = SimpleNamespace(pool=SimpleNamespace())
    zero_size = SimpleNamespace(pool=SimpleNamespace(size=lambda: 0))

    def raises() -> int:
        raise RuntimeError("this pool cannot say")

    boom = SimpleNamespace(pool=SimpleNamespace(size=raises))

    assert _pool_ceiling(no_size) == DEFAULT_MAX_CONCURRENCY  # type: ignore[arg-type]
    assert _pool_ceiling(zero_size) == DEFAULT_MAX_CONCURRENCY  # type: ignore[arg-type]
    assert _pool_ceiling(boom) == DEFAULT_MAX_CONCURRENCY  # type: ignore[arg-type]
