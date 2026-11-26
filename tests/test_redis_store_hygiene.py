"""A Redis read that fails, or is cancelled, leaves nothing of the session in the store's frames.

The store lets a client failure propagate untranslated - the verifier above turns it into the
uniform refusal - so the client's exception carries a traceback through `fetch_session_by_token`
and, for the watermark read, through the frame that holds the parsed record. A reporter that
captures frame locals (Sentry, `cgitb`, a debug middleware) would find the raw token in `token`,
the key built from it in `key`, and the stored document in `value`, `document` and `record` -
unless those frames scrub them on the way out (D-094). Walked with `holding()` from
`tests/refusal_frames.py`.

Only this package's frames are asserted. The client's own frames are not ours: the fakes below,
like redis-py's `execute_command`, hold the key they were asked for, and nothing a store does
can reach into them.
"""

from __future__ import annotations

from typing import Any, NamedTuple

import anyio
import pytest

from fastapi_better_auth import RedisSessionStore
from tests.refusal_frames import holding
from tests.stores import SESSION_ID, TOKEN, USER_ID, stored

OURS = ("redis_store.py:", "revocation.py:")
WATERMARK_KEY = f"revoked-sessions-before-{USER_ID}"
EMAIL = "seed@example.com"
"""From the stored user: present in `value`, `document` and `record`, and nowhere else."""


class Failing:
    """Answers the keys it was seeded with, and raises for the one it was told to fail on."""

    def __init__(self, values: dict[str, str], fail_on: str) -> None:
        self.values = values
        self.fail_on = fail_on

    async def get(self, name: str) -> Any:
        if name == self.fail_on:
            raise ConnectionError("redis went away mid-read")
        found = self.values.get(name)
        return None if found is None else found.encode()


def ours(exc: BaseException, needle: str) -> list[str]:
    return [site for site in holding(exc, needle) if site.startswith(OURS)]


async def failed_read(store: RedisSessionStore) -> ConnectionError:
    with pytest.raises(ConnectionError) as caught:
        await store.fetch_session_by_token(TOKEN)
    return caught.value


class TestTheSessionReadFails:
    @pytest.mark.anyio
    @pytest.mark.parametrize("prefix", ["", "ba:"], ids=["unprefixed", "prefixed"])
    async def test_no_frame_of_ours_holds_the_token_or_the_key(self, prefix: str) -> None:
        store = RedisSessionStore(client=Failing({}, f"{prefix}{TOKEN}"), key_prefix=prefix)

        error = await failed_read(store)

        assert ours(error, TOKEN) == []
        assert TOKEN not in str(error)


class TestTheWatermarkReadFails:
    @pytest.mark.anyio
    async def test_it_propagates_exactly_as_a_failed_session_read_does(self) -> None:
        """Unavailable, never an accepted session: the record is not returned past a watermark
        the store could not read."""
        store = RedisSessionStore(client=Failing({TOKEN: stored()}, WATERMARK_KEY))

        error = await failed_read(store)

        assert type(error) is ConnectionError

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "needle", [TOKEN, SESSION_ID, EMAIL], ids=["token", "session-id", "user-email"]
    )
    async def test_no_frame_of_ours_holds_the_token_the_key_or_the_document(
        self, needle: str
    ) -> None:
        store = RedisSessionStore(client=Failing({TOKEN: stored()}, WATERMARK_KEY))

        error = await failed_read(store)

        assert ours(error, needle) == []
        assert needle not in str(error)


GUARD = 2.0
"""Seconds before a cancelled lookup counts as hung. Healthy runs take milliseconds."""


class Holding:
    """Answers the keys it was seeded with, and waits forever in the `GET` of the one to hold.

    A Redis that has stopped answering mid-lookup, met where the store meets one: inside an
    await on the client, which is where the verifier's deadline lands. `arrived` is set when the
    held `GET` has been issued, so the cancellation lands there by order, not by a timer.
    """

    def __init__(self, values: dict[str, str], hold: str) -> None:
        self.values = values
        self.hold = hold
        self.arrived = anyio.Event()

    async def get(self, name: str) -> Any:
        if name == self.hold:
            self.arrived.set()
            await anyio.sleep_forever()
        found = self.values.get(name)
        return None if found is None else found.encode()


class Cut(NamedTuple):
    """What a lookup cancelled inside a `GET` did: what it returned, if anything, the
    cancellation it raised, if any, and whether the scope that cancelled it caught it."""

    returned: list[object]
    raised: list[BaseException]
    caught: bool


async def cancelled_inside(client: Holding) -> Cut:
    """Start a lookup, wait until it is held in the chosen `GET`, then cancel its scope.

    The scope catches a cancellation whether or not the store swallowed it - the task group's
    own exit is cancelled too - so `returned` and `raised` are what tell the two apart.
    """
    store = RedisSessionStore(client=client)
    returned: list[object] = []
    raised: list[BaseException] = []

    async def lookup() -> None:
        try:
            returned.append(await store.fetch_session_by_token(TOKEN))
        except anyio.get_cancelled_exc_class() as exc:
            raised.append(exc)
            raise

    with anyio.fail_after(GUARD), anyio.CancelScope() as scope:
        async with anyio.create_task_group() as group:
            group.start_soon(lookup)
            await client.arrived.wait()
            scope.cancel()
    return Cut(returned, raised, scope.cancelled_caught)


class TestALookupCancelledInsideAGet:
    """The verifier's deadline cancels a lookup wherever it is waiting - most often in a `GET`.

    A store that turned that cancellation into an answer - a record past a watermark it never
    read, or a miss - would decide a request with nothing behind the decision, and would stop the
    deadline at the store. The cancellation must propagate, and the frames it unwinds through
    must be scrubbed as a failed read's are.
    """

    @pytest.mark.anyio
    async def test_in_the_session_get_it_propagates_and_returns_nothing(self) -> None:
        cut = await cancelled_inside(Holding({TOKEN: stored()}, TOKEN))

        assert cut.returned == [], "a cancelled lookup returned an answer"
        assert len(cut.raised) == 1
        assert cut.caught

    @pytest.mark.anyio
    async def test_in_the_watermark_get_it_propagates_and_returns_no_record(self) -> None:
        """The dangerous one: the record is in hand and only the watermark is unread."""
        cut = await cancelled_inside(Holding({TOKEN: stored()}, WATERMARK_KEY))

        assert cut.returned == [], "a lookup cancelled before its watermark returned an answer"
        assert len(cut.raised) == 1
        assert cut.caught

    @pytest.mark.anyio
    async def test_in_the_session_get_no_frame_of_ours_holds_the_token_or_the_key(self) -> None:
        cut = await cancelled_inside(Holding({TOKEN: stored()}, TOKEN))

        (cancelled,) = cut.raised
        assert ours(cancelled, TOKEN) == []
        # The instrument, on this traceback: the client's own frame holds the key it was asked.
        assert any("get.name" in site for site in holding(cancelled, TOKEN))

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "needle", [TOKEN, SESSION_ID, EMAIL], ids=["token", "session-id", "user-email"]
    )
    async def test_in_the_watermark_get_no_frame_of_ours_holds_the_session(
        self, needle: str
    ) -> None:
        cut = await cancelled_inside(Holding({TOKEN: stored()}, WATERMARK_KEY))

        (cancelled,) = cut.raised
        assert ours(cancelled, needle) == []
        assert any("get.name" in site for site in holding(cancelled, WATERMARK_KEY))


class TestTheWalkerSeesTheseFrames:
    @pytest.mark.anyio
    async def test_the_failing_clients_own_frame_is_found(self) -> None:
        """The instrument, proved on this traceback: the fake's `get` holds the key it was asked
        for, so a walk that found nothing anywhere would be a walk that never ran."""
        store = RedisSessionStore(client=Failing({}, TOKEN))

        error = await failed_read(store)

        assert any("get.name" in site for site in holding(error, TOKEN))
