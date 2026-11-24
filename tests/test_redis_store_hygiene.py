"""A Redis read that fails leaves nothing of the session in the store's own frames.

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

from typing import Any

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


class TestTheWalkerSeesTheseFrames:
    @pytest.mark.anyio
    async def test_the_failing_clients_own_frame_is_found(self) -> None:
        """The instrument, proved on this traceback: the fake's `get` holds the key it was asked
        for, so a walk that found nothing anywhere would be a walk that never ran."""
        store = RedisSessionStore(client=Failing({}, TOKEN))

        error = await failed_read(store)

        assert any("get.name" in site for site in holding(error, TOKEN))
