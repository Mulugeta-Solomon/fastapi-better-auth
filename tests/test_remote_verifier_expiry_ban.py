"""Mode C's expiry and ban rungs, which run on the get-session answer after the token compare.

Upstream's get-session refuses an expired session at the route, but a body can still arrive carrying
an `expiresAt` this process's clock has passed, and upstream never reads `banned` at all - so both
rungs are this verifier's own. They are Mode A's rules exactly: `expiresAt <= now` is expired, the
boundary included; a banned user is refused unless `banExpires` has passed, with the lapse
inclusive too; and only `banned` absent, `null` or `false` is "not banned" (D-182).

The same cases as Mode A's (`test_cookie_verifier.py`, `test_cookie_verifier_bans.py`), driven
through a scripted get-session answer rather than a store. The boundaries need an exact instant, so
those legs freeze the wall clock (`tests/wall_clock.py`); a leg one millisecond the other side of it
proves the freeze is live, since the frozen instant is in the real clock's past.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from fastapi_better_auth import SessionExpired, SessionRevoked
from tests.remote_fixtures import (
    FAR_FUTURE,
    FAR_PAST,
    USER_ID,
    RecordingTransport,
    document,
    run,
    verifier,
    with_cookie,
)
from tests.transports import json_reply
from tests.wall_clock import INSTANT, freeze_wall_clock, wire

MILLISECOND = timedelta(milliseconds=1)


def answering(body: dict[str, Any]) -> RecordingTransport:
    return RecordingTransport(json_reply(body))


class TestExpiry:
    @pytest.mark.anyio
    async def test_an_expired_session_is_refused(self) -> None:
        transport = answering(document(expires=FAR_PAST))

        with pytest.raises(SessionExpired) as caught:
            await run(verifier(transport), with_cookie())

        assert "has expired" in caught.value.reason
        assert transport.calls == 1

    @pytest.mark.anyio
    async def test_expiry_is_inclusive_at_the_check_instant(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`expiresAt <= now`: a session expiring at EXACTLY the check instant is expired."""
        freeze_wall_clock(monkeypatch)
        transport = answering(document(expires=wire(INSTANT)))

        with pytest.raises(SessionExpired):
            await run(verifier(transport), with_cookie())

    @pytest.mark.anyio
    async def test_a_session_expiring_just_after_the_check_instant_is_let_through(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        freeze_wall_clock(monkeypatch)
        transport = answering(document(expires=wire(INSTANT + MILLISECOND)))

        session = await run(verifier(transport), with_cookie())

        assert session is not None
        assert session.user.id == USER_ID
        assert session.expires_at == INSTANT + MILLISECOND


class TestBans:
    @pytest.mark.anyio
    @pytest.mark.parametrize("ban_expires", [None, FAR_FUTURE], ids=["permanent", "not-yet-lapsed"])
    async def test_a_banned_user_is_refused(self, ban_expires: str | None) -> None:
        transport = answering(document(banned=True, banExpires=ban_expires))

        with pytest.raises(SessionRevoked) as caught:
            await run(verifier(transport), with_cookie())

        assert "banned" in caught.value.reason

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("banned", "ban_expires"),
        [(None, None), (False, None), (True, FAR_PAST)],
        ids=["banned-null", "not-banned", "ban-lapsed"],
    )
    async def test_an_unbanned_or_lapsed_user_is_let_through(
        self, banned: bool | None, ban_expires: str | None
    ) -> None:
        transport = answering(document(banned=banned, banExpires=ban_expires))

        session = await run(verifier(transport), with_cookie())

        assert session is not None
        assert session.user.id == USER_ID

    @pytest.mark.anyio
    async def test_a_user_with_no_ban_fields_at_all_is_let_through(self) -> None:
        """No admin plugin, no ban columns: `banned` is unknown, which is not banned."""
        body = document()
        del body["user"]["banned"], body["user"]["banExpires"]

        session = await run(verifier(answering(body)), with_cookie())

        assert session is not None

    @pytest.mark.anyio
    async def test_a_ban_lapses_at_exactly_its_expiry_instant(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`banExpires <= now` has lapsed, the boundary included - the same `<=` as expiry."""
        freeze_wall_clock(monkeypatch)
        transport = answering(document(banned=True, banExpires=wire(INSTANT)))

        session = await run(verifier(transport), with_cookie())

        assert session is not None

    @pytest.mark.anyio
    async def test_a_ban_expiring_just_after_the_check_instant_still_holds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        freeze_wall_clock(monkeypatch)
        transport = answering(document(banned=True, banExpires=wire(INSTANT + MILLISECOND)))

        with pytest.raises(SessionRevoked):
            await run(verifier(transport), with_cookie())
