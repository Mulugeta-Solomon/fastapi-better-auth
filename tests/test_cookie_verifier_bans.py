"""B2: the ban check fails CLOSED, and `StoredUser` refuses a `banned` nobody can read.

`_check_ban` tested `banned is not True` and returned, so a record carrying `1`, `"true"`, `"yes"`
or `[1]` authenticated a banned user. Only `None` (the admin plugin is not installed, so there is
no ban state at all) and `False` are "not banned" now; everything else is banned. The constructor
refuses a non-bool outright, and the guard is kept as well - a `StoredUser` can be built outside a
store, and a security check that relies on someone else having validated is a check with a caller
it has never met (D-182).

Both halves of that decision live here: the ladder driven end to end through the verifier, and the
constructor refusal that a third-party store meets first. Split out of `test_cookie_verifier.py`
and `test_store_contract.py`, whose subjects are the pipeline and the record protocol rather than
this one rule spanning both.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest

from fastapi_better_auth import SessionRevoked, StoredUser
from tests.cookies import (
    CAPTURED_TOKEN,
    COOKIE,
    FAR_FUTURE,
    FAR_PAST,
    FakeStore,
    http,
    run,
    sign,
    stored_session,
    stored_user,
    verifier,
)
from tests.stores import USER_ID, wire_user


def a_user(**overrides: Any) -> StoredUser:
    fields: dict[str, Any] = {"id": USER_ID, "payload": wire_user()}
    fields.update(overrides)
    return StoredUser(**fields)


class TestBans:
    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("banned", "ban_expires"),
        [(True, None), (True, FAR_FUTURE)],
        ids=["permanent", "still-active"],
    )
    async def test_a_banned_user_is_refused(
        self, banned: bool, ban_expires: datetime | None
    ) -> None:
        user = stored_user(banned=banned, ban_expires=ban_expires)
        store = FakeStore(sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, user=user)})
        with pytest.raises(SessionRevoked):
            await run(verifier(store=store), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("banned", "ban_expires"),
        [(None, None), (False, None), (True, FAR_PAST)],
        ids=["unknown", "not-banned", "ban-lapsed"],
    )
    async def test_an_unbanned_or_lapsed_user_is_allowed(
        self, banned: bool | None, ban_expires: datetime | None
    ) -> None:
        user = stored_user(banned=banned, ban_expires=ban_expires)
        store = FakeStore(sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, user=user)})

        session = await run(verifier(store=store), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

        assert session is not None

    @pytest.mark.anyio
    @pytest.mark.parametrize("banned", [1, "true", "yes", 2, [1], 0, ""], ids=repr)
    async def test_a_banned_value_that_is_not_a_bool_is_refused(self, banned: Any) -> None:
        """Fail CLOSED: only `None` and `False` are "not banned", and everything else is banned.

        `StoredUser` refuses a non-bool `banned` at construction, so the only way to hold one is
        to plant it past the constructor - which is exactly the record a third-party store built
        before that check existed, or one written by a store that does its own construction. The
        check is kept beside the constructor because a guard that assumes someone else validated
        is a guard with a caller it has never met.
        """
        user = stored_user()
        object.__setattr__(user, "banned", banned)
        store = FakeStore(sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, user=user)})

        with pytest.raises(SessionRevoked):
            await run(verifier(store=store), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))


class TestStoredUserBanField:
    """The other half of the same decision: the record refuses a `banned` before any check reads
    it, so a third-party store meets the rule at construction rather than at the ban rung."""

    @pytest.mark.parametrize("banned", [1, 0, "true", "", "yes", 2, [1], 1.0], ids=repr)
    def test_a_banned_that_is_not_a_bool_is_refused(self, banned: Any) -> None:
        """`banned` decides whether a user is let in, so it may be `True`, `False` or `None` and
        nothing else. A store handing over `1` or `"true"` is handing over a value the verifier
        would have to guess at, and a guess on a ban check is a guess in the wrong direction."""
        with pytest.raises(TypeError, match="banned"):
            a_user(banned=banned)

    @pytest.mark.parametrize("banned", [True, False, None], ids=repr)
    def test_the_three_readable_values_survive_untouched(self, banned: bool | None) -> None:
        assert a_user(banned=banned).banned is banned

    def test_the_refusal_names_the_type_it_was_given(self) -> None:
        """The message is for whoever wrote the store, so it says what arrived, never what it
        held: `banned` is not credential material, but its neighbours in a payload are."""
        with pytest.raises(TypeError) as caught:
            a_user(banned="true")

        assert "str" in str(caught.value)
