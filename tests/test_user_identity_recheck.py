"""D5: the by-id user lookup re-checks the returned row's id against the one asked for (SA-D5).

`session_from` `compare_digest`s the returned session token against the presented one, closing the
collation-fold a `WHERE token = :token` delegates to the DB. `user_from`'s by-id path
(`WHERE id = :user_id`) had no such re-check, so a case/accent/pad-insensitive collation could fold
a different user onto the row. `check_identity` adds the symmetric guard - constant-time - and
`fetch_user_by_id` turns it on. The session-JOIN path leaves it off: there the user is bound by the
FK join, and its `subject` is the session token, not the user's id.
"""

from __future__ import annotations

import logging

import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy import create_engine

from fastapi_better_auth import SyncStoreAdapter
from fastapi_better_auth._internal.stores.sqlalchemy_core import (
    SESSION_COLUMNS,
    USER_COLUMNS,
    USER_PREFIX,
    plan_for,
    user_from,
)

SUBJECT = "u1"


def _plan():
    return plan_for("session", "user", None, {"session": SESSION_COLUMNS, "user": USER_COLUMNS})


def _user_row(identifier: str) -> dict[str, object]:
    plan = _plan()
    row: dict[str, object] = {f"{USER_PREFIX}{name}": None for name in plan.user_columns}
    row[f"{USER_PREFIX}id"] = identifier
    return row


class TestUserFromIdentityGuard:
    def test_a_folded_id_is_a_miss_under_the_guard(self, caplog: pytest.LogCaptureFixture) -> None:
        """The RED: a row whose id is not the subject it was looked up under is refused, not
        returned - the collation-fold a `WHERE id = :subject` would otherwise honour."""
        plan = _plan()
        folded = _user_row("U1")  # a case-folding collation could return this for subject "u1"

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            assert user_from([folded], plan, SUBJECT, check_identity=True) is None

        assert any(
            "different user than the id it was found under" in entry.getMessage()
            for entry in caplog.records
        )

    def test_a_matching_id_passes_the_guard(self) -> None:
        plan = _plan()
        record = user_from([_user_row(SUBJECT)], plan, SUBJECT, check_identity=True)

        assert record is not None
        assert record.id == SUBJECT

    def test_the_join_path_default_does_not_re_check(self) -> None:
        """The session-JOIN call leaves check_identity off: its `subject` is the session token, and
        the user's id (the userId) must not be compared against it, or every joined lookup breaks."""
        plan = _plan()
        record = user_from([_user_row("some-user-id")], plan, "a-session-token")

        assert record is not None
        assert record.id == "some-user-id"


class TestFetchUserByIdEnablesTheGuard:
    @pytest.mark.anyio
    async def test_a_store_by_id_lookup_refuses_a_folded_row(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Proof the guard is wired: `fetch_user_by_id` passes check_identity=True, so a store that
        answered a folded id (simulated here) returns a miss rather than the wrong user."""
        store = SyncStoreAdapter(engine=create_engine("sqlite://"))
        plan = _plan()
        # Pre-seed the plan so `_ready` needs no real reflection, and stub the row source.
        store._plan = plan  # pyright: ignore[reportPrivateUsage]

        async def folded_select(statement: object, params: object) -> list[dict[str, object]]:
            return [_user_row("U1")]

        monkeypatch.setattr(store, "_select", folded_select)

        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            assert await store.fetch_user_by_id("u1") is None

        assert any(
            "different user than the id it was found under" in entry.getMessage()
            for entry in caplog.records
        )

    @pytest.mark.anyio
    async def test_a_store_by_id_lookup_returns_a_matching_row(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = SyncStoreAdapter(engine=create_engine("sqlite://"))
        store._plan = _plan()  # pyright: ignore[reportPrivateUsage]

        async def matching_select(statement: object, params: object) -> list[dict[str, object]]:
            return [_user_row("u1")]

        monkeypatch.setattr(store, "_select", matching_select)

        record = await store.fetch_user_by_id("u1")
        assert record is not None
        assert record.id == "u1"
