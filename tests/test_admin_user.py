"""`AdminUser` and `Session.impersonated_by` through all three modes, on the shapes they arrive in.

`tests/test_models.py` pins the model against a payload handed straight to `model_validate`. That
proves the fields parse; it does not prove any *verifier* carries them, and the three modes reach
the user object by three different roads - a store record (A), decoded JWT claims (B), and the
`user` half of a `get-session` body (C). Each road is driven here, with the plugin's four fields
present, absent, and lapsed.

The session half is deliberately asymmetric and that is the point of the `None` assertions:
`impersonatedBy` is a column on the *session* row, so Modes A and C can read it and Mode B cannot -
a JWT carries the user object alone. A Mode B token that somehow carried the claim still reads
`None`, because the field is mapped by the verifier and never parsed from the payload.

One suite rather than three additions, because the subject is one noun crossing three lanes:
`test_cookie_verifier.py` is already 703 lines and this would push it past the 800-line ceiling.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from fastapi_better_auth import AdminUser, InvalidCredential, SessionRevoked, StoredUser
from tests.cookies import (
    CAPTURED_TOKEN,
    COOKIE,
    FakeStore,
    http,
    run,
    sign,
    stored_session,
    verifier,
)
from tests.cookies import USER_ID as COOKIE_USER_ID
from tests.jwt_fixtures import SIGNER, build
from tests.remote_fixtures import RecordingTransport, document, with_cookie
from tests.remote_fixtures import run as remote_run
from tests.remote_fixtures import verifier as remote_verifier
from tests.tokens import claims
from tests.transports import json_reply

ADMIN_ID = "McPLn0oFODOJXADr6Mu0CxzTpaQB2XU2"
"""The admin's user id, in the shape better-auth mints (harness, 2026-09-09)."""

LAPSED = datetime.now(timezone.utc) - timedelta(hours=1)
LAPSED_WIRE = "2000-01-01T00:00:00.000Z"

PLUGIN_FIELDS: dict[str, Any] = {
    "role": "admin",
    "banned": False,
    "banReason": None,
    "banExpires": None,
}


def user_payload(**overrides: Any) -> dict[str, Any]:
    """The upstream `user` object with `admin()` mounted, camelCase as it arrives."""
    payload: dict[str, Any] = {
        "id": COOKIE_USER_ID,
        "email": "seed@example.com",
        **PLUGIN_FIELDS,
    }
    payload.update(overrides)
    return payload


def store_with(user: StoredUser, **session_over: Any) -> FakeStore:
    return FakeStore(
        sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, user=user, **session_over)}
    )


async def mode_a(store: FakeStore) -> Any:
    return await run(
        verifier(store=store), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"), AdminUser
    )


async def mode_c(body: dict[str, Any]) -> Any:
    transport = RecordingTransport(json_reply(body))
    return await remote_run(remote_verifier(transport), with_cookie(), AdminUser)


class TestModeA:
    """The store road: `StoredUser.payload` is what `parse_user` is handed."""

    @pytest.mark.anyio
    async def test_the_four_plugin_fields_round_trip(self) -> None:
        user = StoredUser(id=COOKIE_USER_ID, payload=user_payload(role="admin"))

        session = await mode_a(store_with(user))

        assert session is not None
        assert session.user.role == "admin"
        assert session.user.banned is False
        assert session.user.ban_reason is None
        assert session.user.ban_expires is None

    @pytest.mark.anyio
    async def test_a_payload_without_the_plugin_reads_all_none(self) -> None:
        user = StoredUser(id=COOKIE_USER_ID, payload={"id": COOKIE_USER_ID, "email": "s@e.com"})

        session = await mode_a(store_with(user))

        assert session is not None
        assert (session.user.role, session.user.banned) == (None, None)
        assert (session.user.ban_reason, session.user.ban_expires) == (None, None)
        assert session.impersonated_by is None

    @pytest.mark.anyio
    async def test_an_impersonated_session_names_the_admin_behind_it(self) -> None:
        user = StoredUser(id=COOKIE_USER_ID, payload=user_payload())

        session = await mode_a(store_with(user, impersonated_by=ADMIN_ID))

        assert session is not None
        assert session.impersonated_by == ADMIN_ID
        assert session.user.id == COOKIE_USER_ID

    @pytest.mark.anyio
    async def test_a_lapsed_ban_is_admitted_and_reads_as_data(self) -> None:
        """The verifier lets a lapsed ban through (D-182); the model then says it was there."""
        user = StoredUser(
            id=COOKIE_USER_ID,
            payload=user_payload(banned=True, banReason="conformance", banExpires=LAPSED_WIRE),
            banned=True,
            ban_expires=LAPSED,
        )

        session = await mode_a(store_with(user))

        assert session is not None
        assert session.user.banned is True
        assert session.user.ban_reason == "conformance"
        assert session.user.ban_expires is not None
        assert session.user.ban_expires < datetime.now(timezone.utc)

    @pytest.mark.anyio
    async def test_a_live_ban_never_reaches_the_model_at_all(self) -> None:
        """Prove the instrument for the leg above: the verifier decides, not `AdminUser`."""
        user = StoredUser(id=COOKIE_USER_ID, payload=user_payload(banned=True), banned=True)

        with pytest.raises(SessionRevoked):
            await mode_a(store_with(user))

    @pytest.mark.anyio
    async def test_a_banned_that_is_not_a_bool_is_a_401_and_not_a_500(self) -> None:
        """A record that promoted nothing (`banned=None`) still hands the payload through, and
        `StrictBool` refuses the string there rather than reading it as a ban."""
        user = StoredUser(id=COOKIE_USER_ID, payload=user_payload(banned="true"), banned=None)

        with pytest.raises(InvalidCredential) as caught:
            await mode_a(store_with(user))

        assert caught.value.status_code == 401
        assert "banned" in caught.value.reason
        assert "true" not in caught.value.reason


class TestModeB:
    """The claims road: `/api/auth/token` puts the whole user object in the payload."""

    @pytest.mark.anyio
    async def test_the_four_plugin_fields_round_trip(self) -> None:
        token = SIGNER.sign(claims(**PLUGIN_FIELDS))
        verify, _transport = build()

        session = await verify.verify(token, AdminUser)

        assert session.user.role == "admin"
        assert session.user.banned is False
        assert session.user.ban_reason is None
        assert session.user.ban_expires is None

    @pytest.mark.anyio
    async def test_a_token_from_a_deployment_without_the_plugin_reads_all_none(self) -> None:
        verify, _transport = build()

        session = await verify.verify(SIGNER.sign(claims()), AdminUser)

        assert (session.user.role, session.user.banned) == (None, None)
        assert (session.user.ban_reason, session.user.ban_expires) == (None, None)

    @pytest.mark.anyio
    async def test_impersonation_is_unreachable_in_this_mode(self) -> None:
        """`impersonatedBy` is a *session* column. A token carrying the claim anyway changes
        nothing: the field is mapped by the verifier, and Mode B maps none."""
        token = SIGNER.sign(claims(impersonatedBy=ADMIN_ID))
        verify, _transport = build()

        session = await verify.verify(token, AdminUser)

        assert session.impersonated_by is None
        assert session.raw["impersonatedBy"] == ADMIN_ID

    @pytest.mark.anyio
    async def test_a_lapsed_ban_in_the_claims_reads_as_data(self) -> None:
        token = SIGNER.sign(claims(banned=True, banReason="conformance", banExpires=LAPSED_WIRE))
        verify, _transport = build()

        session = await verify.verify(token, AdminUser)

        assert session.user.banned is True
        assert session.user.ban_expires is not None
        assert session.user.ban_expires < datetime.now(timezone.utc)

    @pytest.mark.anyio
    async def test_a_banned_claim_that_is_not_a_bool_is_a_401_and_not_a_500(self) -> None:
        token = SIGNER.sign(claims(banned="true"))
        verify, _transport = build()

        with pytest.raises(InvalidCredential) as caught:
            await verify.verify(token, AdminUser)

        assert caught.value.status_code == 401
        assert "banned: [bool_type]" in caught.value.reason


class TestModeC:
    """The `get-session` road: the `user` half of the document upstream answers with."""

    @pytest.mark.anyio
    async def test_the_four_plugin_fields_round_trip(self) -> None:
        session = await mode_c(document(role="admin", banReason=None))

        assert session.user.role == "admin"
        assert session.user.banned is False
        assert session.user.ban_reason is None
        assert session.user.ban_expires is None

    @pytest.mark.anyio
    async def test_a_document_without_the_plugin_reads_all_none(self) -> None:
        body = document()
        for key in ("banned", "banExpires"):
            body["user"].pop(key)

        session = await mode_c(body)

        assert (session.user.role, session.user.banned) == (None, None)
        assert (session.user.ban_reason, session.user.ban_expires) == (None, None)
        assert session.impersonated_by is None

    @pytest.mark.anyio
    async def test_an_impersonated_session_names_the_admin_behind_it(self) -> None:
        body = document()
        body["session"]["impersonatedBy"] = ADMIN_ID

        session = await mode_c(body)

        assert session.impersonated_by == ADMIN_ID
        assert session.raw["impersonatedBy"] == ADMIN_ID

    @pytest.mark.anyio
    async def test_a_lapsed_ban_is_admitted_and_reads_as_data(self) -> None:
        session = await mode_c(
            document(banned=True, banReason="conformance", banExpires=LAPSED_WIRE)
        )

        assert session.user.banned is True
        assert session.user.ban_reason == "conformance"
        assert session.user.ban_expires is not None
        assert session.user.ban_expires < datetime.now(timezone.utc)
