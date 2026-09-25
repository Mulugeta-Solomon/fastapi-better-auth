"""`Session.cookie` is built after every gate has passed, and no refusal frame keeps its value.

The pair is the verifier's answer to "which cookie did you accept", so it can only exist once
there is an acceptance: past CSRF, the signature or upstream's verdict, the store, expiry, the ban
and the user model. Built any earlier and a refused request would already have constructed the
thing a route forwards as a credential. That ordering is an absence on the wire - a refusal is the
same 401 either way - so it is measured where it happens, with a spy on the one constructor both
verifiers call: every refusal below must leave it uncalled, and the one acceptance calls it once.

The value now travels further down each verifier than it did (D-094): into Mode A's `_resolved`
and `_session`, and Mode C's `_session` and `_build_session`. The refusal rows raised inside
those frames are walked with `tests/refusal_frames.py::holding` for the percent-encoded value and
the raw token alike.
"""

from __future__ import annotations

import urllib.parse
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import SecretStr
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    AuthServiceUnavailable,
    CookieVerifier,
    CsrfFailure,
    InvalidCredential,
    OriginCheck,
    RemoteVerifier,
    Session,
    SessionError,
    SessionExpired,
    SessionRevoked,
    SharedSecret,
    User,
)
from fastapi_better_auth._internal import cookie_verifier, remote_verifier
from tests import remote_fixtures as remote
from tests.cookies import (
    CAPTURED_TOKEN,
    FAR_PAST,
    OTHER_SECRET,
    FakeStore,
    run,
    sign,
    stored_session,
    stored_user,
    verifier,
)
from tests.refusal_frames import holding, refused
from tests.transports import Reply, ScriptedTransport, json_reply

PLAIN = "better-auth.session_token"
APP = "https://app.example.com"
EVIL = "https://evil.example.com"
ENCODED = urllib.parse.quote(sign(CAPTURED_TOKEN), safe="")
FORGED = urllib.parse.quote(sign(CAPTURED_TOKEN, OTHER_SECRET.get_secret_value().encode()), safe="")
OTHER_TOKEN = "Qb8Xm2vTz6Lp1RkYd9Wn4Hs7Cj3Fg5Ae"


class Unparsable(User):
    """A model no stored or upstream payload here satisfies: the last gate refuses."""

    required_field: int


class Spy:
    """Stands in for `accepted_cookie` in one verifier module, and counts what it built."""

    def __init__(self, real: Callable[[str, str], tuple[str, SecretStr]]) -> None:
        self._real = real
        self.built: list[tuple[str, SecretStr]] = []

    def __call__(self, name: str, value: str) -> tuple[str, SecretStr]:
        pair = self._real(name, value)
        self.built.append(pair)
        return pair


@pytest.fixture
def spy_a(monkeypatch: pytest.MonkeyPatch) -> Spy:
    spy = Spy(cookie_verifier.accepted_cookie)
    monkeypatch.setattr(cookie_verifier, "accepted_cookie", spy)
    return spy


@pytest.fixture
def spy_c(monkeypatch: pytest.MonkeyPatch) -> Spy:
    spy = Spy(remote_verifier.accepted_cookie)
    monkeypatch.setattr(remote_verifier, "accepted_cookie", spy)
    return spy


def frames_holding_it(error: BaseException, *ignore: object) -> list[str]:
    """Every frame local still carrying the encoded value or its raw token, needles unrendered."""
    return holding(error, ENCODED, ignore=ignore) + holding(error, CAPTURED_TOKEN, ignore=ignore)


def request(method: str = "GET", *, value: str = ENCODED, **headers: str) -> HTTPConnection:
    return remote.request(method, cookies=(f"{PLAIN}={value}",), **headers)


# ---------------------------------------------------------------- Mode A


def mode_a_row(label: str) -> tuple[CookieVerifier, HTTPConnection, type[User], FakeStore]:
    """One Mode A refusal: the verifier, the request, the model, and the store it reads."""
    store = FakeStore(sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN)})
    connection = request()
    model: type[User] = User
    settings: dict[str, Any] = {}
    if label == "accepted":
        pass
    elif label == "cross-site write":
        settings["csrf"] = OriginCheck(allowed_origins=[APP])
        connection = request("POST", origin=EVIL)
    elif label == "duplicate name":
        connection = remote.request(cookies=(f"{PLAIN}={ENCODED}; {PLAIN}={ENCODED}",))
    elif label == "bad signature":
        connection = request(value=FORGED)
    elif label == "store miss":
        store = FakeStore()
    elif label == "expired":
        store = FakeStore(
            sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, expires_at=FAR_PAST)}
        )
    elif label == "user absent":
        store = FakeStore(sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, user=None)})
    elif label == "banned":
        banned = stored_session(CAPTURED_TOKEN, user=stored_user(banned=True))
        store = FakeStore(sessions={CAPTURED_TOKEN: banned})
    elif label == "user model refuses":
        model = Unparsable
    else:  # pragma: no cover - a typo in the table must not pass silently
        raise AssertionError(f"unknown row {label!r}")
    return verifier(store=store, secure_cookies=False, **settings), connection, model, store


MODE_A_ROWS: dict[str, type[SessionError]] = {
    "cross-site write": CsrfFailure,
    "duplicate name": InvalidCredential,
    "bad signature": InvalidCredential,
    "store miss": SessionRevoked,
    "expired": SessionExpired,
    "user absent": SessionRevoked,
    "banned": SessionRevoked,
    "user model refuses": InvalidCredential,
}
MODE_A_INNER = ("store miss", "expired", "user absent", "banned", "user model refuses")
"""The rows raised from inside `_resolved` or `_session`, the two frames the value now reaches."""


class TestModeAGates:
    @pytest.mark.anyio
    @pytest.mark.parametrize("label", MODE_A_ROWS)
    async def test_no_refusal_ever_builds_the_pair(self, label: str, spy_a: Spy) -> None:
        built, connection, model, _store = mode_a_row(label)

        with pytest.raises(MODE_A_ROWS[label]):
            await run(built, connection, model)

        assert spy_a.built == [], label

    @pytest.mark.anyio
    async def test_the_acceptance_builds_it_once_and_that_is_what_the_session_carries(
        self, spy_a: Spy
    ) -> None:
        built, connection, _model, _store = mode_a_row("accepted")

        session = await run(built, connection)

        assert isinstance(session, Session)
        assert len(spy_a.built) == 1
        assert session.cookie == spy_a.built[0]
        assert session.cookie is not None and session.cookie[1] is spy_a.built[0][1]

    @pytest.mark.anyio
    @pytest.mark.parametrize("label", MODE_A_INNER)
    async def test_no_refusal_frame_holds_the_value(self, label: str) -> None:
        built, connection, model, store = mode_a_row(label)

        error = await refused(built, connection, model=model)

        assert frames_holding_it(error, connection, store) == []


# ---------------------------------------------------------------- Mode C


def mode_c_row(label: str) -> tuple[RemoteVerifier, HTTPConnection, type[User], ScriptedTransport]:
    """One Mode C refusal: the verifier over its scripted upstream, the request and the model."""
    answer: Reply | BaseException = json_reply(remote.document())
    connection = request()
    model: type[User] = User
    settings: dict[str, Any] = {}
    if label == "accepted":
        pass
    elif label == "cross-site write":
        settings["csrf"] = OriginCheck(allowed_origins=[APP])
        connection = request("POST", origin=EVIL)
    elif label == "structurally impossible":
        connection = request(value="no-separator-at-all")
    elif label == "bad signature under a keyring":
        settings["secret"] = SharedSecret(OTHER_SECRET.get_secret_value())
    elif label == "upstream null":
        answer = json_reply(None)
    elif label == "a different token":
        answer = json_reply(remote.document(token=OTHER_TOKEN))
    elif label == "expired":
        answer = json_reply(remote.document(expires=remote.FAR_PAST))
    elif label == "banned":
        answer = json_reply(remote.document(banned=True))
    elif label == "unreachable":
        answer = RuntimeError("the auth service is gone")
    elif label == "rate-limited":
        answer = Reply(b"", status=429)
    elif label == "user model refuses":
        model = Unparsable
    else:  # pragma: no cover - as mode_a_row
        raise AssertionError(f"unknown row {label!r}")
    transport = remote.RecordingTransport(answer)
    return (
        remote.verifier(transport, secure_cookies=False, **settings),
        connection,
        model,
        transport,
    )


MODE_C_ROWS: dict[str, type[SessionError]] = {
    "cross-site write": CsrfFailure,
    "structurally impossible": InvalidCredential,
    "bad signature under a keyring": InvalidCredential,
    "upstream null": InvalidCredential,
    "a different token": InvalidCredential,
    "expired": SessionExpired,
    "banned": SessionRevoked,
    "unreachable": AuthServiceUnavailable,
    "rate-limited": AuthServiceUnavailable,
    "user model refuses": InvalidCredential,
}
MODE_C_INNER = ("a different token", "expired", "banned", "user model refuses")
"""The rows raised from inside `_session` or `_build_session`."""


class TestModeCGates:
    @pytest.mark.anyio
    @pytest.mark.parametrize("label", MODE_C_ROWS)
    async def test_no_refusal_ever_builds_the_pair(self, label: str, spy_c: Spy) -> None:
        built, connection, model, _transport = mode_c_row(label)

        with pytest.raises(MODE_C_ROWS[label]):
            await remote.run(built, connection, model)

        assert spy_c.built == [], label

    @pytest.mark.anyio
    @pytest.mark.parametrize(("label", "second"), [("upstream null", 1), ("rate-limited", 1)])
    async def test_a_remembered_verdict_builds_nothing_either(
        self, label: str, second: int, spy_c: Spy
    ) -> None:
        """The negative cache and the backoff latch answer the repeat with no fetch at all."""
        built, _connection, model, transport = mode_c_row(label)

        for _attempt in range(2):
            with pytest.raises(MODE_C_ROWS[label]):
                await remote.run(built, request(), model)

        assert transport.calls == second
        assert spy_c.built == []

    @pytest.mark.anyio
    async def test_the_acceptance_builds_it_once_and_that_is_what_the_session_carries(
        self, spy_c: Spy
    ) -> None:
        built, connection, _model, _transport = mode_c_row("accepted")

        session = await remote.run(built, connection)

        assert isinstance(session, Session)
        assert len(spy_c.built) == 1
        assert session.cookie == spy_c.built[0]
        assert session.cookie is not None and session.cookie[1] is spy_c.built[0][1]

    @pytest.mark.anyio
    @pytest.mark.parametrize("label", MODE_C_INNER)
    async def test_no_refusal_frame_holds_the_value(self, label: str) -> None:
        built, connection, model, transport = mode_c_row(label)

        error = await refused(built, connection, model=model)

        assert frames_holding_it(error, connection, transport) == []
