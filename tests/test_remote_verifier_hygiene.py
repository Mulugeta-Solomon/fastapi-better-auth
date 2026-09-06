"""No Mode C refusal carries the cookie or the token: not `__cause__`, not a reason, not a frame.

A transport failure chains nothing, so an httpx error holding the outbound cookie never rides out
on `__cause__`. A refusal raised after the fetch - expired, banned, a token mismatch - unwinds
through `verify`, whose frame binds the document naming the session that was presented (D-210),
and each is walked with `holding()` from `tests/refusal_frames.py`. The WP15 refusal paths get the
same walk: a cache-remembered null, a latched refusal, a probe-contract failure on a cold verifier,
a saturated limiter. And no refusal reason names the cookie or the token. What those refusals are
is `test_remote_verifier_pipeline.py` and `test_remote_verifier_gates.py`; the builders are
`tests/remote_fixtures.py`.
"""

from __future__ import annotations

import contextlib
from typing import Any

import anyio
import pytest

from fastapi_better_auth import (
    AuthServiceUnavailable,
    ConfigurationError,
    CsrfDisabled,
    InvalidCredential,
    SessionExpired,
    SessionRevoked,
)
from fastapi_better_auth._internal.remote_verifier import RemoteVerifier
from tests.refusal_frames import holding, refused
from tests.remote_fixtures import (
    COOKIE_VALUE,
    ORIGIN,
    TOKEN,
    RecordingTransport,
    document,
    run,
    verifier,
    with_cookie,
)
from tests.transports import Reply, ScriptedTransport, json_reply

# ---------------------------------------------------------------- transport-failure chaining


class TestChaining:
    class Leaky(Exception):
        """A transport error that holds the outbound cookie the way an httpx error's .request does."""

        def __init__(self, cookie: str) -> None:
            self.request_cookie = cookie
            super().__init__("connection refused")

    @pytest.mark.anyio
    async def test_a_transport_failure_chains_nothing_and_leaks_no_cookie(self) -> None:
        transport = ScriptedTransport(self.Leaky(COOKIE_VALUE))
        built = verifier(transport)
        connection = with_cookie()

        error = await refused(built, connection)

        assert isinstance(error, AuthServiceUnavailable)
        assert error.__cause__ is None, "the transport error rode out on __cause__"
        # `transport` is the fixture holding the scripted Leaky (with the cookie) by construction,
        # exactly as refusal_frames ignores the operator's store; the assertion is that the raised
        # error's own frames and chain carry nothing.
        assert holding(error, COOKIE_VALUE, ignore=[connection, transport]) == []
        assert holding(error, TOKEN, ignore=[connection, transport]) == []


# ---------------------------------------------------------------- frame hygiene, POST-fetch refusals


class TestRefusalFramesPostFetch:
    """A refusal raised AFTER the fetch (`expired`, `banned`) unwinds through `verify`, whose frame
    binds `record`/`response` - both carrying the forwarded token, since the upstream document names
    the session that WAS presented (D-210). The pre-fetch chaining test cannot see this: no document
    is ever built there. Each row asserts no frame of the raised error holds the token or the whole
    cookie value.
    """

    PAST = "2000-01-01T00:00:00.000Z"

    @pytest.mark.anyio
    async def test_an_expired_refusal_holds_no_credential(self) -> None:
        transport = ScriptedTransport(json_reply(document(expires=self.PAST)))
        built = verifier(transport)
        connection = with_cookie()

        error = await refused(built, connection)

        assert isinstance(error, SessionExpired)
        assert holding(error, TOKEN, ignore=[connection, transport]) == []
        assert holding(error, COOKIE_VALUE, ignore=[connection, transport]) == []

    @pytest.mark.anyio
    async def test_a_banned_refusal_holds_no_credential(self) -> None:
        transport = ScriptedTransport(json_reply(document(banned=True)))
        built = verifier(transport)
        connection = with_cookie()

        error = await refused(built, connection)

        assert isinstance(error, SessionRevoked)
        assert holding(error, TOKEN, ignore=[connection, transport]) == []
        assert holding(error, COOKIE_VALUE, ignore=[connection, transport]) == []

    @pytest.mark.anyio
    async def test_a_token_mismatch_refusal_holds_no_credential(self) -> None:
        transport = ScriptedTransport(json_reply(document(token="a-different-token-entirely")))
        built = verifier(transport)
        connection = with_cookie()

        error = await refused(built, connection)

        assert isinstance(error, InvalidCredential)
        assert holding(error, TOKEN, ignore=[connection, transport]) == []
        assert holding(error, COOKIE_VALUE, ignore=[connection, transport]) == []


# ---------------------------------------------------------------- log/reason hygiene extension


class TestReasonHygiene:
    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "answer",
        [Reply(b"null"), json_reply({"session": {}, "user": 3}), json_reply(document(token="x"))],
        ids=["null", "unusable", "mismatch"],
    )
    async def test_no_refusal_reason_carries_the_cookie_or_token(self, answer: Any) -> None:
        v = verifier(RecordingTransport(answer))

        with pytest.raises((InvalidCredential, AuthServiceUnavailable, SessionRevoked)) as caught:
            await run(v, with_cookie())

        assert TOKEN not in caught.value.reason
        assert COOKIE_VALUE not in caught.value.reason


class TestRefusalFramesNewGates:
    """Frame hygiene for the WP15 refusal paths: a cache-remembered null, a latched refusal, a
    saturated limiter, and a probe/ready failure must each leave no frame holding the credential.
    """

    @pytest.mark.anyio
    async def test_a_cache_remembered_null_refusal_holds_no_credential(self) -> None:
        transport = ScriptedTransport(Reply(b"null"))
        built = verifier(transport)
        connection = with_cookie()

        error = await refused(built, connection)

        assert isinstance(error, InvalidCredential)
        assert holding(error, TOKEN, ignore=[connection, transport]) == []
        assert holding(error, COOKIE_VALUE, ignore=[connection, transport]) == []

    @pytest.mark.anyio
    async def test_a_latched_refusal_holds_no_credential(self) -> None:
        transport = ScriptedTransport(Reply(b"", status=429))
        built = verifier(transport)
        connection = with_cookie()

        await refused(built, connection)  # trips the latch
        error = await refused(built, connection)  # refused while latched, before any fetch

        assert isinstance(error, AuthServiceUnavailable)
        assert "backing off" in error.reason
        assert holding(error, TOKEN, ignore=[connection, transport]) == []
        assert holding(error, COOKIE_VALUE, ignore=[connection, transport]) == []

    @pytest.mark.anyio
    async def test_a_probe_contract_failure_holds_no_credential(self) -> None:
        # A cold verifier whose bare probe answers a non-null body refuses on _ready, and the
        # forwarded cookie is never bound in a surviving frame.
        transport = ScriptedTransport(Reply(b'{"not": "null"}'))
        built = RemoteVerifier(
            base_url=ORIGIN,
            csrf=CsrfDisabled(reason="frame test, no cross-site request"),
            transport=transport,
            secure_cookies=False,
        )
        connection = with_cookie()

        error = await refused(built, connection)

        assert isinstance(error, ConfigurationError)
        assert holding(error, TOKEN, ignore=[connection, transport]) == []
        assert holding(error, COOKIE_VALUE, ignore=[connection, transport]) == []

    @pytest.mark.anyio
    async def test_a_saturated_limiter_refusal_holds_no_credential(self) -> None:
        # The limiter refuses BEFORE the fetch, but only once the cookie has been resolved and
        # rung-checked; the refusal must still leave no frame holding the credential.
        gate = anyio.Event()
        held = RecordingTransport(Reply(b"null"), gate=gate)
        built = verifier(held, concurrency=1, queue_timeout=0.1)
        connection = with_cookie()
        errors: list[BaseException] = []

        async def hold_the_only_slot() -> None:
            with contextlib.suppress(BaseException):
                await run(built, with_cookie())

        async with anyio.create_task_group() as tg:
            tg.start_soon(hold_the_only_slot)
            await anyio.sleep(0.01)
            errors.append(await refused(built, connection))
            gate.set()

        error = errors[0]
        assert isinstance(error, AuthServiceUnavailable)
        assert "saturated" in error.reason
        assert holding(error, TOKEN, ignore=[connection, held]) == []
        assert holding(error, COOKIE_VALUE, ignore=[connection, held]) == []
