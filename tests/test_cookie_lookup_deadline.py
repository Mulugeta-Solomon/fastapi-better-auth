"""Mode A puts a deadline on the session store: a store that never answers is a refusal, not a hang.

Every authenticated cookie request awaits the store. A database that stops answering - a dropped
connection with no reset, a lock, a pool with no checkout timeout - or a caller-written store that
hangs would otherwise hold every authenticated request open until the client or the server gave
up, and the worker's concurrency with it. The tests below drive a store that never returns through
the public `CookieVerifier`, and once through a FastAPI app, each bounded by an outer guard so a
missing deadline is a clean failure rather than a stuck suite.

Then what the overrun is: `AuthServiceUnavailable`, exactly as a store error is - the same
response, reported once per outage through the same latch under a kind of its own, never a
session and never a verdict on the credential - and what it is not: a change for a store that
answers in time, or a budget that two slow calls can each spend in full. Cancellation from
outside, and stores that block a thread, are `test_cookie_lookup_cancellation.py`'s.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Iterator
from typing import Any

import anyio
import pytest
from fastapi import Depends, FastAPI

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuth,
    ConfigurationError,
    CookieVerifier,
    CsrfDisabled,
    Session,
    StoredSession,
    StoredUser,
    User,
)
from fastapi_better_auth._internal.reasons import fingerprint
from tests.cookies import CAPTURED_TOKEN, USER_ID, FakeStore, http, run, stored_session
from tests.deadlines import (
    CREDENTIAL,
    DEADLINE,
    GUARD,
    OVERRUN_KIND,
    OVERRUN_REASON,
    ScriptedStore,
    hung_store,
    kinds,
    outage_lines,
    verifier,
)
from tests.fakes import client
from tests.log_hygiene import capturing
from tests.refusal_frames import COOKIE_NAME, COOKIE_VALUE, TOKEN, holding, refused, request
from tests.refusal_frames import SECRET as FRAMES_SECRET

REQUESTS = 5


class HungStore:
    """A `SessionStore` whose session lookup is entered and then never returns."""

    def __init__(self) -> None:
        self.entered = anyio.Event()
        self.completed = 0

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        self.entered.set()
        await anyio.sleep_forever()
        self.completed += 1
        return None

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        return None


class LateStore:
    """Answers a perfectly valid session, but only after `delay` seconds - for the app lane, where
    a store that literally never returned would wedge the `TestClient`'s portal thread for good."""

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.started = 0
        self.completed = 0

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        self.started += 1
        await anyio.sleep(self.delay)
        self.completed += 1
        return stored_session(token)

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        return None


def guarded_app(auth: BetterAuth) -> FastAPI:
    app = FastAPI()
    required = auth.current_session()

    async def read(session: Session[User] = Depends(required)) -> dict[str, Any]:
        return {"id": session.user.id}

    app.add_api_route("/me", read, methods=["GET"])
    return app


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


async def overrun(store: ScriptedStore, **options: Any) -> AuthServiceUnavailable:
    """One request against `store` that must be refused for overrunning, well inside the guard."""
    built = verifier(store, lookup_timeout=options.pop("lookup_timeout", DEADLINE), **options)
    with anyio.fail_after(GUARD), pytest.raises(AuthServiceUnavailable) as caught:
        await run(built, http(cookie=CREDENTIAL))
    return caught.value


# ---------------------------------------------------------------- the reproduction


@pytest.mark.anyio
async def test_a_store_that_never_answers_is_refused_within_the_deadline() -> None:
    store = HungStore()
    built = verifier(store, lookup_timeout=DEADLINE)

    with anyio.move_on_after(GUARD) as guard, pytest.raises(AuthServiceUnavailable):
        await run(built, http(cookie=CREDENTIAL))

    assert not guard.cancelled_caught, "the request hung on the store until the test's own guard"
    assert store.entered.is_set()
    assert store.completed == 0


def test_a_late_store_is_refused_on_the_wire_like_a_store_error(client_backend: str) -> None:
    """The response a timed-out lookup renders is byte-identical to the one a store error renders
    today - same status, body and headers - and the late answer is never honoured."""
    late = LateStore(GUARD)
    failing = FakeStore(session_error=ConnectionError("database went away"))

    timed_out = BetterAuth(verifiers=[verifier(late, lookup_timeout=DEADLINE)])
    errored = BetterAuth(verifiers=[verifier(failing)])
    with client(guarded_app(timed_out), client_backend) as http_client:
        refused = http_client.get("/me", headers={"cookie": CREDENTIAL})
    with client(guarded_app(errored), client_backend) as http_client:
        expected = http_client.get("/me", headers={"cookie": CREDENTIAL})

    assert late.started == 1
    assert late.completed == 0, "the store's late answer was waited for"
    assert refused.status_code == expected.status_code
    assert refused.content == expected.content
    assert refused.headers.get("www-authenticate") == expected.headers.get("www-authenticate")


# ---------------------------------------------------------------- what an overrun is


@pytest.mark.anyio
async def test_an_overrun_is_the_store_unavailable_refusal_and_never_a_miss() -> None:
    """Exactly `AuthServiceUnavailable` - not `SessionRevoked`, which a timed-out lookup falling
    through as `None` would become - with a reason an operator can tell from a store error, the
    token's fingerprint and never the token, and no exception chained behind it."""
    store = hung_store()

    refusal = await overrun(store)

    assert type(refusal) is AuthServiceUnavailable
    assert f"{OVERRUN_REASON} {DEADLINE}s" in refusal.reason
    assert fingerprint(CAPTURED_TOKEN) in refusal.reason
    assert CAPTURED_TOKEN not in refusal.reason
    assert CAPTURED_TOKEN not in repr(refusal)
    assert refusal.__cause__ is None
    assert refusal.__context__ is None
    assert store.completed == 0


@pytest.mark.anyio
async def test_a_hung_store_is_reported_once_however_many_requests_it_hangs(
    records: list[logging.LogRecord],
) -> None:
    store = hung_store()
    built = verifier(store, lookup_timeout=DEADLINE)

    for _ in range(REQUESTS):
        with anyio.fail_after(GUARD), pytest.raises(AuthServiceUnavailable):
            await run(built, http(cookie=CREDENTIAL))

    (line,) = outage_lines(records)
    assert line.levelno == logging.WARNING
    assert tuple(line.args or ()) == (OVERRUN_KIND, "none", fingerprint(CAPTURED_TOKEN))
    assert CAPTURED_TOKEN not in line.getMessage()
    assert store.session_calls == REQUESTS


@pytest.mark.anyio
async def test_a_lookup_that_completes_re_arms_the_report(
    records: list[logging.LogRecord],
) -> None:
    """The store recovering ends the outage: requests are served again, and a second hang is news."""
    store = hung_store()
    built = verifier(store, lookup_timeout=DEADLINE)

    for hang in (True, True, False, True, True):
        store.hang_session = hang
        with anyio.fail_after(GUARD):
            if hang:
                with pytest.raises(AuthServiceUnavailable):
                    await run(built, http(cookie=CREDENTIAL))
            else:
                session = await run(built, http(cookie=CREDENTIAL))
                assert session is not None
                assert session.user.id == USER_ID

    assert kinds(records) == [OVERRUN_KIND, OVERRUN_KIND]


@pytest.mark.anyio
async def test_an_overrun_and_a_store_error_are_told_apart(
    records: list[logging.LogRecord],
) -> None:
    """Both latched on the one lookup, each under its own kind, so a hang that follows an error
    (or the reverse) is still reported - and the two refusals carry different reasons."""
    store = ScriptedStore()
    built = verifier(store, lookup_timeout=DEADLINE)

    store.session_error = ConnectionError("database went away")
    with pytest.raises(AuthServiceUnavailable) as errored:
        await run(built, http(cookie=CREDENTIAL))
    store.session_error = None
    store.hang_session = True
    timed_out = await overrun(store)

    assert kinds(records) == ["ConnectionError", OVERRUN_KIND]
    assert OVERRUN_REASON not in errored.value.reason
    assert OVERRUN_REASON in timed_out.reason


@pytest.mark.anyio
async def test_a_store_raising_its_own_timeout_error_is_a_store_error(
    records: list[logging.LogRecord],
) -> None:
    """The deadline is the verifier's own scope, not `TimeoutError`: a driver's timeout stays the
    store error it is, under its own class."""
    store = ScriptedStore()
    store.session_error = TimeoutError("driver command timeout")

    with pytest.raises(AuthServiceUnavailable) as caught:
        await run(verifier(store, lookup_timeout=GUARD), http(cookie=CREDENTIAL))

    assert OVERRUN_REASON not in caught.value.reason
    assert kinds(records) == ["TimeoutError"]


@pytest.mark.anyio
async def test_a_hung_user_lookup_overruns_on_its_own_latch(
    records: list[logging.LogRecord],
) -> None:
    """A store that does not embed the user makes a second call; that one is bounded too, and is
    reported against the user's fingerprint as a user-lookup failure already is."""
    store = ScriptedStore(embed_user=False)
    store.hang_user = True

    refusal = await overrun(store)

    assert OVERRUN_REASON in refusal.reason
    assert fingerprint(CAPTURED_TOKEN) in refusal.reason
    assert store.user_calls == 1
    (line,) = outage_lines(records)
    assert tuple(line.args or ()) == (OVERRUN_KIND, "none", fingerprint(USER_ID))


# ---------------------------------------------------------------- the budget


@pytest.mark.anyio
async def test_both_lookups_of_one_request_share_one_deadline() -> None:
    """One budget per request: the user lookup runs under the very deadline the session lookup
    did, not a fresh allowance, so two slow calls cannot take twice the limit."""
    store = ScriptedStore(embed_user=False)
    before = anyio.current_time()

    session = await run(verifier(store, lookup_timeout=GUARD), http(cookie=CREDENTIAL))

    assert session is not None
    session_deadline, user_deadline = store.deadlines
    assert session_deadline == user_deadline
    assert before + GUARD <= session_deadline <= anyio.current_time() + GUARD


@pytest.mark.anyio
async def test_each_request_gets_a_budget_of_its_own() -> None:
    store = ScriptedStore()
    built = verifier(store, lookup_timeout=GUARD)

    await run(built, http(cookie=CREDENTIAL))
    await anyio.sleep(DEADLINE)
    await run(built, http(cookie=CREDENTIAL))

    first, second = store.deadlines
    assert second > first


@pytest.mark.anyio
async def test_the_default_budget_is_five_seconds() -> None:
    store = ScriptedStore()
    built = verifier(store)
    before = anyio.current_time()

    await run(built, http(cookie=CREDENTIAL))

    assert built.lookup_timeout == 5.0
    (deadline,) = store.deadlines
    assert before + 5.0 <= deadline <= anyio.current_time() + 5.0


@pytest.mark.anyio
async def test_none_disables_the_deadline(records: list[logging.LogRecord]) -> None:
    """With `None` the lookup runs under no deadline of ours - only the caller's own, which then
    ends it as the cancellation it is, with no refusal and nothing logged."""
    store = hung_store()
    built = verifier(store, lookup_timeout=None)

    with anyio.move_on_after(DEADLINE * 3) as callers_own:
        await run(built, http(cookie=CREDENTIAL))

    assert built.lookup_timeout is None
    assert callers_own.cancelled_caught
    assert store.deadlines == [callers_own.deadline]
    assert outage_lines(records) == []

    store.hang_session = False
    session = await run(built, http(cookie=CREDENTIAL))
    assert session is not None
    assert store.deadlines[-1] == math.inf


@pytest.mark.anyio
async def test_a_store_answering_in_time_is_served_unchanged(
    records: list[logging.LogRecord],
) -> None:
    store = ScriptedStore(embed_user=False)

    session = await run(verifier(store, lookup_timeout=GUARD), http(cookie=CREDENTIAL))

    assert session is not None
    assert session.user.id == USER_ID
    assert session.token is not None
    assert session.token.get_secret_value() == CAPTURED_TOKEN
    assert (store.session_calls, store.user_calls) == (1, 1)
    assert outage_lines(records) == []


# ---------------------------------------------------------------- traceback hygiene


@pytest.mark.anyio
async def test_an_overrun_leaves_the_token_in_no_frame() -> None:
    """D-094, walked from the outside through the resolver FastAPI awaits: no frame on the
    overrun's traceback, or anything chained to it, still holds the raw token."""
    store = hung_store()
    connection = request(cookies=[f"{COOKIE_NAME}={COOKIE_VALUE}"])
    built = CookieVerifier(
        secret=FRAMES_SECRET,
        store=store,
        csrf=CsrfDisabled(reason="this row is not about cross-site request forgery"),
        secure_cookies=False,
        lookup_timeout=DEADLINE,
    )

    with anyio.fail_after(GUARD):
        refusal = await refused(built, connection)

    assert type(refusal) is AuthServiceUnavailable
    assert OVERRUN_REASON in refusal.reason
    assert holding(refusal, TOKEN, ignore=[connection, store]) == []


# ---------------------------------------------------------------- configuration


@pytest.mark.parametrize(
    "value", [0, 0.0, -1, -0.5, math.nan, math.inf, -math.inf, True, False, "5", object()]
)
def test_an_unusable_lookup_timeout_is_refused_at_construction(value: object) -> None:
    with pytest.raises(ConfigurationError) as caught:
        verifier(ScriptedStore(), lookup_timeout=value)

    assert "lookup_timeout" in str(caught.value)


@pytest.mark.parametrize(("value", "kept"), [(3, 3.0), (0.25, 0.25), (5.0, 5.0), (None, None)])
def test_a_usable_lookup_timeout_is_kept(value: float | None, kept: float | None) -> None:
    built = verifier(ScriptedStore(), lookup_timeout=value)

    assert built.lookup_timeout == kept
    assert type(built.lookup_timeout) is type(kept)
