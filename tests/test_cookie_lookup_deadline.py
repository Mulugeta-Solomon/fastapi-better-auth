"""Mode A puts a deadline on the session store: a store that never answers is a refusal, not a hang.

Every authenticated cookie request awaits the store. A database that stops answering - a dropped
connection with no reset, a lock, a pool with no checkout timeout - or a caller-written store that
hangs would otherwise hold every authenticated request open until the client or the server gave
up, and the worker's concurrency with it. The tests below drive a store that never returns through
the public `CookieVerifier`, and once through a FastAPI app, each bounded by an outer guard so a
missing deadline is a clean failure rather than a stuck suite.
"""

from __future__ import annotations

from typing import Any

import anyio
import pytest
from fastapi import Depends, FastAPI

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuth,
    CookieVerifier,
    CsrfDisabled,
    Session,
    SessionStore,
    StoredSession,
    StoredUser,
    User,
)
from tests.cookies import (
    CAPTURED_TOKEN,
    COOKIE,
    SECRET,
    FakeStore,
    http,
    run,
    sign,
    stored_session,
)
from tests.fakes import client

GUARD = 2.0
"""Seconds the test itself waits before it calls the request hung. Generous on purpose: a lookup
that honours its deadline is back in tens of milliseconds, so the guard only ever fires red."""

CREDENTIAL = f"{COOKIE}={sign(CAPTURED_TOKEN)}"


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


def verifier(store: SessionStore, **options: Any) -> CookieVerifier:
    """The cookie lane's plain-name deployment (`tests/cookies.py::verifier`), over any store."""
    return CookieVerifier(
        secret=SECRET,
        store=store,
        csrf=CsrfDisabled(reason="deadline tests do not exercise CSRF"),
        secure_cookies=False,
        **options,
    )


def guarded_app(auth: BetterAuth) -> FastAPI:
    app = FastAPI()
    required = auth.current_session()

    async def read(session: Session[User] = Depends(required)) -> dict[str, Any]:
        return {"id": session.user.id}

    app.add_api_route("/me", read, methods=["GET"])
    return app


@pytest.mark.anyio
async def test_a_store_that_never_answers_is_refused_within_the_deadline() -> None:
    store = HungStore()
    built = verifier(store)

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

    timed_out = BetterAuth(verifiers=[verifier(late)])
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
