"""A store that answers after the deadline with a typed refusal still overran.

An overrun is never honoured, whatever the store ended with. A store that shields its lookup past
the deadline and then raises `SessionRevoked` must not hand the client a revocation verdict on a
credential that may be perfectly valid. A store's own late `AuthServiceUnavailable` is refused too,
and reported under the deadline's kind, so the operator sees that the store was late, not some
generic failure. Both lookups behave alike. A `ConfigurationError` is a deployment fault, not an
answer about the session, so it propagates whenever it arrives. And a typed refusal that arrives
in time is the verdict it always was.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import anyio
import pytest

from fastapi_better_auth import (
    AuthServiceUnavailable,
    ConfigurationError,
    SessionError,
    SessionRevoked,
    StoredSession,
    StoredUser,
)
from tests.cookies import CAPTURED_TOKEN, http, run, stored_session, stored_user
from tests.deadlines import (
    CREDENTIAL,
    DEADLINE,
    GUARD,
    OVERRUN_KIND,
    OVERRUN_REASON,
    kinds,
    verifier,
)
from tests.log_hygiene import capturing

LOOKUPS = ("session", "user")

LATE_REFUSALS: tuple[tuple[str, SessionError], ...] = (
    ("revoked", SessionRevoked(reason="the store's own late verdict")),
    ("unavailable", AuthServiceUnavailable(reason="the store's own late outage")),
)


class ShieldedStore:
    """Holds its lookup past the verifier's deadline behind a shield, then raises `error`.

    Raises from the session lookup, or from the user lookup a store that does not embed the user
    makes. `delay` set to 0 makes the same error arrive in time.
    """

    def __init__(self, lookup: str, error: BaseException, delay: float = DEADLINE * 3) -> None:
        self.lookup = lookup
        self.error = error
        self.delay = delay

    async def _late(self) -> None:
        with anyio.CancelScope(shield=True):
            await anyio.sleep(self.delay)
        raise self.error

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        if self.lookup == "session":
            await self._late()
        return stored_session(token, user=None)

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        await self._late()
        return stored_user()


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


@pytest.fixture(params=LOOKUPS)
def lookup(request: pytest.FixtureRequest) -> str:
    value = request.param
    assert isinstance(value, str)
    return value


@pytest.mark.anyio
@pytest.mark.parametrize(("label", "error"), LATE_REFUSALS, ids=[row[0] for row in LATE_REFUSALS])
async def test_a_late_typed_refusal_is_the_overrun(
    lookup: str, label: str, error: SessionError, records: list[logging.LogRecord]
) -> None:
    store = ShieldedStore(lookup, error)

    with anyio.fail_after(GUARD), pytest.raises(SessionError) as caught:
        await run(verifier(store, lookup_timeout=DEADLINE), http(cookie=CREDENTIAL))

    refusal = caught.value
    assert type(refusal) is AuthServiceUnavailable, f"a late {label} became {type(refusal)}"
    assert refusal is not error
    assert OVERRUN_REASON in refusal.reason
    assert CAPTURED_TOKEN not in refusal.reason
    assert refusal.__cause__ is None
    assert refusal.__context__ is None, "the store's late error rides out on __context__"
    assert kinds(records) == [OVERRUN_KIND]


@pytest.mark.anyio
@pytest.mark.parametrize(("label", "error"), LATE_REFUSALS, ids=[row[0] for row in LATE_REFUSALS])
async def test_a_typed_refusal_in_time_is_unchanged(
    lookup: str, label: str, error: SessionError, records: list[logging.LogRecord]
) -> None:
    store = ShieldedStore(lookup, error, delay=0)

    with pytest.raises(SessionError) as caught:
        await run(verifier(store, lookup_timeout=GUARD), http(cookie=CREDENTIAL))

    assert caught.value is error, f"an in-time {label} was not propagated as the store raised it"
    assert kinds(records) == []


@pytest.mark.anyio
async def test_a_late_configuration_error_still_propagates(
    lookup: str, records: list[logging.LogRecord]
) -> None:
    error = ConfigurationError("schema never migrated")
    store = ShieldedStore(lookup, error)

    with anyio.fail_after(GUARD), pytest.raises(ConfigurationError) as caught:
        await run(verifier(store, lookup_timeout=DEADLINE), http(cookie=CREDENTIAL))

    assert caught.value is error
    assert kinds(records) == []
