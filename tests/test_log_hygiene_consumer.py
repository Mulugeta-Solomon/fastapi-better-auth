"""What a consumer logs *from* this library carries no credential either.

`SessionError`'s docstring tells a consumer to log `reason`. The two ways anyone does it -
`logger.exception`, which renders `str(exc)` plus the traceback, and the explicit reason - are
driven here for every shape `JwtVerifier.verify` refuses, for an ambiguous request, for a boot
refusal, for a secret rendered straight into a template, and for the transport boundary. The A1
headline sits at the top: a query-time database error, whose `DBAPIError.str()` would otherwise
carry the bound session token into every `logger.exception` a consumer keeps.

The lines the library logs on its own are driven in `test_log_hygiene_sites.py`; the instrument
both suites read is `tests/log_hygiene.py`.
"""

from __future__ import annotations

import logging
import pathlib
import time
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine
from sqlalchemy import text as sqla_text
from sqlalchemy.ext.asyncio import AsyncEngine

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuth,
    ConfigurationError,
    SessionError,
    SessionStore,
    SharedSecret,
    SqlAlchemySessionStore,
    SyncStoreAdapter,
    User,
)
from fastapi_better_auth._internal.jwt_verifier import JwtVerifier
from fastapi_better_auth._internal.reasons import fingerprint
from tests.fakes import connection, resolver_of
from tests.log_hygiene import (
    CONSUMER_LOGGER,
    KEY_SET,
    LEAKY_SECRET,
    LIBRARY_LOGGER,
    MIN_NEEDLE,
    ORIGIN,
    SIGNER,
    STORE_TOKEN,
    STORED_USER_ID,
    WRONG_KEY,
    LeakyVerifier,
    QuietlyRaisingVerifier,
    assert_no_leak,
    capturing,
    consumer,
    rendered,
)
from tests.stores import async_engine, build_schema, sync_engine
from tests.tokens import claims, ed25519_signer, forged, tampered, unsigned
from tests.transports import Reply, ScriptedTransport, json_reply


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


class TestQueryErrorHygiene:
    """A1, the headline. SQLAlchemy's `DBAPIError.str()` embeds the bound parameters, so an
    untranslated query error carries the raw session token - and a consumer's `logger.exception`
    writes it, the one thing `StoredSession.token = repr=False` exists to prevent. Both execute
    paths (the async store and `SyncStoreAdapter`) are pinned.

    Pinned to asyncio: `aiosqlite` drives the event loop directly and cannot run under trio, and
    the sync adapter's backend-agnosticism is proven in `test_sync_store_adapter.py` - here the
    property under test is hygiene, not the backend."""

    @pytest.fixture
    def anyio_backend(self) -> str:
        return "asyncio"

    @pytest.mark.anyio
    @pytest.mark.parametrize("flavour", ["async", "sync"])
    async def test_a_query_time_db_error_leaks_no_token_or_user_id(
        self, records: list[logging.LogRecord], tmp_path: pathlib.Path, flavour: str
    ) -> None:
        path = tmp_path / f"{flavour}.sqlite"
        build_schema(path)
        engine: AsyncEngine | Engine
        store: SessionStore
        if flavour == "async":
            async_e = async_engine(path)
            engine, store = async_e, SqlAlchemySessionStore(engine=async_e)
        else:
            sync_e = sync_engine(path)
            engine, store = sync_e, SyncStoreAdapter(engine=sync_e)
        assert isinstance(store, (SqlAlchemySessionStore, SyncStoreAdapter))
        await store.connect()
        # Break the query itself after discovery, the shape a timeout/deadlock/failover takes.
        breaker = sync_engine(path)
        with breaker.begin() as connection:
            connection.execute(sqla_text('DROP TABLE "session"'))
        breaker.dispose()

        try:
            with pytest.raises(AuthServiceUnavailable) as caught:
                await store.fetch_session_by_token(STORE_TOKEN)
            consumer().exception("auth lookup failed", exc_info=caught.value)
            consumer().warning("auth lookup failed: %s", caught.value.reason)
        finally:
            if isinstance(engine, AsyncEngine):
                await engine.dispose()
            else:
                engine.dispose()

        # Scoped to the two loggers this library's contract covers - the consumer logging the
        # refusal, and the library itself. A DBAPI driver logs its own SQL (with parameters) at
        # DEBUG whether the query succeeds or fails; that telemetry is the driver's channel and is
        # out of scope. A1 is that the raised EXCEPTION - which rides into every WARNING/ERROR a
        # consumer keeps - carries no token, and it is proven pre-fix by the standalone
        # reproduction and by the RED run of this suite's sibling assertions.
        ours = [r for r in records if r.name in {CONSUMER_LOGGER, LIBRARY_LOGGER}]
        assert_no_leak(ours, STORE_TOKEN, STORED_USER_ID)
        assert fingerprint(STORE_TOKEN) in rendered(ours), "cannot tell which session failed"


def _long_lifetime() -> str:
    issued = int(time.time())
    return SIGNER.sign(claims(issuer=ORIGIN, issued_at=issued, lifetime=90_000))


def _refused_tokens() -> tuple[tuple[str, str, bool], ...]:
    """Every shape `JwtVerifier.verify` refuses, and whether its reason carries a fingerprint."""
    issued = int(time.time())
    return (
        ("wrong-key", WRONG_KEY.sign(claims(issuer=ORIGIN)), True),
        ("tampered", tampered(SIGNER.sign(claims(issuer=ORIGIN))), True),
        ("expired", SIGNER.sign(claims(issuer=ORIGIN, issued_at=issued - 4000)), True),
        ("unknown-kid", ed25519_signer("not-published").sign(claims(issuer=ORIGIN)), True),
        ("alg-none", unsigned(claims(issuer=ORIGIN)), True),
        ("over-cap", SIGNER.sign(claims(issuer=ORIGIN)) + "x" * 9000, True),
        ("no-dots", "Zt7Qv1oXbK4mPr9wCyHnLdEuAsJf2Ng6-not-a-token", True),
        ("long-lifetime", _long_lifetime(), True),
        ("no-subject", SIGNER.sign(claims(issuer=ORIGIN, sub="")), True),
        ("no-kid", forged({"alg": "EdDSA"}, claims(issuer=ORIGIN)), True),
        ("unusable-id", SIGNER.sign(claims(issuer=ORIGIN, id="   ")), False),
    )


REFUSED_TOKENS = _refused_tokens()
"""Built once. Calling the factory twice - once for values, once for ids - would let the two
lists drift apart and silently mislabel every case."""


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("token", "fingerprinted"),
    [(case[1], case[2]) for case in REFUSED_TOKENS],
    ids=[case[0] for case in REFUSED_TOKENS],
)
async def test_a_naive_consumer_logging_a_refusal_leaks_no_token(
    records: list[logging.LogRecord], token: str, fingerprinted: bool
) -> None:
    """The channel `SessionError`'s own docstring warns about, driven for every failure shape.

    A consumer catches the refusal and logs it the two ways anyone would - `logger.exception`,
    which renders `str(exc)` plus the traceback, and the `reason` the docstring tells them to
    log explicitly. Neither may carry the token, its payload or its signature.
    """
    verifier = JwtVerifier(
        base_url=ORIGIN, transport=ScriptedTransport(json_reply(KEY_SET)), leeway=0.0
    )

    with pytest.raises(SessionError) as caught:
        await verifier.verify(token, User)

    consumer().exception("authentication refused", exc_info=caught.value)
    consumer().warning("authentication refused: %s", caught.value.reason)

    assert_no_leak(records, token)
    if fingerprinted:
        assert fingerprint(token) in rendered(records), "the operator cannot tell which token"


@pytest.mark.anyio
async def test_a_naive_consumer_logging_an_ambiguity_leaks_no_credential(
    records: list[logging.LogRecord],
) -> None:
    """Two credentials arrive and neither is verified. The reason names the verifiers - which
    is operator configuration - and never the two values that caused it."""
    first = SIGNER.sign(claims(issuer=ORIGIN))
    second = WRONG_KEY.sign(claims(issuer=ORIGIN))
    auth = BetterAuth(verifiers=[QuietlyRaisingVerifier(), LeakyVerifier()])
    resolve = resolver_of(auth.current_session())

    with pytest.raises(SessionError) as caught:
        await resolve(connection(x_quiet=first, x_leaky=second))

    consumer().exception("ambiguous request", exc_info=caught.value)
    consumer().warning("ambiguous request: %s", caught.value.reason)

    assert_no_leak(records, first, second)


@pytest.mark.parametrize(
    "value",
    ["", "   ", LEAKY_SECRET[:20], f"{LEAKY_SECRET}\n", "better-auth-secret-12345678901234567890"],
    ids=["empty", "blank", "too-short", "trailing-newline", "placeholder"],
)
def test_a_naive_consumer_logging_a_boot_refusal_leaks_no_secret(
    records: list[logging.LogRecord], value: str
) -> None:
    """A boot refusal is logged by whatever supervises startup, so the message is a log line
    like any other. It may name which secret failed and never what it was."""
    with pytest.raises(ConfigurationError) as caught:
        SharedSecret(value)

    consumer().exception("configuration refused", exc_info=caught.value)

    written = rendered(records)
    assert written, "nothing was logged; this scenario proves nothing"
    assert LEAKY_SECRET not in written
    if len(value) >= MIN_NEEDLE:
        assert value not in written


def test_an_accepted_secret_never_reaches_a_log_line_through_its_own_rendering(
    records: list[logging.LogRecord],
) -> None:
    """The shape that would undo all of it: `logger.info("secret=%s", secret)`, which is what
    everybody writes. `logging` renders args with `%s`, so the type's `__str__` is the guard."""
    secret = SharedSecret(LEAKY_SECRET)

    consumer().info("booting with secret=%s", secret)
    consumer().info("booting with secret=%r", secret)
    consumer().info(f"booting with secret={secret}")

    written = rendered(records)
    assert LEAKY_SECRET not in written
    assert written.count(secret.fingerprint) >= 3


@pytest.mark.anyio
async def test_the_transport_boundary_leaks_no_credential_into_a_refusal(
    records: list[logging.LogRecord],
) -> None:
    """A key set that answers something unusable is a failure whose reason is built from the
    operator's URI and the media type - never from the token that triggered the fetch."""
    token = SIGNER.sign(claims(issuer=ORIGIN))
    verifier = JwtVerifier(
        base_url=ORIGIN,
        transport=ScriptedTransport(Reply(content=b"<html>nope</html>", content_type="text/html")),
    )

    with pytest.raises(AuthServiceUnavailable) as caught:
        await verifier.verify(token, User)

    consumer().exception("key set unusable", exc_info=caught.value)
    consumer().warning("key set unusable: %s", caught.value.reason)

    assert_no_leak(records, token)
