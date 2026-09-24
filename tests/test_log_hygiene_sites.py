"""Every log line this library emits, driven, and the record it produced read for a credential.

One scenario per `COVERED_BY` entry: the contained-verifier traceback, the two JWKS warnings, the
four store-side lines, the cookie verifier's session-data warning, the 429 latch and the advisory
bearer probe. Each asserts that its own template fired - so the manifest is a record of what ran,
not a declaration - and then that nothing a client chose, and no credential, reached the line.
`test_the_manifest_names_tests_that_exist` pins that every name in the manifest resolves to a
test in this file, which is where a new site's scenario must be written.

The one boundary the library cannot hold is pinned here too: a third-party verifier that puts the
credential into its own exception message leaks it into the traceback `core._contained` logs.
"""

from __future__ import annotations

import logging
import pathlib
import sys
import time
from collections.abc import Iterator, Mapping
from typing import Any

import anyio
import pytest
from pydantic import SecretStr, create_model
from sqlalchemy import text as sqla_text
from sqlalchemy.exc import DBAPIError

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuth,
    CookieVerifier,
    CsrfDisabled,
    NotAuthorized,
    RedisSessionStore,
    Session,
    SessionError,
    SharedSecret,
    SyncStoreAdapter,
    TransportResponse,
    User,
    parse_user,
)
from fastapi_better_auth._internal import remote_probe
from fastapi_better_auth._internal.authz import permitted
from fastapi_better_auth._internal.jwks import JwksClient
from fastapi_better_auth._internal.once import Once
from fastapi_better_auth._internal.reasons import REDACTED, fingerprint
from fastapi_better_auth._internal.remote_backoff import BackoffLatch
from fastapi_better_auth._internal.stores.outage import MAX_REPORTED_KINDS
from tests.cookies import COOKIE, FakeStore, http, run, sign, verifier
from tests.fakes import connection, resolver_of
from tests.log_hygiene import (
    COVERED_BY,
    HOSTILE_KID,
    KEY_SET,
    LEAKY_SECRET,
    LIBRARY_LOGGER,
    ORIGIN,
    SHARED_LOG_FUNCTIONS,
    SIGNER,
    STORE_TOKEN,
    STORED_USER_ID,
    UNREADABLE,
    LeakyVerifier,
    QuietlyRaisingVerifier,
    assert_no_leak,
    assert_template_fired,
    capturing,
    consumer,
    manifest_site,
    rendered,
)
from tests.stores import (
    DeniedError,
    DriverFault,
    RecordingRedis,
    ShiftingStateError,
    build_schema,
    sync_engine,
)
from tests.tokens import Clock, claims
from tests.transports import ScriptedTransport, json_reply


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    with capturing() as collected:
        yield collected


@pytest.mark.parametrize("test_name", sorted(set(COVERED_BY.values())))
def test_the_manifest_names_tests_that_exist(test_name: str) -> None:
    """A manifest entry pointing at a test nobody wrote is a coverage claim, not coverage.

    Looked up in this module on purpose: the scenario a manifest entry names is written here,
    and an entry whose test landed in another file fails until it is moved.
    """
    assert callable(getattr(sys.modules[__name__], test_name, None))


@pytest.mark.anyio
async def test_a_contained_verifier_escape_logs_no_credential(
    records: list[logging.LogRecord],
) -> None:
    """`core._contained` logs the traceback of anything that escapes a verifier. The frames
    it renders are this library's, and none of them may put the credential on the line."""
    token = SIGNER.sign(claims(issuer=ORIGIN))
    auth = BetterAuth(verifiers=[QuietlyRaisingVerifier()])
    resolve = resolver_of(auth.current_session())

    with pytest.raises(SessionError) as caught:
        await resolve(connection(x_quiet=token))

    assert_template_fired(records, next(s for s in COVERED_BY if s.module == "core"))
    assert_no_leak(records, token)
    assert fingerprint(token) not in rendered(records)
    assert "RuntimeError" in caught.value.reason


@pytest.mark.anyio
async def test_a_verifier_that_leaks_into_its_own_exception_is_not_contained_by_us(
    records: list[logging.LogRecord],
) -> None:
    """The boundary, pinned so it is not mistaken for a promise: a verifier that interpolates
    the credential into its own exception message puts it in the traceback this library logs.

    Nothing here can scrub a third party's exception text. What this library owes - and what
    the test above proves - is that *its own* frames and its own `reason` never do it.
    """
    token = SIGNER.sign(claims(issuer=ORIGIN))
    auth = BetterAuth(verifiers=[LeakyVerifier()])
    resolve = resolver_of(auth.current_session())

    with pytest.raises(SessionError) as caught:
        await resolve(connection(x_leaky=token))

    assert token in rendered(records), "retune this probe: the leak it documents did not happen"
    assert token not in caught.value.reason, "the reason this library built must still be clean"


def test_an_escaped_authorization_callback_logs_no_credential(
    records: list[logging.LogRecord],
) -> None:
    """`authz` logs the traceback of a predicate or a membership lookup that raised. The session
    it was handed carries the raw cookie-mode token, under `Session.token` and again inside
    `Session.raw`, so that token is what this line must not carry - and the reason it builds
    names the exception type and nothing the consumer's own message said."""
    token = SIGNER.sign(claims(issuer=ORIGIN))
    session: Session[User] = Session(
        user=User(id=STORED_USER_ID),
        expires_at=None,
        token=SecretStr(token),
        raw={"token": token},
    )

    def explode(_session: Session[User]) -> bool:
        raise RuntimeError("the policy table could not be read")

    with pytest.raises(NotAuthorized) as caught:
        permitted(explode, session)

    assert_template_fired(records, manifest_site("the %s raised"))
    assert_no_leak(records, token)
    assert "RuntimeError" in caught.value.reason
    assert token not in caught.value.reason


@pytest.mark.anyio
async def test_a_jwks_refresh_failure_logs_no_attacker_chosen_kid(
    records: list[logging.LogRecord],
) -> None:
    """The one warning this library emits. A `kid` is text out of an *unverified* header, so
    it is both a credential-adjacent value and a log-injection vector; the line names the
    operator's own URI and nothing a client chose."""
    clock = Clock()
    transport = ScriptedTransport(json_reply(KEY_SET), RuntimeError("upstream down"))
    client = JwksClient(base_url=ORIGIN, transport=transport, algorithms=("EdDSA",), clock=clock)

    assert await client.key_for(SIGNER.kid) is not None
    clock.advance(600.0)
    with pytest.raises(AuthServiceUnavailable) as caught:
        await client.key_for(HOSTILE_KID)

    consumer().warning("key set unusable: %s", caught.value.reason)

    assert_template_fired(records, manifest_site("jwks refresh failed"))
    assert HOSTILE_KID not in rendered(records)
    assert "forged log line" not in rendered(records)
    assert REDACTED in caught.value.reason


@pytest.mark.anyio
async def test_a_skipped_jwks_key_logs_neither_its_kid_nor_its_material(
    records: list[logging.LogRecord],
) -> None:
    """The key-set client's other warning. A key the publisher marked `use: "enc"` is dropped
    from the set rather than trusted to check signatures, and the line saying so names the key
    by a sanitized `kid` and one reason word.

    The material is what makes this line worth an assertion. A JWKS is supposed to carry only
    public halves, and a server that mispublished a *private* one would be handing this
    library the whole secret in the very entry it is about to complain about.
    """
    mispublished = {
        **dict(SIGNER.jwk),
        "kid": HOSTILE_KID,
        "use": "enc",
        "d": LEAKY_SECRET,
    }
    transport = ScriptedTransport(json_reply({"keys": [mispublished]}))
    client = JwksClient(base_url=ORIGIN, transport=transport, algorithms=("EdDSA",))

    assert await client.key_for(HOSTILE_KID) is None

    assert_template_fired(records, manifest_site("jwks key %s is not usable"))
    assert_no_leak(records, LEAKY_SECRET, str(SIGNER.jwk["x"]))
    assert HOSTILE_KID not in rendered(records)
    assert "forged log line" not in rendered(records)


@pytest.mark.anyio
async def test_a_malformed_stored_session_logs_no_token(
    records: list[logging.LogRecord],
) -> None:
    """A stored value a store refuses is still session data, and the key it sat under is a live
    session token. The operator gets a fingerprint and a phrase this package wrote - never the
    key, and never a byte of the value."""
    store = RedisSessionStore(client=RecordingRedis({STORE_TOKEN: UNREADABLE}))

    assert await store.fetch_session_by_token(STORE_TOKEN) is None

    assert_template_fired(records, manifest_site("stored %s is unusable"))
    assert_no_leak(records, STORE_TOKEN, STORED_USER_ID)
    assert fingerprint(STORE_TOKEN) in rendered(records), "the operator cannot tell which session"


@pytest.mark.anyio
async def test_a_schema_drift_warning_carries_only_operator_owned_names(
    records: list[logging.LogRecord], tmp_path: pathlib.Path
) -> None:
    """The other store-side line. Everything in it - the table name and the column names - comes
    from this package's own constants and the operator's own configuration, so there is nothing
    here a client could have chosen; the assertion is that no row data joins them."""
    path = tmp_path / "drift.sqlite"
    build_schema(path, drop_session_columns=("ipAddress",))
    engine = sync_engine(path)

    try:
        await SyncStoreAdapter(engine=engine).connect()
    finally:
        engine.dispose()

    drift = next(site for site in COVERED_BY if site.template.startswith("table %s"))
    assert_template_fired(records, drift)
    written = rendered(records)
    assert "ipAddress" in written
    assert STORED_USER_ID not in written


@pytest.mark.anyio
async def test_a_store_lookup_failure_warning_carries_no_token(
    records: list[logging.LogRecord], tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R47's line, over exactly the error A1 is about: a `DBAPIError` whose `str()` embeds the
    bound token, wrapping a driver error whose own message repeats it. The operator gets the
    driver's class, the SQLSTATE and a fingerprint - no message, no args, no parameters and no
    traceback. The instrument is proven live first: the error the store meets does carry it."""
    path = tmp_path / "outage.sqlite"
    build_schema(path)
    engine = sync_engine(path)
    store = SyncStoreAdapter(engine=engine)
    try:
        await store.connect()
        DriverFault(engine, monkeypatch).error = DeniedError
        with engine.connect() as probe, pytest.raises(DBAPIError) as raw:
            probe.execute(sqla_text("SELECT :token"), {"token": STORE_TOKEN})
        carried = STORE_TOKEN in str(raw.value)
        with pytest.raises(AuthServiceUnavailable):
            await store.fetch_session_by_token(STORE_TOKEN)
    finally:
        engine.dispose()

    assert carried, "the fault no longer puts the token in the error; this proves nothing"
    site = manifest_site("session store lookup could not complete")
    assert_template_fired(records, site)
    ours = [record for record in records if record.name == LIBRARY_LOGGER]
    assert_no_leak(ours, STORE_TOKEN)
    (line,) = [record for record in ours if record.msg == site.template]
    assert line.exc_info is None
    assert line.args == ("DeniedError", "42501", fingerprint(STORE_TOKEN))


class LeakyStoreError(Exception):
    """A deployment's own store error that puts the token in its message and its args."""


@pytest.mark.anyio
async def test_a_contained_store_failure_warning_carries_no_token(
    records: list[logging.LogRecord],
) -> None:
    """R47a's caller: the same line, reached from `CookieVerifier` with an error this library did
    not write - its message and its `args` both carry the raw token. The operator gets the class,
    `none` for a SQLSTATE and the token's fingerprint; the refusal carries no chain to it."""
    store = FakeStore(session_error=LeakyStoreError(f"no session for {STORE_TOKEN}", STORE_TOKEN))
    cookie = f"{COOKIE}={sign(STORE_TOKEN)}"

    with pytest.raises(AuthServiceUnavailable) as caught:
        await run(verifier(store=store), http(cookie=cookie))

    carried = STORE_TOKEN in str(store.session_error)
    assert carried, "the store error no longer carries the token; this proves nothing"
    site = manifest_site("session store lookup could not complete")
    assert_template_fired(records, site)
    ours = [record for record in records if record.name == LIBRARY_LOGGER]
    assert_no_leak(ours, STORE_TOKEN)
    (line,) = [record for record in ours if record.msg == site.template]
    assert line.exc_info is None
    assert line.args == ("LeakyStoreError", "none", fingerprint(STORE_TOKEN))
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


@pytest.mark.anyio
async def test_the_suppressed_kinds_notice_carries_no_token(
    records: list[logging.LogRecord],
) -> None:
    """The cap's one notice (D-411). Every failure here is a new kind, and each carries the token
    in its message; the notice itself is constant text and one constant number."""
    store = FakeStore(session_error=ShiftingStateError(f"down while reading {STORE_TOKEN}"))
    refused = verifier(store=store)
    cookie = f"{COOKIE}={sign(STORE_TOKEN)}"

    for _ in range(MAX_REPORTED_KINDS + 2):
        with pytest.raises(AuthServiceUnavailable):
            await run(refused, http(cookie=cookie))

    site = manifest_site("session store lookups are failing in more than")
    assert_template_fired(records, site)
    ours = [record for record in records if record.name == LIBRARY_LOGGER]
    assert_no_leak(ours, STORE_TOKEN)
    (notice,) = [record for record in ours if record.msg == site.template]
    assert notice.args == (MAX_REPORTED_KINDS,)
    assert notice.exc_info is None


@pytest.mark.parametrize(
    "test_name",
    sorted({name for callers in SHARED_LOG_FUNCTIONS.values() for name in callers.values()}),
)
def test_the_caller_manifest_names_tests_that_exist(test_name: str) -> None:
    """The same rule as `COVERED_BY`'s, for the scenarios that drive each caller of a shared site."""
    assert callable(getattr(sys.modules[__name__], test_name, None))


def test_a_session_data_observation_logs_no_cookie_value(
    records: list[logging.LogRecord],
) -> None:
    """The one line the cookie verifier emits. Seeing the out-of-scope `session_data` cookie warns
    once, naming the CVE; the cookie is never parsed, so its value never reaches the line. The
    latch is per-verifier (D-197), so this freshly built verifier starts unfired."""
    value = "sd_9f3ab21c9f3ab21c9f3ab21c"
    verifier = CookieVerifier(
        secret=SharedSecret(LEAKY_SECRET),
        store=RedisSessionStore(client=RecordingRedis()),
        csrf=CsrfDisabled(reason="log-hygiene scenario, no request is verified"),
        secure_cookies=False,
    )

    verifier.extract(connection(cookie=f"better-auth.session_data={value}"))

    observed = next(site for site in COVERED_BY if site.module == "cookie_verifier")
    assert_template_fired(records, observed)
    assert value not in rendered(records)


class _CookieSettingTransport:
    """Answers `null` to the bare probe and a `Set-Cookie` to the advisory bearer request - the
    permissive `requireSignature: false` shape. The set-cookie value is a sentinel so the scenario
    can prove it is never read into the line."""

    async def get(
        self, url: str, *, headers: Mapping[str, str] | None = None, max_bytes: int
    ) -> TransportResponse:
        present = headers is not None and "authorization" in headers
        extra = (
            {"set-cookie": "better-auth.session_token=CLEARED-SENTINEL; Max-Age=0"}
            if present
            else {}
        )
        return TransportResponse(
            status_code=200, headers={"content-type": "application/json", **extra}, content=b"null"
        )

    async def post(self, *args: Any, **kwargs: Any) -> TransportResponse:
        raise AssertionError("get-session is a GET; a POST here is a bug")  # pragma: no cover


def test_a_backoff_latch_warning_carries_no_credential(
    records: list[logging.LogRecord],
) -> None:
    """The 429 latch warns once when it trips, and the line names only the backoff seconds it read
    - it is built from an integer, so there is nothing a credential could ride in on."""
    latch = BackoffLatch(clock=time.monotonic)

    latch.observe(TransportResponse(status_code=429, headers={"x-retry-after": "12"}, content=b""))

    assert_template_fired(records, manifest_site("get-session is rate-limited"))
    assert STORE_TOKEN not in rendered(records)


def test_a_missing_field_advisory_carries_no_payload_value(
    records: list[logging.LogRecord],
) -> None:
    """`parse_user`'s one line. It fires on a *declared* field the payload does not carry, so
    the only thing it may name is the model's own field path - and the payload it was refusing
    is the whole authenticated user object, ids and plugin data included."""
    model = create_model("Scoped", __base__=User, jurisdiction_scope=(str, ...))

    with pytest.raises(SessionError):
        parse_user(model, {"id": STORED_USER_ID, "token": STORE_TOKEN, "jurisdiction": "KE"})

    assert_template_fired(records, manifest_site("%s declares required fields"))
    assert_no_leak(records, STORE_TOKEN, STORED_USER_ID)
    assert "jurisdictionScope" in rendered(records), "the operator cannot tell which key"


def test_the_advisory_require_signature_warning_carries_no_credential(
    records: list[logging.LogRecord], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The advisory bearer probe warns once when the permissive posture sets a cookie. The
    manufactured token it sent and the set-cookie value it saw are never read into the line -
    only its presence was consulted, per the `TransportResponse` rule."""
    monkeypatch.setattr(remote_probe, "_advised", Once())

    async def drive() -> None:
        await remote_probe.run_probe(
            _CookieSettingTransport(),
            uri=f"{ORIGIN}/api/auth/get-session",
            max_bytes=65536,
            refuse_unsigned_bearer=False,
        )

    anyio.run(drive)

    site = next(s for s in COVERED_BY if s.module == "remote_probe")
    assert_template_fired(records, site)
    assert "CLEARED-SENTINEL" not in rendered(records), "the set-cookie value reached the line"
