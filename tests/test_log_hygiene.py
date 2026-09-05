"""Nothing this package logs, and nothing a consumer can log *from* it, carries a credential.

The rule the whole library is written to (D-018, D-087): a token, a signature, a secret or an
attacker-chosen `kid` reaches an operator only as a truncated fingerprint or a sanitized
label. Individual suites assert it for the `reason` each refusal builds. This one asserts it
for the artefact those reasons actually end up in - a `logging.LogRecord`, rendered the way a
handler renders it, traceback included.

**Why the enumeration exists.** Two confirmed members of a set are not the set. `log_sites()`
is collected from `src/` by walking the AST, and `COVERED_BY` names the test that drives each
one; the two are asserted equal, so a future work package that adds a log site fails here until
it is exercised rather than escaping silently. Each scenario then asserts *its own* template
appeared among the records, which is what keeps the manifest from being a declaration nobody
checks.

**The collector reads the call, never the receiver's name** (D-104). An earlier cut matched the
receiver against log-shaped words, so `audit = logging.getLogger(...)`, `_L`, and `self._sink`
were all invisible - the enumeration was blind to precisely the site nobody anticipated, which
is the only kind it exists to catch. Every call of a logging method is collected whatever its
receiver is called; over-collection fails loud and gets classified on purpose, and two
structural pins keep that cheap to read: `getLogger` may only be bound to a module-level
`logger`, and a log message must be a literal `%`-style template (which is also the
log-injection-safe form - `logging` renders the arguments, so nothing a client chose can become
the template).

**The limit, stated because it is real.** `core._contained` logs the traceback of an
exception that escaped somebody else's verifier. If that verifier put the raw credential into
its own exception message, the traceback carries it - and that is the verifier author's leak,
not this library's. `test_a_verifier_that_leaks_into_its_own_exception_is_not_contained_by_us`
pins exactly where the boundary sits, so nobody mistakes this suite for a promise it cannot
keep.
"""

from __future__ import annotations

import ast
import logging
import pathlib
import sys
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

import pytest
from sqlalchemy import Engine
from sqlalchemy import text as sqla_text
from sqlalchemy.ext.asyncio import AsyncEngine

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuth,
    ConfigurationError,
    CookieVerifier,
    CsrfDisabled,
    RedisSessionStore,
    Session,
    SessionError,
    SessionStore,
    SharedSecret,
    SqlAlchemySessionStore,
    SyncStoreAdapter,
    User,
)
from fastapi_better_auth._internal.jwks import JwksClient
from fastapi_better_auth._internal.jwt_verifier import JwtVerifier
from fastapi_better_auth._internal.reasons import REDACTED, fingerprint
from tests.fakes import connection, resolver_of
from tests.stores import RecordingRedis, async_engine, build_schema, sync_engine
from tests.tokens import (
    Clock,
    claims,
    ed25519_signer,
    forged,
    key_set,
    tampered,
    unsigned,
)
from tests.transports import Reply, ScriptedTransport, json_reply

UserModelT = TypeVar("UserModelT", bound=User)

SRC = pathlib.Path(__file__).resolve().parent.parent / "src"
LIBRARY_LOGGER = "fastapi_better_auth"
CONSUMER_LOGGER = "some.application"

LEVELS = frozenset({"critical", "debug", "error", "exception", "info", "log", "warn", "warning"})
LOGGER_BINDING = "logger"
NON_LITERAL = "<non-literal>"
"""What `_template` returns for a message that is not a string literal - and never a real one."""
MIN_NEEDLE = 8
"""A needle shorter than this matches by accident, not by leak."""

SIGNER = ed25519_signer("wp6-1")
KEY_SET = key_set(SIGNER)
WRONG_KEY = ed25519_signer("wp6-1")
"""A different key published under the *same* kid - the substituted-key-set shape."""

ORIGIN = "https://auth.example.com"
HOSTILE_KID = 'evil-kid-9f3ab21c"\n2026-01-01 CRITICAL forged log line'
LEAKY_SECRET = "Zt7Qv1oXbK4mPr9wCyHnLdEuAsJf2Ng6"
STORE_TOKEN = "wBNhqX3M2CKkT7bmDTmeEMA1S1qCcWnn"
STORED_USER_ID = "cIrUeXmXVG5Kg0Pzt4rCozIxLv3oeOMG"
UNREADABLE = (
    f'{{"session": {{"token": "{STORE_TOKEN}", "userId": "{STORED_USER_ID}",'
    f' "expiresAt": "soon"}}, "user": {{"id": "{STORED_USER_ID}"}}}}'
)
"""A stored value whose expiry will not parse, so the whole record is refused - and both the key
it sat under and the ids inside it are candidates to leak into the line that refuses it."""
FORMATTER = logging.Formatter("%(name)s %(levelname)s %(message)s")


# ---------------------------------------------------------------- the enumeration


@dataclass(frozen=True)
class LogSite:
    """One `logger.<level>(...)` call in `src/`, keyed by nothing that moves with an edit.

    Deliberately not keyed on a line number: every edit above a site would rewrite the
    manifest, and a manifest people rewrite by reflex stops being read.
    """

    module: str
    level: str
    template: str


def _template(call: ast.Call) -> str:
    """The literal `%`-style template, or `NON_LITERAL` for anything the enumeration cannot key.

    A message built at the call site - an f-string, a pre-assembled variable - is unclassifiable
    here *and* is the shape that carries interpolated values into a log line in the first place.
    It is not silently tolerated: it becomes a sentinel that fails its own test (B4).
    """
    first = call.args[0] if call.args else None
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value
    return NON_LITERAL


def collect_log_sites(tree: ast.Module, module: str) -> frozenset[LogSite]:
    """Every call of a logging method, whatever its receiver is called.

    Receiver spelling is *not* consulted (B3). A previous cut matched the receiver against
    log-shaped words, which meant `audit = logging.getLogger(...); audit.warning(...)` - or
    `_L`, or `self._sink` - was invisible to the enumeration whose entire job is to notice a
    new log site. Over-collection is the correct failure mode here: a non-logger `.warning(...)`
    landing in `src/` fails this suite loudly and gets classified on purpose.
    """
    return frozenset(
        LogSite(module=module, level=node.func.attr, template=_template(node))
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in LEVELS
    )


def _is_get_logger(func: ast.expr) -> bool:
    return (isinstance(func, ast.Attribute) and func.attr == "getLogger") or (
        isinstance(func, ast.Name) and func.id == "getLogger"
    )


def logger_binding_violations(tree: ast.Module, module: str) -> tuple[str, ...]:
    """Every `getLogger` call that is not bound to a module-level name `logger`.

    The convention is what makes B3's over-collection cheap to read: one logger per module,
    one name, bound where `grep` finds it. An inline `logging.getLogger("x").warning(...)`,
    a binding inside a function, and an alias all fail here.
    """
    bound = {
        id(statement.value): target.id
        for statement in tree.body
        if isinstance(statement, ast.Assign) and isinstance(statement.value, ast.Call)
        if _is_get_logger(statement.value.func)
        for target in statement.targets
        if isinstance(target, ast.Name)
    }
    return tuple(
        f"{module}:{call.lineno} binds getLogger to {bound.get(id(call), '<nothing>')!r};"
        f" this package binds it once per module to a module-level `{LOGGER_BINDING}`"
        for call in ast.walk(tree)
        if isinstance(call, ast.Call) and _is_get_logger(call.func)
        if bound.get(id(call)) != LOGGER_BINDING
    )


def src_files() -> Iterator[pathlib.Path]:
    return (p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts)


def parsed_src() -> Iterator[tuple[str, ast.Module]]:
    for path in src_files():
        yield path.stem, ast.parse(path.read_text(encoding="utf-8"))


def log_sites() -> frozenset[LogSite]:
    return frozenset(
        site for module, tree in parsed_src() for site in collect_log_sites(tree, module)
    )


COVERED_BY: Mapping[LogSite, str] = {
    LogSite(
        module="core",
        level="exception",
        template="%s.%s raised",
    ): "test_a_contained_verifier_escape_logs_no_credential",
    LogSite(
        module="jwks",
        level="warning",
        template="jwks refresh failed for %s; serving the key set on hand",
    ): "test_a_jwks_refresh_failure_logs_no_attacker_chosen_kid",
    LogSite(
        module="jwks",
        level="warning",
        template="jwks key %s is not usable for signature verification (%s); it is skipped",
    ): "test_a_skipped_jwks_key_logs_neither_its_kid_nor_its_material",
    LogSite(
        module="diagnostics",
        level="warning",
        template="stored %s is unusable (%s); answering a miss [%s]",
    ): "test_a_malformed_stored_session_logs_no_token",
    LogSite(
        module="diagnostics",
        level="warning",
        template=(
            "table %s is missing better-auth columns this store reads: %s;"
            " the fields they feed will be absent from every record"
        ),
    ): "test_a_schema_drift_warning_carries_only_operator_owned_names",
    LogSite(
        module="cookie_verifier",
        level="warning",
        template=(
            "a %s cookie was observed; the session-data cookie cache is out of scope in this"
            " version (CVE-2026-67337, a 2FA bypass through exactly that cache) and is never parsed"
        ),
    ): "test_a_session_data_observation_logs_no_cookie_value",
}


# ---------------------------------------------------------------- capture and assertion


class _Collector(logging.Handler):
    def __init__(self, into: list[logging.LogRecord]) -> None:
        super().__init__(logging.DEBUG)
        self._into = into

    def emit(self, record: logging.LogRecord) -> None:
        self._into.append(record)


@pytest.fixture
def records() -> Iterator[list[logging.LogRecord]]:
    """Every record on the root logger at DEBUG - this library's and a consumer's alike."""
    collected: list[logging.LogRecord] = []
    handler = _Collector(collected)
    root = logging.getLogger()
    previous = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        yield collected
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)


def rendered(records: list[logging.LogRecord]) -> str:
    """What a handler would actually write out: the message, the args, and the traceback."""
    return "\n".join(f"{FORMATTER.format(record)} {record.args!r}" for record in records)


def needles(*credentials: str) -> tuple[str, ...]:
    """A credential and each of its segments - a signature alone is enough to be a leak."""
    parts = [piece for value in credentials for piece in (value, *value.split("."))]
    return tuple(dict.fromkeys(part for part in parts if len(part) >= MIN_NEEDLE))


def assert_no_leak(records: list[logging.LogRecord], *credentials: str) -> None:
    assert records, "nothing was logged; this scenario proves nothing"
    written = rendered(records)
    for needle in needles(*credentials):
        assert needle not in written, f"a credential substring reached a log record: {needle[:12]}…"


def assert_template_fired(records: list[logging.LogRecord], site: LogSite) -> None:
    fired = [r for r in records if r.name == LIBRARY_LOGGER and r.msg == site.template]
    assert fired, f"the scenario never reached {site.module}.logger.{site.level}"
    assert fired[0].levelname.lower() in {site.level, "error"}


def consumer() -> logging.Logger:
    return logging.getLogger(CONSUMER_LOGGER)


def _site(head: str) -> LogSite:
    """The manifest entry whose template starts with `head`, and exactly one of them.

    Selected on the template rather than on the module: `jwks` emits two lines now, and
    `next(s for s in COVERED_BY if s.module == ...)` would have picked whichever one the set
    happened to yield first - a scenario silently asserting about the other line's template.
    """
    found = [site for site in COVERED_BY if site.template.startswith(head)]
    assert len(found) == 1, f"{head!r} names {len(found)} log sites, not one"
    return found[0]


# ---------------------------------------------------------------- the manifest is honest


def test_every_log_site_in_src_is_driven_by_a_scenario() -> None:
    """A sampled property is not a set property: this is the enumeration, not a sample.

    A new `logger.*` call anywhere in `src/` fails here until a scenario drives it, which is
    the only thing that stops an unexercised log line from being the one that leaks.
    """
    assert log_sites() == frozenset(COVERED_BY)


@pytest.mark.parametrize("test_name", sorted(set(COVERED_BY.values())))
def test_the_manifest_names_tests_that_exist(test_name: str) -> None:
    """A manifest entry pointing at a test nobody wrote is a coverage claim, not coverage."""
    assert callable(getattr(sys.modules[__name__], test_name, None))


def test_the_collector_is_not_reading_an_empty_file_set() -> None:
    """Guards that scan nothing pass by vacuum."""
    scanned = {path.name for path in src_files()}

    assert "core.py" in scanned
    assert "jwks.py" in scanned
    assert len(log_sites()) >= 2


@pytest.mark.parametrize(
    ("source", "level"),
    [
        ("logger.warning('hi %s', v)", "warning"),
        ("audit = logging.getLogger('x')\naudit.warning('hi %s', v)", "warning"),
        ("_L = logging.getLogger('x')\n_L.info('hi %s', v)", "info"),
        ("self._sink.error('hi %s', v)", "error"),
        ("AUDIT.exception('hi %s', v)", "exception"),
        ("logging.getLogger('x').critical('hi %s', v)", "critical"),
        ("from logging import getLogger\ntrail = getLogger('x')\ntrail.debug('hi %s', v)", "debug"),
    ],
    ids=["logger", "aliased", "initial", "method-receiver", "upper", "inline", "from-import"],
)
def test_the_collector_sees_a_log_call_whatever_its_receiver_is_called(
    source: str, level: str
) -> None:
    """B3, as reproduced. Every one of these was invisible to the previous collector, which
    matched the receiver against log-shaped words - so the one thing this enumeration exists to
    catch, a log site added under a name nobody anticipated, was exactly what it could not see.
    """
    sites = collect_log_sites(ast.parse(source), "probe")

    assert LogSite("probe", level, "hi %s") in sites


@pytest.mark.parametrize(
    "source",
    ["logger.info(f'hi {v}')", "logger.info(msg)", "logger.info()", "logger.info(TEMPLATE % v)"],
    ids=["f-string", "variable", "no-args", "pre-formatted"],
)
def test_a_message_that_is_not_a_literal_is_marked_rather_than_swallowed(source: str) -> None:
    """B4. All four used to collapse to `""`, which is a *valid-looking* template - so the site
    joined the enumeration under a key that says nothing and matched nothing."""
    sites = collect_log_sites(ast.parse(source), "probe")

    assert {site.template for site in sites} == {NON_LITERAL}


def test_every_log_call_in_src_passes_a_literal_template() -> None:
    """B4 over the real tree. A `%`-style literal plus arguments is also the log-injection-safe
    form: `logging` renders the arguments, so nothing a client chose becomes the template."""
    offenders = [site for site in log_sites() if site.template == NON_LITERAL]

    assert not offenders, (
        "these log calls build their message at the call site rather than passing a literal"
        f" template and arguments: {sorted((s.module, s.level) for s in offenders)}"
    )


def test_get_logger_is_only_ever_bound_to_a_module_level_logger() -> None:
    """The convention that makes B3's over-collection cheap: one logger per module, one name.

    Without it, `collect_log_sites` catching every `.warning(...)` would be noise; with it, a
    reviewer knows any logging call in `src/` goes through the one binding at the top of the file.
    """
    offenders = [
        problem
        for module, tree in parsed_src()
        for problem in logger_binding_violations(tree, module)
    ]

    assert not offenders, "\n".join(offenders)


@pytest.mark.parametrize(
    ("source", "compliant"),
    [
        ("import logging\nlogger = logging.getLogger('x')\n", True),
        ("from logging import getLogger\nlogger = getLogger('x')\n", True),
        ("import logging\naudit = logging.getLogger('x')\n", False),
        ("import logging\nlogging.getLogger('x').info('hi')\n", False),
        ("import logging\ndef f():\n    logger = logging.getLogger('x')\n", False),
        ("import logging\nself.logger = logging.getLogger('x')\n", False),
    ],
    ids=["module-level", "from-import", "aliased", "inline", "in-function", "attribute"],
)
def test_the_binding_pin_fires_on_every_way_of_getting_it_wrong(
    source: str, compliant: bool
) -> None:
    """Prove the instrument, both directions: a pin that never fires pins nothing."""
    assert (logger_binding_violations(ast.parse(source), "probe") == ()) is compliant


def test_the_collector_finds_a_synthetic_site_in_a_planted_file(tmp_path: pathlib.Path) -> None:
    """The scan is exercised end to end against a file it has never seen."""
    planted = tmp_path / "planted.py"
    planted.write_text(
        "import logging\nlogger = logging.getLogger()\nlogger.info('hi %s', x)\n", encoding="utf-8"
    )

    sites = collect_log_sites(ast.parse(planted.read_text(encoding="utf-8")), planted.stem)

    assert LogSite("planted", "info", "hi %s") in sites


# ---------------------------------------------------------------- the driven scenarios


class QuietlyRaisingVerifier:
    """Escapes with an exception that does *not* name the credential - so what reaches the
    log is only what this library put there."""

    credential_source = "header:x-quiet"

    def extract(self, connection: Any) -> str | None:
        return connection.headers.get("x-quiet")

    async def verify(self, credential: str, user_model: type[UserModelT]) -> Session[UserModelT]:
        raise RuntimeError("upstream client blew up")


class LeakyVerifier(QuietlyRaisingVerifier):
    """Puts the credential into its own exception message - somebody else's bug, pinned here."""

    credential_source = "header:x-leaky"

    def extract(self, connection: Any) -> str | None:
        return connection.headers.get("x-leaky")

    async def verify(self, credential: str, user_model: type[UserModelT]) -> Session[UserModelT]:
        raise RuntimeError(f"blew up on {credential}")


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

    assert_template_fired(records, _site("jwks refresh failed"))
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

    assert_template_fired(records, _site("jwks key %s is not usable"))
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

    assert_template_fired(records, _site("stored %s is unusable"))
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
