"""Nothing this package logs, and nothing a consumer can log *from* it, carries a credential.

The rule the whole library is written to (D-018, D-087): a token, a signature, a secret or an
attacker-chosen `kid` reaches an operator only as a truncated fingerprint or a sanitized
label. Individual suites assert it for the `reason` each refusal builds. This one asserts it
for the artefact those reasons actually end up in - a `logging.LogRecord`, rendered the way a
handler renders it, traceback included.

**Why the enumeration exists.** Two confirmed members of a set are not the set. `LOG_SITES`
is collected from `src/` by walking the AST for calls on a logger, and `COVERED_BY` names the
test that drives each one; the two are asserted equal, so a future work package that adds a
log site fails here until it is exercised rather than escaping silently. Each scenario then
asserts *its own* template appeared among the records, which is what keeps the manifest from
being a declaration nobody checks.

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
import re
import sys
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

import pytest

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuth,
    ConfigurationError,
    Session,
    SessionError,
    SharedSecret,
    User,
)
from fastapi_better_auth._internal.jwks import JwksClient
from fastapi_better_auth._internal.jwt_verifier import JwtVerifier
from fastapi_better_auth._internal.reasons import REDACTED, fingerprint
from tests.fakes import connection, resolver_of
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
LOGGER_WORDS = frozenset({"log", "logger", "logging", "logs"})
MIN_NEEDLE = 8
"""A needle shorter than this matches by accident, not by leak."""

SIGNER = ed25519_signer("wp6-1")
KEY_SET = key_set(SIGNER)
WRONG_KEY = ed25519_signer("wp6-1")
"""A different key published under the *same* kid - the substituted-key-set shape."""

ORIGIN = "https://auth.example.com"
HOSTILE_KID = 'evil-kid-9f3ab21c"\n2026-01-01 CRITICAL forged log line'
LEAKY_SECRET = "Zt7Qv1oXbK4mPr9wCyHnLdEuAsJf2Ng6"
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


def _words(identifier: str) -> frozenset[str]:
    return frozenset(
        part for part in re.split(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])", identifier) if part
    )


def _is_logger(receiver: ast.expr) -> bool:
    """`logger`, `LOGGER`, `self._logger`, `logging.getLogger("x")` - but never `self.dialog`."""
    named = {word.lower() for word in _words(ast.unparse(receiver))}
    return bool(named & LOGGER_WORDS)


def _template(call: ast.Call) -> str:
    first = call.args[0] if call.args else None
    return first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else ""


def src_files() -> Iterator[pathlib.Path]:
    return (p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts)


def log_sites() -> frozenset[LogSite]:
    found: set[LogSite] = set()
    for path in src_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in LEVELS or not _is_logger(node.func.value):
                continue
            found.add(LogSite(module=path.stem, level=node.func.attr, template=_template(node)))
    return frozenset(found)


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
    ("source", "expected"),
    [
        ("logger.warning('x')", True),
        ("LOGGER.error('x')", True),
        ("self._logger.info('x')", True),
        ("logging.getLogger('a').debug('x')", True),
        ("self.dialog.error('x')", False),
        ("catalogue.info('x')", False),
    ],
    ids=["logger", "upper", "attribute", "inline", "dialog", "catalogue"],
)
def test_the_collector_recognizes_a_logger_without_mistaking_a_word_for_one(
    source: str, expected: bool
) -> None:
    """Prove the instrument. `dialog` and `catalogue` both contain "log"; neither is one."""
    call = ast.parse(source).body[0]
    assert isinstance(call, ast.Expr) and isinstance(call.value, ast.Call)
    func = call.value.func
    assert isinstance(func, ast.Attribute)

    assert _is_logger(func.value) is expected


def test_the_collector_finds_a_synthetic_site_in_a_planted_file(tmp_path: pathlib.Path) -> None:
    """The scan is exercised end to end against a file it has never seen."""
    planted = tmp_path / "planted.py"
    planted.write_text("import logging\nlogger = logging.getLogger()\nlogger.info('hi %s', x)\n")

    tree = ast.parse(planted.read_text(encoding="utf-8"))
    calls = [
        n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    ]
    sites = {
        LogSite(planted.stem, call.func.attr, _template(call))
        for call in calls
        if isinstance(call.func, ast.Attribute)
        and call.func.attr in LEVELS
        and _is_logger(call.func.value)
    }

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

    assert_template_fired(records, next(s for s in COVERED_BY if s.module == "jwks"))
    assert HOSTILE_KID not in rendered(records)
    assert "forged log line" not in rendered(records)
    assert REDACTED in caught.value.reason


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
