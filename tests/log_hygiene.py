"""The instrument the log-hygiene suites share: the enumeration, the manifest, and the capture.

Nothing this package logs, and nothing a consumer can log *from* it, carries a credential. The
rule the whole library is written to (D-018, D-087): a token, a signature, a secret or an
attacker-chosen `kid` reaches an operator only as a truncated fingerprint or a sanitized
label. Individual suites assert it for the `reason` each refusal builds. The three
`test_log_hygiene_*.py` suites assert it for the artefact those reasons actually end up in - a
`logging.LogRecord`, rendered the way a handler renders it, traceback included:

* `test_log_hygiene_manifest.py` proves this instrument, and that the manifest is honest;
* `test_log_hygiene_sites.py` drives every log site the library has, one scenario per entry;
* `test_log_hygiene_consumer.py` drives the channel a consumer logs a refusal through.

**Why the enumeration exists.** Two confirmed members of a set are not the set. `log_sites()`
is collected from `src/` by walking the AST, and `COVERED_BY` names the test that drives each
one; the two are asserted equal, so a future work package that adds a log site fails until it
is exercised rather than escaping silently. Each scenario then asserts *its own* template
appeared among the records, which is what keeps the manifest from being a declaration nobody
checks. The names in `COVERED_BY` resolve in `test_log_hygiene_sites.py`, and that file pins it.

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
(in `test_log_hygiene_sites.py`) pins exactly where the boundary sits, so nobody mistakes these
suites for a promise they cannot keep.

A plain module rather than a test file - the peer of `tests/refusal_frames.py` and
`tests/stores.py` - so the three suites read one enumeration and one manifest rather than copies
that could drift apart.
"""

from __future__ import annotations

import ast
import contextlib
import logging
import pathlib
from collections.abc import Generator, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

from fastapi_better_auth import Session, User
from tests.tokens import ed25519_signer, key_set

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
        module="authz",
        level="exception",
        template="the %s raised",
    ): "test_an_escaped_authorization_callback_logs_no_credential",
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
    LogSite(
        module="remote_backoff",
        level="warning",
        template="get-session is rate-limited upstream (429); backing off %ss before the next call",
    ): "test_a_backoff_latch_warning_carries_no_credential",
    LogSite(
        module="remote_probe",
        level="warning",
        template=(
            "get-session accepted a manufactured bearer token and set a session cookie, so the"
            " bearer plugin is at its default requireSignature: false. A raw session token is then"
            " a bearer credential, so a token in a log, dump or backup is a credential leak. The"
            " one-line fix upstream is bearer({ requireSignature: true }). Advisory only: Mode C"
            " forwards a cookie, never a bearer."
        ),
    ): "test_the_advisory_require_signature_warning_carries_no_credential",
}


# ---------------------------------------------------------------- capture and assertion


class _Collector(logging.Handler):
    def __init__(self, into: list[logging.LogRecord]) -> None:
        super().__init__(logging.DEBUG)
        self._into = into

    def emit(self, record: logging.LogRecord) -> None:
        self._into.append(record)


@contextlib.contextmanager
def capturing() -> Generator[list[logging.LogRecord], None, None]:
    """Every record on the root logger at DEBUG - this library's and a consumer's alike.

    Each suite wraps this in its own `records` fixture: a fixture imported from here would read
    as an unused import, so the behaviour has one home and the fixture sits beside its tests.
    """
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


def manifest_site(head: str) -> LogSite:
    """The manifest entry whose template starts with `head`, and exactly one of them.

    Selected on the template rather than on the module: `jwks` emits two lines now, and
    `next(s for s in COVERED_BY if s.module == ...)` would have picked whichever one the set
    happened to yield first - a scenario silently asserting about the other line's template.
    """
    found = [site for site in COVERED_BY if site.template.startswith(head)]
    assert len(found) == 1, f"{head!r} names {len(found)} log sites, not one"
    return found[0]


# ---------------------------------------------------------------- the verifier doubles


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
