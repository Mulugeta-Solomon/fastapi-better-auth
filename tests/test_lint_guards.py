"""Bans enforced across `src/`, in two families that fail differently.

Every ban here encodes a security decision that a reviewer cannot be relied on to re-derive.
Each one is fired against a synthetic violation so the detector itself is proven, not assumed,
and each is fired against a commented-out copy so a trap comment may still name what it bans.

**Token rules** match a contiguous run of code tokens. That is the right shape for a banned
import or a banned attribute, where the spelling *is* the ban. Comments, NL/NEWLINE,
INDENT/DEDENT and encoding markers are dropped.

The D-010 rules deliberately do not name a receiver. A rule written as `request` `.` `url`
covers exactly the one identifier nothing in `src/` is called - the connection parameter is
`connection`, and a WebSocket-facing verifier would spell it differently again - so the
guard would have watched a spelling that never appears.

**AST rules** match a shape, and exist for the bans a token window cannot express. The
credential-into-`reason` ban is one: the difference between `reason=f"{token}"` and
`reason=f"token rejected {marker}"` is the difference between an *interpolated expression*
and literal text, which tokens do not distinguish. It is also the version-stable choice -
see below.

**The cross-version trap this file had to close (D-099).** An f-string tokenizes differently
across the supported matrix: on 3.10/3.11 the whole literal is one STRING token and its
interior is invisible to a token scanner, while on 3.12+ it arrives as FSTRING_START /
FSTRING_MIDDLE / FSTRING_END with the embedded expressions as real NAME and OP tokens. Every
token rule here was therefore blind inside f-strings on exactly two of the matrix legs -
`reason=f"{connection.url}"` would have passed the `.url` ban on 3.10 and failed it on 3.13.
`token_streams` closes it by re-opening a single-STRING-token f-string and scanning each
embedded expression as its own stream, so the guard sees the same thing on every interpreter.
"""

from __future__ import annotations

import ast
import io
import pathlib
import re
import token as token_types
import tokenize
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass

import pytest

SRC = pathlib.Path(__file__).resolve().parent.parent / "src"

# Comments, NL/NEWLINE, INDENT/DEDENT and encoding markers are dropped: a <=3-line trap
# comment naming a banned symbol must never trip the guard.
CODE_TOKENS = frozenset({token_types.NAME, token_types.OP, token_types.STRING, token_types.NUMBER})

Matcher = Callable[[tokenize.TokenInfo], bool]
Stream = tuple[tokenize.TokenInfo, ...]


def name(expected: str) -> Matcher:
    return lambda tok: tok.type == token_types.NAME and tok.string == expected


def op(expected: str) -> Matcher:
    return lambda tok: tok.type == token_types.OP and tok.string == expected


def text(expected: str) -> Matcher:
    """A string literal whose *value* equals `expected`, case-insensitively."""

    def matches(tok: tokenize.TokenInfo) -> bool:
        if tok.type != token_types.STRING:
            return False
        try:
            value = ast.literal_eval(tok.string)
        except (SyntaxError, ValueError):
            return False
        return isinstance(value, str) and value.lower() == expected

    return matches


@dataclass(frozen=True)
class Rule:
    """One ban: a contiguous code-token pattern, its reason, and a proof snippet."""

    id: str
    reason: str
    pattern: tuple[Matcher, ...]
    probe: str


@dataclass(frozen=True)
class AstRule:
    """One ban expressed as a shape, with the legal shapes it must leave alone."""

    id: str
    reason: str
    find: Callable[[ast.Module], Iterator[int]]
    probe: str
    legal: tuple[str, ...]


@dataclass(frozen=True)
class Violation:
    rule: Rule | AstRule
    path: pathlib.Path
    line: int


RULES: tuple[Rule, ...] = (
    Rule(
        id="pyjwk-client",
        reason="PyJWKClient banned: sync I/O, no size caps, no redirect policy — use the fortified JWKS client",
        pattern=(name("PyJWKClient"),),
        probe="from jwt import PyJWKClient\nclient = PyJWKClient(url)\n",
    ),
    Rule(
        id="urllib-request",
        reason="urllib.request banned: unbounded, blocking, follows redirects — all HTTP goes through the Transport Protocol",
        pattern=(name("urllib"), op("."), name("request")),
        probe="import urllib.request\nurllib.request.urlopen(url)\n",
    ),
    Rule(
        id="urllib-request-from-import",
        reason="urllib.request banned: unbounded, blocking, follows redirects — all HTTP goes through the Transport Protocol",
        pattern=(name("from"), name("urllib"), name("import"), name("request")),
        probe="from urllib import request\n",
    ),
    Rule(
        id="requests-import",
        reason="requests banned: synchronous and untyped — all HTTP goes through the Transport Protocol",
        pattern=(name("import"), name("requests")),
        probe="import requests\nrequests.get(url)\n",
    ),
    Rule(
        id="requests-from-import",
        reason="requests banned: synchronous and untyped — all HTTP goes through the Transport Protocol",
        pattern=(name("from"), name("requests")),
        probe="from requests import get\n",
    ),
    Rule(
        id="default-algorithms",
        reason="get_default_algorithms() banned: re-admits HS* on the JWKS path — pass an explicit allowlist at every decode",
        pattern=(name("get_default_algorithms"), op("(")),
        probe="algs = get_default_algorithms()\n",
    ),
    Rule(
        id="url-attribute",
        reason=".url banned on any connection: attacker-influenced via the Host header — iss/aud/origins come from operator config",
        pattern=(op("."), name("url")),
        probe="issuer = connection.url\n",
    ),
    Rule(
        id="base-url-attribute",
        reason=".base_url banned on any connection: attacker-influenced via the Host header — iss/aud/origins come from operator config",
        pattern=(op("."), name("base_url")),
        probe="issuer = request.base_url\n",
    ),
    Rule(
        id="forwarded-host-get",
        reason='headers.get("x-forwarded-host") banned: a proxy header is as attacker-controlled as Host',
        pattern=(op("."), name("get"), op("("), text("x-forwarded-host")),
        probe='host = connection.headers.get("X-Forwarded-Host")\n',
    ),
    Rule(
        id="forwarded-proto-get",
        reason='headers.get("x-forwarded-proto") banned: a proxy header is as attacker-controlled as Host',
        pattern=(op("."), name("get"), op("("), text("x-forwarded-proto")),
        probe='scheme = connection.headers.get("x-forwarded-proto")\n',
    ),
    Rule(
        id="forwarded-get",
        reason='headers.get("forwarded") banned: a proxy header is as attacker-controlled as Host',
        pattern=(op("."), name("get"), op("("), text("forwarded")),
        probe='hop = connection.headers.get("Forwarded")\n',
    ),
    Rule(
        id="forwarded-host-subscript",
        reason='headers["x-forwarded-host"] banned: a proxy header is as attacker-controlled as Host',
        pattern=(name("headers"), op("["), text("x-forwarded-host")),
        probe='host = connection.headers["x-forwarded-host"]\n',
    ),
    Rule(
        id="host-header-subscript",
        reason='headers["host"] banned: the Host header is attacker-controlled — never derive an auth value from it',
        pattern=(name("headers"), op("["), text("host")),
        probe='host = request.headers["Host"]\n',
    ),
    Rule(
        id="host-header-get",
        reason='headers.get("host") banned: the Host header is attacker-controlled — never derive an auth value from it',
        pattern=(op("."), name("get"), op("("), text("host")),
        probe='host = request.headers.get("host", "")\n',
    ),
)


# ---------------------------------------------------------------- the credential/reason ban

CREDENTIAL_WORDS = frozenset(
    {
        "credential",
        "credentials",
        "creds",
        "jwt",
        "passphrase",
        "password",
        "raw",
        "secret",
        "secrets",
        "sig",
        "signature",
        "token",
        "tokens",
    }
)
"""Matched against the *word parts* of an identifier, never as a substring.

`raw_token`, `rawToken` and `session_token` all name a credential; `tokenizer` does not, and
a substring rule could not tell them apart. `key` is deliberately absent: in this package a
key is a published *public* key, and banning the word would refuse the safe thing.
"""

SANITIZERS = frozenset({"fingerprint", "safe_label"})
"""`reason=f"{fingerprint(token)}"` is the sanctioned form, so a sanitized subtree is skipped.

`len` is deliberately not here. `f"{len(token)}"` is safe, and the ban still fires on it - the
fix is to bind `length = len(token)` before the reason, which is what `src/` already does and
what makes a reason reviewable line by line.
"""

WORD_BOUNDARY = re.compile(r"_+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def identifier_words(identifier: str) -> frozenset[str]:
    """`rawToken` and `raw_token` both become {"raw", "token"}; `tokenizer` stays one word."""
    return frozenset(part.lower() for part in WORD_BOUNDARY.split(identifier) if part)


def names_a_credential(identifier: str) -> bool:
    return bool(identifier_words(identifier) & CREDENTIAL_WORDS)


def _sanitized(node: ast.expr) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in SANITIZERS
    return isinstance(func, ast.Attribute) and func.attr in SANITIZERS


def bare_credentials(node: ast.AST) -> Iterator[str]:
    """Credential-shaped identifiers reachable without passing through a sanitizer.

    A manual descent rather than `ast.walk`, because the whole point is to *stop* at a
    sanitizer call and not read the credential it was handed.
    """
    if isinstance(node, ast.expr) and _sanitized(node):
        return
    if isinstance(node, ast.Name) and names_a_credential(node.id):
        yield node.id
    if isinstance(node, ast.Attribute) and names_a_credential(node.attr):
        yield node.attr
    for child in ast.iter_child_nodes(node):
        yield from bare_credentials(child)


def _built_from_expressions(value: ast.expr) -> ast.expr | None:
    """The `reason=` shapes that can carry a value, or `None` for the ones that cannot.

    A plain call - `reason=_ambiguity(names)` - is not one of them: what a helper puts in a
    reason is the helper's contract, and flagging it would flag every sanctioned form too.
    """
    if isinstance(value, (ast.JoinedStr, ast.Name, ast.Attribute)):
        return value
    if isinstance(value, ast.BinOp) and isinstance(value.op, (ast.Mod, ast.Add)):
        return value
    if isinstance(value, ast.Call):
        func = value.func
        if isinstance(func, ast.Attribute) and func.attr == "format":
            return value
    return None


def reason_interpolations(tree: ast.Module) -> Iterator[int]:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg != "reason":
                continue
            target = _built_from_expressions(keyword.value)
            if target is not None and next(bare_credentials(target), None) is not None:
                yield keyword.value.lineno


AST_RULES: tuple[AstRule, ...] = (
    AstRule(
        id="credential-in-reason",
        reason="a credential-named value interpolated into reason=: error reporters serialize exc.__dict__ and capture locals — pass it through fingerprint() or safe_label()",
        find=reason_interpolations,
        probe='raise InvalidCredential(reason=f"rejected {token}")\n',
        legal=(
            'raise InvalidCredential(reason=f"rejected {fingerprint(token)}")\n',
            'raise InvalidCredential(reason=f"alg={safe_label(alg)} is not allowed {marker}")\n',
            'raise InvalidCredential(reason=f"token rejected [{failure}] {marker}")\n',
            'raise InvalidCredential(reason=f"token is {length} bytes, over the cap {marker}")\n',
            "raise AmbiguousCredentials(reason=_ambiguity(names))\n",
            "raise MissingCredential(reason=self._nothing)\n",
            'raise InvalidCredential(reason="the credential is not a token")\n',
        ),
    ),
)


# ---------------------------------------------------------------- scanning

STRING_PREFIX_LETTERS = "bBfFrRuU"


def _is_fstring(literal: str) -> bool:
    """An `f` among the prefix letters before the opening quote: `rf` yes, `b` and `r` no."""
    prefix = literal[: len(literal) - len(literal.lstrip(STRING_PREFIX_LETTERS))]
    return "f" in prefix.lower()


def _embedded(tok: tokenize.TokenInfo) -> Iterator[Stream]:
    """Each expression embedded in a single-STRING-token f-string, as its own token stream.

    Reached only on 3.10/3.11: from 3.12 the interpreter already hands those expressions to
    the scanner as NAME and OP tokens. Every synthetic token is stamped with the literal's own
    line so a violation still points at real source.
    """
    line = tok.start[0]
    for node in ast.walk(ast.parse(tok.string)):
        if not isinstance(node, ast.FormattedValue):
            continue
        source = ast.unparse(node.value)
        stream = tuple(
            inner._replace(start=(line, inner.start[1]), end=(line, inner.end[1]))
            for inner in tokenize.generate_tokens(io.StringIO(source).readline)
            if inner.type in CODE_TOKENS
        )
        if stream:
            yield stream


def token_streams(source: str) -> tuple[Stream, ...]:
    """The file's code tokens, plus one stream per f-string interior the tokenizer hid.

    A separate stream rather than a splice: rules match a contiguous window, and splicing
    would let a pattern straddle the boundary between literal text and an expression.
    """
    main: list[tokenize.TokenInfo] = []
    extra: list[Stream] = []
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type in CODE_TOKENS:
            main.append(tok)
        if tok.type == token_types.STRING and _is_fstring(tok.string):
            extra.extend(_embedded(tok))
    return (tuple(main), *extra)


def scan(source: str, path: pathlib.Path) -> tuple[Violation, ...]:
    found: list[Violation] = []
    for stream in token_streams(source):
        for rule in RULES:
            width = len(rule.pattern)
            for start in range(len(stream) - width + 1):
                window = stream[start : start + width]
                if all(match(tok) for match, tok in zip(rule.pattern, window)):
                    found.append(Violation(rule=rule, path=path, line=window[0].start[0]))
    tree = ast.parse(source)
    for ast_rule in AST_RULES:
        found.extend(Violation(rule=ast_rule, path=path, line=line) for line in ast_rule.find(tree))
    return tuple(found)


def python_files(root: pathlib.Path) -> Iterator[pathlib.Path]:
    return (p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def src_files() -> Iterator[pathlib.Path]:
    """Only `src/` is scanned — the guard must never read its own probes out of tests/."""
    return python_files(SRC)


def scan_tree(root: pathlib.Path) -> tuple[Violation, ...]:
    found: list[Violation] = []
    for path in python_files(root):
        found.extend(scan(path.read_text(encoding="utf-8"), path))
    return tuple(found)


def _cited(path: pathlib.Path) -> str:
    """Relative to the repo for a real finding; absolute for a planted one under tmp_path."""
    try:
        return path.relative_to(SRC.parent).as_posix()
    except ValueError:
        return path.as_posix()


def render(violations: Sequence[Violation]) -> str:
    return "\n".join(f"  {_cited(v.path)}:{v.line} — {v.rule.reason}" for v in violations)


# ---------------------------------------------------------------- proving the instrument

ALL_RULES: tuple[Rule | AstRule, ...] = (*RULES, *AST_RULES)


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_detector_fires_on_a_synthetic_violation(rule: Rule | AstRule) -> None:
    """Prove the instrument: an unproven guard is not a guard."""
    fired = {v.rule.id for v in scan(rule.probe, pathlib.Path("<probe>"))}
    assert rule.id in fired, f"detector is blind to its own probe — {rule.reason}"


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_a_comment_naming_the_ban_does_not_fire(rule: Rule | AstRule) -> None:
    """A <=3-line trap comment must be able to name the thing it bans."""
    commented = "".join(f"# {line}\n" for line in rule.probe.splitlines())
    assert scan(commented, pathlib.Path("<probe>")) == ()


@pytest.mark.parametrize(
    ("rule_id", "legal"),
    [(rule.id, legal) for rule in AST_RULES for legal in rule.legal],
    ids=[f"{rule.id}-{index}" for rule in AST_RULES for index, _ in enumerate(rule.legal)],
)
def test_the_sanctioned_shapes_stay_legal(rule_id: str, legal: str) -> None:
    """A ban that also refuses the safe form is a ban nobody can comply with, and the safe
    form here is the one every refusal in `src/` already uses."""
    fired = {v.rule.id for v in scan(legal, pathlib.Path("<probe>"))}
    assert rule_id not in fired, f"the sanctioned form was refused: {legal.strip()}"


def test_scanner_reads_at_least_the_package_root() -> None:
    """Guards that scan an empty file set pass by vacuum."""
    scanned = {p.name for p in src_files()}
    assert "__init__.py" in scanned


def test_the_scan_fires_on_a_violation_planted_in_a_real_file(tmp_path: pathlib.Path) -> None:
    """The whole path - walk a tree, read a file, scan it - and not only the probe helper."""
    (tmp_path / "planted.py").write_text(
        "".join(rule.probe for rule in ALL_RULES), encoding="utf-8"
    )

    fired = {v.rule.id for v in scan_tree(tmp_path)}

    assert fired == {rule.id for rule in ALL_RULES}


def test_a_ban_inside_an_fstring_fires_on_every_interpreter() -> None:
    """The cross-version hole (D-099). This passes natively on 3.12+ and through
    `token_streams`' re-opening on 3.10/3.11 - the matrix legs prove both regimes."""
    probe = "reason = f\"host {connection.headers.get('host')} and {request.base_url}\"\n"

    fired = {v.rule.id for v in scan(probe, pathlib.Path("<probe>"))}

    assert "host-header-get" in fired
    assert "base-url-attribute" in fired


def test_an_fstring_that_arrives_as_one_string_token_is_reopened() -> None:
    """The 3.10/3.11 machinery, driven directly so it is proven on any interpreter."""
    literal = "f\"host {connection.headers.get('host')}\""
    tok = tokenize.TokenInfo(
        token_types.STRING, literal, (7, 0), (7, len(literal)), f"x = {literal}\n"
    )

    streams = tuple(_embedded(tok))

    assert streams, "the interior of the f-string was not reopened"
    assert any(inner.string == "headers" for stream in streams for inner in stream)
    assert all(inner.start[0] == 7 for stream in streams for inner in stream)


@pytest.mark.parametrize(
    ("literal", "expected"),
    [
        ('f"{x}"', True),
        ("F'{x}'", True),
        ('rf"{x}"', True),
        ('fr"""{x}"""', True),
        ('"plain"', False),
        ('b"bytes"', False),
        ('r"raw"', False),
    ],
    ids=["lower", "upper", "rf", "fr-triple", "plain", "bytes", "raw"],
)
def test_an_fstring_prefix_is_recognized_without_catching_a_plain_string(
    literal: str, expected: bool
) -> None:
    assert _is_fstring(literal) is expected


@pytest.mark.parametrize(
    ("identifier", "expected"),
    [
        ("token", True),
        ("raw_token", True),
        ("rawToken", True),
        ("session_token", True),
        ("_secret", True),
        ("HTTPSignature", True),
        ("credential", True),
        ("tokenizer", False),
        ("marker", False),
        ("algorithm", False),
        ("key", False),
        ("kid", False),
        ("length", False),
    ],
)
def test_an_identifier_is_matched_by_word_and_never_by_substring(
    identifier: str, expected: bool
) -> None:
    """`tokenizer` contains "token" and is not one. A substring rule could not say so."""
    assert names_a_credential(identifier) is expected


@pytest.mark.parametrize(
    "probe",
    [
        'raise InvalidCredential(reason=f"rejected {token}")\n',
        'raise InvalidCredential(reason=f"rejected {raw_token}")\n',
        'raise InvalidCredential(reason=f"rejected {self._secret}")\n',
        'raise InvalidCredential(reason="rejected {}".format(session_token))\n',
        'raise InvalidCredential(reason="rejected %s" % (credential,))\n',
        'raise InvalidCredential(reason="rejected " + signature)\n',
        "raise InvalidCredential(reason=token)\n",
        'raise InvalidCredential(reason=f"{fingerprint(token)} then {token}")\n',
    ],
    ids=[
        "f-string",
        "compound-name",
        "attribute",
        "format-method",
        "percent",
        "concat",
        "bare-name",
        "sanitized-then-not",
    ],
)
def test_every_interpolation_shape_is_caught(probe: str) -> None:
    """One shape left out is the shape the next leak uses. The last case matters most: a
    sanitized subtree is skipped, and that must not make the rest of the reason invisible."""
    fired = {v.rule.id for v in scan(probe, pathlib.Path("<probe>"))}

    assert "credential-in-reason" in fired


def test_src_is_free_of_banned_constructs() -> None:
    violations = scan_tree(SRC)
    assert not violations, "banned constructs in src/:\n" + render(violations)
