"""Token-level bans enforced across `src/`.

Every ban here encodes a security decision that a reviewer cannot be relied on to
re-derive. The scanner reads real code tokens only, so a trap comment naming a banned
symbol stays legal; each ban is also fired against a synthetic violation so the
detector itself is proven, not assumed.
"""

from __future__ import annotations

import ast
import io
import pathlib
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
class Violation:
    rule: Rule
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
        id="request-url",
        reason="request.url banned: attacker-influenced via the Host header — iss/aud/origins come from operator config",
        pattern=(name("request"), op("."), name("url")),
        probe="issuer = request.url\n",
    ),
    Rule(
        id="request-base-url",
        reason="request.base_url banned: attacker-influenced via the Host header — iss/aud/origins come from operator config",
        pattern=(name("request"), op("."), name("base_url")),
        probe="issuer = request.base_url\n",
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


def code_tokens(source: str) -> tuple[tokenize.TokenInfo, ...]:
    readline = io.StringIO(source).readline
    return tuple(tok for tok in tokenize.generate_tokens(readline) if tok.type in CODE_TOKENS)


def scan(source: str, path: pathlib.Path) -> tuple[Violation, ...]:
    tokens = code_tokens(source)
    found: list[Violation] = []
    for rule in RULES:
        width = len(rule.pattern)
        for start in range(len(tokens) - width + 1):
            window = tokens[start : start + width]
            if all(match(tok) for match, tok in zip(rule.pattern, window)):
                found.append(Violation(rule=rule, path=path, line=window[0].start[0]))
    return tuple(found)


def src_files() -> Iterator[pathlib.Path]:
    """Only `src/` is scanned — the guard must never read its own probes out of tests/."""
    return (p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts)


def render(violations: Sequence[Violation]) -> str:
    return "\n".join(
        f"  {v.path.relative_to(SRC.parent).as_posix()}:{v.line} — {v.rule.reason}"
        for v in violations
    )


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_detector_fires_on_a_synthetic_violation(rule: Rule) -> None:
    """Prove the instrument: an unproven guard is not a guard."""
    fired = {v.rule.id for v in scan(rule.probe, pathlib.Path("<probe>"))}
    assert rule.id in fired, f"detector is blind to its own probe — {rule.reason}"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_a_comment_naming_the_ban_does_not_fire(rule: Rule) -> None:
    """A <=3-line trap comment must be able to name the thing it bans."""
    commented = "".join(f"# {line}\n" for line in rule.probe.splitlines())
    assert scan(commented, pathlib.Path("<probe>")) == ()


def test_scanner_reads_at_least_the_package_root() -> None:
    """Guards that scan an empty file set pass by vacuum."""
    scanned = {p.name for p in src_files()}
    assert "__init__.py" in scanned


def test_src_is_free_of_banned_constructs() -> None:
    violations: list[Violation] = []
    for path in src_files():
        violations.extend(scan(path.read_text(encoding="utf-8"), path))
    assert not violations, "banned constructs in src/:\n" + render(violations)
