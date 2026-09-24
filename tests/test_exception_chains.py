"""No exception raised inside an `except` in `src/` links back to the one being handled, unless listed.

Python records `__context__` on any exception raised while another is being handled, and `from
None` does not stop it: it clears `__cause__` and hides the chain from a default traceback, while
the handled exception - a decode error holding the cookie bytes, a verifier's error quoting the
credential - stays one attribute away for anything that walks the chain. The house pattern decides
the answer inside the handler and raises it after (`cookie_verifier._looked_up`, the SQL stores'
`_select`, `authz.permitted`).

This guard reads every module in `src/` as an AST - so a comment or a string can neither satisfy
it nor trip it, and it never scans itself - and lists each `raise` of an expression that sits
lexically inside a handler, attributed to its innermost handler. Re-raising that handler's own
bound name is the same exception and adds no link, so it is not listed; anything else must appear
in `ALLOWED`, with its reason - a construction-time `from exc` that chains, on purpose, an error
carrying no credential. The comparison is a multiset: a second raise in a listed function, a listed
site that disappears, and an unlisted one all fail it.
"""

from __future__ import annotations

import ast
import pathlib
import sys
from collections import Counter
from collections.abc import Mapping
from typing import NamedTuple

import pytest

PACKAGE = pathlib.Path(__file__).resolve().parents[1] / "src" / "fastapi_better_auth"
SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
MISSING_EXTRA = (
    "construction: a missing optional extra. The ImportError is chained on purpose, so the"
    " operator sees which import failed; it names a module and carries no credential."
)


class ChainedRaise(NamedTuple):
    """One raise inside a handler: where, in which function, and what it raises."""

    module: str
    function: str
    raised: str


ALLOWED: Mapping[ChainedRaise, str] = {
    ChainedRaise("_internal/httpx_transports.py", "_import_httpx", "ConfigurationError"): (
        MISSING_EXTRA
    ),
    ChainedRaise("_internal/httpx_transports.py", "_import_httpx2", "ConfigurationError"): (
        MISSING_EXTRA
    ),
    ChainedRaise("_internal/stores/redis_store.py", "_import_redis", "ConfigurationError"): (
        MISSING_EXTRA
    ),
    ChainedRaise("_internal/stores/sqlalchemy_store.py", "_core", "ConfigurationError"): (
        MISSING_EXTRA
    ),
    ChainedRaise("_internal/urls.py", "_split", "ConfigurationError"): (
        "construction: a base_url that urlsplit refuses. Its ValueError is chained on purpose - it"
        " names the malformed port or bracket - and quotes no userinfo; the URL is configuration."
    ),
}


def _raised(node: ast.Raise) -> str:
    assert node.exc is not None
    target = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
    return ast.unparse(target)


def _reraises_the_handled(node: ast.Raise, handled: str | None) -> bool:
    return handled is not None and isinstance(node.exc, ast.Name) and node.exc.id == handled


def chained_raises(tree: ast.AST, module: str) -> list[ChainedRaise]:
    """Every raise of an expression inside a handler, attributed to its innermost handler.

    A nested function, lambda or class body is not the handler's code - it runs later, when
    nothing is being handled - so it starts with no enclosing handler.
    """
    found: list[ChainedRaise] = []

    def visit(node: ast.AST, function: str, handlers: tuple[str | None, ...]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, SCOPES):
                inner = child.name if function == "<module>" else f"{function}.{child.name}"
                visit(child, inner, ())
            elif isinstance(child, ast.Lambda):
                visit(child, function, ())
            elif isinstance(child, ast.ExceptHandler):
                visit(child, function, (*handlers, child.name))
            else:
                if (
                    isinstance(child, ast.Raise)
                    and child.exc is not None
                    and handlers
                    and not _reraises_the_handled(child, handlers[-1])
                ):
                    found.append(ChainedRaise(module, function, _raised(child)))
                visit(child, function, handlers)

    visit(tree, "<module>", ())
    return found


def src_modules() -> list[pathlib.Path]:
    return sorted(path for path in PACKAGE.rglob("*.py") if "__pycache__" not in path.parts)


def found_in_src() -> Counter[ChainedRaise]:
    found: Counter[ChainedRaise] = Counter()
    for path in src_modules():
        module = path.relative_to(PACKAGE).as_posix()
        found.update(chained_raises(ast.parse(path.read_text(encoding="utf-8")), module))
    return found


def allowlisted() -> Counter[ChainedRaise]:
    """The allowlist as a multiset of sites. `Counter(ALLOWED)` would count its reasons."""
    return Counter(ALLOWED.keys())


def differences(found: Counter[ChainedRaise], allowed: Counter[ChainedRaise]) -> str:
    unlisted = sorted((found - allowed).elements())
    stale = sorted((allowed - found).elements())
    return f"unlisted: {unlisted}; listed but absent: {stale}"


def test_every_raise_inside_a_handler_in_src_is_an_allowlisted_deliberate_chain() -> None:
    found, allowed = found_in_src(), allowlisted()

    assert found == allowed, differences(found, allowed)


def test_the_scan_reads_the_whole_package() -> None:
    """Guards that scan nothing pass by vacuum."""
    scanned = {path.relative_to(PACKAGE).as_posix() for path in src_modules()}

    assert {"_internal/core.py", "_internal/authz.py", "_internal/urls.py"} <= scanned
    assert len(scanned) > 20


@pytest.mark.parametrize(
    "entry", list(ALLOWED), ids=lambda entry: f"{entry.module}:{entry.function}"
)
def test_every_allowlist_entry_is_load_bearing_and_explained(entry: ChainedRaise) -> None:
    """Removing any one entry turns the guard red, and each says why it may stay."""
    without = allowlisted()
    without[entry] -= 1

    assert found_in_src() != +without
    assert ALLOWED[entry].startswith("construction:")


def test_a_planted_violation_turns_the_guard_red() -> None:
    planted = chained_raises(ast.parse(PLANTED), "_internal/planted.py")

    assert planted == [ChainedRaise("_internal/planted.py", "translate", "InvalidCredential")]
    assert found_in_src() + Counter(planted) != allowlisted()


PLANTED = """
def translate(material):
    try:
        return decode(material)
    except UnicodeDecodeError:
        raise InvalidCredential(reason="undecodable") from None
"""


# --- the instrument -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("try:\n    x()\nexcept E:\n    raise F()\n", ["F"]),
        ("try:\n    x()\nexcept E:\n    raise F() from None\n", ["F"]),
        ("try:\n    x()\nexcept E as exc:\n    raise F() from exc\n", ["F"]),
        ("try:\n    x()\nexcept E:\n    if y:\n        raise F()\n", ["F"]),
        (
            "try:\n    x()\nexcept E:\n    try:\n        y()\n    finally:\n        raise F()\n",
            ["F"],
        ),
        (
            (
                "try:\n    x()\nexcept E as outer:\n    try:\n        y()\n    except G:\n"
                "        raise outer\n"
            ),
            ["outer"],
        ),
        ("try:\n    x()\nexcept E:\n    raise\n", []),
        ("try:\n    x()\nexcept E as exc:\n    raise exc\n", []),
        ("try:\n    x()\nexcept E as exc:\n    raise exc from None\n", []),
        ("try:\n    x()\nexcept E:\n    failure = F()\nraise failure from None\n", []),
        ("try:\n    x()\nexcept E:\n    pass\nelse:\n    raise F()\n", []),
        ("try:\n    x()\nexcept E:\n    def later():\n        raise F()\n", []),
        ("try:\n    x()\nexcept E:\n    later = lambda: (_ for _ in ()).throw(F())\n", []),
        ("try:\n    x()\nexcept E:\n    pass  # raise F() from None\n", []),
        ("try:\n    x()\nexcept E:\n    note = 'raise F() from None'\n", []),
    ],
    ids=[
        "raise-in-handler",
        "from-none-still-links",
        "from-exc",
        "nested-if",
        "finally-inside-handler",
        "outer-name-raised-in-an-inner-handler",
        "bare-raise",
        "re-raise-the-handled-name",
        "re-raise-the-handled-name-from-none",
        "raise-after-the-handler",
        "raise-in-else",
        "raise-in-a-nested-def",
        "lambda-body",
        "raise-in-a-comment",
        "raise-in-a-string",
    ],
)
def test_the_collector_reads_handlers_not_text(source: str, expected: list[str]) -> None:
    found = [site.raised for site in chained_raises(ast.parse(source), "m.py")]

    assert found == expected


@pytest.mark.skipif(sys.version_info < (3, 11), reason="except* is Python 3.11 syntax")
def test_the_collector_reads_an_except_star_handler() -> None:
    source = "try:\n    x()\nexcept* E:\n    raise F()\n"

    assert [site.raised for site in chained_raises(ast.parse(source), "m.py")] == ["F"]
