"""The e2e lane is also run against the *published* wheel, which is older than HEAD.

The canary's `published-wheel` job checks out HEAD's test suite and installs whatever PyPI
serves. Every module in `tests/e2e/` therefore meets a library that predates it, and the only
honest answer for a module that needs a post-release feature is to self-skip at module level.
A skip written as `try: from fastapi_better_auth import New except ImportError: pytest.skip(...)`
does that — but only if no *unguarded* import of a post-release name runs first. Put one above
the guard and the guard is dead on exactly the build it exists for: collection raises
`ImportError` and the whole lane is red before a single test runs.

That is not a failure the unit lane can notice by accident, because the unit lane always has
HEAD installed, where every name resolves. This file makes it noticeable *before* merge. In a
subprocess it fronts `sys.path` with a stub package whose surface is exactly the surface of the
0.1.0 wheel — a frozen historical fact, so it cannot go stale — imports every `tests/e2e`
module against it, and requires each one to either import cleanly or raise `Skipped`. Anything
else, `ImportError` above all, is the wheel lane going red at the next weekly canary.

`test_conformance` is held to the stricter rule: it must always import *cleanly*. It is the
lane's floor. If the skip pattern ever spread to it, the published-wheel job could skip
everything and report green having tested nothing.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
from collections.abc import Mapping
from typing import Any, NamedTuple, cast

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
E2E = ROOT / "tests" / "e2e"

PUBLISHED_EXPORTS = (
    "AmbiguousCredentials",
    "AuthServiceUnavailable",
    "BEARER_CHALLENGE",
    "BetterAuth",
    "BetterAuthError",
    "ConfigurationError",
    "ContentEncodingRejected",
    "CsrfFailure",
    "Httpx2Transport",
    "HttpxTransport",
    "InvalidCredential",
    "JwtVerifier",
    "MissingCredential",
    "ResponseTooLarge",
    "Session",
    "SessionError",
    "SessionExpired",
    "SessionRevoked",
    "SharedSecret",
    "Transport",
    "TransportResponse",
    "UntrustedResponse",
    "User",
    "UserT",
    "Verifier",
    "normalize_base_url",
    "parse_user",
)
"""`fastapi_better_auth.__all__` as 0.1.0 published it — the oldest release the wheel lane can
install. History, not a moving target: this tuple is correct forever and never needs updating."""

PUBLISHED_INTERNAL_MODULES = (
    "core",
    "errors",
    "httpx_transports",
    "jwks",
    "jwt_verifier",
    "models",
    "openapi",
    "parsing",
    "reasons",
    "shared_secret",
    "transport",
    "urls",
    "verifiers",
)
"""`fastapi_better_auth._internal` as 0.1.0 shipped it. Every private module added since —
`cookie_verifier`, `csrf`, `stores` — is absent here, so importing one raises `ImportError`
exactly as it does on the wheel. Names *inside* a surviving module are not modelled."""

POST_RELEASE_SYMBOL = "CsrfDisabled"
"""Absent from 0.1.0. The probe that proves the subprocess really got the stub."""

FLOOR = "test_conformance"

STUB_HEADER = '"""Not the library. A stand-in whose only content is 0.1.0\'s export surface."""\n\n'
INTERNAL_STUB = (
    '"""Not the library. Any attribute resolves; only this module\'s existence is modelled."""\n'
    "\n"
    "\n"
    "def __getattr__(name):\n"
    "    return type(name, (), {})\n"
)

RUNNER = '''\
"""Import every e2e module against the stub and report what happened, as JSON."""

import importlib
import json
import pathlib
import sys

stub, root, e2e, probe = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
sys.path.insert(0, stub)
sys.path.insert(1, root)

import fastapi_better_auth
import pytest

modules = {}
for path in sorted(pathlib.Path(e2e).glob("test_*.py")):
    try:
        importlib.import_module("tests.e2e." + path.stem)
    except pytest.skip.Exception as exc:
        modules[path.stem] = "skipped: " + str(exc)
    except Exception as exc:
        modules[path.stem] = type(exc).__name__ + ": " + str(exc)
    else:
        modules[path.stem] = "imported"

print(
    json.dumps(
        {
            "library": fastapi_better_auth.__file__,
            "post_release_symbol_resolves": hasattr(fastapi_better_auth, probe),
            "modules": modules,
        }
    )
)
'''


class Report(NamedTuple):
    """What the subprocess saw."""

    stub: pathlib.Path
    library: str
    post_release_symbol_resolves: bool
    modules: Mapping[str, str]


def write_stub(directory: pathlib.Path) -> pathlib.Path:
    """A package that answers to exactly what 0.1.0 published, and to nothing newer."""
    package = directory / "fastapi_better_auth"
    internal = package / "_internal"
    internal.mkdir(parents=True)
    exports = "\n".join(f'{name} = type("{name}", (), {{}})' for name in PUBLISHED_EXPORTS)
    package.joinpath("__init__.py").write_text(STUB_HEADER + exports + "\n", encoding="utf-8")
    internal.joinpath("__init__.py").write_text(STUB_HEADER, encoding="utf-8")
    for name in PUBLISHED_INTERNAL_MODULES:
        internal.joinpath(f"{name}.py").write_text(INTERNAL_STUB, encoding="utf-8")
    return directory


@pytest.fixture(scope="session")
def report(tmp_path_factory: pytest.TempPathFactory) -> Report:
    """One subprocess for the whole file: never mutate this interpreter's `sys.modules`."""
    workspace = tmp_path_factory.mktemp("published-wheel-surface")
    stub = write_stub(workspace / "stub")
    runner = workspace / "import_every_e2e_module.py"
    runner.write_text(RUNNER, encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, str(runner), str(stub), str(ROOT), str(E2E), POST_RELEASE_SYMBOL],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr

    parsed = cast("dict[str, Any]", json.loads(completed.stdout))
    return Report(
        stub=stub,
        library=parsed["library"],
        post_release_symbol_resolves=parsed["post_release_symbol_resolves"],
        modules=parsed["modules"],
    )


def test_the_subprocess_imported_the_stub_and_not_the_working_tree(report: Report) -> None:
    """Without this the file is vacuous: HEAD resolves every name, so everything would pass."""
    assert pathlib.Path(report.library).is_relative_to(report.stub)
    assert report.post_release_symbol_resolves is False


def test_the_census_covers_every_module_in_the_lane(report: Report) -> None:
    on_disk = {path.stem for path in E2E.glob("test_*.py")}

    assert on_disk, "no e2e modules found; this guard would pass having checked nothing"
    assert set(report.modules) == on_disk


def test_every_e2e_module_imports_cleanly_or_skips_on_the_published_wheel(report: Report) -> None:
    unusable = {
        name: outcome
        for name, outcome in report.modules.items()
        if outcome != "imported" and not outcome.startswith("skipped:")
    }

    assert not unusable, (
        "these modules break the canary's published-wheel lane at collection; move every "
        f"post-0.1.0 import inside a module-level skip guard: {unusable}"
    )


def test_the_conformance_module_never_skips_itself(report: Report) -> None:
    """The lane's floor. If this one skips, the wheel job can be green having tested nothing."""
    assert report.modules[FLOOR] == "imported"
