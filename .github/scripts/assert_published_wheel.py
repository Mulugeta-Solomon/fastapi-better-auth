"""Assert the library under test is the wheel installed from the package index.

Exits non-zero unless the imported module lives in site-packages, outside the checkout,
and its distribution carries no PEP 610 direct_url.json (i.e. it came from an index).
"""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import os
import pathlib
import sys
from collections.abc import Sequence

DIST = "fastapi-better-auth-bridge"
MODULE = "fastapi_better_auth"
SITE_DIRS = frozenset({"site-packages", "dist-packages"})
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CHECKOUT_SRC = REPO_ROOT / "src"


def emit_output(name: str, value: str) -> None:
    """Publish a step output so a later step can name the artifact that was tested.

    One `name=value` line, or none: a newline in a version string read out of installed
    metadata would forge arbitrary step outputs.
    """
    for part, what in ((name, "name"), (value, "value")):
        if "\n" in part or "\r" in part:
            raise SystemExit(f"::error::refusing a step output whose {what} spans lines: {part!r}")
    destination = os.environ.get("GITHUB_OUTPUT")
    if not destination:
        return
    with open(destination, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")


def imported_module_file(module_name: str) -> pathlib.Path:
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise SystemExit(f"::error::cannot import {module_name}: {exc}") from exc
    origin = getattr(module, "__file__", None)
    if origin is None:
        raise SystemExit(f"::error::{module_name} has no __file__; its origin is unverifiable")
    return pathlib.Path(origin).resolve()


def check(dist_name: str, module_name: str) -> list[str]:
    problems: list[str] = []
    module_file = imported_module_file(module_name)
    print(f"{module_name}.__file__ -> {module_file}")

    if module_file.is_relative_to(CHECKOUT_SRC):
        problems.append(
            f"{module_name} resolves into the checkout at {module_file}; this lane would "
            f"re-test HEAD, not the published wheel"
        )
    if not SITE_DIRS & set(module_file.parts):
        problems.append(
            f"{module_name} at {module_file} is not inside a site-packages directory; "
            f"it was not installed, it was found on the path"
        )
    # pytest runs from this directory, and `python -m` puts it first on sys.path.
    shadow = pathlib.Path.cwd() / module_name
    if shadow.exists():
        problems.append(f"{shadow} would shadow the installed package when pytest runs here")

    try:
        dist = importlib.metadata.distribution(dist_name)
    except importlib.metadata.PackageNotFoundError:
        problems.append(f"no installed distribution named {dist_name}")
        return problems

    version = dist.version
    print(f"{dist_name} == {version}")
    emit_output("version", version)

    if dist.read_text("direct_url.json") is not None:
        problems.append(
            f"{dist_name} {version} carries direct_url.json; it was installed from a local "
            f"path, a VCS or a direct URL, not from the package index"
        )

    # A package's __file__ is its __init__.py; a single-file module IS the file.
    is_package = module_file.name == "__init__.py"
    entry = module_name if is_package else f"{module_name}.py"
    imported_at = module_file.parent if is_package else module_file
    recorded_at = pathlib.Path(str(dist.locate_file(entry))).resolve()
    if recorded_at != imported_at:
        problems.append(
            f"{dist_name} {version} records {entry} at {recorded_at} but {module_name} imported "
            f"from {imported_at}; two copies are on the path"
        )
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", default=DIST, help=f"distribution name (default: {DIST})")
    parser.add_argument("--module", default=MODULE, help=f"import package (default: {MODULE})")
    args = parser.parse_args(argv)

    problems = check(args.dist, args.module)
    for problem in problems:
        print(f"::error::{problem}", file=sys.stderr)
    if problems:
        print(f"FAILED: {len(problems)} instrument check(s)", file=sys.stderr)
        return 1
    print(f"OK: the conformance lane runs against the published {args.dist} wheel")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
