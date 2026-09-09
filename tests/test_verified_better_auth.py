"""`VERIFIED_BETTER_AUTH` is the CI matrix, or it is a claim nobody re-checks.

The constant exists so a deployment can log, from its own `lifespan`, which Better Auth
versions the Mode A build in front of it was actually driven against. That is only worth
logging while it is true, and "true" here means three files agree: the canary workflow's two
matrices, COMPATIBILITY.md's better-auth table, and the pin the harness installs. A constant
edited by hand would drift from all three on the first version bump and keep looking
authoritative, which is the failure this file exists to make loud.

Each parser is guarded against finding nothing - a locator that silently missed its table
would make every assertion below pass over an empty set, which is the failure mode that looks
exactly like success (the same guard `test_readme.py` puts on its fence extractor).
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from fastapi_better_auth import VERIFIED_BETTER_AUTH

ROOT = pathlib.Path(__file__).resolve().parents[1]
CANARY = ROOT / ".github" / "workflows" / "canary.yml"
COMPATIBILITY = ROOT / "COMPATIBILITY.md"
HARNESS_PACKAGE = ROOT / "harness" / "auth-server" / "package.json"

MATRIX_LINE = re.compile(r"^\s*version:\s*\[(?P<entries>[^]]*)\]\s*$", re.MULTILINE)
QUOTED = re.compile(r'"([^"]+)"')
VERSION = re.compile(r"\d+\.\d+\.\d+")
TAG = "latest"
"""A dist-tag, not a version: it names whatever npm published last, so it can never be pinned."""

BETTER_AUTH_TABLE_HEADING = "## Better Auth"
BETTER_AUTH_COLUMN = "better-auth"
CANARY_MATRICES = 2
"""Two lanes run the sweep - HEAD, and the wheel published on PyPI - and both list the same
versions. Finding some other number means the workflow moved and this file is now reading half
of it."""


def canary_matrices() -> tuple[tuple[str, ...], ...]:
    """Every `version: [...]` matrix in the canary workflow, in file order."""
    text = CANARY.read_text(encoding="utf-8")
    return tuple(
        tuple(QUOTED.findall(match.group("entries"))) for match in MATRIX_LINE.finditer(text)
    )


def better_auth_rows() -> tuple[tuple[str, ...], ...]:
    """The rows of COMPATIBILITY.md's better-auth table, each already split into cells.

    Located by its `## Better Auth` heading and closed by the first line that is not a table
    row, so the Python and dependency-floor tables further down the file are never read.
    """
    rows: list[tuple[str, ...]] = []
    inside = False
    for line in COMPATIBILITY.read_text(encoding="utf-8").splitlines():
        if line.startswith(BETTER_AUTH_TABLE_HEADING):
            inside = True
            continue
        if not inside:
            continue
        if not line.startswith("|"):
            if rows:
                break
            continue
        rows.append(tuple(cell.strip() for cell in line.strip("|").split("|")))
    return tuple(rows)


def documented_versions() -> frozenset[str]:
    """Every `1.x.y` literal in the first column of that table, header and rule excluded."""
    header, _rule, *body = better_auth_rows()
    assert header[0] == BETTER_AUTH_COLUMN, f"located the wrong table: {header!r}"
    return frozenset(version for row in body for version in VERSION.findall(row[0]))


def harness_pin() -> str:
    """The better-auth version the conformance harness installs."""
    manifest = json.loads(HARNESS_PACKAGE.read_text(encoding="utf-8"))
    dependencies: dict[str, str] = manifest["dependencies"]
    return dependencies[BETTER_AUTH_COLUMN]


def test_the_canary_matrices_are_found_and_agree() -> None:
    """The instrument first: two matrices, both non-empty, both the same list."""
    matrices = canary_matrices()

    assert len(matrices) == CANARY_MATRICES
    assert all(matrices), "a canary matrix parsed as empty"
    assert len(set(matrices)) == 1, f"the canary lanes sweep different versions: {matrices}"


def test_the_constant_is_the_canary_matrix_without_the_dist_tag() -> None:
    """The canary is what actually runs, so it is the source and this constant is the copy."""
    matrix = canary_matrices()[0]

    assert VERIFIED_BETTER_AUTH == tuple(entry for entry in matrix if entry != TAG)
    assert TAG not in VERIFIED_BETTER_AUTH


def test_every_version_the_compatibility_table_names_is_in_the_constant() -> None:
    """A row claiming a version the constant omits is a document promising more than CI runs."""
    documented = documented_versions()

    assert documented, "no version literal was found in the better-auth table"
    assert documented <= set(VERIFIED_BETTER_AUTH), documented - set(VERIFIED_BETTER_AUTH)


def test_the_harness_pin_is_one_of_the_verified_versions() -> None:
    """The gating lane installs exactly one of them; a pin outside the set is unverified."""
    assert harness_pin() in VERIFIED_BETTER_AUTH


def test_the_constant_is_a_tuple_of_plain_version_strings() -> None:
    """A tuple because a deployment logs it and must not be able to edit it; strings because
    they are compared against whatever the Node side reports about itself."""
    assert isinstance(VERIFIED_BETTER_AUTH, tuple)
    assert VERIFIED_BETTER_AUTH


@pytest.mark.parametrize("version", VERIFIED_BETTER_AUTH)
def test_every_entry_is_a_version_and_never_a_dist_tag(version: str) -> None:
    assert isinstance(version, str)
    assert VERSION.fullmatch(version), version
