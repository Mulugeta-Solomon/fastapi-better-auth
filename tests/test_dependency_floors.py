"""Declared dependency floors that exist for a security reason, pinned so nobody lowers one.

A floor in `pyproject.toml` is the only thing standing between a fresh install and a version
of a dependency with a known hole in it: the lockfile binds this repository's own runs, and a
consumer resolving `fastapi-better-auth-bridge` gets whatever the *requirement* permits. So the
requirement is what is asserted here, read out of the published metadata as text.

Python 3.10 ships no `tomllib`, and this suite runs on 3.10 - hence a regex over the dependency
line rather than a parse. `test_the_floor_reader_is_a_live_instrument` proves the reader in both
directions, because a matcher that quietly matched nothing would pass this file by vacuum.
"""

from __future__ import annotations

import pathlib
import re

import pytest

PYPROJECT = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"

PYJWT_FLOOR = (2, 12, 0)
"""CVE-2026-32597: PyJWT below 2.12.0 accepts a token declaring unknown `crit` extensions."""


def _declared_floor(pyproject: str, distribution: str) -> tuple[int, ...]:
    """The `>=` lower bound the dependency list declares for `distribution`, as a tuple."""
    pattern = rf'"{re.escape(distribution)}>=(?P<floor>[0-9][0-9.]*)[^"]*"'
    found = re.search(pattern, pyproject)
    assert found is not None, f"no >= floor is declared for {distribution}"
    return tuple(int(part) for part in found.group("floor").split("."))


def test_the_pyjwt_floor_excludes_cve_2026_32597() -> None:
    """PyJWT below 2.12.0 accepts a token whose header declares `crit` extensions it does not
    understand (CVE-2026-32597). The lockfile pins 2.13.0 for this repository; a consumer gets
    whatever this requirement allows, so the requirement is the fix.
    """
    declared = _declared_floor(PYPROJECT.read_text(encoding="utf-8"), "pyjwt[crypto]")

    assert declared >= PYJWT_FLOOR, (
        f"pyjwt[crypto] is declared >={'.'.join(map(str, declared))}, which permits"
        f" CVE-2026-32597; the floor is {'.'.join(map(str, PYJWT_FLOOR))}"
    )


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('"pyjwt[crypto]>=2.12.0",', (2, 12, 0)),
        ('"pyjwt[crypto]>=2.10",', (2, 10)),
        ('"pyjwt[crypto]>=3",', (3,)),
        ('"pyjwt[crypto]>=2.12.0,<3",', (2, 12, 0)),
    ],
    ids=["patched", "vulnerable", "major-only", "with-a-ceiling"],
)
def test_the_floor_reader_is_a_live_instrument(line: str, expected: tuple[int, ...]) -> None:
    """A guard that reads nothing passes by vacuum; this is the reader firing on planted text."""
    assert _declared_floor(line, "pyjwt[crypto]") == expected


def test_a_dependency_with_no_declared_floor_fails_loudly() -> None:
    """The other direction: a requirement that lost its `>=` must not read as satisfied."""
    with pytest.raises(AssertionError):
        _declared_floor('"pyjwt[crypto]",', "pyjwt[crypto]")
