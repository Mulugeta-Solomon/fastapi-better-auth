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

PYJWT_FLOOR = (2, 15, 0)
"""The first PyJWT release with no known hole in the parse path this library calls.

Below 2.12.0 a token declaring unknown `crit` extensions is accepted (CVE-2026-32597). 2.14.0
is a security release whose fixes include nested and malformed JWS input and compact-encoding
checks, both inside `jwt.decode`. 2.15.0 wraps the `RecursionError` a deeply nested token
raises in `DecodeError`, so the parser's own failure is a refusal like any other.
"""


def _declared_floor(pyproject: str, distribution: str) -> tuple[int, ...]:
    """The `>=` lower bound the dependency list declares for `distribution`, as a tuple."""
    pattern = rf'"{re.escape(distribution)}>=(?P<floor>[0-9][0-9.]*)[^"]*"'
    found = re.search(pattern, pyproject)
    assert found is not None, f"no >= floor is declared for {distribution}"
    return tuple(int(part) for part in found.group("floor").split("."))


def test_the_pyjwt_floor_excludes_the_releases_with_known_holes() -> None:
    """Every PyJWT below `PYJWT_FLOOR` has a known hole in the path this library calls. The
    lockfile binds only this repository's own runs; a consumer gets whatever this requirement
    allows, so the requirement is the fix.
    """
    declared = _declared_floor(PYPROJECT.read_text(encoding="utf-8"), "pyjwt[crypto]")

    assert declared >= PYJWT_FLOOR, (
        f"pyjwt[crypto] is declared >={'.'.join(map(str, declared))}, which permits a release"
        f" with a known hole (see PYJWT_FLOOR); the floor is {'.'.join(map(str, PYJWT_FLOOR))}"
    )


SQLALCHEMY_FLOOR = (2, 0, 24)
"""The first SQLAlchemy release that closes a cancelled asyncio connection gracefully.

`SqlAlchemySessionStore` cancels an abandoned lookup's database call once, so that SQLAlchemy can
close the connection in order - which is where asyncpg sends the server its cancel request. Before
2.0.24 `terminate()` aborts the socket at once, the cancel request never goes out, and Postgres
keeps the abandoned statement running, holding a backend and any lock it waits on (F20). Nothing
in this library can make an older release send it.
"""

SQLALCHEMY = "sqlalchemy[asyncio]"
SQLALCHEMY_DECLARATIONS = 2
"""The `[sqlalchemy]` extra a consumer installs, and the dev group every lane of ours runs."""


def _declared_floors(pyproject: str, distribution: str) -> list[tuple[int, ...]]:
    """Every `>=` lower bound declared for `distribution`, in the order they appear."""
    pattern = rf'"{re.escape(distribution)}>=(?P<floor>[0-9][0-9.]*)[^"]*"'
    return [
        tuple(int(part) for part in found.group("floor").split("."))
        for found in re.finditer(pattern, pyproject)
    ]


def test_the_sqlalchemy_floor_sends_the_cancel_request_an_abandoned_lookup_needs() -> None:
    """Both declarations: the extra is what a consumer resolves, and the dev group is what the
    declared-floors lane installs to prove the suite at that floor."""
    declared = _declared_floors(PYPROJECT.read_text(encoding="utf-8"), SQLALCHEMY)

    assert len(declared) == SQLALCHEMY_DECLARATIONS, f"{SQLALCHEMY} is declared {declared}"
    for floor in declared:
        assert floor >= SQLALCHEMY_FLOOR, (
            f"{SQLALCHEMY} is declared >={'.'.join(map(str, floor))}, which permits a release"
            " that cuts a cancelled connection without cancelling its statement on the server"
            f" (see SQLALCHEMY_FLOOR); the floor is {'.'.join(map(str, SQLALCHEMY_FLOOR))}"
        )


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('"pyjwt[crypto]>=2.15.0",', (2, 15, 0)),
        ('"pyjwt[crypto]>=2.10",', (2, 10)),
        ('"pyjwt[crypto]>=3",', (3,)),
        ('"pyjwt[crypto]>=2.15.0,<3",', (2, 15, 0)),
    ],
    ids=["patched", "vulnerable", "major-only", "with-a-ceiling"],
)
def test_the_floor_reader_is_a_live_instrument(line: str, expected: tuple[int, ...]) -> None:
    """A guard that reads nothing passes by vacuum; this is the reader firing on planted text."""
    assert _declared_floor(line, "pyjwt[crypto]") == expected


def test_the_floors_reader_sees_every_declaration() -> None:
    """A reader that stopped at the first match would let the second declaration drift alone."""
    text = f'"{SQLALCHEMY}>=2.0.24",\n    "{SQLALCHEMY}>=2.0",\n    "sqlalchemy>=1.4",'
    assert _declared_floors(text, SQLALCHEMY) == [(2, 0, 24), (2, 0)]


def test_a_dependency_with_no_declared_floor_fails_loudly() -> None:
    """The other direction: a requirement that lost its `>=` must not read as satisfied."""
    with pytest.raises(AssertionError):
        _declared_floor('"pyjwt[crypto]",', "pyjwt[crypto]")
