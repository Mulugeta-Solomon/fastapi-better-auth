"""Every link in the README and `docs/` goes somewhere that exists.

The README is also the PyPI project page, and PyPI resolves a relative link against its own host,
where nothing of this repository is served. So the README links only by absolute URL, and a URL into
this repository must name a file that is really here. Pages under `docs/` link to each other
relatively, the way GitHub renders them, and an anchor must name a heading on the page it points at.
A page renamed or a heading reworded then fails here instead of on a reader.
"""

from __future__ import annotations

import pathlib
import re
import unicodedata
from collections.abc import Iterator

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
DOC_PAGES = tuple(sorted((ROOT / "docs").glob("*.md")))
TOP_LEVEL = tuple(
    ROOT / name for name in ("CHANGELOG.md", "COMPATIBILITY.md", "CONTRIBUTING.md", "SECURITY.md")
)

REPOSITORY = "https://github.com/Mulugeta-Solomon/fastapi-better-auth/"
IN_REPOSITORY = re.compile(re.escape(REPOSITORY) + r"(?:blob|tree)/main/([^#?]+)(?:#(.+))?")
LINK = re.compile(r"\]\(([^)\s]+)\)")
FENCE = re.compile(r"^[ \t]*(```|~~~)")


def links(path: pathlib.Path) -> Iterator[tuple[int, str]]:
    """Every markdown link target on a page with its line, skipping fenced code."""
    fenced = False
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if FENCE.match(line):
            fenced = not fenced
            continue
        if fenced:
            continue
        for match in LINK.finditer(line):
            yield number, match.group(1)


def slug(heading: str) -> str:
    """GitHub's anchor for a heading: lower case, punctuation dropped, spaces to hyphens."""
    text = heading.strip().lower()
    kept = "".join(
        char for char in text if char in " -_" or unicodedata.category(char)[0] in {"L", "N"}
    )
    return kept.replace(" ", "-")


def anchors(path: pathlib.Path) -> set[str]:
    """The anchors GitHub generates for a page's headings, duplicates suffixed as it does."""
    found: set[str] = set()
    seen: dict[str, int] = {}
    fenced = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if FENCE.match(line):
            fenced = not fenced
            continue
        if fenced or not line.startswith("#"):
            continue
        base = slug(line.lstrip("#"))
        count = seen.get(base, 0)
        seen[base] = count + 1
        found.add(base if count == 0 else f"{base}-{count}")
    return found


def check_target(target: pathlib.Path, anchor: str | None, where: str) -> None:
    assert target.exists(), f"{where}: {target.name} does not exist"
    if anchor is not None:
        assert target.is_file(), f"{where}: an anchor on a directory"
        assert anchor in anchors(target), f"{where}: no heading for #{anchor}"


def test_the_checker_refuses_a_missing_page_and_a_missing_anchor(tmp_path: pathlib.Path) -> None:
    """Prove the instrument: a link that goes nowhere has to fail, not pass quietly."""
    page = tmp_path / "page.md"
    page.write_text("# Title\n\n## A heading\n\n```text\n# not a heading\n```\n", encoding="utf-8")

    check_target(page, "a-heading", "ok")
    with pytest.raises(AssertionError, match="does not exist"):
        check_target(tmp_path / "missing.md", None, "missing page")
    with pytest.raises(AssertionError, match="no heading"):
        check_target(page, "not-a-heading", "heading inside a fence")


def test_the_slug_matches_githubs_for_the_shapes_these_pages_use() -> None:
    assert slug("Moving the verifier's clock") == "moving-the-verifiers-clock"
    assert slug("`additionalFields`: make sure they reach the wire") == (
        "additionalfields-make-sure-they-reach-the-wire"
    )
    assert slug("Organizations and roles — the recipe") == "organizations-and-roles--the-recipe"


def test_the_readme_links_only_by_absolute_url() -> None:
    relative = [
        f"README.md:{number}: {target}"
        for number, target in links(README)
        if not target.startswith("https://")
    ]
    assert relative == []


def test_the_readme_links_into_this_repository_resolve() -> None:
    checked = 0
    for number, target in links(README):
        match = IN_REPOSITORY.fullmatch(target)
        if match is None:
            continue
        check_target(ROOT / match.group(1), match.group(2), f"README.md:{number}")
        checked += 1
    assert checked >= 10


@pytest.mark.parametrize("page", DOC_PAGES + TOP_LEVEL, ids=lambda page: page.name)
def test_relative_links_resolve(page: pathlib.Path) -> None:
    if not page.exists():
        pytest.fail(f"{page.name} is missing")
    for number, target in links(page):
        if target.startswith(("https://", "http://", "mailto:")):
            continue
        where = f"{page.relative_to(ROOT).as_posix()}:{number}"
        path, _, anchor = target.partition("#")
        destination = page if path == "" else (page.parent / path).resolve()
        check_target(destination, anchor or None, where)
