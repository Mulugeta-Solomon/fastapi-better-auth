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
ELSEWHERE = (ROOT / "harness" / "README.md",)
"""Pages outside `docs/` that link into it, so a moved heading cannot leave them pointing nowhere."""

REPOSITORY = "https://github.com/Mulugeta-Solomon/fastapi-better-auth/"
IN_REPOSITORY = re.compile(re.escape(REPOSITORY) + r"(?:blob|tree)/main/([^#?]+)(?:#(.+))?")
INLINE_LINK = re.compile(r"\]\(([^)\s]+)\)")
DEFINITION = re.compile(r"^ {0,3}\[[^\]]+\]:[ \t]*<?([^\s>]+)>?")
"""A reference definition, `[label]: target`: where a `[text][label]` link really points."""
FENCE = re.compile(r"^[ \t]*(`{3,}|~{3,})(.*)$")


def prose(path: pathlib.Path) -> Iterator[tuple[int, str]]:
    """Every line of a page that is not fenced code, with its line number.

    A fence is closed only by a marker of the same character, at least as long as the one that
    opened it, with nothing after it but whitespace (CommonMark 4.5). A `~~~` line inside a
    backtick block is therefore code, and so is a shorter run of backticks.
    """
    opening = ""
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        marker = FENCE.match(line)
        if opening:
            if marker is not None and _closes(opening, marker.group(1), marker.group(2)):
                opening = ""
            continue
        if marker is not None:
            opening = marker.group(1)
            continue
        yield number, line


def _closes(opening: str, candidate: str, rest: str) -> bool:
    return candidate[0] == opening[0] and len(candidate) >= len(opening) and not rest.strip()


def links(path: pathlib.Path) -> Iterator[tuple[int, str]]:
    """Every link target on a page with its line: inline links and reference definitions."""
    for number, line in prose(path):
        definition = DEFINITION.match(line)
        if definition is not None:
            yield number, definition.group(1)
        for match in INLINE_LINK.finditer(line):
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
    for _, line in prose(path):
        if not line.startswith("#"):
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


def relative_targets(page: pathlib.Path) -> list[str]:
    return [target for _, target in links(page) if not target.startswith("https://")]


def check_relative_links(page: pathlib.Path, where: str) -> None:
    for number, target in links(page):
        if target.startswith(("https://", "http://", "mailto:")):
            continue
        path, _, anchor = target.partition("#")
        destination = page if path == "" else (page.parent / path).resolve()
        check_target(destination, anchor or None, f"{where}:{number}")


# ------------------------------------------------------------------ the instrument, proven


def test_the_checker_refuses_a_missing_page_and_a_missing_anchor(tmp_path: pathlib.Path) -> None:
    """Prove the instrument: a link that goes nowhere has to fail, not pass quietly."""
    page = tmp_path / "page.md"
    page.write_text("# Title\n\n## A heading\n\n```text\n# not a heading\n```\n", encoding="utf-8")

    check_target(page, "a-heading", "ok")
    with pytest.raises(AssertionError, match="does not exist"):
        check_target(tmp_path / "missing.md", None, "missing page")
    with pytest.raises(AssertionError, match="no heading"):
        check_target(page, "not-a-heading", "heading inside a fence")


def test_a_reference_style_link_is_a_link(tmp_path: pathlib.Path) -> None:
    """`[text][label]` points wherever `[label]: target` says, so the definition is checked."""
    page = tmp_path / "page.md"
    page.write_text(
        "See the [Guide][guide] and [the site][site].\n\n"
        "[guide]: missing.md\n"
        "[site]: <https://example.com/>\n",
        encoding="utf-8",
    )

    assert list(links(page)) == [(3, "missing.md"), (4, "https://example.com/")]
    assert relative_targets(page) == ["missing.md"]
    with pytest.raises(AssertionError, match=r"page\.md:3: missing\.md does not exist"):
        check_relative_links(page, "page.md")


def test_a_fence_closes_only_on_its_own_marker(tmp_path: pathlib.Path) -> None:
    """A `~~~` line inside a backtick block is code, so the block ends at its real closing fence
    and the link after it is seen."""
    page = tmp_path / "page.md"
    page.write_text(
        "```text\n~~~\n# not a heading\n```\n[broken](missing.md)\n\n## After the block\n",
        encoding="utf-8",
    )

    assert list(links(page)) == [(5, "missing.md")]
    assert anchors(page) == {"after-the-block"}


def test_a_shorter_or_annotated_marker_does_not_close_a_fence(tmp_path: pathlib.Path) -> None:
    page = tmp_path / "page.md"
    page.write_text(
        "````text\n```\n[inside](missing.md)\n```` not a close\n# still code\n````\n"
        "[outside](also-missing.md)\n",
        encoding="utf-8",
    )

    assert list(links(page)) == [(7, "also-missing.md")]
    assert anchors(page) == set()


def test_the_slug_matches_githubs_for_the_shapes_these_pages_use() -> None:
    assert slug("Moving the verifier's clock") == "moving-the-verifiers-clock"
    assert slug("`additionalFields`: make sure they reach the wire") == (
        "additionalfields-make-sure-they-reach-the-wire"
    )
    assert slug("Organizations and roles — the recipe") == "organizations-and-roles--the-recipe"


# ------------------------------------------------------------------ the pages


def test_the_readme_links_only_by_absolute_url() -> None:
    assert relative_targets(README) == []


def test_the_readme_links_into_this_repository_resolve() -> None:
    checked = 0
    for number, target in links(README):
        match = IN_REPOSITORY.fullmatch(target)
        if match is None:
            continue
        check_target(ROOT / match.group(1), match.group(2), f"README.md:{number}")
        checked += 1
    assert checked >= 10


@pytest.mark.parametrize(
    "page",
    DOC_PAGES + TOP_LEVEL + ELSEWHERE,
    ids=lambda page: page.relative_to(ROOT).as_posix(),
)
def test_relative_links_resolve(page: pathlib.Path) -> None:
    if not page.exists():
        pytest.fail(f"{page.name} is missing")
    check_relative_links(page, page.relative_to(ROOT).as_posix())
