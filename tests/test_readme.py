"""The README is executable, or it is a lie nobody notices.

Documentation drifts silently: a factory grows a keyword, a name moves, a route stops being
refused — and the snippet that taught every reader how to use the library keeps rendering
perfectly on PyPI while describing an API that no longer exists. This file removes the silence.
Every python fence in the shipped documents is extracted, executed in a fresh namespace, and the
applications those snippets build are driven over the wire: the protected route has to answer 401
to a forged credential, and the document has to publish the bearer scheme `/docs` needs before it
can show an Authorize button. Executing a snippet proves it parses; asking it for a refusal proves
it is the real API doing real enforcement. "Every" is enforced by a census wider than the
extractor's own gate, so a fence spelled some other way fails loudly instead of vanishing.

Nothing here touches the network, and that is asserted rather than assumed: every snippet
refuses its credential on shape alone, before a key set is ever wanted, and `refuse_network`
records any fetch the shipped transport attempts anyway.
"""

from __future__ import annotations

import pathlib
import re
from collections.abc import Mapping
from typing import Any, NamedTuple

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCUMENTS = (ROOT / "README.md", ROOT / "COMPATIBILITY.md")

FENCE = "```"
PYTHON_FENCE = "```python"

BEARER_NAME = "BetterAuthBearer"
BEARER_DEFINITION = {"type": "http", "scheme": "bearer"}
BEARER_REQUIREMENT: list[dict[str, list[str]]] = [{BEARER_NAME: []}]

UNAUTHENTICATED = {"detail": "Not authenticated"}
FORGED = ("not-a-jwt", "a.b.c")
"""Two credentials refused on shape alone — before a `kid`, and so before any key set."""

BASE_URL = "https://auth.example.com"
BROKEN_SNIPPET = "```python\nfrom fastapi_better_auth import BetterAuht\n```\n"

UNOPENED_SPELLINGS = ("```py", "~~~python", "```python3", "   ```python")
"""Fence openers a reader calls python and `snippets` does not open. None may be silent."""

FENCE_OPENER = re.compile(r"^[ \t]*(?:`{3,}|~{3,})[ \t]*py", re.IGNORECASE | re.MULTILINE)
"""Deliberately looser than the extractor's gate: a backtick *or* tilde run, indented or not,
whose info string starts with `py`. A closing fence carries no info string and never matches."""


def python_fence_openers(text: str) -> int:
    """Count every fence a reader would call a python block, however it is spelled."""
    return len(FENCE_OPENER.findall(text))


class Snippet(NamedTuple):
    """One fenced python block, and where a failure should send the reader."""

    document: str
    line: int
    code: str

    @property
    def id(self) -> str:
        return f"{self.document}:L{self.line}"


def snippets(path: pathlib.Path) -> tuple[Snippet, ...]:
    """Every ```python fence in one document, in the order it is read on the page."""
    found: list[Snippet] = []
    opened: int | None = None
    body: list[str] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.rstrip()
        if opened is None:
            if stripped == PYTHON_FENCE:
                opened, body = number, []
            continue
        if stripped == FENCE:
            found.append(Snippet(document=path.name, line=opened, code="\n".join(body) + "\n"))
            opened = None
            continue
        body.append(line)
    assert opened is None, f"{path.name}: a python fence opened at line {opened} is never closed"
    return tuple(found)


ALL_SNIPPETS = tuple(snippet for path in DOCUMENTS for snippet in snippets(path))


def run(snippet: Snippet) -> dict[str, Any]:
    """Execute one snippet in a namespace of its own, and hand back what it defined."""
    namespace: dict[str, Any] = {"__name__": f"readme_snippet_{snippet.line}"}
    # The source is this repository's own documentation, and running it IS the test.
    exec(compile(snippet.code, f"<{snippet.id}>", "exec"), namespace)  # noqa: S102
    return namespace


def apps_in(namespace: Mapping[str, Any]) -> tuple[FastAPI, ...]:
    return tuple(value for value in namespace.values() if isinstance(value, FastAPI))


def secured_paths(document: Mapping[str, Any]) -> tuple[str, ...]:
    """The GET operations the published document says need a credential."""
    paths: Mapping[str, Any] = document.get("paths", {})
    found: list[str] = []
    for path, operations in paths.items():
        operation: Mapping[str, Any] = operations.get("get", {})
        if "security" in operation:
            found.append(path)
    return tuple(found)


@pytest.fixture
def snippet_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """What a reader's shell already has. `from_env()` reads exactly this one name."""
    monkeypatch.setenv("BETTER_AUTH_URL", BASE_URL)


@pytest.fixture
def refuse_network(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record — and refuse — any fetch the shipped transport attempts.

    A snippet that reached upstream would make this file a networked test pretending to be a
    unit one: green on a laptop, hanging in CI. Patching the client the snippets actually build
    catches that at the one boundary it can happen through, and leaves sockets alone, which the
    event loop underneath `TestClient` needs for itself.
    """
    attempted: list[str] = []

    def refused(_self: object, _method: str, url: str, **_kwargs: object) -> object:
        attempted.append(url)
        raise AssertionError(f"a snippet fetched {url}; snippets must not need the network")

    monkeypatch.setattr(httpx.AsyncClient, "stream", refused)
    return attempted


def test_every_python_fence_in_the_documents_is_extracted() -> None:
    """The census of what a reader calls a python block, against what the extractor opened.

    An extractor that quietly found nothing would make every other test in this file pass on an
    empty parameter list, which is the failure mode that looks exactly like success.
    """
    for path in DOCUMENTS:
        text = path.read_text(encoding="utf-8")
        assert len(snippets(path)) == python_fence_openers(text), path.name
    assert len(ALL_SNIPPETS) >= 3


@pytest.mark.parametrize("opener", UNOPENED_SPELLINGS)
def test_a_python_fence_the_extractor_will_not_open_is_never_silent(
    opener: str, tmp_path: pathlib.Path
) -> None:
    """The census has to be wider than the gate, or a variant spelling escapes both.

    `snippets` opens one spelling on purpose — a exact ```` ```python ```` line — because an
    extractor that guesses would start executing prose. The hazard is a fence a *reader* calls
    python that the extractor never opens: it would be missed by the extraction and by the guard
    above at once, with no signal anywhere. Counting openers more loosely than they are opened is
    what turns that silence into a failure.
    """
    document = tmp_path / "VARIANT.md"
    document.write_text(f"{opener}\nimport fastapi_better_auth\n```\n", encoding="utf-8")

    assert python_fence_openers(document.read_text(encoding="utf-8")) == 1
    assert snippets(document) == ()


def test_the_extractor_catches_a_snippet_that_stopped_working(tmp_path: pathlib.Path) -> None:
    """Prove the instrument: a document that lies has to fail here, not slip through."""
    broken = tmp_path / "BROKEN.md"
    broken.write_text(BROKEN_SNIPPET, encoding="utf-8")

    extracted = snippets(broken)

    assert len(extracted) == 1
    with pytest.raises(ImportError):
        run(extracted[0])


@pytest.mark.parametrize("snippet", ALL_SNIPPETS, ids=[snippet.id for snippet in ALL_SNIPPETS])
@pytest.mark.usefixtures("snippet_environment")
def test_every_snippet_runs(snippet: Snippet, refuse_network: list[str]) -> None:
    """Construction and route registration are the whole of what a snippet may do."""
    run(snippet)

    assert refuse_network == []


@pytest.mark.usefixtures("snippet_environment")
def test_the_applications_the_snippets_build_enforce_and_document_themselves(
    refuse_network: list[str],
) -> None:
    """The snippets are the real API, refusing real requests — not code that merely imports.

    A forged credential is the assertion that covers every route the documents show: it is a
    terminal 401 for `optional_session` exactly as it is for `current_session`, so the whole
    documented surface can be held to one wire shape. Anonymity is the half that differs, so it
    is asserted where it is decidable — some route among the snippets must refuse it.
    """
    published: list[Mapping[str, Any]] = []
    anonymous: list[int] = []

    for snippet in ALL_SNIPPETS:
        for app in apps_in(run(snippet)):
            with TestClient(app) as client:
                document: dict[str, Any] = client.get("/openapi.json").json()
                schemes: Mapping[str, Any] = document.get("components", {}).get(
                    "securitySchemes", {}
                )
                if BEARER_NAME in schemes:
                    published.append(schemes[BEARER_NAME])
                for path in secured_paths(document):
                    where = f"{snippet.id} {path}"
                    assert document["paths"][path]["get"]["security"] == BEARER_REQUIREMENT, where
                    for credential in FORGED:
                        forged = client.get(path, headers={"Authorization": f"Bearer {credential}"})
                        assert forged.status_code == 401, where
                        assert forged.json() == UNAUTHENTICATED, where
                        assert forged.headers["www-authenticate"] == "Bearer", where
                    anonymous.append(client.get(path).status_code)

    assert published, "no snippet builds an application that documents the bearer scheme"
    assert all(
        {key: definition[key] for key in BEARER_DEFINITION} == BEARER_DEFINITION
        and definition["description"]
        for definition in published
    )
    assert 401 in anonymous, "no documented route refuses an anonymous request"
    assert set(anonymous) <= {200, 401}
    assert refuse_network == []
