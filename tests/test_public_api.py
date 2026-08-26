"""The import surface is the contract: `__all__` is exactly what leaks from the root."""

from __future__ import annotations

import importlib.metadata
import inspect

import pytest

import fastapi_better_auth

EXPECTED = (
    "BEARER_CHALLENGE",
    "AmbiguousCredentials",
    "AuthServiceUnavailable",
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
    "Transport",
    "TransportResponse",
    "UntrustedResponse",
    "User",
    "UserT",
    "Verifier",
    "normalize_base_url",
    "parse_user",
)
NON_CLASS_EXPORTS = frozenset({"BEARER_CHALLENGE", "UserT", "normalize_base_url", "parse_user"})
SANCTIONED_TOOLS = ("normalize_base_url", "parse_user")
RESPONSE_CLASSVARS = ("response_status", "response_detail", "response_headers")


def exported_classes() -> tuple[str, ...]:
    return tuple(name for name in fastapi_better_auth.__all__ if name not in NON_CLASS_EXPORTS)


def test_all_lists_exactly_the_expected_names() -> None:
    assert tuple(fastapi_better_auth.__all__) == EXPECTED


def test_all_is_free_of_duplicates_and_matches_the_module() -> None:
    """Ordering is ruff's job (RUF022); membership and uniqueness are this test's."""
    published = list(fastapi_better_auth.__all__)

    assert len(published) == len(set(published))
    assert set(published) == {name for name in dir(fastapi_better_auth) if not name.startswith("_")}


def test_nothing_public_leaks_beyond_all() -> None:
    """Internals live under `_internal/`; a new public attribute must be a deliberate export."""
    public = {name for name in dir(fastapi_better_auth) if not name.startswith("_")}

    assert public == set(fastapi_better_auth.__all__)


@pytest.mark.parametrize("name", EXPECTED)
def test_every_published_name_resolves(name: str) -> None:
    assert getattr(fastapi_better_auth, name, None) is not None


def test_the_non_class_exports_are_exactly_the_documented_ones() -> None:
    """A new non-class export needs a deliberate edit here, and a home in the docs."""
    published = {
        name
        for name in fastapi_better_auth.__all__
        if not inspect.isclass(getattr(fastapi_better_auth, name))
    }

    assert published == NON_CLASS_EXPORTS


@pytest.mark.parametrize("name", exported_classes())
def test_every_exported_class_is_ours(name: str) -> None:
    """Nothing may become our API by accident of a re-export from a dependency."""
    exported: type[object] = getattr(fastapi_better_auth, name)

    assert exported.__module__.startswith("fastapi_better_auth")


@pytest.mark.parametrize("name", exported_classes())
def test_every_exported_class_carries_a_real_docstring(name: str) -> None:
    """Public docstrings are the product; a one-clause stub is not documentation."""
    exported: type[object] = getattr(fastapi_better_auth, name)
    doc = exported.__doc__

    assert doc, f"{name} has no docstring"
    lines = doc.strip().splitlines()
    summary = lines[0].strip()
    assert summary, f"{name} opens with a blank summary line"
    assert len(lines) > 1 or len(summary) >= 60, f"{name} documents itself in one short clause"


def test_the_session_error_docstring_documents_the_extension_mechanism() -> None:
    """B8: an operator cannot write a compliant subclass without knowing these three."""
    doc = fastapi_better_auth.SessionError.__doc__ or ""

    for classvar in RESPONSE_CLASSVARS:
        assert classvar in doc, f"SessionError does not document {classvar}"


@pytest.mark.parametrize("name", SANCTIONED_TOOLS)
def test_the_sanctioned_tools_are_importable_from_the_root(name: str) -> None:
    """A verifier written outside this package is told to contain its own validation
    errors and to canonicalize its own base_url. If the sanctioned way to do either is not
    importable, the safe path is harder than the unsafe one and everyone reimplements it."""
    tool = getattr(fastapi_better_auth, name)

    assert callable(tool)
    assert tool.__module__.startswith("fastapi_better_auth")


@pytest.mark.parametrize("name", SANCTIONED_TOOLS)
def test_every_exported_function_carries_a_real_docstring(name: str) -> None:
    doc = (getattr(fastapi_better_auth, name).__doc__ or "").strip()
    lines = doc.splitlines()

    assert doc, f"{name} has no docstring"
    assert lines[0].strip(), f"{name} opens with a blank summary line"
    assert len(lines) > 1, f"{name} documents itself in one clause"
    assert "Raises:" in doc, f"{name} does not document what it raises"


def test_the_version_marker_matches_the_installed_distribution() -> None:
    """Literal-vs-literal could not catch a release-time drift; this can."""
    assert fastapi_better_auth.__version__ == importlib.metadata.version(
        "fastapi-better-auth-bridge"
    )
