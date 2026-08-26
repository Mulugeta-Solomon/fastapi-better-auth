"""The import surface is the contract: `__all__` is exactly what leaks from the root."""

from __future__ import annotations

import pytest

import fastapi_better_auth
from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuthError,
    ConfigurationError,
    CsrfFailure,
    InvalidCredential,
    Session,
    SessionError,
    SessionExpired,
    SessionRevoked,
    User,
)

EXPECTED = (
    "AuthServiceUnavailable",
    "BetterAuthError",
    "ConfigurationError",
    "CsrfFailure",
    "InvalidCredential",
    "Session",
    "SessionError",
    "SessionExpired",
    "SessionRevoked",
    "User",
)
IMPORTED = (
    AuthServiceUnavailable,
    BetterAuthError,
    ConfigurationError,
    CsrfFailure,
    InvalidCredential,
    Session,
    SessionError,
    SessionExpired,
    SessionRevoked,
    User,
)


def test_all_lists_exactly_the_expected_names() -> None:
    assert tuple(fastapi_better_auth.__all__) == EXPECTED
    assert sorted(EXPECTED) == list(EXPECTED)


def test_nothing_public_leaks_beyond_all() -> None:
    """Internals live under `_internal/`; a new public attribute must be a deliberate export."""
    public = {name for name in dir(fastapi_better_auth) if not name.startswith("_")}

    assert public == set(fastapi_better_auth.__all__)


def test_every_exported_name_resolves_from_the_root() -> None:
    assert [getattr(fastapi_better_auth, name) for name in EXPECTED] == list(IMPORTED)


@pytest.mark.parametrize("name", EXPECTED)
def test_every_export_documents_itself(name: str) -> None:
    """Public docstrings are the product; internal narration is not."""
    exported: type[object] = getattr(fastapi_better_auth, name)

    assert exported.__doc__
    assert exported.__doc__.strip()


def test_the_version_marker_survives() -> None:
    assert fastapi_better_auth.__version__ == "0.0.1"
