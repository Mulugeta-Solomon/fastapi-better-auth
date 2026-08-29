"""Packaging sanity: the version is one value everywhere, and the typing marker exists.

Note: under uv's editable install this resolves against src/, not the built wheel —
the wheel-side py.typed guarantee is enforced by the CI wheel-content check instead.
"""

from importlib import metadata, resources

import fastapi_better_auth


def test_version_matches_the_installed_distribution() -> None:
    assert fastapi_better_auth.__version__ == metadata.version("fastapi-better-auth-bridge")


def test_py_typed_marker_ships() -> None:
    assert resources.files("fastapi_better_auth").joinpath("py.typed").is_file()
