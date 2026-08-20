"""Placeholder-release sanity: the package imports and the typing marker exists.

Note: under uv's editable install this resolves against src/, not the built wheel —
the wheel-side py.typed guarantee is enforced by the CI wheel-content check instead.
"""

from importlib import resources

import fastapi_better_auth


def test_version() -> None:
    assert fastapi_better_auth.__version__ == "0.0.1"


def test_py_typed_marker_ships() -> None:
    assert resources.files("fastapi_better_auth").joinpath("py.typed").is_file()
