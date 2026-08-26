"""`BetterAuth.from_env()`: one variable, named out loud, and nothing read behind your back.

The whole risk in a `from_env` is silence — a variable that is read but undocumented, or a
missing one that produces a working-looking object which refuses every request at runtime.
Both are answered the same way: exactly one variable, the one the Node side already sets, and
a `ConfigurationError` at startup when it is not there.
"""

from __future__ import annotations

import pytest

from fastapi_better_auth import BetterAuth, ConfigurationError, HttpxTransport
from fastapi_better_auth._internal.jwt_verifier import JwtVerifier

VARIABLE = "BETTER_AUTH_URL"


@pytest.fixture(autouse=True)
def no_inherited_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """The developer running this suite may well have the variable set for the harness."""
    monkeypatch.delenv(VARIABLE, raising=False)


def test_it_builds_a_bridge_around_a_jwt_verifier(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(VARIABLE, "https://auth.example.com")

    auth = BetterAuth.from_env()

    assert isinstance(auth, BetterAuth)
    assert len(auth.verifiers) == 1
    verifier = auth.verifiers[0]
    assert isinstance(verifier, JwtVerifier)
    assert verifier.origin == "https://auth.example.com"
    assert verifier.jwks_uri == "https://auth.example.com/api/auth/jwks"


def test_the_value_is_canonicalized_the_same_way_the_constructor_does(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(VARIABLE, "HTTPS://Auth.Example.COM:443/  ")

    verifier = BetterAuth.from_env().verifiers[0]

    assert isinstance(verifier, JwtVerifier)
    assert verifier.origin == "https://auth.example.com"


def test_the_default_transport_is_the_shipped_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(VARIABLE, "https://auth.example.com")

    verifier = BetterAuth.from_env().verifiers[0]

    assert isinstance(verifier, JwtVerifier)
    assert isinstance(verifier.transport, HttpxTransport)


def test_a_missing_variable_is_a_startup_failure_that_names_it() -> None:
    with pytest.raises(ConfigurationError) as caught:
        BetterAuth.from_env()

    assert VARIABLE in str(caught.value)


@pytest.mark.parametrize("value", ["", "   ", "\t"], ids=["empty", "spaces", "tab"])
def test_a_blank_variable_is_the_same_as_a_missing_one(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """An empty variable is what a shell hands you for one that was never exported."""
    monkeypatch.setenv(VARIABLE, value)

    with pytest.raises(ConfigurationError) as caught:
        BetterAuth.from_env()

    assert VARIABLE in str(caught.value)


@pytest.mark.parametrize(
    "value",
    ["auth.example.com", "http://auth.example.com", "https://auth.example.com/api/auth", "ftp://x"],
    ids=["no-scheme", "cleartext", "a-path", "wrong-scheme"],
)
def test_a_value_that_is_not_an_origin_is_refused_at_startup(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv(VARIABLE, value)

    with pytest.raises(ConfigurationError):
        BetterAuth.from_env()


def test_nothing_else_in_the_environment_is_consulted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tuning stays on the constructor, where it is visible in the code that chose it. A
    variable that silently widened `leeway` would be an environment that can extend session
    lifetimes without a deploy."""
    monkeypatch.setenv(VARIABLE, "https://auth.example.com")
    for name, value in (
        ("BETTER_AUTH_LEEWAY", "3600"),
        ("BETTER_AUTH_ALGORITHMS", "HS256"),
        ("BETTER_AUTH_MAX_TOKEN_LIFETIME", "86400"),
        ("BETTER_AUTH_JWKS_URL", "https://evil.example/jwks"),
        ("BETTER_AUTH_SECRET", "not-ours-to-read"),
    ):
        monkeypatch.setenv(name, value)

    verifier = BetterAuth.from_env().verifiers[0]

    assert isinstance(verifier, JwtVerifier)
    assert verifier.leeway == 0.0
    assert verifier.algorithms == ("EdDSA",)
    assert verifier.jwks_uri == "https://auth.example.com/api/auth/jwks"


def test_the_docstring_names_every_variable_it_reads() -> None:
    """A `from_env` whose variables are not in its own documentation is a scavenger hunt."""
    doc = BetterAuth.from_env.__doc__ or ""

    assert VARIABLE in doc
    assert "Raises:" in doc
