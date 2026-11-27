"""The opt-in 503 for an unreachable auth dependency: what `BetterAuth` accepts and refuses.

`unavailable_status` and `unavailable_retry_after` are keyword-only and checked when the bridge
is built, so a deployment that asked for something this library cannot answer never starts.
"""

from __future__ import annotations

import inspect
from http import HTTPStatus
from typing import Any

import pytest

from fastapi_better_auth import BetterAuth, ConfigurationError
from fastapi_better_auth._internal.unavailable import (
    DEFAULT_RETRY_AFTER,
    MAX_RETRY_AFTER,
    MIN_RETRY_AFTER,
)
from tests.fakes import FakeVerifier

HEADER = "x-cred"


class LyingInt(int):
    """An int that prints itself as something else: a refusal must not trust its repr."""

    def __repr__(self) -> str:
        return "https://secret.example/token=abc"

    __str__ = __repr__


def build(**settings: Any) -> BetterAuth:
    return BetterAuth(verifiers=[FakeVerifier(HEADER)], **settings)


def test_both_settings_are_keyword_only_with_the_401_default() -> None:
    parameters = inspect.signature(BetterAuth).parameters

    status = parameters["unavailable_status"]
    retry_after = parameters["unavailable_retry_after"]
    assert status.kind is inspect.Parameter.KEYWORD_ONLY
    assert retry_after.kind is inspect.Parameter.KEYWORD_ONLY
    assert status.default == 401
    assert retry_after.default is None


def test_the_retry_after_numbers_are_the_documented_ones() -> None:
    """The `BetterAuth` docstring states all three; a change here is a change there."""
    assert (MIN_RETRY_AFTER, DEFAULT_RETRY_AFTER, MAX_RETRY_AFTER) == (1, 10, 300)


def test_the_retry_after_bounds_are_whole_seconds_and_the_default_sits_inside() -> None:
    assert MIN_RETRY_AFTER == 1
    assert MIN_RETRY_AFTER <= DEFAULT_RETRY_AFTER <= MAX_RETRY_AFTER
    assert all(type(bound) is int for bound in (MIN_RETRY_AFTER, MAX_RETRY_AFTER))


@pytest.mark.parametrize(
    "settings",
    [
        {},
        {"unavailable_status": 401},
        {"unavailable_status": HTTPStatus.UNAUTHORIZED},
        {"unavailable_status": 503},
        {"unavailable_status": HTTPStatus.SERVICE_UNAVAILABLE},
        {"unavailable_status": 503, "unavailable_retry_after": MIN_RETRY_AFTER},
        {"unavailable_status": 503, "unavailable_retry_after": MAX_RETRY_AFTER},
        {"unavailable_status": 401, "unavailable_retry_after": None},
    ],
    ids=repr,
)
def test_every_sanctioned_combination_builds(settings: dict[str, Any]) -> None:
    build(**settings)


@pytest.mark.parametrize(
    "status",
    [400, 403, 500, 502, 504, 200, 0, -503, 503.0, "503", None, True, False, b"503"],
    ids=repr,
)
def test_any_other_status_is_refused(status: object) -> None:
    with pytest.raises(ConfigurationError, match="unavailable_status"):
        build(unavailable_status=status)


@pytest.mark.parametrize(
    "retry_after",
    [0, -1, MAX_RETRY_AFTER + 1, 10**9, 5.0, 5.5, "5", True, False, b"5"],
    ids=repr,
)
def test_any_other_retry_after_is_refused(retry_after: object) -> None:
    with pytest.raises(ConfigurationError, match="unavailable_retry_after"):
        build(unavailable_status=503, unavailable_retry_after=retry_after)


@pytest.mark.parametrize("retry_after", [MIN_RETRY_AFTER, DEFAULT_RETRY_AFTER, 0, True])
def test_a_retry_after_without_the_503_is_refused_not_ignored(retry_after: object) -> None:
    with pytest.raises(ConfigurationError, match="unavailable_retry_after") as caught:
        build(unavailable_retry_after=retry_after)

    assert "503" in str(caught.value)


def test_a_refusal_prints_the_number_through_int_never_through_the_value() -> None:
    with pytest.raises(ConfigurationError) as status_refusal:
        build(unavailable_status=LyingInt(500))
    with pytest.raises(ConfigurationError) as retry_refusal:
        build(unavailable_status=503, unavailable_retry_after=LyingInt(0))

    for refusal in (status_refusal.value, retry_refusal.value):
        text = str(refusal)
        assert "secret" not in text
        assert "token" not in text
        assert "://" not in text
    assert "500" in str(status_refusal.value)
    assert "got 0" in str(retry_refusal.value)


def test_a_non_int_refusal_names_only_its_type() -> None:
    with pytest.raises(ConfigurationError) as caught:
        build(unavailable_status="https://secret.example/token=abc")

    text = str(caught.value)
    assert "secret" not in text
    assert "str" in text


def test_an_int_subclass_status_is_kept_as_a_plain_int() -> None:
    """`HTTPStatus` is accepted because it is that number; what is kept is the number."""
    auth = build(unavailable_status=HTTPStatus.SERVICE_UNAVAILABLE, unavailable_retry_after=7)

    policy = auth._unavailable  # pyright: ignore[reportPrivateUsage]
    assert type(policy.retry_after) is int
    assert policy.retry_after == 7


def test_from_env_reads_no_variable_for_either_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing in the environment may change what a deployment answers."""
    monkeypatch.setenv("BETTER_AUTH_URL", "https://auth.example.com")
    for name in ("UNAVAILABLE_STATUS", "BETTER_AUTH_UNAVAILABLE_STATUS", "RETRY_AFTER"):
        monkeypatch.setenv(name, "503")

    auth = BetterAuth.from_env()

    assert auth._unavailable.retry_after is None  # pyright: ignore[reportPrivateUsage]
