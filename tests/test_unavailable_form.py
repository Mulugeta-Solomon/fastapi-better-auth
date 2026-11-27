"""The 503 form of `AuthServiceUnavailable`: one object that tells the same truth everywhere.

A handler, a log line and a house envelope all read it, so status, body and headers agree on
the instance, and `repr` and pickling keep what it is. The 401 form is untouched, and the guard
on subclasses still refuses a class that tries to answer 503 by a constant.
"""

from __future__ import annotations

import copy
import gc
import pickle
from collections.abc import Mapping
from typing import ClassVar

import pytest

from fastapi_better_auth import BEARER_CHALLENGE, AuthServiceUnavailable, SessionError
from fastapi_better_auth._internal.unavailable import (
    UNAVAILABLE_DETAIL,
    AuthServiceUnavailable503,
)

REASON = "session store lookup did not answer within 5.0s [fp=9f3ab21c]"
RETRY_AFTER = 7


@pytest.fixture(autouse=True)
def collect_dead_subclasses() -> None:
    """Rogue subclasses briefly enter `__subclasses__()` before their creation raises."""
    gc.collect()


def answer() -> AuthServiceUnavailable503:
    return AuthServiceUnavailable503(reason=REASON, retry_after=RETRY_AFTER)


def test_it_is_still_an_auth_service_unavailable_with_the_same_reason() -> None:
    error = answer()

    assert isinstance(error, AuthServiceUnavailable)
    assert isinstance(error, SessionError)
    assert error.reason == REASON


def test_every_attribute_a_reader_can_take_says_503() -> None:
    error = answer()
    expected = {"Retry-After": str(RETRY_AFTER)}

    assert (error.status_code, error.detail, error.headers) == (503, UNAVAILABLE_DETAIL, expected)
    assert error.response_status == 503
    assert error.response_detail == UNAVAILABLE_DETAIL
    assert error.response_headers == expected
    assert error.retry_after == RETRY_AFTER


def test_the_detail_is_generic() -> None:
    assert UNAVAILABLE_DETAIL == "Service unavailable"


def test_it_carries_no_authentication_challenge() -> None:
    error = answer()

    for headers in (error.headers, error.response_headers):
        assert headers is not None
        assert {name.lower() for name in headers} == {"retry-after"}


def test_the_headers_are_per_instance_and_the_envelope_view_is_read_only() -> None:
    first, second = answer(), answer()
    assert first.headers is not None
    assert first.headers is not second.headers

    first.headers["X-Edited"] = "1"

    assert second.headers == {"Retry-After": str(RETRY_AFTER)}
    assert first.response_headers == {"Retry-After": str(RETRY_AFTER)}
    with pytest.raises(TypeError):
        first.response_headers["X-Edited"] = "1"  # pyright: ignore[reportIndexIssue]


def test_the_class_constants_are_untouched() -> None:
    """The 503 lives on the instance; the class still holds the sanctioned 401 constants."""
    assert AuthServiceUnavailable503.response_status == 401
    assert AuthServiceUnavailable503.response_headers is BEARER_CHALLENGE
    assert AuthServiceUnavailable.response_status == 401


def test_the_401_form_is_untouched() -> None:
    error = AuthServiceUnavailable(reason=REASON)

    assert (error.status_code, error.detail, error.headers) == (
        401,
        "Not authenticated",
        {"WWW-Authenticate": "Bearer"},
    )
    assert error.response_status == 401
    assert error.response_headers is BEARER_CHALLENGE
    assert repr(error) == f"AuthServiceUnavailable(reason={REASON!r})"
    assert type(pickle.loads(pickle.dumps(error))) is AuthServiceUnavailable


def test_repr_carries_the_reason_and_the_retry_after_and_str_carries_neither() -> None:
    error = answer()

    assert repr(error) == f"AuthServiceUnavailable503(reason={REASON!r}, retry_after={RETRY_AFTER})"
    assert REASON not in str(error)


@pytest.mark.parametrize(
    "revive",
    [lambda e: pickle.loads(pickle.dumps(e)), copy.copy, copy.deepcopy],
    ids=["pickle", "copy", "deepcopy"],
)
def test_it_survives_pickle_and_copy_as_the_503(revive: object) -> None:
    error = answer()

    revived = revive(error)  # pyright: ignore[reportCallIssue, reportUnknownVariableType]

    assert type(revived) is AuthServiceUnavailable503  # pyright: ignore[reportUnknownArgumentType]
    assert isinstance(revived, AuthServiceUnavailable503)
    assert revived.reason == REASON
    assert revived.retry_after == RETRY_AFTER
    assert (revived.status_code, revived.headers) == (503, {"Retry-After": str(RETRY_AFTER)})
    assert revived.response_status == 503


def test_retry_after_is_keyword_only_and_required() -> None:
    with pytest.raises(TypeError):
        AuthServiceUnavailable503(reason=REASON)  # pyright: ignore[reportCallIssue]
    with pytest.raises(TypeError):
        AuthServiceUnavailable503(REASON, RETRY_AFTER)  # pyright: ignore[reportCallIssue]


def test_a_subclass_still_may_not_answer_503_by_a_class_constant() -> None:
    with pytest.raises(TypeError, match="response_status"):

        class Loud(AuthServiceUnavailable):  # pyright: ignore[reportUnusedClass]
            response_status: ClassVar[int] = 503

    with pytest.raises(TypeError, match="response_status"):

        class Louder(AuthServiceUnavailable503):  # pyright: ignore[reportUnusedClass]
            response_status: ClassVar[int] = 503


def test_a_subclass_still_may_not_drop_the_challenge_by_a_class_constant() -> None:
    with pytest.raises(TypeError, match="response_headers"):

        class Quiet(AuthServiceUnavailable):  # pyright: ignore[reportUnusedClass]
            response_headers: ClassVar[Mapping[str, str] | None] = {"Retry-After": "5"}
