"""The `Verifier` Protocol: two methods, and the split between them is the security rule.

`extract` is a cheap, synchronous presence check — it decides *whether* this verifier owns
the request, and dispatch runs it on every verifier before any verification happens.
`verify` is the expensive, async, failing half. Collapsing the two would make "which
verifier answers" a question you can only answer by trying them, which is the fallthrough
this library refuses to do.
"""

from __future__ import annotations

import inspect
from typing import Any, get_type_hints

import pytest
from starlette.requests import HTTPConnection

import fastapi_better_auth
from fastapi_better_auth import Verifier
from tests.fakes import (
    AsyncExtractVerifier,
    FailingVerifier,
    FakeVerifier,
    NotAVerifier,
    SyncVerifyVerifier,
)


def test_the_protocol_is_public_api() -> None:
    assert "Verifier" in fastapi_better_auth.__all__
    assert fastapi_better_auth.Verifier is Verifier


def test_a_conforming_fake_is_recognized_at_runtime() -> None:
    assert isinstance(FakeVerifier("x-fake"), Verifier)
    assert isinstance(FailingVerifier("x-fake", fastapi_better_auth.SessionExpired, "r"), Verifier)


@pytest.mark.parametrize(
    "candidate",
    [NotAVerifier(), object(), "a string", 42, None],
    ids=["no-methods", "object", "str", "int", "none"],
)
def test_a_non_conforming_object_is_not_a_verifier(candidate: Any) -> None:
    assert not isinstance(candidate, Verifier)


def test_the_protocol_cannot_be_instantiated() -> None:
    with pytest.raises(TypeError):
        Verifier()  # pyright: ignore[reportAbstractUsage]


def test_extract_is_synchronous_by_declaration() -> None:
    """An async `extract` returns a coroutine, which is never `None` — every request
    would then look like it carried this verifier's credential."""
    assert not inspect.iscoroutinefunction(Verifier.extract)


def test_verify_is_asynchronous_by_declaration() -> None:
    assert inspect.iscoroutinefunction(Verifier.verify)


def test_extract_takes_a_connection_not_a_request() -> None:
    """`HTTPConnection` covers WebSockets too, and carries no URL-derived helpers we may
    read (D-010)."""
    hints = get_type_hints(Verifier.extract)

    assert hints["connection"] is HTTPConnection


def test_runtime_conformance_only_proves_the_methods_exist() -> None:
    """A trap, asserted so it cannot be forgotten: `isinstance` against a runtime-checkable
    Protocol checks names, not signatures. Both of these pass it and neither works."""
    assert isinstance(AsyncExtractVerifier(), Verifier)
    assert isinstance(SyncVerifyVerifier(), Verifier)
