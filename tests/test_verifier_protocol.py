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
from fastapi_better_auth import Session, User, Verifier
from tests.fakes import (
    AsyncExtractVerifier,
    FailingVerifier,
    FakeVerifier,
    NonCallableVerifier,
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


def test_the_protocol_declares_a_credential_source() -> None:
    """A label naming where the credential comes from, so two verifiers racing on one
    source are caught at construction rather than by every request being ambiguous."""
    hints = get_type_hints(Verifier)

    assert hints["credential_source"] is str


def test_a_verifier_without_a_credential_source_is_not_a_verifier() -> None:
    class Sourceless:
        def extract(self, connection: HTTPConnection) -> str | None:
            return None

        async def verify(self, credential: Any, user_model: type[User]) -> Session[User]:
            raise NotImplementedError

    assert not isinstance(Sourceless(), Verifier)


def test_the_credential_source_is_documented_as_diagnostics_only() -> None:
    """An honesty contract, not a control: a verifier that lies about its label must not
    be able to reach anything a request-time decision keys on."""
    doc = Verifier.__doc__ or ""

    assert "credential_source" in doc
    assert "never" in doc.lower()


def test_the_extract_docstring_states_that_a_session_error_is_not_honoured() -> None:
    """The asymmetry with `verify` is deliberate and has to be written down: `extract`
    decides ownership, not validity, so a refusal raised there is a parser escape."""
    doc = Verifier.extract.__doc__ or ""

    assert "SessionError" in doc


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


def test_runtime_conformance_only_proves_the_members_exist() -> None:
    """A trap, asserted so it cannot be forgotten: `isinstance` against a runtime-checkable
    Protocol checks names, not signatures and not callability. All three pass it and none
    of them works."""
    assert isinstance(AsyncExtractVerifier(), Verifier)
    assert isinstance(SyncVerifyVerifier(), Verifier)
    assert isinstance(NonCallableVerifier(), Verifier)
