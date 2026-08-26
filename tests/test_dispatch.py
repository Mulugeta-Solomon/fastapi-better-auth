"""Credential-presence dispatch (D-003) — the three rules, one RED test each.

Which verifier answers a request is decided by which credential is *present*, never by
trying them until one works. The consequences are load-bearing: a present-but-invalid
credential is terminal (trying the next verifier is a downgrade attack), two credentials
are refused before anything is verified, and none is an absence rather than a failure.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from fastapi_better_auth import (
    AmbiguousCredentials,
    BetterAuth,
    ConfigurationError,
    InvalidCredential,
    MissingCredential,
    Session,
    SessionExpired,
    User,
)
from tests.fakes import (
    BAD_CREDENTIAL,
    GOOD_CREDENTIAL,
    AsyncExtractVerifier,
    FailingVerifier,
    FakeVerifier,
    NotAVerifier,
    SyncVerifyVerifier,
    connection,
    resolver_of,
    session_app,
)

HEADER_A = "x-cred-a"
HEADER_B = "x-cred-b"
HEADER_C = "x-cred-c"


def pair() -> tuple[FakeVerifier, FakeVerifier, BetterAuth, list[str]]:
    log: list[str] = []
    first = FakeVerifier(HEADER_A, log=log)
    second = FakeVerifier(HEADER_B, log=log)
    return first, second, BetterAuth(verifiers=[first, second]), log


def resolve_for(auth: BetterAuth) -> Callable[..., Awaitable[Session[Any] | None]]:
    return resolver_of(auth.current_session(user_model=User))


# --- constructor: every fault is a startup fault, never a request-time 500 -------------


def test_no_verifiers_is_a_configuration_error() -> None:
    with pytest.raises(ConfigurationError) as caught:
        BetterAuth(verifiers=[])

    assert "at least one" in str(caught.value)


@pytest.mark.parametrize(
    "verifiers",
    [NotAVerifier(), "x-cred-a", b"bytes", 42, None],
    ids=["single-object", "str", "bytes", "int", "none"],
)
def test_something_that_is_not_a_sequence_of_verifiers_is_rejected(verifiers: Any) -> None:
    with pytest.raises(ConfigurationError):
        BetterAuth(verifiers=verifiers)


def test_an_object_missing_the_protocol_is_rejected_by_position() -> None:
    with pytest.raises(ConfigurationError) as caught:
        BetterAuth(verifiers=[FakeVerifier(HEADER_A), NotAVerifier()])  # pyright: ignore[reportArgumentType]

    message = str(caught.value)
    assert "NotAVerifier" in message
    assert "1" in message


def test_an_async_extract_is_rejected_at_construction() -> None:
    """A coroutine object is never `None`, so this verifier would claim every request."""
    with pytest.raises(ConfigurationError) as caught:
        BetterAuth(verifiers=[AsyncExtractVerifier()])

    assert "extract" in str(caught.value)


def test_a_synchronous_verify_is_rejected_at_construction() -> None:
    with pytest.raises(ConfigurationError) as caught:
        BetterAuth(verifiers=[SyncVerifyVerifier()])  # pyright: ignore[reportArgumentType]

    assert "verify" in str(caught.value)


def test_the_declared_order_is_captured_and_cannot_be_edited_afterwards() -> None:
    first = FakeVerifier(HEADER_A)
    second = FakeVerifier(HEADER_B)
    declared = [first, second]
    auth = BetterAuth(verifiers=declared)
    declared.append(FakeVerifier(HEADER_C))

    assert auth.verifiers == (first, second)


def test_a_user_model_that_is_not_a_user_is_rejected_at_startup() -> None:
    auth = BetterAuth(verifiers=[FakeVerifier(HEADER_A)])

    with pytest.raises(ConfigurationError):
        auth.current_session(user_model=str)  # pyright: ignore[reportArgumentType]

    with pytest.raises(ConfigurationError):
        auth.optional_session(user_model=object)  # pyright: ignore[reportArgumentType]


# --- rule 1: exactly one credential present -------------------------------------------


@pytest.mark.anyio
async def test_the_verifier_whose_credential_is_present_answers() -> None:
    first, second, auth, _log = pair()

    session = await resolve_for(auth)(connection(**{HEADER_B: GOOD_CREDENTIAL}))

    assert session is not None
    assert session.user.id == "u1"
    assert (first.verify_calls, second.verify_calls) == (0, 1)


@pytest.mark.anyio
async def test_every_verifier_is_extracted_before_any_is_verified() -> None:
    """Extraction is the whole dispatch decision; it must finish before verification."""
    first, second, auth, log = pair()

    await resolve_for(auth)(connection(**{HEADER_A: GOOD_CREDENTIAL}))

    assert (first.extract_calls, second.extract_calls) == (1, 1)
    assert log == [f"extract:{HEADER_A}", f"extract:{HEADER_B}", f"verify:{HEADER_A}"]


# --- rule 2: present-but-invalid is terminal ------------------------------------------


@pytest.mark.anyio
async def test_a_failed_verification_never_falls_through_to_another_verifier() -> None:
    """The downgrade attack: forge the weak credential, hope the library tries the next
    verifier and answers "no credential" instead of "bad credential"."""
    failing = FailingVerifier(HEADER_A, InvalidCredential, "forged signature kid=aX9")
    healthy = FakeVerifier(HEADER_B)
    auth = BetterAuth(verifiers=[failing, healthy])

    with pytest.raises(InvalidCredential):
        await resolve_for(auth)(connection(**{HEADER_A: BAD_CREDENTIAL}))

    assert healthy.verify_calls == 0


@pytest.mark.anyio
async def test_a_terminal_failure_keeps_its_own_class() -> None:
    """A fallthrough would answer `MissingCredential`; the distinction is the whole rule."""
    failing = FailingVerifier(HEADER_A, SessionExpired, "expiry elapsed sid_fp=7c1de90f")
    auth = BetterAuth(verifiers=[failing, FakeVerifier(HEADER_B)])

    with pytest.raises(SessionExpired):
        await resolve_for(auth)(connection(**{HEADER_A: BAD_CREDENTIAL}))


@pytest.mark.anyio
async def test_a_malformed_upstream_payload_is_an_invalid_credential() -> None:
    broken = FakeVerifier(HEADER_A, payload={"id": ""})
    auth = BetterAuth(verifiers=[broken])

    with pytest.raises(InvalidCredential):
        await resolve_for(auth)(connection(**{HEADER_A: GOOD_CREDENTIAL}))


# --- rule 3: two or more credentials ---------------------------------------------------


@pytest.mark.anyio
async def test_two_credentials_are_refused_before_anything_is_verified() -> None:
    first, second, auth, _log = pair()

    with pytest.raises(AmbiguousCredentials):
        await resolve_for(auth)(
            connection(**{HEADER_A: GOOD_CREDENTIAL, HEADER_B: GOOD_CREDENTIAL})
        )

    assert (first.verify_calls, second.verify_calls) == (0, 0)


@pytest.mark.anyio
async def test_three_credentials_are_refused_too() -> None:
    verifiers = [FakeVerifier(HEADER_A), FakeVerifier(HEADER_B), FakeVerifier(HEADER_C)]
    auth = BetterAuth(verifiers=verifiers)
    headers = {HEADER_A: GOOD_CREDENTIAL, HEADER_B: GOOD_CREDENTIAL, HEADER_C: GOOD_CREDENTIAL}

    with pytest.raises(AmbiguousCredentials) as caught:
        await resolve_for(auth)(connection(**headers))

    assert all(verifier.verify_calls == 0 for verifier in verifiers)
    assert "3" in caught.value.reason


@pytest.mark.anyio
async def test_ambiguity_beats_a_credential_that_would_have_failed() -> None:
    """Ambiguity is decided on presence alone — validity is never consulted."""
    failing = FailingVerifier(HEADER_A, InvalidCredential, "forged")
    healthy = FakeVerifier(HEADER_B)
    auth = BetterAuth(verifiers=[failing, healthy])

    with pytest.raises(AmbiguousCredentials):
        await resolve_for(auth)(connection(**{HEADER_A: BAD_CREDENTIAL, HEADER_B: GOOD_CREDENTIAL}))

    assert (failing.verify_calls, healthy.verify_calls) == (0, 0)


# --- rule 4: no credential at all ------------------------------------------------------


@pytest.mark.anyio
async def test_no_credential_resolves_to_none_rather_than_an_error() -> None:
    """The resolver is shared: `optional_session` needs the absence, not an exception."""
    first, second, auth, _log = pair()

    assert await resolve_for(auth)(connection()) is None
    assert (first.verify_calls, second.verify_calls) == (0, 0)


# --- the same rules, observed on the wire ----------------------------------------------


def test_the_wire_shape_of_each_rule() -> None:
    _first, _second, auth, _log = pair()
    with TestClient(session_app(auth)) as client:
        ok = client.get("/required", headers={HEADER_A: GOOD_CREDENTIAL})
        ambiguous = client.get(
            "/required", headers={HEADER_A: GOOD_CREDENTIAL, HEADER_B: GOOD_CREDENTIAL}
        )
        absent = client.get("/required")

    assert ok.status_code == 200
    assert ok.json() == {"id": "u1", "model": "User"}
    assert ambiguous.status_code == 400
    assert absent.status_code == 401


def test_missing_and_ambiguous_are_the_documented_classes() -> None:
    assert MissingCredential.response_status == 401
    assert AmbiguousCredentials.response_status == 400
