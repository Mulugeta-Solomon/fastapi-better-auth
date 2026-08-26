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
    BlankSourceVerifier,
    BrokenConfigVerifier,
    FailingVerifier,
    FakeVerifier,
    NonCallableVerifier,
    NotAVerifier,
    NullVerifier,
    RaisingExtractVerifier,
    RaisingVerifyVerifier,
    SessionErrorExtractVerifier,
    SyncVerifyVerifier,
    TracedVerifier,
    WrongModelVerifier,
    connection,
    resolver_of,
    session_app,
)

HEADER_A = "x-cred-a"
HEADER_B = "x-cred-b"
HEADER_C = "x-cred-c"


class AdminUser(User):
    """A deployment's own model, so a verifier that ignores `user_model` is detectable."""

    role: str | None = None


def pair() -> tuple[FakeVerifier, FakeVerifier, BetterAuth, list[str]]:
    log: list[str] = []
    first = FakeVerifier(HEADER_A, log=log)
    second = FakeVerifier(HEADER_B, log=log)
    return first, second, BetterAuth(verifiers=[first, second]), log


def resolve_for(
    auth: BetterAuth, user_model: type[User] = User
) -> Callable[..., Awaitable[Session[Any] | None]]:
    return resolver_of(auth.current_session(user_model=user_model))


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
    assert "[1]" in message


def test_an_async_extract_is_rejected_at_construction() -> None:
    """A coroutine object is never `None`, so this verifier would claim every request."""
    with pytest.raises(ConfigurationError) as caught:
        BetterAuth(verifiers=[AsyncExtractVerifier()])

    assert "extract" in str(caught.value)


def test_a_verify_wrapped_by_a_plain_decorator_is_accepted() -> None:
    """`inspect.iscoroutinefunction` is False for a `functools.wraps` tracing wrapper, and
    refusing that shape would reject a perfectly good verifier at startup."""
    auth = BetterAuth(verifiers=[TracedVerifier(HEADER_A)])

    assert auth.verifiers


@pytest.mark.anyio
async def test_a_verify_that_is_not_awaitable_is_a_configuration_fault_not_a_401() -> None:
    """It cannot be caught at startup for every shape, so it is caught loudly, once,
    rather than degraded into a credential failure that hides the mistake."""
    auth = BetterAuth(verifiers=[SyncVerifyVerifier()])  # pyright: ignore[reportArgumentType]

    with pytest.raises(ConfigurationError) as caught:
        await resolve_for(auth)(connection(**{"x-sync": GOOD_CREDENTIAL}))

    assert "verify" in str(caught.value)


@pytest.mark.parametrize(
    "verifier",
    [NonCallableVerifier(), NotAVerifier()],
    ids=["non-callable-attributes", "missing-methods"],
)
def test_a_verifier_whose_methods_are_not_callable_is_rejected(verifier: Any) -> None:
    with pytest.raises(ConfigurationError):
        BetterAuth(verifiers=[verifier])


def test_the_same_verifier_twice_is_rejected() -> None:
    """Both copies would extract the same credential, so every request would be ambiguous
    - a total authentication outage that startup would otherwise call healthy."""
    verifier = FakeVerifier(HEADER_A)

    with pytest.raises(ConfigurationError) as caught:
        BetterAuth(verifiers=[verifier, verifier])

    assert "twice" in str(caught.value)


def test_two_verifiers_declaring_one_credential_source_are_rejected() -> None:
    """The collision identity-comparison cannot see: two *distinct* verifiers reading the
    same credential. Every request carrying it would be ambiguous, and startup would
    otherwise call the deployment healthy."""
    with pytest.raises(ConfigurationError) as caught:
        BetterAuth(
            verifiers=[
                FakeVerifier(HEADER_A, source="cookie:better-auth.session_token"),
                FailingVerifier(
                    HEADER_B, InvalidCredential, "r", source="COOKIE:Better-Auth.Session_Token"
                ),
            ]
        )

    message = str(caught.value)
    assert "FakeVerifier" in message
    assert "FailingVerifier" in message
    assert "better-auth.session_token" in message.lower()


@pytest.mark.parametrize(
    "verifier",
    [BlankSourceVerifier(HEADER_A), FakeVerifier(HEADER_A, source="")],
    ids=["whitespace-only", "empty"],
)
def test_a_blank_credential_source_is_rejected(verifier: Any) -> None:
    with pytest.raises(ConfigurationError) as caught:
        BetterAuth(verifiers=[verifier])

    assert "credential_source" in str(caught.value)


def test_a_non_string_credential_source_is_rejected() -> None:
    with pytest.raises(ConfigurationError) as caught:
        BetterAuth(verifiers=[FakeVerifier(HEADER_A, source=3)])  # pyright: ignore[reportArgumentType]

    assert "credential_source" in str(caught.value)


def test_the_verifiers_argument_is_keyword_only() -> None:
    with pytest.raises(TypeError):
        BetterAuth([FakeVerifier(HEADER_A)])  # pyright: ignore[reportCallIssue]


def test_the_user_model_argument_is_keyword_only() -> None:
    auth = BetterAuth(verifiers=[FakeVerifier(HEADER_A)])

    with pytest.raises(TypeError):
        auth.current_session(User)  # pyright: ignore[reportCallIssue]
    with pytest.raises(TypeError):
        auth.optional_session(User)  # pyright: ignore[reportCallIssue]


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


@pytest.mark.anyio
async def test_an_empty_credential_is_present_not_absent() -> None:
    """`None` is the only absence signal. Tightening this to a truthiness test would turn
    a blank cookie into "nobody asked", which `optional_session` answers with a 200."""
    verifier = FakeVerifier(HEADER_A)
    auth = BetterAuth(verifiers=[verifier])

    with pytest.raises(InvalidCredential):
        await resolve_for(auth)(connection(**{HEADER_A: ""}))

    assert verifier.verify_calls == 1


# --- rogue verifiers: the protocol is structural, so the answer must be checked --------


@pytest.mark.anyio
async def test_a_verifier_that_returns_none_is_a_configuration_fault() -> None:
    """`None` is the dispatcher's absence signal, so an unchecked return would downgrade a
    presented credential to anonymous - the fail-open D-004 exists to prevent."""
    auth = BetterAuth(verifiers=[NullVerifier(HEADER_A)])

    with pytest.raises(ConfigurationError) as caught:
        await resolve_for(auth)(connection(**{HEADER_A: GOOD_CREDENTIAL}))

    assert "NullVerifier" in str(caught.value)


@pytest.mark.anyio
async def test_a_verifier_that_ignores_the_user_model_is_a_configuration_fault() -> None:
    """Otherwise the wrong model reaches user code and 500s on its first extra field."""
    auth = BetterAuth(verifiers=[WrongModelVerifier(HEADER_A)])

    with pytest.raises(ConfigurationError):
        await resolve_for(auth, user_model=AdminUser)(connection(**{HEADER_A: GOOD_CREDENTIAL}))


def test_a_rogue_verifier_never_grants_anonymous_access() -> None:
    """The wire form of the fail-open: `optional_session` must not answer 200 with a null
    session for a request that presented a credential. A loud 500 is the correct answer -
    the verifier is broken, and hiding that behind a 401 would make it permanent."""
    auth = BetterAuth(verifiers=[NullVerifier(HEADER_A)])
    with TestClient(session_app(auth), raise_server_exceptions=False) as http:
        response = http.get("/optional", headers={HEADER_A: GOOD_CREDENTIAL})

    assert response.status_code == 500
    assert response.text != '{"id":null,"model":null}'


@pytest.mark.parametrize(
    ("verifier_cls", "header"),
    [(RaisingExtractVerifier, HEADER_A), (RaisingVerifyVerifier, HEADER_A)],
    ids=["extract-raises", "verify-raises"],
)
def test_an_exception_escaping_a_verifier_answers_the_uniform_401(
    verifier_cls: Any, header: str
) -> None:
    """A 500 is the only wire-distinguishable request-time outcome, and under a debug
    handler its body is a traceback carrying the credential out of the frame locals."""
    auth = BetterAuth(verifiers=[verifier_cls(header)])
    with TestClient(session_app(auth)) as http:
        response = http.get("/required", headers={header: BAD_CREDENTIAL})

    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}
    assert BAD_CREDENTIAL not in response.text


@pytest.mark.anyio
async def test_a_contained_exception_names_only_its_type() -> None:
    auth = BetterAuth(verifiers=[RaisingVerifyVerifier(HEADER_A)])

    with pytest.raises(InvalidCredential) as caught:
        await resolve_for(auth)(connection(**{HEADER_A: BAD_CREDENTIAL}))

    reason = caught.value.reason
    assert "RuntimeError" in reason
    assert "RaisingVerifyVerifier" in reason
    assert BAD_CREDENTIAL not in reason
    assert caught.value.__cause__ is None


@pytest.mark.anyio
async def test_a_session_error_raised_from_extract_is_a_parser_escape() -> None:
    """Deliberate asymmetry with `verify`, pinned so nobody "fixes" it: `extract` decides
    ownership, not validity, so a refusal raised there is contained like any other escape
    rather than honoured - and its reason does not survive into ours."""
    secret = "sid_fp=7c1de90f elapsed"
    auth = BetterAuth(verifiers=[SessionErrorExtractVerifier(HEADER_A, SessionExpired, secret)])

    with pytest.raises(InvalidCredential) as caught:
        await resolve_for(auth)(connection(**{HEADER_A: GOOD_CREDENTIAL}))

    assert "SessionExpired" in caught.value.reason
    assert "extract" in caught.value.reason
    assert secret not in caught.value.reason


@pytest.mark.anyio
async def test_containment_never_swallows_a_configuration_error() -> None:
    """A deployment fault must stay loud; degrading it to a 401 would hide it forever."""
    auth = BetterAuth(verifiers=[BrokenConfigVerifier(HEADER_A)])

    with pytest.raises(ConfigurationError):
        await resolve_for(auth)(connection(**{HEADER_A: GOOD_CREDENTIAL}))


@pytest.mark.anyio
async def test_containment_never_swallows_a_session_error() -> None:
    """A verifier's own refusal is the answer, not something to reinterpret."""
    auth = BetterAuth(verifiers=[FailingVerifier(HEADER_A, SessionExpired, "elapsed")])

    with pytest.raises(SessionExpired):
        await resolve_for(auth)(connection(**{HEADER_A: BAD_CREDENTIAL}))


@pytest.mark.anyio
async def test_no_raw_credential_survives_in_the_dispatch_frame() -> None:
    """Error reporters capture frame locals; this frame is the sole holder on the
    ambiguity path, where no verifier frame exists to blame."""
    secret = "raw-session-token-9f3ab21c"
    auth = BetterAuth(verifiers=[FakeVerifier(HEADER_A), FakeVerifier(HEADER_B)])

    with pytest.raises(AmbiguousCredentials) as caught:
        await resolve_for(auth)(connection(**{HEADER_A: secret, HEADER_B: secret}))

    rendered = " ".join(repr(frame.f_locals) for frame in _library_frames(caught.value))

    assert rendered, "no library frame was captured; retune this probe"
    assert secret not in rendered, "a presented credential survived in a captured frame"


def _library_frames(error: BaseException) -> list[Any]:
    """Only this library's own frames — a test's locals are not what a reporter blames."""
    frames: list[Any] = []
    tb = error.__traceback__
    while tb is not None:
        if "fastapi_better_auth" in tb.tb_frame.f_code.co_filename:
            frames.append(tb.tb_frame)
        tb = tb.tb_next
    return frames


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
    for header in (HEADER_A, HEADER_B, HEADER_C):
        assert f"header:{header}" in caught.value.reason


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
