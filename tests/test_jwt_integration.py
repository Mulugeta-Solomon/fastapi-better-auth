"""The JWT verifier behind `Depends`, on the wire, on both backends.

Everything else about Mode B is asserted by calling `verify` directly, which is the honest
way to test a verifier and says nothing about the request it was supposed to answer. This
file is the other half: a real FastAPI app, a real `Authorization` header, and the response
a client actually receives - including the one property that has to hold across the whole
taxonomy, that a forged token, an expired one and an unreachable key set are indistinguishable.
"""

from __future__ import annotations

import logging
import time

import jwt
import pytest

from fastapi_better_auth import BetterAuth, ConfigurationError, JwtVerifier, User
from fastapi_better_auth._internal.jwt_verifier import MAX_TOKEN_BYTES
from tests.fakes import client, session_app
from tests.tokens import (
    LIFETIME,
    ORIGIN,
    SUBJECT,
    claims,
    deep_header_token,
    deepest_under,
    ed25519_signer,
    exhausted_parse,
    key_set,
)
from tests.transports import ScriptedTransport, json_reply

SIGNER = ed25519_signer("wire-1")
KEY_SET = key_set(SIGNER)
DEEP_HEADER = deepest_under(deep_header_token, MAX_TOKEN_BYTES)
"""A token whose JOSE header defeats the JSON scanner and still fits under the size cap."""


def bridge(*answers: object) -> tuple[BetterAuth, ScriptedTransport]:
    transport = ScriptedTransport(*(answers or (json_reply(KEY_SET),)))  # pyright: ignore[reportArgumentType]
    return BetterAuth(verifiers=[JwtVerifier(base_url=ORIGIN, transport=transport)]), transport


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_a_valid_token_authenticates_a_route(client_backend: str) -> None:
    auth, _transport = bridge()
    with client(session_app(auth), client_backend) as driver:
        response = driver.get("/required", headers=bearer(SIGNER.sign(claims())))

    assert response.status_code == 200
    assert response.json() == {"id": SUBJECT, "model": "User"}


def test_an_anonymous_request_is_a_401_when_required_and_a_null_when_not(
    client_backend: str,
) -> None:
    auth, transport = bridge()
    with client(session_app(auth), client_backend) as driver:
        required = driver.get("/required")
        optional = driver.get("/optional")

    assert required.status_code == 401
    assert optional.status_code == 200
    assert optional.json() == {"id": None, "model": None}
    assert transport.calls == 0, "an anonymous request must not reach for a key set"


def test_a_presented_token_that_does_not_verify_is_never_degraded_to_anonymous(
    client_backend: str,
) -> None:
    """`optional_session` returns `None` for *nobody asked*, and for nothing else."""
    auth, _transport = bridge()
    with client(session_app(auth), client_backend) as driver:
        response = driver.get("/optional", headers=bearer(ed25519_signer("wire-1").sign(claims())))

    assert response.status_code == 401


def test_every_refusal_is_byte_identical_on_the_wire(client_backend: str) -> None:
    """A client that could tell an expired token from a forged one from an unreachable key
    set has an oracle; a client that can tell any of them from an anonymous request has two."""
    forged = ed25519_signer("wire-1").sign(claims())
    expired = SIGNER.sign(claims(issued_at=int(time.time()) - LIFETIME * 3))

    healthy, _transport = bridge()
    with client(session_app(healthy), client_backend) as driver:
        answers = [
            driver.get("/required"),
            driver.get("/required", headers=bearer(forged)),
            driver.get("/required", headers=bearer(expired)),
            driver.get("/required", headers=bearer("not-a-token")),
        ]
    down, _down_transport = bridge(TimeoutError("jwks unreachable"))
    with client(session_app(down), client_backend) as driver:
        answers.append(driver.get("/required", headers=bearer(SIGNER.sign(claims()))))

    assert {answer.status_code for answer in answers} == {401}
    assert {answer.content for answer in answers} == {b'{"detail":"Not authenticated"}'}
    assert all(answer.headers["www-authenticate"] == "Bearer" for answer in answers)


def test_one_request_verifies_once_however_many_dependencies_declare_it(
    client_backend: str,
) -> None:
    auth, transport = bridge()
    app = session_app(auth)
    token = SIGNER.sign(claims())

    with client(app, client_backend) as driver:
        first = driver.get("/required", headers=bearer(token))
        second = driver.get("/required", headers=bearer(token))

    assert first.status_code == second.status_code == 200
    assert transport.calls == 1, "the key set was fetched again for a cached kid"


def test_two_bearer_verifiers_are_refused_at_construction() -> None:
    """Both would read `Authorization`, so every bearer request would be ambiguous - a total
    outage that startup would otherwise call healthy."""
    with pytest.raises(ConfigurationError) as caught:
        BetterAuth(
            verifiers=[
                JwtVerifier(base_url=ORIGIN, transport=ScriptedTransport(json_reply(KEY_SET))),
                JwtVerifier(
                    base_url="https://auth.example.com",
                    transport=ScriptedTransport(json_reply(KEY_SET)),
                ),
            ]
        )

    assert "header:authorization-bearer" in str(caught.value)


def test_the_user_model_the_application_asked_for_is_the_one_it_gets(
    client_backend: str,
) -> None:
    class Staff(User):
        role: str | None = None

    auth, _transport = bridge()
    with client(session_app(auth, user_model=Staff), client_backend) as driver:
        response = driver.get("/required", headers=bearer(SIGNER.sign(claims(role="admin"))))

    assert response.status_code == 200
    assert response.json() == {"id": SUBJECT, "model": "Staff"}


def test_a_token_the_json_parser_gives_up_on_logs_no_traceback(
    client_backend: str, caplog: pytest.LogCaptureFixture
) -> None:
    """SA-4, measured where it actually cost something, and pinned by construction.

    The wire answer was already the uniform 401 - `core._contained` caught the
    `RecursionError` that escaped the verifier - but containment logs, so every one of these
    unauthenticated ~8 KiB requests bought an ERROR record carrying a full traceback. That is
    a log-amplification lever an attacker pulls for free, and the reason a malformed token has
    to be refused *as* a malformed token. The parse is made to give up here rather than
    driven there by a probe, because whether a probe under the size cap can reach that state
    is a property of the interpreter, and this cost is not.
    """
    auth, transport = bridge()

    with caplog.at_level(logging.ERROR), pytest.MonkeyPatch.context() as patch:
        patch.setattr(jwt, "get_unverified_header", exhausted_parse)
        with client(session_app(auth), client_backend) as driver:
            response = driver.get("/required", headers=bearer(SIGNER.sign(claims())))

    assert response.status_code == 401
    assert response.content == b'{"detail":"Not authenticated"}'
    assert caplog.records == []
    assert transport.calls == 0


def test_a_token_nested_as_deep_as_the_cap_allows_logs_no_traceback(
    client_backend: str, caplog: pytest.LogCaptureFixture
) -> None:
    """The same cost, driven by the deepest header an unauthenticated client may actually
    send. Where that body defeats this interpreter's scanner it is the escape above walked
    for real; where it does not, PyJWT refuses the parsed list as "not a json object". Either
    way the request must be a silent 401, which is the property being measured."""
    auth, transport = bridge()

    with caplog.at_level(logging.ERROR), client(session_app(auth), client_backend) as driver:
        response = driver.get("/required", headers=bearer(DEEP_HEADER))

    assert response.status_code == 401
    assert response.content == b'{"detail":"Not authenticated"}'
    assert caplog.records == []
    assert transport.calls == 0
