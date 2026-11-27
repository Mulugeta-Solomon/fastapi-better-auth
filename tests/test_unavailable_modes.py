"""The opt-in 503 in each mode, with its real dependency failing, through a real FastAPI app.

Two questions per mode. What the default answers: the unknown-credential 401, byte for byte. And
what the 503 reveals that the 401 hid: which requests reach the dependency at all. Only those can
ever be answered 503; everything refused before the dependency is asked stays the 401.
"""

from __future__ import annotations

from typing import Any

import anyio
import pytest
from fastapi import FastAPI

from fastapi_better_auth import BetterAuth, CsrfDisabled, RemoteVerifier, StoredSession
from fastapi_better_auth._internal.jwt_verifier import JwtVerifier
from tests import remote_fixtures as remote
from tests.cookies import (
    CAPTURED_TOKEN,
    COOKIE,
    FAR_PAST,
    FakeStore,
    seeded_store,
    sign,
    stored_session,
)
from tests.cookies import verifier as cookie_verifier
from tests.fakes import TestClient, session_app
from tests.jwks_fixtures import wind_jwks_clock
from tests.tokens import ORIGIN, claims, ed25519_signer, forged, key_set
from tests.transports import ScriptedTransport, json_reply
from tests.unavailable_support import UNKNOWN_CREDENTIAL_401, service_unavailable, wire

RETRY_AFTER = 7
OPT_IN: dict[str, Any] = {"unavailable_status": 503, "unavailable_retry_after": RETRY_AFTER}
LOOKUP_TIMEOUT = 0.05
SIGNER = ed25519_signer("kid-cached")
STRANGER = ed25519_signer("kid-not-cached")
CACHE_TTL = 300.0
OTHER_SECRET_VALUE = b"Nf4Wq7zC2mVt9Bs5Kx1Ld8Hj6Yr3Pg0Zx"


def answers(verifier: Any, headers: dict[str, str], **settings: Any) -> Any:
    app: FastAPI = session_app(BetterAuth(verifiers=[verifier], **settings))
    with TestClient(app) as http:
        return http.get("/required", headers=headers)


def both(verifier: Any, headers: dict[str, str]) -> tuple[Any, Any]:
    """The default bridge's answer, then the opt-in bridge's, from one shared verifier."""
    return wire(answers(verifier, headers)), wire(answers(verifier, headers, **OPT_IN))


# --- Mode A: the session store --------------------------------------------------------------


class StalledStore(FakeStore):
    """A store whose session lookup never returns: the database stall of issue #122."""

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        self.session_calls.append(token)
        await anyio.sleep_forever()
        raise AssertionError("unreachable")  # pragma: no cover


def cookie(value: str) -> dict[str, str]:
    return {"cookie": f"{COOKIE}={value}"}


def test_mode_a_a_signed_cookie_on_a_stalled_store_is_401_by_default_and_503_opted_in() -> None:
    store = StalledStore()
    verifier = cookie_verifier(store=store, lookup_timeout=LOOKUP_TIMEOUT)

    default, opted = both(verifier, cookie(sign(CAPTURED_TOKEN)))

    assert default == UNKNOWN_CREDENTIAL_401
    assert opted == service_unavailable(RETRY_AFTER)
    assert len(store.session_calls) == 2


@pytest.mark.parametrize(
    "value",
    [sign(CAPTURED_TOKEN, OTHER_SECRET_VALUE), CAPTURED_TOKEN, "a.b", "%ZZ"],
    ids=["wrong-secret", "unsigned", "short", "undecodable"],
)
def test_mode_a_only_a_verified_signature_reaches_the_store(value: str) -> None:
    store = StalledStore()
    verifier = cookie_verifier(store=store, lookup_timeout=LOOKUP_TIMEOUT)

    default, opted = both(verifier, cookie(value))

    assert default == opted == UNKNOWN_CREDENTIAL_401
    assert store.session_calls == []


@pytest.mark.parametrize("case", ["revoked", "expired"])
def test_mode_a_every_other_refusal_is_unchanged_with_the_opt_in(case: str) -> None:
    store = seeded_store()
    if case == "expired":
        store.sessions[CAPTURED_TOKEN] = stored_session(CAPTURED_TOKEN, expires_at=FAR_PAST)
    token = "Unseeded0Token0Of0Thirty0Two0Chr" if case == "revoked" else CAPTURED_TOKEN
    verifier = cookie_verifier(store=store)

    default, opted = both(verifier, cookie(sign(token)))

    assert default == opted == UNKNOWN_CREDENTIAL_401


# --- Mode B: the key set ----------------------------------------------------------------------


def bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def jwt_verifier(transport: ScriptedTransport) -> JwtVerifier:
    return JwtVerifier(base_url=ORIGIN, transport=transport)


def test_mode_b_no_key_set_yet_is_401_by_default_and_503_opted_in() -> None:
    transport = ScriptedTransport(OSError("connection refused"))

    default, opted = both(jwt_verifier(transport), bearer(SIGNER.sign(claims())))

    assert default == UNKNOWN_CREDENTIAL_401
    assert opted == service_unavailable(RETRY_AFTER)


def test_mode_b_a_well_formed_header_with_a_forged_signature_also_reaches_the_key_set() -> None:
    """The 503 says nothing about the signature: it is never checked without a key."""
    transport = ScriptedTransport(OSError("connection refused"))
    token = forged({"alg": "EdDSA", "kid": "any-kid", "typ": "JWT"}, claims())

    default, opted = both(jwt_verifier(transport), bearer(token))

    assert default == UNKNOWN_CREDENTIAL_401
    assert opted == service_unavailable(RETRY_AFTER)
    assert transport.calls >= 1


@pytest.mark.parametrize(
    "token",
    [
        "not-a-jwt",
        forged({"alg": "none", "kid": "any-kid"}, claims()),
        forged({"alg": "HS256", "kid": "any-kid"}, claims()),
        forged({"alg": "EdDSA"}, claims()),
    ],
    ids=["garbage", "alg-none", "alg-not-allowed", "no-kid"],
)
def test_mode_b_a_token_refused_on_its_shape_never_reaches_the_key_set(token: str) -> None:
    transport = ScriptedTransport(OSError("connection refused"))

    default, opted = both(jwt_verifier(transport), bearer(token))

    assert default == opted == UNKNOWN_CREDENTIAL_401
    assert transport.calls == 0


def test_mode_b_with_a_fresh_key_set_an_unknown_kid_is_401_not_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wind_jwks_clock(monkeypatch)
    transport = ScriptedTransport(json_reply(key_set(SIGNER)), OSError("connection refused"))
    verifier = jwt_verifier(transport)
    assert answers(verifier, bearer(SIGNER.sign(claims())), **OPT_IN).status_code == 200

    opted = wire(answers(verifier, bearer(STRANGER.sign(claims())), **OPT_IN))

    assert opted == UNKNOWN_CREDENTIAL_401


def test_mode_b_past_the_cache_ttl_a_cached_kid_verifies_and_an_unknown_one_is_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = wind_jwks_clock(monkeypatch)
    transport = ScriptedTransport(json_reply(key_set(SIGNER)), OSError("connection refused"))
    verifier = jwt_verifier(transport)
    assert answers(verifier, bearer(SIGNER.sign(claims())), **OPT_IN).status_code == 200
    clock.advance(CACHE_TTL + 1)

    cached = answers(verifier, bearer(SIGNER.sign(claims())), **OPT_IN)
    default, opted = both(verifier, bearer(STRANGER.sign(claims())))

    assert cached.status_code == 200
    assert default == UNKNOWN_CREDENTIAL_401
    assert opted == service_unavailable(RETRY_AFTER)
    assert verifier._keys.remembered == 0  # pyright: ignore[reportPrivateUsage]


# --- Mode C: the Better Auth server -----------------------------------------------------------


def remote_cookie(value: str = remote.COOKIE_VALUE) -> dict[str, str]:
    return {"cookie": f"{remote.COOKIE_NAME}={value}"}


@pytest.mark.parametrize(
    "value", [remote.COOKIE_VALUE, f"{remote.TOKEN}.forged-signature"], ids=["signed", "forged"]
)
def test_mode_c_any_well_formed_cookie_reaches_the_server(value: str) -> None:
    transport = ScriptedTransport(OSError("connection refused"))

    default, opted = both(remote.verifier(transport), remote_cookie(value))

    assert default == UNKNOWN_CREDENTIAL_401
    assert opted == service_unavailable(RETRY_AFTER)
    assert transport.calls == 2


@pytest.mark.parametrize("value", ["no-dot-at-all", "token."], ids=["no-dot", "no-signature"])
def test_mode_c_a_malformed_cookie_never_reaches_the_server(value: str) -> None:
    transport = ScriptedTransport(OSError("connection refused"))

    default, opted = both(remote.verifier(transport), remote_cookie(value))

    assert default == opted == UNKNOWN_CREDENTIAL_401
    assert transport.calls == 0


def test_mode_c_with_a_keyring_only_a_verified_signature_reaches_the_server() -> None:
    transport = ScriptedTransport(OSError("connection refused"))
    verifier = remote.verifier(transport, secret=remote.SECRET)
    forged_cookie = remote.sign(remote.TOKEN, remote.OTHER_VALUE)

    refused = both(verifier, remote_cookie(forged_cookie))
    reached = both(verifier, remote_cookie())

    assert refused == (UNKNOWN_CREDENTIAL_401, UNKNOWN_CREDENTIAL_401)
    assert reached == (UNKNOWN_CREDENTIAL_401, service_unavailable(RETRY_AFTER))
    assert transport.calls == 2


def test_mode_c_an_unconfirmed_probe_is_503_opted_in() -> None:
    transport = ScriptedTransport(OSError("connection refused"))
    verifier = RemoteVerifier(
        base_url=remote.ORIGIN,
        transport=transport,
        csrf=CsrfDisabled(reason="probe lane"),
        secure_cookies=False,
    )

    default, opted = both(verifier, remote_cookie())

    assert default == UNKNOWN_CREDENTIAL_401
    assert opted == service_unavailable(RETRY_AFTER)


# --- what is cached or latched ----------------------------------------------------------------


def test_mode_c_a_remembered_forged_cookie_stays_401_during_an_outage() -> None:
    """The negative cache holds one outcome - 200 null - and it answers before the server."""
    forged_cookie = f"{remote.TOKEN}.forged-signature"
    transport = ScriptedTransport(json_reply(None), OSError("connection refused"))
    verifier = remote.verifier(transport)
    assert wire(answers(verifier, remote_cookie(forged_cookie))) == UNKNOWN_CREDENTIAL_401
    assert verifier.remembered == 1

    default, opted = both(verifier, remote_cookie(forged_cookie))

    assert default == opted == UNKNOWN_CREDENTIAL_401
    assert transport.calls == 1


def test_mode_c_a_503_is_never_remembered_and_recovery_answers_at_once() -> None:
    transport = ScriptedTransport(
        OSError("connection refused"), json_reply(remote.document())
    )
    verifier = remote.verifier(transport)

    first = wire(answers(verifier, remote_cookie(), **OPT_IN))
    second = answers(verifier, remote_cookie(), **OPT_IN)

    assert first == service_unavailable(RETRY_AFTER)
    assert verifier.remembered == 0
    assert second.status_code == 200


def test_mode_c_the_429_latch_is_answered_by_each_bridge_s_own_setting() -> None:
    """The latch stores a deadline, not a refusal: every latched request builds a fresh one, and
    the bridge that receives it decides its form. Upstream's own Retry-After never leaks."""
    limited = json_reply({"message": "slow down"}, status=429)
    transport = ScriptedTransport(limited)
    verifier = remote.verifier(transport)

    first = wire(answers(verifier, remote_cookie(), **OPT_IN))
    latched_default, latched_opted = both(verifier, remote_cookie())

    assert first == service_unavailable(RETRY_AFTER)
    assert latched_default == UNKNOWN_CREDENTIAL_401
    assert latched_opted == service_unavailable(RETRY_AFTER)
    assert transport.calls == 1
