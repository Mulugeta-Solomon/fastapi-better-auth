"""D1: cookie-name resolution accepts exactly ONE name, never both (SA-D1, session fixation).

`resolve_cookie_value` used to accept the plain and the `__Secure-` name at once and prefer the
prefixed one, so a deployment on one name plus an attacker on a sibling subdomain who plants the
other name authenticated the victim as the attacker. `secure_cookies` narrows the accepted set to
the single name the server actually sets, which is what closes the cross-name fixation. The
residual same-name risk (a sibling can still set a `__Secure-` cookie; only `__Host-` stops that)
is the inherent non-`__Host-` cookie hazard, and two same-name cookies are the pre-existing
duplicate refusal - a bounded DoS, not a login as someone else.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from fastapi_better_auth import (
    ConfigurationError,
    CsrfDisabled,
    InvalidCredential,
    StoredSession,
    User,
)
from fastapi_better_auth._internal.cookie_verifier import CookieVerifier
from tests.cookies import COOKIE, SECRET, SECURE, FakeStore, http, run, sign, stored_user

VICTIM_TOKEN = "victim-session-token-value-000000"
ATTACKER_TOKEN = "attacker-session-token-value-0000"
VICTIM_UID = "victim-uid"
ATTACKER_UID = "attacker-uid"
FAR_FUTURE = datetime(2999, 1, 1, tzinfo=timezone.utc)


def _session_for(token: str, uid: str) -> StoredSession:
    return StoredSession(
        token=token,
        user_id=uid,
        expires_at=FAR_FUTURE,
        payload={"id": "sess", "userId": uid, "token": token},
        user=stored_user(id=uid, payload={"id": uid}),
    )


def two_user_store() -> FakeStore:
    """A store holding the victim's session AND the attacker's, each keyed by its own raw token."""
    return FakeStore(
        sessions={
            VICTIM_TOKEN: _session_for(VICTIM_TOKEN, VICTIM_UID),
            ATTACKER_TOKEN: _session_for(ATTACKER_TOKEN, ATTACKER_UID),
        }
    )


def cookie_verifier(*, secure_cookies: bool, secure_prefix: str = "__Secure-") -> CookieVerifier:
    return CookieVerifier(
        secret=SECRET,
        store=two_user_store(),
        csrf=CsrfDisabled(reason="fixation tests are about name resolution, not CSRF"),
        secure_cookies=secure_cookies,
        secure_prefix=secure_prefix,
    )


# ---------------------------------------------------------------- the fixation is closed


class TestCrossNameFixationIsClosed:
    @pytest.mark.anyio
    async def test_a_plain_deployment_ignores_a_planted_secure_cookie(self) -> None:
        """The lead's poc_wave2.py scenario: server on the plain name, attacker plants `__Secure-`.
        With secure_cookies=False the `__Secure-` cookie is not read at all - the victim's plain
        cookie resolves and the victim is authenticated as THEMSELVES, never as the attacker."""
        built = cookie_verifier(secure_cookies=False)
        header = f"{COOKIE}={sign(VICTIM_TOKEN)}; {SECURE}={sign(ATTACKER_TOKEN)}"

        session = await run(built, http(cookie=header), User)

        assert session is not None
        assert session.user.id == VICTIM_UID, "the planted __Secure- cookie was honoured"

    @pytest.mark.anyio
    async def test_a_plain_deployment_with_only_the_planted_secure_cookie_is_anonymous(
        self,
    ) -> None:
        """Attacker's `__Secure-` cookie alone, no victim cookie: absent, not a login as the
        attacker. The plain-name verifier never reads the prefixed name."""
        built = cookie_verifier(secure_cookies=False)
        header = f"{SECURE}={sign(ATTACKER_TOKEN)}"

        assert await run(built, http(cookie=header), User) is None

    @pytest.mark.anyio
    async def test_a_secure_deployment_ignores_a_planted_plain_cookie(self) -> None:
        """Production default: server on `__Secure-`, a sibling plants the plain name. With
        secure_cookies=True the plain cookie is not read - the victim's `__Secure-` resolves."""
        built = cookie_verifier(secure_cookies=True)
        header = f"{SECURE}={sign(VICTIM_TOKEN)}; {COOKIE}={sign(ATTACKER_TOKEN)}"

        session = await run(built, http(cookie=header), User)

        assert session is not None
        assert session.user.id == VICTIM_UID, "the planted plain cookie was honoured"

    @pytest.mark.anyio
    async def test_the_default_secure_deployment_ignores_a_plain_cookie_alone(self) -> None:
        """The default is secure_cookies=True, so a plain cookie by itself is absent, not a login."""
        built = CookieVerifier(
            secret=SECRET,
            store=two_user_store(),
            csrf=CsrfDisabled(reason="default construction, name resolution only"),
        )

        assert await run(built, http(cookie=f"{COOKIE}={sign(ATTACKER_TOKEN)}"), User) is None

    @pytest.mark.anyio
    async def test_two_same_name_cookies_are_the_existing_duplicate_refusal(self) -> None:
        """The residual same-name risk is the pre-existing duplicate refusal - a bounded DoS, not a
        login as someone else (the critic prefers this over a blanket reject-if-both)."""
        built = cookie_verifier(secure_cookies=True)
        header = f"{SECURE}={sign(VICTIM_TOKEN)}; {SECURE}={sign(ATTACKER_TOKEN)}"

        with pytest.raises(InvalidCredential) as caught:
            await run(built, http(cookie=header), User)

        assert "more than once" in caught.value.reason


# ---------------------------------------------------------------- configuration


class TestSecureCookiesConfiguration:
    def test_it_defaults_to_true_and_is_exposed_read_only(self) -> None:
        built = CookieVerifier(
            secret=SECRET,
            store=two_user_store(),
            csrf=CsrfDisabled(reason="exposed configuration test"),
        )

        assert built.secure_cookies is True
        with pytest.raises(AttributeError):
            built.secure_cookies = False  # type: ignore[misc]

    def test_false_is_exposed(self) -> None:
        assert cookie_verifier(secure_cookies=False).secure_cookies is False

    @pytest.mark.parametrize("value", [1, 0, "true", None, object()])
    def test_a_non_bool_secure_cookies_is_refused(self, value: Any) -> None:
        with pytest.raises(ConfigurationError):
            CookieVerifier(
                secret=SECRET,
                store=two_user_store(),
                csrf=CsrfDisabled(reason="a valid reason here"),
                secure_cookies=value,
            )

    @pytest.mark.anyio
    async def test_a_host_prefix_reads_only_the_host_cookie(self) -> None:
        """`__Host-` is the only prefix a sibling subdomain cannot plant; it stays configurable."""
        built = cookie_verifier(secure_cookies=True, secure_prefix="__Host-")
        host_name = "__Host-better-auth.session_token"

        session = await run(built, http(cookie=f"{host_name}={sign(VICTIM_TOKEN)}"), User)
        assert session is not None
        assert session.user.id == VICTIM_UID

        # The `__Secure-` name a sibling could set is now another cookie's, and read as absent.
        assert await run(built, http(cookie=f"{SECURE}={sign(ATTACKER_TOKEN)}"), User) is None
