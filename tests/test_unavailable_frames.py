"""D-094 for the converted refusal: no frame the 503 carries holds a raw credential.

The 503 is a new object raised from the dispatcher's own frame, inside the `finally` that scrubs
the credential, and `from None`, so it links back to nothing the verifier raised. Walked with the
same instrument as every other refusal, through the resolver FastAPI itself awaits.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from exceptiongroup import ExceptionGroup

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuth,
    CookieVerifier,
    CsrfDisabled,
    Session,
    User,
)
from fastapi_better_auth._internal.unavailable import AuthServiceUnavailable503
from tests.fakes import resolver_of
from tests.refusal_frames import (
    COOKIE_NAME,
    COOKIE_VALUE,
    SECRET,
    SIGNER,
    TOKEN,
    Store,
    claims,
    holding,
    holding_reachable,
    jwt_verifier,
    request,
    stored_session,
)
from tests.unavailable_support import RaisingVerifier

OPT_IN: dict[str, Any] = {"unavailable_status": 503, "unavailable_retry_after": 7}


async def refused_with(verifier: Any, connection: Any, **settings: Any) -> BaseException:
    auth = BetterAuth(verifiers=[verifier], **settings)
    resolve = resolver_of(auth.current_session())
    with pytest.raises(AuthServiceUnavailable) as caught:
        await resolve(connection)
    return caught.value


@pytest.mark.anyio
@pytest.mark.parametrize("needle", [TOKEN, COOKIE_VALUE], ids=["token", "cookie-value"])
async def test_the_mode_a_503_holds_no_cookie_material(needle: str) -> None:
    store = Store(error=RuntimeError("the database is gone"))
    verifier = CookieVerifier(
        secret=SECRET,
        store=store,
        csrf=CsrfDisabled(reason="this row is not about cross-site request forgery"),
        secure_cookies=False,
    )
    connection = request(cookies=[f"{COOKIE_NAME}={COOKIE_VALUE}"])

    error = await refused_with(verifier, connection, **OPT_IN)

    assert isinstance(error, AuthServiceUnavailable503)
    assert holding(error, needle, ignore=[connection, store]) == []


@pytest.mark.anyio
async def test_the_mode_b_503_holds_no_token() -> None:
    token = SIGNER.sign(claims())
    connection = request(authorization=f"Bearer {token}")

    error = await refused_with(jwt_verifier(OSError("connection refused")), connection, **OPT_IN)

    assert isinstance(error, AuthServiceUnavailable503)
    assert holding(error, token, ignore=[connection]) == []


@pytest.mark.anyio
@pytest.mark.parametrize("in_task_group", [False, True], ids=["bare", "task-group"])
@pytest.mark.parametrize("settings", [{}, OPT_IN], ids=["default", "opt-in"])
async def test_a_replaced_refusal_holds_no_credential(
    in_task_group: bool, settings: dict[str, Any]
) -> None:
    """Both replacements: the 503 under the opt-in, and the 401 a default bridge rebuilds."""
    credential = "presented-credential-0123456789"

    def foreign() -> AuthServiceUnavailable503:
        return AuthServiceUnavailable503(reason="upstream down", retry_after=99)

    verifier = RaisingVerifier("x-cred", foreign, in_task_group=in_task_group)
    connection = request(x_cred=credential)

    error = await refused_with(verifier, connection, **settings)

    assert holding(error, credential, ignore=[connection]) == []
    assert error.__context__ is None
    assert error.__cause__ is None


@pytest.mark.anyio
@pytest.mark.parametrize("needle", [TOKEN, COOKIE_VALUE], ids=["token", "cookie-value"])
async def test_a_rule_s_converted_refusal_holds_no_cookie_material(needle: str) -> None:
    """Nothing beyond what every rule refusal already carries on `main`.

    The rule frames hold the verified session as a parameter, and its stored payload carries the
    token: true of `NotAuthorized` today, and not this change's to scrub. So the session is
    excluded, with this test's own locals; anything else holding the material, such as the
    replaced refusal riding along on `__context__`, would still be found.
    """
    verifier = CookieVerifier(
        secret=SECRET,
        store=Store(session=stored_session()),
        csrf=CsrfDisabled(reason="this row is not about cross-site request forgery"),
        secure_cookies=False,
    )
    connection = request(cookies=[f"{COOKIE_NAME}={COOKIE_VALUE}"])
    credential = verifier.extract(connection)
    assert credential is not None
    session = await verifier.verify(credential, User)
    auth = BetterAuth(verifiers=[verifier], **OPT_IN)

    def predicate(_session: Session[User]) -> bool:
        raise AuthServiceUnavailable(reason="the rule's own lookup could not complete")

    gate = auth.require(predicate, reason="calls the store")
    with pytest.raises(AuthServiceUnavailable503) as caught:
        await gate(session=session)

    ignored = [connection, credential, session, needle]
    assert holding(caught.value, needle, ignore=ignored) == []
    assert caught.value.__context__ is None


GROUPED_CREDENTIAL = "regrouped-credential-0123456789"


class Regrouping:
    """A third party's verifier: it catches its own refusal and raises it again inside a
    single-leaf group, so the leaf's traceback holds this `verify` frame, credential and all.
    It does not scrub: a third party's verifier is not the bridge's to scrub."""

    credential_source = "header:x-cred"

    def __init__(self, refusal: Callable[[], AuthServiceUnavailable]) -> None:
        self.refusal = refusal

    def extract(self, connection: Any) -> str | None:
        return connection.headers.get("x-cred")

    async def verify(self, credential: str, user_model: type[User]) -> Session[User]:
        try:
            raise self.refusal()
        except AuthServiceUnavailable as caught:
            raise ExceptionGroup("one leaf", [caught]) from None


def plain() -> AuthServiceUnavailable:
    return AuthServiceUnavailable(reason="upstream down")


def foreign() -> AuthServiceUnavailable:
    return AuthServiceUnavailable503(reason="upstream down", retry_after=99)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("refusal", "settings"),
    [(plain, OPT_IN), (foreign, {})],
    ids=["opt-in-replaces-the-leaf", "default-rebuilds-the-503-form"],
)
async def test_a_replaced_grouped_leaf_is_not_reachable_from_the_refusal(
    refusal: Callable[[], AuthServiceUnavailable], settings: dict[str, Any]
) -> None:
    """A replaced refusal must not reach the leaf it replaced, by any path: the leaf's traceback
    holds the third party's frame, and that frame holds the credential."""
    connection = request(x_cred=GROUPED_CREDENTIAL)

    error = await refused_with(Regrouping(refusal), connection, **settings)

    assert holding_reachable(error, GROUPED_CREDENTIAL, ignore=[connection]) == []


@pytest.mark.anyio
async def test_a_leaf_left_alone_is_raised_as_itself_with_the_verifier_s_own_frames() -> None:
    """Not claimed: a refusal the policy leaves alone is the leaf itself, as on `main`, and its
    traceback holds the custom verifier's frames. Those are the verifier's to scrub. The bridge's
    own frames hold nothing."""
    connection = request(x_cred=GROUPED_CREDENTIAL)

    error = await refused_with(Regrouping(plain), connection)

    holders = holding_reachable(error, GROUPED_CREDENTIAL, ignore=[connection])
    assert type(error) is AuthServiceUnavailable
    assert holders == ["test_unavailable_frames.py:verify.credential"]
