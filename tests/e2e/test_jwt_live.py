"""Mode B against the real thing: a token this repository did not mint, verified end to end.

The unit lane proves the rules; it proves them against tokens and key sets we made up. This
lane closes the only gap that leaves: a token issued by a running better-auth, fetched over
its own `/api/auth/token`, verified against the key set that server publishes — and carried
through a real FastAPI request, because a verifier that works in isolation and not behind
`Depends` has not worked.
"""

import httpx
import pytest

from fastapi_better_auth import BetterAuth, HttpxTransport, InvalidCredential, User
from fastapi_better_auth._internal.jwt_verifier import JwtVerifier
from tests.fakes import session_app

from .conftest import SESSION_COOKIE

pytestmark = pytest.mark.e2e

LIFETIME = 900


@pytest.fixture
def live_token(harness: str, signed_in: dict[str, str]) -> str:
    """The JWT upstream hands a signed-in session, straight from its own endpoint."""
    response = httpx.get(f"{harness}/api/auth/token", cookies={SESSION_COOKIE: signed_in["cookie"]})
    assert response.status_code == 200, response.text
    token: str = response.json()["token"]
    return token


@pytest.mark.anyio
async def test_a_live_token_verifies_against_the_live_key_set(
    harness: str, live_token: str
) -> None:
    async with HttpxTransport() as transport:
        verifier = JwtVerifier(base_url=harness, transport=transport)

        session = await verifier.verify(live_token, User)

    assert session.user.id
    assert session.token is None
    assert session.expires_at is not None
    assert session.expires_at.tzinfo is not None
    assert session.raw["iss"] == harness
    assert session.raw["aud"] == harness
    assert session.raw["exp"] - session.raw["iat"] == LIFETIME
    assert session.raw["sub"] == session.user.id


@pytest.mark.anyio
async def test_a_tampered_live_token_is_refused(harness: str, live_token: str) -> None:
    head, payload, signature = live_token.split(".")
    flipped = ("A" if signature[0] != "A" else "B") + signature[1:]

    async with HttpxTransport() as transport:
        verifier = JwtVerifier(base_url=harness, transport=transport)

        with pytest.raises(InvalidCredential):
            await verifier.verify(f"{head}.{payload}.{flipped}", User)


@pytest.mark.anyio
async def test_a_live_token_authenticates_a_real_route(harness: str, live_token: str) -> None:
    async with HttpxTransport() as transport:
        auth = BetterAuth(verifiers=[JwtVerifier(base_url=harness, transport=transport)])
        app = session_app(auth)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://bridge"
        ) as client:
            authorized = await client.get(
                "/required", headers={"Authorization": f"Bearer {live_token}"}
            )
            anonymous = await client.get("/required")
            forged = await client.get("/required", headers={"Authorization": "Bearer a.b.c"})

    assert authorized.status_code == 200
    assert authorized.json()["id"]
    assert anonymous.status_code == 401
    assert forged.status_code == 401
    assert anonymous.content == forged.content


@pytest.mark.anyio
async def test_from_env_builds_a_bridge_that_verifies_a_live_token(
    harness: str, live_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The three-line getting-started path, against a real server."""
    monkeypatch.setenv("BETTER_AUTH_URL", harness)
    auth = BetterAuth.from_env()
    verifier = auth.verifiers[0]
    assert isinstance(verifier, JwtVerifier)

    try:
        session = await verifier.verify(live_token, User)
    finally:
        transport = verifier.transport
        assert isinstance(transport, HttpxTransport)
        await transport.aclose()

    assert session.user.id
