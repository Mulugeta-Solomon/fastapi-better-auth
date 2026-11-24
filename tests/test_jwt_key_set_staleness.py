"""How long a held key set is honoured, and who waits for its refresh - from `JwtVerifier`'s side.

`test_jwks_cache.py` pins the client's fetch policy directly; this file drives the same rules the
way a deployment meets them, through `JwtVerifier.verify` built by its public constructor, with the
scripted transport standing in for upstream and the key-set client's monotonic clock wound by hand
(`wind_jwks_clock`). PyJWT's own clock is the real one, so every token here is minted live and
only the key set ages.
"""

from __future__ import annotations

import pytest

from fastapi_better_auth import User
from fastapi_better_auth._internal.jwks import CACHE_TTL
from tests.jwks_fixtures import wind_jwks_clock
from tests.jwt_fixtures import SIGNER, build
from tests.tokens import claims


@pytest.mark.anyio
async def test_the_key_set_cache_ages_on_the_wound_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prove the instrument: the verifier's key set is refetched exactly when the wound clock
    says its TTL has passed, and not a moment before - so the tests below measure policy."""
    clock = wind_jwks_clock(monkeypatch)
    verifier, transport = build()
    token = SIGNER.sign(claims())

    await verifier.verify(token, User)
    clock.advance(CACHE_TTL - 1)
    await verifier.verify(token, User)
    assert transport.calls == 1

    clock.advance(2)
    await verifier.verify(token, User)
    assert transport.calls == 2
