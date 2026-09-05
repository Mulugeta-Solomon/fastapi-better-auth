"""D-094 walked for Mode B, and for the dispatcher refusal that needs both modes at once.

The bearer matrix is the mirror of the cookie one: every refusal `JwtVerifier` can produce, driven
through the resolver FastAPI awaits, with every frame of the resulting exception walked for the
raw token. `TestAmbiguousCredentials` is the one refusal neither verifier raises - the dispatcher
does, before either is asked to verify - so the only library frames on that traceback are
`_authenticate`'s own, holding the cookie credential and the bearer token side by side (D-180).

The instrument itself is proven in `test_refusal_frames_cookie.py`; both files walk the one in
`tests/refusal_frames.py`.
"""

from __future__ import annotations

import pytest

from fastapi_better_auth import AmbiguousCredentials
from tests.refusal_frames import (
    BEARER_ROWS,
    COOKIE_VALUE,
    TOKEN,
    ambiguous_row,
    bearer_row,
    holding,
    refused,
    refused_by,
    request,
)
from tests.tokens import GOLDEN_TOKEN


class TestBearerRefusals:
    @pytest.mark.anyio
    @pytest.mark.parametrize("label", BEARER_ROWS)
    async def test_no_frame_holds_the_token(self, label: str) -> None:
        verifier, token = bearer_row(label)
        connection = request(authorization=f"Bearer {token}")

        error = await refused(verifier, connection)

        assert holding(error, token, ignore=[connection]) == []


class TestAmbiguousCredentials:
    """A cookie and a bearer token on one request. `_authenticate` refuses the *shape* of the
    request, so nothing is verified and no per-mode scrub runs at all: the two credentials sit in
    `presented`, and the last one extracted sits in `credential`, in the frame that raises."""

    @pytest.mark.anyio
    async def test_two_credentials_are_the_dispatcher_s_own_refusal(self) -> None:
        verifiers, connection, _store = ambiguous_row()

        error = await refused_by(verifiers, connection)

        assert isinstance(error, AmbiguousCredentials)

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "needle", ["session token", "whole cookie value", "bearer token"], ids=str
    )
    async def test_no_frame_holds_either_credential(self, needle: str) -> None:
        """All three, because the frame carries all three: the cookie credential holds the token
        and the signature that makes it usable, and the bearer token is a credential in its own
        right that this refusal never gave any verifier the chance to scrub."""
        verifiers, connection, store = ambiguous_row()
        wanted = {
            "session token": TOKEN,
            "whole cookie value": COOKIE_VALUE,
            "bearer token": GOLDEN_TOKEN,
        }[needle]

        error = await refused_by(verifiers, connection)

        assert holding(error, wanted, ignore=[connection, store]) == []
