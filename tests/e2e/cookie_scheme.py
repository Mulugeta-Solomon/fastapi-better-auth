"""The OpenAPI key the installed build publishes for an application's only cookie scheme.

The canary's published-wheel leg runs these modules against the last release, which derived that key
from the cookie's name even when there was only one cookie; later builds publish one stable key.
Which of the two to expect is read off the installed build's behaviour - the document a lone
cookie-labelled verifier produces - and never off a version string.
"""

from __future__ import annotations

from typing import Any

from fastapi_better_auth import BetterAuth
from tests.fakes import FakeVerifier, session_app

from .conftest import SESSION_COOKIE

STABLE = "BetterAuthCookie"
DERIVED = f"BetterAuthCookie-{SESSION_COOKIE}"
PROBE_SOURCE = "cookie:probe.session_token"


def cookie_scheme() -> str:
    """`STABLE` if this build publishes a lone cookie under it, else what the last release derived
    for `SESSION_COOKIE`. The probe's cookie is not `SESSION_COOKIE`, so only a key that ignores
    the cookie's name can come back as `STABLE`."""
    probe = BetterAuth(verifiers=[FakeVerifier("x-probe", source=PROBE_SOURCE)])
    document: dict[str, Any] = session_app(probe).openapi()
    published = set(document["components"]["securitySchemes"])
    return STABLE if published == {STABLE} else DERIVED
