"""Fixtures for the conformance lane. Requires the harness: docker compose -f harness/docker-compose.yml up -d"""

import os

import httpx
import pytest

HARNESS_URL = os.environ.get("HARNESS_URL", "http://localhost:3100")
HARNESS_SECRET = os.environ.get("HARNESS_SECRET", "harness-secret-do-not-use-in-production")
SEED_EMAIL = os.environ.get("SEED_EMAIL", "seed@example.com")
SEED_PASSWORD = os.environ.get("SEED_PASSWORD", "seed-password-123")

SESSION_COOKIE = "better-auth.session_token"


@pytest.fixture(scope="session")
def harness() -> str:
    try:
        resp = httpx.get(f"{HARNESS_URL}/healthz", timeout=5)
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001 - any failure means the harness is down
        if os.environ.get("CI"):
            pytest.fail(f"harness not reachable at {HARNESS_URL} in CI: {exc}")
        pytest.skip(f"harness not reachable at {HARNESS_URL}: {exc}")
    return HARNESS_URL


@pytest.fixture(scope="session")
def secret() -> bytes:
    return HARNESS_SECRET.encode()


@pytest.fixture(scope="session")
def signed_in(harness: str) -> dict[str, str]:
    """Sign in the seed user; return the raw session cookie value (still URL-encoded)."""
    resp = httpx.post(
        f"{harness}/api/auth/sign-in/email",
        json={"email": SEED_EMAIL, "password": SEED_PASSWORD},
    )
    assert resp.status_code == 200, resp.text
    raw = resp.cookies.get(SESSION_COOKIE)
    assert raw is not None, f"no {SESSION_COOKIE} cookie on sign-in"
    return {"cookie": raw}
