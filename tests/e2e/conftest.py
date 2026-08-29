"""Fixtures for the conformance lane. Requires the harness: docker compose -f harness/docker-compose.yml up -d"""

import os
import secrets
import urllib.parse

import httpx
import pytest

HARNESS_URL = os.environ.get("HARNESS_URL", "http://localhost:3100")
REDIS_HARNESS_URL = os.environ.get("REDIS_HARNESS_URL", "http://localhost:3101")
HARNESS_SECRET = os.environ.get("HARNESS_SECRET", "harness-secret-do-not-use-in-production")
SEED_EMAIL = os.environ.get("SEED_EMAIL", "seed@example.com")
SEED_PASSWORD = os.environ.get("SEED_PASSWORD", "seed-password-123")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin-password-123")

POSTGRES_URL = os.environ.get(
    "HARNESS_POSTGRES_URL", "postgresql+asyncpg://harness:harness@localhost:55432/harness"
)
REDIS_URL = os.environ.get("HARNESS_REDIS_URL", "redis://localhost:56379/0")

SESSION_COOKIE = "better-auth.session_token"
PASSWORD = "conformance-password-123"


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
def redis_harness() -> str:
    """The secondary-storage topology: `docker compose --profile redis up -d --wait`."""
    try:
        resp = httpx.get(f"{REDIS_HARNESS_URL}/healthz", timeout=5)
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001 - any failure means that topology is down
        if os.environ.get("CI"):
            pytest.fail(f"redis-profile harness not reachable at {REDIS_HARNESS_URL}: {exc}")
        pytest.skip(f"redis-profile harness not reachable at {REDIS_HARNESS_URL}: {exc}")
    return REDIS_HARNESS_URL


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


# ---------------------------------------------------------------- driving the live server
#
# Better Auth refuses a state-changing POST with no `Origin` (`MISSING_OR_NULL_ORIGIN`), and
# `sign-out` additionally requires a JSON content type. Both are upstream's own CSRF posture;
# every helper below sends what a browser would.


def headers(base: str) -> dict[str, str]:
    return {"Origin": base}


def raw_token(cookie: str) -> str:
    """The token half of a signed session cookie - what a store is keyed by."""
    return urllib.parse.unquote(cookie).rpartition(".")[0]


def sign_in(base: str, email: str, password: str) -> str:
    resp = httpx.post(
        f"{base}/api/auth/sign-in/email",
        json={"email": email, "password": password},
        headers=headers(base),
    )
    assert resp.status_code == 200, resp.text
    cookie = resp.cookies.get(SESSION_COOKIE)
    assert cookie is not None, f"no {SESSION_COOKIE} cookie on sign-in"
    return cookie


def sign_up(base: str, label: str) -> tuple[str, str]:
    """A user nobody else's test shares. Returns its id and its email."""
    email = f"{label}-{secrets.token_hex(8)}@example.com"
    resp = httpx.post(
        f"{base}/api/auth/sign-up/email",
        json={"name": f"{label} user", "email": email, "password": PASSWORD},
        headers=headers(base),
    )
    assert resp.status_code == 200, resp.text
    identifier: str = resp.json()["user"]["id"]
    return identifier, email


def sign_out(base: str, cookie: str) -> None:
    resp = httpx.post(
        f"{base}/api/auth/sign-out",
        json={},
        cookies={SESSION_COOKIE: cookie},
        headers=headers(base),
    )
    assert resp.status_code == 200, resp.text


def admin_post(base: str, path: str, body: dict[str, str], cookie: str) -> httpx.Response:
    return httpx.post(
        f"{base}/api/auth/admin/{path}",
        json=body,
        cookies={SESSION_COOKIE: cookie},
        headers=headers(base),
    )
