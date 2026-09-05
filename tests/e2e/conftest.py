"""Fixtures for the conformance lane. Requires the harness: docker compose -f harness/docker-compose.yml up -d"""

import os
import pathlib
import secrets
import subprocess
import urllib.parse

import httpx
import pytest

HARNESS_URL = os.environ.get("HARNESS_URL", "http://localhost:3100")
REDIS_HARNESS_URL = os.environ.get("REDIS_HARNESS_URL", "http://localhost:3101")
STRICT_HARNESS_URL = os.environ.get("STRICT_HARNESS_URL", "http://localhost:3102")
THROTTLED_HARNESS_URL = os.environ.get("THROTTLED_HARNESS_URL", "http://localhost:3103")
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

COMPOSE_FILE = pathlib.Path(__file__).resolve().parents[2] / "harness" / "docker-compose.yml"

# The throttled service's /get-session rule, mirrored from RATE_LIMIT_GET_SESSION_MAX in
# harness/docker-compose.yml. Upstream keys the bucket on the last request it ALLOWED (a refused
# one leaves it untouched), so a window only clears after that many seconds without one.
THROTTLE_WINDOW_SECONDS = 10
THROTTLE_MAX = 3


def harness_sql(sql: str) -> None:
    """Run one statement against the harness database, or skip if docker cannot be reached.

    Session expiry and a database-direct ban cannot be manufactured through the API - upstream
    offers no endpoint that backdates `expiresAt`, and the admin ban route also deletes the
    user's sessions, which would make a ban leg pass for the wrong reason.
    """
    try:
        subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(COMPOSE_FILE),
                "exec",
                "-T",
                "postgres",
                "psql",
                "-U",
                "harness",
                "-d",
                "harness",
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                sql,
            ],
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        pytest.skip(f"cannot reach harness postgres via docker compose: {exc}")


def _reachable(url: str, *, label: str, profile: str | None = None) -> str:
    """Skip locally when a harness posture is down; fail in CI, where a silent skip is worse."""
    try:
        resp = httpx.get(f"{url}/healthz", timeout=5)
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001 - any failure means that posture is down
        start = "" if profile is None else f" (start it with --profile {profile})"
        message = f"{label} harness not reachable at {url}{start}: {exc}"
        if os.environ.get("CI"):
            pytest.fail(message)
        pytest.skip(message)
    return url


@pytest.fixture(scope="session")
def harness() -> str:
    """The default topology: sessions in Postgres, no profile needed."""
    return _reachable(HARNESS_URL, label="default")


@pytest.fixture(scope="session")
def redis_harness() -> str:
    """The secondary-storage topology: `docker compose --profile redis up -d --wait`."""
    return _reachable(REDIS_HARNESS_URL, label="redis-profile", profile="redis")


@pytest.fixture(scope="session")
def strict_harness() -> str:
    """The strict bearer posture: `docker compose --profile strict up -d --wait`.

    `bearer({ requireSignature: true })`, which is the one-line upstream fix this library's
    advisory probe names. Everything else about it is byte-identical to `:3100`.
    """
    return _reachable(STRICT_HARNESS_URL, label="strict-profile", profile="strict")


@pytest.fixture(scope="session")
def throttled_harness() -> str:
    """The rate-limited posture: `docker compose --profile throttled up -d --wait`.

    An explicit `rateLimit: { enabled: true, customRules: { "/get-session": { window: 10,
    max: 3 } } }`, so the 429 path is provable against a real server without `NODE_ENV=production`
    (which would also flip the cookie name to `__Secure-` over http).
    """
    return _reachable(THROTTLED_HARNESS_URL, label="throttled-profile", profile="throttled")


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
