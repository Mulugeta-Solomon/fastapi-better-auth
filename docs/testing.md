# Testing

After reading this page you can run your FastAPI tests as a fake signed-in user, and test
session expiry without waiting for it.

## Override the session dependency

Override `auth.current_session()` — **called**, with the parentheses — and your tests run as
whatever session you hand back, with no cookie, no token, no store and no upstream:

```python
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, FastAPI

from fastapi_better_auth import (
    BetterAuth,
    CookieVerifier,
    OriginCheck,
    Session,
    SharedSecret,
    StoredSession,
    StoredUser,
    User,
)


class DictSessionStore:
    """The quickstart's in-memory SessionStore: no database, no network, no extra."""

    def __init__(self) -> None:
        self._sessions: dict[str, StoredSession] = {}
        self._users: dict[str, StoredUser] = {}

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        return self._sessions.get(token)

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        return self._users.get(user_id)


auth = BetterAuth(
    verifiers=[
        CookieVerifier(
            # A literal only so this page runs; in production read it from the environment.
            secret=SharedSecret("replace-this-with-your-own-32-plus-character-secret"),
            store=DictSessionStore(),
            csrf=OriginCheck(allowed_origins=["https://app.example.com"]),
        )
    ]
)
CurrentSession = Annotated[Session[User], Depends(auth.current_session())]

app = FastAPI()


@app.post("/profile")
async def update_profile(session: CurrentSession) -> User:
    return session.user


async def fake_session() -> Session[User]:
    """The session the suite runs as. Nothing is verified to produce it."""
    return Session(
        user=User(id="u1", email="tester@example.com"),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        raw={"id": "u1"},
    )


def with_fake_session(app: FastAPI, auth: BetterAuth) -> None:
    # Call this from a fixture, never at import: unoverridden routes must still refuse.
    app.dependency_overrides[auth.current_session()] = fake_session
```

The override does not care which verifier `auth` holds. This one is Mode A's over an in-memory
store, so the recipe runs on the bare install with no extra and no network; a Mode B
`JwtVerifier(base_url=...)` built without `transport=` needs the `[httpx]` extra *by design* — it
builds its HTTP client at construction, so a Mode B application missing it never starts instead of
failing its first request.

The parentheses are the whole of it. `current_session(user_model=...)` is memoized per user model,
so calling it again hands back the *same* callable your routes already depend on — which is what
makes it a usable override key. It is also the callable `require(...)` and
`require_membership(...)` compose on, so overriding it drives the authorization gates too: their
predicate and their `member` lookup run against your fake session, and only the authentication half
is bypassed. Two things are *not* reached by that one entry, because they are dependencies of
their own rather than wrappers an override travels through: a route declaring a different
`user_model`, and a route declaring `optional_session`. Add an entry per dependency your routes
actually hold — `auth.optional_session()` alongside `auth.current_session()`, and each with the
`user_model=` the routes use. Getting it wrong is not a hole: the missed route simply verifies for
real and answers `401`.

Drive it from a fixture, and clear the map afterwards — `dependency_overrides` lives on the
application, so an override left behind outlives the test that wanted it:

```text
import pytest
from fastapi.testclient import TestClient

from myapp.main import app, auth
from myapp.testing import with_fake_session


@pytest.fixture
def client():
    with_fake_session(app, auth)
    with TestClient(app) as http:
        yield http
    app.dependency_overrides.clear()
```

This is the bare-factory warning from [Mode B](mode-b-jwt.md#call-the-factory) seen from the
other side. There, forgetting the
parentheses in `Depends(auth.current_session)` is refused while the route is registered; here,
forgetting them writes a key nothing depends on, so the override silently does nothing and your
tests fail against real `401`s. Writing the *value* bare — `dependency_overrides[required] =
auth.current_session` — is the one planting this library cannot refuse at build time, because the
map is a plain dict it has no hook into; that one raises a `ConfigurationError` on the first request
touching the dependency, having verified nothing and served nobody.

**With an application factory** there is no module-level `auth` to import: the key is
`<the BetterAuth the factory built>.current_session(user_model=...)` — `app.state.auth` in
[the Mode A factory](mode-a-cookie.md#with-an-application-factory). The memoization is per `BetterAuth` instance, so
a key taken off any other instance — a leftover module-level one, or the one a second `create_app`
call built — overrides nothing, and the route verifies for real and answers `401`. An application
per test also leaves nothing behind to clear:

```text
@pytest.fixture
def client():
    app = create_app(test_settings)
    with_fake_session(app, app.state.auth)
    with TestClient(app) as http:
        yield http
```

## Moving the verifier's clock

`CookieVerifier` and `RemoteVerifier` refuse a session whose `expiresAt` has passed themselves; no
store this library ships filters on it. So when your auth service shortens a session — a
thirty-minute cap set in a `session.create.before` hook, say — this check is what enforces the cap,
and your suite can prove it without waiting thirty minutes. Pass `now=`, a callable returning an
aware `datetime`, and move it forward:

```python
import base64
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Annotated
from urllib.parse import quote

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastapi_better_auth import (
    BetterAuth,
    CookieVerifier,
    OriginCheck,
    Session,
    SharedSecret,
    StoredSession,
    StoredUser,
    User,
)

# Literals only so this page runs; in production read the secret from the environment.
SECRET = "replace-this-with-your-own-32-plus-character-secret"
TOKEN = "q7Rk2mVx9LpT4sWc8NbZ1hYd6GfJ3eAu"
APP_ORIGIN = "https://app.example.com"


class MovableClock:
    """The clock the verifier's expiry and ban checks read, moved by the test."""

    def __init__(self) -> None:
        self.ahead = timedelta()

    def __call__(self) -> datetime:
        return datetime.now(timezone.utc) + self.ahead


class DictSessionStore:
    def __init__(self) -> None:
        self.sessions: dict[str, StoredSession] = {}

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        return self.sessions.get(token)

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        return None


clock = MovableClock()
store = DictSessionStore()
auth = BetterAuth(
    verifiers=[
        CookieVerifier(
            secret=SharedSecret(SECRET),
            store=store,
            csrf=OriginCheck(allowed_origins=[APP_ORIGIN]),
            now=clock,
        )
    ]
)
CurrentSession = Annotated[Session[User], Depends(auth.current_session())]

app = FastAPI()


@app.post("/profile")
async def update_profile(session: CurrentSession) -> User:
    return session.user


def session_cookie(token: str) -> str:
    """The value Better Auth sets: the token, a dot and its HMAC-SHA256, URL-encoded."""
    digest = hmac.new(SECRET.encode(), token.encode(), hashlib.sha256).digest()
    return quote(f"{token}.{base64.b64encode(digest).decode()}", safe="")


def test_a_session_past_the_thirty_minute_cap_is_refused() -> None:
    store.sessions[TOKEN] = StoredSession(
        token=TOKEN,
        user_id="u1",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        payload={"id": "s1", "userId": "u1", "token": TOKEN},
        user=StoredUser(id="u1", payload={"id": "u1", "email": "tester@example.com"}),
    )
    headers = {
        "Cookie": f"__Secure-better-auth.session_token={session_cookie(TOKEN)}",
        "Origin": APP_ORIGIN,
    }
    with TestClient(app) as client:
        assert client.post("/profile", headers=headers).status_code == 200
        clock.ahead = timedelta(minutes=31)
        assert client.post("/profile", headers=headers).status_code == 401
```

**`now` can only make the verifier stricter.** Expiry is checked against whichever is later, the
real time or `now()`; a ban's lapse against whichever is earlier. Moving `now` forward expires
sessions sooner, and moving it back changes nothing. So a test clock left wired into production can
get exactly one thing wrong — expire sessions early — and can never admit a session the real clock
refuses, or cut a ban short. The same rule means `now` cannot show a ban lapsing: for that, store a
user whose `banExpires` is already in the past, and the real clock lapses it. A `now` that is not
callable is refused at construction. One that raises, or returns anything but an aware `datetime`,
fails closed: the request is the uniform `401`, and the exception is logged at ERROR with its
traceback.

`RemoteVerifier` takes the same `now=` and applies it to the `expiresAt` and `banExpires` that
get-session returns. Its `clock=` is a different thing: monotonic seconds for its caches and
back-off, which never decide a refusal.

**Mode B has no `now=`.** PyJWT checks `exp`, `nbf` and `iat` against its own reading of the clock,
inside `jwt.decode`, and takes no clock from its caller, so this library has none to hand it.
PyJWT reads that clock as `datetime.now(tz=timezone.utc)`, so a patch that replaces `datetime.now`
for the whole process does reach it. This was checked with time-machine 3.5.1 and PyJWT 2.13.0,
before the PyJWT floor moved to 2.15.0: `time_machine.travel()` to 901 seconds after a token was
issued made `JwtVerifier` refuse it as expired. PyJWT 2.15.1 reads the clock the same way. That
patch moves every clock in the process, in both directions, so keep it inside the test that needs
it.
