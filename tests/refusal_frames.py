"""The instrument the refusal-frame suites share: a frame-locals walker and the rows it walks.

D-094 promises that an error reporter which captures frame locals - Sentry, `cgitb`, a debug
middleware - finds nothing on any refusal traceback this library produces. `holding` is how that
is checked from the outside: drive the dispatcher through the resolver FastAPI itself awaits, then
walk every frame of the resulting exception, and of everything it chains to, looking for the
credential.

Two objects are deliberately out of scope, and each row passes them to `holding(ignore=...)`:

* **The connection.** It *is* the credential's carrier, and Starlette, FastAPI and the ASGI server
  each hold it in frames above this library. Nothing this package does can scrub it, so counting
  it would make the assertion unfalsifiable rather than strict.
* **The store.** It is the operator's object; the fakes here hold the seeded record in memory by
  construction, which is a property of the test fixture and not of any code under test.

A plain module rather than a test file - the peer of `tests/tokens.py` and `tests/stores.py` - so
that the cookie matrix, the bearer matrix and the dispatcher rows all walk the same instrument.
`test_refusal_frames_cookie.py` proves it before using it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import inspect
from collections.abc import Collection, Iterator, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import pytest
from pydantic import SecretStr
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    BetterAuth,
    BetterAuthError,
    CookieVerifier,
    CsrfDisabled,
    OriginCheck,
    SessionError,
    SharedSecret,
    SignedDoubleSubmit,
    StoredSession,
    StoredUser,
    User,
)
from fastapi_better_auth._internal.jwt_verifier import JwtVerifier
from tests.fakes import resolver_of
from tests.tokens import (
    GOLDEN_JWKS,
    GOLDEN_KID,
    GOLDEN_TOKEN,
    ORIGIN,
    claims,
    ed25519_signer,
    key_set,
    tampered,
)
from tests.transports import ScriptedTransport, json_reply

SECRET_VALUE = "Zq7Xm2vTz6Lp1RkYd9Wn4Hs7Cj3Fg5Ae"
SECRET = SharedSecret(SECRET_VALUE)
TOKEN = "victim-session-token-0123456789abcdefXYZ"
COOKIE_NAME = "better-auth.session_token"
APP = "https://app.example.com"
EVIL = "https://evil.example.com"
USER_ID = "u1"

MAX_DEPTH = 6
"""How far into a frame local the walk reaches.

One level past the deepest container the library actually builds, which is the dispatcher's
`presented`: a list of `(verifier, credential)` pairs, whose `CookieCredential` holds a tuple of
`(name, value)` cookie pairs - list, tuple, credential, tuple, tuple, str, five deep. A walk that
stopped at four would report the bearer token in that frame and miss the cookie value beside it,
so the ambiguous row's cookie assertions would have been unfalsifiable."""

FAR_FUTURE = datetime.now(timezone.utc) + timedelta(days=7)
FAR_PAST = datetime(2000, 1, 1, tzinfo=timezone.utc)

SIGNER = ed25519_signer("frames-1")
KEY_SET = key_set(SIGNER)


def signed(token: str) -> str:
    digest = hmac.new(SECRET_VALUE.encode(), token.encode(), hashlib.sha256).digest()
    return f"{token}.{base64.b64encode(digest).decode()}"


COOKIE_VALUE = signed(TOKEN)


# ---------------------------------------------------------------- the walker


def _holds(value: object, needle: str, excluded: frozenset[int], depth: int = 0) -> bool:
    """Whether `value` carries `needle` as readable text, `MAX_DEPTH` containers deep.

    A `SecretStr` is not a hit: its `repr` and `str` are the mask, so a reporter that serializes
    it writes `**********`. That is the whole point of putting the verified token in one, and a
    walker that could not tell it from a raw `str` would refuse the fix as well as the bug.

    `excluded` is checked at every level, not only at the frame local: the store is reached
    through the verifier as readily as it is held directly, and an exclusion that only held at
    the top would be one the recursion walked around.
    """
    if depth > MAX_DEPTH or id(value) in excluded or isinstance(value, SecretStr):
        return False
    if isinstance(value, str):
        return needle in value
    if isinstance(value, (bytes, bytearray)):
        return needle.encode("utf-8", "replace") in value
    if isinstance(value, Mapping):
        mapping = cast("Mapping[object, object]", value)
        items: Sequence[object] = [*mapping.keys(), *mapping.values()]
        return any(_holds(item, needle, excluded, depth + 1) for item in items)
    if isinstance(value, (list, tuple, set, frozenset)):
        entries = cast("Collection[object]", value)
        return any(_holds(item, needle, excluded, depth + 1) for item in entries)
    if inspect.isclass(value) or inspect.ismodule(value):
        return False
    if hasattr(value, "__dict__"):
        return any(_holds(item, needle, excluded, depth + 1) for item in vars(value).values())
    slots = getattr(type(value), "__slots__", ())
    return any(_holds(getattr(value, name, None), needle, excluded, depth + 1) for name in slots)


def _frames(exc: BaseException) -> Iterator[tuple[str, str, str, object]]:
    """Every `(file, function, local name, value)` on this exception and everything it chains to."""
    seen: set[int] = set()
    pending: list[BaseException] = [exc]
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        traceback = current.__traceback__
        while traceback:
            frame = traceback.tb_frame
            name = frame.f_code.co_filename.replace("\\", "/").rsplit("/", 1)[-1]
            for key, value in list(frame.f_locals.items()):
                if key != "self":
                    yield name, frame.f_code.co_name, key, value
            traceback = traceback.tb_next
        pending.extend(
            found for found in (current.__cause__, current.__context__) if found is not None
        )


def holding(exc: BaseException, needle: str, *, ignore: Sequence[object] = ()) -> list[str]:
    """Every frame local that still carries `needle`, as `file:function.local`."""
    excluded = frozenset(id(item) for item in ignore)
    found = {
        f"{file}:{function}.{key}"
        for file, function, key, value in _frames(exc)
        if _holds(value, needle, excluded)
    }
    return sorted(found)


# ---------------------------------------------------------------- fixtures


class Store:
    """Answers one session and one user, or raises. The store contract, and nothing else."""

    def __init__(
        self, *, session: StoredSession | None = None, error: BaseException | None = None
    ) -> None:
        self.session = session
        self.error = error

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        if self.error is not None:
            raise self.error
        return self.session

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        return None


def stored_user(**overrides: Any) -> StoredUser:
    fields: dict[str, Any] = {
        "id": USER_ID,
        "payload": {"id": USER_ID, "email": "seed@example.com"},
    }
    fields.update(overrides)
    return StoredUser(**fields)


def stored_session(
    *, expires_at: datetime = FAR_FUTURE, user: StoredUser | None = None
) -> StoredSession:
    return StoredSession(
        token=TOKEN,
        user_id=USER_ID,
        expires_at=expires_at,
        payload={"id": "sess", "userId": USER_ID, "token": TOKEN},
        user=stored_user() if user is None else user,
    )


def request(method: str = "GET", *, cookies: Sequence[str] = (), **headers: str) -> HTTPConnection:
    raw = [(b"cookie", value.encode()) for value in cookies]
    raw += [(key.replace("_", "-").encode(), value.encode()) for key, value in headers.items()]
    return HTTPConnection({"type": "http", "method": method, "path": "/x", "headers": raw})


def ws_request(*, cookies: Sequence[str] = (), **headers: str) -> HTTPConnection:
    """A handshake scope: no `method` key at all, so `requires_check` is forced on by the type.

    The handshake is a GET the same-origin policy does not cover, so a cross-site page can open
    one and the browser attaches the cookie anyway. It is therefore the one refusal path where
    CSRF runs on a request no method test would have selected - and the CSRF frames are the ones
    that hold the victim's live session token (D-180).
    """
    raw = [(b"cookie", value.encode()) for value in cookies]
    raw += [(key.replace("_", "-").encode(), value.encode()) for key, value in headers.items()]
    return HTTPConnection({"type": "websocket", "path": "/ws", "headers": raw})


class Unparsable(User):
    """A model no stored payload here satisfies, so `parse_user` refuses at the last rung."""

    required_field: int


REFUSALS = (BetterAuthError, SessionError)


async def refused_by(
    verifiers: Sequence[Any], connection: HTTPConnection, *, model: type[User] = User
) -> BaseException:
    """Drive the dispatcher through its resolver - the callable FastAPI itself awaits.

    Going through `resolver_of` rather than reaching for `_authenticate` keeps the walk on the
    same frames a real request produces, dependency wrapper included.
    """
    auth = BetterAuth(verifiers=list(verifiers))
    resolve = resolver_of(auth.current_session(user_model=model))
    with pytest.raises(REFUSALS) as caught:
        await resolve(connection)
    return caught.value


async def refused(
    verifier: Any, connection: HTTPConnection, *, model: type[User] = User
) -> BaseException:
    """One verifier's refusal, walked exactly as a composed one is."""
    return await refused_by([verifier], connection, model=model)


# ---------------------------------------------------------------- cookie mode


def cookie_row(
    label: str,
) -> tuple[CookieVerifier, HTTPConnection, type[User], Store]:
    """One refusal, built end to end: the verifier, the request, the model and the store."""
    policy: Any = CsrfDisabled(reason="this row is not about cross-site request forgery")
    store = Store(session=stored_session())
    connection = request(cookies=[f"{COOKIE_NAME}={COOKIE_VALUE}"])
    model: type[User] = User

    if label == "malformed value":
        connection = request(cookies=[f"{COOKIE_NAME}={TOKEN}"])
    elif label == "duplicate cookie name":
        connection = request(
            cookies=[f"{COOKIE_NAME}={COOKIE_VALUE}", f"{COOKIE_NAME}={COOKIE_VALUE}"]
        )
    elif label == "bad signature":
        planted = f"{TOKEN}.{signed('another-token').split('.', 1)[1]}"
        connection = request(cookies=[f"{COOKIE_NAME}={planted}"])
    elif label == "origin cross-site":
        policy = OriginCheck(allowed_origins=[APP])
        connection = request("POST", cookies=[f"{COOKIE_NAME}={COOKIE_VALUE}"], origin=EVIL)
    elif label == "origin absent":
        policy = OriginCheck(allowed_origins=[APP])
        connection = request("POST", cookies=[f"{COOKIE_NAME}={COOKIE_VALUE}"])
    elif label == "websocket origin cross-site":
        policy = OriginCheck(allowed_origins=[APP])
        connection = ws_request(cookies=[f"{COOKIE_NAME}={COOKIE_VALUE}"], origin=EVIL)
    elif label == "websocket origin absent":
        policy = OriginCheck(allowed_origins=[APP])
        connection = ws_request(cookies=[f"{COOKIE_NAME}={COOKIE_VALUE}"])
    elif label == "double submit header absent":
        policy = SignedDoubleSubmit(secret=SECRET, allowed_origins=[APP])
        connection = request("POST", cookies=[f"{COOKIE_NAME}={COOKIE_VALUE}"], origin=APP)
    elif label == "double submit header forged":
        policy = SignedDoubleSubmit(secret=SECRET, allowed_origins=[APP])
        connection = request(
            "POST",
            cookies=[f"{COOKIE_NAME}={COOKIE_VALUE}"],
            origin=APP,
            x_csrf_token="forged",
        )
    elif label == "store miss":
        store = Store(session=None)
    elif label == "store raises":
        store = Store(error=RuntimeError("the database is gone"))
    elif label == "expired":
        store = Store(session=stored_session(expires_at=FAR_PAST))
    elif label == "banned":
        store = Store(session=stored_session(user=stored_user(banned=True)))
    elif label == "parse_user failure":
        model = Unparsable
    else:  # pragma: no cover - a typo in the matrix must not pass silently
        raise AssertionError(f"unknown row {label!r}")

    verifier = CookieVerifier(secret=SECRET, store=store, csrf=policy, secure_cookies=False)
    return verifier, connection, model, store


WEBSOCKET_ROWS = ("websocket origin cross-site", "websocket origin absent")

COOKIE_ROWS = (
    "malformed value",
    "duplicate cookie name",
    "bad signature",
    "origin cross-site",
    "origin absent",
    *WEBSOCKET_ROWS,
    "double submit header absent",
    "double submit header forged",
    "store miss",
    "store raises",
    "expired",
    "banned",
    "parse_user failure",
)


# ---------------------------------------------------------------- bearer mode


def bearer_row(label: str) -> tuple[JwtVerifier, str]:
    """One bearer refusal: the verifier over a scripted key set, and the token to present."""
    if label == "malformed":
        return jwt_verifier(json_reply(KEY_SET)), "two.segments"
    if label == "unknown kid, unreachable key set":
        return jwt_verifier(RuntimeError("the key set host is gone")), _minted(kid=GOLDEN_KID)
    if label == "bad signature":
        return jwt_verifier(json_reply(KEY_SET)), tampered(_minted())
    if label == "expired":
        return jwt_verifier(json_reply(KEY_SET)), _minted(expired=True)
    raise AssertionError(f"unknown row {label!r}")  # pragma: no cover - as cookie_row


def jwt_verifier(answer: Any) -> JwtVerifier:
    return JwtVerifier(base_url=ORIGIN, transport=ScriptedTransport(answer))


def _minted(*, kid: str | None = None, expired: bool = False) -> str:
    issued = datetime.now(timezone.utc) - (timedelta(hours=2) if expired else timedelta(minutes=1))
    payload = claims(issued_at=int(issued.timestamp()))
    headers = None if kid is None else {"kid": kid}
    return SIGNER.sign(payload, headers=headers)


BEARER_ROWS = ("malformed", "unknown kid, unreachable key set", "bad signature", "expired")


# ---------------------------------------------------------------- both modes at once


def ambiguous_row() -> tuple[list[Any], HTTPConnection, Store]:
    """One request carrying a valid cookie AND a bearer token: the dispatcher's own refusal.

    Neither verifier is ever asked to verify, so this is the one refusal whose only library
    frames are `_authenticate`'s - which holds the cookie credential and the bearer token in
    `presented`, and the last-extracted one in `credential`, at the moment it raises.
    """
    store = Store(session=stored_session())
    verifiers: list[Any] = [
        CookieVerifier(
            secret=SECRET,
            store=store,
            csrf=CsrfDisabled(reason="this row is not about cross-site request forgery"),
            secure_cookies=False,
        ),
        jwt_verifier(json_reply(GOLDEN_JWKS)),
    ]
    connection = request(
        cookies=[f"{COOKIE_NAME}={COOKIE_VALUE}"], authorization=f"Bearer {GOLDEN_TOKEN}"
    )
    return verifiers, connection, store
