"""D-094, walked rather than described: no refusal leaves the credential in a frame local.

An error reporter that captures frame locals - Sentry, `cgitb`, a debug middleware - serializes
every local of every frame on a traceback. A refusal path that still holds the raw session token
in one of those frames therefore ships the victim's live credential to whatever is listening,
and the CSRF paths do it on the exact attacker-induced cross-site request the control exists for.

The other suites assert this one frame at a time, from the inside. This one asserts it from the
outside and for every path at once: drive `BetterAuth._authenticate` - the dispatcher's own entry,
so the dispatcher's frames are on the traceback too - through every refusal both modes can
produce, then walk every frame of the resulting exception (and of everything it chains to) looking
for the credential.

Two objects are deliberately out of scope, and each row passes them to `holding(ignore=...)`:

* **The connection.** It *is* the credential's carrier, and Starlette, FastAPI and the ASGI server
  each hold it in frames above this library. Nothing this package does can scrub it, so counting
  it would make the assertion unfalsifiable rather than strict.
* **The store.** It is the operator's object; the fakes here hold the seeded record in memory by
  construction, which is a property of the test fixture and not of any code under test.

`TestTheWalker` proves the instrument before the matrix uses it: a planted unscrubbed frame is caught, a `SecretStr` is not a hit, and the same
value as a bare `str` is.
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
    CsrfFacts,
    CsrfFailure,
    OriginCheck,
    SessionError,
    SessionStore,
    SharedSecret,
    SignedDoubleSubmit,
    StoredSession,
    StoredUser,
    User,
)
from fastapi_better_auth._internal.jwt_verifier import JwtVerifier
from tests.fakes import resolver_of
from tests.tokens import (
    GOLDEN_KID,
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

MAX_DEPTH = 4
"""How far into a frame local the walk reaches. Four is one level past every container the
library builds (a credential inside a record inside a list inside a dict), so a value that
survives this walk is not merely hidden one indirection deeper."""

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


class Unparsable(User):
    """A model no stored payload here satisfies, so `parse_user` refuses at the last rung."""

    required_field: int


REFUSALS = (BetterAuthError, SessionError)


async def refused(
    verifier: Any, connection: HTTPConnection, *, model: type[User] = User
) -> BaseException:
    """Drive the dispatcher through its resolver - the callable FastAPI itself awaits.

    Going through `resolver_of` rather than reaching for `_authenticate` keeps the walk on the
    same frames a real request produces, dependency wrapper included.
    """
    auth = BetterAuth(verifiers=[verifier])
    resolve = resolver_of(auth.current_session(user_model=model))
    with pytest.raises(REFUSALS) as caught:
        await resolve(connection)
    return caught.value


# ---------------------------------------------------------------- the instrument itself


class TestTheWalker:
    def test_it_sees_a_frame_that_does_not_scrub(self) -> None:
        """The liveness probe: a frame that keeps the token is reported, by name."""

        def leaky(session_token: str) -> None:
            raise ValueError("refused")

        with pytest.raises(ValueError) as caught:
            leaky(TOKEN)

        assert holding(caught.value, TOKEN) == ["test_refusal_frames.py:leaky.session_token"]

    def test_a_secret_str_is_not_a_hit(self) -> None:
        def masked(session_token: SecretStr) -> None:
            raise ValueError("refused")

        with pytest.raises(ValueError) as caught:
            masked(SecretStr(TOKEN))

        assert holding(caught.value, TOKEN) == []

    def test_an_ignored_object_is_not_a_hit(self) -> None:
        carrier = [TOKEN]

        def carrying(held: list[str]) -> None:
            raise ValueError("refused")

        with pytest.raises(ValueError) as caught:
            carrying(carrier)

        assert holding(caught.value, TOKEN) != []
        assert holding(caught.value, TOKEN, ignore=[carrier]) == []

    def test_it_follows_a_chained_exception(self) -> None:
        def inner(session_token: str) -> None:
            raise ValueError("first")

        def outer() -> None:
            try:
                inner(TOKEN)
            except ValueError as exc:
                raise RuntimeError("second") from exc

        with pytest.raises(RuntimeError) as caught:
            outer()

        assert "test_refusal_frames.py:inner.session_token" in holding(caught.value, TOKEN)

    def test_it_reaches_a_credential_four_containers_deep(self) -> None:
        def buried(held: dict[str, list[tuple[str, ...]]]) -> None:
            raise ValueError("refused")

        with pytest.raises(ValueError) as caught:
            buried({"a": [(TOKEN,)]})

        assert holding(caught.value, TOKEN) == ["test_refusal_frames.py:buried.held"]


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

    verifier = CookieVerifier(secret=SECRET, store=store, csrf=policy)
    return verifier, connection, model, store


COOKIE_ROWS = (
    "malformed value",
    "duplicate cookie name",
    "bad signature",
    "origin cross-site",
    "origin absent",
    "double submit header absent",
    "double submit header forged",
    "store miss",
    "store raises",
    "expired",
    "banned",
    "parse_user failure",
)


class TestCookieRefusals:
    @pytest.mark.anyio
    @pytest.mark.parametrize("label", COOKIE_ROWS)
    async def test_no_frame_holds_the_session_token(self, label: str) -> None:
        verifier, connection, model, store = cookie_row(label)

        error = await refused(verifier, connection, model=model)

        assert holding(error, TOKEN, ignore=[connection, store]) == []

    @pytest.mark.anyio
    @pytest.mark.parametrize("label", COOKIE_ROWS)
    async def test_no_frame_holds_the_whole_cookie_value(self, label: str) -> None:
        """The signature is credential material too: it is what makes a stolen token usable."""
        verifier, connection, model, store = cookie_row(label)

        error = await refused(verifier, connection, model=model)

        assert holding(error, COOKIE_VALUE, ignore=[connection, store]) == []


# ---------------------------------------------------------------- bearer mode


def bearer_row(label: str) -> tuple[JwtVerifier, str]:
    """One bearer refusal: the verifier over a scripted key set, and the token to present."""
    if label == "malformed":
        return _jwt_verifier(json_reply(KEY_SET)), "two.segments"
    if label == "unknown kid, unreachable key set":
        return _jwt_verifier(RuntimeError("the key set host is gone")), _minted(kid=GOLDEN_KID)
    if label == "bad signature":
        return _jwt_verifier(json_reply(KEY_SET)), tampered(_minted())
    if label == "expired":
        return _jwt_verifier(json_reply(KEY_SET)), _minted(expired=True)
    raise AssertionError(f"unknown row {label!r}")  # pragma: no cover - as cookie_row


def _jwt_verifier(answer: Any) -> JwtVerifier:
    return JwtVerifier(base_url=ORIGIN, transport=ScriptedTransport(answer))


def _minted(*, kid: str | None = None, expired: bool = False) -> str:
    issued = datetime.now(timezone.utc) - (timedelta(hours=2) if expired else timedelta(minutes=1))
    payload = claims(issued_at=int(issued.timestamp()))
    headers = None if kid is None else {"kid": kid}
    return SIGNER.sign(payload, headers=headers)


BEARER_ROWS = ("malformed", "unknown kid, unreachable key set", "bad signature", "expired")


class TestBearerRefusals:
    @pytest.mark.anyio
    @pytest.mark.parametrize("label", BEARER_ROWS)
    async def test_no_frame_holds_the_token(self, label: str) -> None:
        verifier, token = bearer_row(label)
        connection = request(authorization=f"Bearer {token}")

        error = await refused(verifier, connection)

        assert holding(error, token, ignore=[connection]) == []


# ---------------------------------------------------------------- the third-party contract


class Careless:
    """A third-party policy that refuses while its own frame still holds the session token."""

    required_header = None

    def check(self, facts: CsrfFacts, session_token: str) -> None:
        raise CsrfFailure(reason="refused, and the token is still in this frame")


@pytest.mark.anyio
async def test_a_policy_that_does_not_scrub_is_visible_to_the_walker() -> None:
    """The library cannot scrub a frame it does not own, which is why `CsrfPolicy.check` says so.

    A third-party policy that raises while still holding `session_token` puts the victim's live
    token on the traceback from *its* frame. This is that hazard, demonstrated - and the reason
    the protocol docstring makes the `finally` an obligation rather than a suggestion. Everything
    the library owns on that same traceback is clean, which is what makes the remaining frame
    attributable.
    """
    store = Store(session=stored_session())
    verifier = CookieVerifier(secret=SECRET, store=store, csrf=Careless())
    connection = request("POST", cookies=[f"{COOKIE_NAME}={COOKIE_VALUE}"])

    error = await refused(verifier, connection)

    assert holding(error, TOKEN, ignore=[connection, store]) == [
        "test_refusal_frames.py:check.session_token"
    ]


def test_the_store_protocol_is_still_what_the_fakes_implement() -> None:
    """The fakes here stand in for a real store; if they drifted, every row above would be a lie."""
    assert isinstance(Store(), SessionStore)
