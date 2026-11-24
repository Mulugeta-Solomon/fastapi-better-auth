"""`Session.origin`: the configured `allowed_origins` entry the CSRF check matched (#85).

A route forwarding the caller to Better Auth has to send an `Origin` Better Auth trusts, and the
only origin this side ever proved anything about is the one the CSRF check admitted. So that is
what a session carries - but as the *configured entry*, never the request's header (D-010). The
two are byte-identical today, because the match is byte-exact, which is exactly why equality
cannot tell them apart: provenance is asserted as object identity with the stored allowlist
entry, at every position of a multi-entry allowlist, and against a header that is an equal but
distinct string.

Only a built-in policy's own matcher records the entry, and only the check the verifier ran reads
it. Everything else is `None`: a safe method (no check runs), `CsrfDisabled` (it reads nothing),
a policy of your own - a subclass of a shipped one included - and Mode B. `CsrfPolicy.check` is
unchanged and still returns `None`.
"""

from __future__ import annotations

import urllib.parse
from typing import Any

import anyio
import anyio.lowlevel
import pytest
from fastapi import Depends, FastAPI
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    BetterAuth,
    ConfigurationError,
    CookieVerifier,
    CsrfDisabled,
    CsrfFacts,
    CsrfFailure,
    CsrfPolicy,
    OriginCheck,
    RemoteVerifier,
    Session,
    SharedSecret,
    SignedDoubleSubmit,
    StoredSession,
    StoredUser,
    User,
)
from fastapi_better_auth._internal import csrf as csrf_module
from fastapi_better_auth._internal.csrf import enforce_policy
from tests import remote_fixtures as remote
from tests.cookies import CAPTURED_TOKEN, FakeStore, run, sign, stored_session, verifier
from tests.cookies import SECRET as COOKIE_SECRET
from tests.fakes import client
from tests.jwt_fixtures import SIGNER, build
from tests.tokens import claims
from tests.transports import json_reply

ALLOWED = ("https://app.example.com", "https://admin.example.com", "http://localhost:5173")
EVIL = "https://evil.example.com"
PLAIN = "better-auth.session_token"
ENCODED = urllib.parse.quote(sign(CAPTURED_TOKEN), safe="")
TOKEN = CAPTURED_TOKEN
SECRET = SharedSecret("Wd3Rk9Xm2vTz6Lp1QYn4Hs7Cj5Fg8AeZ")
SAFE = ("GET", "HEAD", "OPTIONS")
UNSAFE = ("POST", "PUT", "PATCH", "DELETE")
POSITIONS = range(len(ALLOWED))


def presented(entry: str) -> str:
    """An `Origin` header equal to `entry` and not the same object - what a request carries."""
    copy = (entry + " ")[:-1]
    assert copy == entry and copy is not entry
    return copy


def origin_check() -> OriginCheck:
    return OriginCheck(allowed_origins=list(ALLOWED))


def double_submit() -> SignedDoubleSubmit:
    return SignedDoubleSubmit(secret=SECRET, allowed_origins=list(ALLOWED))


def admitted(policy: CsrfPolicy, facts: CsrfFacts) -> str | None:
    """`enforce_policy` over the suite's session token, which so stays out of every assertion:
    pytest renders a module constant it finds inside a failing expression."""
    return enforce_policy(policy, facts, TOKEN)


def checked(policy: CsrfPolicy, facts: CsrfFacts) -> None:
    """`policy.check` over the suite's session token, kept out of assertions the same way."""
    return policy.check(facts, TOKEN)


def facts_for(policy: CsrfPolicy, origin: str | None, method: str | None = "POST") -> CsrfFacts:
    header = policy.required_header
    value = policy.token_for(TOKEN) if isinstance(policy, SignedDoubleSubmit) else None
    return CsrfFacts(
        method=method, origin=origin, header_name=header, header_value=value if header else None
    )


BUILT_IN = (origin_check, double_submit)
BUILT_IN_IDS = ("OriginCheck", "SignedDoubleSubmit")


class Delegating:
    """A policy of your own that asks a shipped one: still yours, so it hands over nothing."""

    def __init__(self) -> None:
        self.inner = origin_check()

    @property
    def required_header(self) -> str | None:
        return None

    def check(self, facts: CsrfFacts, session_token: str) -> None:
        try:
            self.inner.check(facts, session_token)
        finally:
            session_token = ""


class Subclassed(OriginCheck):
    """A subclass of a shipped policy is a policy of your own, whatever it overrides."""


class Answering:
    """Answers instead of raising, which the sanctioned call refuses as a `ConfigurationError`."""

    required_header = None

    def check(self, facts: CsrfFacts, session_token: str) -> bool:
        del session_token
        return False


class Nesting:
    """A policy of your own that runs the sanctioned call on a shipped policy inside its own
    `check`, and notes the recorder it sees on either side of that inner call."""

    def __init__(self) -> None:
        self.inner = origin_check()
        self.around: tuple[list[str] | None, list[str] | None] | None = None

    @property
    def required_header(self) -> str | None:
        return None

    def check(self, facts: CsrfFacts, session_token: str) -> None:
        before = open_recorder()
        try:
            enforce_policy(self.inner, facts, session_token)
        finally:
            self.around = (before, open_recorder())
            session_token = ""


def open_recorder() -> list[str] | None:
    """What the matcher would record into right now: the recorder only `enforce_policy` opens."""
    return csrf_module._admitted.get()  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------- the matcher


class TestTheMatchedEntry:
    @pytest.mark.parametrize("make", BUILT_IN, ids=BUILT_IN_IDS)
    @pytest.mark.parametrize("position", POSITIONS)
    def test_it_is_the_configured_entry_object_and_not_the_header(
        self, make: Any, position: int
    ) -> None:
        policy: OriginCheck | SignedDoubleSubmit = make()
        header = presented(policy.allowed_origins[position])
        snapshot = facts_for(policy, header)

        matched = admitted(policy, snapshot)

        assert matched is policy.allowed_origins[position]
        assert matched is not snapshot.origin

    @pytest.mark.parametrize("make", BUILT_IN, ids=BUILT_IN_IDS)
    @pytest.mark.parametrize("position", POSITIONS)
    def test_a_websocket_handshake_is_checked_and_so_carries_it(
        self, make: Any, position: int
    ) -> None:
        policy: OriginCheck | SignedDoubleSubmit = make()
        snapshot = CsrfFacts(
            method=None,
            origin=presented(policy.allowed_origins[position]),
            header_name=policy.required_header,
            header_value=policy.token_for(TOKEN)
            if isinstance(policy, SignedDoubleSubmit)
            else None,
            websocket=True,
        )

        assert admitted(policy, snapshot) is policy.allowed_origins[position]

    @pytest.mark.parametrize("make", BUILT_IN, ids=BUILT_IN_IDS)
    @pytest.mark.parametrize("method", SAFE)
    def test_a_safe_method_runs_no_check_and_carries_none(self, make: Any, method: str) -> None:
        """Even with an allowed `Origin` on it: nothing was compared, so nothing was matched."""
        policy: OriginCheck | SignedDoubleSubmit = make()

        assert admitted(policy, facts_for(policy, presented(ALLOWED[0]), method)) is None

    @pytest.mark.parametrize("make", BUILT_IN, ids=BUILT_IN_IDS)
    @pytest.mark.parametrize("position", POSITIONS)
    def test_every_entry_is_still_compared_whichever_one_matched(
        self, make: Any, position: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Recording the match must not turn the constant-time pass into an early exit."""
        policy: OriginCheck | SignedDoubleSubmit = make()
        compared: list[bytes] = []
        real = csrf_module.hmac.compare_digest

        def counting(left: Any, right: Any) -> bool:
            if isinstance(right, bytes) and right.startswith((b"http://", b"https://")):
                compared.append(right)
            return real(left, right)

        monkeypatch.setattr(csrf_module.hmac, "compare_digest", counting)

        admitted(policy, facts_for(policy, presented(ALLOWED[position])))

        assert compared == [entry.encode() for entry in ALLOWED]

    @pytest.mark.parametrize("make", BUILT_IN, ids=BUILT_IN_IDS)
    @pytest.mark.parametrize("position", POSITIONS)
    def test_the_match_is_recorded_only_after_every_entry_was_compared(
        self, make: Any, position: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Recording at the match, inside the loop, is a branch on which entry matched. At every
        comparison the recorder must be open and still empty. A match at the last position
        cannot tell the two apart, so that leg passes either way."""
        policy: OriginCheck | SignedDoubleSubmit = make()
        seen_at_each_compare: list[int | None] = []
        real = csrf_module.hmac.compare_digest

        def watching(left: Any, right: Any) -> bool:
            if isinstance(right, bytes) and right.startswith((b"http://", b"https://")):
                recorder = open_recorder()
                seen_at_each_compare.append(None if recorder is None else len(recorder))
            return real(left, right)

        monkeypatch.setattr(csrf_module.hmac, "compare_digest", watching)

        matched = admitted(policy, facts_for(policy, presented(ALLOWED[position])))

        assert seen_at_each_compare == [0] * len(ALLOWED)
        assert matched is policy.allowed_origins[position]

    @pytest.mark.parametrize("make", BUILT_IN, ids=BUILT_IN_IDS)
    def test_check_itself_still_returns_none(self, make: Any) -> None:
        """The public contract is untouched: a returned answer is what `enforce_policy` refuses."""
        policy: OriginCheck | SignedDoubleSubmit = make()

        assert checked(policy, facts_for(policy, presented(ALLOWED[1]))) is None

    @pytest.mark.parametrize(
        "policy",
        [
            CsrfDisabled(reason="this row checks nothing at all"),
            Delegating(),
            Subclassed(allowed_origins=list(ALLOWED)),
        ],
        ids=["CsrfDisabled", "delegating", "subclassed"],
    )
    def test_any_other_policy_carries_none(self, policy: CsrfPolicy) -> None:
        assert admitted(policy, facts_for(policy, presented(ALLOWED[0]))) is None

    def test_a_refusal_records_nothing_for_the_next_check(self) -> None:
        policy = origin_check()

        with pytest.raises(CsrfFailure):
            admitted(policy, facts_for(policy, EVIL))

        assert admitted(policy, facts_for(policy, presented(ALLOWED[0]), "GET")) is None

    def test_a_check_called_directly_leaks_nothing_into_a_later_one(self) -> None:
        """Outside the sanctioned call there is nowhere to record to, so nothing lingers."""
        policy = origin_check()
        checked(policy, facts_for(policy, presented(ALLOWED[2])))

        assert admitted(Delegating(), facts_for(policy, presented(ALLOWED[0]))) is None
        assert admitted(policy, facts_for(policy, presented(ALLOWED[0]), "GET")) is None


class TestTheRecorderAlwaysCloses:
    """`enforce_policy` opens the recorder and closes it on every way out, so nothing a check
    recorded outlives the call - not after a match, a refusal, a policy that answered, or a call
    nested inside another policy's `check`."""

    @pytest.mark.parametrize(
        ("origin", "method"),
        [(ALLOWED[1], "POST"), (ALLOWED[1], "GET"), (EVIL, "GET")],
        ids=["a match", "a safe method", "a safe method from anywhere"],
    )
    def test_it_is_closed_after_the_call_returns(self, origin: str, method: str) -> None:
        policy = origin_check()

        admitted(policy, facts_for(policy, presented(origin), method))

        assert open_recorder() is None

    @pytest.mark.parametrize(
        ("policy", "origin", "refusal"),
        [
            (origin_check(), EVIL, CsrfFailure),
            (double_submit(), ALLOWED[0], CsrfFailure),
            (Answering(), ALLOWED[0], ConfigurationError),
        ],
        ids=["an unlisted origin", "a refusal after the match", "a policy that answered"],
    )
    def test_it_is_closed_after_the_call_raises(
        self, policy: CsrfPolicy, origin: str, refusal: type[Exception]
    ) -> None:
        snapshot = CsrfFacts(method="POST", origin=presented(origin))

        with pytest.raises(refusal):
            admitted(policy, snapshot)

        assert open_recorder() is None

    @pytest.mark.parametrize(
        ("origin", "refused"),
        [(ALLOWED[2], False), (EVIL, True)],
        ids=["inner matches", "inner refuses"],
    )
    def test_a_nested_call_hands_the_outer_recorder_back(self, origin: str, refused: bool) -> None:
        outer = Nesting()
        snapshot = CsrfFacts(method="POST", origin=presented(origin))

        if refused:
            with pytest.raises(CsrfFailure):
                admitted(outer, snapshot)
        else:
            assert admitted(outer, snapshot) is None

        assert outer.around is not None
        before, after = outer.around
        assert before is not None, "the instrument saw no recorder open inside the outer call"
        assert after is before
        assert before == []
        assert open_recorder() is None

    @pytest.mark.anyio
    @pytest.mark.parametrize(("origin", "refused"), [(ALLOWED[0], False), (EVIL, True)])
    async def test_it_is_closed_after_a_verifier_accepts_or_refuses(
        self, origin: str, refused: bool
    ) -> None:
        built = verifier(
            store=FakeStore(sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN)}),
            csrf=origin_check(),
            secure_cookies=False,
        )
        connection = remote.request("POST", cookies=(f"{PLAIN}={ENCODED}",), origin=origin)

        if refused:
            with pytest.raises(CsrfFailure):
                await run(built, connection)
        else:
            assert await run(built, connection) is not None

        assert open_recorder() is None


# ---------------------------------------------------------------- through the verifiers


def cookie_mode(policy: CsrfPolicy, mode: str) -> CookieVerifier | RemoteVerifier:
    if mode == "A":
        store = FakeStore(sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN)})
        return verifier(store=store, csrf=policy, secure_cookies=False)
    transport = remote.RecordingTransport(json_reply(remote.document()))
    return remote.verifier(transport, csrf=policy, secure_cookies=False)


def capturing_app(auth: BetterAuth) -> tuple[FastAPI, list[Session[User]]]:
    """One route per method the suite drives, each keeping the session it was handed."""
    seen: list[Session[User]] = []
    app = FastAPI()
    required = auth.current_session()

    async def handler(session: Session[User] = Depends(required)) -> dict[str, str]:
        seen.append(session)
        return {"id": session.user.id}

    app.add_api_route("/write", handler, methods=[*SAFE, *UNSAFE])
    return app, seen


def headers_for(policy: CsrfPolicy, origin: str) -> dict[str, str]:
    sent = {"Cookie": f"{PLAIN}={ENCODED}", "Origin": origin}
    if isinstance(policy, SignedDoubleSubmit):
        sent[policy.required_header] = policy.token_for(TOKEN)
    return sent


@pytest.fixture(params=["A", "C"])
def mode(request: pytest.FixtureRequest) -> str:
    kind = request.param
    assert isinstance(kind, str)
    return kind


class TestThroughTheVerifier:
    @pytest.mark.parametrize("make", BUILT_IN, ids=BUILT_IN_IDS)
    @pytest.mark.parametrize("position", POSITIONS)
    @pytest.mark.parametrize("method", UNSAFE)
    def test_an_unsafe_request_carries_the_configured_entry_it_matched(
        self, mode: str, make: Any, position: int, method: str, client_backend: str
    ) -> None:
        policy: OriginCheck | SignedDoubleSubmit = make()
        app, seen = capturing_app(BetterAuth(verifiers=[cookie_mode(policy, mode)]))

        with client(app, client_backend) as http:
            answer = http.request(method, "/write", headers=headers_for(policy, ALLOWED[position]))

        assert answer.status_code == 200, answer.text
        assert seen[0].origin is policy.allowed_origins[position]

    @pytest.mark.parametrize("make", BUILT_IN, ids=BUILT_IN_IDS)
    @pytest.mark.parametrize("method", SAFE)
    def test_a_safe_request_carries_none_even_with_an_allowed_origin(
        self, mode: str, make: Any, method: str, client_backend: str
    ) -> None:
        policy: OriginCheck | SignedDoubleSubmit = make()
        app, seen = capturing_app(BetterAuth(verifiers=[cookie_mode(policy, mode)]))

        with client(app, client_backend) as http:
            answer = http.request(method, "/write", headers=headers_for(policy, ALLOWED[0]))

        assert answer.status_code == 200, answer.text
        assert seen[0].origin is None

    def test_csrf_disabled_carries_none_on_an_unsafe_request(
        self, mode: str, client_backend: str
    ) -> None:
        policy = CsrfDisabled(reason="this row checks nothing at all")
        app, seen = capturing_app(BetterAuth(verifiers=[cookie_mode(policy, mode)]))

        with client(app, client_backend) as http:
            answer = http.post("/write", headers=headers_for(policy, ALLOWED[0]))

        assert answer.status_code == 200, answer.text
        assert seen[0].origin is None

    @pytest.mark.anyio
    async def test_a_websocket_handshake_carries_the_entry(self, mode: str) -> None:
        policy = origin_check()
        handshake = HTTPConnection(
            {
                "type": "websocket",
                "path": "/ws",
                "headers": [
                    (b"cookie", f"{PLAIN}={ENCODED}".encode()),
                    (b"origin", ALLOWED[1].encode()),
                ],
            }
        )
        built = cookie_mode(policy, mode)

        if isinstance(built, CookieVerifier):
            session = await run(built, handshake)
        else:
            session = await remote.run(built, handshake)

        assert session is not None
        assert session.origin is policy.allowed_origins[1]

    @pytest.mark.anyio
    async def test_a_jwt_session_carries_none(self) -> None:
        guarded, _transport = build()

        session = await guarded.verify(SIGNER.sign(claims()), User)

        assert session.origin is None


class Yielding:
    """A store that yields to the loop on every lookup, so concurrent requests interleave."""

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        await anyio.lowlevel.checkpoint()
        return stored_session(CAPTURED_TOKEN) if token == CAPTURED_TOKEN else None

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        return None


class TestConcurrency:
    @pytest.mark.anyio
    async def test_interleaved_requests_each_carry_their_own_entry(self) -> None:
        policy = origin_check()
        built = CookieVerifier(
            secret=COOKIE_SECRET, store=Yielding(), csrf=policy, secure_cookies=False
        )
        results: dict[int, str | None] = {}

        async def one(index: int) -> None:
            connection = remote.request(
                "POST", cookies=(f"{PLAIN}={ENCODED}",), origin=ALLOWED[index % len(ALLOWED)]
            )
            session = await run(built, connection)
            assert session is not None
            results[index] = session.origin

        async with anyio.create_task_group() as group:
            for index in range(30):
                group.start_soon(one, index)

        expected = [policy.allowed_origins[index % len(ALLOWED)] for index in range(30)]
        assert [results[index] for index in range(30)] == expected
        assert all(results[index] is expected[index] for index in range(30))
