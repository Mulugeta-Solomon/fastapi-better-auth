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
from fastapi.testclient import TestClient
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    BetterAuth,
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

        matched = enforce_policy(policy, snapshot, TOKEN)

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

        assert enforce_policy(policy, snapshot, TOKEN) is policy.allowed_origins[position]

    @pytest.mark.parametrize("make", BUILT_IN, ids=BUILT_IN_IDS)
    @pytest.mark.parametrize("method", SAFE)
    def test_a_safe_method_runs_no_check_and_carries_none(self, make: Any, method: str) -> None:
        """Even with an allowed `Origin` on it: nothing was compared, so nothing was matched."""
        policy: OriginCheck | SignedDoubleSubmit = make()

        assert (
            enforce_policy(policy, facts_for(policy, presented(ALLOWED[0]), method), TOKEN) is None
        )

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

        enforce_policy(policy, facts_for(policy, presented(ALLOWED[position])), TOKEN)

        assert compared == [entry.encode() for entry in ALLOWED]

    @pytest.mark.parametrize("make", BUILT_IN, ids=BUILT_IN_IDS)
    def test_check_itself_still_returns_none(self, make: Any) -> None:
        """The public contract is untouched: a returned answer is what `enforce_policy` refuses."""
        policy: OriginCheck | SignedDoubleSubmit = make()

        assert policy.check(facts_for(policy, presented(ALLOWED[1])), TOKEN) is None

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
        assert enforce_policy(policy, facts_for(policy, presented(ALLOWED[0])), TOKEN) is None

    def test_a_refusal_records_nothing_for_the_next_check(self) -> None:
        policy = origin_check()

        with pytest.raises(CsrfFailure):
            enforce_policy(policy, facts_for(policy, EVIL), TOKEN)

        assert (
            enforce_policy(policy, facts_for(policy, presented(ALLOWED[0]), "GET"), TOKEN) is None
        )

    def test_a_check_called_directly_leaks_nothing_into_a_later_one(self) -> None:
        """Outside the sanctioned call there is nowhere to record to, so nothing lingers."""
        policy = origin_check()
        policy.check(facts_for(policy, presented(ALLOWED[2])), TOKEN)

        assert enforce_policy(Delegating(), facts_for(policy, presented(ALLOWED[0])), TOKEN) is None
        assert (
            enforce_policy(policy, facts_for(policy, presented(ALLOWED[0]), "GET"), TOKEN) is None
        )


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
        self, mode: str, make: Any, position: int, method: str
    ) -> None:
        policy: OriginCheck | SignedDoubleSubmit = make()
        app, seen = capturing_app(BetterAuth(verifiers=[cookie_mode(policy, mode)]))

        with TestClient(app) as client:
            answer = client.request(
                method, "/write", headers=headers_for(policy, ALLOWED[position])
            )

        assert answer.status_code == 200, answer.text
        assert seen[0].origin is policy.allowed_origins[position]

    @pytest.mark.parametrize("make", BUILT_IN, ids=BUILT_IN_IDS)
    @pytest.mark.parametrize("method", SAFE)
    def test_a_safe_request_carries_none_even_with_an_allowed_origin(
        self, mode: str, make: Any, method: str
    ) -> None:
        policy: OriginCheck | SignedDoubleSubmit = make()
        app, seen = capturing_app(BetterAuth(verifiers=[cookie_mode(policy, mode)]))

        with TestClient(app) as client:
            answer = client.request(method, "/write", headers=headers_for(policy, ALLOWED[0]))

        assert answer.status_code == 200, answer.text
        assert seen[0].origin is None

    def test_csrf_disabled_carries_none_on_an_unsafe_request(self, mode: str) -> None:
        policy = CsrfDisabled(reason="this row checks nothing at all")
        app, seen = capturing_app(BetterAuth(verifiers=[cookie_mode(policy, mode)]))

        with TestClient(app) as client:
            answer = client.post("/write", headers=headers_for(policy, ALLOWED[0]))

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
