"""Mode C core: construct, extract, and the pipeline through rung 2, the fetch, and the outcome.

The cache, limiter, latch, probe and startup are WP15 and are deliberately absent - here the fetch
happens unconditionally once the local gates pass. What this suite pins is everything that is
reachable without them: the closed outbound header set and the pinned URI (ruling 3), the Q3
outcome table over a scripted transport (ruling 4), the two pre-filter rungs (ruling 5), the
zero-outbound invariants that hold without a cache (CSRF and rung refusals), the transport-failure
chaining that keeps a credential off `__cause__`, and the A+C collision at construction.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
from typing import Any

import anyio
import pytest
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuth,
    ConfigurationError,
    ContentEncodingRejected,
    CookieVerifier,
    CsrfDisabled,
    CsrfFailure,
    InvalidCredential,
    OriginCheck,
    ResponseTooLarge,
    SessionError,
    SessionExpired,
    SessionRevoked,
    SessionStore,
    SharedSecret,
    SignedDoubleSubmit,
    StoredSession,
    StoredUser,
    User,
)
from fastapi_better_auth._internal import remote_verifier as rv
from fastapi_better_auth._internal.remote_verifier import RemoteCredential, RemoteVerifier
from fastapi_better_auth._internal.transport import TransportFailure
from tests.refusal_frames import holding, refused
from tests.transports import Reply, ScriptedTransport, json_reply

pytest.importorskip("hypothesis")
from hypothesis import given, settings
from hypothesis import strategies as st

ORIGIN = "https://auth.example.com"
COOKIE_NAME = "better-auth.session_token"
SECURE_NAME = "__Secure-better-auth.session_token"
APP = "https://app.example.com"
EVIL = "https://evil.example.com"
URI = f"{ORIGIN}/api/auth/get-session?disableCookieCache=true&disableRefresh=true"

SECRET_VALUE = "Zq7Xm2vTz6Lp1RkYd9Wn4Hs7Cj3Fg5Ae"
OTHER_VALUE = "Nf4Wq7zC2mVt9Bs5Kx1Ld8Hj6Yr3Pg0Zx"
SECRET = SharedSecret(SECRET_VALUE)
TOKEN = "SBYZ1bzGdkhXcLuqsW70JjhvmIY4PU3B"
USER_ID = "u1"
FAR_FUTURE = "2999-01-01T00:00:00.000Z"
FAR_PAST = "2000-01-01T00:00:00.000Z"


def sign(token: str, secret_value: str = SECRET_VALUE) -> str:
    digest = hmac.new(secret_value.encode(), token.encode(), hashlib.sha256).digest()
    return f"{token}.{base64.b64encode(digest).decode()}"


COOKIE_VALUE = sign(TOKEN)


def document(
    *, token: str = TOKEN, user_id: str = USER_ID, expires: str = FAR_FUTURE, **user_over: Any
) -> dict[str, Any]:
    session = {
        "id": "sess",
        "token": token,
        "userId": user_id,
        "expiresAt": expires,
        "impersonatedBy": None,
    }
    user: dict[str, Any] = {
        "id": user_id,
        "email": "seed@example.com",
        "banned": False,
        "banExpires": None,
    }
    user.update(user_over)
    return {"session": session, "user": user}


class RecordingTransport(ScriptedTransport):
    """A `ScriptedTransport` that snapshots each request's outbound headers before they are scrubbed.

    The verifier clears the header dict in `finally` (D-094), and the base double appends the *live*
    dict, so `.headers[0]` reads empty after a call. `.sent` holds a copy taken at call time, which
    is what the closed-header-set assertions read.
    """

    def __init__(self, *answers: Any, gate: anyio.Event | None = None) -> None:
        super().__init__(*answers, gate=gate)
        self.sent: list[dict[str, str] | None] = []

    async def get(self, url: str, *, headers: Any = None, max_bytes: int) -> Any:
        self.sent.append(None if headers is None else dict(headers))
        return await super().get(url, headers=headers, max_bytes=max_bytes)


class NullStore:
    """The minimal `SessionStore` a `CookieVerifier` needs so the A+C collision can be built."""

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        return None

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        return None


def verifier(transport: ScriptedTransport, **kwargs: Any) -> RemoteVerifier:
    kwargs.setdefault("csrf", CsrfDisabled(reason="core pipeline tests do not exercise CSRF"))
    kwargs.setdefault("secure_cookies", False)
    built = RemoteVerifier(base_url=ORIGIN, transport=transport, **kwargs)
    # WP15 added the readiness probe at pipeline step 8. These pin the post-readiness pipeline -
    # the outcome table, the rungs, the closed header set, the frame scrubs - so the probe is
    # marked already-passed; the probe/prepare/_ready gate has its own suite in
    # test_remote_startup.py. A scripted double answers every request the same, so an unwarmed
    # probe would read the row's own document as a dead-jar and never reach the fetch.
    built._probed_ok = True  # pyright: ignore[reportPrivateUsage]
    return built


def request(
    method: str = "GET", *, cookies: tuple[str, ...] = (), **headers: str
) -> HTTPConnection:
    raw = [(b"cookie", value.encode()) for value in cookies]
    raw += [(key.replace("_", "-").encode(), value.encode()) for key, value in headers.items()]
    return HTTPConnection({"type": "http", "method": method, "path": "/x", "headers": raw})


def raw_request(cookies: tuple[str, ...], header_items: list[tuple[str, str]]) -> HTTPConnection:
    raw = [(b"cookie", value.encode()) for value in cookies]
    raw += [(name.encode("latin-1"), value.encode("latin-1")) for name, value in header_items]
    return HTTPConnection({"type": "http", "method": "GET", "path": "/x", "headers": raw})


async def run(v: RemoteVerifier, connection: HTTPConnection, model: type[User] = User) -> Any:
    credential = v.extract(connection)
    if credential is None:
        return None
    return await v.verify(credential, model)


def with_cookie(value: str = COOKIE_VALUE, name: str = COOKIE_NAME) -> HTTPConnection:
    return request(cookies=(f"{name}={value}",))


# ---------------------------------------------------------------- construction


class TestConstruction:
    def test_the_uri_is_built_once_with_both_query_params(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        assert v.uri == URI
        assert "disableCookieCache=true" in v.uri
        assert "disableRefresh=true" in v.uri

    def test_the_credential_source_matches_the_cookie_verifier(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        assert v.credential_source == f"cookie:{COOKIE_NAME}"

    def test_neither_secret_nor_secrets_is_legal(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        assert v.secrets == ()

    def test_a_base_path_of_root_puts_get_session_at_the_origin(self) -> None:
        v = RemoteVerifier(
            base_url=ORIGIN,
            csrf=CsrfDisabled(reason="root mount, no cross-site answer needed here"),
            transport=ScriptedTransport(json_reply(document())),
            base_path="",
        )
        assert v.uri == f"{ORIGIN}/get-session?disableCookieCache=true&disableRefresh=true"

    @pytest.mark.parametrize(
        ("kwargs", "needle"),
        [
            ({"base_url": "not a url"}, "base_url"),
            ({"csrf": None}, "CSRF"),
            ({"csrf": object()}, "CsrfPolicy"),
            ({"transport": object()}, "Transport"),
            ({"secret": SECRET, "secrets": [SECRET]}, "at most one"),
            ({"secrets": "a-bare-string"}, "sequence"),
            ({"secrets": []}, "empty"),
            ({"secret": "bare"}, "SharedSecret"),
            ({"cookie_name": "bad name"}, "cookie_name"),
            ({"cookie_name": ""}, "cookie_name"),
            ({"secure_prefix": 3}, "secure_prefix"),
            ({"secure_cookies": "yes"}, "secure_cookies"),
            ({"base_path": "api/auth"}, "base_path"),
            ({"base_path": "/api/auth/"}, "base_path"),
            ({"base_path": "/api/auth?x=1"}, "base_path"),
            ({"base_path": "/api/../secret"}, "base_path"),
            ({"base_path": 3}, "base_path"),
            ({"secure_prefix": "__Se;cure-"}, "secure_prefix"),
            ({"max_bytes": 0}, "max_bytes"),
            ({"max_bytes": True}, "max_bytes"),
            ({"concurrency": 0}, "concurrency"),
            ({"concurrency": 257}, "concurrency"),
            ({"concurrency": True}, "concurrency"),
            ({"concurrency": 1.5}, "concurrency"),
            ({"queue_timeout": 0.05}, "queue_timeout"),
            ({"queue_timeout": "soon"}, "queue_timeout"),
            ({"queue_timeout": float("inf")}, "queue_timeout"),
            ({"negative_ttl": -1.0}, "negative_ttl"),
            ({"negative_ttl": 301.0}, "negative_ttl"),
            ({"negative_ttl": "never"}, "negative_ttl"),
            ({"max_remembered": 0}, "max_remembered"),
            ({"max_remembered": 70000}, "remembered"),
            ({"max_remembered": True}, "max_remembered"),
            ({"clock": "not-callable"}, "clock"),
        ],
    )
    def test_a_bad_argument_is_refused_at_construction(
        self, kwargs: dict[str, Any], needle: str
    ) -> None:
        base: dict[str, Any] = {
            "base_url": ORIGIN,
            "csrf": CsrfDisabled(reason="validation-message tests, no request runs"),
            "transport": ScriptedTransport(json_reply(document())),
        }
        base.update(kwargs)
        with pytest.raises(ConfigurationError) as caught:
            RemoteVerifier(**base)
        assert needle in str(caught.value)


# ---------------------------------------------------------------- extract


class TestExtract:
    def test_no_cookie_is_absent(self) -> None:
        assert verifier(ScriptedTransport(json_reply(document()))).extract(request()) is None

    def test_a_blank_cookie_value_is_absent(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        assert v.extract(request(cookies=(f"{COOKIE_NAME}=   ",))) is None

    def test_a_present_cookie_is_a_credential(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        credential = v.extract(with_cookie())
        assert isinstance(credential, RemoteCredential)

    def test_the_credential_repr_redacts_its_pairs(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        credential = v.extract(with_cookie())
        assert credential is not None
        rendered = repr(credential)
        assert COOKIE_VALUE not in rendered
        assert "redacted" in rendered

    def test_only_the_configured_base_is_extracted(self) -> None:
        """secure_cookies=False reads the plain name; a `__Secure-` cookie beside it is not read."""
        v = verifier(ScriptedTransport(json_reply(document())))
        assert v.extract(request(cookies=(f"{SECURE_NAME}={COOKIE_VALUE}",))) is None

    def test_the_credential_is_immutable(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        credential = v.extract(with_cookie())
        assert credential is not None
        with pytest.raises(AttributeError):
            credential.pairs = ()


# ---------------------------------------------------------------- the outcome table (ruling 4)


OUTCOME_ROWS: tuple[tuple[str, Any, type[SessionError], str], ...] = (
    ("null-no-secret", Reply(b"null"), InvalidCredential, "no session"),
    (
        "not-the-shape",
        json_reply({"session": {}, "user": 3}),
        AuthServiceUnavailable,
        "cannot read",
    ),
    ("not-json", Reply(b"<html/>"), AuthServiceUnavailable, "not JSON"),
    (
        "non-json-content-type",
        Reply(b"{}", content_type="text/html"),
        AuthServiceUnavailable,
        "not JSON",
    ),
    (
        "token-mismatch",
        json_reply(document(token="another-token")),
        InvalidCredential,
        "different token",
    ),
    ("expired", json_reply(document(expires=FAR_PAST)), SessionExpired, "expired"),
    ("banned", json_reply(document(banned=True)), SessionRevoked, "banned"),
    ("401", Reply(b"", status=401), AuthServiceUnavailable, "401"),
    ("403", Reply(b"", status=403), AuthServiceUnavailable, "403"),
    ("404", Reply(b"", status=404), AuthServiceUnavailable, "base_path"),
    ("415", Reply(b"", status=415), AuthServiceUnavailable, "base_path"),
    ("429", Reply(b"", status=429), AuthServiceUnavailable, "429"),
    ("500", Reply(b"", status=500), AuthServiceUnavailable, "500"),
    ("redirect", Reply(b"", status=302), AuthServiceUnavailable, "redirect"),
    ("too-large", ResponseTooLarge(max_bytes=65536), AuthServiceUnavailable, "exceeded"),
    (
        "content-encoding",
        ContentEncodingRejected(encoding="gzip"),
        AuthServiceUnavailable,
        "content encoding",
    ),
    ("timeout", TimeoutError("slow"), AuthServiceUnavailable, "timed out"),
    (
        "transport-failure",
        TransportFailure(reason="refused"),
        AuthServiceUnavailable,
        "fetch failed",
    ),
    ("generic", RuntimeError("boom"), AuthServiceUnavailable, "fetch failed"),
)


class TestOutcomeTable:
    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("answer", "error_cls", "needle"),
        [(row[1], row[2], row[3]) for row in OUTCOME_ROWS],
        ids=[row[0] for row in OUTCOME_ROWS],
    )
    async def test_each_upstream_outcome_maps_to_its_pinned_refusal(
        self, answer: Any, error_cls: type[SessionError], needle: str
    ) -> None:
        transport = RecordingTransport(answer)
        v = verifier(transport)

        with pytest.raises(error_cls) as caught:
            await run(v, with_cookie())

        assert needle in caught.value.reason
        assert transport.calls == 1, "the fetch happens unconditionally once the local gates pass"

    @pytest.mark.anyio
    async def test_a_valid_document_verifies_to_a_session(self) -> None:
        transport = RecordingTransport(json_reply(document()))
        v = verifier(transport)

        session = await run(v, with_cookie())

        assert session is not None
        assert session.user.id == USER_ID
        assert session.token.get_secret_value() == TOKEN
        assert session.raw["impersonatedBy"] is None
        assert transport.calls == 1
        assert transport.posts == 0, "get-session is a GET; a POST here is a bug"

    @pytest.mark.anyio
    async def test_a_null_body_with_a_verified_signature_is_revoked_not_invalid(self) -> None:
        """Ruling 4: with a keyring configured and the cookie's signature verified, a null is a
        session that existed and is gone."""
        transport = RecordingTransport(Reply(b"null"))
        v = verifier(transport, secret=SECRET)

        with pytest.raises(SessionRevoked):
            await run(v, with_cookie())

        assert transport.calls == 1


# ---------------------------------------------------------------- the closed outbound set (ruling 3)


class TestClosedOutboundSet:
    @pytest.mark.anyio
    async def test_a_the_outbound_headers_are_exactly_cookie_and_accept(self) -> None:
        """Ruling 3(a): a valid cookie AND `Authorization: Bearer garbage` - the recorded outbound
        headers are exactly `{cookie, accept}`, the inbound Authorization/Host/Origin never forwarded."""
        transport = RecordingTransport(json_reply(document()))
        v = verifier(transport)
        connection = request(
            cookies=(f"{COOKIE_NAME}={COOKIE_VALUE}",),
            authorization="Bearer garbage-token",
            host="evil.example",
            origin=EVIL,
            referer="https://evil.example/x",
            user_agent="curl/8",
        )

        session = await run(v, connection)

        assert session is not None
        assert transport.sent[0] == {
            "cookie": f"{COOKIE_NAME}={COOKIE_VALUE}",
            "accept": "application/json",
        }
        assert transport.targets[0] == URI

    @settings(derandomize=True, max_examples=150)
    @given(
        st.lists(
            st.tuples(
                st.sampled_from(
                    [
                        "host",
                        "x-forwarded-for",
                        "x-forwarded-host",
                        "x-forwarded-proto",
                        "forwarded",
                        "origin",
                        "referer",
                        "user-agent",
                        "authorization",
                    ]
                )
                | st.text(alphabet="abcdefghijklmnopqrstuvwxyz-", min_size=1, max_size=20),
                st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789 .:/", max_size=40),
            ),
            max_size=8,
        )
    )
    def test_b_no_fuzzed_inbound_header_reaches_the_outbound_request(
        self, extra: list[tuple[str, str]]
    ) -> None:
        """Ruling 3(b): whatever the inbound header set, the outbound URI is byte-identical to
        `self._uri` and the header set is byte-identical to the closed set."""
        transport = RecordingTransport(json_reply(document()))
        v = verifier(transport)
        connection = raw_request((f"{COOKIE_NAME}={COOKIE_VALUE}",), extra)

        session = anyio.run(run, v, connection)

        assert session is not None
        assert transport.targets[0] == URI
        assert transport.sent[0] == {
            "cookie": f"{COOKIE_NAME}={COOKIE_VALUE}",
            "accept": "application/json",
        }


# ---------------------------------------------------------------- the two rungs (ruling 5)


class TestRungs:
    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("value", "needle"),
        [
            ("no-dot-here", "separator"),
            (".onlysig", "empty token"),
            ("tokenonly.", "empty signature"),
            ("x" * 9000 + ".sig", "over the cap"),
            ("%ff.sig", "percent-encoded"),
        ],
    )
    async def test_rung_one_refuses_structurally_with_no_outbound(
        self, value: str, needle: str
    ) -> None:
        transport = RecordingTransport(json_reply(document()))
        v = verifier(transport)

        with pytest.raises(InvalidCredential) as caught:
            await run(v, with_cookie(value))

        assert needle in caught.value.reason
        assert transport.calls == 0

    @pytest.mark.anyio
    async def test_rung_two_with_a_secret_refuses_a_forged_signature_with_no_outbound(self) -> None:
        transport = RecordingTransport(json_reply(document()))
        v = verifier(transport, secret=SECRET)
        forged = f"{TOKEN}.{sign('elsewhere', OTHER_VALUE).split('.', 1)[1]}"

        with pytest.raises(InvalidCredential):
            await run(v, with_cookie(forged))

        assert transport.calls == 0

    @pytest.mark.anyio
    async def test_a_forged_cookie_without_a_secret_costs_one_upstream_call(self) -> None:
        """The narrowed dependency: with no secret, a forged cookie is refused only upstream."""
        transport = RecordingTransport(Reply(b"null"))
        v = verifier(transport)
        forged = f"{TOKEN}.{sign('elsewhere', OTHER_VALUE).split('.', 1)[1]}"

        with pytest.raises(InvalidCredential):
            await run(v, with_cookie(forged))

        assert transport.calls == 1

    @pytest.mark.anyio
    async def test_a_token_over_the_rung_one_cap_is_refused(self) -> None:
        transport = RecordingTransport(json_reply(document()))
        v = verifier(transport)
        oversized = f"{'t' * 5000}.{sign(TOKEN).split('.', 1)[1]}"

        with pytest.raises(InvalidCredential) as caught:
            await run(v, with_cookie(oversized))

        assert "over the cap" in caught.value.reason
        assert transport.calls == 0


# ---------------------------------------------------------------- zero-outbound invariants (subset)


class TestZeroOutbound:
    @pytest.mark.anyio
    async def test_a_cross_site_request_reaches_neither_the_keyring_nor_upstream(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        compares: list[int] = []
        real = rv.verify_signature

        def spy(*args: Any, **kwargs: Any) -> None:
            compares.append(1)
            real(*args, **kwargs)

        monkeypatch.setattr(rv, "verify_signature", spy)
        transport = RecordingTransport(json_reply(document()))
        built = RemoteVerifier(
            base_url=ORIGIN,
            csrf=OriginCheck(allowed_origins=[APP]),
            transport=transport,
            secret=SECRET,
            secure_cookies=False,
        )
        connection = request(
            "POST",
            cookies=(f"{COOKIE_NAME}={COOKIE_VALUE}",),
            origin=EVIL,
            sec_fetch_site="cross-site",
        )

        with pytest.raises(CsrfFailure):
            await run(built, connection)

        assert compares == [], "a CSRF failure reached the keyring"
        assert transport.calls == 0, "a CSRF failure reached upstream"

    @pytest.mark.anyio
    async def test_a_valid_double_submit_lets_a_same_site_post_through(self) -> None:
        policy = SignedDoubleSubmit(secret=SECRET, allowed_origins=[APP])
        transport = RecordingTransport(json_reply(document()))
        built = RemoteVerifier(
            base_url=ORIGIN, csrf=policy, transport=transport, secure_cookies=False
        )
        built._probed_ok = True  # WP15: exercise the post-readiness pipeline (see `verifier`)  # pyright: ignore[reportPrivateUsage]
        header = policy.token_for(TOKEN)
        connection = request(
            "POST",
            cookies=(f"{COOKIE_NAME}={COOKIE_VALUE}",),
            origin=APP,
            x_csrf_token=header,
        )

        session = await run(built, connection)

        assert session is not None
        assert transport.calls == 1


# ---------------------------------------------------------------- transport-failure chaining


class TestChaining:
    class Leaky(Exception):
        """A transport error that holds the outbound cookie the way an httpx error's .request does."""

        def __init__(self, cookie: str) -> None:
            self.request_cookie = cookie
            super().__init__("connection refused")

    @pytest.mark.anyio
    async def test_a_transport_failure_chains_nothing_and_leaks_no_cookie(self) -> None:
        transport = ScriptedTransport(self.Leaky(COOKIE_VALUE))
        built = verifier(transport)
        connection = with_cookie()

        error = await refused(built, connection)

        assert isinstance(error, AuthServiceUnavailable)
        assert error.__cause__ is None, "the transport error rode out on __cause__"
        # `transport` is the fixture holding the scripted Leaky (with the cookie) by construction,
        # exactly as refusal_frames ignores the operator's store; the assertion is that the raised
        # error's own frames and chain carry nothing.
        assert holding(error, COOKIE_VALUE, ignore=[connection, transport]) == []
        assert holding(error, TOKEN, ignore=[connection, transport]) == []


# ---------------------------------------------------------------- frame hygiene, POST-fetch refusals


class TestRefusalFramesPostFetch:
    """A refusal raised AFTER the fetch (`expired`, `banned`) unwinds through `verify`, whose frame
    binds `record`/`response` - both carrying the forwarded token, since the upstream document names
    the session that WAS presented (D-210). The pre-fetch chaining test cannot see this: no document
    is ever built there. Each row asserts no frame of the raised error holds the token or the whole
    cookie value.
    """

    PAST = "2000-01-01T00:00:00.000Z"

    @pytest.mark.anyio
    async def test_an_expired_refusal_holds_no_credential(self) -> None:
        transport = ScriptedTransport(json_reply(document(expires=self.PAST)))
        built = verifier(transport)
        connection = with_cookie()

        error = await refused(built, connection)

        assert isinstance(error, SessionExpired)
        assert holding(error, TOKEN, ignore=[connection, transport]) == []
        assert holding(error, COOKIE_VALUE, ignore=[connection, transport]) == []

    @pytest.mark.anyio
    async def test_a_banned_refusal_holds_no_credential(self) -> None:
        transport = ScriptedTransport(json_reply(document(banned=True)))
        built = verifier(transport)
        connection = with_cookie()

        error = await refused(built, connection)

        assert isinstance(error, SessionRevoked)
        assert holding(error, TOKEN, ignore=[connection, transport]) == []
        assert holding(error, COOKIE_VALUE, ignore=[connection, transport]) == []

    @pytest.mark.anyio
    async def test_a_token_mismatch_refusal_holds_no_credential(self) -> None:
        transport = ScriptedTransport(json_reply(document(token="a-different-token-entirely")))
        built = verifier(transport)
        connection = with_cookie()

        error = await refused(built, connection)

        assert isinstance(error, InvalidCredential)
        assert holding(error, TOKEN, ignore=[connection, transport]) == []
        assert holding(error, COOKIE_VALUE, ignore=[connection, transport]) == []


# ---------------------------------------------------------------- composition (A + C collision)


class TestComposition:
    def test_cookie_and_remote_on_one_name_are_refused_at_construction(self) -> None:
        cookie_verifier = CookieVerifier(
            secret=SECRET,
            store=NullStore(),
            csrf=CsrfDisabled(reason="collision test, no request is verified"),
            secure_cookies=False,
        )
        remote = verifier(ScriptedTransport(json_reply(document())))

        with pytest.raises(ConfigurationError) as caught:
            BetterAuth(verifiers=[cookie_verifier, remote])

        assert "credential_source" in str(caught.value)

    def test_the_null_store_is_a_real_session_store(self) -> None:
        assert isinstance(NullStore(), SessionStore)


# ---------------------------------------------------------------- log/reason hygiene extension


class TestReasonHygiene:
    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "answer",
        [Reply(b"null"), json_reply({"session": {}, "user": 3}), json_reply(document(token="x"))],
        ids=["null", "unusable", "mismatch"],
    )
    async def test_no_refusal_reason_carries_the_cookie_or_token(self, answer: Any) -> None:
        v = verifier(RecordingTransport(answer))

        with pytest.raises((InvalidCredential, AuthServiceUnavailable, SessionRevoked)) as caught:
            await run(v, with_cookie())

        assert TOKEN not in caught.value.reason
        assert COOKIE_VALUE not in caught.value.reason


class NotCallableTransport:
    """Structurally a `Transport` (both names exist), but neither is callable."""

    get = "not-a-function"
    post = "not-a-function"


class TestConstructionEdges:
    def test_the_properties_read_back_what_was_configured(self) -> None:
        transport = ScriptedTransport(json_reply(document()))
        v = verifier(transport)

        assert v.origin == ORIGIN
        assert v.cookie_name == COOKIE_NAME
        assert v.secure_cookies is False
        assert isinstance(v.csrf, CsrfDisabled)
        assert v.transport is transport

    def test_a_default_transport_is_an_httpx_adapter(self) -> None:
        from fastapi_better_auth import HttpxTransport

        v = RemoteVerifier(
            base_url=ORIGIN, csrf=CsrfDisabled(reason="default-transport construction test")
        )

        assert isinstance(v.transport, HttpxTransport)

    def test_a_transport_with_non_callable_members_is_refused(self) -> None:
        with pytest.raises(ConfigurationError) as caught:
            RemoteVerifier(
                base_url=ORIGIN,
                csrf=CsrfDisabled(reason="non-callable transport construction test"),
                transport=NotCallableTransport(),  # type: ignore[arg-type]
            )

        assert "not callable" in str(caught.value)

    def test_a_secrets_keyring_is_accepted(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())), secrets=[SECRET])

        assert v.secrets == (SECRET,)

    def test_the_not_callable_transport_is_structurally_a_transport(self) -> None:
        from fastapi_better_auth import Transport

        assert isinstance(NotCallableTransport(), Transport)


class TestExtractCaps:
    def test_a_cookie_header_over_the_cap_is_absent(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        huge = f"{COOKIE_NAME}=" + "a" * 20000

        assert v.extract(request(cookies=(huge,))) is None

    def test_a_header_of_too_many_pairs_is_absent(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        crowd = "; ".join(f"a{index}=v" for index in range(600))

        assert v.extract(request(cookies=(crowd,))) is None


class TestVerifyGuards:
    @pytest.mark.anyio
    async def test_a_foreign_credential_is_refused(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))

        with pytest.raises(InvalidCredential) as caught:
            await v.verify(object(), User)

        assert "not this verifier's" in caught.value.reason

    @pytest.mark.anyio
    async def test_a_session_error_from_the_transport_is_re_raised_verbatim(self) -> None:
        """A transport is not meant to raise a SessionError, but if it does the fetch site must not
        mask it as a generic fetch failure - it is honoured as the answer it is."""
        transport = ScriptedTransport(SessionRevoked(reason="scripted passthrough marker"))
        v = verifier(transport)

        with pytest.raises(SessionRevoked) as caught:
            await run(v, with_cookie())

        assert caught.value.reason == "scripted passthrough marker"


class TestBans:
    @pytest.mark.anyio
    async def test_a_user_with_no_ban_state_is_let_through(self) -> None:
        """`banned` absent reads as None = unknown, treated as not banned (D-182): a deployment
        without the admin plugin has no ban column at all."""
        body = document()
        body["user"].pop("banned")
        body["user"].pop("banExpires")
        transport = RecordingTransport(json_reply(body))
        v = verifier(transport)

        session = await run(v, with_cookie())

        assert session is not None

    @pytest.mark.anyio
    async def test_a_lapsed_ban_is_let_through(self) -> None:
        transport = RecordingTransport(json_reply(document(banned=True, banExpires=FAR_PAST)))
        v = verifier(transport)

        session = await run(v, with_cookie())

        assert session is not None

    @pytest.mark.anyio
    async def test_a_ban_that_has_not_lapsed_is_refused(self) -> None:
        transport = RecordingTransport(json_reply(document(banned=True, banExpires=FAR_FUTURE)))
        v = verifier(transport)

        with pytest.raises(SessionRevoked):
            await run(v, with_cookie())


def test_the_module_holds_no_logger() -> None:
    """The latch warning lives in remote_backoff and the probe/advisory warnings in remote_probe;
    remote_verifier orchestrates them and emits no log line of its own, so it holds no logger."""
    assert not hasattr(rv, "logger")


# ---------------------------------------------------------------- WP15 zero-outbound gate spies


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def garbage() -> HTTPConnection:
    """A cookie that passes rung 1 (has a separator) but upstream will call `200 null`."""
    return with_cookie("garbage-token.garbage-signature-value")


class TestZeroOutboundGates:
    """The gates before the fetch make ZERO outbound calls, RED-first. `verifier()` marks the probe
    passed, so `transport.calls` counts fetches only - the probe's own calls are out of the way."""

    @pytest.mark.anyio
    async def test_a_negative_cache_hit_makes_zero_additional_outbound(self) -> None:
        transport = RecordingTransport(Reply(b"null"))
        v = verifier(transport)

        with pytest.raises(InvalidCredential):
            await run(v, garbage())
        assert transport.calls == 1, "the first forged cookie cost one upstream call"

        with pytest.raises(InvalidCredential):
            await run(v, garbage())
        assert transport.calls == 1, "the cache hit made zero additional outbound calls"
        assert v.remembered == 1

    @pytest.mark.anyio
    async def test_n_identical_garbage_cookies_make_exactly_one_outbound(self) -> None:
        transport = RecordingTransport(Reply(b"null"))
        v = verifier(transport)

        for _ in range(12):
            with pytest.raises(InvalidCredential):
                await run(v, garbage())

        assert transport.calls == 1, "twelve identical forged cookies cost one upstream call"

    @pytest.mark.anyio
    async def test_a_disabled_cache_costs_one_call_per_forged_cookie(self) -> None:
        transport = RecordingTransport(Reply(b"null"))
        v = verifier(transport, negative_ttl=0.0)

        for _ in range(3):
            with pytest.raises(InvalidCredential):
                await run(v, garbage())

        assert transport.calls == 3, "negative_ttl=0 disables the cache; each forgery costs a call"
        assert v.remembered == 0

    @pytest.mark.anyio
    async def test_a_latched_instance_makes_zero_outbound(self) -> None:
        clock = Clock()
        transport = RecordingTransport(Reply(b"", status=429))
        v = verifier(transport, clock=clock)

        with pytest.raises(AuthServiceUnavailable) as first:
            await run(v, with_cookie())
        assert "429" in first.value.reason
        assert transport.calls == 1

        with pytest.raises(AuthServiceUnavailable) as second:
            await run(v, with_cookie())
        assert transport.calls == 1, "a latched instance made zero outbound calls"
        assert "backing off" in second.value.reason

        clock.advance(30.0)
        with pytest.raises(AuthServiceUnavailable):
            await run(v, with_cookie())
        assert transport.calls == 2, "the latch cleared by time and the next request went out"

    @pytest.mark.anyio
    async def test_a_cold_csrf_failure_reaches_neither_probe_keyring_nor_cache(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The zero-outbound invariant on a COLD verifier: CSRF is before `_ready`, so the probe
        never runs; the keyring is never consulted and the cache is untouched."""
        compares: list[int] = []
        real = rv.verify_signature

        def spy(*args: Any, **kwargs: Any) -> None:
            compares.append(1)
            real(*args, **kwargs)

        monkeypatch.setattr(rv, "verify_signature", spy)
        transport = RecordingTransport(json_reply(document()))
        built = RemoteVerifier(
            base_url=ORIGIN,
            csrf=OriginCheck(allowed_origins=[APP]),
            transport=transport,
            secret=SECRET,
            secure_cookies=False,
        )
        assert built._probed_ok is False, "this verifier is cold - the probe has not run"  # pyright: ignore[reportPrivateUsage]
        connection = request(
            "POST",
            cookies=(f"{COOKIE_NAME}={COOKIE_VALUE}",),
            origin=EVIL,
            sec_fetch_site="cross-site",
        )

        with pytest.raises(CsrfFailure):
            await run(built, connection)

        assert transport.calls == 0, "a cold CSRF failure ran the probe or a fetch"
        assert compares == [], "a CSRF failure reached the keyring"
        assert built.remembered == 0, "a CSRF failure touched the cache"


class TestLimiter:
    """The outbound concurrency limiter, and its saturation reason (ruling 7)."""

    @pytest.mark.anyio
    async def test_saturation_and_transport_timeout_reasons_are_distinct(self) -> None:
        gate = anyio.Event()
        held = RecordingTransport(Reply(b"null"), gate=gate)
        saturating = verifier(held, concurrency=1, queue_timeout=0.1)
        saturation: list[AuthServiceUnavailable] = []

        async def hold_the_only_slot() -> None:
            with contextlib.suppress(InvalidCredential):
                await run(saturating, with_cookie())

        async with anyio.create_task_group() as tg:
            tg.start_soon(hold_the_only_slot)
            await anyio.sleep(0.02)
            with pytest.raises(AuthServiceUnavailable) as caught:
                await run(saturating, garbage())
            saturation.append(caught.value)
            gate.set()

        timed_out = verifier(RecordingTransport(TimeoutError("slow")))
        with pytest.raises(AuthServiceUnavailable) as caught:
            await run(timed_out, with_cookie())

        assert "saturated" in saturation[0].reason
        assert "timed out" in caught.value.reason
        assert saturation[0].reason != caught.value.reason

    @pytest.mark.anyio
    async def test_the_slot_is_released_so_later_requests_still_go_out(self) -> None:
        transport = RecordingTransport(json_reply(document()))
        v = verifier(transport, concurrency=1)

        assert (await run(v, with_cookie())) is not None
        assert (await run(v, with_cookie())) is not None
        assert transport.calls == 2, "the slot was released after the first exchange"

    def test_the_limiter_is_not_built_at_construction(self) -> None:
        """D-198: `anyio.CapacityLimiter(n)` must be built lazily inside the loop, not in
        `__init__`; only the count is stored at construction."""
        v = verifier(ScriptedTransport(Reply(b"null")))

        assert v._limiter_instance is None  # pyright: ignore[reportPrivateUsage]

    @pytest.mark.anyio
    async def test_the_limiter_is_built_on_first_fetch(self) -> None:
        transport = RecordingTransport(json_reply(document()))
        v = verifier(transport)
        assert v._limiter_instance is None  # pyright: ignore[reportPrivateUsage]

        await run(v, with_cookie())

        assert v._limiter_instance is not None  # pyright: ignore[reportPrivateUsage]


class TestRefusalFramesNewGates:
    """Frame hygiene for the WP15 refusal paths: a cache-remembered null, a latched refusal, a
    saturated limiter, and a probe/ready failure must each leave no frame holding the credential.
    """

    @pytest.mark.anyio
    async def test_a_cache_remembered_null_refusal_holds_no_credential(self) -> None:
        transport = ScriptedTransport(Reply(b"null"))
        built = verifier(transport)
        connection = with_cookie()

        error = await refused(built, connection)

        assert isinstance(error, InvalidCredential)
        assert holding(error, TOKEN, ignore=[connection, transport]) == []
        assert holding(error, COOKIE_VALUE, ignore=[connection, transport]) == []

    @pytest.mark.anyio
    async def test_a_latched_refusal_holds_no_credential(self) -> None:
        transport = ScriptedTransport(Reply(b"", status=429))
        built = verifier(transport)
        connection = with_cookie()

        await refused(built, connection)  # trips the latch
        error = await refused(built, connection)  # refused while latched, before any fetch

        assert isinstance(error, AuthServiceUnavailable)
        assert "backing off" in error.reason
        assert holding(error, TOKEN, ignore=[connection, transport]) == []
        assert holding(error, COOKIE_VALUE, ignore=[connection, transport]) == []

    @pytest.mark.anyio
    async def test_a_probe_contract_failure_holds_no_credential(self) -> None:
        # A cold verifier whose bare probe answers a non-null body refuses on _ready, and the
        # forwarded cookie is never bound in a surviving frame.
        transport = ScriptedTransport(Reply(b'{"not": "null"}'))
        built = RemoteVerifier(
            base_url=ORIGIN,
            csrf=CsrfDisabled(reason="frame test, no cross-site request"),
            transport=transport,
            secure_cookies=False,
        )
        connection = with_cookie()

        error = await refused(built, connection)

        assert isinstance(error, ConfigurationError)
        assert holding(error, TOKEN, ignore=[connection, transport]) == []
        assert holding(error, COOKIE_VALUE, ignore=[connection, transport]) == []
