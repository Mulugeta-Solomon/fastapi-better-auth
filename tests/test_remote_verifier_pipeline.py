"""The Mode C pipeline through rung 2, the fetch and the outcome, with the gates out of the way.

`verifier()` marks the readiness probe passed, so here the fetch happens unconditionally once the
local gates pass and `transport.calls` counts fetches alone. What this suite pins is the Q3 outcome
table over a scripted transport (ruling 4); the closed outbound header set and the pinned URI,
fuzzed so that no inbound header reaches the request (ruling 3); the two pre-filter rungs (ruling
5); the zero-outbound invariants that hold without a cache - a cross-site request reaches neither
the keyring nor upstream; and the ban states. The gates themselves are
`test_remote_verifier_gates.py`; the frame and reason channels `test_remote_verifier_hygiene.py`;
the builders `tests/remote_fixtures.py`.
"""

from __future__ import annotations

from typing import Any

import anyio
import pytest

from fastapi_better_auth import (
    AuthServiceUnavailable,
    ContentEncodingRejected,
    CsrfFailure,
    InvalidCredential,
    OriginCheck,
    ResponseTooLarge,
    SessionError,
    SessionExpired,
    SessionRevoked,
    SignedDoubleSubmit,
)
from fastapi_better_auth._internal import remote_verifier as rv
from fastapi_better_auth._internal.remote_verifier import RemoteVerifier
from fastapi_better_auth._internal.transport import TransportFailure
from tests.remote_fixtures import (
    APP,
    COOKIE_NAME,
    COOKIE_VALUE,
    EVIL,
    FAR_FUTURE,
    FAR_PAST,
    ORIGIN,
    OTHER_VALUE,
    SECRET,
    TOKEN,
    URI,
    USER_ID,
    RecordingTransport,
    document,
    raw_request,
    request,
    run,
    sign,
    verifier,
    with_cookie,
)
from tests.transports import Reply, json_reply

pytest.importorskip("hypothesis")
from hypothesis import given, settings
from hypothesis import strategies as st

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
