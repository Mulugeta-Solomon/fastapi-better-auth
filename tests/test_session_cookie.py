"""`Session.cookie`: the one `(name, value)` pair the verifier accepted (#83).

A route that forwards the caller's session to Better Auth - `/revoke-session`, say - needs the
cookie exactly as the verifier took it. Re-reading it off the request is a second decision over
the same bytes, and Starlette's parser makes it differently: the last duplicate wins where the
verifier refuses, and a planted blank survives where the verifier drops it. So the verifier hands
over what it decided on, and nothing else.

The name is the base it read under, prefix included; the value is still percent-encoded and, when
the browser sent it in chunks, reassembled - byte for byte what Mode C already forwards. It is a
`SecretStr`, so every rendering masks it. No local in this file ever holds the plain value: the
constants are module globals, and a failure rendered with `--tb=long -l` shows only masks.
"""

from __future__ import annotations

import pickle
import urllib.parse
from typing import Any

import pytest
from fastapi import Depends, FastAPI
from fastapi.encoders import jsonable_encoder
from fastapi.testclient import TestClient
from pydantic import SecretStr

from fastapi_better_auth import (
    BetterAuth,
    CookieVerifier,
    CsrfDisabled,
    InvalidCredential,
    RemoteVerifier,
    Session,
    User,
)
from tests import remote_fixtures as remote
from tests.cookies import CAPTURED_TOKEN, FakeStore, run, sign, stored_session, verifier
from tests.jwt_fixtures import SIGNER, build
from tests.tokens import claims
from tests.transports import json_reply

PLAIN = "better-auth.session_token"
ENCODED = urllib.parse.quote(sign(CAPTURED_TOKEN), safe="")
"""The signed cookie as Better Auth sets it: `encodeURIComponent`, so `+ / =` are escaped."""
OTHER_TOKEN = "Qb8Xm2vTz6Lp1RkYd9Wn4Hs7Cj3Fg5Ae"
OTHER_ENCODED = urllib.parse.quote(sign(OTHER_TOKEN), safe="")
HALF = len(ENCODED) // 2
MASK = "**********"

ACCEPTED = SecretStr(ENCODED)
OTHER = SecretStr(OTHER_ENCODED)

POSTURES: tuple[tuple[str, dict[str, Any], str], ...] = (
    ("plain", {"secure_cookies": False}, PLAIN),
    ("secure default", {"secure_cookies": True}, f"__Secure-{PLAIN}"),
    ("host prefix", {"secure_cookies": True, "secure_prefix": "__Host-"}, f"__Host-{PLAIN}"),
    (
        "custom prefix and name",
        {"secure_cookies": True, "secure_prefix": "edge-", "cookie_name": "app.sid"},
        "edge-app.sid",
    ),
)
POSTURE_IDS = [label for label, _, _ in POSTURES]


def base_user() -> User:
    return User(id="u1")


def carrying(pair: tuple[str, SecretStr] | None = (PLAIN, ACCEPTED)) -> Session[User]:
    return Session[User](
        user=base_user(), expires_at=None, token=SecretStr(CAPTURED_TOKEN), cookie=pair, raw={}
    )


def mode_a(**settings: Any) -> CookieVerifier:
    store = FakeStore(sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN)})
    return verifier(store=store, **settings)


def mode_c(**settings: Any) -> RemoteVerifier:
    return remote.verifier(remote.RecordingTransport(json_reply(remote.document())), **settings)


async def accepted_by(built: CookieVerifier | RemoteVerifier, *cookies: str) -> Session[User]:
    """Drive one verifier over a request carrying exactly these raw `Cookie` header lines."""
    connection = remote.request(cookies=cookies)
    session: Session[User] | None
    if isinstance(built, CookieVerifier):
        session = await run(built, connection)
    else:
        session = await remote.run(built, connection)
    assert session is not None
    return session


def blank_beside_the_real_one(where: str) -> tuple[str, str]:
    """Two `Cookie` lines: a planted blank, and the real cookie, in the order asked for."""
    lines = (f"{PLAIN}=", f"{PLAIN}={ENCODED}")
    return lines if where == "before" else (lines[1], lines[0])


# ---------------------------------------------------------------- the model


class TestTheField:
    def test_a_session_built_without_one_reads_none(self) -> None:
        assert Session[User](user=base_user(), expires_at=None, raw={}).cookie is None

    def test_it_carries_the_pair_it_was_given(self) -> None:
        session = carrying()

        assert session.cookie == (PLAIN, ACCEPTED)
        assert session.cookie is not None and session.cookie[0] == PLAIN

    def test_the_repr_and_str_mask_the_value(self) -> None:
        session = carrying()

        for rendered in (repr(session), str(session)):
            assert ENCODED not in rendered
            assert CAPTURED_TOKEN not in rendered
            assert f"('{PLAIN}', SecretStr('{MASK}'))" in rendered

    def test_a_json_dump_masks_the_value(self) -> None:
        assert carrying().model_dump(mode="json")["cookie"] == [PLAIN, MASK]

    def test_a_json_string_masks_the_value(self) -> None:
        rendered = carrying().model_dump_json()

        assert ENCODED not in rendered
        assert f'"cookie":["{PLAIN}","{MASK}"]' in rendered

    def test_fastapis_encoder_masks_the_value(self) -> None:
        assert jsonable_encoder(carrying())["cookie"] == [PLAIN, MASK]

    def test_a_python_dump_hands_back_the_secret_itself(self) -> None:
        """Python mode keeps the `SecretStr`: reading the value is still a deliberate call."""
        session = carrying()

        dumped = session.model_dump()["cookie"]

        assert dumped == (PLAIN, ACCEPTED)
        assert isinstance(dumped[1], SecretStr)

    def test_a_route_that_returns_the_session_serves_only_the_mask(self) -> None:
        auth = BetterAuth(verifiers=[mode_a()])
        app = FastAPI()
        required = auth.current_session()

        async def echo(session: Session[User] = Depends(required)) -> Any:
            return session

        app.add_api_route("/echo", echo, methods=["GET"])
        with TestClient(app) as client:
            served = client.get("/echo", headers={"Cookie": f"{PLAIN}={ENCODED}"})

        assert served.status_code == 200
        assert served.json()["cookie"] == [PLAIN, MASK]
        assert ENCODED not in served.text

    def test_two_sessions_differing_only_in_the_value_are_not_equal(self) -> None:
        assert carrying() == carrying()
        assert carrying() != carrying((PLAIN, OTHER))
        assert carrying() != carrying(None)

    def test_a_session_is_still_unhashable_at_call_time(self) -> None:
        with pytest.raises(TypeError):
            hash(carrying())

    @pytest.mark.anyio
    async def test_a_verified_session_pickles_back_equal_carrying_the_value_as_documented(
        self,
    ) -> None:
        """`SecretStr` pickles its value, as `token` always has, and the docstring says so: the
        revived pair compares equal by value, so the value was in the stream.

        A verifier builds the unparametrized `Session`, which is what an application holds.
        """
        session = await accepted_by(mode_a(), f"{PLAIN}={ENCODED}")

        revived = pickle.loads(pickle.dumps(session))

        assert revived == session
        assert revived.cookie == (PLAIN, ACCEPTED)
        assert "cleartext" in (Session.__doc__ or "")


# ---------------------------------------------------------------- what each mode accepted


@pytest.fixture(params=["A", "C"])
def mode(request: pytest.FixtureRequest) -> str:
    kind = request.param
    assert isinstance(kind, str)
    return kind


def built_for(mode: str, **settings: Any) -> CookieVerifier | RemoteVerifier:
    return mode_a(**settings) if mode == "A" else mode_c(**settings)


class TestTheAcceptedPair:
    @pytest.mark.anyio
    @pytest.mark.parametrize(("label", "settings", "name"), POSTURES, ids=POSTURE_IDS)
    async def test_the_name_is_the_base_it_read_and_the_value_is_still_encoded(
        self, mode: str, label: str, settings: dict[str, Any], name: str
    ) -> None:
        built = built_for(mode, **settings)

        session = await accepted_by(built, f"{name}={ENCODED}")

        assert session.cookie == (name, ACCEPTED), label
        assert built.credential_source == f"cookie:{name}"

    @pytest.mark.anyio
    @pytest.mark.parametrize(("label", "settings", "name"), POSTURES, ids=POSTURE_IDS)
    async def test_a_chunked_cookie_is_reassembled_under_the_base_name(
        self, mode: str, label: str, settings: dict[str, Any], name: str
    ) -> None:
        built = built_for(mode, **settings)

        session = await accepted_by(built, f"{name}.1={ENCODED[HALF:]}; {name}.0={ENCODED[:HALF]}")

        assert session.cookie == (name, ACCEPTED), label

    @pytest.mark.anyio
    @pytest.mark.parametrize("where", ["before", "after"])
    async def test_a_planted_blank_beside_the_real_cookie_is_not_the_pair(
        self, mode: str, where: str
    ) -> None:
        """Starlette keeps a blank and lets the last one win; the verifier drops it (G37)."""
        session = await accepted_by(
            built_for(mode, secure_cookies=False), *blank_beside_the_real_one(where)
        )

        assert session.cookie == (PLAIN, ACCEPTED)

    @pytest.mark.anyio
    async def test_a_planted_duplicate_is_refused_rather_than_resolved(self, mode: str) -> None:
        """Starlette would pick the last of two; there is no pair to hand over, only a 401."""
        with pytest.raises(InvalidCredential) as caught:
            await accepted_by(
                built_for(mode, secure_cookies=False),
                f"{PLAIN}={ENCODED}; {PLAIN}={OTHER_ENCODED}",
            )

        assert "more than once" in caught.value.reason

    @pytest.mark.anyio
    async def test_a_whole_cookie_beside_a_chunk_is_refused(self, mode: str) -> None:
        with pytest.raises(InvalidCredential) as caught:
            await accepted_by(
                built_for(mode, secure_cookies=False), f"{PLAIN}={ENCODED}; {PLAIN}.0={ENCODED}"
            )

        assert "both whole and chunked" in caught.value.reason

    @pytest.mark.anyio
    async def test_mode_c_forwards_exactly_the_pair_it_hands_over(self) -> None:
        transport = remote.RecordingTransport(json_reply(remote.document()))
        built = remote.verifier(transport, secure_cookies=True, secure_prefix="__Host-")

        session = await accepted_by(
            built, f"__Host-{PLAIN}.0={ENCODED[:HALF]}; __Host-{PLAIN}.1={ENCODED[HALF:]}"
        )

        assert session.cookie is not None
        assert [sorted(sent or {}) for sent in transport.sent] == [["accept", "cookie"]]
        assert [SecretStr((sent or {})["cookie"]) for sent in transport.sent] == [
            SecretStr(f"{session.cookie[0]}={session.cookie[1].get_secret_value()}")
        ]


class TestModeB:
    @pytest.mark.anyio
    async def test_a_jwt_session_carries_no_cookie(self) -> None:
        guarded, _transport = build()

        session = await guarded.verify(SIGNER.sign(claims()), User)

        assert session.cookie is None


class TestRemoteVerifierNamesItsPrefix:
    @pytest.mark.parametrize("prefix", ["__Secure-", "__Host-", "edge-", ""])
    def test_the_prefix_it_was_built_with_is_public(self, prefix: str) -> None:
        """Mode A always published it; Mode C now does too, so the name is recoverable."""
        assert mode_c(secure_prefix=prefix).secure_prefix == prefix

    def test_the_default_is_the_secure_prefix(self) -> None:
        assert RemoteVerifier(
            base_url=remote.ORIGIN,
            csrf=CsrfDisabled(reason="construction only; no request is verified"),
            transport=remote.RecordingTransport(json_reply(None)),
        ).secure_prefix == ("__Secure-")
