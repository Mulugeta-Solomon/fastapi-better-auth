"""D-094 walked rather than described, for Mode A: no cookie refusal leaves the credential behind.

A refusal path that still holds the raw session token in a frame local ships the victim's live
credential to whatever error reporter is listening, and the CSRF paths do it on the exact
attacker-induced cross-site request the control exists for. The other suites assert that one frame
at a time, from the inside; this one asserts it from the outside and for every cookie path at
once, through the resolver FastAPI itself awaits, so the dispatcher's own frames are on the
traceback too.

`TestTheWalker` proves the instrument before the matrix uses it: a planted unscrubbed frame is
caught, a chained exception is followed, a credential four containers deep is reached, and a
`SecretStr` is not a hit where the same value as a bare `str` is.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from fastapi_better_auth import CookieVerifier, CsrfFacts, CsrfFailure, SessionStore
from tests.refusal_frames import (
    COOKIE_NAME,
    COOKIE_ROWS,
    COOKIE_VALUE,
    MAX_DEPTH,
    SECRET,
    TOKEN,
    WEBSOCKET_ROWS,
    Store,
    cookie_row,
    holding,
    refused,
    request,
    stored_session,
)

FILE = "test_refusal_frames_cookie.py"


def _nested(value: str, depth: int) -> object:
    """`value` wrapped in `depth` containers - one list per level the walk has to descend."""
    held: object = value
    for _ in range(depth):
        held = [held]
    return held


# ---------------------------------------------------------------- the instrument itself


class TestTheWalker:
    def test_it_sees_a_frame_that_does_not_scrub(self) -> None:
        """The liveness probe: a frame that keeps the token is reported, by name."""

        def leaky(session_token: str) -> None:
            raise ValueError("refused")

        with pytest.raises(ValueError) as caught:
            leaky(TOKEN)

        assert holding(caught.value, TOKEN) == [f"{FILE}:leaky.session_token"]

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

        assert f"{FILE}:inner.session_token" in holding(caught.value, TOKEN)

    @pytest.mark.parametrize("depth", [1, 3, MAX_DEPTH], ids=str)
    def test_it_reaches_a_credential_as_deep_as_it_claims_to(self, depth: int) -> None:
        """`MAX_DEPTH` is a number in a module, which is worth nothing until a value planted at
        exactly that depth is found - the dispatcher nests one five containers down."""

        def buried(held: object) -> None:
            raise ValueError("refused")

        with pytest.raises(ValueError) as caught:
            buried(_nested(TOKEN, depth))

        assert holding(caught.value, TOKEN) == [f"{FILE}:buried.held"]

    def test_it_stops_at_the_depth_it_claims_and_not_one_further(self) -> None:
        """The cap, pinned from the other side: an unbounded walk would recurse a live
        application's whole object graph, and a walk that quietly reached further would make the
        depth this instrument advertises a fiction."""

        def buried(held: object) -> None:
            raise ValueError("refused")

        with pytest.raises(ValueError) as caught:
            buried(_nested(TOKEN, MAX_DEPTH + 1))

        assert holding(caught.value, TOKEN) == []


# ---------------------------------------------------------------- the matrix


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


# ---------------------------------------------------------------- the WebSocket handshake


class TestWebSocketHandshake:
    """A handshake carries no `method` at all, so `requires_check` is forced on by the scope type
    (`CsrfFacts.websocket`) rather than chosen by a method test. It is therefore the CSRF refusal
    a method-driven matrix cannot reach - and the frames it lands in are the ones that hold the
    victim's live session token, on a request a cross-site page opened."""

    @pytest.mark.anyio
    @pytest.mark.parametrize("label", WEBSOCKET_ROWS)
    async def test_the_handshake_is_refused_as_a_csrf_failure(self, label: str) -> None:
        """Asserted separately from frame-cleanliness: a row that stopped being a CSRF refusal
        would still walk clean, and would be pinning nothing."""
        verifier, connection, model, _store = cookie_row(label)

        error = await refused(verifier, connection, model=model)

        assert isinstance(error, CsrfFailure)

    @pytest.mark.parametrize("label", WEBSOCKET_ROWS)
    def test_the_scope_is_what_forces_the_check(self, label: str) -> None:
        """The instrument for the rows above: the snapshot has no method and checks anyway."""
        verifier, connection, _model, _store = cookie_row(label)
        captured = CsrfFacts.from_connection(connection, policy=verifier.csrf)

        assert captured.method is None
        assert captured.websocket is True
        assert captured.requires_check is True


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
    verifier = CookieVerifier(secret=SECRET, store=store, csrf=Careless(), secure_cookies=False)
    connection = request("POST", cookies=[f"{COOKIE_NAME}={COOKIE_VALUE}"])

    error = await refused(verifier, connection)

    assert holding(error, TOKEN, ignore=[connection, store]) == [f"{FILE}:check.session_token"]


def test_the_store_protocol_is_still_what_the_fakes_implement() -> None:
    """The fakes here stand in for a real store; if they drifted, every row above would be a lie."""
    assert isinstance(Store(), SessionStore)
