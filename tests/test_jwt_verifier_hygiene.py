"""What a hostile token cannot do: exhaust the parser, or leave the credential anywhere.

SA-4 first: a header or a payload nested as deep as `MAX_TOKEN_BYTES` admits, which on some
interpreters is deeper than the JSON scanner survives. Two monkeypatched guards pin the containment
on every lane (a malformed token, no fetch, no ERROR record); the platform probes measure where the
overflow is really reachable and skip, with the measured depth, where it is not. Then the leak
channels the reason rules do not cover: every refusal shape driven through `leaks()`, the taxonomy
kept distinct, and the frame-locals channel where B1 reopened the early refusals. The refusals
themselves are `test_jwt_verifier_refusals.py`; the builders are `tests/jwt_fixtures.py`.
"""

from __future__ import annotations

import functools
import logging
import time
from typing import Any

import jwt
import pytest

from fastapi_better_auth import InvalidCredential, SessionError, User
from fastapi_better_auth._internal.jwt_verifier import MAX_TOKEN_BYTES
from tests.jwt_fixtures import OTHER, SIGNER, build, leaks, refused
from tests.tokens import (
    ABSENT,
    OTHER_ORIGIN,
    claims,
    deep_header_token,
    deep_payload_token,
    deepest_depth,
    defeats_the_json_parser,
    ed25519_signer,
    exhausted_parse,
    nested_arrays,
    payload_of,
    tampered,
)

# --- a token the JSON parser cannot survive -----------------------------------------------

DEEP_PAYLOAD_TOKEN = functools.partial(deep_payload_token, SIGNER)
DEEP_HEADER_DEPTH = deepest_depth(deep_header_token, MAX_TOKEN_BYTES)
DEEP_PAYLOAD_DEPTH = deepest_depth(DEEP_PAYLOAD_TOKEN, MAX_TOKEN_BYTES)
DEEP_HEADER = deep_header_token(DEEP_HEADER_DEPTH)
DEEP_PAYLOAD = DEEP_PAYLOAD_TOKEN(DEEP_PAYLOAD_DEPTH)
HEADER_OVERFLOWS = defeats_the_json_parser(nested_arrays(DEEP_HEADER_DEPTH))
PAYLOAD_OVERFLOWS = defeats_the_json_parser(nested_arrays(DEEP_PAYLOAD_DEPTH))


def out_of_reach(what: str, depth: int) -> str:
    """Why a probe test does not run on this interpreter, in the terms that decide it.

    It reads as "the cap admits nothing this scanner cannot survive", never as "untested":
    the containment is pinned by the two monkeypatched guards below, which run everywhere.
    """
    return (
        f"this interpreter's JSON scanner survives {depth} nested arrays, which is the "
        f"deepest {what} MAX_TOKEN_BYTES ({MAX_TOKEN_BYTES}) admits, so the overflow is "
        f"not reachable under the cap here"
    )


@pytest.mark.anyio
async def test_a_header_the_json_parser_gives_up_on_is_a_malformed_token(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """SA-4, by construction rather than by probe, so it is the same proof on every lane.

    `RecursionError` is a `RuntimeError`, so it sat outside this library's except tuple and
    escaped `verify` entirely - past the `token = ""` scrub, and out to the dispatcher, which
    contains it as the uniform 401 *and logs the whole traceback for it*. An unauthenticated
    request that costs an ERROR record is a log-amplification lever. The real deep-header
    probe below reaches this parser only where the size cap admits a body deeper than the
    interpreter's own ceiling, which is a platform fact; this does not depend on one.
    """
    token = SIGNER.sign(claims())

    with caplog.at_level(logging.ERROR), pytest.MonkeyPatch.context() as patch:
        patch.setattr(jwt, "get_unverified_header", exhausted_parse)
        error, transport = await refused(token)

    assert isinstance(error, InvalidCredential)
    assert transport.calls == 0
    assert leaks(error, token) == ()
    assert caplog.records == []


@pytest.mark.anyio
async def test_a_payload_the_json_parser_gives_up_on_is_a_malformed_token(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The decode half of the same escape, pinned the same way. The fetch count is part of
    the assertion: a key set really was loaded, so this is the payload parse giving up and
    not the header one answering early for it."""
    token = SIGNER.sign(claims())

    with caplog.at_level(logging.ERROR), pytest.MonkeyPatch.context() as patch:
        patch.setattr(jwt, "decode", exhausted_parse)
        error, transport = await refused(token)

    assert isinstance(error, InvalidCredential)
    assert transport.calls == 1
    assert leaks(error, token) == ()
    assert caplog.records == []


def test_the_nesting_probes_are_the_deepest_the_cap_admits() -> None:
    """Prove the instrument before the observation, on every interpreter.

    A probe built past `MAX_TOKEN_BYTES` is refused for its *length* before any parser sees
    it, so it would pass every test below while reaching nothing; a probe short of the cap
    understates what an unauthenticated client may send. One level deeper than each of these
    is over the cap, which is what makes them the deepest reachable and not merely small.
    """
    assert len(DEEP_HEADER) <= MAX_TOKEN_BYTES
    assert len(DEEP_PAYLOAD) <= MAX_TOKEN_BYTES
    assert len(deep_header_token(DEEP_HEADER_DEPTH + 1)) > MAX_TOKEN_BYTES
    assert len(DEEP_PAYLOAD_TOKEN(DEEP_PAYLOAD_DEPTH + 1)) > MAX_TOKEN_BYTES


@pytest.mark.skipif(not HEADER_OVERFLOWS, reason=out_of_reach("header", DEEP_HEADER_DEPTH))
def test_the_header_nesting_probe_really_defeats_this_interpreters_json_parser() -> None:
    """Platform evidence: here the cap admits a header this scanner cannot finish reading.

    Whether it does is an interpreter property and not a library one - the ceiling is
    `sys.getrecursionlimit()` up to 3.11, a compile-time constant on 3.12/3.13 (3 000 on
    Windows, 10 000 elsewhere) and stack headroom on 3.14+ - so where it is out of reach
    this skips with the measured depth rather than asserting a fact that is not true there.
    """
    with pytest.raises(RecursionError):
        jwt.get_unverified_header(DEEP_HEADER)


@pytest.mark.skipif(not PAYLOAD_OVERFLOWS, reason=out_of_reach("payload", DEEP_PAYLOAD_DEPTH))
def test_the_payload_nesting_probe_really_defeats_this_interpreters_json_parser() -> None:
    with pytest.raises(RecursionError):
        payload_of(DEEP_PAYLOAD)


@pytest.mark.anyio
async def test_a_header_nested_as_deep_as_the_cap_allows_is_refused_without_a_fetch() -> None:
    """The deepest header an unauthenticated client can send, end to end.

    Where the probe overflows this interpreter, this is SA-4's escape route walked for real;
    where it does not, the scanner returns a list and PyJWT refuses it as "not a json object".
    Both are the same verdict, and asserting the verdict is what makes this true everywhere -
    the `RecursionError` half specifically is owned by the guard above.
    """
    error, transport = await refused(DEEP_HEADER)

    assert isinstance(error, InvalidCredential)
    assert transport.calls == 0
    assert leaks(error, DEEP_HEADER) == ()


@pytest.mark.anyio
async def test_a_payload_nested_as_deep_as_the_cap_allows_is_refused() -> None:
    """The decode half. A payload is parsed only after the signature has verified, so this
    probe is signed by a key the key set really publishes: defence in depth rather than an
    open door, and the identical escape if upstream ever mints one."""
    error, _transport = await refused(DEEP_PAYLOAD)

    assert isinstance(error, InvalidCredential)
    assert leaks(error, DEEP_PAYLOAD) == ()


# --- what a reason may carry --------------------------------------------------------------


@pytest.mark.anyio
async def test_no_refusal_carries_any_part_of_the_credential() -> None:
    """Error reporters serialize exception attributes; a token in a reason is a token in a
    third-party store, replayable for as long as it lives."""
    verifier, _transport = build()
    tokens = [
        SIGNER.sign(claims(sub=ABSENT)),
        OTHER.sign(claims()),
        tampered(SIGNER.sign(claims())),
        SIGNER.sign(claims(issuer=OTHER_ORIGIN)),
        SIGNER.sign(claims(issued_at=int(time.time()) - 2000)),
        ed25519_signer("never-published").sign(claims()),
    ]

    for token in tokens:
        with pytest.raises(SessionError) as caught:
            await verifier.verify(token, User)
        assert leaks(caught.value, token) == (), f"a refusal carried part of {token[:12]}..."


@pytest.mark.anyio
async def test_every_refusal_still_tells_an_operator_something() -> None:
    """The other half: a uniform reason would make the whole taxonomy useless in a log."""
    reasons = {
        (await refused(OTHER.sign(claims())))[0].reason,
        (await refused(SIGNER.sign(claims(sub=ABSENT))))[0].reason,
        (await refused(ed25519_signer("never-published").sign(claims())))[0].reason,
        (await refused(SIGNER.sign(claims()), TimeoutError("down")))[0].reason,
    }

    assert len(reasons) == 4
    assert all(reason.strip() for reason in reasons)


LEAK_MARKER = "leaky-credential-9f3ab21c"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("credential", "needle"),
    [
        (LEAK_MARKER + "x" * 9000, LEAK_MARKER),
        (LEAK_MARKER + "-carries-no-dots", LEAK_MARKER),
        ((LEAK_MARKER + "-in-bytes").encode(), LEAK_MARKER),
        (None, None),
    ],
    ids=["over-cap", "wrong-dots", "not-a-string", "deep-path"],
)
async def test_no_raw_credential_survives_in_a_library_frame(
    credential: object, needle: str | None
) -> None:
    """The frame-locals channel, which the reason rules do not cover: a reporter captures
    every frame in the traceback, and this library's frames are the ones it blames us for.

    B1 reopened it on the three *early* refusals — over the size cap, wrong dot count, not a
    string at all — whose own frame held the raw credential while the deep path (a wrong-key
    token) had already been scrubbed. Every shape is driven here, and each must fail before
    the fix.
    """
    verifier, _transport = build()
    if credential is None:
        credential = OTHER.sign(claims())  # the deep path: passes the shape checks, fails at decode

    with pytest.raises(SessionError) as caught:
        await verifier.verify(credential, User)  # pyright: ignore[reportArgumentType]

    rendered = " ".join(repr(frame.f_locals) for frame in _library_frames(caught.value))

    assert rendered, "no library frame was captured; retune this probe"
    if needle is not None:
        assert needle not in rendered
        return
    assert isinstance(credential, str)
    assert credential not in rendered
    assert credential.split(".")[2] not in rendered


def _library_frames(error: BaseException) -> list[Any]:
    frames: list[Any] = []
    traceback = error.__traceback__
    while traceback is not None:
        if "fastapi_better_auth" in traceback.tb_frame.f_code.co_filename:
            frames.append(traceback.tb_frame)
        traceback = traceback.tb_next
    return frames
