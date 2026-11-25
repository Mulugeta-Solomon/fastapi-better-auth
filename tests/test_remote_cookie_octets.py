"""What Mode C looks at before it forwards a cookie upstream: RFC 6265 cookie-octets, and nothing more.

Without a configured secret `RemoteVerifier` cannot check the cookie's signature, so whatever the
browser sent goes upstream as the outbound `cookie:` header. This suite pins the one structural
filter that runs first: the cookie value as it arrived - the percent-encoded form, which is exactly
the form forwarded - must consist only of RFC 6265 `cookie-octet`s (`%x21 / %x23-2B / %x2D-3A /
%x3C-5B / %x5D-7E`). CR, LF, any other control byte, space, `"`, `,`, `;`, `\\`, DEL and anything
outside ASCII are refused as `InvalidCredential` - the uniform 401 a malformed cookie earns in
cookie mode - and no upstream request of any kind is made, not even the readiness probe.

What it deliberately does not do: invent a token shape. A percent-encoded byte (`%0D%0A`) is three
cookie-octets on the wire and is forwarded verbatim, inert - the same thing the browser sent and
the upstream decodes for itself - exactly as cookie mode accepts any decoded token. And it is no
substitute for a secret: a well-formed forged cookie is still forwarded when none is configured.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import Depends, FastAPI
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    BetterAuth,
    CsrfDisabled,
    InvalidCredential,
    RemoteVerifier,
    Session,
    User,
)
from fastapi_better_auth._internal.cookie_parsing import MAX_COOKIE_BYTES
from tests.fakes import client
from tests.remote_fixtures import (
    COOKIE_NAME,
    COOKIE_VALUE,
    ORIGIN,
    SECURE_NAME,
    TOKEN,
    RecordingTransport,
    document,
    run,
    verifier,
)
from tests.transports import Reply, json_reply

SIGNATURE = COOKIE_VALUE.rpartition(".")[2]

HOSTILE = [
    ("crlf", "\r\n"),
    ("cr", "\r"),
    ("lf", "\n"),
    ("nul", "\x00"),
    ("tab", "\t"),
    ("space", " "),
    ("comma", ","),
    ("dquote", '"'),
    ("backslash", "\\"),
    ("del", "\x7f"),
    ("c1-nel", "\x85"),
    ("latin-1", "\xe9"),
    ("nbsp", "\xa0"),
    ("high", "\xff"),
]
"""Bytes outside the cookie-octet set, each placed in the *interior* of the value: the header
parser already strips leading and trailing whitespace and splits on `;`, so the interior is where
a hostile byte survives to reach the outbound header."""


def poisoned(byte: str) -> str:
    return f"{TOKEN[:8]}{byte}{TOKEN[8:]}.{SIGNATURE}"


def raw_cookie_connection(*pairs: tuple[str, str]) -> HTTPConnection:
    """A connection whose Cookie header carries these pairs as raw latin-1 bytes, the way an ASGI
    server hands Starlette a header it did not reject - nothing re-encodes or validates them."""
    header = "; ".join(f"{name}={value}" for name, value in pairs).encode("latin-1")
    scope = {"type": "http", "method": "GET", "path": "/x", "headers": [(b"cookie", header)]}
    return HTTPConnection(scope)


def cold(transport: RecordingTransport, **kwargs: Any) -> RemoteVerifier:
    """A verifier whose readiness probe has not run, so ANY outbound call - probe or fetch - is
    visible on the transport."""
    kwargs.setdefault("csrf", CsrfDisabled(reason="cookie octet tests, no cross-site request"))
    kwargs.setdefault("secure_cookies", False)
    return RemoteVerifier(base_url=ORIGIN, transport=transport, **kwargs)


# ---------------------------------------------------------------- refused before anything is sent


@pytest.mark.anyio
@pytest.mark.parametrize(("label", "byte"), HOSTILE, ids=[label for label, _ in HOSTILE])
async def test_a_non_octet_cookie_is_refused_before_any_outbound_call(
    label: str, byte: str
) -> None:
    transport = RecordingTransport(Reply(b"null"))
    v = cold(transport)

    with pytest.raises(InvalidCredential) as caught:
        await run(v, raw_cookie_connection((COOKIE_NAME, poisoned(byte))))

    assert "cookie-octet" in caught.value.reason
    assert transport.calls == 0, f"{label}: an upstream request was made for a refused cookie"


@pytest.mark.anyio
@pytest.mark.parametrize(("label", "byte"), HOSTILE, ids=[label for label, _ in HOSTILE])
async def test_a_warmed_verifier_never_fetches_for_a_non_octet_cookie(
    label: str, byte: str
) -> None:
    transport = RecordingTransport(json_reply(document()))
    v = verifier(transport)

    with pytest.raises(InvalidCredential):
        await run(v, raw_cookie_connection((COOKIE_NAME, poisoned(byte))))

    assert transport.calls == 0


@pytest.mark.anyio
async def test_a_quoted_cookie_value_is_refused() -> None:
    """RFC 6265 allows a DQUOTE-wrapped value, but Better Auth never sends one and cookie mode
    refuses it too (the quote breaks the 44-character signature), so the two modes agree."""
    transport = RecordingTransport(Reply(b"null"))

    with pytest.raises(InvalidCredential) as caught:
        await run(cold(transport), raw_cookie_connection((COOKIE_NAME, f'"{COOKIE_VALUE}"')))

    assert "cookie-octet" in caught.value.reason
    assert transport.calls == 0


@pytest.mark.anyio
async def test_a_non_octet_byte_in_one_chunk_refuses_the_reassembled_cookie() -> None:
    head, tail = COOKIE_VALUE[:16], COOKIE_VALUE[16:]
    transport = RecordingTransport(Reply(b"null"))
    connection = raw_cookie_connection(
        (f"{COOKIE_NAME}.0", head), (f"{COOKIE_NAME}.1", f"x\r\ny{tail}")
    )

    with pytest.raises(InvalidCredential) as caught:
        await run(cold(transport), connection)

    assert "cookie-octet" in caught.value.reason
    assert transport.calls == 0


@pytest.mark.anyio
async def test_the_refusal_reason_carries_no_cookie_byte() -> None:
    value = poisoned("\r\n")
    with pytest.raises(InvalidCredential) as caught:
        await run(
            cold(RecordingTransport(Reply(b"null"))), raw_cookie_connection((COOKIE_NAME, value))
        )

    reason = caught.value.reason
    assert TOKEN[:8] not in reason
    assert SIGNATURE[:8] not in reason
    assert "\r" not in reason
    assert "tok_fp=" in reason


@pytest.mark.anyio
async def test_an_oversized_cookie_is_refused_by_the_existing_cap_before_any_call() -> None:
    """The length bound is the one cookie mode enforces (`MAX_COOKIE_BYTES`), not a second one."""
    transport = RecordingTransport(Reply(b"null"))
    value = f"{'a' * MAX_COOKIE_BYTES}.{SIGNATURE}"

    with pytest.raises(InvalidCredential) as caught:
        await run(cold(transport), raw_cookie_connection((COOKIE_NAME, value)))

    assert "over the cap" in caught.value.reason
    assert transport.calls == 0


# ---------------------------------------------------------------- what is forwarded, exactly


@pytest.mark.anyio
async def test_a_well_formed_cookie_is_forwarded_verbatim_in_the_closed_header_set() -> None:
    """The real shape Better Auth sets: `encodeURIComponent` of `token.signature`, so the base64
    signature's `+`, `/` and `=` arrive percent-encoded. Every byte is a cookie-octet, and the
    value is forwarded exactly as it arrived, under the configured name, beside `accept` only."""
    encoded = COOKIE_VALUE.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
    transport = RecordingTransport(json_reply(document()))

    session = await run(verifier(transport), raw_cookie_connection((COOKIE_NAME, encoded)))

    assert session.user.id == "u1"
    assert transport.sent == [{"cookie": f"{COOKIE_NAME}={encoded}", "accept": "application/json"}]


@pytest.mark.anyio
async def test_a_percent_encoded_crlf_is_forwarded_inert_and_never_decoded_into_the_header() -> (
    None
):
    """`%0D%0A` is six cookie-octets. It is not decoded before forwarding, so no CR or LF reaches
    the outbound header; upstream decodes it, finds no such session, and answers `200 null`."""
    value = f"{TOKEN[:8]}%0D%0AX-Injected:%201{TOKEN[8:]}.{SIGNATURE}"
    transport = RecordingTransport(Reply(b"null"))

    with pytest.raises(InvalidCredential):
        await run(verifier(transport), raw_cookie_connection((COOKIE_NAME, value)))

    assert transport.sent == [{"cookie": f"{COOKIE_NAME}={value}", "accept": "application/json"}]
    forwarded = transport.sent[0]
    assert forwarded is not None
    assert not {"\r", "\n"}.intersection(forwarded["cookie"])


@pytest.mark.anyio
async def test_the_outbound_name_is_the_configured_secure_name() -> None:
    transport = RecordingTransport(json_reply(document()))

    await run(
        verifier(transport, secure_cookies=True),
        raw_cookie_connection((SECURE_NAME, COOKIE_VALUE)),
    )

    assert transport.sent == [
        {"cookie": f"{SECURE_NAME}={COOKIE_VALUE}", "accept": "application/json"}
    ]


@pytest.mark.anyio
async def test_a_semicolon_ends_the_value_so_a_smuggled_pair_is_never_forwarded() -> None:
    """`;` can never be inside a value: the header parser splits on it, so `tok.sig;evil=1` is two
    pairs, and only the session cookie's own pair is forwarded - the other is not this verifier's
    and goes nowhere."""
    header = f"{COOKIE_NAME}={COOKIE_VALUE};evil=1".encode("latin-1")
    scope = {"type": "http", "method": "GET", "path": "/x", "headers": [(b"cookie", header)]}
    transport = RecordingTransport(json_reply(document()))

    session = await run(verifier(transport), HTTPConnection(scope))

    assert session.user.id == "u1"
    assert transport.sent == [
        {"cookie": f"{COOKIE_NAME}={COOKIE_VALUE}", "accept": "application/json"}
    ]


@pytest.mark.anyio
async def test_a_semicolon_that_cuts_the_value_short_is_refused_without_a_call() -> None:
    """Split at a `;`, the session pair keeps only what came before it; with no signature
    separator left, the structural rung refuses it and nothing is forwarded."""
    header = f"{COOKIE_NAME}={TOKEN[:8]};{TOKEN[8:]}.{SIGNATURE}".encode("latin-1")
    scope = {"type": "http", "method": "GET", "path": "/x", "headers": [(b"cookie", header)]}
    transport = RecordingTransport(Reply(b"null"))

    with pytest.raises(InvalidCredential):
        await run(cold(transport), HTTPConnection(scope))

    assert transport.calls == 0


@pytest.mark.anyio
@pytest.mark.parametrize("edge", ["\r\n", "\n", "\r", " ", "\t", "\x85", "\xa0"], ids=repr)
async def test_whitespace_at_the_edges_is_stripped_by_the_parser_and_never_forwarded(
    edge: str,
) -> None:
    """Leading and trailing whitespace (including CR, LF, NEL and NBSP) is stripped when the
    header is split into pairs, so it cannot reach the outbound header either: what is forwarded
    is exactly the cookie, under the configured name."""
    transport = RecordingTransport(json_reply(document()))

    session = await run(
        verifier(transport), raw_cookie_connection((COOKIE_NAME, f"{edge}{COOKIE_VALUE}{edge}"))
    )

    assert session.user.id == "u1"
    assert transport.sent == [
        {"cookie": f"{COOKIE_NAME}={COOKIE_VALUE}", "accept": "application/json"}
    ]


# ---------------------------------------------------------------- on the wire


@pytest.mark.parametrize(
    "value",
    [poisoned(" "), poisoned(","), poisoned('"'), poisoned("\\")],
    ids=["space", "comma", "dquote", "backslash"],
)
def test_a_non_octet_cookie_gets_the_same_401_as_a_malformed_one(
    value: str, client_backend: str
) -> None:
    """Through a real app: the refusal is byte-for-byte the response a cookie with no signature
    separator gets, and the upstream sees nothing either way."""
    transport = RecordingTransport(json_reply(document()))
    auth = BetterAuth(verifiers=[verifier(transport)])
    app = FastAPI()
    required = auth.current_session(user_model=User)

    async def me(session: Session[User] = Depends(required)) -> str:
        return session.user.id  # pragma: no cover

    app.add_api_route("/me", me)

    with client(app, client_backend) as browser:
        poisoned_answer = browser.get("/me", headers={"cookie": f"{COOKIE_NAME}={value}"})
        malformed_answer = browser.get("/me", headers={"cookie": f"{COOKIE_NAME}=noseparator"})

    assert poisoned_answer.status_code == 401
    assert poisoned_answer.content == malformed_answer.content
    assert dict(poisoned_answer.headers) == dict(malformed_answer.headers)
    assert transport.calls == 0
