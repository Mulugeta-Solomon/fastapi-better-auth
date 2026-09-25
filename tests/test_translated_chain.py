"""Every refusal the library translates from a caught exception leaves that exception behind.

Each site here caught something - a decode error, a third-party transport's exception, a key the
cryptography library would not load, a URL redis-py rejected - and raised its own refusal in its
place with `from None`, *inside* the `except`. That clears `__cause__`, but Python still records
`__context__`, and what rode there was the thing each site meant to drop:

* a `UnicodeDecodeError` whose `.object` is the whole cookie value, token and signature (cookie
  and remote modes, percent-decoding);
* a base64 error whose traceback frames hold the signature;
* a JWKS transport's own exception, quoting whatever it failed on;
* the key library's refusal of a published key; the limiter's `TimeoutError`;
* an HTTP client's error, request and all, behind the import the httpx adapters made *while
  matching it* to learn the library's timeout type - now resolved at construction;
* at construction, redis-py's rejection of a URL that can carry a password, the probe's
  unreachability, and `ipaddress`'s rejection of a configured host.

Every site now decides its refusal inside the handler and raises it after (or converts the failure
to a sentinel its caller refuses on). Each test asserts, bool-first, that the refusal carries
neither `__context__` nor `__cause__`.
"""

from __future__ import annotations

import contextlib
import sys
from collections.abc import AsyncGenerator, Callable

import anyio
import pytest

from fastapi_better_auth import (
    AuthServiceUnavailable,
    ConfigurationError,
    CsrfDisabled,
    Httpx2Transport,
    HttpxTransport,
    InvalidCredential,
    RedisSessionStore,
    RemoteVerifier,
    normalize_base_url,
)
from fastapi_better_auth._internal.cookie_parsing import parse_signed_value
from fastapi_better_auth._internal.transport import TransportFailure
from fastapi_better_auth._internal.urls import ip_literal
from tests.jwks_fixtures import client as jwks_client
from tests.remote_fixtures import ORIGIN, RecordingTransport, run, verifier, with_cookie
from tests.transports import Reply, ScriptedTransport

UNDECODABLE = "tok%ff%fe." + "A" * 43 + "="
"""Percent-encoded bytes that are not UTF-8: `unquote(errors='strict')` refuses them, and its
`UnicodeDecodeError.object` is the whole decoded cookie value."""
NOT_STANDARD_BASE64 = "tok." + "_" * 43 + "="
"""The right length, in the base64url alphabet: standard base64 refuses the `_`."""
NEEDLE = "sup3r-secret-9f3ab21c"
MALFORMED_KEY = b'{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","alg":"EdDSA","x":"%%%"}]}'


def chained(exc: BaseException) -> bool:
    return exc.__context__ is not None or exc.__cause__ is not None


# --- request time ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "material",
    [UNDECODABLE, NOT_STANDARD_BASE64],
    ids=["percent-encoded-non-utf8", "not-standard-base64"],
)
def test_a_cookie_value_that_does_not_parse_is_refused_with_no_chain(material: str) -> None:
    with pytest.raises(InvalidCredential) as caught:
        parse_signed_value(material)

    assert not chained(caught.value), "the refusal carries the decode error - and the cookie"


@pytest.mark.anyio
async def test_a_remote_cookie_that_does_not_percent_decode_is_refused_with_no_chain() -> None:
    built = verifier(ScriptedTransport(Reply(b"null")))

    with pytest.raises(InvalidCredential) as caught:
        await run(built, with_cookie(UNDECODABLE))

    assert not chained(caught.value), "the refusal carries the decode error - and the cookie"


@pytest.mark.anyio
async def test_a_saturated_outbound_queue_is_refused_with_no_chain() -> None:
    gate = anyio.Event()
    built = verifier(
        RecordingTransport(Reply(b"null"), gate=gate), concurrency=1, queue_timeout=0.1
    )
    refusals: list[AuthServiceUnavailable] = []

    async def hold_the_only_slot() -> None:
        with contextlib.suppress(BaseException):
            await run(built, with_cookie())

    async with anyio.create_task_group() as group:
        group.start_soon(hold_the_only_slot)
        await anyio.sleep(0.01)
        with pytest.raises(AuthServiceUnavailable) as caught:
            await run(built, with_cookie())
        refusals.append(caught.value)
        gate.set()

    assert "saturated" in refusals[0].reason
    assert not chained(refusals[0]), "the refusal carries the limiter's TimeoutError"


@pytest.mark.anyio
async def test_a_jwks_transport_failure_is_refused_with_no_chain() -> None:
    keys, _transport = jwks_client(RuntimeError(f"the transport failed carrying {NEEDLE}"))

    with pytest.raises(AuthServiceUnavailable) as caught:
        await keys.key_for("k1")

    assert not chained(caught.value), "the refusal carries the transport's own exception"


@pytest.mark.anyio
async def test_a_published_key_that_does_not_load_is_refused_with_no_chain() -> None:
    keys, _transport = jwks_client(Reply(content=MALFORMED_KEY))

    with pytest.raises(AuthServiceUnavailable) as caught:
        await keys.key_for("k1")

    assert "did not load" in caught.value.reason
    assert not chained(caught.value), "the refusal carries the key library's exception"


class LeakyStreamError(Exception):
    """Stands in for a client library's error, which carries the outbound request - headers,
    and so any cookie the transport was forwarding."""


class _Jar:
    def set_policy(self, policy: object) -> None:
        return None

    def clear(self) -> None:
        return None


class _Cookies:
    jar = _Jar()


class DuckTypedClient:
    """Satisfies the adapters' client protocol structurally, with the library itself absent."""

    cookies = _Cookies()

    @contextlib.asynccontextmanager
    async def stream(self, *args: object, **kwargs: object) -> AsyncGenerator[object, None]:
        raise LeakyStreamError(f"connection reset while sending cookie={NEEDLE}")
        yield

    async def aclose(self) -> None:
        return None


@pytest.mark.anyio
@pytest.mark.parametrize("adapter", [HttpxTransport, Httpx2Transport], ids=["httpx", "httpx2"])
async def test_a_client_error_is_translated_with_no_chain_when_the_library_is_absent(
    adapter: type[HttpxTransport | Httpx2Transport], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The adapter's timeout type came from an import made *while matching* the client's error:
    with the library absent, that import failed with the client's error - request and all - as
    its `__context__`. The type is resolved at construction now, and a missing library simply has
    no timeout type of its own to catch."""
    monkeypatch.setitem(sys.modules, "httpx" if adapter is HttpxTransport else "httpx2", None)
    transport = adapter(client=DuckTypedClient())  # pyright: ignore[reportArgumentType]

    with pytest.raises(TransportFailure) as caught:
        await transport.get(f"{ORIGIN}/api/auth/jwks", max_bytes=1024)

    assert NEEDLE not in str(caught.value)
    assert not chained(caught.value), "the translation carries the client's error on its chain"


# --- construction and startup ------------------------------------------------------------------


@pytest.mark.anyio
async def test_an_auth_service_unreachable_at_startup_is_refused_with_no_chain() -> None:
    built = RemoteVerifier(
        base_url=ORIGIN,
        transport=ScriptedTransport(TimeoutError()),
        csrf=CsrfDisabled(reason="a startup test, no cross-site request"),
        secure_cookies=False,
    )

    with pytest.raises(ConfigurationError) as caught:
        await built.prepare()

    assert "startup" in str(caught.value)
    assert not chained(caught.value), "the startup refusal carries the probe's refusal"


CONSTRUCTIONS: dict[str, Callable[[], object]] = {
    "redis-url-with-a-password": lambda: RedisSessionStore(
        url=f"gopher://user:{NEEDLE}@host:6379/0"
    ),
    "unusable-host": lambda: normalize_base_url("https://bad_host!.example"),
    "unusable-ipv6-literal": lambda: ip_literal("::1::2", "base_url"),
}


@pytest.mark.parametrize("build", list(CONSTRUCTIONS))
def test_a_refused_configuration_carries_no_chain(build: str) -> None:
    """Construction time, where these said `from None` and meant it: a redis URL can carry a
    password, and redis-py's own error is exactly what the message already declines to echo."""
    with pytest.raises(ConfigurationError) as caught:
        CONSTRUCTIONS[build]()

    assert not chained(caught.value), "the refusal carries the error it translated"
