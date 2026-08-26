"""The two shipped transports: `httpx`, and `httpx2` — the same API under two names."""

from __future__ import annotations

import math
from collections.abc import AsyncIterator, Mapping
from contextlib import AbstractAsyncContextManager
from types import MappingProxyType, TracebackType
from typing import TYPE_CHECKING, Protocol, TypeVar

import anyio

from .errors import ConfigurationError
from .transport import ResponseTooLarge, TransportResponse

if TYPE_CHECKING:
    import httpx
    import httpx2

DEADLINE_GRACE = 0.5
DEFAULT_TIMEOUT = 5.0
REQUEST_HEADERS: Mapping[str, str] = MappingProxyType({"accept-encoding": "identity"})

MISSING = (
    "{adapter} needs the {library} package, which is not installed. Install it with:"
    ' pip install "fastapi-better-auth-bridge[{library}]" - or build the client yourself'
    " and pass it as client=."
)

TransportT = TypeVar("TransportT", bound="_HttpxFamilyTransport")


class _StreamedResponse(Protocol):
    """What this adapter reads off a response. Read-only, so a property satisfies it too."""

    @property
    def status_code(self) -> int: ...

    @property
    def headers(self) -> Mapping[str, str]: ...

    def aiter_bytes(self) -> AsyncIterator[bytes]: ...


class _Client(Protocol):
    """The slice of `AsyncClient` this adapter uses — identical in both libraries."""

    def stream(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        content: bytes,
        follow_redirects: bool,
    ) -> AbstractAsyncContextManager[_StreamedResponse]: ...

    async def aclose(self) -> None: ...


def _import_httpx():
    try:
        import httpx
    except ImportError as exc:
        raise ConfigurationError(MISSING.format(adapter="HttpxTransport", library="httpx")) from exc
    return httpx


def _import_httpx2():
    try:
        import httpx2
    except ImportError as exc:
        raise ConfigurationError(
            MISSING.format(adapter="Httpx2Transport", library="httpx2")
        ) from exc
    return httpx2


def _validated_timeout(timeout: object) -> float:
    """`timeout` is annotated `float`; the value comes from an operator's configuration."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ConfigurationError(
            f"timeout must be a number of seconds; got {type(timeout).__name__}."
            " Pass something like timeout=5.0."
        )
    if not math.isfinite(timeout) or timeout <= 0:
        raise ConfigurationError(
            f"timeout must be a positive, finite number of seconds; got {timeout!r}. A fetch"
            " with no deadline holds the request that needed it open for as long as the"
            " other end feels like trickling bytes."
        )
    return float(timeout)


def _validate_cap(max_bytes: object) -> None:
    """Annotated `int`, and every caller of a public protocol was written by someone else."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError(
            f"max_bytes must be a positive integer number of bytes; got {max_bytes!r}."
            " A cap below one refuses every response, silently and forever."
        )


def _request_headers(headers: Mapping[str, str] | None) -> Mapping[str, str]:
    """`identity` first, so the caller can still override it deliberately."""
    merged = dict(REQUEST_HEADERS)
    if headers is not None:
        merged.update({key.lower(): value for key, value in headers.items()})
    return merged


async def _capped(response: _StreamedResponse, max_bytes: int) -> bytes:
    """Count while reading. `Content-Length` is not enforcement - it can be absent, or a lie.

    The abort is a cancellation rather than a `break`, and that is not a style choice. A
    body arrives through a stack of five nested async generators; walking out of the loop
    abandons every one of them mid-yield, and a generator collected before it is exhausted
    is a `ResourceWarning` under trio and a silent late finalization under asyncio.
    Cancelling raises inside the innermost read instead, so the whole stack unwinds on the
    way out - the same path a timeout already takes.
    """
    body = bytearray()
    with anyio.CancelScope() as abort:
        async for chunk in response.aiter_bytes():
            body += chunk
            if len(body) > max_bytes:
                abort.cancel()
    if abort.cancel_called:
        raise ResponseTooLarge(max_bytes=max_bytes)
    return bytes(body)


async def _fetch(
    client: _Client,
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None,
    content: bytes,
    max_bytes: int,
    timeout: float,
) -> TransportResponse:
    _validate_cap(max_bytes)
    with anyio.fail_after(timeout + DEADLINE_GRACE):
        async with client.stream(
            method,
            url,
            headers=_request_headers(headers),
            content=content,
            follow_redirects=False,
        ) as response:
            return TransportResponse(
                status_code=response.status_code,
                headers=response.headers,
                content=await _capped(response, max_bytes),
            )


class _HttpxFamilyTransport:
    """Everything the two adapters share, which is everything except one import."""

    def __init__(self, client: _Client, *, timeout: float, owned: bool) -> None:
        self._client = client
        self._timeout = timeout
        self._owned = owned

    async def get(
        self, url: str, *, headers: Mapping[str, str] | None = None, max_bytes: int
    ) -> TransportResponse:
        """Fetch `url`, reading at most `max_bytes` of body. See `Transport.get`."""
        return await _fetch(
            self._client,
            "GET",
            url,
            headers=headers,
            content=b"",
            max_bytes=max_bytes,
            timeout=self._timeout,
        )

    async def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        content: bytes = b"",
        max_bytes: int,
    ) -> TransportResponse:
        """Send `content` to `url`, reading at most `max_bytes` of body. See `Transport.post`."""
        return await _fetch(
            self._client,
            "POST",
            url,
            headers=headers,
            content=content,
            max_bytes=max_bytes,
            timeout=self._timeout,
        )

    async def aclose(self) -> None:
        """Close the client this adapter built. An injected one is left alone: its lifetime
        belongs to whoever built it, and closing a shared pool is an outage well beyond us."""
        if self._owned:
            await self._client.aclose()

    # `typing.Self` is 3.11+, and typing-extensions is not a runtime dependency of this
    # library; the TypeVar is the 3.10-compatible spelling of the same thing.
    async def __aenter__(self: TransportT) -> TransportT:  # noqa: PYI019
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()


class HttpxTransport(_HttpxFamilyTransport):
    """A `Transport` backed by `httpx`. Needs the `[httpx]` extra.

        auth_transport = HttpxTransport(timeout=5.0)

        async with HttpxTransport() as transport:
            response = await transport.get(jwks_url, max_bytes=64 * 1024)

    Redirects are refused twice over: the client is built with `follow_redirects=False`, and
    every request passes it again explicitly, so an injected client configured to follow them
    still does not. That is the one piece of an injected client's configuration this adapter
    overrules, and it is deliberate - the URL being pinned is the whole security of the
    fetch, and a transport that could be bounced elsewhere makes the pin decorative.

    `timeout` is a deadline for the *whole* exchange, not a per-operation budget. The
    library's own connect, read, write and pool timeouts are set to it as well, so a single
    stalled phase raises the library's own timeout error - but those reset on every byte that
    arrives, which means they alone cannot stop a server that trickles a response out
    forever. An `anyio` deadline covers the whole call for that case, a short grace after the
    per-phase budget so that the library's more specific error wins whenever it applies, and
    raises `TimeoutError` when it fires. Both propagate untranslated: a transport does not
    know what a failed fetch means to the request that caused it.

    Everything else about an injected client - proxies, TLS verification, the connection
    pool, and its own timeout configuration - is left exactly as it was handed over. Its
    per-phase timeouts are then whatever it was built with rather than `timeout`, while the
    whole-exchange deadline still applies.

    Args:
        timeout: Seconds. The deadline for one fetch, and the client's per-phase budget when
            this adapter builds the client. Must be positive and finite.
        client: An `httpx.AsyncClient` to borrow instead of building one. When given, this
            adapter never closes it, and the `[httpx]` extra is not needed: the extra buys
            the client, not the adapter.

    Raises:
        ConfigurationError: If `httpx` is not installed and no client was passed, or if
            `timeout` is not a usable number of seconds. Raised while the application is
            being built, never on the request that would have needed the fetch.
    """

    def __init__(
        self, *, timeout: float = DEFAULT_TIMEOUT, client: httpx.AsyncClient | None = None
    ) -> None:
        checked = _validated_timeout(timeout)
        owned = client is None
        if client is None:
            module = _import_httpx()
            client = module.AsyncClient(timeout=module.Timeout(checked), follow_redirects=False)
        super().__init__(client, timeout=checked, owned=owned)


class Httpx2Transport(_HttpxFamilyTransport):
    """A `Transport` backed by `httpx2`. Needs the `[httpx2]` extra.

        auth_transport = Httpx2Transport(timeout=5.0)

        async with Httpx2Transport() as transport:
            response = await transport.get(jwks_url, max_bytes=64 * 1024)

    `httpx2` is the maintained continuation of `httpx` under a different import name, and it
    is API-continuous with it: this adapter is `HttpxTransport` with one import changed, and
    both are held to one shared conformance suite so that neither can quietly drift. Which
    one to install is a deployment question, not a behavioural one.

    Every guarantee is `HttpxTransport`'s, and for the same reasons: redirects are refused
    per request as well as per client, so an injected client cannot turn them back on;
    `timeout` bounds the whole exchange rather than each phase of it; and nothing a failed
    fetch raises is translated here.

    Args:
        timeout: Seconds. The deadline for one fetch, and the client's per-phase budget when
            this adapter builds the client. Must be positive and finite.
        client: An `httpx2.AsyncClient` to borrow instead of building one. When given, this
            adapter never closes it, and the `[httpx2]` extra is not needed.

    Raises:
        ConfigurationError: If `httpx2` is not installed and no client was passed, or if
            `timeout` is not a usable number of seconds. Raised while the application is
            being built, never on the request that would have needed the fetch.
    """

    def __init__(
        self, *, timeout: float = DEFAULT_TIMEOUT, client: httpx2.AsyncClient | None = None
    ) -> None:
        checked = _validated_timeout(timeout)
        owned = client is None
        if client is None:
            module = _import_httpx2()
            client = module.AsyncClient(timeout=module.Timeout(checked), follow_redirects=False)
        super().__init__(client, timeout=checked, owned=owned)
