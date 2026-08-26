"""The HTTP boundary: the only door this library has onto a network."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Protocol, runtime_checkable


class UntrustedResponse(Exception):
    """Base for a response a transport refuses to deliver because it cannot vouch for it.

    Catch this to translate every transport-level refusal in one clause:

        try:
            response = await transport.get(jwks_url, max_bytes=MAX_JWKS_BYTES)
        except (UntrustedResponse, TimeoutError):
            raise AuthServiceUnavailable(reason="jwks fetch failed") from None

    Deliberately outside this library's own taxonomy - neither a `SessionError` nor a
    `BetterAuthError`. A transport has no request context, so it cannot know whether a refused
    response should answer a client with a 401 or stop the application from starting; only the
    verifier that made the call knows that, and translating is its job. The base-class choice
    is the safety net for the day it forgets: an escaping `BetterAuthError` is honoured by
    dispatch and would leave as a 500 - the one request-time answer a client can tell apart
    from every other - while this is contained as the uniform 401 like any other stray
    exception, which is the direction a security library should fail in.

    Its two concrete forms - `ResponseTooLarge` and `ContentEncodingRejected` - are the two
    ways a body can be refused before it is trusted. A network timeout is not one of them: it
    is a builtin `TimeoutError` the adapter raised (see `Transport`), caught alongside this.
    """


def _rebuild_too_large(max_bytes: int) -> ResponseTooLarge:
    return ResponseTooLarge(max_bytes=max_bytes)


class ResponseTooLarge(UntrustedResponse):
    """A response body outgrew the caller's `max_bytes` cap, and the read was abandoned.

    Raised by a transport, caught by whatever asked it to fetch something - most simply
    through the `UntrustedResponse` base, which also covers `ContentEncodingRejected`:

        try:
            response = await transport.get(jwks_url, max_bytes=MAX_JWKS_BYTES)
        except (UntrustedResponse, TimeoutError):
            raise AuthServiceUnavailable(reason="jwks fetch failed") from None

    An `UntrustedResponse`, so it stays outside the taxonomy for the reasons stated there: an
    untranslated one fails closed as the uniform 401 rather than escaping as a 500.

    Args:
        max_bytes: Keyword-only, required. The cap that was exceeded. How far past it the
            body went is not reported, because the read stopped as soon as it was crossed.
    """

    max_bytes: int

    def __init__(self, *, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        super().__init__(f"response body exceeded the {max_bytes}-byte cap; the read was abandoned")

    def __reduce__(self) -> tuple[Callable[[int], ResponseTooLarge], tuple[int]]:
        """Keyword-only `__init__` and the default `__reduce__` do not survive a pickle."""
        return (_rebuild_too_large, (self.max_bytes,))


def _rebuild_bad_encoding(encoding: str) -> ContentEncodingRejected:
    return ContentEncodingRejected(encoding=encoding)


class ContentEncodingRejected(UntrustedResponse):
    """The server applied a `Content-Encoding` after the transport asked for `identity`.

    An `UntrustedResponse`, caught the same way and outside the taxonomy for the same reason.

    The transport requests `accept-encoding: identity` and counts the *wire* bytes it reads,
    so a compressed body can never be decompressed on unbounded input - a 260 KB gzip stream
    expands to 256 MB, the decompression-bomb DoS this boundary exists to stop. A server that
    answers the pinned origin with a `Content-Encoding` anyway has ignored that request: it is
    misconfigured, or hostile, and either way its body is refused rather than decoded. The
    JWKS and get-session bodies are small JSON served as identity, so nothing legitimate is
    lost by refusing.

    Args:
        encoding: Keyword-only, required. The `Content-Encoding` value the server sent.
    """

    encoding: str

    def __init__(self, *, encoding: str) -> None:
        self.encoding = encoding
        super().__init__(
            f"server applied Content-Encoding {encoding!r} after the transport requested"
            " identity; refusing to decode an unverified, possibly compressed body"
        )

    def __reduce__(self) -> tuple[Callable[[str], ContentEncodingRejected], tuple[str]]:
        """Keyword-only `__init__` and the default `__reduce__` do not survive a pickle."""
        return (_rebuild_bad_encoding, (self.encoding,))


@dataclass(frozen=True, slots=True)
class TransportResponse:
    """One HTTP response, already read to the end and already capped.

    There is no stream here and no lazy body: by the time a `TransportResponse` exists the
    bytes are in memory and a caller-supplied cap has been enforced against them. That is
    the whole point of the shape - a lazy body would let the size cap be skipped by a caller
    that simply never finished reading, and would make cleanup the caller's problem.

    Header names are lowercased on construction, so `response.headers["content-type"]` is
    the one spelling that works. HTTP header names are case-insensitive and HTTP/2 sends
    them lowercased; the type owns the normalization so that no adapter can forget it and no
    caller has to guess.

    Repeated header names arrive **comma-joined**, exactly as the underlying HTTP client
    produced them - two `WWW-Authenticate: ...` lines become one `"Bearer, Basic"` value. That
    is what a single-valued header a caller reads (`content-type`, `www-authenticate`) needs.
    It is **wrong** for `Set-Cookie`, whose values legitimately contain commas: never read
    `Set-Cookie` or any comma-bearing header off this mapping - a join is ambiguous for them,
    and a server could smuggle a second value past a caller's single-value check. This library
    reads responses and never sets cookies, so the headers it consults are safe.

    Instances compare by value. Formally hashable, but `hash()` raises `TypeError` at call
    time because `headers` is a mapping - the same house rule `Session` follows. Key on
    something else.

    Attributes:
        status_code: The status exactly as the server sent it. A 3xx is a real answer here,
            not a hop: see `Transport` for why nothing follows it.
        headers: Read-only, lowercased, and copied - mutating the mapping that was passed in
            does not change a response that was already built. Kept out of `repr()`: a
            response repr reaches logs and tracebacks, and a `Set-Cookie` here can carry a
            live session cookie.
        content: The body, whole. Kept out of `repr()` for the same reason - an unverified
            body must not ride along.
    """

    status_code: int
    headers: Mapping[str, str] = field(repr=False)
    content: bytes = field(repr=False)

    def __post_init__(self) -> None:
        lowered = {key.lower(): value for key, value in self.headers.items()}
        object.__setattr__(self, "headers", MappingProxyType(lowered))


@runtime_checkable
class Transport(Protocol):
    """Two async methods, and three obligations that make them safe to point at a pinned URL.

    Implement this to hand the library an HTTP client your deployment already owns - one
    with your proxy, your CA bundle, your connection pool. The shipped adapters
    (`HttpxTransport`, `Httpx2Transport`) implement exactly this and get no privileges yours
    does not:

        class MyTransport:
            async def get(
                self, url: str, *, headers: Mapping[str, str] | None = None, max_bytes: int
            ) -> TransportResponse:
                ...

            async def post(
                self,
                url: str,
                *,
                headers: Mapping[str, str] | None = None,
                content: bytes = b"",
                max_bytes: int,
            ) -> TransportResponse:
                ...

    **A redirect is never followed.** A 3xx is returned as it arrived, for the caller to
    refuse. This is the obligation the rest of the configuration rests on: the JWKS URL is
    pinned to the operator's canonical origin precisely so that a key set comes from where
    they said it would, and a transport that quietly followed a `Location` header would let
    whoever answers that origin - or anyone who can inject one 3xx - move the fetch
    somewhere else. A substituted key set is a complete authentication bypass, with no
    signature left to fall back on.

    **`max_bytes` is enforced while the body is being read**, and against the *wire* bytes.
    The read counts the undecoded stream and stops the instant the cap is crossed, raising
    `ResponseTooLarge` with the buffer bounded by cap+1 - so a `Content-Encoding` a server
    applied (which this boundary asked it not to) cannot decompress a bomb past the cap; such
    a response is refused as `ContentEncodingRejected` before any decode. `Content-Length` is
    not enforcement: a server may omit it, and one that means harm may lie about it. Both
    refusals share the `UntrustedResponse` base, so one `except` clause covers them.

    **A timeout is a builtin `TimeoutError`; other failures are left alone.** The Protocol
    defines its timeout type: whatever the underlying client uses internally, a fetch that
    times out raises a builtin `TimeoutError`, so a caller's recipe does not depend on which
    library is underneath. Every other network failure - a refused connection, a TLS error, a
    mid-response disconnect - propagates as whatever the client raised, untranslated: a
    transport does not know what one means to the request that caused it, and the verifier
    above turns both timeout and refusal into `AuthServiceUnavailable`:

        try:
            response = await transport.get(jwks_url, max_bytes=MAX_JWKS_BYTES)
        except (UntrustedResponse, TimeoutError):
            raise AuthServiceUnavailable(reason="jwks fetch failed") from None

    `max_bytes` is required and has no default, because the cap is the *caller's* policy: a
    transport that picked one would be deciding how much of an unverified body its caller
    has to hold. There is no `close` here on purpose - lifecycle belongs to whoever built
    the client, and a caller that was handed a transport it did not build must not be able
    to close it out from under its owner. The shipped adapters offer `aclose()` and
    `async with` outside the protocol.

    The protocol is runtime-checkable, so `isinstance` proves the two member *names* exist
    and nothing about their signatures, their callability, or whether they honour a single
    obligation above.
    """

    async def get(
        self, url: str, *, headers: Mapping[str, str] | None = None, max_bytes: int
    ) -> TransportResponse:
        """Fetch `url`, reading at most `max_bytes` of body.

        Args:
            url: The absolute URL to fetch. Built from operator configuration, never from
                anything on an incoming request.
            headers: Request headers to send, or `None`.
            max_bytes: Keyword-only, required. The largest body this caller will accept.

        Returns:
            The response, read to the end.

        Raises:
            ResponseTooLarge: If the body outgrew `max_bytes`. The read is abandoned.
            ContentEncodingRejected: If the server applied a `Content-Encoding`.
            TimeoutError: If the fetch timed out.
            Exception: Whatever the underlying HTTP client raises for a non-timeout
                connection or TLS failure, untranslated.
        """
        ...

    async def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        content: bytes = b"",
        max_bytes: int,
    ) -> TransportResponse:
        """Send `content` to `url`, reading at most `max_bytes` of body.

        Args:
            url: The absolute URL to post to. Built from operator configuration, never from
                anything on an incoming request.
            headers: Request headers to send, or `None`.
            content: The request body, already encoded. Defaults to empty.
            max_bytes: Keyword-only, required. The largest body this caller will accept.

        Returns:
            The response, read to the end.

        Raises:
            ResponseTooLarge: If the body outgrew `max_bytes`. The read is abandoned.
            ContentEncodingRejected: If the server applied a `Content-Encoding`.
            TimeoutError: If the fetch timed out.
            Exception: Whatever the underlying HTTP client raises for a non-timeout
                connection or TLS failure, untranslated.
        """
        ...
