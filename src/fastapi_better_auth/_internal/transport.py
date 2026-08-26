"""The HTTP boundary: the only door this library has onto a network."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Protocol, runtime_checkable


def _rebuild(max_bytes: int) -> ResponseTooLarge:
    return ResponseTooLarge(max_bytes=max_bytes)


class ResponseTooLarge(Exception):
    """A response body outgrew the caller's `max_bytes` cap, and the read was abandoned.

    Raised by a transport, caught by whatever asked it to fetch something:

        try:
            response = await transport.get(jwks_url, max_bytes=MAX_JWKS_BYTES)
        except (ResponseTooLarge, TimeoutError):
            raise AuthServiceUnavailable(reason="jwks fetch failed") from None

    Deliberately outside this library's own taxonomy - neither a `SessionError` nor a
    `BetterAuthError`. A transport has no request context, so it cannot know whether an
    oversized body should answer a client with a 401 or stop the application from starting;
    only the verifier that made the call knows that, and translating is its job. The choice
    of base class is the safety net for the day it forgets: an escaping `BetterAuthError` is
    honoured by dispatch and would leave as a 500 - the one request-time answer a client can
    tell apart from every other - while this is contained as the uniform 401 like any other
    stray exception, which is the direction a security library should fail in.

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
        return (_rebuild, (self.max_bytes,))


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
    caller has to guess. Repeated header names are collapsed, keeping the last value.

    Attributes:
        status_code: The status exactly as the server sent it. A 3xx is a real answer here,
            not a hop: see `Transport` for why nothing follows it.
        headers: Read-only, lowercased, and copied - mutating the mapping that was passed in
            does not change a response that was already built.
        content: The body, whole. Kept out of `repr()` because a response repr reaches logs
            and tracebacks, and an unverified body must not ride along.
    """

    status_code: int
    headers: Mapping[str, str]
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

    **`max_bytes` is enforced while the body is being read**, not after it has arrived. The
    read stops and `ResponseTooLarge` is raised as soon as the cap is crossed, so the bytes
    an implementation holds stay bounded by the cap plus one network chunk. Checking
    `Content-Length` is not enforcement: a server may omit it, and one that means harm may
    lie about it.

    **Failures are left alone.** A refused connection, a TLS failure, a timeout - they
    propagate as whatever the underlying client raises. A transport does not know what a
    failed fetch means to the request that caused it, so it does not translate; the verifier
    above it turns them into `AuthServiceUnavailable`. Keeping the transport dumb is what
    keeps the security decision in one place.

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
            Exception: Whatever the underlying HTTP client raises for a connection, TLS or
                timeout failure, untranslated.
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
            Exception: Whatever the underlying HTTP client raises for a connection, TLS or
                timeout failure, untranslated.
        """
        ...
