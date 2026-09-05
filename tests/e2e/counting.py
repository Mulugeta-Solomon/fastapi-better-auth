"""A transport that counts what the verifier actually put on the wire.

Several of Mode C's properties are *absences*: a cached forged cookie must cost no second
upstream call, a cross-site request must cost none at all, and a latched verifier must stop
calling. A status code cannot see any of them - the answer is the same 401 either way - so the
instrument has to sit at the boundary and count.

`CountingTransport` wraps a real transport rather than replacing it: every leg that counts still
talks to the live Better Auth server through the shipped `HttpxTransport`, and the count is the
only thing added. `posts` is counted separately and asserted to stay zero, because Mode C's
outbound request is a GET by design and a POST would be a bug the get-count could not see.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi_better_auth import Transport, TransportResponse


class CountingTransport:
    """Delegates to `inner` and counts the calls. A `Transport`, structurally and for real."""

    def __init__(self, inner: Transport) -> None:
        self._inner = inner
        self.calls = 0
        self.posts = 0

    async def get(
        self, url: str, *, headers: Mapping[str, str] | None = None, max_bytes: int
    ) -> TransportResponse:
        self.calls += 1
        return await self._inner.get(url, headers=headers, max_bytes=max_bytes)

    async def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        content: bytes = b"",
        max_bytes: int,
    ) -> TransportResponse:
        self.posts += 1
        return await self._inner.post(url, headers=headers, content=content, max_bytes=max_bytes)
