"""Scripted `Transport` doubles for the JWKS lane: counted calls, and a gate to hold one open.

`tests/scripted_server.py` drives a real socket and proves what the *adapter* owes (WP4) —
a redirect not followed, a body abandoned mid-read, a stalled connection timing out. None of
that is what the JWKS client's own policy is made of. Its rules are about *how many* fetches
happen, in what window, and behind which lock, so what they need is a transport that counts
and can be held open on command, not one that dials.

Every double answers the `Transport` Protocol exactly, including the obligations the client
depends on: `max_bytes` is recorded rather than ignored, a 3xx comes back as a 3xx, and `post`
fails the test outright, because a key set is fetched with GET or the pin means nothing.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import anyio

from fastapi_better_auth import TransportResponse

JSON = "application/json"


@dataclass(frozen=True)
class Reply:
    """One scripted answer. `content_type=None` sends no `Content-Type` header at all."""

    content: bytes
    status: int = 200
    content_type: str | None = JSON

    def response(self) -> TransportResponse:
        headers = {} if self.content_type is None else {"Content-Type": self.content_type}
        return TransportResponse(status_code=self.status, headers=headers, content=self.content)


def json_reply(document: Any, *, status: int = 200, content_type: str | None = JSON) -> Reply:
    return Reply(
        content=json.dumps(document).encode("utf-8"), status=status, content_type=content_type
    )


Answer = Reply | BaseException


class ScriptedTransport:
    """Answers from a script, records every call, and repeats its last answer forever.

    Repeating rather than exhausting is deliberate: a cache test asserts a *count*, and a
    transport that ran out would fail with a different error than the one under test.
    """

    def __init__(self, *answers: Answer, gate: anyio.Event | None = None) -> None:
        assert answers, "a scripted transport with no answers can only mislead"
        self.answers = list(answers)
        self.gate = gate
        self.calls = 0
        self.posts = 0
        self.targets: list[str] = []
        self.caps: list[int] = []
        self.headers: list[Mapping[str, str] | None] = []

    async def get(
        self, url: str, *, headers: Mapping[str, str] | None = None, max_bytes: int
    ) -> TransportResponse:
        self.calls += 1
        self.targets.append(url)
        self.caps.append(max_bytes)
        self.headers.append(headers)
        if self.gate is not None:
            await self.gate.wait()
        answer = self.answers[min(self.calls - 1, len(self.answers) - 1)]
        if isinstance(answer, BaseException):
            raise answer
        return answer.response()

    async def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        content: bytes = b"",
        max_bytes: int,
    ) -> TransportResponse:
        self.posts += 1
        raise AssertionError("the key set is fetched with GET; a POST here is a bug")


class NotATransport:
    """Has neither method — what a typo, or an httpx client passed by mistake, looks like."""
