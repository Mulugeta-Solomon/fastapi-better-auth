"""D3: `CookieVerifier.extract` caps the Cookie header before parsing it (SA-D3, CPU-DoS).

A request whose joined Cookie header is over `MAX_COOKIE_HEADER_BYTES`, or that parses into more
than `MAX_COOKIE_PAIRS` pairs, carries no credential this library will spend CPU on: `extract`
returns absent without parsing it. This makes the parse bound the library's own guarantee rather
than the ASGI server's header cap (a dependency default the critic named as the only prior bound).
`extract` stays non-raising and a normal cookie is unchanged.
"""

from __future__ import annotations

from fastapi_better_auth import CsrfDisabled
from fastapi_better_auth._internal.cookie_parsing import (
    MAX_COOKIE_HEADER_BYTES,
    MAX_COOKIE_PAIRS,
)
from fastapi_better_auth._internal.cookie_verifier import CookieVerifier
from tests.cookies import CAPTURED_TOKEN, COOKIE, SECRET, http, seeded_store, sign


def verifier() -> CookieVerifier:
    return CookieVerifier(
        secret=SECRET,
        store=seeded_store(),
        csrf=CsrfDisabled(reason="header-cap tests are about parsing, not CSRF"),
        secure_cookies=False,
    )


class TestCookieHeaderCaps:
    def test_a_normal_cookie_is_unchanged(self) -> None:
        credential = verifier().extract(http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

        assert credential is not None

    def test_a_header_over_the_byte_cap_reads_as_absent(self) -> None:
        """A valid cookie buried under a header padded past the cap is not parsed - the whole
        header is refused before `cookie_pairs`, so the real credential is never reached."""
        real = f"{COOKIE}={sign(CAPTURED_TOKEN)}"
        padding = "; ".join(f"pad{i}=x" for i in range(MAX_COOKIE_HEADER_BYTES // 8))
        oversized = f"{real}; {padding}"
        assert len(oversized) > MAX_COOKIE_HEADER_BYTES

        assert verifier().extract(http(cookie=oversized)) is None

    def test_a_header_at_the_byte_cap_is_still_parsed(self) -> None:
        """The bound is inclusive: a header exactly at the cap is read, one past it is not."""
        real = f"{COOKIE}={sign(CAPTURED_TOKEN)}"
        filler = "a" * (MAX_COOKIE_HEADER_BYTES - len(real) - len("; pad="))
        at_cap = f"{real}; pad={filler}"
        assert len(at_cap) == MAX_COOKIE_HEADER_BYTES

        assert verifier().extract(http(cookie=at_cap)) is not None

    def test_too_many_pairs_reads_as_absent(self) -> None:
        """A header under the byte cap but with more than `MAX_COOKIE_PAIRS` tiny pairs is refused
        for the pair count: many small pairs is the other shape of the same parse cost."""
        real = f"{COOKIE}={sign(CAPTURED_TOKEN)}"
        pairs = "; ".join(f"c{i}=" for i in range(MAX_COOKIE_PAIRS + 5))
        header = f"{real}; {pairs}"
        # Kept comfortably under the byte cap so the pair count is the rung that fires.
        assert len(header) <= MAX_COOKIE_HEADER_BYTES

        assert verifier().extract(http(cookie=header)) is None

    def test_the_cap_is_non_raising(self) -> None:
        """The Verifier Protocol forbids `extract` from raising; an oversized header is absent."""
        oversized = "x=" + "y" * (MAX_COOKIE_HEADER_BYTES + 1)

        assert verifier().extract(http(cookie=oversized)) is None
