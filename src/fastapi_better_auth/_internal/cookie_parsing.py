"""The structural half of cookie mode: a raw cookie header down to a token and its signature.

No cryptography lives here, on purpose. This module reads the request's own bytes and proves
their *shape* - which name is present, how chunks reassemble, that the signature is 44 standard
base64 characters over 32 bytes - and never recomputes an HMAC or touches a secret. That is the
verifier's job, and keeping the two apart is what lets the keyring's one `compare_digest` be the
only comparison the "bad signature" invariant has to watch.

Every rejection is `InvalidCredential`, and every one carries a distinct reason: a mutation that
drops one guard changes the reason a test pins rather than only the accept/reject a later guard
would still produce. No rejection reason carries a byte of the cookie - only a fingerprint of it -
and every frame that holds cookie material scrubs it in `finally`, so a reporter that captures a
failure traceback's locals finds nothing (D-094).
"""

from __future__ import annotations

import base64
import binascii
import urllib.parse
from dataclasses import dataclass

from .errors import InvalidCredential
from .reasons import fingerprint

SIGNATURE_LENGTH = 44
HMAC_BYTES = 32
MAX_COOKIE_BYTES = 8192
MAX_CHUNKS = 100
MAX_COOKIE_HEADER_BYTES = 16384
"""The largest joined Cookie header this library will parse - 16 KiB, above any real browser's.

A request over it carries no credential this library reads: `extract` returns absent rather than
walking a header sized to burn CPU. This makes the parse bound the library's own guarantee, not
the ASGI server's header cap (a dependency default). Starlette decodes the cookie bytes 1:1 to
latin-1 characters, so the character count is the byte count (D-193).
"""
MAX_COOKIE_PAIRS = 512
"""The most `name=value` pairs `extract` will parse from one Cookie header, above any real browser."""
SESSION_TOKEN_SUFFIX = ".session_token"
SESSION_DATA_SUFFIX = ".session_data"
DATA_COOKIE_FALLBACK = "better-auth.session_data"


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class ParsedCookie:
    """A structurally valid signed cookie, split into its two parts and nothing believed yet.

    `token` is the raw session token the store is keyed by; `signature` is the 44-character
    standard-base64 HMAC the verifier still has to check against its keyring. Both are live
    credential material, so the repr renders neither - a record reaches tracebacks and error
    reporters like anything else.
    """

    token: str
    signature: str

    def __repr__(self) -> str:
        return "ParsedCookie(token=<redacted>, signature=<redacted>)"


def cookie_pairs(header: str) -> tuple[tuple[str, str], ...]:
    """Every `name=value` in a raw Cookie header, in order, duplicates kept.

    Split on `;`, then each pair on its *first* `=` (RFC 6265 §5.4), so a base64 value's own `=`
    padding survives in the value. A fragment with no `=` is not a cookie pair and is dropped.
    Reading the raw header rather than `request.cookies` is deliberate: Starlette collapses
    duplicate names with an unstated precedence, and a duplicate session cookie is exactly what the
    verifier has to be able to see and refuse.
    """
    pairs: list[tuple[str, str]] = []
    for fragment in header.split(";"):
        name, separator, value = fragment.strip().partition("=")
        if separator:
            pairs.append((name.strip(), value.strip()))
    return tuple(pairs)


def acceptable_names(base: str) -> frozenset[str]:
    """Every cookie name this verifier will treat as its own: the base and its chunk names.

    The single configured base - `secure_cookies` decides whether that is the `__Secure-`-prefixed
    name or the plain one, never both - joined by every chunk index Better Auth may split a long
    cookie across. A name outside this set is another cookie's and is never read. Accepting only
    the one configured name is what closes the cross-name session fixation: a sibling subdomain
    that plants the *other* name is not read at all (D-189).
    """
    names: set[str] = {base}
    for index in range(MAX_CHUNKS):
        names.add(f"{base}.{index}")
    return frozenset(names)


def session_data_names(
    cookie_name: str, secure_prefix: str, secure_cookies: bool
) -> frozenset[str]:
    """The name of the cookie-cache `session_data` cookie this verifier must never parse.

    Derived from the token cookie by swapping the `session_token` suffix for `session_data`, so a
    renamed token cookie keeps them aligned; falls back to Better Auth's default when the name does
    not carry that suffix. One base, matching the `secure_cookies` choice the token cookie uses, so
    it emits the same single name the acceptable set does. The verifier warns once if it sees one
    (CVE-2026-67337) and reads it for nothing else.
    """
    if cookie_name.endswith(SESSION_TOKEN_SUFFIX):
        data = cookie_name[: -len(SESSION_TOKEN_SUFFIX)] + SESSION_DATA_SUFFIX
    else:
        data = DATA_COOKIE_FALLBACK
    return frozenset({f"{secure_prefix}{data}" if secure_cookies else data})


def resolve_named_cookie(pairs: tuple[tuple[str, str], ...], base: str) -> tuple[str, str]:
    """The single configured base's `(name, value)`, reassembled if it arrived chunked.

    The name is always the `base` - the one name the audit's D-189 fix accepts, never a second
    accept-both name - and the value is a single whole cookie or a contiguous run of chunks
    joined in index order. A base carrying both a whole cookie and chunks, a duplicated name, or
    a chunk run with a gap, a repeat or a missing index 0 is refused: a server emits none of
    those shapes.

    Mode C forwards exactly this pair as its outbound `cookie:` header, under the base name the
    browser sent (`__Secure-` preserved verbatim), value still percent-encoded.

    Raises:
        InvalidCredential: For any malformed set, and (defensively) if the base has no material.
    """
    try:
        value = _value_for_base(pairs, base)
        if value is not None:
            return base, value
        # extract only dispatches when an acceptable name was present, so this is unreachable
        # through the real entry point; refused rather than returned so no direct caller gets ""
        raise InvalidCredential(reason="no session cookie material after resolution")
    finally:
        pairs = ()


def resolve_cookie_value(pairs: tuple[tuple[str, str], ...], base: str) -> str:
    """The one signed cookie value these pairs carry for the single configured base.

    The `.value` projection of `resolve_named_cookie`, kept as the name Mode A reads (the cookie
    verifier needs the value, never the name it resolved under, because it already knows the base).

    Raises:
        InvalidCredential: For any malformed set, and (defensively) if the base has no material.
    """
    try:
        return resolve_named_cookie(pairs, base)[1]
    finally:
        pairs = ()


def parse_signed_value(material: str) -> ParsedCookie:
    """A raw cookie value down to `(token, signature)`, or an `InvalidCredential` naming the flaw.

    The pipeline is exact Better Auth (better-call) parity: `unquote(errors='strict')` once, split
    at the *last* dot, a non-empty token, and a signature of exactly 44 standard-base64 characters
    decoding to 32 bytes. One frame holds every credential local, and `finally` scrubs them.
    """
    marker = fingerprint(material)
    decoded = token = signature = ""
    digest = b""
    try:
        length = len(material)
        if length > MAX_COOKIE_BYTES:
            raise InvalidCredential(
                reason=f"cookie value is {length} bytes, over the cap [{marker}]"
            )
        try:
            decoded = urllib.parse.unquote(material, errors="strict")
        except UnicodeDecodeError:
            raise InvalidCredential(
                reason=f"cookie value is not valid percent-encoded UTF-8 [{marker}]"
            ) from None
        token, separator, signature = decoded.rpartition(".")
        if not separator:
            raise InvalidCredential(
                reason=f"cookie value carries no signature separator [{marker}]"
            )
        if not token:
            raise InvalidCredential(reason=f"cookie value has an empty token [{marker}]")
        length = len(signature)
        required = SIGNATURE_LENGTH
        if length != required:
            raise InvalidCredential(
                reason=f"signature is {length} characters, not {required} [{marker}]"
            )
        try:
            digest = base64.b64decode(signature, validate=True)
        except (binascii.Error, ValueError):
            raise InvalidCredential(reason=f"signature is not standard base64 [{marker}]") from None
        length = len(digest)
        if length != HMAC_BYTES:
            raise InvalidCredential(
                reason=f"signature does not decode to {HMAC_BYTES} bytes [{marker}]"
            )
        result = ParsedCookie(token=token, signature=signature)
    finally:
        material = decoded = token = signature = ""
        digest = b""
    return result


def _value_for_base(pairs: tuple[tuple[str, str], ...], base: str) -> str | None:
    """The value one base carries: a single whole cookie, its reassembled chunks, or None.

    Holds cookie material in the `pairs` argument and in `whole`/`chunks`, so it scrubs all three
    in `finally` before any raise can put them on a traceback (D-094).
    """
    whole = [value for name, value in pairs if name == base]
    chunks = [(int(name[len(base) + 1 :]), value) for name, value in pairs if _is_chunk(name, base)]
    try:
        if not whole and not chunks:
            return None
        if whole and chunks:
            raise InvalidCredential(
                reason=f"the {base!r} cookie arrived both whole and chunked; a server sends one or"
                " the other"
            )
        if whole:
            if len(whole) > 1:
                raise InvalidCredential(
                    reason=f"the {base!r} cookie name appears more than once on one request"
                )
            return whole[0]
        return _reassembled(chunks, base)
    finally:
        pairs = ()
        whole.clear()
        chunks.clear()


def _is_chunk(name: str, base: str) -> bool:
    prefix = f"{base}."
    if not name.startswith(prefix):
        return False
    suffix = name[len(prefix) :]
    # `.isascii()` guards `int()`: `'²'.isdigit()` is True but `int('²')` raises.
    # Unreachable via extract (acceptable_names is ASCII), but this stays safe on a direct caller.
    return suffix.isascii() and suffix.isdigit() and int(suffix) < MAX_CHUNKS


def _reassembled(chunks: list[tuple[int, str]], base: str) -> str:
    """Concatenate a contiguous chunk run from 0, or refuse a gap, a repeat or a missing first.

    Holds the raw chunk values in `ordered`/`value`, so the contiguity check runs INSIDE the
    scrubbed region and both are cleared in `finally` (D-094). The `chunks` argument is the same
    list `_value_for_base` clears in its own finally, so it is not re-cleared here.
    """
    ordered = sorted(chunks, key=lambda item: item[0])
    value = ""
    try:
        indices = [index for index, _ in ordered]
        if indices != list(range(len(indices))):
            raise InvalidCredential(
                reason=f"the {base!r} cookie chunks are not a contiguous run from 0; a gap, a"
                " repeat or a missing first chunk is refused"
            )
        value = "".join(chunk_value for _, chunk_value in ordered)
        length = len(value)
        if length > MAX_COOKIE_BYTES:
            raise InvalidCredential(
                reason=f"the reassembled {base!r} cookie is {length} bytes, over the cap"
            )
        return value
    finally:
        value = ""
        ordered.clear()
