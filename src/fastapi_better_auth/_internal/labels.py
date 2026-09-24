"""The `credential_source` labels this package reads: what one says, and when two say the same.

A label is written by whoever wrote the verifier, and three places read it: the OpenAPI scheme it
publishes, the operator-facing text that names a verifier, and the construction-time check that no
two verifiers read one credential. They read it through this module, so they cannot disagree about
what a label means.
"""

from __future__ import annotations

BEARER_SOURCE = "header:authorization-bearer"
COOKIE_PREFIX = "cookie:"

BROWSER_COOKIE_PREFIXES = ("__secure-", "__host-")
"""The cookie-name prefixes a user agent enforces, casefolded: it matches them case-insensitively
(RFC 6265bis §5.4), so `__secure-sid` is as much a secure-prefixed cookie as `__Secure-sid`."""


def cookie_source(cookie: str) -> str:
    """The label of a verifier that reads the cookie named `cookie`, exactly as the browser sends it."""
    return f"{COOKIE_PREFIX}{cookie}"


def cookie_named(source: str) -> str | None:
    """The cookie a `cookie:<name>` label names, or `None` for any other label.

    The `cookie:` prefix is matched case-insensitively and the name is kept verbatim: a cookie name
    is case-sensitive, so `__Secure-` may not be folded away.
    """
    stripped = source.strip()
    if not stripped.casefold().startswith(COOKIE_PREFIX):
        return None
    name = stripped[len(COOKIE_PREFIX) :].strip()
    return name or None


def collision_key(source: str) -> str:
    """What two labels share when their verifiers would find one credential.

    Casefolded, as every label comparison here is. A cookie label is reduced to its base: the
    cookie's name with every leading `__Secure-` and `__Host-` removed. The plain and the prefixed
    spellings of one base are how Better Auth names one session cookie in its two postures, and
    reading both is the cross-name fixation shape. A configured name may itself begin with a
    prefix, so the secure posture of `__Host-x` reads `__Secure-__Host-x`: one strip would leave
    it looking unrelated to the plain `__Host-x`. Any other leading text is part of an unrelated
    name, because no browser gives it a meaning.
    """
    cookie = cookie_named(source)
    if cookie is None:
        return source.strip().casefold()
    return cookie_source(_base(cookie.casefold()))


def _base(folded: str) -> str:
    while True:
        prefix = next((p for p in BROWSER_COOKIE_PREFIXES if folded.startswith(p)), None)
        if prefix is None:
            return folded
        folded = folded[len(prefix) :]
