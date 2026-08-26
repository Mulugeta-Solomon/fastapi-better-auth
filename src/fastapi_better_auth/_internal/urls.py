"""Origin normalization: one spelling of the operator's Better Auth server, settled once."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from types import MappingProxyType
from urllib.parse import SplitResult, urlsplit

from .errors import ConfigurationError

ALLOWED_SCHEMES = ("https", "http")
DEFAULT_PORTS: Mapping[str, int] = MappingProxyType({"https": 443, "http": 80})
EXAMPLE = "https://auth.example.com"
HOSTNAME = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*")
MAX_HOST_LENGTH = 253


def normalize_base_url(value: str, *, field: str = "base_url") -> str:
    """Reduce an operator-supplied URL to its canonical origin, or refuse it.

    Call this in a verifier's `__init__` on every URL it takes from configuration, and
    keep the value it returns:

        class HeaderVerifier:
            def __init__(self, base_url: str) -> None:
                self.base_url = normalize_base_url(base_url)

    Everything a verifier derives from configuration - the JWKS URL it will fetch, the
    issuer and audience it will require, the origins it will trust - is built from this
    string, and comparisons against it are exact. Two spellings of one origin would
    therefore be two origins, so the string is canonicalized once, while the application
    is being constructed, and the canonical form is what everything downstream sees.

    Accepted input is an origin and nothing else: a scheme, a host, and an optional port.
    A path, a query, a fragment or embedded credentials are rejected rather than silently
    dropped, because each of them means the caller believed this value was something it is
    not.

    The host must be an ASCII hostname or an IP literal. A non-ASCII host is refused
    rather than converted, because the conversion is where the two dangerous things live:
    several Unicode codepoints are IDNA *label separators*, so a host that reads as
    `auth.example.com` in configuration can be fetched from a subdomain of somewhere else
    entirely - while still comparing equal as an issuer, because it is compared against
    the same spelling. Pass the punycode (`xn--`) form if you need an international domain.

    `http` is accepted only for a loopback host. A key set fetched over cleartext can be
    replaced by anyone on the path, and a substituted key set is a complete authentication
    bypass with no signature left to fall back on.

    Canonicalization lowercases the scheme and host, drops one trailing slash and one
    trailing dot, compresses IP literals, and removes the port when it is the scheme's
    default, so `HTTPS://Auth.Example.COM:443/` and `https://auth.example.com` are one
    value. The result is idempotent: normalizing it again returns it unchanged.

    Args:
        value: The URL as the operator wrote it, typically from configuration or an
            environment variable.
        field: The setting name to blame in the error message, when one helper serves
            several settings.

    Returns:
        The canonical origin, with no trailing slash - for example
        `https://auth.example.com`.

    Raises:
        ConfigurationError: If the value is not a usable origin. The message names what is
            wrong and shows the form that would have been accepted. Configuration is
            validated while the application is being built, so this never becomes a
            request-time response.
    """
    text = _as_text(value, field)
    split = _split(text, field)
    scheme = _scheme(split, field)
    _reject_userinfo(split, field)
    host, loopback = _canonical_host(split, field)
    if scheme == "http" and not loopback:
        raise ConfigurationError(
            f"{field} uses http for {host!r}. A key set or session fetched over cleartext"
            " can be replaced by anyone on the network path, and a substituted key set is a"
            " complete authentication bypass. http is accepted only for a loopback host"
            f" (localhost, 127.0.0.0/8, ::1); use https for anything else."
        )
    origin = f"{scheme}://{host}{_port(split, scheme, field)}"
    _reject_extras(split, origin, field)
    return origin


def _as_text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ConfigurationError(
            f"{field} must be a string; got {type(value).__name__}."
            f" Pass an origin such as {EXAMPLE!r}."
        )
    text = value.strip()
    if any(char.isspace() or char < "\x20" or char == "\x7f" for char in text):
        raise ConfigurationError(
            f"{field} must not contain whitespace or control characters."
            f" Pass an origin such as {EXAMPLE!r}."
        )
    return text


def _split(text: str, field: str) -> SplitResult:
    try:
        split = urlsplit(text)
        _parseable_port = split.port
    except ValueError as exc:
        raise ConfigurationError(
            f"{field} is not a usable URL. Pass an origin such as {EXAMPLE!r}."
        ) from exc
    return split


def _scheme(split: SplitResult, field: str) -> str:
    if not split.scheme:
        raise ConfigurationError(
            f"{field} must include a scheme. Pass an origin such as {EXAMPLE!r}, not a bare host."
        )
    if split.scheme not in ALLOWED_SCHEMES:
        raise ConfigurationError(
            f"{field} must use the https or http scheme; got {split.scheme!r}."
            f" Pass an origin such as {EXAMPLE!r}."
        )
    return split.scheme


def _reject_userinfo(split: SplitResult, field: str) -> None:
    if split.username is not None or split.password is not None:
        raise ConfigurationError(
            f"{field} must not carry credentials in the URL. Pass an origin such as {EXAMPLE!r}."
        )


def _canonical_host(split: SplitResult, field: str) -> tuple[str, bool]:
    """The authority host, in the exact spelling that will later be dialled."""
    raw = split.hostname
    if not raw:
        raise ConfigurationError(
            f"{field} must include a host. Pass an origin such as {EXAMPLE!r}."
        )
    if ":" in raw:
        address = ip_literal(raw, field)
        return f"[{address.compressed}]", address.is_loopback
    if not raw.isascii():
        raise ConfigurationError(
            f"{field} must have an ASCII host. Several Unicode characters are IDNA label"
            " separators, so a non-ASCII host can be fetched from a different domain than"
            " the one it reads as. Pass the punycode ('xn--') form."
        )
    host = raw.removesuffix(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not HOSTNAME.fullmatch(host) or len(host) > MAX_HOST_LENGTH:
            raise ConfigurationError(
                f"{field} has an unusable host {host!r}. A host is letters, digits, hyphens"
                f" and dots, or an IP literal. Pass an origin such as {EXAMPLE!r}."
            ) from None
        return host, host == "localhost"
    return address.compressed, address.is_loopback


def ip_literal(raw: str, field: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    unusable = (
        f"{field} has an unusable IPv6 host. Pass a bracketed literal such as"
        " 'https://[::1]', with no zone identifier."
    )
    if "%" in raw:
        raise ConfigurationError(unusable)
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        raise ConfigurationError(unusable) from None
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        raise ConfigurationError(
            f"{field} must not use an IPv4-mapped IPv6 host: CPython renders it - and"
            " answers is_loopback for it - differently before and after 3.13, so the"
            " canonical origin would change under a Python upgrade and stop matching the"
            f" issuer it is compared against. Pass 'https://{mapped}' instead."
        )
    return address


def _port(split: SplitResult, scheme: str, field: str) -> str:
    port = split.port
    if port is None or port == DEFAULT_PORTS[scheme]:
        return ""
    if port == 0:
        raise ConfigurationError(
            f"{field} must not use port 0, which is not a port anything can be reached on."
        )
    return f":{port}"


def _reject_extras(split: SplitResult, origin: str, field: str) -> None:
    if split.path not in ("", "/"):
        raise ConfigurationError(
            f"{field} must be an origin with no path; got the path {split.path!r}. Pass {origin!r}."
        )
    if split.query:
        raise ConfigurationError(
            f"{field} must be an origin with no query string. Pass {origin!r}."
        )
    if split.fragment:
        raise ConfigurationError(f"{field} must be an origin with no fragment. Pass {origin!r}.")
