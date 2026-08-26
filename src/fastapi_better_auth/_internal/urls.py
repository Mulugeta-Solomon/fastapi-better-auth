"""Origin normalization: one spelling of the operator's Better Auth server, settled once."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from urllib.parse import SplitResult, urlsplit

from .errors import ConfigurationError

ALLOWED_SCHEMES = ("https", "http")
DEFAULT_PORTS: Mapping[str, int] = MappingProxyType({"https": 443, "http": 80})
EXAMPLE = "https://auth.example.com"


def normalize_base_url(value: str, *, field: str = "base_url") -> str:
    """Reduce an operator-supplied URL to its canonical origin, or refuse it.

    Everything a verifier derives from configuration - the JWKS URL it will fetch, the
    issuer and audience it will require, the origins it will trust - is built from this
    string, and comparisons against it are exact. Two spellings of one origin would
    therefore be two origins, so the string is canonicalized once, at startup, and the
    canonical form is what the rest of the library ever sees.

    Accepted input is an origin and nothing else: a scheme (`https`, or `http` for a local
    development server), a host, and an optional port. A path, a query, a fragment or
    embedded credentials are rejected rather than silently dropped, because each of them
    means the caller believed this value was something it is not.

    Canonicalization lowercases the scheme and host, drops a single trailing slash, and
    removes the port when it is the scheme's default, so `HTTPS://Auth.Example.COM:443/`
    and `https://auth.example.com` are one value. The result is idempotent: normalizing it
    again returns it unchanged.

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
    origin = f"{scheme}://{_authority(split, scheme, field)}"
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
        _port_is_parseable = split.port
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


def _authority(split: SplitResult, scheme: str, field: str) -> str:
    host = split.hostname
    if not host:
        raise ConfigurationError(
            f"{field} must include a host. Pass an origin such as {EXAMPLE!r}."
        )
    bracketed = f"[{host}]" if ":" in host else host
    port = split.port
    if port is None or port == DEFAULT_PORTS[scheme]:
        return bracketed
    return f"{bracketed}:{port}"


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
