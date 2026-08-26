"""`base_url` is an origin, canonicalized once at startup — never a string compared later.

Every verifier that pins a JWKS URL, an issuer or an audience derives it from this value
(D-010: never from the request), so two spellings of one origin must not be two origins.
The helper answers with the canonical form or raises `ConfigurationError`; there is no
third outcome and no request-time path into it.
"""

from __future__ import annotations

import pytest

from fastapi_better_auth import ConfigurationError
from fastapi_better_auth._internal.urls import ip_literal, normalize_base_url

CANONICAL: tuple[tuple[str, str], ...] = (
    ("https://auth.example.com", "https://auth.example.com"),
    ("https://auth.example.com/", "https://auth.example.com"),
    ("HTTPS://Auth.Example.COM/", "https://auth.example.com"),
    ("https://AUTH.example.com", "https://auth.example.com"),
    ("https://auth.example.com:443", "https://auth.example.com"),
    ("https://auth.example.com:443/", "https://auth.example.com"),
    ("http://localhost:80", "http://localhost"),
    ("http://localhost", "http://localhost"),
    ("https://auth.example.com:8443", "https://auth.example.com:8443"),
    ("https://auth.example.com:80", "https://auth.example.com:80"),
    ("http://127.0.0.1:3000", "http://127.0.0.1:3000"),
    ("http://[::1]:3000", "http://[::1]:3000"),
    ("https://[::1]:8443", "https://[::1]:8443"),
    ("https://[::1]:443", "https://[::1]"),
    ("  https://auth.example.com  ", "https://auth.example.com"),
    ("https://auth.example.com.", "https://auth.example.com"),
    ("https://[0:0:0:0:0:0:0:1]", "https://[::1]"),
    ("https://Keys.example.com", "https://keys.example.com"),
)

REJECTED: tuple[tuple[str, str, str], ...] = (
    ("bare-host", "auth.example.com", "scheme"),
    ("scheme-relative", "//auth.example.com", "scheme"),
    ("unsupported-scheme", "ftp://auth.example.com", "ftp"),
    ("file-scheme", "file:///etc/passwd", "file"),
    ("empty", "", "scheme"),
    ("whitespace-only", "   ", "scheme"),
    ("no-host", "https://", "host"),
    ("no-host-with-path", "https:///api/auth", "host"),
    ("path", "https://auth.example.com/api/auth", "path"),
    ("path-deep", "https://auth.example.com/a/b/", "path"),
    ("query", "https://auth.example.com?tenant=acme", "query"),
    ("query-after-slash", "https://auth.example.com/?tenant=acme", "query"),
    ("fragment", "https://auth.example.com#frag", "fragment"),
    ("embedded-newline", "https://auth.exa\nmple.com", "whitespace"),
    ("embedded-tab", "https://auth.exa\tmple.com", "whitespace"),
    ("embedded-space", "https://auth.exa mple.com", "whitespace"),
    ("control-character", "https://auth.example.com\x7f", "whitespace"),
    ("ideographic-full-stop", "https://auth.example.com。evil.example", "ASCII"),
    ("fullwidth-full-stop", "https://auth.example.com．evil.example", "ASCII"),
    ("halfwidth-ideographic-stop", "https://auth.example.com｡evil.example", "ASCII"),
    ("zero-width-space", "https://auth.exa\u200bmple.com", "ASCII"),
    ("cyrillic-homograph", "https://аuth.example.com", "ASCII"),
    ("backslash-host", "https://auth.example.com\\evil.example", "host"),
    ("percent-encoded-null", "https://auth.example.com%00.evil.example", "host"),
    ("bare-dot", "https://.", "host"),
    ("double-dot", "https://..", "host"),
    ("empty-label", "https://auth..example.com", "host"),
    ("leading-hyphen-label", "https://-auth.example.com", "host"),
    ("trailing-hyphen-label", "https://auth-.example.com", "host"),
    ("underscore-label", "https://auth_server.example.com", "host"),
    ("ipv6-zone-id", "https://[fe80::1%25eth0]", "host"),
    ("ipv4-mapped-ipv6", "https://[::ffff:127.0.0.1]", "IPv4-mapped"),
    ("ipv4-mapped-cleartext", "http://[::FFFF:10.0.0.5]", "IPv4-mapped"),
    ("port-zero", "https://auth.example.com:0", "port"),
    ("cleartext-public-host", "http://auth.example.com", "https"),
    ("cleartext-private-ip", "http://10.0.0.5:3000", "https"),
    ("cleartext-link-local", "http://169.254.169.254", "https"),
)

LOOPBACK_HTTP = ("http://localhost", "http://127.0.0.1", "http://[::1]", "http://127.0.0.2:8080")


@pytest.mark.parametrize(("raw", "expected"), CANONICAL, ids=[c[0] for c in CANONICAL])
def test_accepted_forms_canonicalize(raw: str, expected: str) -> None:
    assert normalize_base_url(raw) == expected


@pytest.mark.parametrize(("raw", "expected"), CANONICAL, ids=[c[0] for c in CANONICAL])
def test_normalization_is_idempotent(raw: str, expected: str) -> None:
    """A value that survives one pass must survive every later one unchanged."""
    once = normalize_base_url(raw)

    assert normalize_base_url(once) == once
    assert normalize_base_url(expected) == expected


@pytest.mark.parametrize(
    ("raw", "needle"), [(r[1], r[2]) for r in REJECTED], ids=[r[0] for r in REJECTED]
)
def test_rejected_forms_raise_and_name_the_fault(raw: str, needle: str) -> None:
    with pytest.raises(ConfigurationError) as caught:
        normalize_base_url(raw)

    assert needle in str(caught.value), f"the message does not name what is wrong: {caught.value}"


@pytest.mark.parametrize("raw", LOOPBACK_HTTP)
def test_cleartext_is_allowed_only_for_a_loopback_host(raw: str) -> None:
    """A local development server is the one place nobody can sit on the path."""
    assert normalize_base_url(raw).startswith("http://")


def test_the_canonical_host_is_the_host_that_will_be_dialled() -> None:
    """The homograph attack this closes: U+3002 is an IDNA label separator, so a host
    stored verbatim as `auth.example.com。evil.example` - and compared equal as an issuer -
    is fetched from a subdomain of `evil.example`."""
    smuggled = "auth.example.com。evil.example"

    assert smuggled.encode("idna") == b"auth.example.com.evil.example", "retune this probe"
    with pytest.raises(ConfigurationError) as caught:
        normalize_base_url(f"https://{smuggled}")

    assert "ASCII" in str(caught.value)


def test_a_cleartext_rejection_says_what_is_actually_at_risk() -> None:
    with pytest.raises(ConfigurationError) as caught:
        normalize_base_url("http://auth.example.com")

    message = str(caught.value)
    assert "https" in message
    assert "loopback" in message


def test_credentials_in_the_url_are_rejected_and_never_echoed() -> None:
    """A password in a config string reaches logs and tracebacks; do not repeat it."""
    with pytest.raises(ConfigurationError) as caught:
        normalize_base_url("https://admin:hunter2@auth.example.com")

    message = str(caught.value)
    assert "credential" in message
    assert "hunter2" not in message
    assert "admin" not in message


def test_a_rejected_path_shows_the_origin_that_would_have_been_accepted() -> None:
    with pytest.raises(ConfigurationError) as caught:
        normalize_base_url("https://auth.example.com/api/auth")

    assert "https://auth.example.com" in str(caught.value)


def test_the_field_name_appears_in_every_message() -> None:
    """One helper serves several settings; the operator must learn which one is wrong."""
    with pytest.raises(ConfigurationError) as caught:
        normalize_base_url("nope", field="jwks_url")

    assert "jwks_url" in str(caught.value)


@pytest.mark.parametrize(
    "raw",
    ["https://auth.example.com:notaport", "https://auth.example.com:99999", "https://[::1"],
    ids=["non-numeric-port", "out-of-range-port", "unclosed-ipv6"],
)
def test_a_url_python_itself_refuses_to_parse_is_a_configuration_error(raw: str) -> None:
    """`urlsplit` defers its port parsing, so the failure surfaces on attribute access."""
    with pytest.raises(ConfigurationError):
        normalize_base_url(raw)


def test_an_ipv4_mapped_host_is_refused_because_python_renders_it_two_ways() -> None:
    """`IPv6Address('::ffff:127.0.0.1')` compresses to `::ffff:7f00:1` before CPython 3.13
    and `::ffff:127.0.0.1` after, and `is_loopback` flips with it. Either would make the
    canonical origin - the string an `iss` claim is compared against - depend on the
    interpreter, and would move the cleartext exemption under a Python upgrade."""
    with pytest.raises(ConfigurationError) as caught:
        normalize_base_url("https://[::ffff:127.0.0.1]")

    assert "127.0.0.1" in str(caught.value)


def test_a_bracketed_host_that_is_not_an_address_is_rejected() -> None:
    """Driven at the helper, because `urlsplit` validates bracketed hosts itself on the
    Pythons that carry the fix - and does not on every version this package supports."""
    with pytest.raises(ConfigurationError) as caught:
        ip_literal("::1::2", "base_url")

    assert "IPv6" in str(caught.value)


def test_a_non_string_is_a_configuration_error_not_a_type_error() -> None:
    with pytest.raises(ConfigurationError):
        normalize_base_url(None)  # pyright: ignore[reportArgumentType]

    with pytest.raises(ConfigurationError):
        normalize_base_url(b"https://auth.example.com")  # pyright: ignore[reportArgumentType]


def test_configuration_errors_are_not_answerable_as_a_response() -> None:
    """Prove the instrument: a `SessionError` here would be a request-time 401 instead."""
    with pytest.raises(ConfigurationError) as caught:
        normalize_base_url("auth.example.com")

    assert not hasattr(caught.value, "status_code")
