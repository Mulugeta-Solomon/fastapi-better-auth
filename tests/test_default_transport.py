"""A verifier handed no `transport=` builds one at construction, and says what to do when it can't.

`JwtVerifier` and `RemoteVerifier` build their default `HttpxTransport` eagerly and on purpose: a
Mode B or Mode C deployment missing its HTTP client stops at startup instead of answering its first
request with a 500. That makes this refusal the first thing a `[sqlalchemy]`-only install meets
when it copies a Mode B line (#65), so its text is product: it names the verifier, both remedies
that work, and why construction is the moment. The adapters' own message, for a missing library,
may only offer remedies that can work - "build the client yourself" is not one when the client's
library is exactly what is absent.

Blocked through `sys.modules[name] = None`, which makes `import name` raise `ImportError` the way
an environment without the package does, and is undone by `monkeypatch` after each test.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import cast

import pytest

from fastapi_better_auth import (
    ConfigurationError,
    Httpx2Transport,
    HttpxTransport,
    JwtVerifier,
    OriginCheck,
    RemoteVerifier,
    Transport,
)
from fastapi_better_auth._internal import jwt_verifier as jwt_verifier_module
from fastapi_better_auth._internal import remote_config as remote_config_module

ORIGIN = "https://auth.example.com"
FRONT_END = "https://app.example.com"

INSTALL_HTTPX = 'pip install "fastapi-better-auth-bridge[httpx]"'
INSTALL_HTTPX2 = 'pip install "fastapi-better-auth-bridge[httpx2]"'
SECOND_REMEDY = "transport=Httpx2Transport()"
UNREAL_REMEDY = "client="


def jwt_verifier(transport: Transport | None) -> object:
    return JwtVerifier(base_url=ORIGIN, transport=transport)


def remote_verifier(transport: Transport | None) -> object:
    return RemoteVerifier(
        base_url=ORIGIN, csrf=OriginCheck(allowed_origins=[FRONT_END]), transport=transport
    )


VERIFIERS: dict[str, Callable[[Transport | None], object]] = {
    "JwtVerifier": jwt_verifier,
    "RemoteVerifier": remote_verifier,
}

ADAPTERS: dict[str, tuple[Callable[[], Transport], str, str]] = {
    "httpx": (HttpxTransport, "Httpx2Transport", INSTALL_HTTPX2),
    "httpx2": (Httpx2Transport, "HttpxTransport", INSTALL_HTTPX),
}
"""Library -> (the adapter over it, its sibling adapter, the install line of the sibling's extra)."""


def no_transport(verifier: str) -> Transport:
    """A default builder gone wrong: it swallowed its own refusal and built nothing."""
    return cast("Transport", None)


class ShapedButBroken:
    """The two names the `Transport` Protocol checks for, neither of them callable."""

    get = "not a coroutine function"
    post = 0


def shaped_but_broken(verifier: str) -> Transport:
    return cast("Transport", ShapedButBroken())


BROKEN_DEFAULTS: dict[str, Callable[[str], Transport]] = {
    "NoneType": no_transport,
    "ShapedButBroken": shaped_but_broken,
}


def refusal_without_httpx(name: str, monkeypatch: pytest.MonkeyPatch) -> ConfigurationError:
    monkeypatch.setitem(sys.modules, "httpx", None)
    with pytest.raises(ConfigurationError) as caught:
        VERIFIERS[name](None)
    return caught.value


@pytest.mark.parametrize("name", sorted(VERIFIERS))
def test_the_refusal_names_the_verifier_and_both_remedies(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    message = str(refusal_without_httpx(name, monkeypatch))

    assert message.startswith(f"{name} "), message
    assert INSTALL_HTTPX in message, message
    assert SECOND_REMEDY in message, message
    assert INSTALL_HTTPX2 in message, message


@pytest.mark.parametrize("name", sorted(VERIFIERS))
def test_the_refusal_says_why_construction_needs_the_library(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The eager build is the design, so the message has to say so - or it reads as a bug to
    work around, and the first workaround anyone reaches for is a lazy import."""
    message = str(refusal_without_httpx(name, monkeypatch))

    assert "at construction" in message, message
    assert "stops the application from starting" in message, message
    assert UNREAL_REMEDY not in message, message


@pytest.mark.parametrize("name", sorted(VERIFIERS))
def test_the_refusal_is_chained_to_the_import_that_failed(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Chained exactly as the adapter's own refusal is: nothing secret is involved, and the
    `ImportError` underneath is what tells an operator which import path Python walked."""
    refusal = refusal_without_httpx(name, monkeypatch)

    assert isinstance(refusal.__cause__, ImportError)


@pytest.mark.parametrize("name", sorted(VERIFIERS))
def test_the_second_remedy_works_with_httpx_absent(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A remedy the message names has to be one that runs: `httpx2` alone is enough."""
    monkeypatch.setitem(sys.modules, "httpx", None)

    assert VERIFIERS[name](Httpx2Transport()) is not None


@pytest.mark.parametrize("built", sorted(BROKEN_DEFAULTS))
@pytest.mark.parametrize("name", sorted(VERIFIERS))
def test_a_default_that_is_not_a_transport_is_refused_by_the_verifier(
    name: str, built: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G18's eager-transport invariant may not rest on one call raising: whatever the default
    builder hands back is checked by the verifier that will fetch with it, and refused in its name.
    A shaped-but-broken object passes the runtime `Transport` Protocol, which checks only that the
    two names are present, so the default is held to the library's own transport family."""
    for module in (jwt_verifier_module, remote_config_module):
        monkeypatch.setattr(module, "default_transport", BROKEN_DEFAULTS[built])

    with pytest.raises(ConfigurationError) as caught:
        VERIFIERS[name](None)

    message = str(caught.value)
    assert message.startswith(f"{name} "), message
    assert built in message, message


@pytest.mark.parametrize("library", sorted(ADAPTERS))
def test_an_adapter_missing_its_library_offers_only_remedies_that_can_work(
    library: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`client=` wants an `AsyncClient` of the very library that is not installed, so it cannot
    be the answer here; installing the extra, or switching to the sibling adapter, can."""
    build, sibling, install_sibling = ADAPTERS[library]
    monkeypatch.setitem(sys.modules, library, None)

    with pytest.raises(ConfigurationError) as caught:
        build()

    message = str(caught.value)
    assert f'pip install "fastapi-better-auth-bridge[{library}]"' in message, message
    assert f"{sibling}()" in message, message
    assert install_sibling in message, message
    assert UNREAL_REMEDY not in message, message
    assert isinstance(caught.value.__cause__, ImportError)
