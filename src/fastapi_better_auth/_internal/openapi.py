"""What `/docs` is told about the credentials this application accepts."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Sequence

from fastapi import Depends, Security
from fastapi.openapi.models import SecurityBase as SecuritySchemeModel
from fastapi.security import APIKeyCookie, HTTPBearer
from fastapi.security.base import SecurityBase
from starlette.requests import HTTPConnection

from .errors import ConfigurationError
from .verifiers import Verifier

BEARER_SOURCE = "header:authorization-bearer"
COOKIE_PREFIX = "cookie:"

BEARER_SCHEME_NAME = "BetterAuthBearer"
COOKIE_SCHEME_PREFIX = "BetterAuthCookie-"

BEARER_DESCRIPTION = (
    "The session token your Better Auth server issued, sent as `Authorization: Bearer <token>`."
)
COOKIE_DESCRIPTION = (
    "The Better Auth session cookie `{name}`, which the browser sends on its own once the"
    " user has signed in."
)

UNSAFE_IN_A_NAME = re.compile(r"[^A-Za-z0-9._-]")
"""An OpenAPI component key is `[a-zA-Z0-9._-]+`; a cookie name may hold more than that."""

Declaration = Callable[..., Awaitable[None]]


class DeclaredScheme(SecurityBase):
    """A security scheme this library publishes and never runs.

    FastAPI collects a `SecurityRequirement` from any dependency that is a `SecurityBase`,
    which is what puts the scheme in `components.securitySchemes`, the requirement on every
    operation, and the Authorize button on `/docs`. It also *calls* that dependency on every
    request - and the shipped schemes are the wrong thing to call here, twice over.

    They read the credential. A second reader is a second answer to "what did this request
    present", and the one that decides is supposed to be the verifier, which extracts from
    the connection itself. Declaring the scheme without ever asking it anything is the only
    shape in which that cannot drift.

    And `fastapi.security.HTTPBearer.__call__` takes a `Request`, which FastAPI fills only on
    an HTTP connection. A WebSocket route carrying our dependency would have raised
    `TypeError: missing 1 required positional argument: 'request'` on every connection. This
    takes the `HTTPConnection` both kinds of route have, and reads nothing off it.

    The `model` is built by the real `fastapi.security` class and taken from it, so the
    published definition is byte-for-byte what any other FastAPI application would publish.
    """

    def __init__(self, *, model: SecuritySchemeModel, scheme_name: str) -> None:
        self.model = model
        self.scheme_name = scheme_name

    async def __call__(self, connection: HTTPConnection) -> None:
        """Nothing. The connection is read by verifiers, and by nothing else in this package."""


def schemes_for(verifiers: Sequence[Verifier]) -> tuple[DeclaredScheme, ...]:
    """The schemes a set of verifiers documents, in the order they were declared.

    A verifier whose `credential_source` this module cannot read contributes nothing. That is
    deliberate: the label is an honesty contract about where a credential lives, and a scheme
    invented for a label nobody wrote to that contract would tell every reader of the document
    the wrong place to put one.

    Raises:
        ConfigurationError: If two labels sanitize onto one OpenAPI component key, which would
            publish one definition under a name the other also claims.
    """
    declared: list[DeclaredScheme] = []
    for verifier in verifiers:
        scheme = scheme_for(verifier)
        if scheme is None:
            continue
        _reject_name_collision(scheme, verifier, declared)
        declared.append(scheme)
    return tuple(declared)


def scheme_for(verifier: Verifier) -> DeclaredScheme | None:
    """The scheme one verifier's declared `credential_source` names, or `None` for a label
    this module does not recognize."""
    source = verifier.credential_source.strip()
    if source.casefold() == BEARER_SOURCE:
        return _declared(
            HTTPBearer(
                auto_error=False,
                scheme_name=BEARER_SCHEME_NAME,
                description=BEARER_DESCRIPTION,
            )
        )
    cookie = _cookie_name(source)
    if cookie is None:
        return None
    return _declared(
        APIKeyCookie(
            name=cookie,
            auto_error=False,
            scheme_name=COOKIE_SCHEME_PREFIX + UNSAFE_IN_A_NAME.sub("-", cookie),
            description=COOKIE_DESCRIPTION.format(name=cookie),
        )
    )


def declaring(schemes: Sequence[DeclaredScheme]) -> Declaration | None:
    """One dependency per scheme, chained, or `None` when there is nothing to declare.

    A dependency declares its own sub-dependencies through its parameters, so a set of schemes
    whose size is only known at construction has to be a chain rather than one signature. The
    fold runs from the last scheme back, which is what makes the requirements FastAPI
    flattens - depth-first, in parameter order - come out in the order the verifiers were
    declared.
    """
    chain: Declaration | None = None
    for scheme in reversed(schemes):
        chain = _link(scheme, chain)
    return chain


def _link(scheme: DeclaredScheme, inner: Declaration | None) -> Declaration:
    if inner is None:

        async def last(_declared: None = Security(scheme)) -> None:
            return None

        return last

    async def link(_declared: None = Security(scheme), _rest: None = Depends(inner)) -> None:
        return None

    return link


def _declared(scheme: SecurityBase) -> DeclaredScheme:
    """Keep what a real scheme says about itself; drop the callable that would read a request."""
    return DeclaredScheme(model=scheme.model, scheme_name=scheme.scheme_name)


def _cookie_name(source: str) -> str | None:
    """The cookie a `cookie:<name>` label names. Matched case-insensitively, sliced verbatim:
    a cookie name is case-sensitive, so `__Secure-` may not be folded away."""
    if not source.casefold().startswith(COOKIE_PREFIX):
        return None
    name = source[len(COOKIE_PREFIX) :].strip()
    return name or None


def _reject_name_collision(
    scheme: DeclaredScheme, verifier: Verifier, seen: Sequence[DeclaredScheme]
) -> None:
    if all(each.scheme_name != scheme.scheme_name for each in seen):
        return
    raise ConfigurationError(
        f"BetterAuth(verifiers=...) has two verifiers that would both be published as"
        f" {scheme.scheme_name!r}: {type(verifier).__name__} declares"
        f" credential_source={verifier.credential_source!r}, and an earlier verifier's label"
        " sanitizes onto the same OpenAPI name. One definition would silently replace the"
        " other, so /docs would name a credential nothing reads."
    )
