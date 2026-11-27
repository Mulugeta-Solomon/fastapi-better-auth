"""The checks `BetterAuth` runs on what it is built with, before any request exists."""

from __future__ import annotations

import inspect
from collections.abc import Sequence
from typing import cast

from .errors import ConfigurationError
from .labels import collision_key
from .models import User
from .verifiers import Verifier


def validated_verifiers(verifiers: object) -> tuple[Verifier, ...]:
    if isinstance(verifiers, (str, bytes, bytearray)) or not isinstance(verifiers, Sequence):
        raise ConfigurationError(
            "BetterAuth(verifiers=...) takes a sequence of verifiers, in the order their"
            f" credentials should be looked for; got {type(verifiers).__name__}."
        )
    ordered = tuple(cast("Sequence[object]", verifiers))
    if not ordered:
        raise ConfigurationError(
            "BetterAuth(verifiers=...) needs at least one verifier: with none configured,"
            " every request would be answered as unauthenticated."
        )
    seen: list[Verifier] = []
    for index, verifier in enumerate(ordered):
        _validate_verifier(verifier, index)
        checked = cast("Verifier", verifier)
        if any(checked is earlier for earlier in seen):
            raise ConfigurationError(
                f"BetterAuth(verifiers=...) lists the same {type(checked).__name__} twice."
                " Both copies would find the same credential, so every request carrying it"
                " would be ambiguous."
            )
        _reject_collision(checked, seen)
        seen.append(checked)
    return cast("tuple[Verifier, ...]", ordered)


def _reject_collision(verifier: Verifier, seen: Sequence[Verifier]) -> None:
    """Two *different* verifiers reading one credential — what identity cannot see."""
    key = collision_key(verifier.credential_source)
    clash = next((s for s in seen if collision_key(s.credential_source) == key), None)
    if clash is None:
        return
    raise ConfigurationError(
        f"BetterAuth(verifiers=...) has two verifiers on one credential:"
        f" {type(clash).__name__} declares credential_source={clash.credential_source!r} and"
        f" {type(verifier).__name__} declares credential_source={verifier.credential_source!r}."
        " Both would find it (a cookie and its __Secure- or __Host- form count as one), so"
        " every request carrying it would be ambiguous."
    )


def _validate_verifier(verifier: object, index: int) -> None:
    where = f"BetterAuth(verifiers=...)[{index}]"
    if not isinstance(verifier, Verifier):
        raise ConfigurationError(
            f"{where} is a {type(verifier).__name__}, which does not implement the Verifier"
            " protocol: it needs a synchronous extract(connection) and an async"
            " verify(credential, user_model)."
        )
    for method in ("extract", "verify"):
        if not callable(getattr(verifier, method)):
            raise ConfigurationError(f"{where} has a {method} that is not callable.")
    _validate_source(verifier.credential_source, where)
    if inspect.iscoroutinefunction(verifier.extract):
        raise ConfigurationError(
            f"{where} declares extract() as async. extract() is a synchronous presence"
            " check; an async one returns a coroutine object, which is never None, so this"
            " verifier would claim every request and every request would be ambiguous."
        )


def _validate_source(source: object, where: str) -> None:
    """`source` is annotated `str`; the object declaring it was written by someone else."""
    if not isinstance(source, str) or not source.strip():
        raise ConfigurationError(
            f"{where} must declare a non-empty string credential_source naming where its"
            " credential comes from, such as 'cookie:better-auth.session_token'. It is how"
            " two verifiers reading one credential are caught here rather than by every"
            f" request being ambiguous; got {source!r}."
        )


def validate_user_model(user_model: object) -> None:
    if not (isinstance(user_model, type) and issubclass(user_model, User)):
        raise ConfigurationError(
            "user_model must be User or a subclass of it, because the upstream payload is"
            f" parsed into it; got {user_model!r}."
        )
