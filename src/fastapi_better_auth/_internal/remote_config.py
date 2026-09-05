"""RemoteVerifier's construction-time validation: one validator per knob, each a ConfigurationError.

Every knob is validated at construction (a knob the code ignores is a lie), so a deployment that
could not verify safely never finishes starting up. Split out of `remote_verifier` to keep that
module under the size limit; the validators are pure functions with no dependency on the verifier's
internals, so they live cleanly on their own.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from typing import cast

from .cookie_verifier import ILLEGAL_IN_A_COOKIE_NAME
from .errors import ConfigurationError
from .httpx_transports import HttpxTransport
from .negative_cache import (
    MAX_NEGATIVE_TTL,
    MAX_REMEMBERED,
    MIN_NEGATIVE_TTL,
    MIN_REMEMBERED,
)
from .shared_secret import SharedSecret
from .transport import Transport

MAX_OUTBOUND_CONCURRENCY = 8
MIN_CONCURRENCY = 1
MAX_CONCURRENCY = 256
QUEUE_TIMEOUT = 2.0
MIN_QUEUE_TIMEOUT = 0.1

_BASE_PATH_MESSAGE = (
    "RemoteVerifier(base_path=...) must be the path Better Auth is mounted at, starting with '/'"
    " and with no trailing slash, query or fragment - '/api/auth' by default, or '' for a server"
    " mounted at the root; got {got!r}."
)


def validated_transport(transport: object) -> Transport:
    if transport is None:
        return HttpxTransport()
    if not isinstance(transport, Transport):
        raise ConfigurationError(
            f"RemoteVerifier(transport=...) is a {type(transport).__name__}, which does not"
            " implement the Transport protocol: it needs async get(url, *, headers, max_bytes)"
            " and post(...) methods. Pass HttpxTransport(), Httpx2Transport(), or an adapter of"
            " your own."
        )
    for method in ("get", "post"):
        if not callable(getattr(transport, method)):
            raise ConfigurationError(
                f"RemoteVerifier(transport=...) has a {method} that is not callable."
            )
    return transport


def validated_optional_keyring(
    secret: SharedSecret | None, secrets: Sequence[SharedSecret] | None
) -> tuple[SharedSecret, ...]:
    if secret is not None and secrets is not None:
        raise ConfigurationError(
            "RemoteVerifier takes at most one of secret= or secrets=. Both configure the same"
            " optional local signature pre-check; passing both leaves it undecided which keyring"
            " is authoritative."
        )
    if secret is None and secrets is None:
        return ()
    if secret is not None:
        entries: tuple[object, ...] = (secret,)
    else:
        if isinstance(secrets, (str, bytes, bytearray)) or not isinstance(secrets, Sequence):
            raise ConfigurationError(
                "RemoteVerifier(secrets=...) takes a sequence of SharedSecret; got"
                f" {type(secrets).__name__}. A bare string would be iterated one character at a time."
            )
        entries = tuple(cast("Sequence[object]", secrets))
        if not entries:
            raise ConfigurationError(
                "RemoteVerifier(secrets=...) is empty, so no signature could ever be pre-checked."
                " Pass at least one SharedSecret, or neither secret= nor secrets= to skip the"
                " local pre-check entirely."
            )
    for entry in entries:
        if not isinstance(entry, SharedSecret):
            raise ConfigurationError(
                "RemoteVerifier signs nothing, but it pre-checks with SharedSecret, not"
                f" {type(entry).__name__}: SharedSecret is what refuses a weak or placeholder"
                " value at boot and keeps it out of every rendering. Write"
                " SharedSecret(os.environ['BETTER_AUTH_SECRET'])."
            )
    return cast("tuple[SharedSecret, ...]", entries)


def validated_cookie_name(cookie_name: object) -> str:
    if not isinstance(cookie_name, str) or not cookie_name.strip():
        raise ConfigurationError(
            "RemoteVerifier(cookie_name=...) must be a non-empty string, such as"
            f" 'better-auth.session_token'; got {cookie_name!r}."
        )
    if ILLEGAL_IN_A_COOKIE_NAME.intersection(cookie_name):
        raise ConfigurationError(
            "RemoteVerifier(cookie_name=...) must be a bare cookie name with no whitespace,"
            f" ';', '=' or ','; got {cookie_name!r}."
        )
    return cookie_name


def validated_prefix(secure_prefix: object) -> str:
    if not isinstance(secure_prefix, str):
        raise ConfigurationError(
            "RemoteVerifier(secure_prefix=...) must be a string, empty to read only the plain"
            f" cookie name; got {type(secure_prefix).__name__}."
        )
    if secure_prefix and ILLEGAL_IN_A_COOKIE_NAME.intersection(secure_prefix):
        raise ConfigurationError(
            "RemoteVerifier(secure_prefix=...) must carry no whitespace, ';', '=' or ','; got"
            f" {secure_prefix!r}."
        )
    return secure_prefix


def validated_secure_cookies(secure_cookies: object) -> bool:
    if not isinstance(secure_cookies, bool):
        raise ConfigurationError(
            "RemoteVerifier(secure_cookies=...) must be a bool: True to read only the"
            " secure-prefixed cookie name, False to read only the plain one; got"
            f" {type(secure_cookies).__name__}."
        )
    return secure_cookies


def validated_base_path(base_path: object) -> str:
    if not isinstance(base_path, str):
        raise ConfigurationError(_BASE_PATH_MESSAGE.format(got=type(base_path).__name__))
    if base_path == "":
        return base_path
    malformed = (
        not base_path.startswith("/")
        or base_path.endswith("/")
        or any(char.isspace() or char < "\x20" or char == "\x7f" for char in base_path)
        or "?" in base_path
        or "#" in base_path
        or ".." in base_path
    )
    if malformed:
        raise ConfigurationError(_BASE_PATH_MESSAGE.format(got=base_path))
    return base_path


def validated_cap(max_bytes: object) -> int:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ConfigurationError(
            "RemoteVerifier(max_bytes=...) must be a positive integer number of bytes; got"
            f" {max_bytes!r}. It bounds the get-session body this verifier will read."
        )
    return max_bytes


def validated_concurrency(concurrency: object) -> int:
    if (
        isinstance(concurrency, bool)
        or not isinstance(concurrency, int)
        or not MIN_CONCURRENCY <= concurrency <= MAX_CONCURRENCY
    ):
        raise ConfigurationError(
            f"RemoteVerifier(concurrency=...) must be between {MIN_CONCURRENCY} and"
            f" {MAX_CONCURRENCY} outbound get-session calls; got {concurrency!r}. It bounds how"
            " much of this process one stalled auth service can occupy, not how fast upstream is"
            " asked."
        )
    return concurrency


def validated_queue_timeout(queue_timeout: object) -> float:
    if isinstance(queue_timeout, bool) or not isinstance(queue_timeout, (int, float)):
        raise ConfigurationError(
            "RemoteVerifier(queue_timeout=...) must be a number of seconds; got"
            f" {type(queue_timeout).__name__}."
        )
    if not math.isfinite(queue_timeout) or queue_timeout < MIN_QUEUE_TIMEOUT:
        raise ConfigurationError(
            f"RemoteVerifier(queue_timeout=...) must be at least {MIN_QUEUE_TIMEOUT} seconds; got"
            f" {queue_timeout!r}. Below that a saturated moment refuses every request that arrives"
            " during it."
        )
    return float(queue_timeout)


def validated_negative_ttl(negative_ttl: object) -> float:
    if isinstance(negative_ttl, bool) or not isinstance(negative_ttl, (int, float)):
        raise ConfigurationError(
            "RemoteVerifier(negative_ttl=...) must be a number of seconds; got"
            f" {type(negative_ttl).__name__}."
        )
    if not math.isfinite(negative_ttl) or not MIN_NEGATIVE_TTL <= negative_ttl <= MAX_NEGATIVE_TTL:
        raise ConfigurationError(
            f"RemoteVerifier(negative_ttl=...) must be between {int(MIN_NEGATIVE_TTL)} and"
            f" {int(MAX_NEGATIVE_TTL)} seconds; 0 disables the cache, which costs one upstream call"
            f" per forged cookie and is safe, never a bypass. Got {negative_ttl!r}."
        )
    return float(negative_ttl)


def validated_max_remembered(max_remembered: object) -> int:
    if (
        isinstance(max_remembered, bool)
        or not isinstance(max_remembered, int)
        or not MIN_REMEMBERED <= max_remembered <= MAX_REMEMBERED
    ):
        raise ConfigurationError(
            "RemoteVerifier(max_remembered=...) must be a positive number of remembered refusals,"
            f" at most {MAX_REMEMBERED}; got {max_remembered!r}. A garbage-cookie space is the"
            " attacker's imagination, so remembering it is bounded."
        )
    return max_remembered


def validated_clock(clock: object) -> Callable[[], float]:
    if not callable(clock):
        raise ConfigurationError(
            "RemoteVerifier(clock=...) must be a callable returning monotonic seconds, such as"
            f" time.monotonic; got {type(clock).__name__}."
        )
    return cast("Callable[[], float]", clock)
