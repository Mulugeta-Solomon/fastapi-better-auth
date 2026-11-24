"""The boot probe: what a get-session deployment can honestly be checked for before it serves.

Mode C's entire outcome mapping rests on one contract - `GET /api/auth/get-session` answers **200
with a literal `null` body** for an unauthenticated request. The probe is one bare GET, no Cookie,
that proves exactly that, and each rung is written knowing what it does and does not prove:

1. **Reachable.** A transport failure is a reachability fact, transient, and does not by itself
   mean the deployment is misconfigured. It does NOT prove the deployment stays reachable.
2. **200.** A 404/405 here is the single most common misconfiguration - the wrong `base_path`. It
   does NOT prove a later request will be 200.
3. **`application/json`.** A proxy serving an HTML login page instead would make Mode C map every
   anonymous request to `AuthServiceUnavailable` forever. It does NOT prove the body is well-formed.
4. **The body is exactly `null`.** This is the load-bearing rung: it is the 200-null contract
   itself. It does NOT prove an *authenticated* request returns a well-shaped document (only a live
   cookie can, and the probe has none).
5. **The dead-jar detector.** A bare request that comes back carrying a *session document* means
   the transport is replaying a retained cookie - a distinct fault naming the transport, not the
   deployment.

Then one second request carries `Authorization: Bearer <a manufactured random token>`, no cookie,
and checks ONLY whether a `set-cookie` header is *present* - never its value (the
`TransportResponse` rule stands). Present means the bearer plugin self-signed the manufactured
token and then cleared the missing session, which happens only in the permissive
`requireSignature: false` posture. What it does NOT prove: that Mode C is insecure - Mode C
forwards a cookie and never a bearer, and the cookie path always verifies upstream. The hazard is
about *other* consumers of a leaked raw token.

That rung has two settings, and `refuse_unsigned_bearer` picks between them. **Off** (the default)
it is advisory: one `logger.warning` per process, NEVER a refusal, and its own transport failure is
swallowed - the posture is the operator's to set. **On** it is a rung like the four above: a
`set-cookie` is a `ConfigurationError` naming the one-line upstream fix, and its own reachability
failure surfaces as `AuthServiceUnavailable` the way rung 1's does, so a transient outage is
retried rather than remembered as a verdict. Neither setting reads the header's value, replays a
real credential, or acts as a kill switch at request time.

The probe raises `ConfigurationError` for a contract failure (permanent: a redirect, a `4xx` other
than the three below, a non-JSON or non-null body, a dead jar) and `AuthServiceUnavailable` for a
reachability failure (transient); the caller decides whether a reachability failure stops startup or
is retried lazily.

**Not every status is an answer.** `408`, `425`, `429` and every `5xx` say the upstream could not
answer *right now* - it is restarting, overloaded or rate-limiting - which proves nothing about the
contract either way. Remembering one as a contract verdict would turn a few seconds of upstream
restart into an outage lasting until the process restarts, so each is a reachability failure like a
timeout: `AuthServiceUnavailable`, retried on the caller's window, never remembered. The same holds
for the bearer rung when it refuses, because there a transient status leaves the posture unproven.
Every other status that is not `200` remains a contract failure. The transient line is logged at
most once per `outage` latch the caller passes, naming the status and its class and never the body.
"""

from __future__ import annotations

import json
import logging
import secrets
import string
from typing import Any, cast

from .errors import AuthServiceUnavailable, BetterAuthError, ConfigurationError, SessionError
from .once import Once
from .reasons import safe_label
from .remote_response import JSON_MEDIA_TYPES
from .stores.session_document import parse_session_document
from .transport import (
    ContentEncodingRejected,
    ResponseTooLarge,
    Transport,
    TransportResponse,
)

logger = logging.getLogger("fastapi_better_auth")

ACCEPT_JSON = "application/json"
SET_COOKIE = "set-cookie"
AUTHORIZATION = "authorization"
PROBE_MARKER = "probe"
MANUFACTURED_TOKEN_LENGTH = 32
TOKEN_ALPHABET = string.ascii_letters + string.digits
ROUTING_STATUSES = frozenset({404, 405, 415})
TRANSIENT_STATUSES = {408: "request timeout", 425: "too early", 429: "rate limited"}
"""The `4xx` answers that mean "not now" rather than "no": each status, and the class a line names."""
SERVER_ERROR = "server error"
SERVER_ERRORS = range(500, 600)

_advised = Once()


async def run_probe(
    transport: Transport,
    *,
    uri: str,
    max_bytes: int,
    refuse_unsigned_bearer: bool = False,
    outage: Once | None = None,
) -> None:
    """Prove the deployment honours the 200-null contract, then check `requireSignature`.

    Args:
        transport: The HTTP boundary both requests go out through.
        uri: The pinned get-session URI.
        max_bytes: The largest body either request will read.
        refuse_unsigned_bearer: Whether the bearer rung refuses a permissive upstream posture
            (`True`) or logs one advisory warning per process and serves (`False`, the default -
            the pre-gate behaviour, so an older caller of this internal entry point is unchanged).
        outage: The latch that decides whether a transient status is logged. The verifier passes
            one per instance, so an outage spanning many retry windows is one line; `None` (the
            raw one-shot `probe()`) logs nothing and leaves the raised error to its caller.

    Raises:
        ConfigurationError: A contract failure - a redirect or a `4xx` other than `408`, `425`
            and `429`, a non-JSON body, a body that is not literally `null`, or a session document
            from a bare request (the dead-jar detector); and, under `refuse_unsigned_bearer`, an
            upstream that accepts an unsigned bearer. Permanent facts about the deployment.
        AuthServiceUnavailable: A reachability failure - a timeout, a refused connection, an
            oversized or content-encoded answer, or a transient status (`408`, `425`, `429`, any
            `5xx`). Transient.
    """
    response = await _probe_get(transport, uri, {"accept": ACCEPT_JSON}, max_bytes)
    _refuse_transient(response.status_code, uri, outage)
    _assert_null_contract(response, uri, transport)
    await _advise(
        transport, uri=uri, max_bytes=max_bytes, refuse=refuse_unsigned_bearer, outage=outage
    )


def transient_class(status: int) -> str | None:
    """The class of a status that means the upstream could not answer now, or `None`."""
    if status in SERVER_ERRORS:
        return SERVER_ERROR
    return TRANSIENT_STATUSES.get(status)


def _refuse_transient(status: int, uri: str, outage: Once | None) -> None:
    """Raise `AuthServiceUnavailable` for a transient status, reporting it once per `outage`.

    Only the status and the class this module names reach the reason and the line - never the
    body, which is whatever an overloaded proxy or a crashing server chose to send.
    """
    status_class = transient_class(status)
    if status_class is None:
        return
    if outage is not None and outage.fire():
        logger.warning(
            "get-session readiness probe answered %d (%s), so the upstream could not answer now;"
            " every request is refused as AuthServiceUnavailable until a probe passes, and the"
            " probe is retried on its own window. Not repeated for this verifier.",
            status,
            status_class,
        )
    raise AuthServiceUnavailable(
        reason=f"get-session readiness probe answered {status} ({status_class}), a transient"
        f" status; it is retried rather than remembered [{uri}]"
    )


def _assert_null_contract(response: TransportResponse, uri: str, transport: Transport) -> None:
    status = response.status_code
    if status != 200:
        raise ConfigurationError(_status_message(status, uri))
    media = _media_type(response)
    if media not in JSON_MEDIA_TYPES:
        raise ConfigurationError(
            f"get-session at {uri} answered an anonymous request as {safe_label(media)}, not JSON;"
            " the 200-null contract Mode C rests on is not being honoured."
        )
    parsed = _decoded(response, uri)
    if parsed is None:
        return
    if isinstance(parsed, dict) and parse_session_document(
        cast("dict[str, Any]", parsed), PROBE_MARKER
    ):
        raise ConfigurationError(
            f"get-session at {uri} answered a bare request (no cookie) with a live session"
            f" document, which means {type(transport).__name__} is replaying a retained upstream"
            " cookie. The transport's jar must be shut; build one this library owns, or pass a"
            " dedicated client."
        )
    raise ConfigurationError(
        f"get-session at {uri} answered an anonymous request with a non-null body; the 200-null"
        " contract Mode C rests on is not being honoured."
    )


async def _advise(
    transport: Transport, *, uri: str, max_bytes: int, refuse: bool, outage: Once | None
) -> None:
    """The bearer posture rung: advisory by default, refusing under `refuse_unsigned_bearer`.

    Advisory, it swallows every failure of its own and warns once per process. Refusing, it is a
    rung like the four before it: its own failures propagate (so a reachability failure or a
    transient status stays an `AuthServiceUnavailable` the caller can retry - an unproven posture
    must not pass the probe) and a `set-cookie` is a `ConfigurationError`.
    """
    token = "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(MANUFACTURED_TOKEN_LENGTH))
    headers = {"accept": ACCEPT_JSON, AUTHORIZATION: f"Bearer {token}"}
    try:
        response = await _probe_get(transport, uri, headers, max_bytes)
    except (BetterAuthError, SessionError):
        if refuse:
            raise
        return
    finally:
        headers.clear()
        token = ""
    if refuse:
        _refuse_transient(response.status_code, uri, outage)
    if SET_COOKIE not in response.headers:
        return
    if refuse:
        raise ConfigurationError(_unsigned_bearer_message(uri))
    if _advised.fire():
        logger.warning(
            "get-session accepted a manufactured bearer token and set a session cookie, so the"
            " bearer plugin is at its default requireSignature: false. A raw session token is then"
            " a bearer credential, so a token in a log, dump or backup is a credential leak. The"
            " one-line fix upstream is bearer({ requireSignature: true }). Advisory only: Mode C"
            " forwards a cookie, never a bearer."
        )


def _unsigned_bearer_message(uri: str) -> str:
    return (
        f"get-session at {uri} accepted a manufactured bearer token and set a session cookie, so"
        " the bearer plugin upstream is at its default requireSignature: false. A raw session"
        " token is then a bearer credential, so a token in a log, dump or backup is a credential"
        " leak. RemoteVerifier(refuse_unsigned_bearer=True) makes that a refusal rather than a"
        " warning: fix it upstream with bearer({ requireSignature: true }), or drop the flag to go"
        " back to the advisory warning."
    )


async def _probe_get(
    transport: Transport, uri: str, headers: dict[str, str], max_bytes: int
) -> TransportResponse:
    """Fetch the probe, translating every reachability failure to `AuthServiceUnavailable`.

    Raised `from None`: a transport error may carry the outbound request, and though this request
    holds no real credential the house rule keeps it off the chain uniformly. The header dict is
    scrubbed in `finally` - the advisory rung carries a manufactured bearer token.
    """
    try:
        try:
            return await transport.get(uri, headers=headers, max_bytes=max_bytes)
        except (BetterAuthError, SessionError):
            raise
        except TimeoutError:
            failure = AuthServiceUnavailable(
                reason=f"get-session readiness probe timed out [{uri}]"
            )
        except ResponseTooLarge:
            failure = AuthServiceUnavailable(
                reason=f"get-session readiness probe answered a body over the {max_bytes}-byte cap"
            )
        except ContentEncodingRejected:
            failure = AuthServiceUnavailable(
                reason="get-session readiness probe answered a content encoding after identity"
            )
        except Exception as exc:  # noqa: BLE001 - a transport failure or a third-party error
            failure = AuthServiceUnavailable(
                reason=f"get-session readiness probe could not reach [{type(exc).__name__}] {uri}"
            )
        raise failure from None
    finally:
        headers.clear()


def _status_message(status: int, uri: str) -> str:
    if status in ROUTING_STATUSES:
        return (
            f"get-session answered {status} at {uri}; check that base_path= names where Better"
            " Auth is mounted."
        )
    return (
        f"get-session answered {status} at {uri}; an anonymous request must answer 200 with a"
        " null body for Mode C to read it."
    )


def _media_type(response: TransportResponse) -> str:
    declared = response.headers.get("content-type", "")
    return declared.split(";")[0].strip().lower()


def _decoded(response: TransportResponse, uri: str) -> Any:
    # Raised OUTSIDE the except so `__context__` does not chain the JSONDecodeError, whose `.doc`
    # is the raw body (the house pattern, D-181).
    parsed: Any = None
    try:
        parsed = json.loads(response.content)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError):
        unreadable = True
    else:
        unreadable = False
    if unreadable:
        raise ConfigurationError(
            f"get-session at {uri} answered an anonymous request with a body that is not JSON;"
            " the 200-null contract Mode C rests on is not being honoured."
        ) from None
    return parsed
