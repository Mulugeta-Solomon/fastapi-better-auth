"""The get-session outcome table: one response in, one record or one mapped refusal out.

Mode C's whole contract is that `GET /api/auth/get-session` answers **200 with a literal `null`
body** for an unauthenticated request and a `{session, user}` object for an authenticated one.
This module is that contract read exhaustively: a `TransportResponse` maps to the parsed record,
or to the `SessionError` the arc pins for every other shape - a non-200, a non-JSON body, a body
that is JSON but not the shape, and the two ways a `null` can be read.

Two things are deliberately **not** here. The fetch failures (a timeout, a refused connection, an
oversized or content-encoded body) are classified at the fetch site, because the underlying
exception carries the outbound request - and the forwarded cookie in it - so it must never reach a
traceback here. And the token comparison, expiry and ban are decided against the credential the
verifier forwarded, in the verifier's own frame; this module only proves the response is a
trustworthy document, never that it is *this* request's session.

There is no 503 in the taxonomy and none is added: every unreachable/unreadable outcome is an
`AuthServiceUnavailable`, which is a 401 on the wire, indistinguishable from every other refusal.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, cast

from .errors import AuthServiceUnavailable, InvalidCredential, SessionRevoked
from .reasons import safe_label
from .stores.records import StoredSession
from .stores.session_document import parse_session_document
from .transport import TransportResponse

JSON_MEDIA_TYPES = frozenset({"application/json"})
RETRY_AFTER_HEADERS = ("retry-after", "x-retry-after")
DEFAULT_BACKOFF = 5
MIN_BACKOFF = 1
MAX_BACKOFF = 60

ROUTING_STATUSES = frozenset({404, 405, 415})
RATE_LIMITED = 429


def session_document_from(
    response: TransportResponse, *, uri: str, marker: str, signature_verified: bool
) -> StoredSession:
    """The `{session, user}` record this response carries, or the refusal it maps to.

    Args:
        response: The get-session response, already fetched and capped.
        uri: The pinned get-session URI, for the operator-facing reason.
        marker: A fingerprint of the forwarded token, for correlation - never the token.
        signature_verified: Whether a configured keyring positively verified the cookie's
            signature. It decides only the `200 + null` outcome: a verified null is a session
            that existed and is gone (`SessionRevoked`), an unverified one is a cookie whose
            existence was never established (`InvalidCredential`).

    Returns:
        The parsed record. The verifier still checks its token against the forwarded one, its
        expiry, and its ban state before it is a session.

    Raises:
        InvalidCredential: A `200 + null` with no verified signature.
        SessionRevoked: A `200 + null` whose signature a keyring verified.
        AuthServiceUnavailable: Every non-200, non-JSON, or unreadable document.
    """
    status = response.status_code
    if status != 200:
        raise _status_failure(response, uri)
    media = _media_type(response)
    if media not in JSON_MEDIA_TYPES:
        raise AuthServiceUnavailable(
            reason=f"get-session at {uri} is served as {safe_label(media)}, not JSON"
        )
    parsed = _decoded(response, uri)
    if parsed is None:
        raise null_outcome(signature_verified, marker)
    if not isinstance(parsed, dict):
        raise AuthServiceUnavailable(
            reason=f"get-session at {uri} is unusable: it is not a JSON object"
        )
    document = cast("Mapping[str, Any]", parsed)
    record = parse_session_document(document, marker)
    if record is None:
        raise AuthServiceUnavailable(
            reason=f"get-session at {uri} answered a document this bridge cannot read [{marker}]"
        )
    return record


def is_cacheable_null(response: TransportResponse) -> bool:
    """Whether this is the one cacheable outcome: `200`, JSON, body literally `null`.

    The negative cache remembers exactly this and nothing else. It is read against the response
    already fetched, so a refusal that came from a token mismatch, an expiry, a ban or an
    unreadable document - none of which are 200-null - is never remembered.
    """
    if response.status_code != 200:
        return False
    if _media_type(response) not in JSON_MEDIA_TYPES:
        return False
    try:
        return json.loads(response.content) is None
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError):
        return False


def retry_after_seconds(headers: Mapping[str, str]) -> int:
    """Whole seconds to back off after a 429, clamped to `[MIN_BACKOFF, MAX_BACKOFF]`.

    Reads `retry-after` then `x-retry-after` - upstream sets only the latter, and the standard
    name is read first for a proxy that normalises. An absent or unparseable value is
    `DEFAULT_BACKOFF`. A hostile or absurd value is clamped rather than trusted.
    """
    for name in RETRY_AFTER_HEADERS:
        raw = headers.get(name)
        if raw is None:
            continue
        try:
            value = int(raw.strip())
        except (TypeError, ValueError):
            continue
        return max(MIN_BACKOFF, min(MAX_BACKOFF, value))
    return DEFAULT_BACKOFF


def _status_failure(response: TransportResponse, uri: str) -> AuthServiceUnavailable:
    status = response.status_code
    if status == RATE_LIMITED:
        backoff = retry_after_seconds(response.headers)
        return AuthServiceUnavailable(
            reason=f"get-session is rate-limited upstream (429); backing off {backoff}s"
        )
    if status in ROUTING_STATUSES:
        return AuthServiceUnavailable(
            reason=f"get-session answered {status} at {uri}; check base_path="
        )
    if 300 <= status < 400:
        return AuthServiceUnavailable(
            reason=f"get-session answered {status} from {uri}; redirects are never followed"
        )
    return AuthServiceUnavailable(reason=f"get-session answered {status} from {uri}")


def _media_type(response: TransportResponse) -> str:
    declared = response.headers.get("content-type", "")
    return declared.split(";")[0].strip().lower()


def _decoded(response: TransportResponse, uri: str) -> Any:
    # Raised OUTSIDE the except so `__context__` does not chain the `JSONDecodeError`, whose
    # `.doc` is the raw body (the house pattern, D-181).
    parsed: Any = None
    try:
        parsed = json.loads(response.content)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError):
        unparseable = True
    else:
        unparseable = False
    if unparseable:
        raise AuthServiceUnavailable(
            reason=f"get-session at {uri} is unusable: it is not JSON"
        ) from None
    return parsed


def null_outcome(signature_verified: bool, marker: str) -> InvalidCredential | SessionRevoked:
    """The refusal a `200 + null` maps to, reused by a live fetch and by a negative-cache hit.

    A verified signature means the session existed and is gone (`SessionRevoked`, Mode A parity);
    an unverified one means the cookie's existence was never established (`InvalidCredential`).
    """
    if signature_verified:
        return SessionRevoked(reason=f"upstream reports the signed session is gone [{marker}]")
    return InvalidCredential(reason=f"upstream reports no session for this cookie [{marker}]")
