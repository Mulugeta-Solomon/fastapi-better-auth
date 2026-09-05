"""The one signed-cookie comparison two verifiers share: a keyring HMAC, in constant time.

Better Auth signs a session cookie as `token + "." + base64(HMAC-SHA256(secret, token))`. Both
the cookie verifier (which always checks it) and the remote verifier (which checks it only when
the operator configured a secret) need the identical comparison, so it lives here rather than in
either. The keyring is the `BETTER_AUTH_SECRETS` rotation: a cookie signed with any current secret
must verify, so every entry is tried with a `compare_digest` and no early return, and the cookie
is accepted iff any matched. The token, the signature and every derived byte string are scrubbed
in `finally` - this is a frame that raises the bad-signature refusal, so a reporter capturing its
locals must find no credential (D-094).
"""

from __future__ import annotations

import base64
import hashlib
import hmac

from .errors import InvalidCredential
from .shared_secret import SharedSecret


def verify_signature(
    secrets: tuple[SharedSecret, ...], token: str, signature: str, marker: str
) -> None:
    """One `compare_digest` per keyring entry, no early return, accepted iff any matched.

    Iterating without an early return keeps the work independent of which key matched, and
    `matched |=` accumulates so a match is never short-circuited away.

    Args:
        secrets: The keyring, one or more `SharedSecret`s.
        token: The raw session token the signature is computed over.
        signature: The 44-character standard-base64 signature presented on the cookie.
        marker: A fingerprint of the credential, for the refusal reason - never the credential.

    Raises:
        InvalidCredential: If the signature verifies against no configured secret.
    """
    message = presented = expected = b""
    digest = None
    try:
        message = token.encode("utf-8")
        presented = signature.encode("ascii")
        matched = False
        for secret in secrets:
            digest = hmac.new(secret.get_secret_value().encode("utf-8"), message, hashlib.sha256)
            expected = base64.b64encode(digest.digest())
            matched |= hmac.compare_digest(presented, expected)
        if not matched:
            raise InvalidCredential(
                reason=f"signature verifies against no configured secret [{marker}]"
            )
    finally:
        token = signature = ""
        message = presented = expected = b""
        digest = None
