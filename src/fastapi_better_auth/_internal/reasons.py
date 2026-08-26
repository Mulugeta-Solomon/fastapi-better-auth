"""What an operator-facing `reason` may carry: a fingerprint, and a label nobody else wrote."""

from __future__ import annotations

import hashlib
import re

FINGERPRINT_LENGTH = 8
LABEL_PATTERN = re.compile(r"[A-Za-z0-9_.:+-]{1,64}")
REDACTED = "<redacted>"


def fingerprint(credential: str) -> str:
    """A short, stable label for a credential that cannot be turned back into one.

    `reason` reaches logs and error reporters, so the credential itself can never go there
    (D-018). A truncated digest gives an operator the one thing they actually need from it -
    "this is the same token that failed a minute ago" - and gives an attacker nothing.
    """
    digest = hashlib.sha256(credential.encode("utf-8", "replace")).hexdigest()
    return f"tok_fp={digest[:FINGERPRINT_LENGTH]}"


def safe_label(value: object) -> str:
    """Render an attacker-supplied identifier for a log line, or refuse to.

    A `kid` and an `alg` come out of an unverified token header, which means they are text a
    client chose that ends up in an operator's log. A value that is already a plain
    identifier survives verbatim, because that is what makes the line useful; anything else -
    a newline that would forge a second log entry, a quote that would break a parser, a
    control character, a megabyte of padding - becomes `<redacted>`. The same rule
    `parse_user` applies to a payload-chosen field path (D-069), for the same reason.
    """
    if not isinstance(value, str) or not LABEL_PATTERN.fullmatch(value):
        return REDACTED
    return value
