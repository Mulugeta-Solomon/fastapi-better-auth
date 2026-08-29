"""The two things a store tells an operator, and the shape that keeps a credential out of both."""

from __future__ import annotations

import logging

from ..reasons import fingerprint, safe_label

logger = logging.getLogger("fastapi_better_auth")

MAX_REPORTED_COLUMNS = 12


def unusable(kind: str, why: str, subject: str) -> None:
    """A stored record this store refuses to believe, named by fingerprint and never by value.

    The subject is a session token or a user id - both credential-adjacent, both on their way
    into an operator's log - so it goes through `fingerprint` (D-018). `why` is written by this
    package, never by the data.
    """
    logger.warning(
        "stored %s is unusable (%s); answering a miss [%s]",
        safe_label(kind),
        why,
        fingerprint(subject),
    )


def drifted(table: str, missing: tuple[str, ...]) -> None:
    """Columns better-auth's own schema has that this database does not.

    Loud on purpose, and once per store rather than once per request: it means the upstream
    schema has moved, or a migration did not finish, and the fields those columns feed will be
    absent from every record this store answers with until it does.
    """
    named = ", ".join(safe_label(column) for column in missing[:MAX_REPORTED_COLUMNS])
    logger.warning(
        "table %s is missing better-auth columns this store reads: %s;"
        " the fields they feed will be absent from every record",
        safe_label(table),
        named,
    )
