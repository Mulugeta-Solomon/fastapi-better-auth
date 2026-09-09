"""The one sanctioned door from upstream data to a `User`."""

from __future__ import annotations

import logging
import re
from typing import Any, TypeVar

from pydantic import ValidationError
from pydantic_core import ErrorDetails

from .errors import InvalidCredential
from .models import User
from .once import OnceByKey

logger = logging.getLogger("fastapi_better_auth")

UserModelT = TypeVar("UserModelT", bound=User)

MAX_REPORTED_ERRORS = 5
MAX_REASON_LENGTH = 500
MAX_ADVISED_KEYS = 5
MISSING = "missing"
REDACTED = "<redacted>"
SAFE_LOCATION = re.compile(r"[A-Za-z0-9_]{1,64}")

_advised = OnceByKey()


def parse_user(user_model: type[UserModelT], payload: Any) -> UserModelT:
    """Build a user model from an upstream payload, or fail as a credential failure.

    This is how a verifier turns decoded JWT claims or a `get-session` body into the user
    model the application asked for. Use it instead of calling `user_model.model_validate`
    yourself - including in a verifier of your own:

        from fastapi_better_auth import Session, parse_user

        class HeaderVerifier:
            credential_source = "header:x-assertion"

            async def verify(self, credential: str, user_model: type[UserT]) -> Session[UserT]:
                claims = decode(credential)
                return Session(
                    user=parse_user(user_model, claims),
                    expires_at=expiry_of(claims),
                    raw=claims,
                )

    A `pydantic.ValidationError` escaping a verifier is answered as a 500, and a 500 is
    distinguishable on the wire from the uniform 401 every other failure renders: it tells
    a client that *this* payload parsed differently from the last one, and under a
    debugging handler it echoes the payload back. Materializing the user through this
    function is what makes that outcome unreachable.

    The validation diagnosis survives on `InvalidCredential.reason` - which field, what
    kind of failure - for logs and error reporters. The *values* the payload carried do
    not. That covers three channels that each leaked in review: pydantic renders
    `input_value=` into its own message, and a model's own validator may interpolate the
    value it rejected into its `ValueError`, so the summary is rebuilt from the field path
    and pydantic's error *type* alone; and the original is not chained onto the raise,
    because `__cause__` is rendered by `logger.exception` and walked by error reporters,
    which would put it all back. The upstream payload is also dropped from this function's
    locals before the raise, since reporters capture those too.

    One thing the payload *can* influence, stated plainly because the alternative is a
    guarantee this cannot keep: the field **path**. For a model with `extra="forbid"`, or
    one with a mapping field, the rejected key is chosen by the payload and pydantic puts
    it in `loc`. A path segment survives into the reason only if it is already
    `[A-Za-z0-9_]{1,64}` - so it cannot carry a quote, a separator, a newline or a control
    character into a log line, and it cannot choose how long that line is. Anything else
    is replaced by `<redacted>`. Keeping plain names is what makes the reason useful to
    the operator reading it.

    One refusal is worth a log line of its own, and gets one: a *required* field the payload
    does not carry. That is a deployment telling on itself - the payload was authenticated
    before it got here, so the mismatch is between this model's field names and the ones the
    Better Auth server sends, and every request will be refused until one of them changes. A
    single `WARNING` per process per user model names the model and the missing **wire keys**
    (the aliases, sanitized the same way the reason is); the values the payload carried are no
    more logged than they are put in the reason. An optional field is silent by design: it is
    the forward-compatible shape, and it reads `None`.

    Args:
        user_model: The `User` subclass this deployment declared.
        payload: The upstream data - decoded JWT claims, or a `get-session` body.

    Returns:
        An instance of `user_model`.

    Raises:
        InvalidCredential: If the payload does not validate. Renders the uniform 401.
    """
    try:
        return user_model.model_validate(payload)
    except ValidationError as exc:
        summary = _summarize(user_model, exc)
        absent = _missing_paths(exc)
    payload = None
    _advise(user_model, absent)
    raise InvalidCredential(reason=summary) from None


def _advise(user_model: type[User], absent: tuple[str, ...]) -> None:
    """One warning per process per model when a declared field is not on the wire.

    Honest because every mode authenticates the payload before parsing it: this is the
    deployment's own configuration, not a caller's input. Same discipline as `reason` - the
    sanitized field path, never a value - and only for `missing`, so it stays one signal.
    """
    if not absent or not _advised.fire(user_model):
        return
    logger.warning(
        "%s declares required fields the upstream payload did not carry: %s. Every request"
        " carrying this payload shape is refused as a 401. If these are Better Auth"
        " additionalFields, the names shown are the wire keys this model expects - check them"
        " against the ones your Better Auth server actually sends.",
        user_model.__name__,
        ", ".join(absent),
    )


def _missing_paths(exc: ValidationError) -> tuple[str, ...]:
    absent = [
        _location(error) for error in exc.errors(include_url=False) if error["type"] == MISSING
    ]
    return tuple(dict.fromkeys(absent))[:MAX_ADVISED_KEYS]


def _summarize(user_model: type[User], exc: ValidationError) -> str:
    total = exc.error_count()
    reported = [_render(error) for error in exc.errors(include_url=False)[:MAX_REPORTED_ERRORS]]
    if total > len(reported):
        reported.append(f"+{total - len(reported)} more")
    summary = f"{user_model.__name__} payload rejected ({total}): " + "; ".join(reported)
    return summary[:MAX_REASON_LENGTH]


def _render(error: ErrorDetails) -> str:
    """Field path and error type only: `msg` and half of `loc` can be payload-supplied."""
    return f"{_location(error)}: [{error['type']}]"


def _location(error: ErrorDetails) -> str:
    parts = [part if isinstance(part, int) else _safe(part) for part in error["loc"]]
    return ".".join(str(part) for part in parts) or "<root>"


def _safe(part: str) -> str:
    return part if SAFE_LOCATION.fullmatch(part) else REDACTED
