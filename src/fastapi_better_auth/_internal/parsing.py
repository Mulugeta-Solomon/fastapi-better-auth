"""The one sanctioned door from upstream data to a `User`."""

from __future__ import annotations

import re
from typing import Any, TypeVar

from pydantic import ValidationError
from pydantic_core import ErrorDetails

from .errors import InvalidCredential
from .models import User

UserModelT = TypeVar("UserModelT", bound=User)

MAX_REPORTED_ERRORS = 5
MAX_REASON_LENGTH = 500
REDACTED = "<redacted>"
SAFE_LOCATION = re.compile(r"[A-Za-z0-9_]{1,64}")


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
    kind of failure - for logs and error reporters. Nothing the payload chose does. That
    covers three channels that each leaked in review: pydantic renders `input_value=` into
    its own message, `loc` is payload-supplied for an `extra="forbid"` model or a mapping
    field, and a model's own validator may interpolate the value it rejected into its
    `ValueError`. The summary is therefore rebuilt from the field path and pydantic's error
    *type*, and the original is not chained onto the raise - `__cause__` is rendered by
    `logger.exception` and walked by error reporters, which would put it all back.

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
    raise InvalidCredential(reason=summary) from None


def _summarize(user_model: type[User], exc: ValidationError) -> str:
    total = exc.error_count()
    reported = [_render(error) for error in exc.errors(include_url=False)[:MAX_REPORTED_ERRORS]]
    if total > len(reported):
        reported.append(f"+{total - len(reported)} more")
    summary = f"{user_model.__name__} payload rejected ({total}): " + "; ".join(reported)
    return summary[:MAX_REASON_LENGTH]


def _render(error: ErrorDetails) -> str:
    """Field path and error type only: `msg` and half of `loc` can be payload-supplied."""
    parts = [part if isinstance(part, int) else _safe(part) for part in error["loc"]]
    location = ".".join(str(part) for part in parts) or "<root>"
    return f"{location}: [{error['type']}]"


def _safe(part: str) -> str:
    return part if SAFE_LOCATION.fullmatch(part) else REDACTED
