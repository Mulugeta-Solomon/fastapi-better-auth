"""The data a verified request hands to user code."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class User(BaseModel):
    """A Better Auth user, parsed from a JWT payload or a `get-session` response.

    Fields are snake_case and the camelCase names Better Auth puts on the wire are
    accepted as aliases, so `emailVerified` populates `email_verified`. Keys this model
    does not declare — registered JWT claims, plugin fields, anything a future upstream
    release adds — are ignored here and stay readable on `Session.raw`.

    Only `id` is required, and it must be non-empty. Everything else is optional: a JWT
    `definePayload` can legitimately strip fields, and refusing an otherwise valid
    session because a display name went missing would be the worse failure.

    Subclass it to type the fields your deployment actually has:

        class AdminUser(User):
            role: str | None = None
            ban_reason: str | None = None   # reads Better Auth's `banReason`

    Then pass the subclass where a user model is expected; `Session[AdminUser].user` is
    typed as `AdminUser`. Instances are immutable.
    """

    model_config = ConfigDict(
        alias_generator=to_camel,
        extra="ignore",
        frozen=True,
        populate_by_name=True,
    )

    id: str = Field(min_length=1)
    email: str | None = None
    name: str | None = None
    email_verified: bool | None = None
    image: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


UserT = TypeVar("UserT", bound=User)


class Session(BaseModel, Generic[UserT]):
    """A verified session, generic over the user model it carries.

    Instances are built by this library's verifiers once verification has succeeded —
    they are never parsed from an upstream response, so unknown keyword arguments are
    rejected rather than ignored.

    Attributes:
        user: The authenticated user. `Session[AdminUser].user` is typed `AdminUser`.
        expires_at: Session expiry when the credential carries one, else `None`.
        token: The raw session token in cookie mode; `None` in JWT mode, which has no
            server-side session token to hand back.
        raw: The upstream payload exactly as it arrived — the decoded JWT claims, or the
            whole `get-session` body. Everything this model does not promote to a field
            (`ipAddress`, `userAgent`, `activeOrganizationId`, plugin data) is reachable
            here, which is what keeps upstream field additions from being breaking
            changes. The mapping is copied one level deep; nested containers are shared
            with the caller's payload.

    Instances are immutable, and not hashable: `raw` is a dict.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    user: UserT
    expires_at: datetime | None = None
    token: str | None = None
    raw: dict[str, Any]
