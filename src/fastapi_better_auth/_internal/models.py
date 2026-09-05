"""The data a verified request hands to user code."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from datetime import datetime, timezone
from typing import Annotated, Any, Generic, TypeVar

from pydantic import (
    AfterValidator,
    AliasGenerator,
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    SecretStr,
)
from pydantic.alias_generators import to_camel

ID_MAX_LENGTH = 255
EMAIL_MAX_LENGTH = 320
NAME_MAX_LENGTH = 1000
IMAGE_MAX_LENGTH = 4096


def _coerce_integer_id(value: Any) -> Any:
    # bool is an int subclass; coercing it would turn True into a usable id.
    if isinstance(value, bool) or not isinstance(value, int):
        return value
    return str(value)


def _reject_unusable_id(value: str) -> str:
    if not value.strip():
        raise ValueError("must contain a non-whitespace character")
    if any(char < "\x20" or char == "\x7f" for char in value):
        raise ValueError("must not contain control characters")
    return value


def _assume_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


class _RawMapping(Mapping[str, Any]):
    """A read-only view of the upstream payload whose repr masks the raw session token.

    `Session.raw` carries the payload as it arrived so an application can read its own fields,
    but in cookie mode that payload holds the raw session token under `token` in cleartext -
    which `repr(session.raw)` would render even though `Session.token` (a `SecretStr`) is masked.
    The value stays reachable by key; only the repr redacts it (D-194).
    """

    __slots__ = ("_data",)
    _MASKED = frozenset({"token"})

    def __init__(self, value: Mapping[str, Any]) -> None:
        self._data: dict[str, Any] = dict(value)

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        rendered = ", ".join(
            f"{key!r}: {'<redacted>' if key in self._MASKED else value!r}"
            for key, value in self._data.items()
        )
        return f"{{{rendered}}}"


def _freeze(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return _RawMapping(value)


UserId = Annotated[
    str,
    BeforeValidator(_coerce_integer_id),
    Field(min_length=1, max_length=ID_MAX_LENGTH),
    AfterValidator(_reject_unusable_id),
]
UpstreamDatetime = Annotated[datetime, AfterValidator(_assume_utc)]
RawPayload = Annotated[Mapping[str, Any], AfterValidator(_freeze)]


class User(BaseModel):
    """A Better Auth user, parsed from a JWT payload or a `get-session` response.

    Fields are snake_case and the camelCase names Better Auth puts on the wire are
    accepted as aliases, so `emailVerified` populates `email_verified`. Aliases are
    validation-only: this model always *dumps* snake_case, whichever door it left by.
    Keys it does not declare are ignored here and stay readable on `Session.raw`.

    Only `id` is required. Integer ids are accepted and stored as strings, because
    Better Auth's `advanced.database.useNumberId` makes them a supported configuration.
    Every other field is optional and defaults to `None`.

    Users compare and hash by value, so a `User` is usable as a dict key or set member.

    Subclass it to type the fields your deployment actually has:

        class AdminUser(User):
            role: str | None = None

    Then pass the subclass where a user model is expected; `Session[AdminUser].user` is
    typed as `AdminUser`.

    Do not treat these fields as trusted assertions about the user. A Better Auth
    `additionalFields` entry defaults to `input: true`, which means the account holder
    could set it at sign-up; only server-controlled plugin fields (the admin plugin's
    `role` and `banned`, for instance) reflect a decision your system made. Read `None`
    as "unknown", never as "safe" - a missing `banned` is not an unbanned user.

    Instances are immutable.
    """

    model_config = ConfigDict(
        alias_generator=AliasGenerator(validation_alias=to_camel),
        extra="ignore",
        frozen=True,
        populate_by_name=True,
    )

    id: UserId
    email: str | None = Field(default=None, max_length=EMAIL_MAX_LENGTH)
    name: str | None = Field(default=None, max_length=NAME_MAX_LENGTH)
    email_verified: bool | None = None
    image: str | None = Field(default=None, max_length=IMAGE_MAX_LENGTH)
    created_at: UpstreamDatetime | None = None
    updated_at: UpstreamDatetime | None = None


# The `_co` suffix PLC0105 asks for cannot be applied: this name is exported API.
UserT = TypeVar("UserT", bound=User, covariant=True)  # noqa: PLC0105


class Session(BaseModel, Generic[UserT]):
    """A verified session, generic over the user model it carries.

    Instances are built by this library's verifiers once verification has succeeded.
    They are never parsed from an upstream response, so an unknown keyword argument is
    rejected rather than ignored.

    `Session` is covariant in its user type: a `Session[AdminUser]` may be passed
    wherever a `Session[User]` is expected.

    Attributes:
        user: The authenticated user. `Session[AdminUser].user` is typed `AdminUser`.
        expires_at: Session expiry, timezone-aware. Required, and deliberately without a
            default: every mode carries an expiry somewhere, so a verifier that forgot to
            map one would otherwise produce a session that never expires. Pass `None`
            only as a visible statement that this credential has no expiry. Naive values
            are rejected - this library enforces expiry, and a naive value reads the
            wrong clock.
        token: The raw session token in cookie mode; `None` in JWT mode, which has no
            server-side session token to hand back. Held as a `SecretStr`, so it is
            masked in reprs and dumps and excluded from responses; read it deliberately
            with `.get_secret_value()`.
        raw: The upstream payload as it arrived - the decoded JWT claims, or the whole
            `get-session` body. Everything this model does not promote to a field
            (`ipAddress`, `userAgent`, `activeOrganizationId`, plugin data) is reachable
            here, which is what keeps upstream field additions from being breaking
            changes. It is read-only and excluded from every serialization, so it never
            reaches a response body or an OpenAPI schema. In cookie mode it also carries
            the raw session token under `token`: its repr masks that one value (as
            `Session.token` is masked), but the value stays reachable by key, so do not
            log `raw` wholesale.

    `raw` is copied one level deep: the mapping itself is new and read-only, but nested
    containers are shared with the payload that was passed in. Never hand one payload
    dict to two `Session` constructions, and deep-copy before caching one.

    Instances are immutable. `Session` is formally hashable, but `hash()` raises
    `TypeError` at call time because `raw` is a mapping - key on `session.user` instead.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    user: UserT
    expires_at: AwareDatetime | None
    token: SecretStr | None = None
    raw: RawPayload = Field(repr=False, exclude=True)
