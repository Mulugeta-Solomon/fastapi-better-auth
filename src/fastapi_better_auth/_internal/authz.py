"""Authorization: what a session that is already verified is then allowed to do.

Two dependency builders, both composed on `current_session`, so authentication happens first and
exactly once and an unauthenticated request is a 401 that never reaches a rule. Both refuse with
`NotAuthorized` - one 403, one body, no challenge - and put why on the exception rather than on
the wire.

The rules themselves are the consumer's: a synchronous predicate over the session, and an
asynchronous membership lookup taking the resource id this request named. That is deliberate -
this library owns no database - and it puts consumer code inside a refusal path, so everything it
can do wrong is contained here: an answer that is not `True`, a missing `async`, an unexpected
`async`, and any exception at all.
"""

from __future__ import annotations

import inspect
import keyword
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Generic, TypeVar, cast

from fastapi import Depends
from pydantic import TypeAdapter, ValidationError

from .containment import unwrapped
from .errors import BetterAuthError, ConfigurationError, NotAuthorized, SessionError
from .models import Session, User, UserId
from .reasons import safe_label

logger = logging.getLogger("fastapi_better_auth")

UserModelT = TypeVar("UserModelT", bound=User)
GrantT = TypeVar("GrantT")

Dependency = Callable[..., Awaitable[Any]]
Predicate = Callable[[Session[Any]], Any]
Member = Callable[[str, Session[Any]], Any]

SESSION_PARAM = "session"
RESERVED = frozenset({SESSION_PARAM, "connection"})
"""Names this dependency uses itself; binding the resource id to one would shadow the session."""

PREDICATE = "authorization predicate"
LOOKUP = "membership lookup"
HONOURED: tuple[type[BaseException], ...] = (BetterAuthError, SessionError)

RESOURCE_ID: TypeAdapter[str] = TypeAdapter(UserId)
"""One spelling of the id rules: the same `UserId` a `User.id` is validated against."""

ASYNC_PREDICATE = (
    "require(predicate, ...) was given an async predicate. A coroutine object is truthy but is"
    " never True, so every request would be refused - permanently, and indistinguishably from a"
    " policy that simply says no. Declare it with `def`; work that has to await belongs in"
    " require_membership's lookup."
)
SYNC_LOOKUP = (
    "require_membership(..., member, ...) was given a callable that did not return an awaitable."
    " Declare it with `async def`. A value returned from a plain `def` would reach the route as"
    " the grant, so a missing keyword would decide the authorization answer."
)


@dataclass(frozen=True, slots=True)
class Membership(Generic[UserModelT, GrantT]):
    """What `BetterAuth.require_membership` hands a route once membership is established.

    Three things, and deliberately not just the session: the route almost always needs the grant
    the lookup found - a role, a row, a set of scopes - and re-deriving it inside the handler
    would mean asking the same question twice and risking two different answers.

    Attributes:
        session: The verified session, typed on the user model the gate was built with.
        resource_id: The id this request named, exactly as FastAPI resolved it from the path or
            the query - never a value read back out of the session.
        grant: Whatever the membership lookup answered. `None` and `False` never reach here;
            they are the refusal. Any other value, falsy or not, is a grant.

    Immutable, so a route body cannot edit the authorization answer it was given and pass it on.
    """

    session: Session[UserModelT]
    resource_id: str
    grant: GrantT


def require_dependency(current: Dependency, predicate: object, reason: object) -> Dependency:
    """The dependency `BetterAuth.require` returns: the session, gated on one rule."""
    rule = _validated_predicate(predicate)
    text = _validated_reason(reason, "require")

    async def authorized(session: Session[Any] = Depends(current)) -> Session[Any]:
        if permitted(rule, session):
            return session
        raise NotAuthorized(reason=f"{text} refused for user {session.user.id}")

    return authorized


def membership_dependency(
    current: Dependency, id_param: object, member: object, reason: object
) -> Dependency:
    """The dependency `BetterAuth.require_membership` returns.

    The resource id is a parameter of the returned dependency whose *name* is configuration, so
    the binding is written into `__signature__`: FastAPI reads a dependency's parameters through
    `inspect.signature`, which honours it, and then resolves the name from the route's path when
    the path declares one and from the query string when it does not.
    """
    name = _validated_id_param(id_param)
    lookup = _validated_member(member)
    text = _validated_reason(reason, "require_membership")

    async def authorized(**values: Any) -> Membership[Any, Any]:
        session = cast("Session[Any]", values[SESSION_PARAM])
        resource_id = cast("str", values[name])
        if not _usable(resource_id):
            raise NotAuthorized(reason=_unusable(text, session, name, resource_id))
        grant = await granted(lookup, resource_id, session)
        if grant is None or grant is False:
            raise NotAuthorized(reason=_no_membership(text, session, name, resource_id))
        return Membership(session=session, resource_id=resource_id, grant=grant)

    carrier: Any = authorized
    carrier.__signature__ = _binding(name, current)
    return authorized


def permitted(predicate: Predicate, session: Session[Any]) -> bool:
    """Ask the rule, and hold it to an answer that is exactly `True`.

    `if predicate(...)` would admit every accidental truthy value a consumer can return - a
    database row, a non-empty error string, the coroutine object an `async def` predicate hands
    back - so the comparison is identity against `True` and everything else refuses.
    """
    try:
        answer = predicate(session)
    except HONOURED:
        raise
    except Exception as exc:  # noqa: BLE001 - see _contained: a 500 here is the leak
        raise _resolved(exc, PREDICATE) from None
    if inspect.isawaitable(answer):
        _close(answer)
        raise ConfigurationError(ASYNC_PREDICATE)
    return answer is True


async def granted(member: Member, resource_id: str, session: Session[Any]) -> Any:
    """Run the consumer's membership query under the same containment the dispatcher uses.

    The whole call is inside the `try`, not just the `await`: a plain `def` that raises before
    returning its coroutine does that work synchronously, and a containment wrapping only the
    `await` would never see it (D-064).
    """
    try:
        answer = member(resource_id, session)
        if not inspect.isawaitable(answer):
            raise ConfigurationError(SYNC_LOOKUP)
        return await answer
    except HONOURED:
        raise
    except Exception as exc:  # noqa: BLE001 - see _contained: a 500 here is the leak
        raise _resolved(exc, LOOKUP) from None


def _resolved(exc: Exception, what: str) -> BaseException:
    """Decide whether an escaping exception is an answer or an accident (D-066)."""
    leaf = unwrapped(exc)
    if isinstance(leaf, HONOURED):
        return leaf
    return _contained(leaf, what)


def _contained(exc: BaseException, what: str) -> NotAuthorized:
    """Turn an escaping exception into the uniform refusal, and log the real one.

    A 500 is the one request-time answer a client can tell apart from every other, and under a
    debug handler its body is a traceback out of this request's frames - which hold the session,
    and in cookie mode the raw token with it. Operators still get the whole traceback, through
    the log. The `reason` names the exception's type and not its message: that message is the
    consumer's own text and may hold anything at all.
    """
    logger.exception("the %s raised", what)
    return NotAuthorized(reason=f"{type(exc).__name__} escaped the {what}")


def _binding(name: str, current: Dependency) -> inspect.Signature:
    return inspect.Signature(
        parameters=[
            inspect.Parameter(name, inspect.Parameter.KEYWORD_ONLY, annotation=str),
            inspect.Parameter(
                SESSION_PARAM,
                inspect.Parameter.KEYWORD_ONLY,
                annotation=Session[Any],
                default=Depends(current),
            ),
        ]
    )


def _close(answer: object) -> None:
    """A coroutine nobody awaits is a warning of its own; close it before refusing."""
    if inspect.iscoroutine(answer):
        answer.close()


def _usable(resource_id: str) -> bool:
    try:
        RESOURCE_ID.validate_python(resource_id)
    except ValidationError:
        return False
    return True


def _no_membership(text: str, session: Session[Any], name: str, resource_id: str) -> str:
    label = safe_label(resource_id)
    return f"{text}: no membership for user {session.user.id} in {name}={label}"


def _unusable(text: str, session: Session[Any], name: str, resource_id: str) -> str:
    label = safe_label(resource_id)
    return f"{text}: unusable {name}={label} for user {session.user.id}; nothing was looked up"


def _validated_predicate(predicate: object) -> Predicate:
    if not callable(predicate):
        raise ConfigurationError(
            "require(predicate, ...) takes a synchronous callable that is handed the Session and"
            " answers True to allow the request; got"
            f" {type(predicate).__name__}, which is not callable."
        )
    return cast("Predicate", predicate)


def _validated_member(member: object) -> Member:
    if not callable(member):
        raise ConfigurationError(
            "require_membership(id_param, member, ...) takes an async callable that is handed the"
            " resource id and the Session and answers the grant, or None for no membership; got"
            f" {type(member).__name__}, which is not callable."
        )
    return cast("Member", member)


def _validated_reason(reason: object, where: str) -> str:
    if not isinstance(reason, str) or not reason.strip():
        raise ConfigurationError(
            f"{where}(..., reason=...) must name the rule in your own words. It is the whole of"
            " what an operator reads when this gate refuses a request - it reaches .reason, a"
            f" registered handler and your logs, and never the client; got {reason!r}."
        )
    return reason


def _validated_id_param(id_param: object) -> str:
    if not isinstance(id_param, str) or not id_param.isidentifier() or keyword.iskeyword(id_param):
        raise ConfigurationError(
            "require_membership(id_param, ...) takes the name FastAPI should bind this request's"
            " resource id to, such as 'org_id'. It becomes a parameter of the dependency, so it"
            f" has to be a Python identifier and not a keyword; got {id_param!r}."
        )
    if id_param in RESERVED:
        raise ConfigurationError(
            f"require_membership(id_param=...) may not be {id_param!r}: this dependency declares"
            f" that name itself, so the resource id would shadow {SESSION_PARAM!r}. Name the"
            " parameter after the resource, such as 'org_id'."
        )
    return id_param
