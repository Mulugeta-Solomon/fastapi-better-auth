"""The dispatcher, and the two dependencies user code declares."""

from __future__ import annotations

import inspect
import logging
import os
import sys
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, NoReturn, TypeVar, cast

if sys.version_info >= (3, 11):  # pragma: no cover - one branch per interpreter
    from builtins import BaseExceptionGroup
else:  # pragma: no cover - one branch per interpreter
    from exceptiongroup import BaseExceptionGroup

from fastapi import Depends
from starlette.requests import HTTPConnection

from .errors import (
    AmbiguousCredentials,
    BetterAuthError,
    ConfigurationError,
    InvalidCredential,
    MissingCredential,
    SessionError,
)
from .models import Session, User
from .verifiers import Verifier

logger = logging.getLogger("fastapi_better_auth")

BASE_URL_ENV = "BETTER_AUTH_URL"
GROUP_TYPES: tuple[type[BaseException], ...] = (BaseExceptionGroup,)

BARE_FACTORY = (
    "current_session / optional_session was passed to Depends() without being called. Write"
    " Depends(auth.current_session()) or Depends(auth.optional_session()) - with the"
    " parentheses. Passed bare, the factory itself becomes the dependency: FastAPI calls it,"
    " discards the dependency it returns, and nothing verifies the request. At router level"
    " that is a silent bypass of every route under the router, which is why it is refused"
    " here, while the application is still being built."
)

UserModelT = TypeVar("UserModelT", bound=User)

Resolver = Callable[[HTTPConnection], Awaitable["Session[Any] | None"]]
Dependency = Callable[..., Awaitable[Any]]
Presented = list["tuple[Verifier, Any]"]


class _NotADependency:
    """The type of the guard parameter on both factories, and never a dependency's type.

    FastAPI builds a pydantic field for every parameter of a dependency it does not recognize
    as one of its own, and it does so while the route is being registered. A factory passed to
    `Depends` *without* being called therefore reaches this hook at import time - the last
    moment before an application carrying a silent authentication bypass would have booted
    healthy. A normal call never touches pydantic, so nothing about the supported spelling
    changes.
    """

    @classmethod
    def __get_pydantic_core_schema__(cls, source: object, handler: object) -> NoReturn:
        raise ConfigurationError(BARE_FACTORY)

    def __repr__(self) -> str:
        return "<not a dependency>"


NOT_A_DEPENDENCY = _NotADependency()


class BetterAuth:
    """The bridge: verifiers composed into the dependencies your routes declare.

    One instance owns the modes an application accepts and the dependency callables it
    hands to FastAPI:

        auth = BetterAuth(verifiers=[JwtVerifier(base_url="https://auth.example.com")])

        Current = Annotated[Session[MyUser], Depends(auth.current_session(user_model=MyUser))]
        Maybe = Annotated[Session[MyUser] | None, Depends(auth.optional_session(user_model=MyUser))]

        @app.get("/me")
        async def me(session: Current) -> MyUser:
            return session.user

    **Which verifier answers is decided by which credential is present**, in the order the
    verifiers were declared, and the decision is made from extraction alone - before
    anything is verified:

    - *Exactly one credential.* That verifier verifies it, and its answer is final. If it
      refuses, the request is refused: falling through to the next verifier would let an
      attacker forge the weakest credential in the list and be re-checked by another mode.
    - *Two or more credentials.* `AmbiguousCredentials`, raised before any verification. A
      request that presents two identities has not said who it is, and choosing one for it
      would let the client choose which verifier answers.
    - *No credential.* `current_session` raises `MissingCredential`; `optional_session`
      returns `None`. That is the only case in which `optional_session` returns `None`.

    Everything that can be wrong with the configuration is raised while the application is
    being built - an empty verifier list, the same verifier twice, an object that is not a
    verifier, a user model that is not a `User` - so a deployment that could not verify
    safely never finishes starting up. The two faults that cannot be seen until a request
    arrives, because `Verifier` is a structural protocol, are still answered as
    `ConfigurationError` rather than as a refusal: a `verify` that is not awaitable, and
    one that answers with something other than a `Session` of the requested user model.
    Degrading either into a 401 would hide a broken verifier permanently, and a `None`
    answer taken at face value would read as "nobody asked".

    An exception that escapes a verifier is contained: it is logged with its traceback and
    answered as `InvalidCredential`. `extract` parses attacker-supplied bytes, so a crafted
    credential that makes a parser raise would otherwise produce a 500 - the one
    request-time answer a client can tell apart from every other.

    Args:
        verifiers: One or more verifiers, in the order their credentials should be looked
            for. Each must satisfy the `Verifier` protocol and validate its own
            configuration in its own `__init__`.

    Raises:
        ConfigurationError: If the sequence is empty, or an entry is not a usable verifier.
    """

    def __init__(self, *, verifiers: Sequence[Verifier]) -> None:
        self._verifiers = _validated(verifiers)
        self._nothing = _nothing_presented(self._verifiers)
        self._resolvers: dict[type[User], Resolver] = {}
        self._required: dict[type[User], Dependency] = {}
        self._optional: dict[type[User], Dependency] = {}

    @classmethod
    def from_env(cls) -> BetterAuth:
        """Build a JWT-mode bridge from the environment, reading exactly one variable.

        `BETTER_AUTH_URL` - the same name the Better Auth server itself reads for its
        `baseURL`, so a deployment that already sets it needs nothing new:

            auth = BetterAuth.from_env()

        That is the whole of it, and it is exactly equivalent to writing
        `BetterAuth(verifiers=[JwtVerifier(base_url=<that value>)])` by hand. **No other
        variable is consulted.** The algorithm allowlist, `leeway`, the token-lifetime
        ceiling, the transport, a second verifier - all of them stay constructor arguments,
        where the code that chose them is the code you read in review. A variable that could
        widen `leeway` would be an environment able to extend session lifetimes without a
        deploy; one that could move the key set would be a bypass with no signature left to
        fall back on.

        Returns:
            A `BetterAuth` composing a single `JwtVerifier` on the configured origin.

        Raises:
            ConfigurationError: If `BETTER_AUTH_URL` is missing or blank, or is not a usable
                origin. Raised while the application is being built, so a deployment that
                could not verify anything never finishes starting up.
        """
        # Imported here, not at module scope: the dispatcher knows the Verifier protocol,
        # and nothing about which modes exist.
        from .jwt_verifier import JwtVerifier

        value = os.environ.get(BASE_URL_ENV, "")
        if not value.strip():
            raise ConfigurationError(
                f"{BASE_URL_ENV} is not set. from_env() reads exactly that one variable, and"
                " it must be your Better Auth server's origin - the same value its own"
                " baseURL is set to, such as 'https://auth.example.com'. Everything else is a"
                " constructor argument: BetterAuth(verifiers=[JwtVerifier(base_url=...)])."
            )
        return cls(verifiers=[JwtVerifier(base_url=value)])

    @property
    def verifiers(self) -> tuple[Verifier, ...]:
        """The verifiers, in declared extraction order. A snapshot taken at construction."""
        return self._verifiers

    def current_session(
        self,
        *,
        user_model: type[UserModelT] = User,
        _guard: _NotADependency = NOT_A_DEPENDENCY,
    ) -> Callable[..., Awaitable[Session[UserModelT]]]:
        """Build the dependency that requires a verified session.

        Returns the *same* callable every time it is asked for a given `user_model`, and
        that identity is load-bearing: FastAPI keys its per-request dependency cache on the
        callable, so a router-level dependency and a route-level one resolve to one cache
        entry and the request is verified exactly once. A factory that returned a fresh
        closure each call would verify twice - two JWKS lookups, two calls against
        upstream's rate limit, and two chances for the answers to disagree.

        `optional_session` shares the same underlying resolver, so declaring both on one
        route also verifies once.

        **Call it.** `Depends(auth.current_session())`, with the parentheses. Passing the
        factory itself - `Depends(auth.current_session)` - used to be a bypass rather than an
        error: at router level FastAPI resolved *it* as the dependency, called it, discarded
        the callable it returned, and no verification happened on any route under that router.
        It is now refused with a `ConfigurationError` naming the missing parentheses, and
        refused while the application is being built rather than on a request, so a deployment
        carrying that mistake never starts up.

        Args:
            user_model: The `User` subclass to parse the upstream payload into. The
                returned dependency is typed `Session[user_model]`.

        Returns:
            A dependency callable to pass to `Depends`.

        Raises:
            ConfigurationError: If `user_model` is not a `User` subclass; while the
                application is being built, if this factory was passed to `Depends` without
                being called; at request time, if a verifier answers with something that is
                not a `Session[user_model]`.
            MissingCredential: At request time, when no verifier found a credential.
            AmbiguousCredentials: At request time, when two or more verifiers did.
            SessionError: At request time, whatever the chosen verifier raised.
        """
        _validate_user_model(user_model)
        cached = self._required.get(user_model)
        if cached is None:
            cached = self._required.setdefault(user_model, self._require(user_model))
        return cast("Callable[..., Awaitable[Session[UserModelT]]]", cached)

    def optional_session(
        self,
        *,
        user_model: type[UserModelT] = User,
        _guard: _NotADependency = NOT_A_DEPENDENCY,
    ) -> Callable[..., Awaitable[Session[UserModelT] | None]]:
        """Build the dependency that allows an anonymous request through.

        `None` means *nobody asked* - and nothing else. A credential that was presented and
        did not verify still raises: an endpoint that quietly degraded a forged token to
        "anonymous" would hand attackers a way to probe which credentials this deployment
        rejects, and would turn a revoked session into a silent downgrade rather than a
        refusal.

        Memoized on `user_model`, and sharing one resolver with `current_session`, for the
        reasons in that method's documentation.

        **Call it.** `Depends(auth.optional_session())`, with the parentheses - passing the
        factory itself is refused while the application is built. See `current_session`.

        Args:
            user_model: The `User` subclass to parse the upstream payload into.

        Returns:
            A dependency callable to pass to `Depends`, resolving to `Session[user_model]`
            or `None`.

        Raises:
            ConfigurationError: If `user_model` is not a `User` subclass; while the
                application is being built, if this factory was passed to `Depends` without
                being called; at request time, if a verifier answers with something that is
                not a `Session[user_model]`.
            AmbiguousCredentials: At request time, when two or more verifiers found one.
            SessionError: At request time, for any credential that was presented and did
                not verify.
        """
        _validate_user_model(user_model)
        cached = self._optional.get(user_model)
        if cached is None:
            cached = self._optional.setdefault(user_model, self._allow(user_model))
        return cast("Callable[..., Awaitable[Session[UserModelT] | None]]", cached)

    def _require(self, user_model: type[UserModelT]) -> Dependency:
        resolve = self._resolver_for(user_model)

        async def require(session: Session[Any] | None = Depends(resolve)) -> Session[Any]:
            if session is None:
                raise MissingCredential(reason=self._nothing)
            return session

        return require

    def _allow(self, user_model: type[UserModelT]) -> Dependency:
        resolve = self._resolver_for(user_model)

        async def allow(session: Session[Any] | None = Depends(resolve)) -> Session[Any] | None:
            return session

        return allow

    def _resolver_for(self, user_model: type[UserModelT]) -> Resolver:
        cached = self._resolvers.get(user_model)
        if cached is not None:
            return cached

        async def resolve(connection: HTTPConnection) -> Session[UserModelT] | None:
            return await self._authenticate(connection, user_model)

        return self._resolvers.setdefault(user_model, resolve)

    async def _authenticate(
        self, connection: HTTPConnection, user_model: type[UserModelT]
    ) -> Session[UserModelT] | None:
        presented: Presented = []
        credential: object | None = None
        try:
            for verifier in self._verifiers:
                credential = _extracted(verifier, connection)
                if credential is not None:
                    presented.append((verifier, credential))
            credential = None
            if len(presented) > 1:
                names = [_named(each) for each, _credential in presented]
                raise AmbiguousCredentials(reason=_ambiguity(names))
            if not presented:
                return None
            chosen, credential = presented[0]
            answer = await _verified(chosen, credential, user_model)
        finally:
            credential = None
            presented.clear()
        return _checked(answer, chosen, user_model)


def _extracted(verifier: Verifier, connection: HTTPConnection) -> object | None:
    try:
        credential = verifier.extract(connection)
    except BetterAuthError:
        raise
    except Exception as exc:  # noqa: BLE001 - see _contained: a 500 here is the leak
        raise _resolved(exc, verifier, "extract", (BetterAuthError,)) from None
    if inspect.isawaitable(credential):
        if inspect.iscoroutine(credential):
            credential.close()
        raise ConfigurationError(
            f"{type(verifier).__name__}.extract() returned an awaitable. extract() is a"
            " synchronous presence check, and an awaitable is never None, so this verifier"
            " would claim every request. Declare it with `def` - and note that a decorator"
            " hides an `async def` from the check made at construction."
        )
    return credential


async def _verified(verifier: Verifier, credential: object, user_model: type[UserModelT]) -> Any:
    try:
        answer = verifier.verify(credential, user_model)
        if not inspect.isawaitable(answer):
            raise ConfigurationError(
                f"{type(verifier).__name__}.verify() did not return an awaitable. Declare it"
                " with `async def`."
            )
        return await answer
    except (BetterAuthError, SessionError):
        raise
    except Exception as exc:  # noqa: BLE001 - see _contained: a 500 here is the leak
        raise _resolved(exc, verifier, "verify", (BetterAuthError, SessionError)) from None


def _unwrapped(exc: BaseException) -> BaseException:
    """A task group with one failing child delivers a group whose single leaf is the answer."""
    leaf = exc
    while isinstance(leaf, GROUP_TYPES):
        nested: tuple[BaseException, ...] = getattr(leaf, "exceptions", ())
        if len(nested) != 1:
            break
        leaf = nested[0]
    return leaf


def _resolved(
    exc: Exception,
    verifier: Verifier,
    method: str,
    honoured: tuple[type[BaseException], ...],
) -> BaseException:
    """Decide whether an escaping exception is an answer or an accident.

    `anyio` task groups - the concurrency tool this library mandates - wrap a child's
    exception in a `BaseExceptionGroup`, and a group whose leaves are all `Exception` is
    itself an `Exception`. Without unwrapping, a verifier's deliberate `CsrfFailure` (403,
    no challenge) raised from inside a task group is rewritten as `InvalidCredential`
    (401, with a challenge) - a wire-shape change nothing else in the suite can see.

    A single-leaf group is that leaf, and an honoured leaf is re-raised **as itself**, so
    its class, status, headers and `reason` all survive. A group with more than one leaf is
    not one verifier's answer, so it stays contained rather than guessed at.
    """
    leaf = _unwrapped(exc)
    if isinstance(leaf, honoured):
        return leaf
    return _contained(leaf, verifier, method)


def _contained(exc: BaseException, verifier: Verifier, method: str) -> InvalidCredential:
    """Turn an escaping exception into the uniform refusal, and log the real one.

    A 500 is the only request-time answer a client can tell apart from every other, and
    `extract` parses attacker bytes by definition - so a crafted credential that makes a
    parser raise becomes a probe for which verifiers this deployment runs. Under a debug
    handler the 500 body is a traceback carrying the credential out of the frame locals.
    Operators still get the whole traceback, through the log.
    """
    name = type(verifier).__name__
    logger.exception("%s.%s raised", name, method)
    return InvalidCredential(reason=f"{type(exc).__name__} escaped {name}.{method}")


def _checked(session: Any, verifier: Verifier, user_model: type[UserModelT]) -> Session[UserModelT]:
    """Check the answer rather than assume it: `Verifier` is a structural protocol.

    `None` is the dispatcher's absence signal, so returning it unchecked would degrade a
    credential that *was* presented into an anonymous request - which `optional_session`
    answers with a 200. A loud refusal is the right answer to a broken verifier; a uniform
    401 would hide it forever.
    """
    name = type(verifier).__name__
    if not isinstance(session, Session):
        raise ConfigurationError(
            f"{name}.verify() returned {type(session).__name__} for a credential it"
            " accepted; it must return a Session or raise a SessionError."
        )
    typed = cast("Session[UserModelT]", session)
    if not isinstance(typed.user, user_model):
        raise ConfigurationError(
            f"{name}.verify() ignored user_model: it returned a"
            f" {type(typed.user).__name__} where {user_model.__name__} was asked for."
        )
    return typed


def _named(verifier: Verifier) -> str:
    """Class name plus declared source. Operator-supplied labels, never client data."""
    return f"{type(verifier).__name__}({verifier.credential_source})"


def _nothing_presented(verifiers: Sequence[Verifier]) -> str:
    asked = ", ".join(_named(verifier) for verifier in verifiers)
    return f"no credential presented; verifiers asked: {asked}"


def _ambiguity(names: Sequence[str]) -> str:
    return f"{len(names)} credentials presented at once: {', '.join(names)}"


def _validated(verifiers: object) -> tuple[Verifier, ...]:
    if isinstance(verifiers, (str, bytes, bytearray)) or not isinstance(verifiers, Sequence):
        raise ConfigurationError(
            "BetterAuth(verifiers=...) takes a sequence of verifiers, in the order their"
            f" credentials should be looked for; got {type(verifiers).__name__}."
        )
    ordered = tuple(cast("Sequence[object]", verifiers))
    if not ordered:
        raise ConfigurationError(
            "BetterAuth(verifiers=...) needs at least one verifier: with none configured,"
            " every request would be answered as unauthenticated."
        )
    seen: list[Verifier] = []
    for index, verifier in enumerate(ordered):
        _validate_verifier(verifier, index)
        checked = cast("Verifier", verifier)
        if any(checked is earlier for earlier in seen):
            raise ConfigurationError(
                f"BetterAuth(verifiers=...) lists the same {type(checked).__name__} twice."
                " Both copies would find the same credential, so every request carrying it"
                " would be ambiguous."
            )
        _reject_collision(checked, seen)
        seen.append(checked)
    return cast("tuple[Verifier, ...]", ordered)


def _reject_collision(verifier: Verifier, seen: Sequence[Verifier]) -> None:
    """Two *different* verifiers reading one credential — what identity cannot see."""
    source = verifier.credential_source.strip().casefold()
    clash = next((s for s in seen if s.credential_source.strip().casefold() == source), None)
    if clash is None:
        return
    raise ConfigurationError(
        f"BetterAuth(verifiers=...) has two verifiers on one credential:"
        f" {type(clash).__name__} and {type(verifier).__name__} both declare"
        f" credential_source={verifier.credential_source!r}. Both would find it, so every"
        " request carrying that credential would be ambiguous."
    )


def _validate_verifier(verifier: object, index: int) -> None:
    where = f"BetterAuth(verifiers=...)[{index}]"
    if not isinstance(verifier, Verifier):
        raise ConfigurationError(
            f"{where} is a {type(verifier).__name__}, which does not implement the Verifier"
            " protocol: it needs a synchronous extract(connection) and an async"
            " verify(credential, user_model)."
        )
    for method in ("extract", "verify"):
        if not callable(getattr(verifier, method)):
            raise ConfigurationError(f"{where} has a {method} that is not callable.")
    _validate_source(verifier.credential_source, where)
    if inspect.iscoroutinefunction(verifier.extract):
        raise ConfigurationError(
            f"{where} declares extract() as async. extract() is a synchronous presence"
            " check; an async one returns a coroutine object, which is never None, so this"
            " verifier would claim every request and every request would be ambiguous."
        )


def _validate_source(source: object, where: str) -> None:
    """`source` is annotated `str`; the object declaring it was written by someone else."""
    if not isinstance(source, str) or not source.strip():
        raise ConfigurationError(
            f"{where} must declare a non-empty string credential_source naming where its"
            " credential comes from, such as 'cookie:better-auth.session_token'. It is how"
            " two verifiers reading one credential are caught here rather than by every"
            f" request being ambiguous; got {source!r}."
        )


def _validate_user_model(user_model: object) -> None:
    if not (isinstance(user_model, type) and issubclass(user_model, User)):
        raise ConfigurationError(
            "user_model must be User or a subclass of it, because the upstream payload is"
            f" parsed into it; got {user_model!r}."
        )
