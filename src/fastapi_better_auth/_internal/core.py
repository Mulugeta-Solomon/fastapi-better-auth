"""The dispatcher, and the two dependencies user code declares."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, TypeVar, cast

from fastapi import Depends
from starlette.requests import HTTPConnection

from .errors import AmbiguousCredentials, ConfigurationError, MissingCredential
from .models import Session, User
from .verifiers import Verifier

UserModelT = TypeVar("UserModelT", bound=User)

Resolver = Callable[[HTTPConnection], Awaitable["Session[Any] | None"]]
Dependency = Callable[..., Awaitable[Any]]
Presented = list["tuple[Verifier, Any]"]


class BetterAuth:
    """The bridge: verifiers composed into the dependencies your routes declare.

    One instance owns the modes an application accepts and the dependency callables it
    hands to FastAPI:

        auth = BetterAuth(verifiers=[JwtVerifier(base_url="https://auth.example.com")])

        CurrentSession = Annotated[Session[MyUser], Depends(auth.current_session(user_model=MyUser))]
        MaybeSession = Annotated[Session[MyUser] | None, Depends(auth.optional_session(user_model=MyUser))]

        @app.get("/me")
        async def me(session: CurrentSession) -> MyUser:
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
    being built - an empty verifier list, an object that is not a verifier, a user model
    that is not a `User` - so a deployment that could not verify safely never finishes
    starting up.

    Args:
        verifiers: One or more verifiers, in the order their credentials should be looked
            for. Each must satisfy the `Verifier` protocol and validate its own
            configuration in its own `__init__`.

    Raises:
        ConfigurationError: If the sequence is empty, or an entry is not a usable verifier.
    """

    def __init__(self, verifiers: Sequence[Verifier]) -> None:
        self._verifiers = _validated(verifiers)
        self._resolvers: dict[type[User], Resolver] = {}
        self._required: dict[type[User], Dependency] = {}
        self._optional: dict[type[User], Dependency] = {}

    @property
    def verifiers(self) -> tuple[Verifier, ...]:
        """The verifiers, in declared extraction order. A snapshot taken at construction."""
        return self._verifiers

    def current_session(
        self, user_model: type[UserModelT] = User
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

        Args:
            user_model: The `User` subclass to parse the upstream payload into. The
                returned dependency is typed `Session[user_model]`.

        Returns:
            A dependency callable to pass to `Depends`.

        Raises:
            ConfigurationError: If `user_model` is not a `User` subclass.
            MissingCredential: At request time, when no verifier found a credential.
        """
        _validate_user_model(user_model)
        cached = self._required.get(user_model)
        if cached is None:
            cached = self._required.setdefault(user_model, self._require(user_model))
        return cast("Callable[..., Awaitable[Session[UserModelT]]]", cached)

    def optional_session(
        self, user_model: type[UserModelT] = User
    ) -> Callable[..., Awaitable[Session[UserModelT] | None]]:
        """Build the dependency that allows an anonymous request through.

        `None` means *nobody asked* - and nothing else. A credential that was presented and
        did not verify still raises: an endpoint that quietly degraded a forged token to
        "anonymous" would hand attackers a way to probe which credentials this deployment
        rejects, and would turn a revoked session into a silent downgrade rather than a
        refusal.

        Memoized on `user_model`, and sharing one resolver with `current_session`, for the
        reasons in that method's documentation.

        Args:
            user_model: The `User` subclass to parse the upstream payload into.

        Returns:
            A dependency callable to pass to `Depends`, resolving to `Session[user_model]`
            or `None`.

        Raises:
            ConfigurationError: If `user_model` is not a `User` subclass.
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
                raise MissingCredential(reason=self._nothing_presented())
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
        presented: Presented = [
            (verifier, credential)
            for verifier in self._verifiers
            if (credential := verifier.extract(connection)) is not None
        ]
        if len(presented) > 1:
            raise AmbiguousCredentials(reason=_ambiguity(presented))
        if not presented:
            return None
        verifier, credential = presented[0]
        return await verifier.verify(credential, user_model)

    def _nothing_presented(self) -> str:
        asked = ", ".join(type(verifier).__name__ for verifier in self._verifiers)
        return f"no credential presented; verifiers asked: {asked}"


def _ambiguity(presented: Presented) -> str:
    names = ", ".join(type(verifier).__name__ for verifier, _credential in presented)
    return f"{len(presented)} credentials presented at once: {names}"


def _validated(verifiers: object) -> tuple[Verifier, ...]:
    if isinstance(verifiers, (str, bytes, bytearray)) or not isinstance(verifiers, Sequence):
        raise ConfigurationError(
            "BetterAuth(verifiers=...) takes a sequence of verifiers, in the order their"
            f" credentials should be looked for; got {type(verifiers).__name__}."
        )
    ordered = cast("tuple[Verifier, ...]", tuple(cast("Sequence[object]", verifiers)))
    if not ordered:
        raise ConfigurationError(
            "BetterAuth(verifiers=...) needs at least one verifier: with none configured,"
            " every request would be answered as unauthenticated."
        )
    for index, verifier in enumerate(ordered):
        _validate_verifier(verifier, index)
    return ordered


def _validate_verifier(verifier: object, index: int) -> None:
    where = f"BetterAuth(verifiers=...)[{index}]"
    if not isinstance(verifier, Verifier):
        raise ConfigurationError(
            f"{where} is a {type(verifier).__name__}, which does not implement the Verifier"
            " protocol: it needs a synchronous extract(connection) and an async"
            " verify(credential, user_model)."
        )
    if inspect.iscoroutinefunction(verifier.extract):
        raise ConfigurationError(
            f"{where} declares extract() as async. extract() is a synchronous presence"
            " check; an async one returns a coroutine object, which is never None, so this"
            " verifier would claim every request and every request would be ambiguous."
        )
    if not inspect.iscoroutinefunction(verifier.verify):
        raise ConfigurationError(
            f"{where} declares verify() as a plain function. verify() is awaited on every"
            " request, so a synchronous one would fail at request time rather than here."
        )


def _validate_user_model(user_model: object) -> None:
    if not (isinstance(user_model, type) and issubclass(user_model, User)):
        raise ConfigurationError(
            "user_model must be User or a subclass of it, because the upstream payload is"
            f" parsed into it; got {user_model!r}."
        )
