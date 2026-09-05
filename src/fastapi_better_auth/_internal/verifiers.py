"""The extension point: what a verification mode has to be able to do."""

from __future__ import annotations

from typing import Any, Protocol, TypeVar, runtime_checkable

from starlette.requests import HTTPConnection

from .models import Session, User

UserModelT = TypeVar("UserModelT", bound=User)


@runtime_checkable
class Verifier(Protocol):
    """One way of proving who is calling: find the credential, then verify it.

    Implement this to teach the bridge a credential your deployment already has - a
    gateway-issued assertion, a service-to-service token, a test double. The shipped modes
    implement exactly this protocol and get no privileges yours does not.

    The split between the two methods is a security rule, not a convenience. `extract`
    answers "is this request mine?" from what is already in memory; the answer decides
    which verifier runs, before any verification happens. Merging the two would make
    "which verifier owns this request" a question that can only be answered by trying them
    in turn - and trying the next verifier after one has failed is a downgrade attack: an
    attacker forges the credential of whichever mode is weakest and rides the fallthrough.

    Configuration is validated eagerly, in `__init__`, raising `ConfigurationError`. A
    verifier that cannot verify safely must stop the application from starting, never
    answer a request with a 500.

    An implementation narrows the credential to whatever shape it actually passes between
    its own two halves; nothing else looks inside it:

        class HeaderVerifier:
            credential_source = "header:x-assertion"

            def extract(self, connection: HTTPConnection) -> str | None:
                return connection.headers.get("x-assertion")

            async def verify(self, credential: str, user_model: type[UserT]) -> Session[UserT]:
                ...

    The protocol is runtime-checkable, and `BetterAuth` checks every verifier it is handed.
    Be aware of what that check can see: `isinstance` against a runtime-checkable protocol
    proves the member *names* exist, and nothing about their signatures or their
    callability.

    Attributes:
        credential_source: A short label naming *where* this verifier's credential comes
            from - `"header:authorization-bearer"`, `"cookie:better-auth.session_token"`.
            `BetterAuth` requires a non-empty string and refuses, at construction, to
            compose two verifiers that declare the same one: they would both find the same
            credential, so every request carrying it would be `AmbiguousCredentials` - a
            total authentication outage that startup would otherwise call healthy, and one
            that comparing verifier *identity* cannot see, because the two are different
            objects.

            It is an honesty contract, and it is used for exactly two things:
            build-time collision detection, and naming the verifier in operator-facing
            reasons and logs. It is **never** consulted at request time and no security
            decision is ever made from it - a verifier that declares a label it does not
            read is a verifier that misleads its own operator, not one that can authorize
            anything. Dispatch keys on what `extract` actually returns.
    """

    credential_source: str

    def extract(self, connection: HTTPConnection) -> object | None:
        """Return this verifier's credential from the request, or `None` if it is absent.

        A presence check, not a verification: read a header or a cookie, do the cheapest
        structural work that distinguishes "this is mine" from "this is not", and hand
        back whatever `verify` will need. Nothing here decides whether the credential is
        *good*.

        Synchronous and non-blocking on purpose. It runs on every verifier on every
        request, before dispatch has chosen one, so it must not touch the network, the
        filesystem, a lock, or the event loop. It also must not raise: a credential that
        is present but malformed is `verify`'s business, and returning it is how it gets
        there.

        That includes `SessionError`. Raising one here is treated as a parser escape and
        is **not** honoured - it is contained as `InvalidCredential` like any other
        exception, and its `reason` does not survive into the one the client's request
        produces. The asymmetry with `verify`, which may raise `SessionError` freely, is
        deliberate: `extract` decides which verifier *owns* the request, and a method that
        could also reject it would be deciding validity before dispatch had chosen anyone.
        Rejection belongs in `verify`.

        `HTTPConnection` rather than `Request`, so the same dependency serves WebSocket
        routes. Never derive a value that will be compared during verification - an
        issuer, an audience, an allowed origin - from the connection: the Host header and
        the request URL are attacker-controlled (D-010). Those come from configuration.

        Args:
            connection: The incoming HTTP or WebSocket connection.

        Returns:
            The credential, in whatever form `verify` expects, or `None` when this
            verifier's credential is not on the request. `None` is the *only* absence
            signal - an empty string counts as present, and will be dispatched to
            `verify`. Return `None` for a blank or whitespace-only value, or a planted
            empty cookie from a sibling subdomain will make every request ambiguous.
        """
        ...

    async def verify(self, credential: Any, user_model: type[UserModelT]) -> Session[UserModelT]:
        """Verify a credential `extract` found, and build the session it proves.

        This is the whole of verification: signature or lookup, expiry, revocation, and
        parsing the upstream payload into `user_model`. Reaching it means dispatch has
        already committed to this verifier - whatever it raises is the answer to the
        request, and no other verifier is consulted.

        Declare it with `async def`; a plain function is checked for an awaitable result
        and refused loudly if it does not return one.

        Every failure is a `SessionError` subclass carrying a `reason` for operators.
        Anything else that escapes - including a `pydantic.ValidationError` from parsing
        the upstream payload - is contained as `InvalidCredential` and logged, so a
        crafted credential cannot be told apart from any other refusal. That net is a
        backstop, not the contract: build the user with `parse_user`, which does the
        containment deliberately and keeps the payload's own values out of the reason.

        Args:
            credential: Exactly what this verifier's own `extract` returned.
            user_model: The `User` subclass the application asked for. Return
                `Session[user_model]`, not `Session[User]`: returning the wrong model, or
                returning `None`, is refused as a configuration fault.

        Returns:
            The verified session.

        Raises:
            SessionError: On every failure. `InvalidCredential` for a credential that does
                not verify, `SessionExpired` / `SessionRevoked` for one that no longer
                should, `AuthServiceUnavailable` when a dependency could not be reached -
                which is still a refusal, because a session that cannot be verified must
                not be honoured.
        """
        ...


@runtime_checkable
class PreparedVerifier(Protocol):
    """A verifier with startup work an operator may run once, from a lifespan handler.

    Optional, and separate from `Verifier` on purpose. `Verifier` is a `runtime_checkable`
    protocol, so adding a member to it would change `isinstance` for every existing and
    third-party verifier; a verifier that does not implement this one is exactly as valid as
    before, and `BetterAuth.startup()` simply skips it.

    Implement it when a mode has work worth doing at boot rather than on the first request that
    needs it - reaching a network dependency, discovering a schema. `RemoteVerifier` implements
    it to run its reachability-and-contract probe once, so a deployment whose Better Auth server
    cannot honour the get-session contract fails to *start* instead of refusing its first
    authenticated request.

        auth = BetterAuth(verifiers=[RemoteVerifier(base_url=..., csrf=...)])
        app = FastAPI(lifespan=auth.lifespan)

    `prepare()` must be idempotent: `startup()` may be called more than once, and a verifier that
    is also reached lazily runs the same work on first use. It raises `ConfigurationError` for a
    fault that makes the deployment unservable, so it propagates out of the lifespan and stops the
    server from taking traffic.
    """

    async def prepare(self) -> None:
        """Run this verifier's startup work once. Idempotent; raises `ConfigurationError` on a
        fault that should stop the application from starting."""
        ...
