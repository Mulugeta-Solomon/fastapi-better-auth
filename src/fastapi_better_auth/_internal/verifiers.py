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
            def extract(self, connection: HTTPConnection) -> str | None:
                return connection.headers.get("x-assertion")

            async def verify(self, credential: str, user_model: type[UserT]) -> Session[UserT]:
                ...

    The protocol is runtime-checkable, and `BetterAuth` checks every verifier it is handed.
    Be aware of what that check can see: `isinstance` against a runtime-checkable protocol
    proves the two method *names* exist and nothing about their signatures.
    """

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
        crafted credential cannot be told apart from any other refusal. Do the containment
        yourself where you can: catch `ValidationError` around your model parsing and
        raise `InvalidCredential` with a reason that names the field rather than the value.

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
