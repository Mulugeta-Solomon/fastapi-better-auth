"""The opt-in 503 for an auth dependency that could not answer, and the one place it is decided.

By default `AuthServiceUnavailable` is the uniform 401, like every other refusal in its family.
A browser reads a credentialed 401 as "the session ended", so during a database stall every
valid session is told to sign in again, and the sign-in meets the same stall. A deployment that
prefers to say "try again later" opts in on `BetterAuth`, and the dispatcher then answers that one
refusal with a 503, a `Retry-After` header and no challenge. A 503 is still a refusal.

The 503 form is built here and nowhere else, as a new object carrying the same `reason`. The
dispatcher also turns it back into the plain 401 under a bridge that did not opt in, so a custom
verifier cannot make a default deployment answer 503.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType

from .errors import AuthServiceUnavailable, ConfigurationError

UNAUTHORIZED = 401
SERVICE_UNAVAILABLE = 503
UNAVAILABLE_STATUSES = (UNAUTHORIZED, SERVICE_UNAVAILABLE)
UNAVAILABLE_DETAIL = "Service unavailable"
RETRY_AFTER_HEADER = "Retry-After"

MIN_RETRY_AFTER = 1
"""Zero would invite an immediate retry into the outage it is reporting."""
MAX_RETRY_AFTER = 300
"""Five minutes. The header is fixed, not tied to recovery, so a longer one keeps clients away
long after the dependency is back. Thirty times the longest retry spacing the library uses."""
DEFAULT_RETRY_AFTER = 10
"""The library's longest default retry spacing. Two of its own latches hold for 10 s: Mode B
refetches the key set at most every 10 s (`REFETCH_INTERVAL`), so a kid no honoured key set
carries gets the same refusal until then, and Mode C retries an unconfirmed readiness probe every
10 s (`PROBE_RETRY_INTERVAL`). A retry inside those windows meets the same latch. Elsewhere a retry
can succeed sooner: Mode A asks the store again on every request (its lookup deadline is 5 s),
and Mode C with a confirmed probe asks upstream again on the next request."""

MISSING_REASON = "an AuthServiceUnavailable subclass carried no reason"


class AuthServiceUnavailable503(AuthServiceUnavailable):
    """The 503 form of `AuthServiceUnavailable`: same class family, same `reason`.

    Private. Only the dispatcher builds it, for a bridge built with `unavailable_status=503`.
    Its class constants stay the sanctioned 401 ones, so the guard on subclasses is unchanged and
    a subclass still cannot answer 503 by a constant. The 503 lives on the instance, and every
    attribute a reader can take tells it: `status_code`, `detail`, `headers`, and the three
    `response_*` reads a house envelope uses. `repr` and pickling keep `retry_after`.
    """

    retry_after: int

    def __init__(self, *, reason: str, retry_after: int) -> None:
        super().__init__(reason=reason)
        answered = {RETRY_AFTER_HEADER: str(retry_after)}
        self.retry_after = retry_after
        self.status_code = SERVICE_UNAVAILABLE
        self.detail = UNAVAILABLE_DETAIL
        self.headers = dict(answered)
        # The response_* names are ClassVars on SessionError. This instance shadows them, so an
        # envelope reading them off the exception reads the same 503 the default handler writes.
        vars(self).update(
            response_status=SERVICE_UNAVAILABLE,
            response_detail=UNAVAILABLE_DETAIL,
            response_headers=MappingProxyType(answered),
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(reason={self.reason!r}, retry_after={self.retry_after!r})"

    def __reduce__(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
    ) -> tuple[Callable[..., AuthServiceUnavailable503], tuple[str, int]]:
        return (_rebuild_503, (self.reason, self.retry_after))


def _rebuild_503(reason: str, retry_after: int) -> AuthServiceUnavailable503:
    return AuthServiceUnavailable503(reason=reason, retry_after=retry_after)


@dataclass(frozen=True, slots=True)
class UnavailablePolicy:
    """What one bridge answers for `AuthServiceUnavailable`.

    `retry_after` is `None` for the default 401 and the whole seconds to send with the 503.
    Frozen, and held by one bridge only, so two bridges in one process never affect each other.
    """

    retry_after: int | None

    def replacing(self, refusal: BaseException) -> AuthServiceUnavailable | None:
        """The refusal to raise instead of `refusal`, or `None` to raise `refusal` itself.

        With the default, only the 503 form is replaced, by the plain 401 with the same reason.
        Everything else passes as itself, so what leaves the dispatcher is what `main` raised.
        With the opt-in, every `AuthServiceUnavailable` becomes this bridge's 503.
        """
        if not isinstance(refusal, AuthServiceUnavailable):
            return None
        if self.retry_after is not None:
            return AuthServiceUnavailable503(
                reason=_reason_of(refusal), retry_after=self.retry_after
            )
        if isinstance(refusal, AuthServiceUnavailable503):
            return AuthServiceUnavailable(reason=_reason_of(refusal))
        return None


def _reason_of(refusal: AuthServiceUnavailable) -> str:
    """The `reason`, read so a third-party subclass that never set one cannot become a 500.

    Read from the instance dictionary, so no third-party code runs on the refusal path. A
    subclass that keeps its reason behind a property gets `MISSING_REASON` too.
    """
    reason: object = vars(refusal).get("reason")
    return reason if isinstance(reason, str) else MISSING_REASON


def unavailable_policy(status: object, retry_after: object) -> UnavailablePolicy:
    """Check `unavailable_status` and `unavailable_retry_after` together, and keep plain ints.

    Raises:
        ConfigurationError: For a status other than 401 or 503, a retry-after given without
            503, or one that is not whole seconds in `[MIN_RETRY_AFTER, MAX_RETRY_AFTER]`.
    """
    plain_status = _plain_int(status)
    if plain_status not in UNAVAILABLE_STATUSES:
        raise ConfigurationError(
            f"BetterAuth(unavailable_status=...) must be 401 or 503; got {_shown(status)}. 401 is"
            " the default and answers an unreachable auth dependency like every other refusal;"
            " 503 answers it with Retry-After and no challenge."
        )
    if plain_status == UNAUTHORIZED:
        if retry_after is not None:
            raise ConfigurationError(
                "BetterAuth(unavailable_retry_after=...) is only sent with a 503, and"
                " unavailable_status is 401. Pass unavailable_status=503 as well, or drop it."
            )
        return UnavailablePolicy(retry_after=None)
    if retry_after is None:
        return UnavailablePolicy(retry_after=DEFAULT_RETRY_AFTER)
    seconds = _plain_int(retry_after)
    if seconds is None or not MIN_RETRY_AFTER <= seconds <= MAX_RETRY_AFTER:
        raise ConfigurationError(
            "BetterAuth(unavailable_retry_after=...) must be whole seconds, an int from"
            f" {MIN_RETRY_AFTER} to {MAX_RETRY_AFTER}; got {_shown(retry_after)}."
        )
    return UnavailablePolicy(retry_after=seconds)


def _plain_int(value: object) -> int | None:
    """The number as a built-in `int`, or `None`. A `bool` is not a number here."""
    if isinstance(value, int) and not isinstance(value, bool):
        return int.__int__(value)
    return None


def _shown(value: object) -> str:
    """How a refused value is printed: through `int`, never through the value's own `repr`."""
    number = _plain_int(value)
    if number is not None:
        return int.__repr__(number)
    return f"a {type(value).__name__}"
