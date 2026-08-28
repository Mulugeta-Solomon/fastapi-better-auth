"""The operator's shared secret: refused at boot if it is weak, redacted everywhere after."""

from __future__ import annotations

import hmac
from collections.abc import Callable

from .errors import ConfigurationError
from .reasons import fingerprint

BETTER_AUTH_DEFAULT_SECRET = "better-auth-secret-12345678901234567890"
MIN_SECRET_LENGTH = 32
UNSET = "<unset>"

PLACEHOLDER_SECRETS: frozenset[str] = frozenset(
    {
        BETTER_AUTH_DEFAULT_SECRET,
        "change-me",
        "changeme",
        "credential",
        "default",
        "example",
        "password",
        "placeholder",
        "secret",
        "supersecret",
        "test",
        "todo",
        "your-secret",
        "your-secret-here",
    }
)


class SharedSecret:
    """A Better Auth shared secret, validated once and unprintable thereafter.

    The value your Better Auth server signs with - its `secret` option, or the
    `BETTER_AUTH_SECRET` it reads from the environment. Anything on this side that has to
    recompute one of upstream's HMACs needs the identical bytes, so this type holds them and
    nothing else may.

        auth_secret = SharedSecret(os.environ["BETTER_AUTH_SECRET"])

    **It refuses at construction, which is the point.** Applications build their
    configuration while starting up, so an unusable secret stops a deployment rather than
    becoming a 500 on the first request that carries a cookie. Refused: anything that is not
    a `str`; an empty or whitespace-only value; a value with leading or trailing whitespace
    (a secret read from a file keeps its newline, and an HMAC over a *trimmed* copy would
    silently disagree with upstream's over the untrimmed one); a known placeholder, including
    better-auth's own default secret; a value shorter than 32 characters; and a value that is
    one short unit repeated, whose strength is only that unit's.

    Upstream *warns* below 32 characters and refuses its own default only in production. This
    refuses both, always: a secret this library cannot vouch for is one it will not carry.

    **It redacts everywhere else.** `repr()`, `str()`, `format()` and `%s` all render
    `SharedSecret(tok_fp=<8 hex>)` - enough for an operator to tell two secrets apart in a
    boot log, and useless to anyone else. The value has exactly one door, `get_secret_value()`,
    so every use of it is visible in review. Instances are immutable, carry no `__dict__` for
    a reporter to serialize, and compare in constant time.

    Args:
        value: The secret, exactly as the Better Auth server has it.

    Raises:
        ConfigurationError: For any value that could not safely authenticate anything.
    """

    __slots__ = ("_fingerprint", "_value")

    _fingerprint: str
    _value: str

    def __init__(self, value: str) -> None:
        try:
            accepted = _accepted(value)
        finally:
            # A refused construction leaves this frame on the traceback, and a reporter
            # reads its locals (D-094). Cleared on the accepted path too; `accepted` is used.
            value = ""
        object.__setattr__(self, "_value", accepted)
        object.__setattr__(self, "_fingerprint", fingerprint(accepted))

    @property
    def fingerprint(self) -> str:
        """`tok_fp=` plus eight hex characters of SHA-256 - the package's one such scheme.

        The only form of this secret that may reach a log line, an error message or a metric.
        Stable for a given value, so "the same secret failed twice" is answerable, and not
        reversible into the value.
        """
        return self._fingerprint

    def get_secret_value(self) -> str:
        """The raw secret. The one call that hands it out - keep it at the point of use."""
        return self._value

    def __repr__(self) -> str:
        # A refused construction leaves a half-built instance in __init__'s frame, and a
        # reporter reprs every local it finds; an AttributeError here would be its crash.
        return f"{type(self).__name__}({getattr(self, '_fingerprint', UNSET)})"

    def __eq__(self, other: object) -> bool:
        """Constant-time, and only ever against another `SharedSecret`.

        A bare `str` compares unequal rather than raising: an equality check that blew up
        would turn a stray comparison into a 500, and one that answered `True` would make
        `get_secret_value()` optional. Lengths are still distinguishable, as they are for
        every `compare_digest`.
        """
        if not isinstance(other, SharedSecret):
            return NotImplemented
        return hmac.compare_digest(self._value.encode("utf-8"), other._value.encode("utf-8"))

    def __hash__(self) -> int:
        """Keyed on the fingerprint: `hash()` of the value is a per-process oracle for it."""
        return hash(self._fingerprint)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable; construct a new one instead")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable; construct a new one instead")

    def __reduce__(self) -> tuple[Callable[[str], SharedSecret], tuple[str]]:
        """Rebuild through the constructor, so an unpickled secret is a validated one."""
        return (_rebuild, (self._value,))


def _rebuild(value: str) -> SharedSecret:
    return SharedSecret(value)


def _accepted(value: object) -> str:
    """The validated secret, or a `ConfigurationError` naming it only by fingerprint."""
    if not isinstance(value, str):
        kind = type(value).__name__
        value = ""
        raise ConfigurationError(
            "SharedSecret must be a str holding the same value your Better Auth server's"
            f" `secret` is set to; got {kind}."
        )
    refusal = _refusal(value)
    if refusal is None:
        return value
    marker = fingerprint(value)
    value = ""
    raise ConfigurationError(f"SharedSecret({marker}) {refusal}")


def _refusal(value: str) -> str | None:
    """Why this value is unusable, or `None`. It *returns* the reason rather than raising it:
    a frame that never raises is a frame no traceback carries the secret out of (D-094)."""
    if not value.strip():
        return "is empty. Set it to your Better Auth server's `secret`."
    if value != value.strip():
        return (
            "has leading or trailing whitespace. Strip it: the Node side does not, so the two"
            " would compute different HMACs over the same request and every session would"
            " fail to verify with nothing to see."
        )
    if value.casefold() in PLACEHOLDER_SECRETS:
        return (
            "is a known placeholder secret, so anyone can forge a session for this deployment."
            " Generate a real one with `openssl rand -base64 32` and set it on both sides."
        )
    if len(value) < MIN_SECRET_LENGTH:
        return (
            f"is {len(value)} characters; at least {MIN_SECRET_LENGTH} are required. Upstream"
            " only warns below that; a bridge that cannot vouch for a secret does not carry it."
        )
    unit = len(_repeating_unit(value))
    if unit < MIN_SECRET_LENGTH:
        return (
            f"repeats a {unit}-character unit, so its strength is that unit's however long the"
            f" whole value is. Use {MIN_SECRET_LENGTH} or more characters that are not a"
            " repetition."
        )
    return None


def _repeating_unit(value: str) -> str:
    """The shortest `unit` with `unit * n == value`, or the value when it is not a repetition.

    `(v + v).find(v, 1)` lands on the smallest period, and on `len(v)` when there is none.
    """
    period = (value + value).find(value, 1)
    return value if period >= len(value) else value[:period]
