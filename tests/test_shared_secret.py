"""`SharedSecret`: what it refuses at boot, and what it refuses to say afterwards.

Two contracts, tested separately because they fail differently. **Refusal** is the boot gate:
a secret that could not authenticate anything, or that is a value the whole internet already
knows, stops the application from starting rather than becoming a silent 500 on the first
cookie. **Redaction** is what happens for the rest of the process's life: the value has
exactly one door out (`get_secret_value()`), and every other rendering path - `repr`, `str`,
`format`, `%s`, an exception message, a captured frame local - carries the fingerprint or
nothing.

The frame-locals tests are the ones that would rot quietly: they walk the traceback of a
refused construction and assert the raw value is not in any of this library's frames, the
D-018/D-094 channel an error reporter reads.
"""

from __future__ import annotations

import hashlib
import hmac
import pickle
import re
from collections.abc import Callable
from typing import Any

import pytest

import fastapi_better_auth
from fastapi_better_auth import ConfigurationError, SharedSecret
from fastapi_better_auth._internal.reasons import fingerprint
from fastapi_better_auth._internal.shared_secret import (
    BETTER_AUTH_DEFAULT_SECRET,
    MIN_SECRET_LENGTH,
    PLACEHOLDER_SECRETS,
)

LEAK_MARKER = "leak-marker-must-never-be-rendered"
GOOD = "Zt7Qv1oXbK4mPr9wCyHnLdEuAsJf2Ng6"
OTHER = "Ku3Bx8sVaW5tQe0rYiPmLdNcZgHj7Of4"


def _library_frames(error: BaseException) -> list[Any]:
    """Only this library's own frames - a test's locals are not what a reporter blames."""
    frames: list[Any] = []
    traceback = error.__traceback__
    while traceback is not None:
        if "fastapi_better_auth" in traceback.tb_frame.f_code.co_filename:
            frames.append(traceback.tb_frame)
        traceback = traceback.tb_next
    return frames


REFUSED: tuple[tuple[str, object, str], ...] = (
    ("not-a-string", LEAK_MARKER.encode(), "must be a str"),
    ("empty", "", "is empty"),
    ("whitespace-only", "   \t\n ", "is empty"),
    ("leading-whitespace", f"  {GOOD}", "leading or trailing whitespace"),
    ("trailing-newline", f"{GOOD}\n", "leading or trailing whitespace"),
    ("placeholder", BETTER_AUTH_DEFAULT_SECRET, "known placeholder"),
    ("too-short", LEAK_MARKER[:20], "at least"),
    ("repeated-unit", "changeme" * 4, "repeats"),
)
REFUSED_IDS = tuple(case[0] for case in REFUSED)


def test_a_usable_secret_survives_construction_byte_for_byte() -> None:
    """The stored value is the operator's, unmodified: an HMAC over a trimmed copy of it
    would not match the one the Node side computes over theirs."""
    assert SharedSecret(GOOD).get_secret_value() == GOOD


def test_it_is_exported_from_the_package_root() -> None:
    assert fastapi_better_auth.SharedSecret is SharedSecret


@pytest.mark.parametrize(("value", "expected"), [(c[1], c[2]) for c in REFUSED], ids=REFUSED_IDS)
def test_an_unusable_secret_is_refused_at_construction(value: object, expected: str) -> None:
    with pytest.raises(ConfigurationError) as caught:
        SharedSecret(value)  # pyright: ignore[reportArgumentType]

    assert expected in str(caught.value)


@pytest.mark.parametrize("value", [c[1] for c in REFUSED], ids=REFUSED_IDS)
def test_a_refusal_names_the_secret_only_by_fingerprint(value: object) -> None:
    """The message reaches a boot log. It may say *which* secret and never *what* it is."""
    with pytest.raises(ConfigurationError) as caught:
        SharedSecret(value)  # pyright: ignore[reportArgumentType]

    rendered = str(caught.value)
    assert LEAK_MARKER not in rendered
    assert GOOD not in rendered
    if isinstance(value, str) and value:
        assert value not in rendered


@pytest.mark.parametrize("value", [c[1] for c in REFUSED], ids=REFUSED_IDS)
def test_no_refused_secret_survives_in_a_library_frame(value: object) -> None:
    """A reporter captures frame locals, so every raise path inside the type scrubs its own
    (D-094). The caller's frame still holds the value, and never was ours to clear."""
    with pytest.raises(ConfigurationError) as caught:
        SharedSecret(value)  # pyright: ignore[reportArgumentType]

    rendered = " ".join(repr(frame.f_locals) for frame in _library_frames(caught.value))

    assert rendered, "no library frame was captured; retune this probe"
    assert LEAK_MARKER not in rendered
    assert GOOD not in rendered
    # Each case must assert its OWN value, not two fixed markers: five of the eight shapes
    # carry neither, and would pass this test with the scrub deleted.
    if isinstance(value, str) and len(value) >= 8:
        assert value not in rendered
        assert value.strip() not in rendered


def test_a_refusal_is_a_configuration_error_and_not_a_request_time_answer() -> None:
    """`ConfigurationError` is deliberately not an `HTTPException`: there is no status code
    that makes an unusable secret a client's problem."""
    with pytest.raises(ConfigurationError) as caught:
        SharedSecret("")

    assert isinstance(caught.value, fastapi_better_auth.BetterAuthError)
    assert not isinstance(caught.value, fastapi_better_auth.SessionError)


def test_the_verified_default_secret_is_in_the_placeholder_set() -> None:
    """Pinned against the published better-auth@1.7.1 tarball, `dist/utils/constants.mjs`
    (D-097). A drift here means upstream changed its default and this set is stale."""
    assert BETTER_AUTH_DEFAULT_SECRET == "better-auth-secret-12345678901234567890"
    assert BETTER_AUTH_DEFAULT_SECRET in PLACEHOLDER_SECRETS


@pytest.mark.parametrize("placeholder", sorted(PLACEHOLDER_SECRETS))
def test_every_placeholder_is_refused_for_being_one(placeholder: str) -> None:
    """The order of the ladder is the point: a placeholder shorter than the floor would
    otherwise be refused for its *length*, and its entry in the set would be unreachable -
    a rule that can never fire is not a rule."""
    with pytest.raises(ConfigurationError) as caught:
        SharedSecret(placeholder)

    assert "known placeholder" in str(caught.value)


@pytest.mark.parametrize("placeholder", sorted(PLACEHOLDER_SECRETS))
def test_a_placeholder_is_matched_case_insensitively(placeholder: str) -> None:
    with pytest.raises(ConfigurationError) as caught:
        SharedSecret(placeholder.upper())

    assert "known placeholder" in str(caught.value)


@pytest.mark.parametrize("length", range(MIN_SECRET_LENGTH - 4, MIN_SECRET_LENGTH + 5))
def test_the_length_floor_is_a_boundary_and_not_a_point(length: int) -> None:
    """A point check at one convenient length passes while its neighbours are wrong."""
    value = GOOD[:length] if length <= len(GOOD) else GOOD + OTHER[: length - len(GOOD)]
    assert len(value) == length

    if length < MIN_SECRET_LENGTH:
        with pytest.raises(ConfigurationError) as caught:
            SharedSecret(value)
        assert "at least" in str(caught.value)
    else:
        assert SharedSecret(value).get_secret_value() == value


@pytest.mark.parametrize(
    "value",
    ["a" * 32, "ab" * 16, "changeme" * 4, "0123456789" * 8, (GOOD[:16]) * 2],
    ids=["one-char", "two-chars", "padded-placeholder", "digits", "doubled-good"],
)
def test_a_secret_that_repeats_a_short_unit_is_its_unit(value: str) -> None:
    """`u * n` has the strength of `u`. Long enough to pass the floor is not the same as
    strong enough, and this is the one weak shape a length check cannot see."""
    assert len(value) >= MIN_SECRET_LENGTH

    with pytest.raises(ConfigurationError) as caught:
        SharedSecret(value)

    assert "repeats" in str(caught.value)


def test_a_secret_that_merely_starts_with_a_repeat_is_accepted() -> None:
    """The reduction is exact, not a prefix heuristic: refusing a legitimate random secret
    at boot is an outage, so this rule may only fire on a true repetition."""
    value = "abab" + GOOD

    assert SharedSecret(value).get_secret_value() == value


def test_repr_carries_the_fingerprint_and_never_the_value() -> None:
    secret = SharedSecret(GOOD)

    assert GOOD not in repr(secret)
    assert secret.fingerprint in repr(secret)
    assert type(secret).__name__ in repr(secret)


RENDERERS: list[Callable[[Any], str]] = [
    repr,
    str,
    "{}".format,
    "{!s}".format,
    "{!r}".format,
    lambda secret: f"{secret}",
    # Percent formatting is under test, not a style choice: it is how `logging` renders args.
    lambda secret: "%s" % (secret,),  # noqa: UP031
]


@pytest.mark.parametrize(
    "render",
    RENDERERS,
    ids=["repr", "str", "format", "format-str", "format-repr", "f-string", "percent"],
)
def test_no_rendering_path_carries_the_value(render: Callable[[Any], str]) -> None:
    """`str()` is not `repr()` by accident here - a type that redacted one and not the other
    would leak through the single most common way a value reaches a log line."""
    secret = SharedSecret(GOOD)

    rendered = render(secret)

    assert GOOD not in rendered
    assert secret.fingerprint in rendered


def test_the_fingerprint_is_the_packages_one_scheme_and_not_a_second() -> None:
    secret = SharedSecret(GOOD)

    assert secret.fingerprint == fingerprint(GOOD)
    assert re.fullmatch(r"tok_fp=[0-9a-f]{8}", secret.fingerprint)


def test_the_fingerprint_cannot_be_turned_back_into_the_secret() -> None:
    """It is a truncated digest, which is the whole reason it is safe to log."""
    secret = SharedSecret(GOOD)

    assert secret.fingerprint.endswith(hashlib.sha256(GOOD.encode()).hexdigest()[:8])


def test_two_secrets_with_the_same_value_are_equal_and_hash_alike() -> None:
    assert SharedSecret(GOOD) == SharedSecret(GOOD)
    assert hash(SharedSecret(GOOD)) == hash(SharedSecret(GOOD))


def test_two_different_secrets_are_not_equal() -> None:
    assert SharedSecret(GOOD) != SharedSecret(OTHER)


@pytest.mark.parametrize(
    "other", [GOOD, GOOD.encode(), None, 7], ids=["str", "bytes", "none", "int"]
)
def test_a_secret_never_compares_equal_to_a_bare_value(other: object) -> None:
    """`secret == "the raw string"` is False, always. The direction matters: a comparison
    that answered True for a raw string would make the type's own accessor optional, and one
    that raised would turn a stray equality check into a 500."""
    secret = SharedSecret(GOOD)

    assert (secret == other) is False
    assert (secret != other) is True


def test_equality_goes_through_a_constant_time_comparison(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prove the instrument. `==` on two secrets must not be `str.__eq__`, which returns as
    soon as two bytes differ and turns a comparison into a search."""
    seen: list[tuple[object, object]] = []
    real = hmac.compare_digest

    def spy(left: Any, right: Any) -> bool:
        seen.append((left, right))
        return real(left, right)

    monkeypatch.setattr(hmac, "compare_digest", spy)

    assert SharedSecret(GOOD) == SharedSecret(GOOD)
    assert seen, "equality did not reach hmac.compare_digest"
    assert all(isinstance(side, bytes) for pair in seen for side in pair), (
        "compare_digest refuses non-ASCII str operands; a secret must be compared as bytes"
    )


def test_a_non_ascii_secret_still_compares() -> None:
    """The bug the bytes encoding exists for: `compare_digest` raises `TypeError` on two
    non-ASCII `str`s, so a passphrase secret would crash the comparison rather than fail it."""
    value = "pässwörd-är-inte-ett-lösenord-här-nu"

    assert SharedSecret(value) == SharedSecret(value)


def test_the_hash_keys_on_the_fingerprint_and_not_on_the_value() -> None:
    """`hash()` of the raw value is a per-process oracle for it; the fingerprint is the
    sanctioned shadow, and equal secrets still hash alike because equal values fingerprint
    alike."""
    secret = SharedSecret(GOOD)

    assert hash(secret) == hash(secret.fingerprint)


@pytest.mark.parametrize("attribute", ["_value", "_fingerprint", "anything"])
def test_a_secret_cannot_be_rebound_after_construction(attribute: str) -> None:
    secret = SharedSecret(GOOD)

    with pytest.raises(AttributeError):
        setattr(secret, attribute, "x")


@pytest.mark.parametrize("attribute", ["_value", "_fingerprint"])
def test_a_secret_cannot_be_stripped_of_its_value(attribute: str) -> None:
    secret = SharedSecret(GOOD)

    with pytest.raises(AttributeError):
        delattr(secret, attribute)


def test_a_half_built_secret_still_reprs() -> None:
    """A refused construction leaves an instance with no `_fingerprint` alive in `__init__`'s
    frame, and a reporter reprs every local on the traceback. A `__repr__` that raised there
    would turn this type's own boot refusal into the reporter's crash."""
    unfinished = object.__new__(SharedSecret)

    assert repr(unfinished) == "SharedSecret(<unset>)"


def test_a_secret_carries_no_instance_dict_to_walk() -> None:
    """`__slots__` closes the most casual leak there is: a reporter that serializes
    `obj.__dict__` finds nothing to serialize."""
    assert not hasattr(SharedSecret(GOOD), "__dict__")


def test_a_secret_survives_a_round_trip_through_copy() -> None:
    """`deepcopy` of a config object holding one must still hold a usable secret."""
    restored: SharedSecret = pickle.loads(pickle.dumps(SharedSecret(GOOD)))

    assert restored == SharedSecret(GOOD)
    assert restored.get_secret_value() == GOOD
