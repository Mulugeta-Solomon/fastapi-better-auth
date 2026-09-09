"""ValidationError containment — the one sanctioned door from upstream data to a `User`.

A `pydantic.ValidationError` escaping a verifier is a 500, and a 500 is wire-distinguishable
from the uniform 401 the rest of the family renders: it tells a client that *this* payload
parsed differently, and under a debug handler it echoes the input back. `parse_user` turns
every one of them into `InvalidCredential`, keeps the diagnosis on `reason`, and keeps the
input out of it.
"""

from __future__ import annotations

import logging
import traceback
from typing import Any

import pytest
from pydantic import ConfigDict, Field, ValidationError, create_model, field_validator

from fastapi_better_auth import AdminUser, InvalidCredential, User, parse_user
from fastapi_better_auth._internal import parsing
from fastapi_better_auth._internal.once import OnceByKey

LIBRARY_LOGGER = "fastapi_better_auth"
LEAKY_MARKER = "mallory-9f3ab21c"
PLAIN_MARKER = "mallory9f3ab21c"
OVERLONG_EMAIL = f"{'x' * 400}@example.com"
OVERLONG_IMAGE = f"https://cdn.example.com/{LEAKY_MARKER}/{'x' * 5000}"


class RequiredRole(User):
    """A deployment's own user model, with a field the upstream payload must carry."""

    role: str


class StrictUser(User):
    """`extra="forbid"` puts the rejected key - which the payload chose - into `loc`."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class TaggedUser(User):
    """A mapping field puts the payload's own keys into `loc`."""

    labels: dict[str, str] = Field(default_factory=dict)


class ChattyUser(User):
    """A validator that interpolates the value it rejected into its own message."""

    role: str = ""

    @field_validator("role")
    @classmethod
    def reject_unknown(cls, value: str) -> str:
        if value not in ("admin", "member", ""):
            raise ValueError(f"unknown role {value}")
        return value


MALFORMED: tuple[tuple[str, Any], ...] = (
    ("missing-id", {"email": "seed@example.com"}),
    ("empty-id", {"id": ""}),
    ("whitespace-id", {"id": "   "}),
    ("control-character-id", {"id": "u\x00 1"}),
    ("bool-id", {"id": True}),
    ("overlong-email", {"id": "u1", "email": OVERLONG_EMAIL}),
    ("wrong-type", {"id": ["u1"]}),
    ("not-a-mapping", ["id", "u1"]),
    ("none", None),
    ("string", "u1"),
)


def test_a_valid_payload_produces_the_model_that_was_asked_for() -> None:
    user = parse_user(User, {"id": "u1", "emailVerified": True})

    assert user.id == "u1"
    assert user.email_verified is True


def test_a_subclass_is_returned_as_the_subclass() -> None:
    user = parse_user(RequiredRole, {"id": "u1", "role": "admin"})

    assert isinstance(user, RequiredRole)
    assert user.role == "admin"


@pytest.mark.parametrize("payload", [p[1] for p in MALFORMED], ids=[p[0] for p in MALFORMED])
def test_every_malformed_payload_becomes_an_invalid_credential(payload: Any) -> None:
    with pytest.raises(InvalidCredential):
        parse_user(User, payload)


@pytest.mark.parametrize("payload", [p[1] for p in MALFORMED], ids=[p[0] for p in MALFORMED])
def test_no_validation_error_ever_escapes(payload: Any) -> None:
    """Prove the instrument: these payloads really do make pydantic raise."""
    with pytest.raises(ValidationError):
        User.model_validate(payload)


def test_a_missing_subclass_field_is_contained_too() -> None:
    with pytest.raises(InvalidCredential):
        parse_user(RequiredRole, {"id": "u1"})


def test_the_reason_names_the_model_and_the_field_that_failed() -> None:
    with pytest.raises(InvalidCredential) as caught:
        parse_user(RequiredRole, {"id": "u1"})

    reason = caught.value.reason
    assert "RequiredRole" in reason
    assert "role" in reason


def test_the_reason_does_not_echo_the_input_value() -> None:
    """Error reporters serialize `exc.__dict__`; pydantic's own text carries `input_value`."""
    payload = {"id": f"{LEAKY_MARKER}\x00"}

    with pytest.raises(InvalidCredential) as caught:
        parse_user(User, payload)
    with pytest.raises(ValidationError) as pydantic_error:
        User.model_validate(payload)

    assert LEAKY_MARKER in str(pydantic_error.value), "pydantic stopped echoing; retune this"
    assert LEAKY_MARKER not in caught.value.reason


def test_the_reason_does_not_echo_a_long_input_value_either() -> None:
    with pytest.raises(InvalidCredential) as caught:
        parse_user(User, {"id": "u1", "image": OVERLONG_IMAGE})

    assert "xxxx" not in caught.value.reason
    assert LEAKY_MARKER not in caught.value.reason


def test_the_upstream_payload_does_not_survive_in_the_parse_frame() -> None:
    """B5: error reporters capture frame locals, and this frame holds the whole upstream
    payload - session id, ip address, plugin data - at the moment it raises."""
    secret = "raw-session-token-9f3ab21c"
    payload = {"id": "", "image": f"https://cdn.example/{secret}"}

    with pytest.raises(InvalidCredential) as caught:
        parse_user(User, payload)

    frames: list[Any] = []
    tb = caught.value.__traceback__
    while tb is not None:
        if "fastapi_better_auth" in tb.tb_frame.f_code.co_filename:
            frames.append(tb.tb_frame)
        tb = tb.tb_next
    rendered = " ".join(repr(frame.f_locals) for frame in frames)

    assert frames, "no library frame was captured; retune this probe"
    assert secret not in rendered, "the upstream payload survived in a captured frame"


def test_the_pydantic_error_is_not_chained_onto_the_raise() -> None:
    """`__cause__` is rendered by `logger.exception` and walked by error reporters, so
    chaining would put `input_value=` back in both after the summary took it out."""
    with pytest.raises(InvalidCredential) as caught:
        parse_user(User, {"id": ""})

    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__


def test_the_rendered_traceback_carries_no_input_value() -> None:
    payload = {"id": f"{LEAKY_MARKER}\x00"}

    with pytest.raises(InvalidCredential) as caught:
        parse_user(User, payload)
    with pytest.raises(ValidationError) as pydantic_error:
        User.model_validate(payload)
    rendered = "".join(
        traceback.format_exception(
            type(caught.value), caught.value, caught.value.__traceback__, chain=True
        )
    )

    assert LEAKY_MARKER in str(pydantic_error.value), "pydantic stopped echoing; retune this"
    assert LEAKY_MARKER not in rendered


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (StrictUser, {"id": "u1", LEAKY_MARKER: "x"}),
        (TaggedUser, {"id": "u1", "labels": {LEAKY_MARKER: 1}}),
    ],
    ids=["extra-forbid-key", "dict-key"],
)
def test_a_payload_field_name_that_is_not_a_plain_identifier_is_redacted(
    model: type[User], payload: dict[str, Any]
) -> None:
    """`loc` is pydantic's field path, and for these two ordinary subclass shapes the path
    itself is payload-supplied. `LEAKY_MARKER` carries a hyphen, so it is redacted."""
    with pytest.raises(ValidationError) as pydantic_error:
        model.model_validate(payload)
    with pytest.raises(InvalidCredential) as caught:
        parse_user(model, payload)

    assert LEAKY_MARKER in str(pydantic_error.value), "pydantic stopped echoing; retune this"
    assert LEAKY_MARKER not in caught.value.reason
    assert "<redacted>" in caught.value.reason


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (StrictUser, {"id": "u1", PLAIN_MARKER: "x"}),
        (TaggedUser, {"id": "u1", "labels": {PLAIN_MARKER: 1}}),
    ],
    ids=["extra-forbid-key", "dict-key"],
)
def test_a_plain_identifier_field_name_does_reach_the_reason(
    model: type[User], payload: dict[str, Any]
) -> None:
    """The contract, stated honestly rather than by accident of a hyphen: a payload-chosen
    key that is already `[A-Za-z0-9_]{1,64}` is kept. It is what makes the reason usable
    for the operator, it cannot carry a separator or a control character into a log line,
    and it is size-capped. Anything else is redacted - see the test above."""
    with pytest.raises(InvalidCredential) as caught:
        parse_user(model, payload)

    assert PLAIN_MARKER in caught.value.reason


def test_an_oversized_field_name_is_redacted() -> None:
    """The cap is what keeps a payload from choosing how long a log line is."""
    with pytest.raises(InvalidCredential) as caught:
        parse_user(StrictUser, {"id": "u1", "x" * 65: "y"})

    assert "x" * 65 not in caught.value.reason
    assert "<redacted>" in caught.value.reason


@pytest.mark.parametrize(
    "name",
    ["two words", "semi;colon", "new\nline", "quote'mark", "dot.path", "null\x00byte"],
    ids=["space", "semicolon", "newline", "quote", "dot", "null"],
)
def test_a_field_name_that_could_confuse_a_log_line_is_redacted(name: str) -> None:
    with pytest.raises(InvalidCredential) as caught:
        parse_user(StrictUser, {"id": "u1", name: "y"})

    assert name not in caught.value.reason
    assert "<redacted>" in caught.value.reason


def test_the_docstring_states_which_field_names_survive() -> None:
    """The contract is only honest if the reader of the public docstring learns it."""
    doc = parse_user.__doc__ or ""

    assert "field name" in doc or "field path" in doc
    assert "redact" in doc.lower()


def test_a_subclass_validator_message_never_reaches_the_reason() -> None:
    """A user model's own `ValueError` text is not ours to trust with the value it saw."""
    with pytest.raises(InvalidCredential) as caught:
        parse_user(ChattyUser, {"id": "u1", "role": LEAKY_MARKER})

    assert LEAKY_MARKER not in caught.value.reason
    assert "role" in caught.value.reason


def test_the_reason_is_bounded_however_many_fields_fail() -> None:
    """A log line is not a place to render an unbounded list."""
    payload = {
        "id": "",
        "email": OVERLONG_EMAIL,
        "name": "n" * 2000,
        "image": "i" * 8000,
        "emailVerified": "sort-of",
        "createdAt": "yesterday",
        "updatedAt": "tomorrow",
    }

    with pytest.raises(InvalidCredential) as caught:
        parse_user(User, payload)

    reason = caught.value.reason
    assert len(reason) <= 500
    assert "(7)" in reason
    assert "+2 more" in reason


def test_the_contained_error_still_renders_the_uniform_401() -> None:
    with pytest.raises(InvalidCredential) as caught:
        parse_user(User, {"id": ""})

    assert caught.value.status_code == 401
    assert caught.value.detail == "Not authenticated"


# --- the additionalFields advisory (#43) ------------------------------------------
#
# A *required* subclass field is the strict mode: it fails closed on the first request. What it
# cannot do is say *why* on the wire, because the wire is a uniform 401 for everything. The
# warning below is the second channel - the deployment telling on itself in its own logs.


def scoped_model(name: str = "Scoped") -> type[User]:
    """A brand-new subclass every call, so the per-model warning latch starts unfired.

    Written as a factory rather than a module-level class because "once per process per model"
    is exactly what these tests measure: two tests sharing one class would make the second one
    pass because the first had already fired.
    """
    return create_model(name, __base__=User, jurisdiction_scope=(str, ...))


def parse_missing(model: type[User]) -> InvalidCredential:
    with pytest.raises(InvalidCredential) as caught:
        parse_user(model, {"id": "u1", "jurisdiction": "KE"})
    return caught.value


def advisories(records: list[logging.LogRecord]) -> list[logging.LogRecord]:
    return [record for record in records if record.name == LIBRARY_LOGGER]


def test_a_required_field_the_wire_does_not_carry_is_a_401_naming_the_wire_key() -> None:
    """The one thing a reader has to be able to copy out of a log and take to the Node side:
    the *alias*, `jurisdictionScope`, not the Python name `jurisdiction_scope`."""
    refusal = parse_missing(scoped_model())

    assert refusal.reason == "Scoped payload rejected (1): jurisdictionScope: [missing]"
    assert refusal.status_code == 401


def test_a_missing_field_warns_once_per_process_per_model(
    caplog: pytest.LogCaptureFixture,
) -> None:
    model = scoped_model()

    with caplog.at_level(logging.WARNING, logger=LIBRARY_LOGGER):
        parse_missing(model)
        parse_missing(model)
        parse_missing(model)

    assert len(advisories(caplog.records)) == 1


def test_a_second_model_gets_its_own_advisory(caplog: pytest.LogCaptureFixture) -> None:
    """Per model, not per process: two deployments' models on one process must both be told."""
    with caplog.at_level(logging.WARNING, logger=LIBRARY_LOGGER):
        parse_missing(scoped_model("First"))
        parse_missing(scoped_model("Second"))

    written = " ".join(record.getMessage() for record in advisories(caplog.records))
    assert len(advisories(caplog.records)) == 2
    assert "First" in written
    assert "Second" in written


def test_the_advisory_names_the_model_and_the_wire_key(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=LIBRARY_LOGGER):
        parse_missing(scoped_model())

    record = advisories(caplog.records)[0]

    assert record.levelno == logging.WARNING
    assert "Scoped" in record.getMessage()
    assert "jurisdictionScope" in record.getMessage()
    assert "additionalFields" in record.getMessage()


def test_the_advisory_carries_no_value_from_the_payload(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The same discipline as `reason` (D-046, D-059): the diagnosis, never the data."""
    model = create_model("Scoped", __base__=User, jurisdiction_scope=(str, ...))

    with caplog.at_level(logging.WARNING, logger=LIBRARY_LOGGER), pytest.raises(InvalidCredential):
        parse_user(model, {"id": LEAKY_MARKER, "jurisdiction": LEAKY_MARKER})

    written = " ".join(record.getMessage() for record in advisories(caplog.records))
    assert advisories(caplog.records), "nothing was logged; this scenario proves nothing"
    assert LEAKY_MARKER not in written


def test_a_field_name_a_log_line_could_not_survive_is_redacted_here_too(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """`loc` for a `missing` error is the model's own alias, so this is belt and braces - but
    the sanitizer runs on both channels or on neither. The hostile spelling is the field's
    validation alias: a field *named* that way has no `__init__` signature on the oldest
    supported pydantic, and the alias is what a `missing` error reports anyway."""
    model = create_model(
        "Injected", __base__=User, injected=(str, Field(validation_alias="new\nline"))
    )

    with caplog.at_level(logging.WARNING, logger=LIBRARY_LOGGER), pytest.raises(InvalidCredential):
        parse_user(model, {"id": "u1"})

    written = " ".join(record.getMessage() for record in advisories(caplog.records))
    assert "<redacted>" in written
    assert "new\nline" not in written


def test_a_refusal_that_is_not_about_a_missing_field_is_silent(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `banned: "true"` is a wire-shape problem, not a name mismatch. Warning on it would
    make the advisory fire for every malformed payload and stop meaning anything.

    The latch is replaced so this is a genuine observation: `AdminUser` is a module-level class
    another test may already have fired the per-model latch for, and a silence that only means
    "already warned" would let an advisory-on-every-error mutation pass."""
    monkeypatch.setattr(parsing, "_advised", OnceByKey())
    with caplog.at_level(logging.WARNING, logger=LIBRARY_LOGGER), pytest.raises(InvalidCredential):
        parse_user(AdminUser, {"id": "u1", "banned": "true"})

    assert advisories(caplog.records) == []


def test_a_payload_that_parses_is_silent(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger=LIBRARY_LOGGER):
        parse_user(scoped_model(), {"id": "u1", "jurisdictionScope": "KE"})

    assert advisories(caplog.records) == []
