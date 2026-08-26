"""ValidationError containment — the one sanctioned door from upstream data to a `User`.

A `pydantic.ValidationError` escaping a verifier is a 500, and a 500 is wire-distinguishable
from the uniform 401 the rest of the family renders: it tells a client that *this* payload
parsed differently, and under a debug handler it echoes the input back. `parse_user` turns
every one of them into `InvalidCredential`, keeps the diagnosis on `reason`, and keeps the
input out of it.
"""

from __future__ import annotations

import traceback
from typing import Any

import pytest
from pydantic import ConfigDict, Field, ValidationError, field_validator

from fastapi_better_auth import InvalidCredential, User, parse_user

LEAKY_MARKER = "mallory-9f3ab21c"
PLAIN_MARKER = "mallory9f3ab21c"
OVERLONG_EMAIL = f"{'x' * 400}@example.com"
OVERLONG_IMAGE = f"https://cdn.example.com/{LEAKY_MARKER}/{'x' * 5000}"


class AdminUser(User):
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
    user = parse_user(AdminUser, {"id": "u1", "role": "admin"})

    assert isinstance(user, AdminUser)
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
        parse_user(AdminUser, {"id": "u1"})


def test_the_reason_names_the_model_and_the_field_that_failed() -> None:
    with pytest.raises(InvalidCredential) as caught:
        parse_user(AdminUser, {"id": "u1"})

    reason = caught.value.reason
    assert "AdminUser" in reason
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
