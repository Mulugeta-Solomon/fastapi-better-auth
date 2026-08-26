"""D2 — what a `Session` is allowed to reveal when something serializes it.

A model that reaches a route return value, a log line, a debugger, or an OpenAPI schema
must not carry the raw session token or the upstream payload with it. Every channel that
has ever leaked one is asserted here, including the two that only appear once FastAPI is
in the picture.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import httpx2
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from fastapi_better_auth import Session, User

SECRET_TOKEN = "raw-session-token-9f3ab21ce4"
RAW_MARKER = "203.0.113.7"
MASK = "**********"


def a_session() -> Session[User]:
    return Session[User](
        user=User.model_validate({"id": "u1", "email": "seed@example.com"}),
        expires_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
        token=SecretStr(SECRET_TOKEN),
        raw={"session": {"ipAddress": RAW_MARKER}},
    )


def read_session() -> Session[User]:
    return a_session()


def session_app() -> FastAPI:
    app = FastAPI()
    app.add_api_route("/session", read_session, methods=["GET"])
    return app


def route_body_and_schema() -> tuple[str, dict[str, Any]]:
    with TestClient(session_app()) as client:
        body = client.get("/session").text
        schema: dict[str, Any] = client.get("/openapi.json").json()
    return body, schema


def session_schema(schema: dict[str, Any]) -> dict[str, Any]:
    schemas: dict[str, Any] = schema["components"]["schemas"]
    matches = [s for s in schemas.values() if "token" in s.get("properties", {})]
    assert len(matches) == 1, "expected exactly one Session schema in the OpenAPI document"
    return matches[0]


@pytest.mark.parametrize(
    "channel",
    ["repr", "str", "model_dump", "model_dump_json"],
)
def test_the_token_never_appears_in_a_local_serialization(channel: str) -> None:
    session = a_session()
    rendered = {
        "repr": repr(session),
        "str": str(session),
        "model_dump": str(session.model_dump()),
        "model_dump_json": session.model_dump_json(),
    }[channel]

    assert SECRET_TOKEN not in rendered
    assert MASK in rendered


@pytest.mark.parametrize("channel", ["repr", "str", "model_dump", "model_dump_json"])
def test_raw_never_appears_in_a_local_serialization(channel: str) -> None:
    session = a_session()
    rendered = {
        "repr": repr(session),
        "str": str(session),
        "model_dump": str(session.model_dump()),
        "model_dump_json": session.model_dump_json(),
    }[channel]

    assert RAW_MARKER not in rendered
    assert "raw" not in rendered


def test_the_secret_is_still_reachable_on_purpose() -> None:
    """Masking is not hiding: verifiers call `.get_secret_value()` deliberately."""
    token = a_session().token

    assert token is not None
    assert token.get_secret_value() == SECRET_TOKEN


def test_a_route_returning_a_session_leaks_neither_token_nor_raw() -> None:
    body, _ = route_body_and_schema()

    assert SECRET_TOKEN not in body
    assert RAW_MARKER not in body
    assert MASK in body


def test_the_openapi_schema_hides_raw_and_marks_the_token_write_only() -> None:
    _, schema = route_body_and_schema()
    properties: dict[str, Any] = session_schema(schema)["properties"]

    assert "raw" not in properties
    assert "user" in properties
    token_variants: list[dict[str, Any]] = properties["token"]["anyOf"]
    string_variant = next(v for v in token_variants if v.get("type") == "string")
    assert string_variant["format"] == "password"
    assert string_variant["writeOnly"] is True


def test_the_whole_openapi_document_is_free_of_both() -> None:
    _, schema = route_body_and_schema()
    document = json.dumps(schema)

    assert SECRET_TOKEN not in document
    assert RAW_MARKER not in document


def test_one_response_never_mixes_two_casings() -> None:
    """A7: FastAPI dumps response models with by_alias=True; a serialization alias here
    would emit camelCase `User` fields beside snake_case `Session` fields."""
    body, _ = route_body_and_schema()
    payload: dict[str, Any] = json.loads(body)
    user: dict[str, Any] = payload["user"]

    assert "email_verified" in user
    assert "emailVerified" not in user
    camel = [key for key in (*payload, *user) if any(char.isupper() for char in key)]
    assert camel == []


def test_the_response_is_a_real_response_not_an_error() -> None:
    """Prove the instrument: a 500 would satisfy every absence assertion above."""
    with TestClient(session_app()) as client:
        response: httpx2.Response = client.get("/session")

    assert response.status_code == 200
    assert response.json()["user"]["id"] == "u1"
