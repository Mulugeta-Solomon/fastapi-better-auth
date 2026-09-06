"""Mode C from the outside: construction, what `extract` owns, and what it refuses to be.

The pinned URI with both query parameters; the credential source that collides with a
`CookieVerifier` on the same name - refused at construction, not at request time; the argument
validation table; the properties reading back what was configured; the default transport.
`extract` reports absence for no cookie, a blank one, the wrong prefix, a header over the cap or
with too many pairs, and otherwise hands back an immutable `RemoteCredential` whose repr redacts
its pairs. `verify` refuses a credential that is not its own and honours a `SessionError` a
transport raises. The pipeline past `extract` is `test_remote_verifier_pipeline.py`, the WP15
gates `test_remote_verifier_gates.py`, the leak channels `test_remote_verifier_hygiene.py`; the
builders are `tests/remote_fixtures.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

from fastapi_better_auth import (
    BetterAuth,
    ConfigurationError,
    CookieVerifier,
    CsrfDisabled,
    InvalidCredential,
    SessionRevoked,
    SessionStore,
    User,
)
from fastapi_better_auth._internal import remote_verifier as rv
from fastapi_better_auth._internal.remote_verifier import RemoteCredential, RemoteVerifier
from tests.remote_fixtures import (
    COOKIE_NAME,
    COOKIE_VALUE,
    ORIGIN,
    SECRET,
    SECURE_NAME,
    URI,
    NullStore,
    document,
    request,
    run,
    verifier,
    with_cookie,
)
from tests.transports import ScriptedTransport, json_reply

# ---------------------------------------------------------------- construction


class TestConstruction:
    def test_the_uri_is_built_once_with_both_query_params(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        assert v.uri == URI
        assert "disableCookieCache=true" in v.uri
        assert "disableRefresh=true" in v.uri

    def test_the_credential_source_matches_the_cookie_verifier(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        assert v.credential_source == f"cookie:{COOKIE_NAME}"

    def test_neither_secret_nor_secrets_is_legal(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        assert v.secrets == ()

    def test_a_base_path_of_root_puts_get_session_at_the_origin(self) -> None:
        v = RemoteVerifier(
            base_url=ORIGIN,
            csrf=CsrfDisabled(reason="root mount, no cross-site answer needed here"),
            transport=ScriptedTransport(json_reply(document())),
            base_path="",
        )
        assert v.uri == f"{ORIGIN}/get-session?disableCookieCache=true&disableRefresh=true"

    @pytest.mark.parametrize(
        ("kwargs", "needle"),
        [
            ({"base_url": "not a url"}, "base_url"),
            ({"csrf": None}, "CSRF"),
            ({"csrf": object()}, "CsrfPolicy"),
            ({"transport": object()}, "Transport"),
            ({"secret": SECRET, "secrets": [SECRET]}, "at most one"),
            ({"secrets": "a-bare-string"}, "sequence"),
            ({"secrets": []}, "empty"),
            ({"secret": "bare"}, "SharedSecret"),
            ({"cookie_name": "bad name"}, "cookie_name"),
            ({"cookie_name": ""}, "cookie_name"),
            ({"secure_prefix": 3}, "secure_prefix"),
            ({"secure_cookies": "yes"}, "secure_cookies"),
            ({"base_path": "api/auth"}, "base_path"),
            ({"base_path": "/api/auth/"}, "base_path"),
            ({"base_path": "/api/auth?x=1"}, "base_path"),
            ({"base_path": "/api/../secret"}, "base_path"),
            ({"base_path": 3}, "base_path"),
            ({"secure_prefix": "__Se;cure-"}, "secure_prefix"),
            ({"max_bytes": 0}, "max_bytes"),
            ({"max_bytes": True}, "max_bytes"),
            ({"concurrency": 0}, "concurrency"),
            ({"concurrency": 257}, "concurrency"),
            ({"concurrency": True}, "concurrency"),
            ({"concurrency": 1.5}, "concurrency"),
            ({"queue_timeout": 0.05}, "queue_timeout"),
            ({"queue_timeout": "soon"}, "queue_timeout"),
            ({"queue_timeout": float("inf")}, "queue_timeout"),
            ({"negative_ttl": -1.0}, "negative_ttl"),
            ({"negative_ttl": 301.0}, "negative_ttl"),
            ({"negative_ttl": "never"}, "negative_ttl"),
            ({"max_remembered": 0}, "max_remembered"),
            ({"max_remembered": 70000}, "remembered"),
            ({"max_remembered": True}, "max_remembered"),
            ({"clock": "not-callable"}, "clock"),
        ],
    )
    def test_a_bad_argument_is_refused_at_construction(
        self, kwargs: dict[str, Any], needle: str
    ) -> None:
        base: dict[str, Any] = {
            "base_url": ORIGIN,
            "csrf": CsrfDisabled(reason="validation-message tests, no request runs"),
            "transport": ScriptedTransport(json_reply(document())),
        }
        base.update(kwargs)
        with pytest.raises(ConfigurationError) as caught:
            RemoteVerifier(**base)
        assert needle in str(caught.value)


# ---------------------------------------------------------------- extract


class TestExtract:
    def test_no_cookie_is_absent(self) -> None:
        assert verifier(ScriptedTransport(json_reply(document()))).extract(request()) is None

    def test_a_blank_cookie_value_is_absent(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        assert v.extract(request(cookies=(f"{COOKIE_NAME}=   ",))) is None

    def test_a_present_cookie_is_a_credential(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        credential = v.extract(with_cookie())
        assert isinstance(credential, RemoteCredential)

    def test_the_credential_repr_redacts_its_pairs(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        credential = v.extract(with_cookie())
        assert credential is not None
        rendered = repr(credential)
        assert COOKIE_VALUE not in rendered
        assert "redacted" in rendered

    def test_only_the_configured_base_is_extracted(self) -> None:
        """secure_cookies=False reads the plain name; a `__Secure-` cookie beside it is not read."""
        v = verifier(ScriptedTransport(json_reply(document())))
        assert v.extract(request(cookies=(f"{SECURE_NAME}={COOKIE_VALUE}",))) is None

    def test_the_credential_is_immutable(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        credential = v.extract(with_cookie())
        assert credential is not None
        with pytest.raises(AttributeError):
            credential.pairs = ()


# ---------------------------------------------------------------- composition (A + C collision)


class TestComposition:
    def test_cookie_and_remote_on_one_name_are_refused_at_construction(self) -> None:
        cookie_verifier = CookieVerifier(
            secret=SECRET,
            store=NullStore(),
            csrf=CsrfDisabled(reason="collision test, no request is verified"),
            secure_cookies=False,
        )
        remote = verifier(ScriptedTransport(json_reply(document())))

        with pytest.raises(ConfigurationError) as caught:
            BetterAuth(verifiers=[cookie_verifier, remote])

        assert "credential_source" in str(caught.value)

    def test_the_null_store_is_a_real_session_store(self) -> None:
        assert isinstance(NullStore(), SessionStore)


class NotCallableTransport:
    """Structurally a `Transport` (both names exist), but neither is callable."""

    get = "not-a-function"
    post = "not-a-function"


class TestConstructionEdges:
    def test_the_properties_read_back_what_was_configured(self) -> None:
        transport = ScriptedTransport(json_reply(document()))
        v = verifier(transport)

        assert v.origin == ORIGIN
        assert v.cookie_name == COOKIE_NAME
        assert v.secure_cookies is False
        assert isinstance(v.csrf, CsrfDisabled)
        assert v.transport is transport

    def test_a_default_transport_is_an_httpx_adapter(self) -> None:
        from fastapi_better_auth import HttpxTransport

        v = RemoteVerifier(
            base_url=ORIGIN, csrf=CsrfDisabled(reason="default-transport construction test")
        )

        assert isinstance(v.transport, HttpxTransport)

    def test_a_transport_with_non_callable_members_is_refused(self) -> None:
        with pytest.raises(ConfigurationError) as caught:
            RemoteVerifier(
                base_url=ORIGIN,
                csrf=CsrfDisabled(reason="non-callable transport construction test"),
                transport=NotCallableTransport(),  # type: ignore[arg-type]
            )

        assert "not callable" in str(caught.value)

    def test_a_secrets_keyring_is_accepted(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())), secrets=[SECRET])

        assert v.secrets == (SECRET,)

    def test_the_not_callable_transport_is_structurally_a_transport(self) -> None:
        from fastapi_better_auth import Transport

        assert isinstance(NotCallableTransport(), Transport)


class TestExtractCaps:
    def test_a_cookie_header_over_the_cap_is_absent(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        huge = f"{COOKIE_NAME}=" + "a" * 20000

        assert v.extract(request(cookies=(huge,))) is None

    def test_a_header_of_too_many_pairs_is_absent(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))
        crowd = "; ".join(f"a{index}=v" for index in range(600))

        assert v.extract(request(cookies=(crowd,))) is None


class TestVerifyGuards:
    @pytest.mark.anyio
    async def test_a_foreign_credential_is_refused(self) -> None:
        v = verifier(ScriptedTransport(json_reply(document())))

        with pytest.raises(InvalidCredential) as caught:
            await v.verify(object(), User)

        assert "not this verifier's" in caught.value.reason

    @pytest.mark.anyio
    async def test_a_session_error_from_the_transport_is_re_raised_verbatim(self) -> None:
        """A transport is not meant to raise a SessionError, but if it does the fetch site must not
        mask it as a generic fetch failure - it is honoured as the answer it is."""
        transport = ScriptedTransport(SessionRevoked(reason="scripted passthrough marker"))
        v = verifier(transport)

        with pytest.raises(SessionRevoked) as caught:
            await run(v, with_cookie())

        assert caught.value.reason == "scripted passthrough marker"


def test_the_module_holds_no_logger() -> None:
    """The latch warning lives in remote_backoff and the probe/advisory warnings in remote_probe;
    remote_verifier orchestrates them and emits no log line of its own, so it holds no logger."""
    assert not hasattr(rv, "logger")
