"""Mode A: the cookie verifier, composed from the CSRF policy layer and the session store.

The load-bearing negatives, driven RED before the pipeline existed: a cross-origin POST carrying a
perfectly good, correctly signed session cookie is refused at the CSRF rung with the keyring and the
store both untouched; a cookie whose signature does not verify never reaches the store; every one of
the eleven golden vectors is driven through the real public API and lands on a session or on the one
right rejection; and no configuration this verifier accepts makes it honour an unsigned or forged
cookie.
"""

from __future__ import annotations

import base64
import hmac
import logging
from datetime import datetime, timezone
from typing import Any

import pytest
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuth,
    ConfigurationError,
    CsrfDisabled,
    CsrfFailure,
    InvalidCredential,
    OriginCheck,
    Session,
    SessionError,
    SessionExpired,
    SessionRevoked,
    SharedSecret,
    SignedDoubleSubmit,
    User,
)
from fastapi_better_auth._internal import cookie_verifier as cv
from fastapi_better_auth._internal.cookie_verifier import CookieVerifier
from tests.cookies import (
    CAPTURED_TOKEN,
    COOKIE,
    COOKIE_DOC,
    DOTTED_TOKEN,
    FAR_FUTURE,
    FAR_PAST,
    SECRET,
    USER_ID,
    VECTOR_SECRET_VALUE,
    FakeStore,
    http,
    run,
    seeded_store,
    sign,
    stored_session,
    stored_user,
    verifier,
)
from tests.fakes import GOOD_CREDENTIAL, FakeVerifier, resolver_of
from tests.fakes import connection as fake_connection

APP = "https://app.example.com"
EVIL = "https://evil.example.com"
SECURE = "__Secure-better-auth.session_token"

OTHER_SECRET = SharedSecret("Nf4Wq7zC2mVt9Bs5Kx1Ld8Hj6Yr3Pg0Zx")
CSRF_SECRET = SharedSecret("Qb8Xm2vTz6Lp1RkYd9Wn4Hs7Cj3Fg5Ae")


class _FixedClock:
    """Stands in for `cookie_verifier.datetime`, whose `now(tz)` the expiry check reads."""

    def __init__(self, instant: datetime) -> None:
        self._instant = instant

    def now(self, tz: Any = None) -> datetime:
        return self._instant


# ---------------------------------------------------------------- construction


class TestConstruction:
    def test_exactly_one_of_secret_or_secrets_is_required(self) -> None:
        with pytest.raises(ConfigurationError):
            CookieVerifier(store=seeded_store(), csrf=CsrfDisabled(reason="a valid reason here"))

    def test_secret_and_secrets_together_are_refused(self) -> None:
        with pytest.raises(ConfigurationError):
            CookieVerifier(
                secret=SECRET,
                secrets=[SECRET],
                store=seeded_store(),
                csrf=CsrfDisabled(reason="a valid reason here"),
            )

    def test_an_empty_keyring_is_refused(self) -> None:
        with pytest.raises(ConfigurationError):
            CookieVerifier(
                secrets=[], store=seeded_store(), csrf=CsrfDisabled(reason="a valid reason here")
            )

    def test_a_bare_string_in_the_keyring_is_refused(self) -> None:
        with pytest.raises(ConfigurationError):
            CookieVerifier(
                secrets=[VECTOR_SECRET_VALUE],  # type: ignore[list-item]
                store=seeded_store(),
                csrf=CsrfDisabled(reason="a valid reason here"),
            )

    def test_a_secret_that_is_not_a_shared_secret_is_refused(self) -> None:
        with pytest.raises(ConfigurationError):
            CookieVerifier(
                secret=VECTOR_SECRET_VALUE,  # type: ignore[arg-type]
                store=seeded_store(),
                csrf=CsrfDisabled(reason="a valid reason here"),
            )

    def test_a_store_that_is_not_a_session_store_is_refused(self) -> None:
        with pytest.raises(ConfigurationError):
            CookieVerifier(
                secret=SECRET,
                store=object(),  # type: ignore[arg-type]
                csrf=CsrfDisabled(reason="a valid reason here"),
            )

    def test_csrf_none_points_at_csrf_disabled(self) -> None:
        with pytest.raises(ConfigurationError) as caught:
            CookieVerifier(secret=SECRET, store=seeded_store(), csrf=None)  # type: ignore[arg-type]

        assert "CsrfDisabled" in str(caught.value)

    def test_a_csrf_that_is_not_a_policy_is_refused(self) -> None:
        with pytest.raises(ConfigurationError):
            CookieVerifier(secret=SECRET, store=seeded_store(), csrf=object())  # type: ignore[arg-type]

    @pytest.mark.parametrize("name", ["", "   ", "has space", "has;semicolon", "has=equals"])
    def test_a_malformed_cookie_name_is_refused(self, name: str) -> None:
        with pytest.raises(ConfigurationError):
            verifier(cookie_name=name)

    def test_the_credential_source_is_derived_from_the_cookie_name(self) -> None:
        assert verifier().credential_source == f"cookie:{COOKIE}"
        assert verifier(cookie_name="my.cookie").credential_source == "cookie:my.cookie"

    def test_the_configuration_is_exposed_read_only(self) -> None:
        policy = CsrfDisabled(reason="exposed configuration test")
        store = seeded_store()
        built = CookieVerifier(secret=SECRET, store=store, csrf=policy)

        assert built.cookie_name == COOKIE
        assert built.secure_prefix == "__Secure-"
        assert built.csrf is policy
        assert built.store is store
        with pytest.raises(AttributeError):
            built.cookie_name = "other"  # type: ignore[misc]

    def test_a_bare_string_of_secrets_is_refused(self) -> None:
        with pytest.raises(ConfigurationError):
            CookieVerifier(
                secrets="not-a-sequence-of-secrets",  # type: ignore[arg-type]
                store=seeded_store(),
                csrf=CsrfDisabled(reason="a valid reason here"),
            )

    def test_a_store_with_a_non_callable_method_is_refused(self) -> None:
        class BrokenStore:
            fetch_session_by_token = "not-a-method"
            fetch_user_by_id = "not-a-method"

        with pytest.raises(ConfigurationError):
            CookieVerifier(
                secret=SECRET,
                store=BrokenStore(),  # type: ignore[arg-type]
                csrf=CsrfDisabled(reason="a valid reason here"),
            )

    @pytest.mark.parametrize("prefix", [123, "__Se cure-", "__Secure;"])
    def test_a_malformed_secure_prefix_is_refused(self, prefix: Any) -> None:
        with pytest.raises(ConfigurationError):
            verifier(secure_prefix=prefix)

    def test_an_empty_secure_prefix_reads_only_the_plain_name(self) -> None:
        built = verifier(secure_prefix="")

        assert built.secure_prefix == ""

    def test_the_snapshot_is_immutable(self) -> None:
        credential = verifier().extract(http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))
        assert credential is not None
        with pytest.raises(AttributeError):
            credential.pairs = ()


# ---------------------------------------------------------------- extract


class TestExtract:
    def test_no_cookie_at_all_is_absent(self) -> None:
        assert verifier().extract(http()) is None

    def test_another_cookie_is_absent(self) -> None:
        assert verifier().extract(http(cookie="theme=dark")) is None

    def test_a_present_cookie_is_a_snapshot(self) -> None:
        credential = verifier().extract(http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

        assert credential is not None

    def test_a_blank_cookie_value_reads_as_absent(self) -> None:
        """The Verifier Protocol contract: a blank or whitespace-only acceptable value must read as
        ABSENT, or a planted empty cookie from a sibling subdomain makes every composed request
        AmbiguousCredentials before any verify runs (a cookie-tossing DoS)."""
        assert verifier().extract(http(cookie=f"{COOKIE}=")) is None
        assert verifier().extract(http(cookie=f"{COOKIE}=   ")) is None

    def test_a_blank_valued_cookie_beside_a_real_one_leaves_the_real_one(self) -> None:
        """Dropping blanks is safe for the duplicate defence: a real cookie plus a planted blank of
        the same name resolves to the real one, not a duplicate rejection."""
        real = sign(CAPTURED_TOKEN)
        assert verifier().extract(http(cookie=f"{COOKIE}=; {COOKIE}={real}")) is not None

    def test_a_chunked_cookie_is_present(self) -> None:
        assert verifier().extract(http(cookie=f"{COOKIE}.0=part")) is not None

    def test_the_snapshot_repr_hides_the_cookie_material(self) -> None:
        credential = verifier().extract(http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

        assert CAPTURED_TOKEN not in repr(credential)

    @pytest.mark.anyio
    async def test_two_cookie_headers_are_joined_before_parsing(self) -> None:
        """HTTP/2 may split cookies across header lines; `headers.get` would see only the first."""
        raw = [
            (b"cookie", b"theme=dark"),
            (b"cookie", f"{COOKIE}={sign(CAPTURED_TOKEN)}".encode()),
        ]
        connection = HTTPConnection({"type": "http", "method": "GET", "path": "/", "headers": raw})

        session = await run(verifier(), connection)

        assert session is not None
        assert session.user.id == USER_ID


# ---------------------------------------------------------------- the golden vectors


def cookie_verifier_for_vectors() -> CookieVerifier:
    return CookieVerifier(
        secret=SECRET,
        store=seeded_store(),
        csrf=CsrfDisabled(reason="golden vectors test signature parity only"),
    )


@pytest.mark.anyio
@pytest.mark.parametrize("vector", COOKIE_DOC["vectors"], ids=lambda v: v["name"])
async def test_every_golden_vector_through_the_real_api(vector: dict[str, str]) -> None:
    connection = http(cookie=f"{COOKIE}={vector['cookie_value']}")
    built = cookie_verifier_for_vectors()

    if vector["expect"] == "signature_valid":
        session = await run(built, connection)
        assert session is not None
        assert session.token is not None
        token = session.token.get_secret_value()
        assert token in {CAPTURED_TOKEN, DOTTED_TOKEN}
    else:
        with pytest.raises(InvalidCredential):
            await run(built, connection)


# ---------------------------------------------------------------- the pipeline, in order


class TestVerifyPipeline:
    @pytest.mark.anyio
    async def test_a_valid_cookie_yields_a_session_carrying_the_raw_token(self) -> None:
        session = await run(verifier(), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

        assert session is not None
        assert isinstance(session, Session)
        assert session.user.id == USER_ID
        assert session.token is not None
        assert session.token.get_secret_value() == CAPTURED_TOKEN
        assert session.expires_at == FAR_FUTURE

    @pytest.mark.anyio
    async def test_a_forged_signature_is_invalid_credential(self) -> None:
        forged = sign(CAPTURED_TOKEN, secret=b"a-different-secret-entirely-here!")
        with pytest.raises(InvalidCredential):
            await run(verifier(), http(cookie=f"{COOKIE}={forged}"))

    @pytest.mark.anyio
    async def test_a_valid_signature_for_an_unknown_session_is_revoked(self) -> None:
        """Signature good, store empty: the session was signed out or never existed."""
        empty = FakeStore()
        with pytest.raises(SessionRevoked):
            await run(verifier(store=empty), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

    @pytest.mark.anyio
    async def test_expiry_is_inclusive_at_the_check_instant(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Strict expiry is `expires_at <= now`: a session expiring at EXACTLY the check instant is
        expired. Only a frozen clock distinguishes `<=` from `<`; year-2000/2999 cannot."""
        instant = datetime(2026, 6, 1, tzinfo=timezone.utc)
        monkeypatch.setattr(cv, "datetime", _FixedClock(instant))
        store = FakeStore(
            sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, expires_at=instant)}
        )
        with pytest.raises(SessionExpired):
            await run(verifier(store=store), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

    @pytest.mark.anyio
    async def test_an_expired_session_is_rejected_though_the_signature_is_good(self) -> None:
        store = FakeStore(
            sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, expires_at=FAR_PAST)}
        )
        with pytest.raises(SessionExpired):
            await run(verifier(store=store), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

    @pytest.mark.anyio
    async def test_a_record_with_no_embedded_user_triggers_a_second_lookup(self) -> None:
        store = FakeStore(
            sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, user=None)},
            users={USER_ID: stored_user()},
        )

        session = await run(verifier(store=store), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

        assert session is not None
        assert store.user_calls == [USER_ID]

    @pytest.mark.anyio
    async def test_a_session_whose_user_is_absent_is_revoked(self) -> None:
        store = FakeStore(sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, user=None)})
        with pytest.raises(SessionRevoked):
            await run(verifier(store=store), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

    @pytest.mark.anyio
    async def test_impersonation_provenance_is_surfaced_on_raw(self) -> None:
        store = FakeStore(
            sessions={
                CAPTURED_TOKEN: stored_session(
                    CAPTURED_TOKEN, impersonated_by="admin-9", payload={"impersonatedBy": "admin-9"}
                )
            }
        )

        session = await run(verifier(store=store), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

        assert session is not None
        assert session.raw["impersonatedBy"] == "admin-9"


# ---------------------------------------------------------------- CSRF ordering + zero-call


class TestCsrfOrdering:
    def keyring_spy(self, monkeypatch: pytest.MonkeyPatch) -> list[int]:
        calls: list[int] = []
        real = hmac.compare_digest

        def spy(a: Any, b: Any) -> bool:
            calls.append(1)
            return real(a, b)

        monkeypatch.setattr(cv.hmac, "compare_digest", spy)
        return calls

    @pytest.mark.anyio
    async def test_a_cross_origin_post_is_refused_before_the_keyring_or_the_store(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The phase's reason to exist: a good cookie on a cross-site POST is a uniform 403, and
        the signature is never checked and the store is never asked.

        The refusal is triggered at the `Sec-Fetch-Site: cross-site` rung, which fires before
        OriginCheck's own `compare_digest`, so the global `compare_digest` spy reads exactly the
        keyring's calls - which must be zero. `hmac` is one shared module object across `csrf` and
        this verifier, so a spy on it cannot otherwise be attributed to one caller."""
        calls = self.keyring_spy(monkeypatch)
        store = seeded_store()
        built = CookieVerifier(secret=SECRET, store=store, csrf=OriginCheck(allowed_origins=[APP]))
        connection = http(
            "POST",
            cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}",
            origin=EVIL,
            sec_fetch_site="cross-site",
        )

        with pytest.raises(CsrfFailure):
            await run(built, connection)

        assert calls == [], "a CSRF failure reached the keyring"
        assert store.session_calls == [], "a CSRF failure reached the store"

    @pytest.mark.anyio
    async def test_a_bad_signature_never_reaches_the_store(self) -> None:
        """The named Mode-A invariant: with a bad signature, nothing reaches the engine or Redis."""
        store = seeded_store()
        built = CookieVerifier(
            secret=SECRET, store=store, csrf=CsrfDisabled(reason="isolating the signature rung")
        )
        forged = sign(CAPTURED_TOKEN, secret=b"the-wrong-secret-thirty-two-plus!")

        with pytest.raises(InvalidCredential):
            await run(built, http(cookie=f"{COOKIE}={forged}"))

        assert store.session_calls == []

    @pytest.mark.anyio
    async def test_a_valid_signature_reaches_the_keyring_once_per_secret(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Property-spy, not just outcome: the keyring compare is actually executed, one per key,
        with no early return - a `==` that never called `compare_digest` would pass the outcome.

        The matching secret is placed *first*, so a `matched = compare` (last-key-wins) mutation
        rejects a cookie the first key signed, and an early `break` after a match cuts the count to
        one - each caught by an assertion here that a matching-key-last arrangement would not."""
        calls = self.keyring_spy(monkeypatch)
        built = CookieVerifier(
            secrets=[SECRET, OTHER_SECRET],
            store=seeded_store(),
            csrf=CsrfDisabled(reason="isolating the keyring"),
        )

        session = await run(built, http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

        assert session is not None, "a cookie the first keyring secret signed was refused"
        assert len(calls) == 2, "the keyring did not compare once per secret with no early return"

    @pytest.mark.anyio
    async def test_a_cross_origin_request_with_a_valid_double_submit_token_passes(self) -> None:
        """The stronger policy composes: the bound header token lets a same-site POST through."""
        policy = SignedDoubleSubmit(secret=CSRF_SECRET, allowed_origins=[APP])
        built = CookieVerifier(secret=SECRET, store=seeded_store(), csrf=policy)
        header = policy.token_for(CAPTURED_TOKEN)
        connection = http(
            "POST", cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}", origin=APP, x_csrf_token=header
        )

        session = await run(built, connection)

        assert session is not None


# ---------------------------------------------------------------- store failure parity


class TestStoreFailureParity:
    @pytest.mark.anyio
    async def test_a_raw_store_failure_becomes_a_uniform_refusal(self) -> None:
        """The SQL store already raises AuthServiceUnavailable; the Redis store lets a connection
        error escape untranslated. The verifier translates the latter so the two answer alike - and
        the translation carries NO chain: the Redis error can embed the token, so a reintroduced
        `raise ... from exc` (or a raise inside the handler) would re-leak it through __context__."""
        store = FakeStore(session_error=ConnectionError("redis down"))
        with pytest.raises(AuthServiceUnavailable) as caught:
            await run(verifier(store=store), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None

    @pytest.mark.anyio
    async def test_an_already_translated_store_failure_propagates_unchanged(self) -> None:
        store = FakeStore(session_error=AuthServiceUnavailable(reason="store lookup [tok_fp=abc]"))
        with pytest.raises(AuthServiceUnavailable) as caught:
            await run(verifier(store=store), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

        assert "tok_fp=abc" in caught.value.reason

    @pytest.mark.anyio
    async def test_a_store_config_fault_is_not_degraded_to_a_refusal(self) -> None:
        """A ConfigurationError from the store is a deployment fault, not a client's 401."""
        store = FakeStore(session_error=ConfigurationError("schema never migrated"))
        with pytest.raises(ConfigurationError):
            await run(verifier(store=store), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

    @pytest.mark.anyio
    async def test_a_user_lookup_failure_is_also_a_uniform_refusal(self) -> None:
        store = FakeStore(
            sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, user=None)},
            user_error=ConnectionError("redis down"),
        )
        with pytest.raises(AuthServiceUnavailable) as caught:
            await run(verifier(store=store), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None

    @pytest.mark.anyio
    async def test_an_already_translated_user_lookup_failure_propagates(self) -> None:
        store = FakeStore(
            sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, user=None)},
            user_error=AuthServiceUnavailable(reason="user lookup [tok_fp=xyz]"),
        )
        with pytest.raises(AuthServiceUnavailable) as caught:
            await run(verifier(store=store), http(cookie=f"{COOKIE}={sign(CAPTURED_TOKEN)}"))

        assert "tok_fp=xyz" in caught.value.reason

    @pytest.mark.anyio
    async def test_verify_refuses_a_foreign_credential_object(self) -> None:
        """The dispatcher only ever hands verify this verifier's own snapshot; a defensive guard
        refuses anything else rather than reaching into it."""
        with pytest.raises(InvalidCredential):
            await verifier().verify("not a snapshot", User)


# ---------------------------------------------------------------- structural rejections


class TestStructuralRejections:
    @pytest.mark.anyio
    async def test_a_lone_blank_cookie_reads_as_absent(self) -> None:
        """A blank value carries no credential; extract returns None, so run sees no credential."""
        assert await run(verifier(), http(cookie=f"{COOKIE}=")) is None

    @pytest.mark.anyio
    async def test_a_duplicate_session_cookie_is_refused(self) -> None:
        signed = sign(CAPTURED_TOKEN)
        with pytest.raises(InvalidCredential):
            await run(verifier(), http(cookie=f"{COOKIE}={signed}; {COOKIE}={signed}"))

    @pytest.mark.anyio
    async def test_the_secure_prefixed_cookie_is_preferred(self) -> None:
        """Both present is not ambiguous within one verifier: `__Secure-` wins."""
        good = sign(CAPTURED_TOKEN)
        bad = sign(CAPTURED_TOKEN, secret=b"wrong-secret-value-thirty-two-ch!")
        connection = http(cookie=f"{COOKIE}={bad}; {SECURE}={good}")

        session = await run(verifier(), connection)

        assert session is not None


# ---------------------------------------------------------------- no bypass


class TestNoBypass:
    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "csrf",
        [
            CsrfDisabled(reason="even with CSRF turned off"),
            OriginCheck(allowed_origins=[APP]),
        ],
        ids=["csrf-disabled", "origin-check"],
    )
    async def test_no_policy_makes_an_unsigned_token_verify(self, csrf: Any) -> None:
        """There is no flag, and no CSRF choice, that accepts a token this keyring did not sign."""
        built = CookieVerifier(secret=SECRET, store=seeded_store(), csrf=csrf)
        unsigned = f"{CAPTURED_TOKEN}.{base64.b64encode(b'x' * 32).decode()}"
        connection = http("GET", cookie=f"{COOKIE}={unsigned}", origin=APP)

        with pytest.raises(InvalidCredential):
            await run(built, connection)


class TestBlankCookieComposition:
    @pytest.mark.anyio
    async def test_a_planted_blank_cookie_does_not_break_a_bearer_request(self) -> None:
        """F-A regression: with a bearer verifier composed alongside the cookie one, a valid bearer
        plus a planted blank `better-auth.session_token=` must STILL authenticate via the bearer -
        not become AmbiguousCredentials because the cookie verifier reported a blank as present."""
        auth = BetterAuth(verifiers=[FakeVerifier("x-bearer"), verifier()])
        resolve = resolver_of(auth.current_session())

        session = await resolve(fake_connection(x_bearer=GOOD_CREDENTIAL, cookie=f"{COOKIE}="))

        assert session is not None
        assert session.user.id == "u1", "the bearer credential must have authenticated"

    @pytest.mark.anyio
    async def test_two_real_cookies_of_one_name_still_reject_as_duplicate(self) -> None:
        """The duplicate defence survives the blank predicate: two NON-blank same-name cookies are
        still a malformed set."""
        signed = sign(CAPTURED_TOKEN)
        with pytest.raises(InvalidCredential):
            await run(verifier(), http(cookie=f"{COOKIE}={signed}; {COOKIE}={signed}"))


# ---------------------------------------------------------------- frame-locals hygiene (D-094)


def _library_frames(error: BaseException) -> list[Any]:
    """Every traceback frame that belongs to this library - the ones a reporter blames us for."""
    frames: list[Any] = []
    traceback = error.__traceback__
    while traceback is not None:
        if "fastapi_better_auth" in traceback.tb_frame.f_code.co_filename:
            frames.append(traceback.tb_frame)
        traceback = traceback.tb_next
    return frames


class TestFrameLocalsHygiene:
    """The D-094 guarantee the module CLAIMS, made executable: on every refusal path the raw token
    and signature flow BY VALUE into the helper frames that raise, so each must scrub before it
    propagates or a Sentry-style frame-locals capture lifts a live credential out of the traceback.
    """

    def _store_for(self, scenario: str) -> FakeStore:
        if scenario == "revoked":
            return FakeStore()
        if scenario == "expired":
            return FakeStore(
                sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, expires_at=FAR_PAST)}
            )
        if scenario == "store-down":
            return FakeStore(session_error=ConnectionError("redis down"))
        if scenario == "user-absent":
            return FakeStore(sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, user=None)})
        if scenario == "parse-fail":
            # A valid, live session whose user payload parse_user rejects (empty id): the ONLY path
            # that reaches _session's raise with the raw token still on that frame.
            bad_user = stored_user(payload={"id": ""})
            return FakeStore(
                sessions={CAPTURED_TOKEN: stored_session(CAPTURED_TOKEN, user=bad_user)}
            )
        return seeded_store()  # bad-sig

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "scenario", ["bad-sig", "revoked", "expired", "store-down", "user-absent", "parse-fail"]
    )
    async def test_no_refusal_path_leaves_the_token_in_a_library_frame(self, scenario: str) -> None:
        if scenario == "bad-sig":
            cookie_value = sign(CAPTURED_TOKEN, secret=b"a-wrong-secret-thirty-two-chars!!")
        else:
            cookie_value = sign(CAPTURED_TOKEN)
        signature = cookie_value.rpartition(".")[2]
        built = verifier(store=self._store_for(scenario))

        with pytest.raises(SessionError) as caught:
            await run(built, http(cookie=f"{COOKIE}={cookie_value}"))

        frames = _library_frames(caught.value)
        rendered = " ".join(repr(frame.f_locals) for frame in frames)
        assert frames, "no library frame was captured; retune this probe"
        assert CAPTURED_TOKEN not in rendered, f"the raw token survived a {scenario} frame"
        assert signature not in rendered, f"the signature survived a {scenario} frame"


# ---------------------------------------------------------------- the session_data warning


def test_a_session_data_cookie_is_observed_once_and_never_parsed(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """CVE-2026-67337: the cookie cache is out of scope. Seeing one warns exactly once, loud, and
    the value is never read."""
    monkeypatch.setattr(cv._SESSION_DATA_ONCE, "_fired", False, raising=False)  # pyright: ignore[reportPrivateUsage]
    built = verifier()

    with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
        built.extract(http(cookie="better-auth.session_data=secret-value; theme=dark"))
        built.extract(http(cookie="better-auth.session_data=another-secret-value"))

    warnings = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert len(warnings) == 1, "the session_data warning is not once-only"
    assert "secret-value" not in warnings[0].getMessage(), "the session_data value was rendered"
