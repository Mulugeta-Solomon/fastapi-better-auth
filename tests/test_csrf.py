"""The CSRF policy layer: what a cookie-authenticated unsafe request has to prove.

Every refusal here is `CsrfFailure` - the 403 the taxonomy already carries - and every
configuration fault is a `ConfigurationError` raised while the application is being built.
The suite is organized as the ladder itself: the snapshot, then each rung, then the two
shipped policies, then the hygiene the whole package is written to.

The load-bearing negatives, driven RED before any of this existed: a cross-origin POST
carrying a perfectly good session token is refused; a WebSocket handshake from a cross-site
origin is refused even though its method is GET; and an unsafe request with no `Origin` at
all is refused rather than waved through.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from starlette.requests import HTTPConnection

from fastapi_better_auth import (
    ConfigurationError,
    CsrfDisabled,
    CsrfFacts,
    CsrfFailure,
    CsrfPolicy,
    OriginCheck,
    SharedSecret,
    SignedDoubleSubmit,
)
from fastapi_better_auth._internal.csrf import (
    DEFAULT_TOKEN_HEADER,
    enforce_policy,
    validated_policy,
)
from fastapi_better_auth._internal.reasons import REDACTED, fingerprint

APP = "https://app.example.com"
API = "https://api.example.com"
EVIL = "https://evil.example.com"
SECRET_VALUE = "Qb8Xm2vTz6Lp1RkYd9Wn4Hs7Cj3Fg5Ae"
OTHER_SECRET_VALUE = "Nf4Wq7zC2mVt9Bs5Kx1Ld8Hj6Yr3Pg0Z"
SECRET = SharedSecret(SECRET_VALUE)
OTHER_SECRET = SharedSecret(OTHER_SECRET_VALUE)

TOKEN = "vGm1nQ7bLxPd4Ks9.QkR2wYt6Zc8Ah5Vf0Bj3Nu7Md1Lp4Xe6Sg9Ry2Tw8Cq5="
OTHER_TOKEN = "aB3kR9wZ2mQ7tYx4.LpN6dHs1Vc8Gj5Fq0Ur3Wb7Ke2Zn9Tm4Ax6Cy1Sd8Po5="
REASONLESS = ("", "   ", "todo", "n/a", "testing")
GOOD_REASON = "Mode B only; this deployment sends no cookies"

SAFE = ("GET", "HEAD", "OPTIONS", "get", "options")
UNSAFE = ("POST", "PUT", "PATCH", "DELETE", "TRACE", "post", "delete")


def facts(
    *,
    method: str | None = "POST",
    origin: str | None = APP,
    sec_fetch_site: str | None = None,
    header_name: str | None = None,
    header_value: str | None = None,
    websocket: bool = False,
) -> CsrfFacts:
    """A snapshot built by hand — the shape a policy is actually handed."""
    return CsrfFacts(
        method=method,
        origin=origin,
        sec_fetch_site=sec_fetch_site,
        header_name=header_name,
        header_value=header_value,
        websocket=websocket,
    )


def http(method: str = "POST", **headers: str) -> HTTPConnection:
    raw = [(key.replace("_", "-").encode(), value.encode()) for key, value in headers.items()]
    return HTTPConnection({"type": "http", "method": method, "path": "/", "headers": raw})


def websocket(**headers: str) -> HTTPConnection:
    """A handshake scope: no `method` key at all, which is what makes it its own case."""
    raw = [(key.replace("_", "-").encode(), value.encode()) for key, value in headers.items()]
    return HTTPConnection({"type": "websocket", "path": "/ws", "headers": raw})


def origin_check(**kwargs: Any) -> OriginCheck:
    kwargs.setdefault("allowed_origins", [APP])
    return OriginCheck(**kwargs)


def double_submit(**kwargs: Any) -> SignedDoubleSubmit:
    kwargs.setdefault("secret", SECRET)
    kwargs.setdefault("allowed_origins", [APP])
    return SignedDoubleSubmit(**kwargs)


def shipped_policies() -> tuple[CsrfPolicy, ...]:
    return (origin_check(), double_submit(), CsrfDisabled(reason=GOOD_REASON))


# ---------------------------------------------------------------- the snapshot


def test_the_snapshot_is_captured_from_an_http_connection() -> None:
    policy = origin_check(require_header="x-requested-with")

    captured = CsrfFacts.from_connection(
        http("POST", origin=APP, sec_fetch_site="same-site", x_requested_with="fetch"),
        policy=policy,
    )

    assert captured.method == "POST"
    assert captured.origin == APP
    assert captured.sec_fetch_site == "same-site"
    assert captured.header_name == "x-requested-with"
    assert captured.header_value == "fetch"
    assert captured.websocket is False


def test_a_websocket_handshake_is_captured_as_one() -> None:
    """A handshake scope carries no `method`, so the flag is the only thing that says so."""
    captured = CsrfFacts.from_connection(websocket(origin=APP), policy=origin_check())

    assert captured.websocket is True
    assert captured.method is None
    assert captured.origin == APP


def test_the_snapshot_reads_only_the_header_the_policy_asked_for() -> None:
    """The policy owns the header name, so the wiring cannot disagree with the check."""
    connection = http("POST", origin=APP, x_csrf_token="planted", x_requested_with="fetch")

    neither = CsrfFacts.from_connection(connection, policy=origin_check())
    asked = CsrfFacts.from_connection(
        connection, policy=origin_check(require_header="X-Requested-With")
    )

    assert neither.header_name is None
    assert neither.header_value is None
    assert asked.header_name == "x-requested-with"
    assert asked.header_value == "fetch"


def test_the_snapshot_never_raises_on_a_request_that_carries_nothing() -> None:
    """It runs inside `extract`, which may not raise for any request whatsoever."""
    captured = CsrfFacts.from_connection(http("POST"), policy=double_submit())

    assert captured.origin is None
    assert captured.sec_fetch_site is None
    assert captured.header_value is None
    assert captured.header_name == DEFAULT_TOKEN_HEADER


@pytest.mark.parametrize(
    "hostile",
    [
        {"origin": "\x00\x7f not a url at all"},
        {"origin": "x" * 9000},
        {"sec_fetch_site": "cross-site, same-origin"},
        {"x_csrf_token": ""},
        {"x_csrf_token": "\t"},
    ],
    ids=["control-bytes", "enormous", "comma-joined", "empty", "tab"],
)
def test_the_snapshot_never_raises_on_a_hostile_request(hostile: dict[str, str]) -> None:
    """`extract` owes the dispatcher a method that cannot be made to raise by any request."""
    captured = CsrfFacts.from_connection(http("POST", **hostile), policy=double_submit())

    assert captured.requires_check is True


def test_the_snapshot_is_frozen() -> None:
    captured = facts()

    with pytest.raises(dataclasses.FrozenInstanceError):
        captured.origin = EVIL  # type: ignore[misc]


def test_the_snapshot_renders_no_submitted_token() -> None:
    """`repr` is what an error reporter serializes out of a captured frame, and `%s` - which
    is how `logging` renders an argument - falls through to it, so both are asserted."""
    captured = facts(header_name="x-csrf-token", header_value=TOKEN, origin=EVIL)

    rendered = f"{captured!r} {captured} {captured!s}"

    assert TOKEN not in rendered
    assert fingerprint(TOKEN) in rendered
    assert EVIL in rendered, "the operator cannot diagnose a refusal with nothing in the repr"


def test_a_hostile_origin_is_redacted_from_the_snapshot_rendering() -> None:
    captured = facts(origin='https://evil\n2026-01-01 CRITICAL forged"')

    assert REDACTED in repr(captured)


@pytest.mark.parametrize("method", SAFE)
def test_a_safe_method_needs_no_check(method: str) -> None:
    assert facts(method=method).requires_check is False


@pytest.mark.parametrize("method", UNSAFE)
def test_an_unsafe_method_needs_a_check(method: str) -> None:
    assert facts(method=method).requires_check is True


@pytest.mark.parametrize("method", SAFE)
def test_every_websocket_handshake_needs_a_check(method: str) -> None:
    """The handshake is a GET and is not same-origin-policy protected (CSWSH)."""
    assert facts(method=method, websocket=True).requires_check is True


def test_a_request_with_no_method_at_all_needs_a_check() -> None:
    """Fail closed: an unrecognizable scope is not evidence that the request was safe."""
    assert facts(method=None).requires_check is True


# ---------------------------------------------------------------- OriginCheck: the ladder


def test_a_same_origin_unsafe_request_passes() -> None:
    origin_check().check(facts(origin=APP, sec_fetch_site="same-origin"), TOKEN)


def test_a_cross_origin_post_is_refused_even_with_a_good_session_token() -> None:
    """The load-bearing RED: the rider's cookie is valid and the request is still refused."""
    with pytest.raises(CsrfFailure) as caught:
        origin_check().check(facts(origin=EVIL), TOKEN)

    assert caught.value.status_code == 403
    assert caught.value.detail == "Forbidden"
    assert caught.value.headers is None


def test_a_cross_site_websocket_handshake_is_refused() -> None:
    """The second load-bearing RED: a GET, and still checked (CSWSH)."""
    with pytest.raises(CsrfFailure):
        origin_check().check(facts(method=None, origin=EVIL, websocket=True), TOKEN)


def test_a_same_origin_websocket_handshake_passes() -> None:
    origin_check().check(facts(method=None, origin=APP, websocket=True), TOKEN)


@pytest.mark.parametrize(
    "origin", [None, "", "   ", "null"], ids=["absent", "empty", "blank", "null"]
)
def test_an_unsafe_request_without_a_usable_origin_is_refused(origin: str | None) -> None:
    """The third RED. Non-browser clients belong on Mode B, not on a hole in this check."""
    with pytest.raises(CsrfFailure):
        origin_check().check(facts(origin=origin), TOKEN)


def test_a_cross_site_fetch_metadata_declaration_is_refused_before_the_allowlist() -> None:
    """`Sec-Fetch-Site: cross-site` is the browser saying so; nothing below it can rescue it."""
    with pytest.raises(CsrfFailure) as caught:
        origin_check().check(facts(origin=APP, sec_fetch_site="Cross-Site"), TOKEN)

    assert "Sec-Fetch-Site" in caught.value.reason


@pytest.mark.parametrize(
    "site", ["same-origin", "same-site", "none", "", "future-value-nobody-has-shipped-yet"]
)
def test_every_other_fetch_metadata_value_falls_through_to_the_allowlist(site: str) -> None:
    """`same-site` is a sibling subdomain - the subdomain-takeover shape - so it is not a
    pass on its own; it is decided by the exact-match allowlist like everything else."""
    policy = origin_check()

    policy.check(facts(origin=APP, sec_fetch_site=site), TOKEN)
    with pytest.raises(CsrfFailure):
        policy.check(facts(origin=EVIL, sec_fetch_site=site), TOKEN)


@pytest.mark.parametrize("method", SAFE)
def test_a_safe_method_skips_every_rung(method: str) -> None:
    policy = origin_check(require_header="x-requested-with")

    policy.check(facts(method=method, origin=EVIL, sec_fetch_site="cross-site"), TOKEN)


def test_the_allowlist_is_canonicalized_at_construction() -> None:
    """Two spellings of one origin are one origin - settled once, at build time."""
    policy = OriginCheck(allowed_origins=["HTTPS://App.Example.COM:443/"])

    assert policy.allowed_origins == (APP,)
    policy.check(facts(origin=APP), TOKEN)


@pytest.mark.parametrize(
    "presented",
    [f"{APP}/", f"{APP}:443", "HTTPS://APP.EXAMPLE.COM", f"{APP}/path", f" {APP}"],
    ids=["trailing-slash", "explicit-port", "uppercase", "with-path", "leading-space"],
)
def test_a_presented_origin_is_matched_verbatim_and_never_re_canonicalized(presented: str) -> None:
    """A browser serializes `Origin` canonically. Re-normalizing attacker bytes would run
    operator-configuration validation over client input, which is a category error - and the
    refusals it raises are `ConfigurationError`, i.e. a 500 built out of a hostile header."""
    with pytest.raises(CsrfFailure):
        origin_check().check(facts(origin=presented), TOKEN)


def test_a_non_ascii_origin_is_refused_rather_than_crashing_the_comparison() -> None:
    """`compare_digest` raises `TypeError` on a non-ASCII `str`; a refusal must stay a 403."""
    with pytest.raises(CsrfFailure):
        origin_check().check(facts(origin="https://éxample.com"), TOKEN)


def test_one_of_several_allowed_origins_passes() -> None:
    policy = OriginCheck(allowed_origins=[APP, API])

    policy.check(facts(origin=API), TOKEN)
    policy.check(facts(origin=APP), TOKEN)
    with pytest.raises(CsrfFailure):
        policy.check(facts(origin=EVIL), TOKEN)


# ---------------------------------------------------------------- the custom-header rung


def test_a_required_header_must_be_present() -> None:
    policy = origin_check(require_header="x-requested-with")

    policy.check(facts(header_name="x-requested-with", header_value="fetch"), TOKEN)
    with pytest.raises(CsrfFailure):
        policy.check(facts(header_name="x-requested-with", header_value=None), TOKEN)
    with pytest.raises(CsrfFailure):
        policy.check(facts(header_name="x-requested-with", header_value="  "), TOKEN)


def test_a_snapshot_captured_for_another_header_is_refused() -> None:
    """A hand-built snapshot cannot smuggle a value past the header the policy asked for."""
    policy = origin_check(require_header="x-requested-with")

    with pytest.raises(CsrfFailure) as caught:
        policy.check(facts(header_name="x-something-else", header_value="fetch"), TOKEN)

    assert "x-requested-with" in caught.value.reason


def test_no_required_header_means_no_header_rung() -> None:
    origin_check().check(facts(header_name=None, header_value=None), TOKEN)


# ---------------------------------------------------------------- SignedDoubleSubmit


def test_the_signed_token_is_accepted() -> None:
    policy = double_submit()

    policy.check(
        facts(header_name=DEFAULT_TOKEN_HEADER, header_value=policy.token_for(TOKEN)), TOKEN
    )


def test_a_forged_signed_token_is_refused() -> None:
    policy = double_submit()

    with pytest.raises(CsrfFailure):
        policy.check(facts(header_name=DEFAULT_TOKEN_HEADER, header_value="0" * 64), TOKEN)


def test_a_signed_token_minted_for_another_session_is_refused() -> None:
    """The whole point of binding it to the session: a sibling subdomain that can plant a
    cookie still cannot plant a value that matches *this* session's token."""
    policy = double_submit()
    planted = policy.token_for(OTHER_TOKEN)

    with pytest.raises(CsrfFailure):
        policy.check(facts(header_name=DEFAULT_TOKEN_HEADER, header_value=planted), TOKEN)


def test_a_missing_signed_token_is_refused() -> None:
    policy = double_submit()

    with pytest.raises(CsrfFailure):
        policy.check(facts(header_name=DEFAULT_TOKEN_HEADER, header_value=None), TOKEN)


def test_a_correct_signed_token_does_not_rescue_a_cross_origin_request() -> None:
    """The rungs are a ladder, in a fixed order: the origin gate is not optional here."""
    policy = double_submit()

    with pytest.raises(CsrfFailure) as caught:
        policy.check(
            facts(
                origin=EVIL,
                header_name=DEFAULT_TOKEN_HEADER,
                header_value=policy.token_for(TOKEN),
            ),
            TOKEN,
        )

    assert "Origin" in caught.value.reason


@pytest.mark.parametrize("method", SAFE)
def test_the_signed_policy_skips_a_safe_method(method: str) -> None:
    double_submit().check(facts(method=method, origin=EVIL), TOKEN)


def test_a_cross_site_websocket_handshake_is_refused_by_the_signed_policy() -> None:
    with pytest.raises(CsrfFailure):
        double_submit().check(facts(method=None, origin=EVIL, websocket=True), TOKEN)


def test_the_token_helper_is_stable_hex_and_bound_to_both_inputs() -> None:
    """What the application hands its frontend. Two sessions, or two secrets, never collide."""
    policy = double_submit()
    minted = policy.token_for(TOKEN)

    assert minted == policy.token_for(TOKEN)
    assert len(minted) == 64
    assert bytes.fromhex(minted)
    assert minted != policy.token_for(OTHER_TOKEN)
    assert minted != double_submit(secret=OTHER_SECRET).token_for(TOKEN)
    assert TOKEN not in minted
    assert SECRET_VALUE not in minted


@pytest.mark.parametrize("value", [None, 7, b"bytes"], ids=["none", "int", "bytes"])
def test_the_token_helper_refuses_a_value_that_is_not_a_session_token(value: object) -> None:
    with pytest.raises(TypeError):
        double_submit().token_for(value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [None, 7, b"bytes"], ids=["none", "int", "bytes"])
def test_a_session_token_that_is_not_a_string_is_refused_rather_than_crashing(
    value: object,
) -> None:
    """`verify` hands this over; a verifier that hands over the wrong thing fails closed."""
    policy = double_submit()

    with pytest.raises(CsrfFailure):
        policy.check(facts(header_name=DEFAULT_TOKEN_HEADER, header_value="x" * 64), value)  # type: ignore[arg-type]


def test_the_signed_policy_requires_its_header_by_construction() -> None:
    policy = double_submit()

    assert policy.required_header == DEFAULT_TOKEN_HEADER
    assert double_submit(header="X-App-Csrf").required_header == "x-app-csrf"


def test_the_signed_policy_publishes_its_allowlist() -> None:
    assert double_submit(allowed_origins=["HTTPS://App.Example.COM/"]).allowed_origins == (APP,)


def test_a_policy_renders_its_configuration_and_never_the_secret() -> None:
    """A configuration object gets printed, logged and captured by error reporters; the one
    thing in this one that must not survive that is the shared secret."""
    plain = repr(origin_check(require_header="x-requested-with"))
    signed = repr(double_submit())

    assert APP in plain
    assert APP in signed
    assert DEFAULT_TOKEN_HEADER in signed
    assert SECRET_VALUE not in signed
    assert SECRET.fingerprint in signed


# ---------------------------------------------------------------- CsrfDisabled


@pytest.mark.parametrize(
    "hostile",
    [
        {"origin": EVIL},
        {"origin": None},
        {"origin": EVIL, "sec_fetch_site": "cross-site"},
        {"method": None, "origin": EVIL, "websocket": True},
    ],
    ids=["cross-origin", "no-origin", "cross-site", "cswsh"],
)
def test_the_disabled_policy_passes_everything(hostile: dict[str, Any]) -> None:
    CsrfDisabled(reason=GOOD_REASON).check(facts(**hostile), TOKEN)


@pytest.mark.parametrize("reason", REASONLESS)
def test_the_disabled_policy_refuses_a_reason_nobody_would_call_one(reason: str) -> None:
    with pytest.raises(ConfigurationError):
        CsrfDisabled(reason=reason)


def test_the_disabled_policy_refuses_a_reason_that_is_not_a_string() -> None:
    with pytest.raises(ConfigurationError):
        CsrfDisabled(reason=None)  # type: ignore[arg-type]


def test_the_disabled_policy_carries_its_reason_where_an_operator_sees_it() -> None:
    policy = CsrfDisabled(reason=GOOD_REASON)

    assert policy.reason == GOOD_REASON
    assert GOOD_REASON in repr(policy)
    assert policy.required_header is None


# ---------------------------------------------------------------- configuration is eager


@pytest.mark.parametrize(
    "allowed",
    [
        [],
        (),
        APP,
        b"https://app.example.com",
        7,
        None,
        [APP, 7],
        ["not-a-url"],
        ["https://app.example.com/path"],
        ["http://app.example.com"],
        [APP, f"{APP}:443"],
    ],
    ids=[
        "empty-list",
        "empty-tuple",
        "bare-string",
        "bytes",
        "int",
        "none",
        "non-string-entry",
        "not-a-url",
        "with-path",
        "cleartext",
        "duplicate-after-normalization",
    ],
)
def test_an_unusable_allowlist_is_refused_at_construction(allowed: object) -> None:
    """A bare string is the one that matters: iterating it would allow 21 one-character
    origins and nothing else, and the application would boot looking configured."""
    with pytest.raises(ConfigurationError):
        OriginCheck(allowed_origins=allowed)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "header",
    ["", "   ", "x csrf", "x:csrf", "x\ncsrf", 7, "cookie", "Origin", "content-type", "referer"],
    ids=[
        "empty",
        "blank",
        "space",
        "colon",
        "newline",
        "int",
        "cookie",
        "origin",
        "content-type",
        "referer",
    ],
)
def test_an_unusable_required_header_is_refused_at_construction(header: object) -> None:
    """A header the browser sets itself is not a custom header: a cross-site form POST
    carries `content-type` and `cookie` already, so requiring one protects nothing."""
    with pytest.raises(ConfigurationError):
        OriginCheck(allowed_origins=[APP], require_header=header)  # type: ignore[arg-type]
    with pytest.raises(ConfigurationError):
        SignedDoubleSubmit(secret=SECRET, allowed_origins=[APP], header=header)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "secret", [SECRET_VALUE, None, 7, b"bytes"], ids=["str", "none", "int", "bytes"]
)
def test_the_signed_policy_refuses_a_secret_that_is_not_a_shared_secret(secret: object) -> None:
    """A bare `str` would skip every boot refusal `SharedSecret` exists to make."""
    with pytest.raises(ConfigurationError) as caught:
        SignedDoubleSubmit(secret=secret, allowed_origins=[APP])  # type: ignore[arg-type]

    assert "SharedSecret" in str(caught.value)
    assert SECRET_VALUE not in str(caught.value)


def test_a_missing_allowlist_is_refused_by_the_signed_policy_too() -> None:
    with pytest.raises(ConfigurationError):
        SignedDoubleSubmit(secret=SECRET, allowed_origins=[])


# ---------------------------------------------------------------- the policy contract


@pytest.mark.parametrize("policy", shipped_policies(), ids=lambda p: type(p).__name__)
def test_every_shipped_policy_satisfies_the_protocol(policy: CsrfPolicy) -> None:
    assert isinstance(policy, CsrfPolicy)
    assert validated_policy(policy, where="CookieVerifier(csrf=...)") is policy


def test_the_protocol_is_a_data_protocol_and_refuses_issubclass() -> None:
    with pytest.raises(TypeError):
        issubclass(OriginCheck, CsrfPolicy)  # type: ignore[misc]


def test_none_is_never_a_policy() -> None:
    """D-006: no `None` default, so a cookie mode cannot be built without a CSRF answer."""
    with pytest.raises(ConfigurationError) as caught:
        validated_policy(None, where="CookieVerifier(csrf=...)")

    assert "CsrfDisabled" in str(caught.value)


class Headerless:
    """Every member present and `required_header` unusable — what `isinstance` cannot see."""

    required_header = "x bad header"

    def check(self, facts: CsrfFacts, session_token: str) -> None:
        return None


class NotCallable:
    required_header = None
    check = "not-a-function"


class Nothing:
    """No members at all: a typo, or a half-written policy."""


@pytest.mark.parametrize(
    "policy", [Headerless(), NotCallable(), Nothing(), object(), "OriginCheck", 7]
)
def test_an_object_that_cannot_be_a_policy_is_refused_at_construction(policy: object) -> None:
    with pytest.raises(ConfigurationError):
        validated_policy(policy, where="CookieVerifier(csrf=...)")


class Answering:
    """Returns `False` for "deny" — the shape that fails OPEN at a caller that ignores it."""

    required_header = None

    def check(self, facts: CsrfFacts, session_token: str) -> bool:
        return False


@pytest.mark.parametrize("policy", shipped_policies(), ids=lambda p: type(p).__name__)
def test_the_sanctioned_call_runs_a_well_behaved_policy(policy: CsrfPolicy) -> None:
    enforce_policy(policy, facts(method="GET"), TOKEN)


def test_a_policy_that_answers_instead_of_raising_is_refused_loudly() -> None:
    """`check` allows by returning None, so a returned `False` would be read as "allowed"."""
    with pytest.raises(ConfigurationError) as caught:
        enforce_policy(Answering(), facts(origin=EVIL), TOKEN)  # pyright: ignore[reportArgumentType]

    assert "Answering" in str(caught.value)


def test_the_sanctioned_call_lets_a_refusal_through_unchanged() -> None:
    with pytest.raises(CsrfFailure):
        enforce_policy(origin_check(), facts(origin=EVIL), TOKEN)


# ---------------------------------------------------------------- hygiene


def refusals() -> tuple[tuple[str, CsrfPolicy, CsrfFacts], ...]:
    """Every way this layer refuses, so the hygiene assertion is the set and not a sample."""
    signed = double_submit()
    return (
        ("cross-site", origin_check(), facts(origin=APP, sec_fetch_site="cross-site")),
        ("no-origin", origin_check(), facts(origin=None)),
        ("unlisted-origin", origin_check(), facts(origin=EVIL)),
        (
            "missing-header",
            origin_check(require_header="x-requested-with"),
            facts(header_name="x-requested-with", header_value=None),
        ),
        (
            "wrong-header",
            origin_check(require_header="x-requested-with"),
            facts(header_name="x-elsewhere", header_value=TOKEN),
        ),
        (
            "forged-token",
            signed,
            facts(header_name=DEFAULT_TOKEN_HEADER, header_value=signed.token_for(OTHER_TOKEN)),
        ),
        ("cswsh", origin_check(), facts(method=None, origin=EVIL, websocket=True)),
    )


REFUSALS = refusals()


@pytest.mark.parametrize(
    ("policy", "captured"),
    [(case[1], case[2]) for case in REFUSALS],
    ids=[case[0] for case in REFUSALS],
)
def test_no_refusal_reason_carries_a_credential(policy: CsrfPolicy, captured: CsrfFacts) -> None:
    """D-018, for this layer: a reason reaches logs and error reporters, so the session
    token and the submitted value may only appear as a fingerprint."""
    with pytest.raises(CsrfFailure) as caught:
        policy.check(captured, TOKEN)

    reason = caught.value.reason
    assert reason, "a refusal with no reason tells an operator nothing"
    assert TOKEN not in reason
    assert TOKEN.split(".")[1] not in reason
    assert OTHER_TOKEN not in reason
    assert SECRET_VALUE not in reason


@pytest.mark.parametrize(
    ("policy", "captured"),
    [(case[1], case[2]) for case in REFUSALS],
    ids=[case[0] for case in REFUSALS],
)
def test_no_refusal_reason_reaches_the_client(policy: CsrfPolicy, captured: CsrfFacts) -> None:
    """The 403 is uniform: same status, same body, no challenge, whichever rung refused."""
    with pytest.raises(CsrfFailure) as caught:
        policy.check(captured, TOKEN)

    assert caught.value.status_code == 403
    assert caught.value.detail == "Forbidden"
    assert caught.value.headers is None
    assert caught.value.reason not in str(caught.value)


def test_a_hostile_origin_cannot_forge_a_log_line_through_a_reason() -> None:
    hostile = 'https://evil.example.com"\n2026-01-01 CRITICAL forged log line'

    with pytest.raises(CsrfFailure) as caught:
        origin_check().check(facts(origin=hostile), TOKEN)

    assert "forged log line" not in caught.value.reason
    assert REDACTED in caught.value.reason
