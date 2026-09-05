"""The fortified key-set client: every rule it enforces, and the cost of forgetting one.

A JWKS client is a network fetch that decides which public key verifies a token, driven by a
`kid` an attacker chose. Everything here is one of those two facts made into a rule: the fetch
is pinned, capped, unfollowed and refused unless it is JSON; the `kid` may not cause an
unbounded number of fetches, an unbounded amount of remembered state, or a key this deployment
never allowed.

The transport is a double on purpose — see `tests/transports.py`. What is being proved is the
client's *policy* (how many fetches, in what window, behind which lock), and the adapter's own
obligations already have a real socket pointed at them in `tests/test_transports.py`.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import anyio
import anyio.lowlevel
import pytest

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuthError,
    ConfigurationError,
    ContentEncodingRejected,
    ResponseTooLarge,
    SessionError,
)
from fastapi_better_auth._internal.jwks import (
    CACHE_TTL,
    JWKS_PATH,
    MAX_JWKS_BYTES,
    MAX_KEYS,
    MAX_REMEMBERED_MISSES,
    MIN_CACHE_TTL,
    MIN_RSA_KEY_BITS,
    JwksClient,
)
from fastapi_better_auth._internal.reasons import REDACTED
from tests.tokens import (
    ORIGIN,
    Clock,
    Signer,
    deepest_depth,
    defeats_the_json_parser,
    ed25519_signer,
    exhausted_parse,
    key_set,
    nested_arrays,
    rsa_signer,
    weak_rsa_signer,
)
from tests.transports import NotATransport, Reply, ScriptedTransport, json_reply

SIGNER = ed25519_signer("cached-1")
ROTATED = ed25519_signer("cached-2")
KEY_SET = key_set(SIGNER)
DEEP_DOCUMENT_DEPTH = deepest_depth(nested_arrays, MAX_JWKS_BYTES)
DEEP_DOCUMENT = nested_arrays(DEEP_DOCUMENT_DEPTH)
"""The deepest key-set body `MAX_JWKS_BYTES` admits: what an upstream that has been taken over
may actually send, bounded by the cap rather than by anything this process controls."""
DOCUMENT_OVERFLOWS = defeats_the_json_parser(DEEP_DOCUMENT)
"""Whether that body defeats *this* interpreter's scanner, which is a platform fact - see
`test_a_key_set_the_json_parser_gives_up_on_is_unusable` for the part that is not."""
OUT_OF_REACH = (
    f"this interpreter's JSON scanner survives {DEEP_DOCUMENT_DEPTH} nested arrays, which is "
    f"the deepest body MAX_JWKS_BYTES ({MAX_JWKS_BYTES}) admits, so the overflow is not "
    f"reachable under the cap here"
)
LIBRARY_LOGGER = "fastapi_better_auth"
SKIP_PREFIX = "jwks key %s is not usable"
"""The head of the skip template. Matched on the *template*, so a test asserting "one skip"
cannot be satisfied by some other line that happens to mention the same words."""


def _skips(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """The skip lines emitted so far. Read at assert time: pytest hands each phase its own
    record list, so a reference taken during setup would stay empty for the whole call."""
    return [
        record
        for record in caplog.records
        if record.name == LIBRARY_LOGGER and str(record.msg).startswith(SKIP_PREFIX)
    ]


def client(
    *answers: Reply | BaseException,
    clock: Clock | None = None,
    gate: anyio.Event | None = None,
    algorithms: tuple[str, ...] = ("EdDSA",),
    **settings: Any,
) -> tuple[JwksClient, ScriptedTransport]:
    transport = ScriptedTransport(*answers, gate=gate)
    return (
        JwksClient(
            base_url=ORIGIN,
            transport=transport,
            algorithms=algorithms,
            clock=Clock() if clock is None else clock,
            **settings,
        ),
        transport,
    )


# --- the fetch ------------------------------------------------------------------------


@pytest.mark.anyio
async def test_the_key_set_is_fetched_from_the_pinned_origin() -> None:
    keys, transport = client(json_reply(KEY_SET))

    found = await keys.key_for(SIGNER.kid)

    assert found is not None
    assert keys.uri == f"{ORIGIN}{JWKS_PATH}"
    assert transport.targets == [f"{ORIGIN}{JWKS_PATH}"]
    assert transport.posts == 0


@pytest.mark.anyio
async def test_the_fetch_carries_the_size_cap() -> None:
    """`max_bytes` has no default in the Protocol because the cap is the caller's policy."""
    keys, transport = client(json_reply(KEY_SET))

    await keys.key_for(SIGNER.kid)

    assert transport.caps == [MAX_JWKS_BYTES]


@pytest.mark.anyio
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308, 400, 401, 404, 429, 500, 503])
async def test_a_non_200_is_unavailable(status: int) -> None:
    """A 3xx is in this list deliberately: the transport does not follow redirects, so a
    redirect arrives here as an answer, and an answer that is not the key set is a failure."""
    keys, _transport = client(json_reply(KEY_SET, status=status))

    with pytest.raises(AuthServiceUnavailable):
        await keys.key_for(SIGNER.kid)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "content_type",
    ["text/html", "text/plain", "application/xml", None, "application/jsonx"],
)
async def test_a_body_that_is_not_json_is_unavailable(content_type: str | None) -> None:
    keys, _transport = client(json_reply(KEY_SET, content_type=content_type))

    with pytest.raises(AuthServiceUnavailable):
        await keys.key_for(SIGNER.kid)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "content_type",
    [
        "application/json",
        "application/json; charset=utf-8",
        "APPLICATION/JSON",
        "application/jwk-set+json",
        "application/jwk-set+json; charset=UTF-8",
    ],
)
async def test_the_json_media_types_upstream_may_use_are_accepted(content_type: str) -> None:
    keys, _transport = client(json_reply(KEY_SET, content_type=content_type))

    assert await keys.key_for(SIGNER.kid) is not None


@pytest.mark.anyio
@pytest.mark.parametrize(
    "failure",
    [
        ResponseTooLarge(max_bytes=MAX_JWKS_BYTES),
        ContentEncodingRejected(encoding="gzip"),
        TimeoutError("jwks timed out"),
        RuntimeError("connection refused"),
    ],
    ids=["too-large", "content-encoding", "timeout", "network"],
)
async def test_every_transport_failure_becomes_unavailable(failure: BaseException) -> None:
    """`UntrustedResponse` and `TimeoutError` are the two the Protocol names; everything else
    arrives as whatever the HTTP library raised, untranslated, and is ours to translate."""
    keys, _transport = client(failure)

    with pytest.raises(AuthServiceUnavailable):
        await keys.key_for(SIGNER.kid)


@pytest.mark.anyio
async def test_a_configuration_error_from_the_transport_is_not_swallowed() -> None:
    """The translation wraps the fetch and nothing else: a deployment fault stays a
    deployment fault rather than being reported as an unreachable auth service."""
    keys, _transport = client(ConfigurationError("the injected client was never opened"))

    with pytest.raises(ConfigurationError):
        await keys.key_for(SIGNER.kid)


@pytest.mark.anyio
async def test_a_session_error_from_the_transport_is_not_swallowed() -> None:
    keys, _transport = client(AuthServiceUnavailable(reason="already translated"))

    with pytest.raises(SessionError) as caught:
        await keys.key_for(SIGNER.kid)

    assert caught.value.reason == "already translated"


# --- the document ---------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize(
    "document",
    [
        b"not json at all",
        b"",
        b"[]",
        b'"keys"',
        b"null",
        b'{"nokeys": []}',
        b'{"keys": {}}',
        b'{"keys": [null]}',
        b'{"keys": [{"kty": "OKP", "alg": "EdDSA"}]}',
        b'{"keys": [{"kid": 7, "alg": "EdDSA"}]}',
        b'{"keys": [{"kid": "", "alg": "EdDSA"}]}',
        b'{"keys": [{"kid": "k", "alg": 7}]}',
        b'{"keys": [{"kid": "k"}]}',
    ],
    ids=[
        "not-json",
        "empty",
        "array",
        "string",
        "null",
        "no-keys-member",
        "keys-not-a-list",
        "key-not-an-object",
        "no-kid",
        "kid-not-a-string",
        "empty-kid",
        "alg-not-a-string",
        "no-alg",
    ],
)
async def test_a_malformed_key_set_is_unavailable(document: bytes) -> None:
    keys, _transport = client(Reply(content=document))

    with pytest.raises(AuthServiceUnavailable):
        await keys.key_for(SIGNER.kid)


@pytest.mark.anyio
async def test_a_key_set_the_json_parser_gives_up_on_is_unusable(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """SA-4's sibling, by construction rather than by probe, so it holds on every lane.

    `RecursionError` is a `RuntimeError`, so it sat outside the except tuple around the parse
    and escaped `key_for` as itself - the one answer this client is built never to give, since
    every other unparseable body is an `AuthServiceUnavailable`. The real deep-body probe
    below reaches this parser only where the cap admits a body deeper than the interpreter's
    own ceiling; this does not depend on which interpreter is running it.
    """
    keys, _transport = client(json_reply(KEY_SET))

    with caplog.at_level(logging.ERROR), pytest.MonkeyPatch.context() as patch:
        patch.setattr(json, "loads", exhausted_parse)
        with pytest.raises(AuthServiceUnavailable) as caught:
            await keys.key_for(SIGNER.kid)

    assert caught.value.reason.endswith("is unusable: it is not JSON")
    assert caplog.records == []


def test_the_nesting_probe_is_the_deepest_the_cap_admits() -> None:
    """Prove the instrument before the observation, on every interpreter. A body past
    `MAX_JWKS_BYTES` never reaches the parser at all, so a probe built past it would pass the
    tests below while proving nothing; one level deeper than this is over the cap."""
    assert len(DEEP_DOCUMENT) <= MAX_JWKS_BYTES
    assert len(nested_arrays(DEEP_DOCUMENT_DEPTH + 1)) > MAX_JWKS_BYTES


@pytest.mark.skipif(not DOCUMENT_OVERFLOWS, reason=OUT_OF_REACH)
def test_the_nesting_probe_really_defeats_this_interpreters_json_parser() -> None:
    """Platform evidence: here the cap admits a body this scanner cannot finish reading.
    Where it does not, this skips with the measured depth rather than asserting a fact that
    is not true there - the containment itself is pinned by the guard above."""
    with pytest.raises(RecursionError):
        json.loads(DEEP_DOCUMENT)


@pytest.mark.anyio
async def test_a_key_set_nested_as_deep_as_the_cap_allows_is_unusable() -> None:
    """The deepest body the cap admits, end to end. Where the probe overflows this
    interpreter, this is the escape route walked for real; where it does not, the scanner
    returns a list and the document is refused for not being a JSON object. Both are the
    same verdict, which is why this holds everywhere."""
    keys, _transport = client(Reply(content=DEEP_DOCUMENT))

    with pytest.raises(AuthServiceUnavailable):
        await keys.key_for(SIGNER.kid)


@pytest.mark.anyio
async def test_an_empty_key_set_is_not_malformed_it_simply_knows_no_kid() -> None:
    keys, _transport = client(json_reply({"keys": []}))

    assert await keys.key_for(SIGNER.kid) is None


@pytest.mark.anyio
async def test_a_key_whose_material_is_broken_is_unavailable() -> None:
    """An allowed algorithm whose key will not load is a corrupt key set, not an unknown
    kid: reporting it as unknown would send the operator hunting for a rotation that
    already happened."""
    broken = dict(SIGNER.jwk)
    broken["x"] = "not-base64url-material"
    keys, _transport = client(json_reply({"keys": [broken]}))

    with pytest.raises(AuthServiceUnavailable):
        await keys.key_for(SIGNER.kid)


@pytest.mark.anyio
async def test_more_keys_than_the_cap_is_unavailable() -> None:
    flood = key_set(*[ed25519_signer(f"flood-{index}") for index in range(MAX_KEYS + 1)])
    keys, _transport = client(json_reply(flood))

    with pytest.raises(AuthServiceUnavailable):
        await keys.key_for("flood-0")


@pytest.mark.anyio
async def test_a_key_set_exactly_at_the_cap_is_accepted() -> None:
    signers = [ed25519_signer(f"full-{index}") for index in range(MAX_KEYS)]
    keys, _transport = client(json_reply(key_set(*signers)))

    assert await keys.key_for("full-0") is not None


@pytest.mark.anyio
async def test_a_key_outside_the_allowlist_is_ignored_rather_than_refused() -> None:
    """Upstream may publish an algorithm this deployment does not accept - during a
    rotation, that is the normal state of the world for a while. The key set stays usable."""
    other = rsa_signer("rsa-1")
    keys, _transport = client(json_reply(key_set(SIGNER, other)), algorithms=("EdDSA",))

    assert await keys.key_for(SIGNER.kid) is not None
    assert await keys.key_for(other.kid) is None


@pytest.mark.anyio
async def test_a_duplicated_kid_keeps_the_first_key_published() -> None:
    """Two entries under one kid is ambiguous; resolving it consistently is what matters."""
    shadow = dict(ed25519_signer("shadow").jwk)
    shadow["kid"] = SIGNER.kid
    keys, _transport = client(json_reply({"keys": [dict(SIGNER.jwk), shadow]}))

    found = await keys.key_for(SIGNER.kid)

    assert found is not None
    assert found.jwk["x"] == SIGNER.jwk["x"]


# --- what a published key says about itself ---------------------------------------------


def _published(signer: Signer, **fields: Any) -> dict[str, Any]:
    """One JWK with extra members set on it, exactly as upstream would publish them."""
    return {**dict(signer.jwk), **fields}


SKIPPED: tuple[tuple[str, dict[str, Any]], ...] = (
    ("use", {"use": "enc"}),
    ("use-unknown", {"use": "sig-ish"}),
    ("use-null", {"use": None}),
    ("key_ops", {"key_ops": ["encrypt", "decrypt"]}),
    ("key_ops-empty", {"key_ops": []}),
    ("key_ops-not-a-list", {"key_ops": "verify"}),
)
"""Every declaration that says this key is not for checking signatures. `key_ops: "verify"`
is in here because `"verify" in "verify"` is `True` for a string - a membership test on an
unvalidated JSON value is how a malformed key set talks its way past a list check."""


@pytest.mark.anyio
@pytest.mark.parametrize(("label", "fields"), SKIPPED, ids=[name for name, _ in SKIPPED])
async def test_a_key_that_does_not_declare_itself_for_verification_is_skipped(
    label: str, fields: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    """SA-8. RFC 7517 4.2/4.3: `use` and `key_ops` are optional, and absent means unrestricted
    - but *present and pointing elsewhere* is upstream saying this key does not check
    signatures, and loading it anyway is checking signatures with an encryption key.

    Skipped rather than refused, deliberately: failing the whole set for one bad key is an
    outage for every token, while skipping is an outage only for the tokens that key signed.
    So the answer is an unknown kid, and a line in the log saying which key and why.
    """
    keys, _transport = client(json_reply({"keys": [_published(SIGNER, **fields)]}))

    assert await keys.key_for(SIGNER.kid) is None
    assert len(_skips(caplog)) == 1


@pytest.mark.anyio
async def test_an_undersized_rsa_key_is_skipped(caplog: pytest.LogCaptureFixture) -> None:
    """A 1024-bit RSA key loads and verifies its own signatures perfectly well, which is the
    problem: nothing downstream would ever notice. The size is only knowable after the key
    material is loaded, so this skip sits after the load rather than beside the declarations."""
    weak = weak_rsa_signer("weak-1")
    keys, _transport = client(json_reply(key_set(weak)), algorithms=("RS256",))

    assert await keys.key_for(weak.kid) is None
    assert len(_skips(caplog)) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "fields",
    [{}, {"use": "sig"}, {"key_ops": ["verify"]}, {"use": "sig", "key_ops": ["verify", "sign"]}],
    ids=["silent", "use-sig", "key-ops-verify", "both"],
)
async def test_a_key_that_declares_itself_for_verification_still_loads(
    fields: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    """The over-refusal half. Upstream publishes neither member today, so a rule that read
    absence as refusal would be an outage on the very deployment this library exists for."""
    keys, _transport = client(json_reply({"keys": [_published(SIGNER, **fields)]}))

    assert await keys.key_for(SIGNER.kid) is not None
    assert _skips(caplog) == []


@pytest.mark.anyio
async def test_a_key_at_the_rsa_floor_still_loads(caplog: pytest.LogCaptureFixture) -> None:
    """The floor is a floor, not a ceiling: 2048 is what upstream would publish."""
    strong = rsa_signer("strong-1")
    keys, _transport = client(json_reply(key_set(strong)), algorithms=("RS256",))

    found = await keys.key_for(strong.kid)

    assert found is not None
    assert found.key.key_size == MIN_RSA_KEY_BITS
    assert _skips(caplog) == []


@pytest.mark.anyio
async def test_one_bad_key_never_costs_the_rest_of_the_set(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The blast radius, stated as a test: the sibling keys in the same document keep working.

    A skip that raised would turn one mispublished key into a total authentication outage,
    which is strictly worse than the thing it is protecting against.
    """
    keys, _transport = client(
        json_reply({"keys": [_published(SIGNER, use="enc"), dict(ROTATED.jwk)]})
    )

    assert await keys.key_for(ROTATED.kid) is not None
    assert await keys.key_for(SIGNER.kid) is None
    assert len(_skips(caplog)) == 1


@pytest.mark.anyio
async def test_a_skipped_key_is_reported_once_per_fetch_and_never_per_lookup(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A line per lookup would be the log-amplification lever the key set is capped against;
    the parse happens once per fetch, so the line does too."""
    keys, transport = client(json_reply({"keys": [_published(SIGNER, use="enc")]}))

    for _ in range(5):
        assert await keys.key_for(SIGNER.kid) is None

    assert transport.calls == 1
    assert len(_skips(caplog)) == 1


@pytest.mark.anyio
async def test_a_skip_names_the_key_only_through_a_safe_label(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A `kid` is text upstream chose and an operator reads; the whole set is capped at 32
    keys, so a hostile one is only reachable through a compromised key set - which is exactly
    when a forged log line would be most useful to whoever compromised it."""
    hostile = 'aaa"\n2026-01-01 CRITICAL root logged in'
    keys, _transport = client(json_reply({"keys": [_published(SIGNER, kid=hostile, use="enc")]}))

    assert await keys.key_for(hostile) is None
    written = "\n".join(f"{record.getMessage()}" for record in _skips(caplog))
    assert REDACTED in written
    assert "CRITICAL" not in written


# --- the cache ------------------------------------------------------------------------


@pytest.mark.anyio
async def test_a_second_lookup_is_served_from_the_cache() -> None:
    keys, transport = client(json_reply(KEY_SET))

    assert await keys.key_for(SIGNER.kid) is not None
    assert await keys.key_for(SIGNER.kid) is not None
    assert transport.calls == 1


@pytest.mark.anyio
async def test_the_cache_is_refetched_once_it_has_expired() -> None:
    clock = Clock()
    keys, transport = client(json_reply(KEY_SET), clock=clock)

    await keys.key_for(SIGNER.kid)
    clock.advance(CACHE_TTL + 1)
    await keys.key_for(SIGNER.kid)

    assert transport.calls == 2


@pytest.mark.anyio
async def test_a_rotated_kid_is_picked_up_without_waiting_for_the_ttl() -> None:
    """A rotation is exactly the case a fresh cache would answer wrongly: the key set is
    young and the kid is new. What bounds the refetch is the ten-second window, not the
    five-minute TTL - so a rotated key is live in seconds, at one fetch per window."""
    clock = Clock()
    keys, transport = client(json_reply(KEY_SET), json_reply(key_set(SIGNER, ROTATED)), clock=clock)

    assert await keys.key_for(SIGNER.kid) is not None
    clock.advance(11)

    assert await keys.key_for(ROTATED.kid) is not None
    assert transport.calls == 2


@pytest.mark.anyio
async def test_a_rotation_inside_the_refetch_window_waits_for_it() -> None:
    """The other half of the same rule, stated so nobody has to discover it in production."""
    clock = Clock()
    keys, transport = client(json_reply(KEY_SET), json_reply(key_set(SIGNER, ROTATED)), clock=clock)

    await keys.key_for(SIGNER.kid)

    assert await keys.key_for(ROTATED.kid) is None
    assert transport.calls == 1


@pytest.mark.anyio
async def test_concurrent_misses_coalesce_behind_one_fetch() -> None:
    """Two requests arriving on a cold cache must produce one fetch, not two: upstream has
    a rate limit, and two answers that disagree is a state this library cannot resolve."""
    gate = anyio.Event()
    keys, transport = client(json_reply(KEY_SET), gate=gate)
    found: list[object] = []

    async def look_up() -> None:
        found.append(await keys.key_for(SIGNER.kid))

    async with anyio.create_task_group() as group:
        group.start_soon(look_up)
        group.start_soon(look_up)
        with anyio.fail_after(2):
            while keys.waiting < 1 or transport.calls < 1:
                await anyio.lowlevel.checkpoint()
        gate.set()

    assert transport.calls == 1
    assert len(found) == 2
    assert all(entry is not None for entry in found)


@pytest.mark.anyio
async def test_a_cancelled_fetch_does_not_burn_the_refetch_window() -> None:
    """SA-8. The window was stamped *before* the await, so a caller whose own deadline expired
    mid-fetch spent the whole ten seconds on behalf of everyone behind it: nobody fetched, and
    every lookup in that window answered `AuthServiceUnavailable` off a cold cache.

    A caller's deadline is not an attempt anybody made. The stamp moved to completion - a
    fetch that returned, and one that failed, are both attempts; a cancelled one is not.

    Cancelled on a *signal* rather than on a stopwatch: the scope is cut only once the
    transport has recorded the call, so the probe cannot pass by having never fetched at all.
    """
    clock = Clock()
    gate = anyio.Event()
    keys, transport = client(json_reply(KEY_SET), clock=clock, gate=gate)
    scopes: list[anyio.CancelScope] = []

    async def look_up() -> None:
        with anyio.CancelScope() as scope:
            scopes.append(scope)
            await keys.key_for(SIGNER.kid)

    async with anyio.create_task_group() as group:
        group.start_soon(look_up)
        with anyio.fail_after(2):
            while transport.calls < 1 or not scopes:
                await anyio.lowlevel.checkpoint()
        scopes[0].cancel()

    assert transport.calls == 1, "the fetch never started; this probe proves nothing"
    assert keys._may_fetch() is True  # pyright: ignore[reportPrivateUsage]

    gate.set()
    assert await keys.key_for(SIGNER.kid) is not None
    assert transport.calls == 2


@pytest.mark.anyio
@pytest.mark.parametrize(
    "failure",
    [TimeoutError("upstream down"), ConfigurationError("the injected client was never opened")],
    ids=["unavailable", "misconfigured"],
)
async def test_a_fetch_that_finished_badly_is_still_an_attempt(failure: BaseException) -> None:
    """The other side of the same rule, and the reason it is not simply "stamp on success":
    a failing upstream must not become one fetch per request. Both of these *finished*."""
    clock = Clock()
    keys, transport = client(failure, clock=clock)

    with pytest.raises((SessionError, BetterAuthError)):
        await keys.key_for(SIGNER.kid)
    assert keys._may_fetch() is False  # pyright: ignore[reportPrivateUsage]

    with pytest.raises((SessionError, BetterAuthError)):
        await keys.key_for(SIGNER.kid)
    assert transport.calls == 1


# --- the unknown kid ------------------------------------------------------------------


@pytest.mark.anyio
async def test_an_unknown_kid_is_not_refetched_for_inside_the_window() -> None:
    """Within the refetch window, a kid nobody has published is refused without a second
    upstream call - otherwise it would cost one fetch per request."""
    clock = Clock()
    keys, transport = client(json_reply(KEY_SET), clock=clock)

    assert await keys.key_for("never-published") is None
    assert await keys.key_for("never-published") is None
    assert transport.calls == 1


@pytest.mark.anyio
async def test_a_kid_cached_as_absent_is_rechecked_at_the_window_not_the_negative_ttl() -> None:
    """B2: a kid a fetch did not contain is cached as absent - but a rotation routinely lands
    the first token bearing a new kid before this process has fetched the rotation. The
    re-check has to open with the 10s refetch window, not stay shut for the 60s negative TTL,
    or every real rotation refuses valid tokens six times longer than advertised.

    RED before the reorder: at t=11 the negative cache short-circuits and returns None for a
    kid that is now published, for the full 60s.
    """
    clock = Clock()
    keys, transport = client(
        json_reply(KEY_SET),  # t=0: the rotated kid is not published yet
        json_reply(key_set(SIGNER, ROTATED)),  # by t=11 it is
        clock=clock,
        negative_ttl=60.0,
    )

    assert await keys.key_for(ROTATED.kid) is None  # cached as absent
    clock.advance(11)  # past the 10s window, far under the 60s TTL

    assert await keys.key_for(ROTATED.kid) is not None
    assert transport.calls == 2


@pytest.mark.anyio
async def test_the_flood_defense_survives_the_window_winning_over_the_negative_cache() -> None:
    """The other side of B2's reorder: letting the window override the negative cache must
    not reopen the flood. Distinct unknown kids inside one window still cost a single fetch."""
    clock = Clock()
    keys, transport = client(json_reply(KEY_SET), clock=clock, negative_ttl=60.0)

    assert await keys.key_for(ROTATED.kid) is None
    for index in range(50):
        assert await keys.key_for(f"flood-{index}") is None
    assert await keys.key_for(ROTATED.kid) is None

    assert transport.calls == 1


@pytest.mark.anyio
async def test_a_confirmed_absent_verdict_does_not_outlive_its_ttl_into_a_stale_key_set() -> None:
    """A kid confirmed absent by a fresh fetch may answer None while that verdict is young.
    Once it is older than negative_ttl AND the key set has gone stale, the verdict expires and
    the honest answer becomes AuthServiceUnavailable (D-083): the kid can no longer be told
    apart from one freshly rotated in. A long refetch window keeps a fetch from papering over
    the transition, so the expiry is what is under test."""
    clock = Clock()
    keys, _transport = client(
        json_reply(KEY_SET),
        clock=clock,
        cache_ttl=60.0,
        negative_ttl=30.0,
        refetch_interval=1000.0,
    )

    assert await keys.key_for("gone") is None  # confirmed absent, verdict fresh, keys fresh
    clock.advance(20)
    assert await keys.key_for("gone") is None  # still inside negative_ttl and cache_ttl
    clock.advance(50)  # now past BOTH negative_ttl and cache_ttl, window still shut

    with pytest.raises(AuthServiceUnavailable):
        await keys.key_for("gone")
    assert keys.remembered == 0  # the expired verdict was dropped, not re-served as None


@pytest.mark.anyio
async def test_a_flood_of_unknown_kids_costs_one_fetch_per_window() -> None:
    """The negative cache alone does not bound this - each kid is new, so each one misses
    it. The refetch window is what turns a kid generator into one fetch every ten seconds."""
    clock = Clock()
    keys, transport = client(
        json_reply(KEY_SET), clock=clock, negative_ttl=0.0, refetch_interval=10.0
    )

    for index in range(50):
        assert await keys.key_for(f"flood-{index}") is None
    assert transport.calls == 1

    clock.advance(11)
    assert await keys.key_for("flood-later") is None
    assert transport.calls == 2


@pytest.mark.anyio
async def test_what_the_client_remembers_about_unknown_kids_is_bounded() -> None:
    """Remembering is what stops the flood; remembering without a bound *is* the flood.

    Asserted as an equality rather than a ceiling: a client that remembered nothing would
    also satisfy `<=`, and would be one fetch per unknown kid the moment the window opened.
    """
    clock = Clock()
    keys, transport = client(json_reply(KEY_SET), clock=clock)

    for index in range(MAX_REMEMBERED_MISSES * 3):
        assert await keys.key_for(f"flood-{index}") is None

    assert keys.remembered == MAX_REMEMBERED_MISSES
    assert transport.calls == 1


# --- staleness ------------------------------------------------------------------------


@pytest.mark.anyio
async def test_a_stale_key_set_still_verifies_the_kids_it_carries() -> None:
    """Upstream being unreachable must not log out every user holding a valid token."""
    clock = Clock()
    keys, transport = client(json_reply(KEY_SET), TimeoutError("upstream down"), clock=clock)

    assert await keys.key_for(SIGNER.kid) is not None
    clock.advance(CACHE_TTL + 1)

    assert await keys.key_for(SIGNER.kid) is not None
    assert transport.calls == 2


@pytest.mark.anyio
async def test_a_stale_key_set_never_turns_an_unknown_kid_into_an_accepted_one() -> None:
    """Availability buys the keys we already fetched, and nothing else. A kid we cannot
    confirm is unavailable - not unknown - because a rotation we missed looks the same."""
    clock = Clock()
    keys, _transport = client(json_reply(KEY_SET), TimeoutError("upstream down"), clock=clock)

    await keys.key_for(SIGNER.kid)
    clock.advance(CACHE_TTL + 1)

    with pytest.raises(AuthServiceUnavailable):
        await keys.key_for(ROTATED.kid)


@pytest.mark.anyio
async def test_a_cold_cache_that_cannot_be_filled_is_unavailable() -> None:
    keys, _transport = client(TimeoutError("upstream down"))

    with pytest.raises(AuthServiceUnavailable):
        await keys.key_for(SIGNER.kid)


# --- configuration --------------------------------------------------------------------


@pytest.mark.parametrize("ttl", [0, 1, 59, -1])
def test_a_cache_ttl_below_the_floor_is_refused(ttl: float) -> None:
    """A one-second cache is a fetch per request wearing a cache's name."""
    with pytest.raises(ConfigurationError) as caught:
        client(json_reply(KEY_SET), cache_ttl=ttl)

    assert str(int(MIN_CACHE_TTL)) in str(caught.value)


@pytest.mark.parametrize("ttl", ["300", None, object()], ids=["a-string", "none", "an-object"])
def test_a_cache_ttl_that_is_not_a_number_is_refused(ttl: Any) -> None:
    with pytest.raises(ConfigurationError):
        client(json_reply(KEY_SET), cache_ttl=ttl)


@pytest.mark.parametrize("ttl", [60, 300, 3600])
def test_a_cache_ttl_at_or_above_the_floor_is_accepted(ttl: float) -> None:
    keys, _transport = client(json_reply(KEY_SET), cache_ttl=ttl)

    assert keys.uri.endswith(JWKS_PATH)


def test_a_transport_that_is_not_one_is_refused_at_construction() -> None:
    with pytest.raises(ConfigurationError):
        JwksClient(base_url=ORIGIN, transport=NotATransport(), algorithms=("EdDSA",))  # pyright: ignore[reportArgumentType]
