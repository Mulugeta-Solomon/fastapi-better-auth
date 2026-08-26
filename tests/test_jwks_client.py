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

from typing import Any

import anyio
import anyio.lowlevel
import pytest

from fastapi_better_auth import (
    AuthServiceUnavailable,
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
    JwksClient,
)
from tests.tokens import ORIGIN, Clock, ed25519_signer, key_set, rsa_signer
from tests.transports import NotATransport, Reply, ScriptedTransport, json_reply

SIGNER = ed25519_signer("cached-1")
ROTATED = ed25519_signer("cached-2")
KEY_SET = key_set(SIGNER)


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


# --- the unknown kid ------------------------------------------------------------------


@pytest.mark.anyio
async def test_an_unknown_kid_is_remembered_and_not_fetched_for_again() -> None:
    """Without this, a kid nobody has ever published costs one upstream fetch per request."""
    clock = Clock()
    keys, transport = client(json_reply(KEY_SET), clock=clock, refetch_interval=0.0)

    assert await keys.key_for("never-published") is None
    assert await keys.key_for("never-published") is None
    assert transport.calls == 1


@pytest.mark.anyio
async def test_a_remembered_kid_is_looked_for_again_once_its_ttl_has_passed() -> None:
    clock = Clock()
    keys, transport = client(
        json_reply(KEY_SET), clock=clock, refetch_interval=0.0, negative_ttl=60.0
    )

    assert await keys.key_for(ROTATED.kid) is None
    clock.advance(61)
    assert await keys.key_for(ROTATED.kid) is None
    assert transport.calls == 2


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
