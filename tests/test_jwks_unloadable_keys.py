"""A key entry this library cannot load costs that key, not the whole key set.

Better Auth serves several keys during a rotation, and an operator can configure other algorithms
upstream, so one entry with an unsupported curve, a mismatched key type or broken material is a
fact about that entry. It is skipped, with one warning per refresh naming it by a sanitized `kid`
and never by its material, and the rest of the set serves; a token naming it is refused like any
unknown `kid`. Only a document in which *no* key loads is a failed refresh, as before.

Entries skipped for what they declare (`use`, `key_ops`, an undersized RSA modulus) are
`test_jwks_client.py`'s; this file is the load failures.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from fastapi_better_auth import AuthServiceUnavailable, InvalidCredential, User
from fastapi_better_auth._internal.jwks import CACHE_TTL
from fastapi_better_auth._internal.reasons import REDACTED
from tests.jwks_fixtures import ROTATED, SIGNER, client, wind_jwks_clock
from tests.jwt_fixtures import SIGNER as TOKEN_SIGNER
from tests.jwt_fixtures import build
from tests.tokens import Clock, claims, ed25519_signer
from tests.transports import json_reply

LIBRARY_LOGGER = "fastapi_better_auth"
SKIP_PREFIX = "jwks key %s is not usable"
PRIVATE_MATERIAL = "Zt7Qv1oXbK4mPr9wCyHnLdEuAsJf2Ng6"
"""Stands in for a private half a broken upstream mispublished in the very entry it complains of."""


def _skips(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        record
        for record in caplog.records
        if record.name == LIBRARY_LOGGER and str(record.msg).startswith(SKIP_PREFIX)
    ]


def _broken(kid: str, **fields: Any) -> dict[str, Any]:
    """An entry under an allowed `alg` whose key will not load, with `fields` set on it."""
    return {**dict(ed25519_signer(kid).jwk), **fields}


UNLOADABLE: tuple[tuple[str, dict[str, Any]], ...] = (
    ("broken-material", _broken("bad-1", x="not-base64url-material")),
    ("unsupported-crv", _broken("bad-1", crv="P-256")),
    ("kty-mismatch", _broken("bad-1", kty="EC")),
    ("no-material", {k: v for k, v in _broken("bad-1").items() if k != "x"}),
)


@pytest.mark.anyio
@pytest.mark.parametrize(("label", "entry"), UNLOADABLE, ids=[name for name, _ in UNLOADABLE])
async def test_an_unloadable_key_is_skipped_and_the_rest_of_the_set_serves(
    label: str, entry: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    """F4.3. RED before the fix: the one entry that would not load failed the whole refresh,
    an outage for every token although its sibling was fine."""
    keys, _transport = client(json_reply({"keys": [entry, dict(SIGNER.jwk)]}))

    found = await keys.key_for(SIGNER.kid)

    assert found is not None and found.kid == SIGNER.kid
    assert await keys.key_for("bad-1") is None
    assert len(_skips(caplog)) == 1
    assert _skips(caplog)[0].levelno == logging.WARNING


@pytest.mark.anyio
async def test_a_set_in_which_no_key_loads_is_a_failed_refresh() -> None:
    """Every entry broken is a corrupt key set, not an empty one: answering "unknown kid"
    would send the operator hunting for a rotation that already happened."""
    keys, _transport = client(
        json_reply({"keys": [_broken("bad-1", x="!!"), _broken("bad-2", crv="P-256")]})
    )

    with pytest.raises(AuthServiceUnavailable):
        await keys.key_for("bad-1")


@pytest.mark.anyio
async def test_a_set_whose_only_other_entries_are_declared_away_still_fails_on_a_broken_one() -> (
    None
):
    """An entry skipped for what it declares is not a key that loaded: a set of one broken key
    and one `use: "enc"` key has no key to answer from, and is a failed refresh."""
    enc = {**dict(ROTATED.jwk), "use": "enc"}
    keys, _transport = client(json_reply({"keys": [_broken("bad-1", x="!!"), enc]}))

    with pytest.raises(AuthServiceUnavailable):
        await keys.key_for(ROTATED.kid)


@pytest.mark.anyio
async def test_an_unloadable_key_is_reported_once_per_refresh(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The parse happens once per fetch, so the line does too - never once per lookup."""
    clock = Clock()
    keys, transport = client(
        json_reply({"keys": [_broken("bad-1", x="!!"), dict(SIGNER.jwk)]}), clock=clock
    )

    for _ in range(5):
        assert await keys.key_for("bad-1") is None
    assert len(_skips(caplog)) == 1

    clock.advance(CACHE_TTL + 1)
    assert await keys.key_for(SIGNER.kid) is not None
    assert transport.calls == 2
    assert len(_skips(caplog)) == 2


@pytest.mark.anyio
async def test_an_unloadable_key_is_named_by_a_safe_label_and_never_by_its_material(
    caplog: pytest.LogCaptureFixture,
) -> None:
    hostile = 'bad"\n2026-01-01 CRITICAL root logged in'
    entry = {**_broken("ignored", x="!!", d=PRIVATE_MATERIAL), "kid": hostile}
    keys, _transport = client(json_reply({"keys": [entry, dict(SIGNER.jwk)]}))

    assert await keys.key_for(SIGNER.kid) is not None
    written = "\n".join(record.getMessage() for record in _skips(caplog))
    assert REDACTED in written
    assert "CRITICAL" not in written
    assert PRIVATE_MATERIAL not in written
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.anyio
async def test_a_broken_first_entry_does_not_claim_its_kid_from_a_loadable_duplicate() -> None:
    """Duplicate kids, as the client resolves them: the first entry that *loads* under a kid
    wins (a skipped entry - declared away or, now, unloadable - claims nothing). Pinned so a
    change to it is a decision, not an accident; the loaded key is the second entry's."""
    shadow = dict(ROTATED.jwk)
    shadow["kid"] = SIGNER.kid
    keys, _transport = client(json_reply({"keys": [_broken(SIGNER.kid, x="!!"), shadow]}))

    found = await keys.key_for(SIGNER.kid)

    assert found is not None
    assert found.jwk["x"] == ROTATED.jwk["x"]


# --- through the verifier ---------------------------------------------------------------


@pytest.mark.anyio
async def test_a_token_naming_an_unloadable_key_is_refused_as_an_unknown_kid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refused like any unknown kid - a credential refusal, negative-cached, no second fetch -
    while a token signed by the sibling key verifies from the same document."""
    wind_jwks_clock(monkeypatch)
    broken = _broken("wp40-broken", x="!!")
    verifier, transport = build(json_reply({"keys": [broken, dict(TOKEN_SIGNER.jwk)]}))
    named = ed25519_signer("wp40-broken").sign(claims())

    assert (await verifier.verify(TOKEN_SIGNER.sign(claims()), User)).user.id == claims()["sub"]
    for _ in range(3):
        with pytest.raises(InvalidCredential):
            await verifier.verify(named, User)
    assert transport.calls == 1
