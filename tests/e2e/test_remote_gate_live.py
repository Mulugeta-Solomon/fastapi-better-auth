"""The Mode C bearer gate against two live Better Auth servers, one in each posture.

`refuse_unsigned_bearer=True` turns the probe's advisory bearer rung into a refusing one, and the
whole point of the flag is that a deployment stops rather than starts. That is a claim about a
*live* server's configuration, so a scripted double cannot settle it: the unit lane proves the
mapping, this lane proves the two postures a real `bearer()` plugin actually produces.

`:3100` is the permissive default (`requireSignature: false`) and must refuse `prepare()`;
`:3102` is the same image with `requireSignature: true` and must pass it, silently. The
discriminator either way is whether a `Set-Cookie` came back for one manufactured random token —
never its value, never a real credential — which `test_conformance.py::TestBearerPosture` pins on
the wire independently of this library.

Its own module, not a leg of `test_remote_live.py`: `refuse_unsigned_bearer` is a post-0.3.0
keyword, and a module that mentions it must skip on the published wheel rather than raise.

Asyncio only. The gate adds no concurrency of its own; the probe lock it runs under is proven on
both backends in the unit lane.
"""

from __future__ import annotations

import inspect
import logging

import pytest

from fastapi_better_auth import ConfigurationError, HttpxTransport

try:
    # Every name Mode C added after 0.1.0 belongs in here, not above: the canary's
    # published-wheel leg installs the last release, and one unguarded post-release import
    # raises before this guard is reached, killing the lane it exists to keep green.
    from fastapi_better_auth import CsrfDisabled, RemoteVerifier
except ImportError:
    pytest.skip(
        "this build of fastapi-better-auth-bridge publishes no remote mode",
        allow_module_level=True,
    )

if "refuse_unsigned_bearer" not in inspect.signature(RemoteVerifier.__init__).parameters:
    # Added after 0.3.0. A wheel whose RemoteVerifier predates the keyword cannot run this module;
    # the honest answer is the same skip as a missing name, not a TypeError (D-256).
    pytest.skip(
        "this build of fastapi-better-auth-bridge predates refuse_unsigned_bearer"
        " (added after 0.3.0)",
        allow_module_level=True,
    )

pytestmark = [pytest.mark.e2e, pytest.mark.anyio]

CSRF_REASON = "the probe carries no request at all; the rung is unit-tested"
UPSTREAM_FIX = "bearer({ requireSignature: true })"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def gated(base: str, transport: HttpxTransport) -> RemoteVerifier:
    """The live verifier every leg uses, with the gate on."""
    return RemoteVerifier(
        base_url=base,
        csrf=CsrfDisabled(reason=CSRF_REASON),
        transport=transport,
        secure_cookies=False,
        refuse_unsigned_bearer=True,
    )


async def test_the_gate_refuses_a_permissive_server_at_startup(
    harness: str, caplog: pytest.LogCaptureFixture
) -> None:
    """`:3100` mounts `bearer({ requireSignature: false })`, so startup must not complete."""
    with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
        async with HttpxTransport() as transport:
            verifier = gated(harness, transport)
            with pytest.raises(ConfigurationError) as refusal:
                await verifier.prepare()

    message = str(refusal.value)
    assert UPSTREAM_FIX in message, "the refusal must name the one-line upstream fix"
    assert verifier.uri in message
    assert not [r for r in caplog.records if "requireSignature" in r.getMessage()], (
        "the gate refuses; it does not also emit the advisory warning"
    )


async def test_the_gate_passes_a_strict_server_silently(
    strict_harness: str, caplog: pytest.LogCaptureFixture
) -> None:
    """`:3102` is the same image with `requireSignature: true`: `prepare()` returns and says
    nothing. The anti-vacuum control for the leg above — the refusal there is the posture and not
    the flag, because the flag alone refuses nothing here."""
    with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
        async with HttpxTransport() as transport:
            verifier = gated(strict_harness, transport)
            await verifier.prepare()

    assert verifier.refuse_unsigned_bearer is True
    assert not caplog.records, "a strict server passes the gate and logs nothing"
