"""Which Better Auth versions this build was driven against, readable at runtime."""

from __future__ import annotations

VERIFIED_BETTER_AUTH: tuple[str, ...] = ("1.6.30", "1.7.1")
"""The Better Auth versions this release was **tested against**, newest last.

Not a support matrix and not a promise: Better Auth publishes no wire-format stability
contract, and the cookie HMAC, the session-store layout and the JWT plugin's claims have all
moved across minor releases. Every version named here is one the conformance suite is actually
run against - the same list the weekly canary sweeps, minus its `latest` entry, which is an
npm dist-tag rather than a version and so names something different every week. A version
absent from this tuple is untested here, which is not the same as broken.

**Advisory, and it can only ever be advisory.** Nothing in Modes A or B has a path to the
version the Node process is really running: Mode A reads a database or a Redis key, Mode B
verifies offline against a cached key set, and neither asks the server anything. So this
answers "what was this build verified against?" and never "what is deployed?". What it is for
is the other half of that comparison - log it at startup beside the Better Auth version your
own deployment pins, and a bump that outran this library shows up in a boot log and in code
review rather than in a support ticket:

    logger.info("better-auth verified against %s", VERIFIED_BETTER_AUTH)

`tests/test_verified_better_auth.py` keeps it equal to the canary workflow's matrix, a
superset of every version COMPATIBILITY.md's better-auth table names, and inclusive of the
conformance harness's own pin, so the four cannot be edited out of sync.
"""
