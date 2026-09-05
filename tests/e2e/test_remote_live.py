"""Mode C against the real thing: a cookie verified by asking the Better Auth server itself.

The unit lane proves the whole outcome table against a scripted transport - a socket this
repository wrote both ends of. This lane closes the gap that leaves: a cookie issued by a running
Better Auth, carried through a real FastAPI request, forwarded to that same server's
`get-session`, and answered by it. Both storage topologies run wherever the property exists in
both, because `:3100` keeps sessions in Postgres and `:3101` keeps them in Redis and may never
write the Postgres row at all.

The headline is leg 2: signing out on the Node side must make the very next request a 401.
`disableCookieCache=true` is what makes that hold, and it is the property Mode B cannot have.

Three legs are absences rather than answers, and a status code cannot see an absence - the
refusal is the same 401 either way. They are measured at the boundary with
`tests/e2e/counting.py::CountingTransport`, which wraps the shipped `HttpxTransport` and counts:
a repeated forged cookie must cost no second upstream call (the negative cache), a cross-site
write must cost none at all (CSRF runs before the fetch), and a verifier upstream has answered
`429` must stop calling entirely (the backoff latch).

Two harness postures exist only for this lane. `:3102` runs `bearer({ requireSignature: true })`
and is exercised in `test_conformance.py`; `:3103` runs an explicit
`rateLimit: { customRules: { "/get-session": { window: 10, max: 3 } } }`, which is what makes the
live 429 leg possible without `NODE_ENV=production` - that would also flip the cookie name to
`__Secure-` over http and quietly turn this into a different server.

Asyncio only. The anyio primitives Mode C uses - the probe lock and the capacity limiter - are
proven on both backends in the unit lane; what is new here is the live server, not the loop, and
one live pass is enough of it.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import secrets
import urllib.parse
from typing import Any, cast

import anyio
import httpx
import pytest
from fastapi import Depends, FastAPI

from fastapi_better_auth import (
    AuthServiceUnavailable,
    BetterAuth,
    ConfigurationError,
    HttpxTransport,
    InvalidCredential,
    Session,
    SessionRevoked,
    SharedSecret,
    Transport,
    User,
)
from fastapi_better_auth._internal.jwt_verifier import JwtVerifier
from tests.fakes import connection, session_app

from .conftest import (
    ADMIN_EMAIL,
    ADMIN_PASSWORD,
    HARNESS_SECRET,
    PASSWORD,
    SEED_EMAIL,
    SEED_PASSWORD,
    SESSION_COOKIE,
    THROTTLE_MAX,
    THROTTLE_WINDOW_SECONDS,
    admin_post,
    harness_sql,
    raw_token,
    sign_in,
    sign_out,
    sign_up,
)

try:
    # Every name Mode C added after 0.1.0 belongs in here, not above: the canary's
    # published-wheel leg installs the last release, and one unguarded post-release import
    # raises before this guard is reached, killing the lane it exists to keep green.
    from fastapi_better_auth import (
        CsrfDisabled,
        OriginCheck,
        RemoteVerifier,
        StoredSession,
        StoredUser,
    )
    from fastapi_better_auth._internal.cookie_verifier import CookieVerifier
    from fastapi_better_auth._internal.remote_response import DEFAULT_BACKOFF

    from .counting import CountingTransport
except ImportError:
    pytest.skip(
        "this build of fastapi-better-auth-bridge publishes no remote mode",
        allow_module_level=True,
    )

pytestmark = pytest.mark.e2e

COOKIE_SCHEME = "BetterAuthCookie-better-auth.session_token"
BEARER_SCHEME = "BetterAuthBearer"
CSRF_REASON = "a GET carries no CSRF risk; the rung is unit-tested"
PROBE_CALLS = 2
"""What `prepare()` costs: the bare null-contract request, and the advisory bearer one."""
DOCUMENT_BYTES = 64 * 1024
RETRY_AFTER_RANGE = range(THROTTLE_WINDOW_SECONDS - 1, THROTTLE_WINDOW_SECONDS + 1)
"""What a live 429's `X-Retry-After` can read: upstream computes ceil(window - time since the
last ALLOWED request), so a slow runner reads one less than a fast one. Never the default."""
assert DEFAULT_BACKOFF not in RETRY_AFTER_RANGE, "the range would hide a parser that read no header"


def backing_off(reason: str) -> int:
    """The seconds a 429 refusal reason says it is backing off for."""
    found = re.search(r"backing off (\d+)s", reason)
    assert found is not None, reason
    return int(found.group(1))


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(params=["postgres", "redis"])
def topology(request: pytest.FixtureRequest) -> str:
    """Both storage truths. Resolved lazily, so a profile that is down skips only its own leg."""
    name = "harness" if request.param == "postgres" else "redis_harness"
    return cast("str", request.getfixturevalue(name))


class EmptyStore:
    """A `SessionStore` that answers nothing. Leg 12 refuses before a lookup could happen."""

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        return None

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        return None


def build(base: str, transport: Transport | None = None) -> RemoteVerifier:
    """The verifier every leg uses: the live server, http, the plain cookie name."""
    return RemoteVerifier(
        base_url=base,
        csrf=CsrfDisabled(reason=CSRF_REASON),
        transport=transport,
        secure_cookies=False,
    )


def cookie_header(cookie: str) -> dict[str, str]:
    """The raw Cookie header the verifier reads - not httpx's jar, which re-encodes."""
    return {"Cookie": f"{SESSION_COOKIE}={cookie}"}


def forged() -> str:
    """A structurally plausible cookie that names no session, distinct on every call.

    Distinct matters: the negative cache is keyed on the whole cookie value, so reusing one
    would make a leg that means to spend an upstream call quietly spend nothing.
    """
    token = secrets.token_hex(16)
    signature = base64.b64encode(secrets.token_bytes(32)).decode()
    return urllib.parse.quote(f"{token}.{signature}")


def tampered(cookie: str) -> str:
    """The same cookie with one signature byte flipped: a token that exists, over a signature
    that never signed it."""
    token, _, signature = urllib.parse.unquote(cookie).rpartition(".")
    flipped = ("A" if signature[0] != "A" else "B") + signature[1:]
    return urllib.parse.quote(f"{token}.{flipped}")


async def drive(app: FastAPI, **request: Any) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://bridge"
    ) as client:
        return await client.get("/required", **request)


def write_app(auth: BetterAuth) -> FastAPI:
    """One POST route, so the CSRF rung is reachable at all: a GET carries no CSRF risk."""
    app = FastAPI()
    required = auth.current_session()

    async def write(session: Session[User] = Depends(required)) -> dict[str, Any]:
        return {"id": session.user.id}

    app.add_api_route("/write", write, methods=["POST"])
    return app


async def post(app: FastAPI, origin: str, cookie: str) -> httpx.Response:
    headers = {**cookie_header(cookie), "Origin": origin}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://bridge"
    ) as client:
        return await client.post("/write", headers=headers)


async def fetch(url: str, **request: Any) -> httpx.Response:
    """A direct read of the live server, beside whatever the verifier is doing."""
    async with httpx.AsyncClient() as client:
        return await client.get(url, **request)


async def upstream_user_id(base: str, cookie: str) -> str:
    """Who upstream says this cookie is, read straight off the server, for the equality check."""
    resp = await fetch(f"{base}/api/auth/get-session", headers=cookie_header(cookie))
    assert resp.status_code == 200, resp.text
    identifier: str = resp.json()["user"]["id"]
    return identifier


class TestLiveSession:
    """Legs 1-3: the cookie a real Better Auth issued - accepted, revoked, and tampered with."""

    @pytest.mark.anyio
    async def test_a_live_cookie_authenticates_a_real_route(self, topology: str) -> None:
        cookie = sign_in(topology, SEED_EMAIL, SEED_PASSWORD)
        expected = await upstream_user_id(topology, cookie)

        async with HttpxTransport() as transport:
            app = session_app(BetterAuth(verifiers=[build(topology, transport)]))
            authorized = await drive(app, headers=cookie_header(cookie))
            anonymous = await drive(app)

        assert authorized.status_code == 200, authorized.text
        assert authorized.json()["id"] == expected
        assert anonymous.status_code == 401
        sign_out(topology, cookie)

    @pytest.mark.anyio
    async def test_signing_out_upstream_makes_the_next_request_401(self, topology: str) -> None:
        """The headline. `disableCookieCache=true` forces the authoritative read, so the cookie
        that authenticated a moment ago is refused the instant the Node side deletes the session -
        with no shared database, no shared Redis and no shared secret."""
        cookie = sign_in(topology, SEED_EMAIL, SEED_PASSWORD)

        async with HttpxTransport() as transport:
            app = session_app(BetterAuth(verifiers=[build(topology, transport)]))
            before = await drive(app, headers=cookie_header(cookie))
            sign_out(topology, cookie)
            after = await drive(app, headers=cookie_header(cookie))

        assert before.status_code == 200, before.text
        assert after.status_code == 401

    @pytest.mark.anyio
    async def test_a_tampered_signature_is_refused(self, topology: str) -> None:
        """No secret is configured here, so the refusal is upstream's: the cookie reaches
        get-session, `getSignedCookie` fails, and `200 null` comes back."""
        cookie = sign_in(topology, SEED_EMAIL, SEED_PASSWORD)

        async with HttpxTransport() as transport:
            app = session_app(BetterAuth(verifiers=[build(topology, transport)]))
            refused = await drive(app, headers=cookie_header(tampered(cookie)))

        assert refused.status_code == 401
        sign_out(topology, cookie)


class TestZeroOutbound:
    """Legs 4 and 7: the two properties that are absences on the wire, counted at the boundary."""

    @pytest.mark.anyio
    async def test_a_repeated_forgery_costs_exactly_one_upstream_call(self, topology: str) -> None:
        """The negative cache against the real server. Both requests are 401; only the first is
        allowed to cost anything, and that is the whole point - a forged-cookie flood collapses
        to one get-session call per TTL window instead of one per request."""
        garbage = forged()

        async with HttpxTransport() as inner:
            counting = CountingTransport(inner)
            verifier = build(topology, counting)
            await verifier.prepare()
            probed = counting.calls
            app = session_app(BetterAuth(verifiers=[verifier]))

            first = await drive(app, headers=cookie_header(garbage))
            after_first = counting.calls
            second = await drive(app, headers=cookie_header(garbage))
            after_second = counting.calls

        assert probed == PROBE_CALLS, "the boot probe is one bare request and one advisory one"
        assert first.status_code == 401
        assert second.status_code == 401
        assert after_first == probed + 1, "the first forgery is the one that asks upstream"
        assert after_second == after_first, "the repeat was answered from the negative cache"
        assert counting.posts == 0, "get-session is a GET; a POST here would be a bug"

    @pytest.mark.anyio
    async def test_a_cross_site_write_is_403_before_any_upstream_call(self, harness: str) -> None:
        """CSRF sits before the fetch and before the readiness probe, so a cross-site request
        that carries a genuinely valid cookie never reaches the network at all. The same-origin
        write is the anti-vacuum control: it is a 200 only because the cookie really works, so
        the 403 is the CSRF rung refusing and not a broken credential answering 401.

        One topology is the whole proof - the rung runs before anything storage-shaped.
        """
        allowed = "https://app.example.com"
        cookie = sign_in(harness, SEED_EMAIL, SEED_PASSWORD)

        async with HttpxTransport() as inner:
            counting = CountingTransport(inner)
            auth = BetterAuth(
                verifiers=[
                    RemoteVerifier(
                        base_url=harness,
                        csrf=OriginCheck(allowed_origins=[allowed]),
                        transport=counting,
                        secure_cookies=False,
                    )
                ]
            )
            app = write_app(auth)
            cross_site = await post(app, "https://evil.example.com", cookie)
            blocked = counting.calls
            same_site = await post(app, allowed, cookie)

        assert cross_site.status_code == 403, cross_site.text
        assert cross_site.json() == {"detail": "Forbidden"}
        assert blocked == 0, "a cross-site request must never reach get-session"
        assert same_site.status_code == 200, same_site.text
        sign_out(harness, cookie)


class TestUpstreamState:
    """Legs 5, 6a and 6b: the three ways a session that still parses is no longer a session."""

    @pytest.mark.anyio
    async def test_a_database_expired_session_is_refused(self, harness: str) -> None:
        """Postgres topology only, and the topology is the reason. With `secondaryStorage`
        configured upstream never writes the Postgres session row at all, and the Redis entry
        carries a TTL equal to the session lifetime - so an expired session there is not an
        expired row, it is an absent key, which leg 2 already covers.

        Upstream checks `expiresAt` at the route layer right after `findSession`, so this comes
        back as `200 null` and the bridge refuses it before its own expiry check is reached.
        """
        cookie = sign_in(harness, SEED_EMAIL, SEED_PASSWORD)
        token = raw_token(cookie)

        async with HttpxTransport() as transport:
            app = session_app(BetterAuth(verifiers=[build(harness, transport)]))
            before = await drive(app, headers=cookie_header(cookie))
            harness_sql(
                f"""UPDATE session SET "expiresAt" = now() - interval '1 hour'"""
                f""" WHERE token = '{token}'"""
            )
            after = await drive(app, headers=cookie_header(cookie))

        assert before.status_code == 200, before.text
        assert after.status_code == 401

    @pytest.mark.anyio
    async def test_a_database_direct_ban_is_refused_by_this_library(self, harness: str) -> None:
        """The ban leg that proves the bridge and not upstream. Written straight to the column
        rather than through the admin endpoint, because that endpoint also deletes the user's
        sessions - which would make this pass for the wrong reason, as leg 2 all over again.
        Upstream's `get-session` never reads `banned`, so it answers a complete session document
        carrying `banned: true`, and the 401 is this library enforcing what upstream does not.

        A freshly signed-up user, never the seed one, and the column is restored either way.
        """
        victim, email = sign_up(harness, "remote-banned")
        cookie = sign_in(harness, email, PASSWORD)
        try:
            async with HttpxTransport() as transport:
                verifier = build(harness, transport)
                app = session_app(BetterAuth(verifiers=[verifier]))
                before = await drive(app, headers=cookie_header(cookie))
                harness_sql(
                    f"""UPDATE "user" SET banned = true, "banReason" = 'conformance'"""
                    f""" WHERE id = '{victim}'"""
                )
                answered = await fetch(
                    f"{harness}/api/auth/get-session", headers=cookie_header(cookie)
                )
                after = await drive(app, headers=cookie_header(cookie))
                credential = verifier.extract(connection(cookie=f"{SESSION_COOKIE}={cookie}"))
                assert credential is not None
                with pytest.raises(SessionRevoked) as refusal:
                    await verifier.verify(credential, User)
        finally:
            harness_sql(
                f"""UPDATE "user" SET banned = false, "banReason" = NULL WHERE id = '{victim}'"""
            )

        assert before.status_code == 200, before.text
        assert answered.json()["user"]["banned"] is True, "upstream still answers a session"
        assert after.status_code == 401
        assert "banned" in refusal.value.reason

    @pytest.mark.anyio
    async def test_on_secondary_storage_only_the_admin_route_ban_is_visible(
        self, redis_harness: str
    ) -> None:
        """The ban path an operator on `secondaryStorage` actually has, and the one they do not.

        With sessions in Redis the user document lives inside the session value, so a ban written
        straight to the Postgres column is invisible to `findSession` - asserted here rather than
        described, because it is a deployment hazard and not a detail. The admin endpoint is the
        supported path: it deletes the user's sessions, and the very next request is a 401.

        A freshly signed-up user, never the seed one, and the column is restored either way.
        """
        victim, email = sign_up(redis_harness, "remote-banned-redis")
        cookie = sign_in(redis_harness, email, PASSWORD)
        admin = sign_in(redis_harness, ADMIN_EMAIL, ADMIN_PASSWORD)
        try:
            async with HttpxTransport() as transport:
                app = session_app(BetterAuth(verifiers=[build(redis_harness, transport)]))
                before = await drive(app, headers=cookie_header(cookie))
                harness_sql(f"""UPDATE "user" SET banned = true WHERE id = '{victim}'""")
                invisible = await drive(app, headers=cookie_header(cookie))
                banned = admin_post(
                    redis_harness,
                    "ban-user",
                    {"userId": victim, "banReason": "conformance"},
                    admin,
                )
                after = await drive(app, headers=cookie_header(cookie))
        finally:
            harness_sql(
                f"""UPDATE "user" SET banned = false, "banReason" = NULL WHERE id = '{victim}'"""
            )
            sign_out(redis_harness, admin)

        assert before.status_code == 200, before.text
        assert invisible.status_code == 200, "a database ban does not reach secondary storage"
        assert banned.status_code == 200, banned.text
        assert after.status_code == 401


class TestComposition:
    """Legs 8, 9 and 12: Mode C beside Mode B, in the document, and never beside Mode A."""

    def build(self, base: str, transport: Transport) -> BetterAuth:
        return BetterAuth(
            verifiers=[
                JwtVerifier(base_url=base, transport=transport),
                RemoteVerifier(
                    base_url=base,
                    csrf=OriginCheck(allowed_origins=[base]),
                    transport=transport,
                    secure_cookies=False,
                ),
            ]
        )

    @pytest.mark.anyio
    async def test_bearer_alone_cookie_alone_and_both_at_once(self, harness: str) -> None:
        cookie = sign_in(harness, SEED_EMAIL, SEED_PASSWORD)
        issued = await fetch(f"{harness}/api/auth/token", headers=cookie_header(cookie))
        assert issued.status_code == 200, issued.text
        bearer = issued.json()["token"]

        async with HttpxTransport() as transport:
            app = session_app(self.build(harness, transport))
            bearer_only = await drive(app, headers={"Authorization": f"Bearer {bearer}"})
            cookie_only = await drive(app, headers=cookie_header(cookie))
            both = await drive(
                app, headers={"Authorization": f"Bearer {bearer}", **cookie_header(cookie)}
            )

        assert bearer_only.status_code == 200, bearer_only.text
        assert cookie_only.status_code == 200, cookie_only.text
        assert both.status_code == 400, "two credentials at once must be AmbiguousCredentials"
        assert bearer_only.json()["id"] == cookie_only.json()["id"]
        sign_out(harness, cookie)

    @pytest.mark.anyio
    async def test_the_document_declares_the_two_schemes_as_alternatives(
        self, harness: str
    ) -> None:
        """Ruling 11, on the wire: OpenAPI reads `security` as OR only when it is a list of
        single-key requirement objects. A `declaring()` that folded both schemes into one object
        would publish an AND - and would still satisfy a test that flattens the names into a set,
        which is what the assertion here used to be. The length and arity checks catch it."""
        async with HttpxTransport() as transport:
            app = session_app(self.build(harness, transport))
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://bridge"
            ) as client:
                document = (await client.get("/openapi.json")).json()
                docs = await client.get("/docs")

        schemes = document["components"]["securitySchemes"]
        assert schemes[BEARER_SCHEME]["type"] == "http"
        assert schemes[COOKIE_SCHEME]["type"] == "apiKey"
        assert schemes[COOKIE_SCHEME]["in"] == "cookie"
        assert schemes[COOKIE_SCHEME]["name"] == SESSION_COOKIE
        declared = document["paths"]["/required"]["get"]["security"]
        assert len(declared) == 2
        assert all(len(requirement) == 1 for requirement in declared), "an AND fold merged them"
        assert {name for requirement in declared for name in requirement} == {
            BEARER_SCHEME,
            COOKIE_SCHEME,
        }
        assert docs.status_code == 200

    def test_mode_a_and_mode_c_on_one_cookie_are_refused_at_construction(
        self, harness: str
    ) -> None:
        """Both read the same cookie under the same name, so both declare the same
        `credential_source` and every request carrying it would be ambiguous. Mode A and Mode C
        are a choice, not a stack, and the collision check already there says so."""
        with pytest.raises(ConfigurationError) as refusal:
            BetterAuth(
                verifiers=[
                    CookieVerifier(
                        secret=SharedSecret(HARNESS_SECRET),
                        store=EmptyStore(),
                        csrf=CsrfDisabled(reason=CSRF_REASON),
                        secure_cookies=False,
                    ),
                    build(harness),
                ]
            )

        assert "two verifiers on one credential" in str(refusal.value)
        assert f"cookie:{SESSION_COOKIE}" in str(refusal.value)


class TestProbe:
    """Legs 10 and 11: what the boot probe proves against a live deployment."""

    @pytest.mark.anyio
    async def test_the_probe_passes_against_a_live_deployment(self, topology: str) -> None:
        async with HttpxTransport() as transport:
            await build(topology, transport).probe()

    @pytest.mark.anyio
    async def test_a_wrong_base_path_refuses_at_startup_and_names_the_uri(
        self, harness: str
    ) -> None:
        """The single most common misconfiguration, and the one the probe exists to catch before
        the deployment takes traffic rather than on its first authenticated request."""
        async with HttpxTransport() as transport:
            wrong = RemoteVerifier(
                base_url=harness,
                csrf=CsrfDisabled(reason=CSRF_REASON),
                transport=transport,
                secure_cookies=False,
                base_path="/api/nope",
            )
            with pytest.raises(ConfigurationError) as refusal:
                await wrong.prepare()

        assert wrong.uri in str(refusal.value)
        assert "base_path=" in str(refusal.value)

    @pytest.mark.anyio
    async def test_the_transport_never_keeps_a_cookie_upstream_sets(self, harness: str) -> None:
        """The dead-jar rule, live, against a response that really carries a session cookie.

        The verifier's own requests never receive one - `disableRefresh=true` is pinned - so a
        leg that forwards a cookie and then asks bare proves nothing: a live jar had nothing to
        keep, and the leg stayed green with the dead-jar policy deleted. Here the session is aged
        past `updateAge`, so a plain get-session through the SAME transport makes upstream refresh
        it and re-set the cookie, and that `Set-Cookie` is asserted present. A live jar would store
        it and answer the bare request that follows as the seed user; the probe's own dead-jar rung
        would then raise. Postgres topology, because the row is what ages.
        """
        cookie = sign_in(harness, SEED_EMAIL, SEED_PASSWORD)
        token = raw_token(cookie)

        async with HttpxTransport() as transport:
            verifier = build(harness, transport)
            app = session_app(BetterAuth(verifiers=[verifier]))
            authorized = await drive(app, headers=cookie_header(cookie))
            # expiresIn 7 d and updateAge 1 d upstream: a refresh is due once expiresAt <= now + 6 d.
            harness_sql(
                f"""UPDATE session SET "expiresAt" = now() + interval '5 days'"""
                f""" WHERE token = '{token}'"""
            )
            refreshed = await transport.get(
                f"{harness}/api/auth/get-session",
                headers={"accept": "application/json", "cookie": f"{SESSION_COOKIE}={cookie}"},
                max_bytes=DOCUMENT_BYTES,
            )
            bare = await transport.get(
                f"{harness}/api/auth/get-session",
                headers={"accept": "application/json"},
                max_bytes=DOCUMENT_BYTES,
            )
            await verifier.probe()

        assert authorized.status_code == 200, authorized.text
        assert refreshed.status_code == 200
        assert json.loads(refreshed.content) is not None, "the aged session should still verify"
        assert "set-cookie" in refreshed.headers, "no refresh: the jar was never offered a cookie"
        assert json.loads(bare.content) is None, "a bare request was answered as somebody"
        sign_out(harness, cookie)


class TestRateLimited:
    """Leg 13: the 429 path, against a server that really rate-limits.

    Driven through `verify()` rather than a route, because the two things being pinned - which
    refusal, and with what reason - are deliberately invisible on the wire: every one of these is
    the same 401 to a client. The reason is also where `X-Retry-After` shows up, and the header
    name is the point. Upstream sends `X-Retry-After` and not `Retry-After`, so a parser that read
    only the standard name would fall back to the five-second default and this leg would read
    `backing off 5s`.

    Two window-length waits bracket the probe, so the leg starts from a bucket whose state it
    knows. Upstream keys the bucket on the last request it allowed (a refused one leaves it
    untouched), so a window only clears after that many seconds without an allowed request.
    """

    async def refuse(self, verifier: RemoteVerifier) -> BaseException:
        """One verification of a fresh forgery, returning whatever it refused with."""
        credential = verifier.extract(connection(cookie=f"{SESSION_COOKIE}={forged()}"))
        assert credential is not None
        try:
            await verifier.verify(credential, User)
        except (InvalidCredential, AuthServiceUnavailable) as refusal:
            return refusal
        raise AssertionError("a forged cookie was accepted")

    @pytest.mark.anyio
    async def test_a_real_429_refuses_and_latches_with_no_further_calls(
        self, throttled_harness: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="fastapi_better_auth"):
            async with HttpxTransport() as inner:
                counting = CountingTransport(inner)
                verifier = build(throttled_harness, counting)
                await anyio.sleep(THROTTLE_WINDOW_SECONDS)
                await verifier.prepare()
                probed = counting.calls
                await anyio.sleep(THROTTLE_WINDOW_SECONDS)

                allowed = [await self.refuse(verifier) for _ in range(THROTTLE_MAX)]
                limited = await self.refuse(verifier)
                after_limit = counting.calls
                raw = await fetch(f"{throttled_harness}/api/auth/get-session")
                latched = await self.refuse(verifier)
                after_latch = counting.calls

        assert probed == PROBE_CALLS
        assert all(isinstance(refusal, InvalidCredential) for refusal in allowed), allowed
        assert after_limit == probed + THROTTLE_MAX + 1, "every verification asked exactly once"

        assert isinstance(limited, AuthServiceUnavailable)
        assert "rate-limited upstream (429)" in limited.reason
        # The live proof of the parse: upstream names the wait in X-Retry-After only, and the
        # reason carries that header's number rather than the no-header default.
        assert raw.status_code == 429
        assert raw.headers.get("retry-after") is None, "upstream sends only the X- spelling"
        assert int(raw.headers["x-retry-after"]) in RETRY_AFTER_RANGE
        assert backing_off(limited.reason) in RETRY_AFTER_RANGE

        assert isinstance(latched, AuthServiceUnavailable)
        assert "backing off after a recent rate-limit (429)" in latched.reason
        assert after_latch == after_limit, "a latched verifier makes no outbound call at all"
        assert counting.posts == 0
        backoffs = [
            record.getMessage() for record in caplog.records if "backing off" in record.getMessage()
        ]
        assert len(backoffs) == 1, "the latch warns once, not once per refused request"
