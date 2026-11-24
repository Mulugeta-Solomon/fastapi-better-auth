# The verified session

After reading this page you know what a `Session` carries in each mode, and you can forward the
signed-in user's session to a Better Auth route such as `/revoke-session`.

## What a verified session carries

Beside `user`, `expires_at`, `token`, `impersonated_by` and `raw`, a `Session` carries three facts
the verifier established while it checked the request. Which mode verified it decides whether each
one is set:

| Field | Mode A — cookie + store | Mode B — JWT | Mode C — remote get-session |
|---|---|---|---|
| `id` | the stored session's `id` | `None`, always | the `id` get-session returned, when it carries one |
| `cookie` | the `(name, value)` it accepted | `None` | the `(name, value)` it forwarded |
| `origin` | the `allowed_origins` entry the CSRF check matched, on an unsafe method or a WebSocket handshake | `None` | as Mode A |

- **`id` is the session's row key, not a credential** — safe to log, to compare, to store beside
  your own rows. `SqlAlchemySessionStore` requires it, so a row without one is refused like a row
  without a token; `RedisSessionStore` reads it when the stored document carries one; a store of
  your own sets `StoredSession.id` or leaves it `None`. Mode B has no session row: the JWT plugin's
  default payload is the user object, so its `id` claim is the *user's* id, and a JWT carries a
  session id only if your `definePayload` adds one — read that from `session.raw`.
- **`cookie` is a credential.** The value is a `SecretStr`, masked in `repr`, in JSON dumps and in
  anything FastAPI serializes, and read only with `.get_secret_value()`. The name is the one the
  verifier read, `__Secure-` or `__Host-` prefix included, and the value is exactly what it
  accepted: still percent-encoded, and reassembled if the browser sent it in chunks. Take it from
  here rather than from `request.cookies`, which is a second decision over the same bytes and a
  different one — Starlette lets the last of two same-named cookies win where the verifier refuses
  the request, and keeps a planted blank one where the verifier drops it.
- **`origin` is your configuration, not the request's header.** It is the configured string the
  CSRF check's comparison matched: byte-identical to the request's `Origin` today, because the
  match is exact, but owned by your `allowed_origins`. It is set only where that comparison ran and
  matched, under `OriginCheck` or `SignedDoubleSubmit`. A `GET` runs no check, `CsrfDisabled` reads
  nothing, and a policy of your own — a subclass of a shipped one included — hands nothing over, so
  each of those leaves it `None`.

### Forwarding to Better Auth

Some Better Auth routes act on the caller's own session — revoking one, say — and are best reached
by forwarding the request as the signed-in browser would have sent it. `/revoke-session` reads
three things (`dist/api/routes/session.mjs`): the caller's session cookie, which it looks up for
itself, uncached; a trusted `Origin`, without which Better Auth's global origin check refuses every
cookie-bearing `POST` (`dist/api/middlewares/origin-check.mjs`); and a JSON body naming the session
token to revoke. `session.cookie` and `session.origin` are the first two:

```python
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI
from pydantic import SecretStr

from fastapi_better_auth import BetterAuth, OriginCheck, RemoteVerifier, Session, SharedSecret, User

BETTER_AUTH_URL = "https://auth.example.com"

auth = BetterAuth(
    verifiers=[
        RemoteVerifier(
            base_url=BETTER_AUTH_URL,
            csrf=OriginCheck(allowed_origins=["https://app.example.com"]),
            # A literal only so this page runs — in production, read it from the environment.
            secret=SharedSecret("replace-this-with-your-own-32-plus-character-secret"),
        )
    ]
)
CurrentSession = Annotated[Session[User], Depends(auth.current_session())]


async def revoke_upstream(
    client: httpx.AsyncClient, session: Session[User], token: SecretStr
) -> httpx.Response | None:
    """Ask Better Auth to revoke `token` as the signed-in browser would - or do nothing.

    `None` when there is nothing trustworthy to forward with: no cookie (Mode B), or no origin
    (a GET ran no CSRF check, or a policy of your own matched none).
    """
    if session.cookie is None or session.origin is None:
        return None
    name, value = session.cookie
    return await client.post(
        f"{BETTER_AUTH_URL}/api/auth/revoke-session",
        headers={"Cookie": f"{name}={value.get_secret_value()}", "Origin": session.origin},
        json={"token": token.get_secret_value()},
    )


app = FastAPI()


@app.post("/sessions/current/revoke")
async def revoke_current(session: CurrentSession) -> dict[str, bool]:
    if session.token is None:
        return {"revoked": False}
    async with httpx.AsyncClient() as client:
        answer = await revoke_upstream(client, session, session.token)
    return {"revoked": answer is not None and answer.status_code == 200}
```

- **The origin must be in Better Auth's `trustedOrigins` as well.** `allowed_origins` here and
  `trustedOrigins` there are two lists, and Better Auth refuses the forward when the origin is only
  in yours. It trusts its own `baseURL` by default, so a front end on any other origin has to be
  named on both sides.
- **Do not forward a state-changing call from a `GET`.** No CSRF check runs on a safe method, so
  `session.origin` is `None` there and nothing has checked where the request came from. A link on
  another site can make a signed-in browser send that `GET` with its cookie. A route that then
  forwards with an origin it picked itself presents a request nobody checked to Better Auth as a
  trusted one. Forward only from an unsafe method that passed the CSRF check, with the origin the
  check matched, which is what the recipe does.
- **The cookie is a live credential on its way out.** Nothing above binds its value to a name
  outside the call that sends it; keep it that way, and keep the outbound request out of your logs.
  `tests/e2e/test_session_facts_live.py` runs this recipe against a live Better Auth server and
  shows the revoked session refused on the very next request.
