# Deploying across two origins

After reading this page you can serve a front end and this API from different hosts in a cookie
mode (Mode A or Mode C): pick the cookie settings Better Auth needs, and configure CORS and CSRF on
this side.

## Two origins, one site or two

A front end on one host and this API on another are two **origins**. Whether they are also two
**sites** is what decides which cookie Better Auth has to set, so it is the question to answer
first. A *site* is a scheme plus a registrable domain — the public suffix and the one label to its
left — so `https://app.example.com` and `https://api.example.com` are two origins and one site,
while `https://example.com` and `https://example-api.net` are two sites. A request is *same-site*
when its URL is same-site with the page that sent it — strictly, with that page's "site for
cookies" — and *cross-site* otherwise. (The
[HTML Standard](https://html.spec.whatwg.org/multipage/browsers.html#sites), §7.1.1.1 "Sites",
builds a site from an origin's scheme and its host's registrable domain;
[RFC 6265bis](https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/22/),
`draft-ietf-httpbis-rfc6265bis-22`, defines the registrable domain in §2.3 and same-site and
cross-site requests in §5.2, deferring to the HTML Standard's *same site*. Both fetched
2026-09-25.)

Two properties of the cookie then decide whether it reaches this API, and they answer different
questions:

- **Scope — which hosts it is sent to at all.** A cookie set with no `Domain=` attribute is
  *host-only*: the browser returns it to the exact host that set it and to no other, while one set
  with `Domain=example.com` goes to `example.com` and every host under it (RFC 6265bis §5.7
  step 10, §5.8.3). No `SameSite` value widens a cookie's scope.
- **`SameSite` — whether a cross-site request carries it.** A `Lax` cookie rides on every
  same-site request, but on a cross-site one only when it is a top-level navigation with a safe
  method, so never on a cross-site `fetch` or form `POST`; a `None` cookie rides on both, and is
  ignored unless it is also `Secure` (RFC 6265bis §5.6.7.1, §5.8.3, §5.7 step 19).

**Same-site siblings under a domain you own** — `app.example.com`, `admin.example.com`,
`auth.example.com`, `api.example.com`. Every hop between them is same-site — provided every one is
served over the same scheme, since a site includes it and `http://old.example.com` is not the same
site as `https://app.example.com` — so Better Auth's default `SameSite=Lax` (`better-auth@1.7.1`
and `@1.7.5`, `dist/cookies/index.mjs:35`) is correct and sufficient. `SameSite=None` is not
needed here, and it is a strictly weaker cookie: it adds cross-site requests to the ones that carry
it, and no request this layout depends on is cross-site. What the siblings need instead is
**scope**. Better Auth's defaults carry no `Domain=` — it adds one when `crossSubDomainCookies` is
enabled (`:38`) — so by default its cookie is host-only, and a cookie set from `auth.example.com`
never reaches `api.example.com`, whatever its `SameSite` says. Two ways to give it that reach:

1. **Serve Better Auth from the API's own host** — a reverse proxy sending
   `api.example.com/api/auth/*` to the Node server — so the host-only cookie it sets is already the
   API host's. It is the narrowest cookie there is: no other sibling ever receives it.
2. **`advanced.crossSubDomainCookies`, with `domain` set explicitly.** Its shape is `enabled`,
   `additionalCookies` and `domain` (`@better-auth/core@1.7.1` and `@1.7.5`,
   `dist/types/init-options.d.mts:314-330`). Enabled, the cookie carries a `Domain=` attribute
   (`dist/cookies/index.mjs:38`), and a cookie scoped to `example.com` is sent to
   `app.example.com` and `api.example.com` alike. That widens where the cookie goes; it does not
   make any request same-site that was not already.

**Only the first way keeps `__Host-` open.** `__Host-` is the one cookie prefix a sibling cannot
plant, which is why `CookieVerifier`'s `secure_prefix` documentation and SECURITY.md tell you to
prefer `secure_prefix="__Host-"` where you can make Better Auth emit it. RFC 6265bis defines a
`__Host-` cookie as one set with `Secure`, `Path=/` and **no `Domain` attribute** (§4.1.3.2), and a
browser ignores a `__Host-` cookie that is not host-only (§5.7 step 21). `crossSubDomainCookies`
works by emitting `Domain=`, so a `__Host-` name under it is a cookie the browser drops without a
word, and every session-guarded route answers `401`. The second way therefore gives that hardening
up: its cookie is `__Secure-` at most, and a sibling can plant a `Domain`-scoped `__Secure-`
cookie under the same name.

**Read what the code does with `domain`, not what the option's doc comment says it does.** The
comment says "By default, the domain will be the root domain from the base URL"
(`init-options.d.mts:326-327`, both versions). The code performs no shortening of any kind:
`Domain=` becomes the `domain` you configured, or else the **hostname** of your `baseURL` —
`options.advanced?.crossSubDomainCookies?.domain || (baseURLString ? new URL(baseURLString).hostname : void 0)`
(`better-auth@1.7.1` and `@1.7.5`, `dist/cookies/index.mjs:24-25`). So a `baseURL` of
`https://api.example.com` with `enabled: true` and no `domain` yields `Domain=api.example.com` — a
cookie that still never reaches the sibling it was turned on for. **If you enable it, set `domain`
explicitly**, to the domain you own and never to a public suffix (below). `Domain=example.com` sends
the cookie to every subdomain that exists today and every one that ever will, a larger blast radius
than the pair of hosts you meant to connect — so where the first way is open to you, it is the
smaller cookie.

**Cross-site: two registrable domains, or siblings under a public suffix** — `app.example.com`
calling `api.example-api.net`, or two hosts under a platform domain such as `up.railway.app`
(below). Every request from the front end to the API is now cross-site, and a `Lax` cookie is never
attached to a cross-site `fetch`, so Better Auth has to set `SameSite=None; Secure`:
`advanced: { defaultCookieAttributes: { sameSite: "none", secure: true } }`, which is spread over
its defaults (`better-auth@1.7.1` and `@1.7.5`, `dist/cookies/index.mjs:39`; `"none"` is one of the
values `better-call@1.4.0`, the version both pin, accepts at `dist/cookies.d.mts:71`). Scope still
decides where it goes, and here it has one answer: a `Domain=` may name only the host that sets the
cookie or a parent of it (RFC 6265bis §5.7 step 10), never another registrable domain, so Better
Auth has to set it from the API's own host (or, under a domain you own, from a sibling of the API
with `crossSubDomainCookies` as above). And a browser may still refuse it: a cross-site cookie is a
third-party cookie, and RFC 6265bis §7.1 records that most user agents now limit those and that
resources cannot rely on them being treated consistently. Where you can put both hosts under one
domain you own, the same-site layout is the sturdier one.

> **A platform domain cannot do this.** A `Domain=` attribute may not name a public suffix. RFC
> 6265bis §5.7 step 9 is exact about it: a user agent configured to reject public suffixes **ignores
> the cookie entirely**, unless the attribute is identical to the request host, in which case the
> cookie is narrowed to that one host. Either way it never reaches a sibling. The Public Suffix List
> ([publicsuffix.org](https://publicsuffix.org/list/public_suffix_list.dat), fetched 2026-09-25,
> `VERSION: 2026-09-24_13-26-36_UTC`, 16 501 lines) contains `fly.dev` (line 13660), `herokuapp.com`
> (14037), `up.railway.app` (15445), `onrender.com` (15477) and `vercel.app` (16269). So
> `yourapp-web.up.railway.app` and `yourapp-api.up.railway.app` **cannot** share a cookie, and
> neither can two `*.vercel.app` deployments — the browser drops the `Set-Cookie` and nothing in
> either log says why. No configuration on either side changes it. The fallback that does work there
> is the plain cross-site path above: `SameSite=None; Secure`, CORS with credentials, and
> `OriginCheck`. Put a domain you own in front of both hosts and `crossSubDomainCookies` is back on
> the table.

**Either layout: what this side needs.** Nothing in this library changes between the two. The
cookie's name does not depend on `SameSite` or `Domain=`: it is built from the cookie prefix and
the `__Secure-` prefix alone (`dist/cookies/index.mjs:28-33`, both versions), and the `__Secure-`
prefix follows `advanced.useSecureCookies`, else the base URL's protocol, else production mode
(`:23`) — so `CookieVerifier` reads the same `__Secure-better-auth.session_token` by default in
both. What is on this side, in both:

1. **CORS with credentials allowed, from an explicit origin list.** Siblings are one site but two
   origins, so a same-site front end needs this exactly as a cross-site one does. A wildcard is not
   an option: a browser refuses a credentialed response whose `Access-Control-Allow-Origin` is `*`,
   so name the front ends you actually serve.
2. **The cookie mode's CSRF policy allows those same origins** — and it is not optional in either
   layout: a `None` cookie rides on cross-site requests and a `Lax` one on every sibling's, which is
   why `csrf=` has no default.

Both are in this application, and it is the same application for either layout:

```python
from typing import Annotated

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from fastapi_better_auth import (
    BetterAuth,
    CookieVerifier,
    OriginCheck,
    Session,
    SessionStore,
    SharedSecret,
    StoredSession,
    StoredUser,
    User,
)

FRONT_END = "https://app.example.com"


class DictSessionStore:
    """The two reads a `SessionStore` is. Empty here; in production, a store from docs/stores.md."""

    def __init__(self) -> None:
        self.sessions: dict[str, StoredSession] = {}
        self.users: dict[str, StoredUser] = {}

    async def fetch_session_by_token(self, token: str) -> StoredSession | None:
        return self.sessions.get(token)

    async def fetch_user_by_id(self, user_id: str) -> StoredUser | None:
        return self.users.get(user_id)


store: SessionStore = DictSessionStore()

auth = BetterAuth(
    verifiers=[
        CookieVerifier(
            # A literal only so this page runs — in production,
            # SharedSecret(os.environ["BETTER_AUTH_SECRET"]).
            secret=SharedSecret("replace-this-with-your-own-32-plus-character-secret"),
            store=store,
            csrf=OriginCheck(allowed_origins=[FRONT_END]),
        )
    ]
)
CurrentSession = Annotated[Session[User], Depends(auth.current_session())]

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONT_END],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["content-type"],
)


@app.post("/comments")
async def comment(session: CurrentSession) -> dict[str, str]:
    return {"author": session.user.id}
```

The browser has to opt in as well, once, wherever your front end calls this API:
`fetch("https://api.example.com/comments", {method: "POST", credentials: "include"})`. Without
`credentials: "include"` no cookie is attached and every request arrives anonymous.

**CORS is not the CSRF control, and the two allowlists are not the same control over one list.** A
form `POST` is never preflighted: it reaches your route whatever `allow_origins` says, and CORS
withholds only the *response* from the page that sent it. Which cookie rides along depends on where
that page is: a form on another *site* carries a `SameSite=None` cookie and not a `Lax` one
(RFC 6265bis §5.6.7.1, §5.8.3), while a form on a *sibling* is same-site and carries either.
What refuses the request itself is the CSRF policy. Keep the two lists in step — and never treat
either as standing in for the other. The policy guards only the routes that depend on the verifier,
and only when the request carries its cookie: see
[Where the CSRF check runs](csrf.md#where-the-csrf-check-runs).

**`SameSite=Lax` does nothing against a sibling.** A sibling's requests are same-site, so the
browser attaches the cookie to them exactly as it does to your front end's, and only the CSRF
policy tells the two apart — which is why `OriginCheck` does not treat `Sec-Fetch-Site: same-site`
as a pass. `OriginCheck` is the floor; but a *bare* double-submit cookie proves only that the sender
could set a cookie, and a sibling can set one on the shared parent domain — so on a shared parent
domain reach for `SignedDoubleSubmit`, whose token is an HMAC of the session token under your
secret: bound to the session, and useless to a sibling. What neither policy stops is a sibling
planting the session cookie's own name — possible unless that cookie is `__Host-`, which
`crossSubDomainCookies` rules out (above). A signed-out victim's own front end then sends the
attacker's session from an allowed origin, with a token minted for that same session, and the
victim's writes land in the attacker's account
([SECURITY.md](../SECURITY.md)). A
**non-browser** client (mobile, server-to-server) has no `Origin` for `OriginCheck` to trust and
belongs on **Mode B** (bearer) instead: compose both verifiers and each request picks its own by
which credential it carries. All of this applies unchanged to Mode C, which reads the same cookie.

**More than one front end is expected, not exceptional.** `allowed_origins` is a sequence and
nothing says it holds one entry —
`OriginCheck(allowed_origins=["https://app.example.com", "https://admin.example.com"])` is a
two-front-end deployment, and `SignedDoubleSubmit` takes the same argument. Every entry must be an
origin a page is genuinely served from, **including this API's own origin** when a page served from
here posts back to it: a same-origin `POST` still carries `Origin`, and an allowlist that omits it
refuses every one of those requests. An empty list, a bare string, and two spellings of one origin
are each refused at construction rather than at 3 a.m.
