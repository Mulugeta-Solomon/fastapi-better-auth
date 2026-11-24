# CSRF

After reading this page you can choose a cross-site request forgery (CSRF) policy for Mode A or
Mode C, and you know which requests it checks.

A cookie is sent by the browser on its own, so a mode that reads one has to refuse requests that
another site made the browser send. `CookieVerifier` and `RemoteVerifier` therefore take a required
`csrf=` argument with no default. Mode B reads a bearer header, which a browser never sends on its
own, so it has no CSRF policy.

## The three policies

| Policy | Parameters | What it checks |
|---|---|---|
| `OriginCheck` | `allowed_origins` (required); `require_header=None` | Refuses `Sec-Fetch-Site: cross-site`. Then `Origin` must be present and exactly equal one of `allowed_origins`. If `require_header` is set, that header must be present and non-blank. Most deployments want this one. |
| `SignedDoubleSubmit` | `secret` (a `SharedSecret`, required); `allowed_origins` (required); `header="x-csrf-token"` | Everything `OriginCheck` checks, then the header must carry `token_for(session_token)`: an HMAC of the session token under your secret. A sibling subdomain cannot produce it. |
| `CsrfDisabled` | `reason` (required, at least 16 characters) | Nothing. The reason is written in your source and shows in `repr()`, so turning the check off is a visible decision. |

Rules that hold for both checking policies:

- `allowed_origins` is a list of full origins, such as `["https://app.example.com"]`. List every
  front end, and this API's own origin if a page served from it posts back to it.
- An empty list, a bare string instead of a list, and two spellings of one origin are each refused
  at construction.
- `Sec-Fetch-Site: same-site` is not a pass. A sibling subdomain is same-site.
- A request with no `Origin` on an unsafe method is refused. A client that sends no `Origin`, such
  as a mobile app or another server, belongs on Mode B.

To use `SignedDoubleSubmit`, hand the token to your front end from a route of your own, and have it
send the token back in the header on every unsafe request:

```text
policy = SignedDoubleSubmit(
    secret=SharedSecret(os.environ["BETTER_AUTH_SECRET"]),
    allowed_origins=["https://app.example.com"],
)

@app.get("/csrf")
async def csrf(session: CurrentSession) -> dict[str, str]:
    return {"token": policy.token_for(session.token.get_secret_value())}
```

## Where the CSRF check runs

The CSRF policy is not middleware and not a property of the application: it is a step inside the
cookie verifier that holds it — `CookieVerifier` in Mode A, and `RemoteVerifier` in Mode C, which
enforces the same policy before its get-session call. A verifier runs only for a route that depends
on `current_session()` or `optional_session()`, or on a `require(...)` or `require_membership(...)`
gate composed on them — and there only when the request carries the one cookie name that verifier
reads: the prefixed name (`__Secure-better-auth.session_token` by default) under
`secure_cookies=True`, the plain name under `False`. The other spelling is invisible to it, so a
request carrying only that one is anonymous — a `401` from `current_session()`, `None` from
`optional_session()` — and never a CSRF refusal. A request is handed to the verifier whose
credential it carries, and one carrying two credentials, such as that cookie and a bearer token, is
answered `400` (`AmbiguousCredentials`) before either one is verified, and so before CSRF.
`OriginCheck` and `SignedDoubleSubmit` then check only unsafe methods and WebSocket handshakes,
never `GET`, `HEAD` or `OPTIONS`. So:

- **A public route that reads no cookie needs no CSRF answer, and gets none.** There is no ambient
  credential on it for a forged request to borrow — and its client need not send a CSRF header, or
  fetch a token first, to call it.
- **An `optional_session` request with no cookie is anonymous and unchecked**, for the same reason.
  The same request carrying the cookie is checked like any other: cross-site, `OriginCheck` answers
  it `403`.
- **An unsafe route that uses the cookie without depending on the verifier has neither
  authentication nor CSRF protection.** Reading `request.cookies` yourself, or trusting that some
  earlier gate ran, skips both at once. Depend on the verifier and the two arrive together — which
  is also why there is no CSRF-only dependency to put on such a route instead.
- **A check on every unsafe request, whatever the route, is middleware you add yourself.** This
  library ships none.

The first three are pinned, in Mode A and in Mode C, by `tests/test_csrf_scope.py`.

For a front end on another origin, CORS and the CSRF allowlist work together; see
[Deploying across two origins](cross-origin.md). What CSRF cannot stop, a planted session cookie,
is in [SECURITY.md](../SECURITY.md).
