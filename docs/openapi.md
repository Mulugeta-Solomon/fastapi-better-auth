# OpenAPI and `/docs`

After reading this page you know what security schemes your application publishes, and how to make
"Try it out" in `/docs` work with each mode.

You wire nothing. Each verifier publishes a security scheme derived from the credential it reads,
and every route that depends on a session lists it as a security requirement.

## Mode B: the bearer scheme

A `JwtVerifier` route publishes an HTTP bearer scheme under the key `BetterAuthBearer`. The
Authorize button in `/docs` takes a JWT and sends it as `Authorization: Bearer <token>`.

## Modes A and C: the cookie scheme

Mode A and Mode C read the same cookie, so this section applies to both. The cookie route publishes
an `APIKeyCookie` scheme, so `/docs` shows an Authorize field for it and
the security requirement appears on the operation. Two honest limits: an `APIKeyCookie` scheme, so `/docs` shows an Authorize field for it and
the security requirement appears on the operation. Two honest limits:

- **Swagger UI cannot *set* a cookie from the Authorize modal**
  ([swagger-api/swagger-ui#9710](https://github.com/swagger-api/swagger-ui/issues/9710)); the field
  is declarative. What makes "Try it out" work is `FastAPI(swagger_ui_parameters={"withCredentials":
  True})`, which tells Swagger to send the browser's *own* cookie — the one Better Auth already set —
  so a developer signed in on a same-site `/docs` can exercise the route.
- The scheme is documentation only. What it would read is never read; every credential comes from
  the verifier that owns it.

The scheme's component key is `BetterAuthCookie` whatever the cookie is called, so a committed
OpenAPI snapshot does not change with a per-environment cookie prefix; its `name` is the one cookie
the verifier reads, exactly as the browser sends it (`__Secure-better-auth.session_token` under the
default `secure_cookies=True`; the description names it too), so a snapshot that diffs `name` pins
its exporter's prefix; and an application that reads two different cookies publishes one key per
cookie, `BetterAuthCookie-<cookie name>` with each character outside `A-Za-z0-9._-` replaced by `-`
(`session+id` → `BetterAuthCookie-session-id`), so adding a second cookie verifier renames the
first one's key.
