# Documentation

After reading this page you know which page answers your question.

These pages describe the `main` branch. Changes that are merged but not yet released are listed
under "Unreleased" in the [changelog](../CHANGELOG.md). Every Python example on these pages is run
by the test suite (`tests/test_readme.py`); a block marked `text` is shown, not run, because it
needs a database, a network or your own application.

## Start here

- [Choosing a mode](choosing-a-mode.md): Mode A, B or C, and what each can see.
- [Troubleshooting](troubleshooting.md): a symptom, its usual cause, and where the fix is.

## The three modes

- [Mode A: session cookie and shared store](mode-a-cookie.md)
- [Session stores](stores.md): the SQL and Redis stores, grants, and writing your own.
- [Mode B: JWT verified against the key set](mode-b-jwt.md)
- [Mode C: ask the Better Auth server](mode-c-remote.md)

## Cookie modes (A and C)

- [Shared secret](shared-secret.md): `SharedSecret`, rotation, and the boot fingerprint.
- [CSRF](csrf.md): the three policies, and which requests they check.
- [Deploying across two origins](cross-origin.md): cookie scope, `SameSite`, CORS.

## Every mode

- [User models](user-models.md): your own `User` subclass, `AdminUser`, `additionalFields`.
- [The verified session](sessions.md): what `Session` carries, and forwarding it to Better Auth.
- [Authorization](authorization.md): `require`, `require_membership`, `AuthorizationRefused`.
- [Errors](errors.md): each exception and the HTTP answer it gets.
- [Logging](logging.md): what is logged, at which level, and how often.
- [Testing](testing.md): overriding the session, and moving the verifier's clock.
- [OpenAPI and `/docs`](openapi.md)
- [HTTP clients](http-clients.md): `HttpxTransport`, `Httpx2Transport`, proxies.
- [Configuring the Better Auth server](better-auth-server.md): `requireSignature`, session
  lifetime, and who owns the database schema.

## Project

- [CHANGELOG.md](../CHANGELOG.md)
- [CONTRIBUTING.md](../CONTRIBUTING.md)
- [SECURITY.md](../SECURITY.md)
- [COMPATIBILITY.md](../COMPATIBILITY.md)
