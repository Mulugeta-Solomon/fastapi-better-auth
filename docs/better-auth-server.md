# Configuring the Better Auth server

After reading this page you know the settings on your Better Auth (Node) server that this library
depends on or cannot fix: the `bearer` plugin's `requireSignature`, session lifetime, and who owns
the database schema.

Mode C's rate-limit settings are on the [Mode C page](mode-c-remote.md#the-shared-rate-limit-bucket).
The `additionalFields` trap is on [User models](user-models.md#additionalfields-make-sure-they-reach-the-wire).

## `requireSignature`: a raw session token is a bearer credential

If your Better Auth server mounts the `bearer` plugin, check this option before anything else on
this page. `requireSignature` defaults to **false**, and while it is false a *raw, unsigned* session
token presented as `Authorization: Bearer <token>` is signed by the server with its own secret and
installed as the session cookie (`dist/plugins/bearer/index.mjs:34-38`, then `:46`). It
authenticates. Which means a session token in a log line, a database dump, a backup or an error
report is not an identifier — it is a credential.

The fix is one line upstream:

```ts
bearer({ requireSignature: true })
```

With it set, a dot-less token is ignored outright (`dist/plugins/bearer/index.mjs:36`). That is not
advice taken on faith: the conformance lane runs two live Better Auth servers, one at each setting,
and pins the behaviour in both directions — `tests/e2e/test_conformance.py::TestBearerPosture`.

`RemoteVerifier` checks for the permissive posture at startup. Alongside the probe it sends one
request carrying a manufactured random token and looks at nothing but whether a `set-cookie` header
came back: the permissive posture emits one, the strict posture does not. By default that check is
advisory — one warning per process naming the fix, and nothing else. It never reads that header's
value and never replays a real credential.

**Make it a hard gate with `RemoteVerifier(refuse_unsigned_bearer=True)`.** The same request becomes
a rung of the probe: a `set-cookie` is a `ConfigurationError` naming
`bearer({ requireSignature: true })`, so `prepare()` refuses and a server wired through
`FastAPI(lifespan=auth.lifespan)` never starts. It is remembered like every other contract failure —
a deployment that skipped the lifespan and probes lazily refuses every request instead. Its own
reachability failure is *not* a verdict, and neither is a `408`, `425`, `429` or `5xx` answer that
sets no cookie: each stays the transient `AuthServiceUnavailable` the unreachable-at-boot path
already handles, and is retried rather than remembered. A `set-cookie` is the verdict whatever
status comes with it. The flag is
opt-in because the posture is your server's to set, and off is the current behaviour exactly.

**Modes A and B have no such check, and cannot.** Neither talks to your Better Auth server — Mode A
reads the session store, Mode B verifies offline against a cached key set — so neither is ever in a
position to observe the plugin's posture. There the warning above is documentation, and the fix is
still the same one line upstream.

## Sessions do not slide on bridge traffic

Every `get-session` call this library makes pins `disableRefresh=true`, so the route takes its
read-only branch (`dist/api/routes/session.mjs:163-170`) instead of the one that calls
`updateSession` and pushes `expiresAt` forward (`:191-195`). That is deliberate — a verifier that
extended sessions would make your API's request rate a factor in how long people stay signed in, and
would be handed a `Set-Cookie` the browser never sees — but the consequence deserves stating plainly:
**traffic to FastAPI does not keep a session alive.**

A session expires `session.expiresIn` after it was issued (7 days by default,
`dist/context/create-context.mjs:147`), however busy your API is. Better Auth normally slides that
forward once a session is older than `session.updateAge` (1 day by default, `:146`) — but
only requests that reach *Better Auth* do it.

Two remedies, and most deployments already have the first:

- **The browser also talks to the Node server** — signing in, refreshing, any Better Auth route at
  all. Sessions then slide there exactly as they always did and nothing here changes.
- **Otherwise raise `expiresIn` upstream** to whatever "signed in" should mean for your product, and
  accept that it is a fixed window from sign-in rather than a sliding one.

Mode A behaves the same way, for the same reason: a store read is a read, never a write.

## Who owns the database schema

**One tool owns every table, and on a FastAPI project that tool is yours** — Alembic, or whatever
your side already runs. The recipe: run `auth generate` on the Node side, hand-port the SQL it
prints into one migration of your own, re-diff on every Better Auth upgrade, and **never run
`auth migrate` against a database another tool migrates.** That includes not copying this
repository's harness container, which does exactly that on every boot.

The reason is what `auth migrate` is. It is Kysely-only — on any other adapter it logs "Only kysely
adapter is supported for migrations", points you at `generate`, and calls `process.exit(1)`
(`better-auth@1.7.3` `dist/db/get-migration.mjs:350`). And its plan is not a migration history:
`getMigrations` introspects the live database, diffs it against the schema your config implies, and
returns the difference as `toBeCreated` / `toBeAdded` / `toBeAddedIndexes` (`:335`, `:387-389`),
which `runMigrations` then executes statement by statement (`:643-649`). No migrations table, no
version stamp — nothing records that it ran, nothing can roll it back, and two tools that each
introspect-and-diff the same database can each decide the other's work is drift.

Better Auth 1.7.3 raises the stakes, because schema validation is now on by default.
`advanced.database.validateSchema` defaults to `true`, and its own doc comment says what that
buys: the schema is validated at initialization, problems are reported through the configured
logger, and authentication requests await the same check and fail when the schema does not match
(`@better-auth/core@1.7.3` `dist/types/init-options.d.mts:391-400`). All three halves are real. A
failure at init is logged (`better-auth@1.7.3` `dist/auth/base.mjs:10-18`); **every HTTP request
awaits the check** (`dist/api/index.mjs:167-168`) and so does every `auth.api.*` call
(`dist/api/to-auth-endpoints.mjs:41-42`); and the check throws `SchemaMismatchError` whenever it
finds anything (`@better-auth/core@1.7.3` `dist/db/schema-check.mjs:60-76`). None of it is
`NODE_ENV`-gated. So a schema the Node side does not recognise stops that server serving rather
than degrading quietly — which, on a database two tools have been fighting over, means the failure
arrives during a deploy instead of during an incident. All of it is unchanged at 1.7.5:
`dist/auth/base.mjs`, `dist/api/to-auth-endpoints.mjs` and `@better-auth/core`'s
`dist/db/schema-check.mjs` are byte-identical to 1.7.3's, the option's doc comment is still
`dist/types/init-options.d.mts:391-400`, and the per-request await has only moved to
`dist/api/index.mjs:169-170`. `better-auth@1.7.1` has none of this machinery: the same mismatch
there is silent until something reads a missing column.

This repository's harness is the exception that proves the rule — `harness/auth-server/Dockerfile`
runs `auth migrate` on every start because nothing else owns that database, and a conformance
harness *wants* its schema pinned to the version under test. A product does not.
