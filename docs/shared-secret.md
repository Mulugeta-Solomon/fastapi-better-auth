# Shared secret

After reading this page you can give Mode A or Mode C your Better Auth secret, rotate it, and
prove at startup that both servers use the same value.

## `SharedSecret`

`SharedSecret` holds the value your Better Auth server signs cookies with: its `secret` option, or
the `BETTER_AUTH_SECRET` it reads from the environment. Mode A requires it. Mode C uses it, when
you configure it, to refuse forged cookies locally. Mode B does not use it.

```text
SharedSecret(os.environ["BETTER_AUTH_SECRET"])
```

It refuses an unusable value at construction, so a bad secret stops the application from starting.
Refused: a value that is not a `str`; an empty or whitespace-only value; leading or trailing
whitespace; a value with no UTF-8 encoding; a known placeholder, including Better Auth's own
default secret; fewer than 32 characters; and one short unit repeated.

It never prints its value. `repr()`, `str()` and `%s` show only `SharedSecret(tok_fp=<8 hex>)`, and
pickling is refused. `get_secret_value()` is the one way to read the value.

**Rotation.** Pass `secrets=[...]` instead of `secret=` to `CookieVerifier` or `RemoteVerifier`. A
cookie signed with any of them is accepted. Every entry is compared in constant time, with no early
return.

## Is it the same secret? Fingerprint both sides at boot

A secret with the right *shape* and the wrong *value* is accepted at construction and then fails one
request at a time, as a constant-time comparison miss inside the verifier — the same uniform `401` a
forged cookie earns, and by default not logged at all. Two deployment configs, two secret stores, one
stale copy, and the symptom is "nobody can sign in" with nothing anywhere saying why.

`SharedSecret.fingerprint` closes that, and it costs one line on each side. It is `tok_fp=` followed
by the first eight hex characters of SHA-256 over the secret's UTF-8 bytes: stable for a given value,
safe to log, and not reversible into the secret.

```python
import contextlib
import logging
from collections.abc import AsyncGenerator

from fastapi import FastAPI

from fastapi_better_auth import VERIFIED_BETTER_AUTH, SharedSecret

logger = logging.getLogger("myapp")

# A literal only so this page runs — in production, SharedSecret(os.environ["BETTER_AUTH_SECRET"]).
secret = SharedSecret("replace-this-with-your-own-32-plus-character-secret")


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    logger.info("better-auth secret %s", secret.fingerprint)
    logger.info("better-auth verified against %s", VERIFIED_BETTER_AUTH)
    yield


app = FastAPI(lifespan=lifespan)
```

Hand that same `secret` object to your `CookieVerifier` (or `RemoteVerifier`): one value, one
fingerprint, nothing to keep in step. Then print the matching string from your Better Auth server's
own startup — the identical construction, so the two are comparable by eye:

```ts
import { createHash } from "node:crypto";

console.log(
  "better-auth secret tok_fp=" +
    createHash("sha256").update(process.env.BETTER_AUTH_SECRET, "utf8").digest("hex").slice(0, 8),
);
```

The two lines are written to match, prefix and all, so when the secrets match the boot logs read
identically. **Two different strings is the whole check** — and you have it at deploy time rather
than in a support ticket an hour later. That the two constructions really do agree, on ASCII and on
non-ASCII secrets alike, is pinned by `tests/test_shared_secret.py`; neither line gives anything
back but the label.

**One more line worth logging there.** `VERIFIED_BETTER_AUTH` is the tuple of Better Auth versions
this release's conformance lane is actually run against — log it beside the Better Auth version your
own deployment pins, and an upstream bump this library has not been driven against shows up in a boot
log and in code review instead of in an incident. It is advisory and can only be: Mode A reads a
database or a Redis key and never the server, so nothing here can ask what is really running.
