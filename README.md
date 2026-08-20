# fastapi-better-auth

**A bridge to a TypeScript [Better Auth](https://better-auth.com) server — not a Python port.**
(If you want a full Python re-implementation, this is not it.) Community-maintained; not affiliated
with or endorsed by Better Auth.

> **Status: placeholder release (0.0.1).** The library is in active development — 0.1.0 is the first
> usable release. Watch the [repository](https://github.com/Mulugeta-Solomon/fastapi-better-auth)
> for progress.

## What this will be

Better Auth is TypeScript-only: sign-in/up, OAuth, and 2FA run on your Node service. This package
makes its sessions first-class in FastAPI — verified correctly, with the traps handled:

| Mode | How | Revocation lag |
|---|---|---|
| **A — Cookie + shared DB/Redis** | Verify the signed `session_token` cookie (HMAC-SHA256, exact wire parity with better-call) and read the session store directly | Instant |
| **B — JWT / JWKS** | Verify Better Auth JWT-plugin tokens statelessly against `/api/auth/jwks` (EdDSA by default, pinned allowlist, required claims) | ≤ token lifetime (15 min default) |
| **C — Remote get-session** | Forward the credential to `GET /api/auth/get-session` with fail-closed semantics | Instant |

All three behind one FastAPI-native surface:

```python
# Planned 0.1 API — subject to change until 0.1.0 ships
auth = BetterAuth(verifiers=[JwtVerifier(base_url="https://auth.example.com")])
CurrentSession = Annotated[Session[MyUser], Depends(auth.current_session(user_model=MyUser))]

@app.get("/me")
async def me(session: CurrentSession) -> MyUser:
    return session.user
```

Design commitments: fail-closed everywhere; CSRF ships in the same release as cookie mode;
compatibility with Better Auth is **tested in CI against a real Node server**, never assumed.

## Why a library instead of the snippet

The hand-rolled verifier circulating in Better Auth issues splits the cookie on the wrong dot,
misses the `__Secure-` name, compares HMACs non-constant-time, and never enforces `expiresAt`
(upstream's `findSession` doesn't either — the route layer does, so a bare DB join honors expired
sessions forever). This package exists to own those details, with conformance tests pinning them
to real Better Auth releases.

## License

MIT © Mulugeta Solomon
