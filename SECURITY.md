# Security Policy

## Reporting a vulnerability

Please report vulnerabilities **privately** via GitHub's *Report a vulnerability* button
(Security tab of this repository). Do not open public issues for security problems.

- Acknowledgement target: within 72 hours.
- Coordinated disclosure: we will agree on a timeline with you; default is disclosure after a fix
  is released, or 90 days, whichever comes first.

## Supported versions

Pre-1.0: only the **latest released version** receives fixes.

## Better Auth compatibility floor

This library bridges to a Better Auth (TypeScript) server you operate. Once 0.1.0 ships, this file
will pin a **minimum safe Better Auth version** (at least ≥ 1.4.9 — earlier versions are affected by
CVE-2026-67337, a critical 2FA bypass via the session cookie cache). Keeping your Better Auth server
current is part of your deployment's security posture; this library cannot patch the server side.

## Maintainer inactivity policy

If the maintainer is unresponsive to a reported vulnerability for 90 days, this project should be
considered unmaintained: a banner will be added to the README (by the maintainer returning, or via
PR by any credible reporter referencing this policy), and users should migrate.
