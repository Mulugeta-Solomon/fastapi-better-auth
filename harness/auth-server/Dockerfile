# node:22-alpine, pinned by digest (the multi-arch index); Dependabot's docker ecosystem bumps
# tag and digest together.
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
# Canary lane overrides the pinned better-auth at build time; empty = use the lockfile pin.
ARG BETTER_AUTH_VERSION=""
# Mitigation, not a root-cause fix: in October 2026 npm 10.9.9 crashed here with "Cannot read
# properties of null (reading 'edgesOut')" for 1.6.30 and 1.7.1 on every sweep for about two
# weeks, then stopped with no change on this side. It could not be reproduced afterwards (npm
# 11, today's registry or `--before` an October date), so the cause is unknown. A few spaced
# attempts absorb a transient registry or arborist failure; they would NOT have saved the
# October sweeps, which failed the same way every time. A version that genuinely cannot be
# installed still fails the build after the last attempt. A version equal to both lockfile
# pins is already installed by `npm ci`, so it skips npm entirely - the 1.7.1 legs crashed on
# exactly that no-op install. Which version actually runs is proven afterwards by
# .github/scripts/harness_better_auth_version.py, not by this step.
RUN if [ -n "$BETTER_AUTH_VERSION" ]; then \
      pinned=$(node -p 'const d = require("./package.json").dependencies; d["better-auth"] === d.auth ? d.auth : ""'); \
      if [ "$BETTER_AUTH_VERSION" = "$pinned" ]; then \
        echo "better-auth@${BETTER_AUTH_VERSION} is the lockfile pin; npm ci already installed it"; \
        exit 0; \
      fi; \
      attempt=1; \
      until npm install --no-save "better-auth@${BETTER_AUTH_VERSION}" "auth@${BETTER_AUTH_VERSION}"; do \
        if [ "$attempt" -ge 3 ]; then \
          echo "better-auth@${BETTER_AUTH_VERSION} could not be installed after ${attempt} attempts" >&2; \
          exit 1; \
        fi; \
        echo "npm install failed (attempt ${attempt}); retrying in $((attempt * 15))s" >&2; \
        sleep $((attempt * 15)); \
        attempt=$((attempt + 1)); \
      done; \
    fi
COPY src ./src
EXPOSE 3100
# Harness-only: `auth migrate` applies DDL with no history of its own, so it is safe here only
# because nothing else owns this database. A product's migration tool owns every table - see
# "Who owns the database schema" in the top-level README before copying this line.
CMD ["sh", "-c", "./node_modules/.bin/auth migrate --config src/auth.mjs --yes && node src/index.mjs"]
