FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
# Canary lane overrides the pinned better-auth at build time; empty = use the lockfile pin.
ARG BETTER_AUTH_VERSION=""
RUN if [ -n "$BETTER_AUTH_VERSION" ]; then \
      npm install --no-save "better-auth@${BETTER_AUTH_VERSION}" "auth@${BETTER_AUTH_VERSION}"; \
    fi
COPY src ./src
EXPOSE 3100
# Harness-only: `auth migrate` applies DDL with no history of its own, so it is safe here only
# because nothing else owns this database. A product's migration tool owns every table - see
# "Who owns the database schema" in the top-level README before copying this line.
CMD ["sh", "-c", "./node_modules/.bin/auth migrate --config src/auth.mjs --yes && node src/index.mjs"]
