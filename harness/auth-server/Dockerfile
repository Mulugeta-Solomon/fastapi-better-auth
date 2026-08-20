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
CMD ["sh", "-c", "./node_modules/.bin/auth migrate --config src/auth.mjs --yes && node src/index.mjs"]
