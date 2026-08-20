FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY src ./src
EXPOSE 3100
CMD ["sh", "-c", "./node_modules/.bin/auth migrate --config src/auth.mjs --yes && node src/index.mjs"]
