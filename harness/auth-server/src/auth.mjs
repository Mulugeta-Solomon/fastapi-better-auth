import { betterAuth } from "better-auth";
import { bearer, jwt } from "better-auth/plugins";
import Redis from "ioredis";
import pg from "pg";

// REDIS_URL switches the harness into the secondary-storage topology, where sessions
// live in Redis (keyed by raw token) and may never reach the Postgres session table.
const redis = process.env.REDIS_URL ? new Redis(process.env.REDIS_URL) : null;

export const auth = betterAuth({
  baseURL: process.env.BETTER_AUTH_URL ?? "http://localhost:3100",
  secret: process.env.BETTER_AUTH_SECRET,
  database: new pg.Pool({ connectionString: process.env.DATABASE_URL }),
  emailAndPassword: { enabled: true },
  plugins: [jwt(), bearer()],
  ...(redis && {
    secondaryStorage: {
      get: (key) => redis.get(key),
      set: async (key, value, ttl) => {
        if (ttl) await redis.set(key, value, "EX", ttl);
        else await redis.set(key, value);
      },
      delete: async (key) => {
        await redis.del(key);
      },
    },
  }),
});
