import { betterAuth } from "better-auth";
import { admin, bearer, jwt } from "better-auth/plugins";
import Redis from "ioredis";
import pg from "pg";

// REDIS_URL switches the harness into the secondary-storage topology, where sessions
// live in Redis (keyed by raw token) and may never reach the Postgres session table.
const redis = process.env.REDIS_URL ? new Redis(process.env.REDIS_URL) : null;

// Exported so the seed can promote a user to `admin`: role assignment is a database
// operation upstream, and every admin endpoint is gated on it.
export const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

export const auth = betterAuth({
  baseURL: process.env.BETTER_AUTH_URL ?? "http://localhost:3100",
  secret: process.env.BETTER_AUTH_SECRET,
  database: pool,
  emailAndPassword: { enabled: true },
  // admin() is what puts banned/banReason/banExpires on user and impersonatedBy on
  // session; without it those columns do not exist at all.
  plugins: [jwt(), bearer(), admin()],
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
