import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { auth, pool } from "./auth.mjs";

const SEED_EMAIL = process.env.SEED_EMAIL ?? "seed@example.com";
const SEED_PASSWORD = process.env.SEED_PASSWORD ?? "seed-password-123";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL ?? "admin@example.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD ?? "admin-password-123";

async function signUp(name, email, password) {
  try {
    await auth.api.signUpEmail({ body: { name, email, password } });
    console.log(`seeded user ${email}`);
  } catch (err) {
    if (String(err?.body?.code ?? err).includes("USER_ALREADY_EXISTS")) {
      console.log(`seed user ${email} already exists`);
    } else {
      throw err;
    }
  }
}

async function seed() {
  await signUp("Seed User", SEED_EMAIL, SEED_PASSWORD);
  await signUp("Admin User", ADMIN_EMAIL, ADMIN_PASSWORD);
  // The admin plugin reads `role` off the user row and offers no endpoint that grants it
  // without an existing admin, so the first one is made here.
  await pool.query('UPDATE "user" SET role = $1 WHERE email = $2', ["admin", ADMIN_EMAIL]);
  console.log(`promoted ${ADMIN_EMAIL} to admin`);
}

const app = new Hono();
app.get("/healthz", (c) => c.json({ ok: true }));
app.on(["GET", "POST"], "/api/auth/*", (c) => auth.handler(c.req.raw));

await seed();
const port = Number(process.env.PORT ?? 3100);
serve({ fetch: app.fetch, port, hostname: "0.0.0.0" });
console.log(`harness auth server listening on :${port}`);
