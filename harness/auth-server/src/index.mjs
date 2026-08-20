import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { auth } from "./auth.mjs";

const SEED_EMAIL = process.env.SEED_EMAIL ?? "seed@example.com";
const SEED_PASSWORD = process.env.SEED_PASSWORD ?? "seed-password-123";

async function seed() {
  try {
    await auth.api.signUpEmail({
      body: { name: "Seed User", email: SEED_EMAIL, password: SEED_PASSWORD },
    });
    console.log(`seeded user ${SEED_EMAIL}`);
  } catch (err) {
    if (String(err?.body?.code ?? err).includes("USER_ALREADY_EXISTS")) {
      console.log(`seed user ${SEED_EMAIL} already exists`);
    } else {
      throw err;
    }
  }
}

const app = new Hono();
app.get("/healthz", (c) => c.json({ ok: true }));
app.on(["GET", "POST"], "/api/auth/*", (c) => auth.handler(c.req.raw));

await seed();
const port = Number(process.env.PORT ?? 3100);
serve({ fetch: app.fetch, port, hostname: "0.0.0.0" });
console.log(`harness auth server listening on :${port}`);
