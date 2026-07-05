import { env, SELF } from "cloudflare:test";
import { expect, it } from "vitest";
import { createApiKey, createUser } from "./fixtures";

// Werkzeug-parity HTTP semantics handled centrally in src/index.ts.

it("returns 405 Method not allowed for a wrong method on an existing path", async () => {
  const res = await SELF.fetch("https://sl.test/api/user_info", {
    method: "DELETE",
  });
  expect(res.status).toBe(405);
  expect(await res.json()).toEqual({ error: "Method not allowed" });
});

it("returns 405 for wrong method on a parameterized route", async () => {
  const res = await SELF.fetch("https://sl.test/api/aliases/123/toggle", {
    method: "PUT",
  });
  expect(res.status).toBe(405);
  expect(await res.json()).toEqual({ error: "Method not allowed" });
});

it("returns 404 No such endpoint for unknown API paths", async () => {
  const res = await SELF.fetch("https://sl.test/api/nope", { method: "GET" });
  expect(res.status).toBe(404);
  expect(await res.json()).toEqual({ error: "No such endpoint" });
});

it("grants sudo from the browser-session sudo_time even on API-key auth", async () => {
  const user = await createUser(env.DB);
  const apiKey = await createApiKey(env.DB, user.id); // no sudo_mode_at
  const token = "sudo-session-token";
  await env.KV.put(
    `session:${token}`,
    JSON.stringify({
      user_id: user.id,
      sudo_time: Math.floor(Date.now() / 1000),
    }),
  );

  const denied = await SELF.fetch("https://sl.test/api/api_key", {
    method: "POST",
    headers: {
      Authentication: apiKey.code,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ device: "test" }),
  });
  expect(denied.status).toBe(440);

  const granted = await SELF.fetch("https://sl.test/api/api_key", {
    method: "POST",
    headers: {
      Authentication: apiKey.code,
      "Content-Type": "application/json",
      Cookie: `slapp=${token}`,
    },
    body: JSON.stringify({ device: "test" }),
  });
  expect(granted.status).toBe(201);
  expect(await granted.json()).toHaveProperty("api_key");
});
