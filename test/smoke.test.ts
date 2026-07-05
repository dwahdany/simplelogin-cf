import { env, SELF } from "cloudflare:test";
import { expect, it } from "vitest";

it("serves the health endpoint", async () => {
  const res = await SELF.fetch("https://sl.test/api/health");
  expect(res.status).toBe(200);
  expect(await res.json()).toEqual({ status: "ok" });
});

it("has a working D1 binding", async () => {
  const row = await env.DB.prepare("SELECT 1 AS x").first<{ x: number }>();
  expect(row?.x).toBe(1);
});

it("has a working KV binding", async () => {
  await env.KV.put("smoke", "ok");
  expect(await env.KV.get("smoke")).toBe("ok");
});
