import { SELF } from "cloudflare:test";
import { expect, it } from "vitest";

// CORS contract for the browser extension.
//
// Flask enables flask-cors app-wide on the API:
//   CORS(app, resources={r"/api/*": {"origins": "*"}})  (simplelogin_app.py:476)
// The rewrite uses hono/cors with defaults on /api/* (src/index.ts), which is
// equivalent: wildcard origin, no credentials, and preflight reflects the
// requested headers (flask-cors' default allow_headers="*" does the same),
// which is what lets the extension send its `Authentication` header.
//
// Deliberate deviation: hono/cors answers preflights with 204 No Content,
// while Flask's auto-OPTIONS handler returns 200. Browsers accept any 2xx
// for a preflight, so the extension behaves identically.

const ORIGIN = "chrome-extension://dphilobhebphkdjbpfohgikllaljmgbn";

it("answers the extension preflight for GET /api/v2/aliases", async () => {
  const res = await SELF.fetch("https://sl.test/api/v2/aliases", {
    method: "OPTIONS",
    headers: {
      Origin: ORIGIN,
      "Access-Control-Request-Method": "GET",
      "Access-Control-Request-Headers": "authentication",
    },
  });
  expect(res.status).toBe(204);
  expect(await res.text()).toBe("");
  expect(res.headers.get("access-control-allow-origin")).toBe("*");
  expect(res.headers.get("access-control-allow-methods")).toContain("GET");
  // Reflects the requested headers — the extension's Authentication header.
  expect(res.headers.get("access-control-allow-headers")).toBe(
    "authentication",
  );
  expect(res.headers.get("vary")).toContain("Access-Control-Request-Headers");
});

it("keeps CORS headers on a 401 so the extension can read the error", async () => {
  const res = await SELF.fetch("https://sl.test/api/user_info", {
    headers: { Origin: ORIGIN },
  });
  expect(res.status).toBe(401);
  expect(await res.json()).toEqual({ error: "Wrong api key" });
  expect(res.headers.get("access-control-allow-origin")).toBe("*");
});

it("keeps CORS headers on the API 404 handler", async () => {
  const res = await SELF.fetch("https://sl.test/api/no-such", {
    headers: { Origin: ORIGIN },
  });
  expect(res.status).toBe(404);
  expect(await res.json()).toEqual({ error: "No such endpoint" });
  expect(res.headers.get("access-control-allow-origin")).toBe("*");
});

it("answers the preflight for POST /api/v3/alias/custom/new", async () => {
  const res = await SELF.fetch("https://sl.test/api/v3/alias/custom/new", {
    method: "OPTIONS",
    headers: {
      Origin: ORIGIN,
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "content-type,authentication",
    },
  });
  expect(res.status).toBe(204);
  expect(res.headers.get("access-control-allow-origin")).toBe("*");
  expect(res.headers.get("access-control-allow-methods")).toContain("POST");
  expect(res.headers.get("access-control-allow-headers")).toBe(
    "content-type,authentication",
  );
});
