import { env } from "cloudflare:test";
import { Hono } from "hono";
import { beforeAll, describe, expect, it } from "vitest";
import type { UserRow } from "../src/lib/rows";
import { createSession } from "../src/lib/session";
import {
  csrfTokenField,
  generateCsrfToken,
  makeField,
  validateCsrfToken,
} from "../src/lib/web/forms";
import {
  buildCurrentUser,
  flash,
  renderErrorPage,
  webRender,
} from "../src/lib/web/render";
import { requireWebLogin, type WebEnv } from "../src/lib/web/webauth";
import { createApiKey, createUser } from "./fixtures";

let user: UserRow;

const app = new Hono<WebEnv>();
app.get("/test/anon", async (c) => webRender(c, "spike/anon.html", {}, {}));
app.get("/test/flash-then-anon", async (c) => {
  await flash(c, 'Alias created <a href="/x">view</a>', "success");
  return webRender(c, "spike/anon.html", {}, {});
});
app.get("/test/notfound", async (c) => renderErrorPage(c, 404));
app.use("/test/page", requireWebLogin);
app.get("/test/page", async (c) => {
  const current = await buildCurrentUser(c, c.get("webUser"));
  const token = await generateCsrfToken(c, c.get("webSession"));
  return webRender(
    c,
    "spike/page.html",
    {
      form: {
        email: makeField({ name: "email", label: "Email", type: "email" }),
      },
      csrf_form: { csrf_token: csrfTokenField(token) },
    },
    { currentUser: current },
  );
});

async function fetchApp(path: string, headers: Record<string, string> = {}) {
  return app.request(path, { headers }, env);
}

/** Run a handler that sets a session cookie and return that cookie. */
async function sessionCookieFor(userId: number): Promise<string> {
  const helper = new Hono<WebEnv>();
  helper.get("/mk", async (c) => {
    await createSession(c, userId);
    return c.text("ok");
  });
  const res = await helper.request("/mk", {}, env);
  const setCookie = res.headers.get("set-cookie") ?? "";
  return setCookie.split(";")[0];
}

beforeAll(async () => {
  user = await createUser(env.DB);
  await createApiKey(env.DB, user.id);
});

describe("web render pipeline", () => {
  it("renders an anonymous page through single.html/base.html", async () => {
    const res = await fetchApp("/test/anon");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('<div id="anonbody">hello anon</div>');
    expect(html).toMatch(/<title>\s*Anon\s*\| SimpleLogin\s*<\/title>/);
    expect(html).toContain("https://simplelogin.io"); // LANDING_PAGE_URL logo link
  });

  it("redirects anonymous users to login with the 401-funnel flash", async () => {
    const res = await fetchApp("/test/page?x=1");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      "/auth/login?next=%2Ftest%2Fpage%3Fx%3D1",
    );
  });

  it("renders the full logged-in layout: header, active menu tab, form macro, csrf", async () => {
    const cookie = await sessionCookieFor(user.id);
    const res = await fetchApp("/test/page", { Cookie: cookie });
    expect(res.status).toBe(200);
    const html = await res.text();
    // header + menu through default.html
    expect(html).toContain('href="/dashboard/"');
    expect(html).toMatch(/nav-link active[\s\S]{0,200}Settings/);
    // parent-import-free render_field macro with kwargs
    expect(html).toMatch(
      /<input [^>]*class="form-control"[^>]*placeholder="you@example.com"[^>]*>/,
    );
    // csrf hidden field
    expect(html).toMatch(
      /<input id="csrf_token" name="csrf_token" type="hidden" value="[^"]+">/,
    );
    // fixture users are inside the 7-day trial => is_premium() true
    expect(html).toContain('<span id="premium">true</span>');
    expect(html).toContain('<span id="args">none</span>');
    // footer notification Vue app source
    expect(html).toContain("/api/notifications?page=");
  });

  it("drains flash messages exactly once as toastr calls", async () => {
    const cookie = await sessionCookieFor(user.id);
    const res = await fetchApp("/test/flash-then-anon", { Cookie: cookie });
    const html = await res.text();
    expect(html).toContain("toastr.success(");
    expect(html).toContain("Alias created");
    const res2 = await fetchApp("/test/anon", { Cookie: cookie });
    expect(await res2.text()).not.toContain("Alias created");
  });

  it("renders the 404 error page with exact strings", async () => {
    const res = await fetchApp("/test/notfound");
    expect(res.status).toBe(404);
    const html = await res.text();
    expect(html).toContain("This page does not exist.");
    expect(html).toContain("Go Back");
  });

  it("round-trips CSRF tokens and rejects bad ones with flask-wtf strings", async () => {
    const helper = new Hono<WebEnv>();
    helper.get("/csrf", async (c) => {
      const token = await generateCsrfToken(c);
      const setCookie = c.res.headers.get("set-cookie");
      return c.json({ token, cookie: setCookie?.split(";")[0] ?? null });
    });
    helper.post("/check", async (c) => {
      const { token } = await c.req.json<{ token: string }>();
      const err = await validateCsrfToken(c, token);
      return c.json({ err });
    });
    const r1 = await helper.request("/csrf", {}, env);
    const { token, cookie } = await r1.json<{
      token: string;
      cookie: string;
    }>();
    expect(cookie).toContain("slapp=");

    const ok = await helper.request(
      "/check",
      {
        method: "POST",
        headers: { Cookie: cookie, "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      },
      env,
    );
    expect(await ok.json()).toEqual({ err: null });

    const bad = await helper.request(
      "/check",
      {
        method: "POST",
        headers: { Cookie: cookie, "Content-Type": "application/json" },
        body: JSON.stringify({ token: `${token}x` }),
      },
      env,
    );
    expect(await bad.json()).toEqual({ err: "The CSRF token is invalid." });

    const missing = await helper.request(
      "/check",
      {
        method: "POST",
        headers: { Cookie: cookie, "Content-Type": "application/json" },
        body: JSON.stringify({ token: "" }),
      },
      env,
    );
    expect(await missing.json()).toEqual({ err: "The CSRF token is missing." });
  });
});
