/**
 * Web spec 05 — billing + misc pages (/dashboard/billing, /pricing,
 * /subscription_success, /coupon, /lifetime_licence, /referral, /support,
 * /app, /setup_done, /enter_admin).
 *
 * Sessions are seeded directly into KV (cookie `slapp` holds the opaque
 * token, see src/lib/session.ts); CSRF tokens are signed the same way
 * src/lib/web/forms.ts does.
 */

import {
  createExecutionContext,
  env,
  SELF,
  waitOnExecutionContext,
} from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import { timestampSign } from "../src/lib/crypto";
import { addDays, toStr } from "../src/lib/dates";
import { sentEmails } from "../src/lib/mailer";
import type { UserRow } from "../src/lib/rows";
import { createUser } from "./fixtures";

const B = "https://sl.test";
const CSRF_SECRET = "c".repeat(40);

let seq = 0;

interface WebSession {
  cookie: string;
  token: string;
  csrfToken(): Promise<string>;
  flashes(): Promise<Array<{ category: string; message: string }>>;
}

/** Seed a logged-in KV session (with a CSRF secret) and return its cookie. */
async function webSession(userId: number): Promise<WebSession> {
  const token = `bill-${++seq}-${crypto.randomUUID()}`;
  await env.KV.put(
    `session:${token}`,
    JSON.stringify({ user_id: userId, csrf: CSRF_SECRET }),
  );
  return {
    cookie: `slapp=${token}`,
    token,
    csrfToken: () =>
      timestampSign(`${env.FLASK_SECRET}wtf-csrf-token`, CSRF_SECRET),
    flashes: async () => {
      const raw = await env.KV.get(`session:${token}`);
      return raw ? (JSON.parse(raw).flashes ?? []) : [];
    },
  };
}

function get(path: string, cookie?: string): Promise<Response> {
  return SELF.fetch(`${B}${path}`, {
    headers: cookie ? { Cookie: cookie } : {},
    redirect: "manual",
  });
}

function post(
  path: string,
  cookie: string,
  form: Record<string, string>,
): Promise<Response> {
  return SELF.fetch(`${B}${path}`, {
    method: "POST",
    headers: {
      Cookie: cookie,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(form).toString(),
    redirect: "manual",
  });
}

// ---- local row fixtures (billing-specific tables) ----

async function insert(
  table: string,
  values: Record<string, unknown>,
): Promise<number> {
  const cols = Object.keys(values);
  const row = await env.DB.prepare(
    `INSERT INTO ${table} (${cols.map((c) => `"${c}"`).join(", ")})
     VALUES (${cols.map((_, i) => `?${i + 1}`).join(", ")}) RETURNING id`,
  )
    .bind(...cols.map((c) => values[c]))
    .first<{ id: number }>();
  if (!row) throw new Error(`insert into ${table} failed`);
  return row.id;
}

const futureDate = (days: number) => toStr(addDays(new Date(), days));
const futureDateOnly = (days: number) => futureDate(days).slice(0, 10);

function createPaddleSub(
  userId: number,
  overrides: Record<string, unknown> = {},
): Promise<number> {
  return insert("subscription", {
    cancel_url: "https://paddle.example/cancel",
    update_url: "https://paddle.example/update",
    subscription_id: `psub-${++seq}`,
    event_time: futureDate(0),
    next_bill_date: futureDateOnly(10),
    cancelled: 0,
    plan: "monthly",
    user_id: userId,
    ...overrides,
  });
}

// ---------------------------------------------------------------------------

describe("auth gating", () => {
  const routes = [
    "/dashboard/billing",
    "/dashboard/pricing",
    "/dashboard/subscription_success",
    "/dashboard/coupon",
    "/dashboard/lifetime_licence",
    "/dashboard/referral",
    "/dashboard/support",
    "/dashboard/app",
    "/dashboard/setup_done",
  ];
  for (const path of routes) {
    it(`redirects anonymous GET ${path} to login with next=full_path`, async () => {
      const res = await get(path);
      expect(res.status).toBe(302);
      expect(res.headers.get("location")).toBe(
        `/auth/login?next=${encodeURIComponent(`${path}?`)}`,
      );
    });
  }
});

describe("GET|POST /dashboard/billing", () => {
  it("redirects to the dashboard with a warning when there is no subscription", async () => {
    const user = await createUser(env.DB);
    const s = await webSession(user.id);
    const res = await get("/dashboard/billing", s.cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect(await s.flashes()).toEqual([
      {
        category: "warning",
        message: "You don't have any active subscription",
      },
    ]);
  });

  it("renders the active-subscription page with plan name and csrf form", async () => {
    const user = await createUser(env.DB);
    await createPaddleSub(user.id);
    const s = await webSession(user.id);
    const res = await get("/dashboard/billing", s.cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("<b>Monthly</b>");
    expect(html).toContain("Update billing information");
    expect(html).toContain("https://paddle.example/update");
    expect(html).toContain("Change to Yearly Plan"); // monthly plan offers yearly
    expect(html).toMatch(
      /<input id="csrf_token" name="csrf_token" type="hidden" value="[^"]+">/,
    );
  });

  it("renders the cancelled branch with the end date and re-subscribe link", async () => {
    const user = await createUser(env.DB);
    await createPaddleSub(user.id, { cancelled: 1, plan: "yearly" });
    const s = await webSession(user.id);
    const html = await (await get("/dashboard/billing", s.cookie)).text();
    expect(html).toContain("You have canceled your subscription");
    expect(html).toContain(futureDateOnly(10));
    expect(html).toContain('href="/dashboard/pricing"');
  });

  it("rejects a POST with a bad CSRF token: Invalid request flash + redirect", async () => {
    const user = await createUser(env.DB);
    await createPaddleSub(user.id);
    const s = await webSession(user.id);
    const res = await post("/dashboard/billing", s.cookie, {
      csrf_token: "garbage",
      "form-name": "cancel",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/billing");
    expect(await s.flashes()).toEqual([
      { category: "warning", message: "Invalid request" },
    ]);
  });

  it("POST cancel without Paddle credentials flashes the generic error and keeps the row", async () => {
    const user = await createUser(env.DB);
    const subId = await createPaddleSub(user.id);
    const s = await webSession(user.id);
    const res = await post("/dashboard/billing", s.cookie, {
      csrf_token: await s.csrfToken(),
      "form-name": "cancel",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/billing");
    const flashes = await s.flashes();
    expect(flashes).toHaveLength(1);
    expect(flashes[0].category).toBe("error");
    expect(flashes[0].message).toContain("Something went wrong");
    const row = await env.DB.prepare(
      "SELECT cancelled, plan FROM subscription WHERE id = ?1",
    )
      .bind(subId)
      .first<{ cancelled: number; plan: string }>();
    expect(row).toEqual({ cancelled: 0, plan: "monthly" }); // no DB mutation
  });
});

describe("GET /dashboard/pricing", () => {
  it("renders the pricing page with Paddle defaults (-1) for a free user", async () => {
    const user = await createUser(env.DB);
    const s = await webSession(user.id);
    const res = await get("/dashboard/pricing", s.cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Upgrade to unlock premium features");
    expect(html).toContain("Paddle.Setup({vendor: -1});");
    expect(html).toContain("upgradePaddle(-1)");
    expect(html).toContain("/dashboard/subscription_success");
  });

  it("redirects lifetime users away", async () => {
    const user = await createUser(env.DB, { lifetime: 1 });
    const s = await webSession(user.id);
    const res = await get("/dashboard/pricing", s.cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect(await s.flashes()).toEqual([
      {
        category: "error",
        message: "You already have a lifetime subscription",
      },
    ]);
  });

  it("redirects users with an active (non-cancelled) Paddle subscription", async () => {
    const user = await createUser(env.DB);
    await createPaddleSub(user.id);
    const s = await webSession(user.id);
    const res = await get("/dashboard/pricing", s.cookie);
    expect(res.status).toBe(302);
    expect(await s.flashes()).toEqual([
      { category: "error", message: "You already have an active subscription" },
    ]);
  });

  it("lets a cancelled-but-paid Paddle subscriber re-subscribe (alert shown)", async () => {
    const user = await createUser(env.DB);
    await createPaddleSub(user.id, { cancelled: 1 });
    const s = await webSession(user.id);
    const res = await get("/dashboard/pricing", s.cookie);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("You have an active subscription until");
  });

  it("redirects partner-subscribed users with the partner name in the flash", async () => {
    const user = await createUser(env.DB);
    const partnerId = await insert("partner", {
      name: `Partner${seq + 1}`,
      contact_email: `partner${++seq}@example.com`,
    });
    const partnerName = `Partner${seq}`;
    const puId = await insert("partner_user", {
      user_id: user.id,
      partner_id: partnerId,
      external_user_id: `ext-${seq}`,
    });
    await insert("partner_subscription", {
      partner_user_id: puId,
      end_at: null,
      lifetime: 1,
    });
    const s = await webSession(user.id);
    const res = await get("/dashboard/pricing", s.cookie);
    expect(res.status).toBe(302);
    expect(await s.flashes()).toEqual([
      {
        category: "error",
        message: `You already have a subscription provided by ${partnerName}`,
      },
    ]);
  });
});

describe("GET /dashboard/subscription_success", () => {
  it("renders the thank-you page", async () => {
    const user = await createUser(env.DB);
    const s = await webSession(user.id);
    const res = await get("/dashboard/subscription_success", s.cookie);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      "Thanks so much for supporting SimpleLogin!",
    );
  });
});

describe("GET|POST /dashboard/coupon", () => {
  it("renders the redeem form and the 1-year coupon card (PADDLE_COUPON_ID=None)", async () => {
    const user = await createUser(env.DB);
    const s = await webSession(user.id);
    const res = await get("/dashboard/coupon", s.cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('placeholder="Coupon Code"');
    expect(html).toContain('data-product="None"');
    expect(html).toContain("The coupon must be used before");
  });

  it("hides the redeem form when the user already has a Paddle sub (even cancelled)", async () => {
    const user = await createUser(env.DB);
    await createPaddleSub(user.id, { cancelled: 1 });
    const s = await webSession(user.id);
    const html = await (await get("/dashboard/coupon", s.cookie)).text();
    expect(html).not.toContain('placeholder="Coupon Code"');
    expect(html).toContain("1-year coupon"); // buy card is unconditional
  });

  it("redeems a valid coupon: manual subscription created + success flash rendered", async () => {
    const user = await createUser(env.DB);
    const code = `coupon-${++seq}`;
    await insert("coupon", { code, nb_year: 2 });
    const s = await webSession(user.id);
    const res = await post("/dashboard/coupon", s.cookie, {
      csrf_token: await s.csrfToken(),
      code,
    });
    expect(res.status).toBe(200); // no redirect — same render as GET
    const html = await res.text();
    expect(html).toContain(
      "Your account has been upgraded to Premium, thanks for your support!",
    );
    const coupon = await env.DB.prepare(
      "SELECT used, used_by_user_id FROM coupon WHERE code = ?1",
    )
      .bind(code)
      .first<{ used: number; used_by_user_id: number }>();
    expect(coupon).toEqual({ used: 1, used_by_user_id: user.id });
    const manual = await env.DB.prepare(
      "SELECT end_at, comment, is_giveaway FROM manual_subscription WHERE user_id = ?1",
    )
      .bind(user.id)
      .first<{ end_at: string; comment: string; is_giveaway: number }>();
    expect(manual?.comment).toBe("using coupon code");
    // end_at ~ now + 2 years + 1 day
    const expectedYear = new Date().getUTCFullYear() + 2;
    expect(manual?.end_at.slice(0, 4)).toBe(String(expectedYear));
  });

  it("flashes a warning for an already-used coupon", async () => {
    const user = await createUser(env.DB);
    const code = `coupon-${++seq}`;
    await insert("coupon", { code, used: 1 });
    const s = await webSession(user.id);
    const res = await post("/dashboard/coupon", s.cookie, {
      csrf_token: await s.csrfToken(),
      code,
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      "This coupon cannot be redeemed. It&#39;s invalid or has expired",
    );
  });

  it("flashes a warning when the user has an active non-manual subscription", async () => {
    const user = await createUser(env.DB);
    await createPaddleSub(user.id);
    const code = `coupon-${++seq}`;
    await insert("coupon", { code });
    const s = await webSession(user.id);
    const res = await post("/dashboard/coupon", s.cookie, {
      csrf_token: await s.csrfToken(),
      code,
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      "You have an active subscription. Please remove it before redeeming a coupon",
    );
    const coupon = await env.DB.prepare(
      "SELECT used FROM coupon WHERE code = ?1",
    )
      .bind(code)
      .first<{ used: number }>();
    expect(coupon?.used).toBe(0);
  });

  it("shows the DataRequired error when the code is empty", async () => {
    const user = await createUser(env.DB);
    const s = await webSession(user.id);
    const res = await post("/dashboard/coupon", s.cookie, {
      csrf_token: await s.csrfToken(),
      code: "",
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("This field is required.");
  });

  it("silently re-renders (no redemption) on a CSRF failure", async () => {
    const user = await createUser(env.DB);
    const code = `coupon-${++seq}`;
    await insert("coupon", { code });
    const s = await webSession(user.id);
    const res = await post("/dashboard/coupon", s.cookie, {
      csrf_token: "tampered",
      code,
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    // no flash at all — neither the success nor any of the failure messages
    expect(html).not.toContain("Your account has been upgraded to Premium");
    expect(html).not.toContain("This coupon cannot be redeemed");
    expect(html).not.toContain("You have an active subscription");
    const coupon = await env.DB.prepare(
      "SELECT used FROM coupon WHERE code = ?1",
    )
      .bind(code)
      .first<{ used: number }>();
    expect(coupon?.used).toBe(0);
  });

  it("extends an active manual sub ending Feb 29 to Feb 28 (arrow year clamping)", async () => {
    const user = await createUser(env.DB);
    // next Feb 29 strictly in the future (leap years are >= 4 apart, so the
    // following year never has one)
    let leapYear = new Date().getUTCFullYear() + 1;
    while (
      !((leapYear % 4 === 0 && leapYear % 100 !== 0) || leapYear % 400 === 0)
    ) {
      leapYear++;
    }
    await insert("manual_subscription", {
      user_id: user.id,
      end_at: `${leapYear}-02-29 12:00:00+00:00`,
    });
    const code = `coupon-${++seq}`;
    await insert("coupon", { code, nb_year: 1 });
    const s = await webSession(user.id);
    const res = await post("/dashboard/coupon", s.cookie, {
      csrf_token: await s.csrfToken(),
      code,
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      "Your account has been upgraded to Premium, thanks for your support!",
    );
    const row = await env.DB.prepare(
      "SELECT end_at FROM manual_subscription WHERE user_id = ?1",
    )
      .bind(user.id)
      .first<{ end_at: string }>();
    // arrow shift(years=1) clamps Feb 29 -> Feb 28, not Mar 1
    expect(row?.end_at).toBe(`${leapYear + 1}-02-28 12:00:00+00:00`);
  });

  it("redirects lifetime-coupon codes to the lifetime licence page", async () => {
    const user = await createUser(env.DB);
    const code = `lt-${++seq}`;
    await insert("lifetime_coupon", { code, nb_used: 5 });
    const s = await webSession(user.id);
    const res = await post("/dashboard/coupon", s.cookie, {
      csrf_token: await s.csrfToken(),
      code,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/lifetime_licence");
    expect(await s.flashes()).toEqual([
      {
        category: "success",
        message: "Redirect to the lifetime coupon page instead",
      },
    ]);
  });
});

describe("GET|POST /dashboard/lifetime_licence", () => {
  it("renders the licence form", async () => {
    const user = await createUser(env.DB);
    const s = await webSession(user.id);
    const res = await get("/dashboard/lifetime_licence", s.cookie);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('placeholder="Licence Code"');
  });

  it("404s on the hyphen spelling /lifetime-licence (route does not exist in Flask)", async () => {
    const user = await createUser(env.DB);
    const s = await webSession(user.id);
    const res = await get("/dashboard/lifetime-licence", s.cookie);
    expect(res.status).toBe(404);
    expect(await res.text()).toContain("This page does not exist.");
  });

  it("redirects lifetime users with a warning", async () => {
    const user = await createUser(env.DB, { lifetime: 1 });
    const s = await webSession(user.id);
    const res = await get("/dashboard/lifetime_licence", s.cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect(await s.flashes()).toEqual([
      { category: "warning", message: "You already have a lifetime licence" },
    ]);
  });

  it("redirects users with an active Paddle subscription", async () => {
    const user = await createUser(env.DB);
    await createPaddleSub(user.id);
    const s = await webSession(user.id);
    const res = await get("/dashboard/lifetime_licence", s.cookie);
    expect(res.status).toBe(302);
    expect(await s.flashes()).toEqual([
      {
        category: "warning",
        message: "Please cancel your current subscription first",
      },
    ]);
  });

  it("upgrades the user on a valid licence code and decrements nb_used", async () => {
    const user = await createUser(env.DB);
    const code = `lt-${++seq}`;
    await insert("lifetime_coupon", { code, nb_used: 3, paid: 1 });
    const s = await webSession(user.id);
    const res = await post("/dashboard/lifetime_licence", s.cookie, {
      csrf_token: await s.csrfToken(),
      code,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect(await s.flashes()).toEqual([
      { category: "success", message: "You are upgraded to lifetime premium!" },
    ]);
    const u = await env.DB.prepare(
      "SELECT lifetime, paid_lifetime, lifetime_coupon_id FROM users WHERE id = ?1",
    )
      .bind(user.id)
      .first<{
        lifetime: number;
        paid_lifetime: number;
        lifetime_coupon_id: number;
      }>();
    expect(u?.lifetime).toBe(1);
    expect(u?.paid_lifetime).toBe(1);
    const lc = await env.DB.prepare(
      "SELECT nb_used, updated_at FROM lifetime_coupon WHERE code = ?1",
    )
      .bind(code)
      .first<{ nb_used: number; updated_at: string | null }>();
    expect(lc?.nb_used).toBe(2);
    // Flask's Core UPDATE stamps updated_at via the ModelMixin onupdate default
    expect(lc?.updated_at).toMatch(
      /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\+00:00$/,
    );
  });

  it("notifies the admin with the Flask User-repr subject (None for null fields)", async () => {
    const user = await createUser(env.DB); // name is NULL -> "None"
    const code = `lt-${++seq}`;
    await insert("lifetime_coupon", { code, nb_used: 2, comment: null });
    const s = await webSession(user.id);
    sentEmails.length = 0;

    // ADMIN_EMAIL is not part of the test bindings — dispatch directly with
    // an extended env (same isolate, same D1/KV instances as SELF).
    const adminEnv = { ...env, ADMIN_EMAIL: "admin@sl.example.com" };
    const ctx = createExecutionContext();
    const res = await worker.fetch(
      new Request(`${B}/dashboard/lifetime_licence`, {
        method: "POST",
        headers: {
          Cookie: s.cookie,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          csrf_token: await s.csrfToken(),
          code,
        }).toString(),
        redirect: "manual",
      }),
      adminEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].to).toBe("admin@sl.example.com");
    // f"User {user} ..." uses User.__repr__ = "<User {id} {name} {email}>";
    // Python None renders as "None" (both name and comment here).
    expect(sentEmails[0].subject).toBe(
      `User <User ${user.id} None ${user.email}> used lifetime coupon(None). Coupon nb_used: 1`,
    );
  });

  it("re-renders with a warning on an invalid code", async () => {
    const user = await createUser(env.DB);
    const s = await webSession(user.id);
    const res = await post("/dashboard/lifetime_licence", s.cookie, {
      csrf_token: await s.csrfToken(),
      code: "does-not-exist",
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Coupon code expired or invalid");
  });
});

describe("GET|POST /dashboard/referral", () => {
  it("renders the empty state", async () => {
    const user = await createUser(env.DB);
    const s = await webSession(user.id);
    const res = await get("/dashboard/referral", s.cookie);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("You don't have any referral code yet");
  });

  it("creates a referral and redirects with highlight_id", async () => {
    const user = await createUser(env.DB);
    const s = await webSession(user.id);
    const code = `ref-code-${++seq}`;
    const res = await post("/dashboard/referral", s.cookie, {
      "form-name": "create",
      code,
      name: "my referral",
    });
    expect(res.status).toBe(302);
    const row = await env.DB.prepare(
      "SELECT id, user_id, name FROM referral WHERE code = ?1",
    )
      .bind(code)
      .first<{ id: number; user_id: number; name: string }>();
    expect(row?.user_id).toBe(user.id);
    expect(row?.name).toBe("my referral");
    expect(res.headers.get("location")).toBe(
      `/dashboard/referral?highlight_id=${row?.id}`,
    );
    expect(await s.flashes()).toEqual([
      { category: "success", message: "A new referral code has been created" },
    ]);

    // the created referral renders with its share link
    const html = await (await get("/dashboard/referral", s.cookie)).text();
    expect(html).toContain(`?slref=${code}`);
    expect(html).toContain(`https://simplelogin.io?slref=${code}`);
  });

  it("rejects an invalid referral code with the pattern flash", async () => {
    const user = await createUser(env.DB);
    const s = await webSession(user.id);
    const res = await post("/dashboard/referral", s.cookie, {
      "form-name": "create",
      code: "AB",
      name: "x",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/referral");
    expect(await s.flashes()).toEqual([
      {
        category: "error",
        message:
          "At least 3 characters. Only lowercase letters, numbers, " +
          "dashes (-) and underscores (_) are currently supported.",
      },
    ]);
  });

  it("rejects a duplicate referral code (any user's)", async () => {
    const owner = await createUser(env.DB);
    const other = await createUser(env.DB);
    const code = `dup-code-${++seq}`;
    await insert("referral", { user_id: owner.id, code, name: null });
    const s = await webSession(other.id);
    const res = await post("/dashboard/referral", s.cookie, {
      "form-name": "create",
      code,
      name: "x",
    });
    expect(res.status).toBe(302);
    expect(await s.flashes()).toEqual([
      { category: "error", message: "Code already used" },
    ]);
  });

  it("updates own referral name; a foreign referral falls through to a 200 render", async () => {
    const owner = await createUser(env.DB);
    const attacker = await createUser(env.DB);
    const code = `upd-code-${++seq}`;
    const refId = await insert("referral", {
      user_id: owner.id,
      code,
      name: "before",
    });

    // foreign update: no change, 200 render, no flash
    const sa = await webSession(attacker.id);
    const res1 = await post("/dashboard/referral", sa.cookie, {
      "form-name": "update",
      "referral-id": String(refId),
      name: "hacked",
    });
    expect(res1.status).toBe(200);
    expect(await sa.flashes()).toEqual([]);
    let row = await env.DB.prepare("SELECT name FROM referral WHERE id = ?1")
      .bind(refId)
      .first<{ name: string }>();
    expect(row?.name).toBe("before");

    // owner update: renamed + redirect with highlight
    const so = await webSession(owner.id);
    const res2 = await post("/dashboard/referral", so.cookie, {
      "form-name": "update",
      "referral-id": String(refId),
      name: "after",
    });
    expect(res2.status).toBe(302);
    expect(res2.headers.get("location")).toBe(
      `/dashboard/referral?highlight_id=${refId}`,
    );
    expect(await so.flashes()).toEqual([
      { category: "success", message: "Referral name updated" },
    ]);
    row = await env.DB.prepare("SELECT name FROM referral WHERE id = ?1")
      .bind(refId)
      .first<{ name: string }>();
    expect(row?.name).toBe("after");
  });

  it("deletes own referral", async () => {
    const user = await createUser(env.DB);
    const refId = await insert("referral", {
      user_id: user.id,
      code: `del-code-${++seq}`,
      name: null,
    });
    const s = await webSession(user.id);
    const res = await post("/dashboard/referral", s.cookie, {
      "form-name": "delete",
      "referral-id": String(refId),
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/referral");
    expect(await s.flashes()).toEqual([
      { category: "success", message: "Referral deleted" },
    ]);
    const row = await env.DB.prepare("SELECT id FROM referral WHERE id = ?1")
      .bind(refId)
      .first();
    expect(row).toBeNull();
  });
});

describe("GET /dashboard/support", () => {
  it("redirects with 'Support isn't enabled' when ZENDESK_HOST is unset", async () => {
    const user = await createUser(env.DB);
    const s = await webSession(user.id);
    const res = await get("/dashboard/support", s.cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect(await s.flashes()).toEqual([
      { category: "error", message: "Support isn't enabled" },
    ]);
  });
});

describe("GET|POST /dashboard/app", () => {
  async function createClientUser(
    user: UserRow,
    clientName: string,
  ): Promise<number> {
    const clientId = await insert("client", {
      name: clientName,
      user_id: user.id,
      oauth_client_id: `oc-${++seq}`,
      oauth_client_secret: "secret",
    });
    return insert("client_user", {
      user_id: user.id,
      client_id: clientId,
    });
  }

  it("renders the (empty) apps table", async () => {
    const user = await createUser(env.DB);
    const s = await webSession(user.id);
    const res = await get("/dashboard/app", s.cookie);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Sign in with SimpleLogin");
  });

  it("lists authorized apps with the real email when no alias is linked", async () => {
    const user = await createUser(env.DB);
    await createClientUser(user, "DemoApp");
    const s = await webSession(user.id);
    const html = await (await get("/dashboard/app", s.cookie)).text();
    expect(html).toContain("DemoApp");
    expect(html).toContain(`mailto:${user.email}`);
  });

  it("revokes an app (flash keeps Flask's double space) and redirects", async () => {
    const user = await createUser(env.DB);
    const cuId = await createClientUser(user, "RevokeMe");
    const s = await webSession(user.id);
    const res = await post("/dashboard/app", s.cookie, {
      "client-user-id": String(cuId),
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/app");
    expect(await s.flashes()).toEqual([
      { category: "success", message: "Link with RevokeMe  has been removed" },
    ]);
    const row = await env.DB.prepare("SELECT id FROM client_user WHERE id = ?1")
      .bind(cuId)
      .first();
    expect(row).toBeNull();
  });

  it("flashes the unknown-error message for a foreign client_user", async () => {
    const owner = await createUser(env.DB);
    const attacker = await createUser(env.DB);
    const cuId = await createClientUser(owner, "NotYours");
    const s = await webSession(attacker.id);
    const res = await post("/dashboard/app", s.cookie, {
      "client-user-id": String(cuId),
    });
    expect(res.status).toBe(302);
    expect(await s.flashes()).toEqual([
      {
        category: "error",
        message: "Unknown error, sorry for the inconvenience, refresh the page",
      },
    ]);
    const row = await env.DB.prepare("SELECT id FROM client_user WHERE id = ?1")
      .bind(cuId)
      .first();
    expect(row).not.toBeNull();
  });
});

describe("GET /dashboard/setup_done", () => {
  it("sets the setup_done cookie and redirects to the dashboard", async () => {
    const user = await createUser(env.DB);
    const s = await webSession(user.id);
    const res = await get("/dashboard/setup_done", s.cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain("setup_done=true");
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Lax");
  });
});

describe("GET /dashboard/enter_admin", () => {
  it("404s unconditionally (WebAuthn admin gate not ported)", async () => {
    const user = await createUser(env.DB);
    const s = await webSession(user.id);
    const res = await get("/dashboard/enter_admin", s.cookie);
    expect(res.status).toBe(404);
    expect(await res.text()).toContain("This page does not exist.");
  });
});
