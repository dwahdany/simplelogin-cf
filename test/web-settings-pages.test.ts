/**
 * Web settings + security pages (specs/web/04-settings-security-pages.md).
 *
 * Covers, per route: anonymous gating (302 -> /auth/login?next=...), sudo
 * gating (302 -> /dashboard/enter_sudo?next=<path>), GET renders, POST happy
 * paths (DB effect + redirect + flash in the KV session), validation
 * failures and CSRF rejections.
 */

import { env, SELF } from "cloudflare:test";
import { Secret, TOTP } from "otpauth";
import { beforeEach, describe, expect, it } from "vitest";
import { hashPassword } from "../src/lib/crypto";
import { sentEmails } from "../src/lib/mailer";
import type { UserRow } from "../src/lib/rows";
import {
  createAlias,
  createApiKey,
  createContact,
  createUser,
} from "./fixtures";

const BASE = "https://sl.test";

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

async function webSession(
  user: UserRow,
  opts: { sudo?: boolean } = {},
): Promise<string> {
  const token = crypto.randomUUID().replaceAll("-", "");
  const data: Record<string, unknown> = {
    user_id: user.id,
    alternative_id: user.alternative_id ?? undefined,
  };
  if (opts.sudo) data.sudo_time = Math.floor(Date.now() / 1000);
  await env.KV.put(`session:${token}`, JSON.stringify(data));
  return `slapp=${token}`;
}

function get(
  path: string,
  cookie?: string,
  headers: Record<string, string> = {},
): Promise<Response> {
  return SELF.fetch(`${BASE}${path}`, {
    headers: { ...(cookie ? { Cookie: cookie } : {}), ...headers },
    redirect: "manual",
  });
}

function post(
  path: string,
  cookie: string,
  fields: Record<string, string>,
  headers: Record<string, string> = {},
): Promise<Response> {
  return SELF.fetch(`${BASE}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Cookie: cookie,
      ...headers,
    },
    body: new URLSearchParams(fields).toString(),
    redirect: "manual",
  });
}

/** GET the page and pull the signed csrf token out of the hidden field. */
async function getCsrf(path: string, cookie: string): Promise<string> {
  const res = await get(path, cookie);
  const html = await res.text();
  const m = html.match(/name="csrf_token" type="hidden" value="([^"]+)"/);
  if (!m) throw new Error(`no csrf token on ${path} (status ${res.status})`);
  return m[1];
}

/** Pending flash messages stored in the KV session for this cookie. */
async function flashes(
  cookie: string,
): Promise<Array<{ category: string; message: string }>> {
  const token = cookie.split("=")[1];
  const raw = await env.KV.get(`session:${token}`);
  if (!raw) return [];
  return (JSON.parse(raw).flashes ?? []) as Array<{
    category: string;
    message: string;
  }>;
}

function userRow(id: number): Promise<UserRow | null> {
  return env.DB.prepare("SELECT * FROM users WHERE id = ?1")
    .bind(id)
    .first<UserRow>();
}

beforeEach(() => {
  sentEmails.length = 0;
});

// --------------------------------------------------------------------------
// auth + sudo gating
// --------------------------------------------------------------------------

describe("auth gating", () => {
  it("redirects anonymous users to login with next=<full_path>", async () => {
    for (const path of [
      "/dashboard/setting",
      "/dashboard/api_key",
      "/dashboard/enter_sudo",
      "/dashboard/notifications",
      "/dashboard/mfa_setup",
      "/dashboard/delete_account",
    ]) {
      const res = await get(path);
      expect(res.status).toBe(302);
      expect(res.headers.get("location")).toBe(
        `/auth/login?next=${encodeURIComponent(`${path}?`)}`,
      );
    }
  });

  it("redirects sudo-gated pages to enter_sudo with next=<path only>", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user); // no sudo_time
    const res = await get("/dashboard/account_setting?foo=bar", cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      "/dashboard/enter_sudo?next=%2Fdashboard%2Faccount_setting",
    );
  });

  it("lets a sudo-fresh session through", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const res = await get("/dashboard/account_setting", cookie);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Account Email");
  });
});

// --------------------------------------------------------------------------
// 1. /dashboard/setting
// --------------------------------------------------------------------------

describe("GET/POST /dashboard/setting", () => {
  it("renders the settings page with all form-name blocks", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user);
    const res = await get("/dashboard/setting", cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toMatch(/<title>\s*Settings\s*\| SimpleLogin\s*<\/title>/);
    expect(html).toContain("Current Plan");
    // fixture users are in trial
    expect(html).toContain("Your Premium trial expires");
    for (const formName of [
      "notification-preference",
      "update-profile",
      "change-alias-generator",
      "change-random-alias-default-domain",
      "random-alias-suffix",
      "enable_data_breach_check",
      "change-sender-format",
      "replace-ra",
      "sender-in-ra",
      "expand-alias-info",
      "one-click-unsubscribe",
      "include_website_in_one_click_alias",
      "change-blocked-behaviour",
      "sender-header",
      "alias-delete-action",
    ]) {
      expect(html).toContain(`value="${formName}"`);
    }
  });

  it("updates the newsletter preference (happy path)", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user);
    const csrf = await getCsrf("/dashboard/setting", cookie);
    // fixture default notification=1; posting without checkbox = off
    const res = await post("/dashboard/setting", cookie, {
      csrf_token: csrf,
      "form-name": "notification-preference",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/setting");
    expect((await userRow(user.id))?.notification).toBe(0);
    expect(await flashes(cookie)).toEqual([
      {
        category: "success",
        message: "Your notification preference has been updated",
      },
    ]);
  });

  it("rejects a POST without a CSRF token", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user);
    const res = await post("/dashboard/setting", cookie, {
      "form-name": "notification-preference",
      notification: "on",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/setting");
    expect(await flashes(cookie)).toEqual([
      { category: "warning", message: "Invalid request" },
    ]);
    // no write happened
    expect((await userRow(user.id))?.notification).toBe(1);
  });

  it("updates the profile name and flashes", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user);
    const csrf = await getCsrf("/dashboard/setting", cookie);
    const res = await post("/dashboard/setting", cookie, {
      csrf_token: csrf,
      "form-name": "update-profile",
      name: "New Name",
    });
    expect(res.status).toBe(302);
    expect((await userRow(user.id))?.name).toBe("New Name");
    expect(await flashes(cookie)).toEqual([
      { category: "success", message: "Your profile has been updated" },
    ]);
  });

  it("re-renders (200, no flash) when the profile did not change", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user);
    const csrf = await getCsrf("/dashboard/setting", cookie);
    const res = await post("/dashboard/setting", cookie, {
      csrf_token: csrf,
      "form-name": "update-profile",
      name: "",
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).not.toContain("Your profile has been updated");
  });

  it("change-blocked-behaviour writes and falls through to a 200 render", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user);
    const csrf = await getCsrf("/dashboard/setting", cookie);
    const res = await post("/dashboard/setting", cookie, {
      csrf_token: csrf,
      "form-name": "change-blocked-behaviour",
      "blocked-behaviour": "1",
    });
    expect(res.status).toBe(200); // Flask bug parity: no redirect
    expect((await userRow(user.id))?.block_behaviour).toBe("return_5xx");
    // the flash renders on this very response
    expect(await res.text()).toContain("Your preference has been updated");
  });

  it("random-alias-suffix rejects non-numeric values with an error flash", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user);
    const csrf = await getCsrf("/dashboard/setting", cookie);
    const res = await post("/dashboard/setting", cookie, {
      csrf_token: csrf,
      "form-name": "random-alias-suffix",
      "random-alias-suffix-generator": "abc",
    });
    expect(res.status).toBe(302);
    expect(await flashes(cookie)).toEqual([
      { category: "error", message: "Invalid value" },
    ]);
  });

  it("data breach monitoring is premium-gated", async () => {
    // trial users ARE premium; use an expired trial
    const user = await createUser(env.DB, {
      trial_end: "2020-01-01 00:00:00+00:00",
    });
    const cookie = await webSession(user);
    const csrf = await getCsrf("/dashboard/setting", cookie);
    const res = await post("/dashboard/setting", cookie, {
      csrf_token: csrf,
      "form-name": "enable_data_breach_check",
      enable_data_breach_check: "on",
    });
    expect(res.status).toBe(302);
    expect((await userRow(user.id))?.enable_data_breach_check).toBe(0);
    expect(await flashes(cookie)).toEqual([
      {
        category: "warning",
        message: "Only premium plan can enable data breach monitoring",
      },
    ]);
  });

  it("one-click-unsubscribe accepts enum NAMES and rejects unknown values", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user);
    const csrf = await getCsrf("/dashboard/setting", cookie);
    let res = await post("/dashboard/setting", cookie, {
      csrf_token: csrf,
      "form-name": "one-click-unsubscribe",
      "unsubscribe-behaviour": "DisableAlias",
    });
    expect(res.status).toBe(302);
    expect((await userRow(user.id))?.unsub_behaviour).toBe(0);
    expect((await flashes(cookie)).pop()?.message).toBe(
      "Your preference has been updated",
    );

    const csrf2 = await getCsrf("/dashboard/setting", cookie);
    res = await post("/dashboard/setting", cookie, {
      csrf_token: csrf2,
      "form-name": "one-click-unsubscribe",
      "unsubscribe-behaviour": "Bogus",
    });
    expect(res.status).toBe(302);
    expect((await flashes(cookie)).pop()).toEqual({
      category: "warning",
      message: "There was an error. Please try again",
    });
  });

  it("change-random-alias-default-domain rejects unknown domains", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user);
    const csrf = await getCsrf("/dashboard/setting", cookie);
    const res = await post("/dashboard/setting", cookie, {
      csrf_token: csrf,
      "form-name": "change-random-alias-default-domain",
      "random-alias-default-domain": "nope.example.com",
    });
    expect(res.status).toBe(302);
    expect((await flashes(cookie)).pop()).toEqual({
      category: "error",
      message: "Domain does not exist or it hasn't been verified",
    });
  });
});

// --------------------------------------------------------------------------
// 2. /dashboard/account_setting
// --------------------------------------------------------------------------

describe("GET/POST /dashboard/account_setting", () => {
  it("creates a pending email change and emails the NEW address", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/account_setting", cookie);
    const res = await post("/dashboard/account_setting", cookie, {
      csrf_token: csrf,
      "form-name": "update-email",
      email: "new-inbox@other.example",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/account_setting");
    const ec = await env.DB.prepare(
      "SELECT * FROM email_change WHERE user_id = ?1",
    )
      .bind(user.id)
      .first<{ new_email: string; code: string }>();
    expect(ec?.new_email).toBe("new-inbox@other.example");
    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].to).toBe("new-inbox@other.example");
    expect(sentEmails[0].subject).toBe("Confirm email update on SimpleLogin");
    expect(sentEmails[0].text).toContain(`/auth/change_email?code=${ec?.code}`);
    expect((await flashes(cookie)).pop()?.message).toBe(
      "A confirmation email is on the way, please check your inbox",
    );
  });

  it("shows field errors for an invalid email (200 re-render)", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/account_setting", cookie);
    const res = await post("/dashboard/account_setting", cookie, {
      csrf_token: csrf,
      "form-name": "update-email",
      email: "not-an-email",
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Invalid email address.");
    expect(sentEmails).toHaveLength(0);
  });

  it("rejects an email already used by another account", async () => {
    const other = await createUser(env.DB);
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/account_setting", cookie);
    const res = await post("/dashboard/account_setting", cookie, {
      csrf_token: csrf,
      "form-name": "update-email",
      email: other.email,
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(`Email ${other.email} already used`);
  });

  it("CSRF failure flashes Invalid request and redirects to /dashboard/setting", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const res = await post("/dashboard/account_setting", cookie, {
      "form-name": "change-password",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/setting");
    expect(await flashes(cookie)).toEqual([
      { category: "warning", message: "Invalid request" },
    ]);
  });

  it("change-password creates a reset code and sends the email", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/account_setting", cookie);
    const res = await post("/dashboard/account_setting", cookie, {
      csrf_token: csrf,
      "form-name": "change-password",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/account_setting");
    const code = await env.DB.prepare(
      "SELECT code FROM reset_password_code WHERE user_id = ?1",
    )
      .bind(user.id)
      .first<{ code: string }>();
    expect(code).not.toBeNull();
    expect(sentEmails[0].subject).toBe("Reset your password on SimpleLogin");
    expect(sentEmails[0].text).toContain(
      `/auth/reset_password?code=${code?.code}`,
    );
    expect((await flashes(cookie)).pop()?.message).toBe(
      "You are going to receive an email containing instructions to change your password",
    );
  });

  it("send-full-user-report creates a job once, then dedupes (200 render)", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/account_setting", cookie);
    let res = await post("/dashboard/account_setting", cookie, {
      csrf_token: csrf,
      "form-name": "send-full-user-report",
    });
    expect(res.status).toBe(200); // no redirect — re-render
    expect(await res.text()).toContain(
      "You will receive your SimpleLogin data via email shortly",
    );
    const job = await env.DB.prepare(
      "SELECT * FROM job WHERE name = 'send-user-report'",
    ).first<{ payload: string }>();
    expect(JSON.parse(job?.payload ?? "{}")).toEqual({ user_id: user.id });

    res = await post("/dashboard/account_setting", cookie, {
      csrf_token: csrf,
      "form-name": "send-full-user-report",
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      "An export of your data is currently in progress",
    );
  });
});

// --------------------------------------------------------------------------
// 3./4. resend / cancel email change
// --------------------------------------------------------------------------

describe("resend_email_change / cancel_email_change", () => {
  async function pendingChange(userId: number): Promise<string> {
    const newEmail = `pending-${crypto.randomUUID().slice(0, 8)}@other.example`;
    await env.DB.prepare(
      `INSERT INTO email_change (user_id, new_email, code, expired)
       VALUES (?1, ?2, ?3, '2999-01-01 00:00:00+00:00')`,
    )
      .bind(userId, newEmail, `code-${crypto.randomUUID()}`)
      .run();
    return newEmail;
  }

  it("GET resend always fails CSRF and redirects to /dashboard/setting", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const res = await get("/dashboard/resend_email_change", cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/setting");
    expect(await flashes(cookie)).toEqual([
      { category: "warning", message: "Invalid request. Please try again" },
    ]);
  });

  it("POST resend re-sends the confirmation email", async () => {
    const user = await createUser(env.DB);
    const pendingEmail = await pendingChange(user.id);
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/account_setting", cookie);
    const res = await post("/dashboard/resend_email_change", cookie, {
      csrf_token: csrf,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/account_setting");
    expect(sentEmails[0].to).toBe(pendingEmail);
    expect((await flashes(cookie)).pop()?.message).toBe(
      "A confirmation email is on the way, please check your inbox",
    );
  });

  it("POST cancel deletes the pending change", async () => {
    const user = await createUser(env.DB);
    await pendingChange(user.id);
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/account_setting", cookie);
    const res = await post("/dashboard/cancel_email_change", cookie, {
      csrf_token: csrf,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/account_setting");
    const row = await env.DB.prepare(
      "SELECT 1 FROM email_change WHERE user_id = ?1",
    )
      .bind(user.id)
      .first();
    expect(row).toBeNull();
    expect((await flashes(cookie)).pop()?.message).toBe(
      "Your email change is cancelled",
    );
  });

  it("POST cancel without a pending change flashes the warning", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/account_setting", cookie);
    const res = await post("/dashboard/cancel_email_change", cookie, {
      csrf_token: csrf,
    });
    expect(res.status).toBe(302);
    expect((await flashes(cookie)).pop()?.message).toBe(
      "You have no pending email change. Redirect back to Setting page",
    );
  });
});

// --------------------------------------------------------------------------
// 5. unlink_proton_account
// --------------------------------------------------------------------------

describe("POST /dashboard/unlink_proton_account", () => {
  it("unlinks a linked Proton account", async () => {
    const user = await createUser(env.DB);
    await env.DB.prepare(
      "INSERT INTO partner (name, contact_email) VALUES ('Proton', 'proton@example.com')",
    ).run();
    await env.DB.prepare(
      `INSERT INTO partner_user (user_id, partner_id, external_user_id, partner_email)
       VALUES (?1, (SELECT id FROM partner WHERE name = 'Proton'), 'ext-1', 'p@proton.me')`,
    )
      .bind(user.id)
      .run();
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/account_setting", cookie);
    const res = await post("/dashboard/unlink_proton_account", cookie, {
      csrf_token: csrf,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/account_setting");
    const pu = await env.DB.prepare(
      "SELECT 1 FROM partner_user WHERE user_id = ?1",
    )
      .bind(user.id)
      .first();
    expect(pu).toBeNull();
    expect((await flashes(cookie)).pop()?.message).toBe(
      "Your Proton account has been unlinked",
    );
  });

  it("flashes Account cannot be unlinked for partner-created users", async () => {
    const user = await createUser(env.DB, { flags: 2 });
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/account_setting", cookie);
    const res = await post("/dashboard/unlink_proton_account", cookie, {
      csrf_token: csrf,
    });
    expect(res.status).toBe(302);
    expect((await flashes(cookie)).pop()?.message).toBe(
      "Account cannot be unlinked",
    );
  });

  it("500s when the user was never linked (Flask bug parity)", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/account_setting", cookie);
    const res = await post("/dashboard/unlink_proton_account", cookie, {
      csrf_token: csrf,
    });
    expect(res.status).toBe(500);
  });
});

// --------------------------------------------------------------------------
// 6. /dashboard/api_key
// --------------------------------------------------------------------------

describe("GET/POST /dashboard/api_key", () => {
  it("lists keys with masked values", async () => {
    const user = await createUser(env.DB);
    const key = await createApiKey(env.DB, user.id);
    await env.DB.prepare("UPDATE api_key SET name = 'Chrome' WHERE id = ?1")
      .bind(key.id)
      .run();
    const cookie = await webSession(user, { sudo: true });
    const res = await get("/dashboard/api_key", cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Chrome");
    expect(html).toContain("**********");
    expect(html).not.toContain(key.code); // secret never rendered on the list
  });

  it("create shows the secret once on new_api_key.html (200)", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/api_key", cookie);
    const res = await post("/dashboard/api_key", cookie, {
      csrf_token: csrf,
      "form-name": "create",
      name: "My Phone",
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("New API Key My Phone is created");
    const row = await env.DB.prepare(
      "SELECT code FROM api_key WHERE user_id = ?1 AND name = 'My Phone'",
    )
      .bind(user.id)
      .first<{ code: string }>();
    expect(row?.code).toHaveLength(60);
    expect(html).toContain(row?.code as string);
    expect(html).toContain("New API Key My Phone has been created");
  });

  it("create with an empty name silently redirects (lost error, Flask parity)", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/api_key", cookie);
    const res = await post("/dashboard/api_key", cookie, {
      csrf_token: csrf,
      "form-name": "create",
      name: "",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/api_key");
    expect(await flashes(cookie)).toEqual([]);
  });

  it("delete removes the key; other users' keys are protected", async () => {
    const user = await createUser(env.DB);
    const other = await createUser(env.DB);
    const mine = await createApiKey(env.DB, user.id);
    const theirs = await createApiKey(env.DB, other.id);
    const cookie = await webSession(user, { sudo: true });

    let csrf = await getCsrf("/dashboard/api_key", cookie);
    let res = await post("/dashboard/api_key", cookie, {
      csrf_token: csrf,
      "form-name": "delete",
      "api-key-id": String(theirs.id),
    });
    expect(res.status).toBe(302);
    expect((await flashes(cookie)).pop()?.message).toBe(
      "You cannot delete this api key",
    );

    csrf = await getCsrf("/dashboard/api_key", cookie);
    res = await post("/dashboard/api_key", cookie, {
      csrf_token: csrf,
      "form-name": "delete",
      "api-key-id": String(mine.id),
    });
    expect(res.status).toBe(302);
    // nameless key: Python prints the literal None
    expect((await flashes(cookie)).pop()?.message).toBe(
      "API Key None has been deleted",
    );
    const gone = await env.DB.prepare("SELECT 1 FROM api_key WHERE id = ?1")
      .bind(mine.id)
      .first();
    expect(gone).toBeNull();
  });

  it("delete-all wipes every key", async () => {
    const user = await createUser(env.DB);
    await createApiKey(env.DB, user.id);
    await createApiKey(env.DB, user.id);
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/api_key", cookie);
    const res = await post("/dashboard/api_key", cookie, {
      csrf_token: csrf,
      "form-name": "delete-all",
    });
    expect(res.status).toBe(302);
    const n = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM api_key WHERE user_id = ?1",
    )
      .bind(user.id)
      .first<{ n: number }>();
    expect(n?.n).toBe(0);
    expect((await flashes(cookie)).pop()?.message).toBe(
      "All API Keys have been deleted",
    );
  });
});

// --------------------------------------------------------------------------
// 7. /dashboard/enter_sudo
// --------------------------------------------------------------------------

describe("GET/POST /dashboard/enter_sudo", () => {
  it("grants sudo on the correct password and honors ?next=", async () => {
    const user = await createUser(env.DB, {
      password: await hashPassword("correct horse"),
    });
    const cookie = await webSession(user);
    const csrf = await getCsrf("/dashboard/enter_sudo", cookie);
    const res = await post(
      "/dashboard/enter_sudo?next=%2Fdashboard%2Faccount_setting",
      cookie,
      { csrf_token: csrf, password: "correct horse" },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/account_setting");
    const raw = await env.KV.get(`session:${cookie.split("=")[1]}`);
    expect(JSON.parse(raw ?? "{}").sudo_time).toBeGreaterThan(0);
  });

  it("rejects an unsafe next url and lands on the dashboard", async () => {
    const user = await createUser(env.DB, {
      password: await hashPassword("pw123456"),
    });
    const cookie = await webSession(user);
    const csrf = await getCsrf("/dashboard/enter_sudo", cookie);
    const res = await post(
      `/dashboard/enter_sudo?next=${encodeURIComponent("https://evil.example/x")}`,
      cookie,
      { csrf_token: csrf, password: "pw123456" },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
  });

  it("flashes Incorrect password and re-renders (200) on failure", async () => {
    const user = await createUser(env.DB, {
      password: await hashPassword("right"),
    });
    const cookie = await webSession(user);
    const csrf = await getCsrf("/dashboard/enter_sudo", cookie);
    const res = await post("/dashboard/enter_sudo", cookie, {
      csrf_token: csrf,
      password: "wrong",
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Incorrect password");
  });

  it("rate-limits at 3/minute including GETs (429 page)", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user);
    for (let i = 0; i < 3; i++) {
      expect((await get("/dashboard/enter_sudo", cookie)).status).toBe(200);
    }
    const res = await get("/dashboard/enter_sudo", cookie);
    expect(res.status).toBe(429);
    expect(await res.text()).toContain("Whoa, slow down there, pardner!");
  });
});

// --------------------------------------------------------------------------
// 8./9. mfa_setup / mfa_cancel
// --------------------------------------------------------------------------

describe("GET/POST /dashboard/mfa_setup", () => {
  it("generates an otp secret on GET and shows the provisioning URI", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const res = await get("/dashboard/mfa_setup", cookie);
    expect(res.status).toBe(200);
    const fresh = await userRow(user.id);
    expect(fresh?.otp_secret).toMatch(/^[A-Z2-7]{32}$/);
    const html = await res.text();
    expect(html).toContain("otpauth://totp/SimpleLogin:");
    expect(html).toContain(fresh?.otp_secret as string);
  });

  it("activates MFA with a valid token and shows 8 recovery codes", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/mfa_setup", cookie);
    const secret = (await userRow(user.id))?.otp_secret as string;
    const token = new TOTP({
      secret: Secret.fromBase32(secret),
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    }).generate();
    const res = await post("/dashboard/mfa_setup", cookie, {
      csrf_token: csrf,
      token,
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Recovery codes");
    expect(html).toContain("MFA has been activated");
    expect(html.match(/<li>[a-z]{8}<\/li>/g)).toHaveLength(8);
    const fresh = await userRow(user.id);
    expect(fresh?.enable_otp).toBe(1);
    expect(fresh?.last_otp).toBe(token);
    // alternative_id rotated but THIS session stays valid
    expect(fresh?.alternative_id).not.toBe(user.alternative_id);
    const again = await get("/dashboard/setting", cookie);
    expect(again.status).toBe(200);
    const codes = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM recovery_code WHERE user_id = ?1",
    )
      .bind(user.id)
      .first<{ n: number }>();
    expect(codes?.n).toBe(8);
  });

  it("flashes Incorrect token on a bad code", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/mfa_setup", cookie);
    const res = await post("/dashboard/mfa_setup", cookie, {
      csrf_token: csrf,
      token: "000000",
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Incorrect token");
    expect((await userRow(user.id))?.enable_otp).toBe(0);
  });

  it("redirects when MFA is already enabled", async () => {
    const user = await createUser(env.DB, {
      enable_otp: 1,
      otp_secret: "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP",
    });
    const cookie = await webSession(user, { sudo: true });
    const res = await get("/dashboard/mfa_setup", cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect((await flashes(cookie)).pop()?.message).toBe(
      "you have already enabled MFA",
    );
  });
});

describe("GET/POST /dashboard/mfa_cancel", () => {
  it("disables TOTP, wipes recovery codes, flashes a WARNING", async () => {
    const user = await createUser(env.DB, {
      enable_otp: 1,
      otp_secret: "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP",
    });
    await env.DB.prepare(
      "INSERT INTO recovery_code (user_id, code) VALUES (?1, 'x')",
    )
      .bind(user.id)
      .run();
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/mfa_cancel", cookie);
    const res = await post("/dashboard/mfa_cancel", cookie, {
      csrf_token: csrf,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    const fresh = await userRow(user.id);
    expect(fresh?.enable_otp).toBe(0);
    expect(fresh?.otp_secret).toBeNull();
    const codes = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM recovery_code WHERE user_id = ?1",
    )
      .bind(user.id)
      .first<{ n: number }>();
    expect(codes?.n).toBe(0);
    expect((await flashes(cookie)).pop()).toEqual({
      category: "warning",
      message: "TOTP is now disabled",
    });
  });

  it("redirects when MFA is not enabled", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const res = await get("/dashboard/mfa_cancel", cookie);
    expect(res.status).toBe(302);
    expect((await flashes(cookie)).pop()?.message).toBe(
      "you don't have MFA enabled",
    );
  });
});

// --------------------------------------------------------------------------
// 10./11. fido_setup / fido_manage
// --------------------------------------------------------------------------

describe("fido pages", () => {
  it("fido_setup is gated (WebAuthn deferred)", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const res = await get("/dashboard/fido_setup", cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect((await flashes(cookie)).pop()?.message).toBe(
      "WebAuthn is not supported in this deployment",
    );
  });

  it("fido_manage guards users without a security key", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const res = await get("/dashboard/fido_manage", cookie);
    expect(res.status).toBe(302);
    expect((await flashes(cookie)).pop()?.message).toBe(
      "You haven't registered a security key",
    );
  });

  it("fido_manage lists and unlinks keys (last unlink clears fido_uuid)", async () => {
    const uuid = crypto.randomUUID();
    const user = await createUser(env.DB, { fido_uuid: uuid });
    await env.DB.prepare(
      `INSERT INTO fido (credential_id, uuid, public_key, sign_count, name, user_id)
       VALUES ('cred-1', ?1, 'pk-1', 0, 'My Yubikey', ?2)`,
    )
      .bind(uuid, user.id)
      .run();
    const cookie = await webSession(user, { sudo: true });

    const page = await get("/dashboard/fido_manage", cookie);
    expect(page.status).toBe(200);
    expect(await page.text()).toContain("My Yubikey");

    const csrf = await getCsrf("/dashboard/fido_manage", cookie);
    const res = await post("/dashboard/fido_manage", cookie, {
      csrf_token: csrf,
      credential_id: "cred-1",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect((await flashes(cookie)).pop()?.message).toBe(
      "Key My Yubikey successfully unlinked",
    );
    const fresh = await userRow(user.id);
    expect(fresh?.fido_uuid).toBeNull();
  });
});

// --------------------------------------------------------------------------
// 12. delete_account
// --------------------------------------------------------------------------

describe("GET/POST /dashboard/delete_account", () => {
  it("renders the confirmation page", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const res = await get("/dashboard/delete_account", cookie);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Account Deletion");
  });

  it("schedules the delete-account job + audit log", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const csrf = await getCsrf("/dashboard/delete_account", cookie);
    const res = await post("/dashboard/delete_account", cookie, {
      csrf_token: csrf,
      "form-name": "delete-account",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/setting");
    const job = await env.DB.prepare(
      "SELECT payload FROM job WHERE name = 'delete-account'",
    ).first<{ payload: string }>();
    expect(JSON.parse(job?.payload ?? "{}")).toEqual({ user_id: user.id });
    const audit = await env.DB.prepare(
      "SELECT action FROM user_audit_log WHERE user_id = ?1",
    )
      .bind(user.id)
      .first<{ action: string }>();
    expect(audit?.action).toBe("user_marked_for_deletion");
    expect((await flashes(cookie)).pop()).toEqual({
      category: "info",
      message:
        "Your account deletion has been scheduled. You'll receive an email when the deletion is finished",
    });
  });

  it("re-renders (200) with Invalid request on CSRF failure", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user, { sudo: true });
    const res = await post("/dashboard/delete_account", cookie, {
      "form-name": "delete-account",
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Invalid request");
  });
});

// --------------------------------------------------------------------------
// 13./14. notification pages
// --------------------------------------------------------------------------

describe("notification pages", () => {
  async function makeNotification(
    userId: number,
    title: string | null,
    message: string,
  ): Promise<number> {
    const row = await env.DB.prepare(
      "INSERT INTO notification (user_id, title, message) VALUES (?1, ?2, ?3) RETURNING id",
    )
      .bind(userId, title, message)
      .first<{ id: number }>();
    return row?.id as number;
  }

  it("GET marks the notification read and renders the message", async () => {
    const user = await createUser(env.DB);
    const id = await makeNotification(user.id, "Big news", "<b>hello</b>");
    const cookie = await webSession(user);
    const res = await get(`/dashboard/notification/${id}`, cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Big news");
    expect(html).toContain("<b>hello</b>"); // |safe raw HTML
    const read = await env.DB.prepare(
      "SELECT read FROM notification WHERE id = ?1",
    )
      .bind(id)
      .first<{ read: number }>();
    expect(read?.read).toBe(1);
  });

  it("POST deletes it (no CSRF check, Flask parity) and flashes the title", async () => {
    const user = await createUser(env.DB);
    const id = await makeNotification(user.id, "Big news", "msg");
    const cookie = await webSession(user);
    const res = await post(`/dashboard/notification/${id}`, cookie, {});
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect((await flashes(cookie)).pop()?.message).toBe(
      "Big news has been deleted",
    );
    const gone = await env.DB.prepare(
      "SELECT 1 FROM notification WHERE id = ?1",
    )
      .bind(id)
      .first();
    expect(gone).toBeNull();
  });

  it("guards other users' notifications and unknown ids", async () => {
    const owner = await createUser(env.DB);
    const id = await makeNotification(owner.id, "t", "m");
    const user = await createUser(env.DB);
    const cookie = await webSession(user);

    let res = await get(`/dashboard/notification/${id}`, cookie);
    expect(res.status).toBe(302);
    expect((await flashes(cookie)).pop()?.message).toBe(
      "You don't have access to this page. Redirect you to the home page",
    );

    res = await get("/dashboard/notification/does-not-exist", cookie);
    expect(res.status).toBe(302);
    expect((await flashes(cookie)).pop()?.message).toBe(
      "Incorrect link. Redirect you to the home page",
    );
  });

  it("lists notifications unread-first", async () => {
    const user = await createUser(env.DB);
    await makeNotification(user.id, "First", "m1");
    await makeNotification(user.id, "Second", "m2");
    const cookie = await webSession(user);
    const res = await get("/dashboard/notifications", cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("First");
    expect(html).toContain("Second");
    expect(html).toContain("More ➡");
  });
});

// --------------------------------------------------------------------------
// 15./16./17. unsubscribe / block_contact / encoded
// --------------------------------------------------------------------------

describe("unsubscribe + block_contact", () => {
  it("GET unsubscribe renders the confirm page", async () => {
    const user = await createUser(env.DB);
    const alias = await createAlias(
      env.DB,
      user.id,
      user.default_mailbox_id as number,
    );
    const cookie = await webSession(user);
    const res = await get(`/dashboard/unsubscribe/${alias.id}`, cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Deactivate alias");
    expect(html).toContain(alias.email);
  });

  it("POST disables the alias and redirects with highlight", async () => {
    const user = await createUser(env.DB);
    const alias = await createAlias(
      env.DB,
      user.id,
      user.default_mailbox_id as number,
    );
    const cookie = await webSession(user);
    const csrf = await getCsrf(`/dashboard/unsubscribe/${alias.id}`, cookie);
    const res = await post(`/dashboard/unsubscribe/${alias.id}`, cookie, {
      csrf_token: csrf,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      `/dashboard/?highlight_alias_id=${alias.id}`,
    );
    const fresh = await env.DB.prepare(
      "SELECT enabled FROM alias WHERE id = ?1",
    )
      .bind(alias.id)
      .first<{ enabled: number }>();
    expect(fresh?.enabled).toBe(0);
    expect((await flashes(cookie)).pop()?.message).toBe(
      `Alias ${alias.email} has been blocked`,
    );
  });

  it("POST honors the RFC 8058 One-Click CSRF exemption", async () => {
    const user = await createUser(env.DB);
    const alias = await createAlias(
      env.DB,
      user.id,
      user.default_mailbox_id as number,
    );
    const cookie = await webSession(user);
    const res = await post(
      `/dashboard/unsubscribe/${alias.id}`,
      cookie,
      {},
      { "List-Unsubscribe-Post": "One-Click" },
    );
    expect(res.status).toBe(302);
    const fresh = await env.DB.prepare(
      "SELECT enabled FROM alias WHERE id = ?1",
    )
      .bind(alias.id)
      .first<{ enabled: number }>();
    expect(fresh?.enabled).toBe(0);
  });

  it("POST without One-Click header and without CSRF is rejected", async () => {
    const user = await createUser(env.DB);
    const alias = await createAlias(
      env.DB,
      user.id,
      user.default_mailbox_id as number,
    );
    const cookie = await webSession(user);
    const res = await post(`/dashboard/unsubscribe/${alias.id}`, cookie, {});
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain(
      `/dashboard/unsubscribe/${alias.id}`,
    );
    expect((await flashes(cookie)).pop()?.message).toBe("Invalid request");
    const fresh = await env.DB.prepare(
      "SELECT enabled FROM alias WHERE id = ?1",
    )
      .bind(alias.id)
      .first<{ enabled: number }>();
    expect(fresh?.enabled).toBe(1);
  });

  it("unsubscribe guards foreign aliases; non-int ids 404", async () => {
    const owner = await createUser(env.DB);
    const alias = await createAlias(
      env.DB,
      owner.id,
      owner.default_mailbox_id as number,
    );
    const user = await createUser(env.DB);
    const cookie = await webSession(user);
    let res = await get(`/dashboard/unsubscribe/${alias.id}`, cookie);
    expect(res.status).toBe(302);
    expect((await flashes(cookie)).pop()?.message).toBe(
      "You don't have access to this page. Redirect you to the home page",
    );
    res = await get("/dashboard/unsubscribe/abc", cookie);
    expect(res.status).toBe(404); // <int:> converter parity
  });

  it("block_contact GET + POST blocks the sender", async () => {
    const user = await createUser(env.DB);
    const alias = await createAlias(
      env.DB,
      user.id,
      user.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, user.id, alias.id);
    const cookie = await webSession(user);

    const page = await get(`/dashboard/block_contact/${contact.id}`, cookie);
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain("Block sender");
    expect(html).toContain(contact.website_email);

    const csrf = await getCsrf(
      `/dashboard/block_contact/${contact.id}`,
      cookie,
    );
    const res = await post(`/dashboard/block_contact/${contact.id}`, cookie, {
      csrf_token: csrf,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      `/dashboard/alias_contact_manager/${alias.id}?highlight_contact_id=${contact.id}`,
    );
    const fresh = await env.DB.prepare(
      "SELECT block_forward FROM contact WHERE id = ?1",
    )
      .bind(contact.id)
      .first<{ block_forward: number }>();
    expect(fresh?.block_forward).toBe(1);
    expect((await flashes(cookie)).pop()?.message).toBe(
      `Emails sent from ${contact.website_email} are now blocked`,
    );
  });

  it("block_contact on an already-blocked contact redirects without a flash", async () => {
    const user = await createUser(env.DB);
    const alias = await createAlias(
      env.DB,
      user.id,
      user.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, user.id, alias.id, {
      block_forward: 1,
    });
    const cookie = await webSession(user);
    const csrf = await getCsrf(
      `/dashboard/block_contact/${contact.id}`,
      cookie,
    );
    const res = await post(`/dashboard/block_contact/${contact.id}`, cookie, {
      csrf_token: csrf,
    });
    expect(res.status).toBe(302);
    expect(await flashes(cookie)).toEqual([]);
  });

  it("encoded unsubscribe flashes Invalid unsubscribe request (deferred)", async () => {
    const user = await createUser(env.DB);
    const cookie = await webSession(user);
    const res = await get("/dashboard/unsubscribe/encoded/whatever", cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect((await flashes(cookie)).pop()).toEqual({
      category: "error",
      message: "Invalid unsubscribe request",
    });
  });
});
