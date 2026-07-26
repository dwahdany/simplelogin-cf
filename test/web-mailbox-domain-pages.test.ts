/**
 * Integration tests for the mailbox/domain web pages
 * (src/web/mailbox-domain-pages.ts, specs/web/03-mailbox-domain-pages.md).
 * Requests go through SELF.fetch, i.e. the full worker in src/index.ts with
 * the router mounted at /dashboard.
 */

import { env, SELF } from "cloudflare:test";
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { sentEmails } from "../src/lib/mailer";
import type { MailboxRow, UserRow } from "../src/lib/rows";
import { createSession } from "../src/lib/session";
import type { WebEnv } from "../src/lib/web/webauth";
import {
  expectedMxRecords,
  isMxHostSetEquivalent,
  setMailboxDnsClient,
} from "../src/web/mailbox-domain-pages";
import {
  createAlias,
  createContact,
  createEmailLog,
  createMailbox,
  createUser,
} from "./fixtures";

const BASE = "http://example.com";

// ---- in-memory DNS client (like Flask tests' InMemoryDNSClient) ----

/** MX hosts per hostname; unknown hostnames get a generic MX so mailbox
 * creation succeeds by default. Set an empty array for an MX-less domain. */
const mxRecords = new Map<string, string[]>();
/** A records per MX hostname; unknown hostnames resolve to null. */
const aRecords = new Map<string, string>();

// Tests and SELF share this isolate, so the routes see this client.
setMailboxDnsClient({
  async getMxDomainList(hostname) {
    return mxRecords.get(hostname) ?? ["mx.mock.test"];
  },
  async getARecord(hostname) {
    return aRecords.get(hostname) ?? null;
  },
});

/** The optional blocklist tables (absent from the D1 migrations). */
async function createBlocklistTables(): Promise<void> {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS invalid_mailbox_domain (
       id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL UNIQUE)`,
  ).run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS forbidden_mx_ip (
       id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL UNIQUE,
       comment TEXT)`,
  ).run();
}

/** Build a logged-in (optionally sudo-fresh) KV session, return its cookie. */
async function sessionCookieFor(userId: number, sudo = false): Promise<string> {
  const helper = new Hono<WebEnv>();
  helper.get("/mk", async (c) => {
    await createSession(
      c,
      userId,
      sudo ? { sudo_time: Math.floor(Date.now() / 1000) } : {},
    );
    return c.text("ok");
  });
  const res = await helper.request("/mk", {}, env);
  return (res.headers.get("set-cookie") ?? "").split(";")[0];
}

async function get(path: string, cookie?: string): Promise<Response> {
  return SELF.fetch(BASE + path, {
    headers: cookie ? { Cookie: cookie } : {},
    redirect: "manual",
  });
}

/** GET the page and extract the csrf hidden-field token. */
async function getCsrf(path: string, cookie: string): Promise<string> {
  const res = await get(path, cookie);
  const html = await res.text();
  const m = html.match(/name="csrf_token" type="hidden" value="([^"]+)"/);
  if (!m) throw new Error(`no csrf token on ${path} (status ${res.status})`);
  return m[1];
}

async function post(
  path: string,
  cookie: string,
  fields: Record<string, string | string[]>,
): Promise<Response> {
  const body = new URLSearchParams();
  for (const [k, v] of Object.entries(fields)) {
    if (Array.isArray(v)) for (const x of v) body.append(k, x);
    else body.append(k, v);
  }
  return SELF.fetch(BASE + path, {
    method: "POST",
    headers: {
      Cookie: cookie,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
    redirect: "manual",
  });
}

/** Pending (undrained) flash messages straight from the KV session. */
async function getFlashes(
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

async function clearFlashes(cookie: string): Promise<void> {
  const token = cookie.split("=")[1];
  const raw = await env.KV.get(`session:${token}`);
  if (!raw) return;
  const data = JSON.parse(raw);
  data.flashes = [];
  await env.KV.put(`session:${token}`, JSON.stringify(data));
}

async function insertActivation(
  mailboxId: number,
  code: string,
): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO mailbox_activation (mailbox_id, code, tries) VALUES (?1, ?2, 0)",
  )
    .bind(mailboxId, code)
    .run();
}

// ---------------------------------------------------------------------------

describe("auth gating", () => {
  const paths = [
    "/dashboard/mailbox",
    "/dashboard/mailbox_verify",
    "/dashboard/mailbox/1",
    "/dashboard/mailbox/1/cancel_email_change",
    "/dashboard/mailbox/confirm_change",
    "/dashboard/custom_domain",
    "/dashboard/domains/1/dns",
    "/dashboard/domains/1/info",
    "/dashboard/domains/1/trash",
    "/dashboard/domains/1/auto-create",
    "/dashboard/subdomain",
    "/dashboard/directory",
    "/dashboard/batch_import",
    "/dashboard/refused_email",
  ];

  it("redirects anonymous GETs to /auth/login?next=...", async () => {
    for (const path of paths) {
      const res = await get(path);
      expect(res.status, path).toBe(302);
      const loc = res.headers.get("location") ?? "";
      expect(loc, path).toContain("/auth/login?next=");
      expect(decodeURIComponent(loc.split("next=")[1]), path).toContain(path);
    }
  });

  it("sends non-sudo sessions of sudo routes to enter_sudo", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id, false);
    const mb = await env.DB.prepare("SELECT id FROM mailbox WHERE user_id = ?1")
      .bind(user.id)
      .first<{ id: number }>();
    const res = await get(`/dashboard/mailbox/${mb?.id}`, cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      `/dashboard/enter_sudo?next=%2Fdashboard%2Fmailbox%2F${mb?.id}`,
    );
    const res2 = await get("/dashboard/batch_import", cookie);
    expect(res2.status).toBe(302);
    expect(res2.headers.get("location")).toBe(
      "/dashboard/enter_sudo?next=%2Fdashboard%2Fbatch_import",
    );
  });
});

// ---------------------------------------------------------------------------

describe("route 1: /dashboard/mailbox", () => {
  it("GET renders the mailbox list", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const res = await get("/dashboard/mailbox", cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toMatch(/<title>\s*Mailboxes\s*\| SimpleLogin\s*<\/title>/);
    expect(html).toContain(user.email);
    expect(html).toContain('name="form-name" value="create"');
  });

  it("POST create makes an unverified mailbox, sends the email, redirects to detail", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/mailbox", cookie);
    sentEmails.length = 0;
    const res = await post("/dashboard/mailbox", cookie, {
      "form-name": "create",
      csrf_token: csrf,
      email: "NewBox@Example.com",
    });
    expect(res.status).toBe(302);
    const mb = await env.DB.prepare(
      "SELECT * FROM mailbox WHERE user_id = ?1 AND email = ?2",
    )
      .bind(user.id, "newbox@example.com")
      .first<MailboxRow>();
    expect(mb).toBeTruthy();
    expect(mb?.verified).toBe(0);
    expect(res.headers.get("location")).toBe(`/dashboard/mailbox/${mb?.id}`);
    const activation = await env.DB.prepare(
      "SELECT * FROM mailbox_activation WHERE mailbox_id = ?1",
    )
      .bind(mb?.id)
      .first<{ code: string }>();
    expect(activation).toBeTruthy();
    expect(sentEmails[0].to).toBe("newbox@example.com");
    expect(sentEmails[0].subject).toBe(
      "Please confirm your mailbox newbox@example.com",
    );
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "success",
        message:
          "You are going to receive an email to confirm newbox@example.com.",
      },
    ]);
  });

  it("POST create with an invalid email flashes Invalid request", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/mailbox", cookie);
    const res = await post("/dashboard/mailbox", cookie, {
      "form-name": "create",
      csrf_token: csrf,
      email: "not-an-email",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/mailbox");
    expect(await getFlashes(cookie)).toEqual([
      { category: "warning", message: "Invalid request" },
    ]);
  });

  it("POST create with a space in the local part is form-invalid (wtforms Email -> email_validator)", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/mailbox", cookie);
    const res = await post("/dashboard/mailbox", cookie, {
      "form-name": "create",
      csrf_token: csrf,
      email: "joe doe@gmail.com",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/mailbox");
    expect(await getFlashes(cookie)).toEqual([
      { category: "warning", message: "Invalid request" },
    ]);
    // Flask never gets to the lower/strip step: no mailbox row is written
    expect(
      await env.DB.prepare("SELECT 1 FROM mailbox WHERE email = ?1")
        .bind("joedoe@gmail.com")
        .first(),
    ).toBeNull();
  });

  it("POST create refuses a domain with no MX records", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/mailbox", cookie);
    mxRecords.set("nomx.example.com", []);
    sentEmails.length = 0;
    const res = await post("/dashboard/mailbox", cookie, {
      "form-name": "create",
      csrf_token: csrf,
      email: "box@nomx.example.com",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/mailbox");
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "warning",
        message:
          "Invalid email: We couldn't get any MX records configured for this domain",
      },
    ]);
    expect(
      await env.DB.prepare("SELECT 1 FROM mailbox WHERE email = ?1")
        .bind("box@nomx.example.com")
        .first(),
    ).toBeNull();
    expect(sentEmails.length).toBe(0);
  });

  it("POST create refuses blocklisted mailbox domains (parent-suffix match)", async () => {
    await createBlocklistTables();
    await env.DB.prepare(
      "INSERT OR IGNORE INTO invalid_mailbox_domain (domain) VALUES ('blocked-domain.test')",
    ).run();
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/mailbox", cookie);
    const res = await post("/dashboard/mailbox", cookie, {
      "form-name": "create",
      csrf_token: csrf,
      email: "box@mail.blocked-domain.test",
    });
    expect(res.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "warning",
        message: "Invalid email: We don't allow mailboxes using this domain",
      },
    ]);
    expect(
      await env.DB.prepare("SELECT 1 FROM mailbox WHERE email = ?1")
        .bind("box@mail.blocked-domain.test")
        .first(),
    ).toBeNull();
  });

  it("POST create refuses domains whose MX resolves to a forbidden IP", async () => {
    await createBlocklistTables();
    await env.DB.prepare(
      "INSERT OR IGNORE INTO forbidden_mx_ip (ip) VALUES ('10.11.12.13')",
    ).run();
    mxRecords.set("evil-mx.example.com", ["mx.evil-mx.test"]);
    aRecords.set("mx.evil-mx.test", "10.11.12.13");
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/mailbox", cookie);
    const res = await post("/dashboard/mailbox", cookie, {
      "form-name": "create",
      csrf_token: csrf,
      email: "box@evil-mx.example.com",
    });
    expect(res.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "warning",
        message:
          "Invalid email: We don't allow mailbox domains that point to these MX records",
      },
    ]);
    expect(
      await env.DB.prepare("SELECT 1 FROM mailbox WHERE email = ?1")
        .bind("box@evil-mx.example.com")
        .first(),
    ).toBeNull();
  });

  it("POST with a bad CSRF token flashes Invalid request", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await getCsrf("/dashboard/mailbox", cookie); // ensures session csrf exists
    const res = await post("/dashboard/mailbox", cookie, {
      "form-name": "create",
      csrf_token: "tampered",
      email: "x@example.com",
    });
    expect(res.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      { category: "warning", message: "Invalid request" },
    ]);
  });

  it("POST set-default switches the default mailbox", async () => {
    const user = await createUser(env.DB);
    const other = await createMailbox(
      env.DB,
      user.id,
      `other-${user.id}@example.com`,
    );
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/mailbox", cookie);
    const res = await post("/dashboard/mailbox", cookie, {
      "form-name": "set-default",
      csrf_token: csrf,
      mailbox_id: String(other.id),
    });
    expect(res.status).toBe(302);
    const row = await env.DB.prepare(
      "SELECT default_mailbox_id FROM users WHERE id = ?1",
    )
      .bind(user.id)
      .first<{ default_mailbox_id: number }>();
    expect(row?.default_mailbox_id).toBe(other.id);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "success",
        message: `Mailbox ${other.email} is set as Default Mailbox`,
      },
    ]);
  });

  it("POST delete enqueues the delete-mailbox job", async () => {
    const user = await createUser(env.DB);
    const other = await createMailbox(
      env.DB,
      user.id,
      `todel-${user.id}@example.com`,
    );
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/mailbox", cookie);
    const res = await post("/dashboard/mailbox", cookie, {
      "form-name": "delete",
      csrf_token: csrf,
      mailbox_id: String(other.id),
      transfer_mailbox_id: "-1",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/mailbox");
    const job = await env.DB.prepare(
      "SELECT * FROM job WHERE name = 'delete-mailbox' ORDER BY id DESC LIMIT 1",
    ).first<{ payload: string }>();
    expect(JSON.parse(job?.payload ?? "{}")).toEqual({
      mailbox_id: other.id,
      transfer_mailbox_id: null,
      send_mail: true,
    });
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "success",
        message:
          `Mailbox ${other.email} scheduled for deletion.` +
          "You will receive a confirmation email when the deletion is finished",
      },
    ]);
  });

  it("POST delete with an empty transfer_mailbox_id is Invalid request (wtforms int coercion)", async () => {
    const user = await createUser(env.DB);
    const other = await createMailbox(
      env.DB,
      user.id,
      `keep-${user.id}@example.com`,
    );
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/mailbox", cookie);
    const res = await post("/dashboard/mailbox", cookie, {
      "form-name": "delete",
      csrf_token: csrf,
      mailbox_id: String(other.id),
      transfer_mailbox_id: "", // int('') raises -> form invalid in Flask
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/mailbox");
    expect(await getFlashes(cookie)).toEqual([
      { category: "warning", message: "Invalid request" },
    ]);
    // no delete-mailbox job scheduled for this mailbox
    const job = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM job
       WHERE name = 'delete-mailbox' AND json_extract(payload, '$.mailbox_id') = ?1`,
    )
      .bind(other.id)
      .first<{ n: number }>();
    expect(job?.n).toBe(0);
  });

  it("POST delete of the default mailbox is refused", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/mailbox", cookie);
    const res = await post("/dashboard/mailbox", cookie, {
      "form-name": "delete",
      csrf_token: csrf,
      mailbox_id: String(user.default_mailbox_id),
      transfer_mailbox_id: "-1",
    });
    expect(res.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      { category: "warning", message: "Cannot delete your default mailbox" },
    ]);
  });
});

// ---------------------------------------------------------------------------

describe("route 2: /dashboard/mailbox_verify", () => {
  it("verifies with a valid code and renders the validation page", async () => {
    const user = await createUser(env.DB);
    const mb = await createMailbox(
      env.DB,
      user.id,
      `verify-${user.id}@example.com`,
      {
        verified: 0,
      },
    );
    await insertActivation(mb.id, "secret-code");
    const cookie = await sessionCookieFor(user.id);
    const res = await get(
      `/dashboard/mailbox_verify?mailbox_id=${mb.id}&code=secret-code`,
      cookie,
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(
      "verified, you can now start creating alias with it",
    );
    const row = await env.DB.prepare(
      "SELECT verified FROM mailbox WHERE id = ?1",
    )
      .bind(mb.id)
      .first<{ verified: number }>();
    expect(row?.verified).toBe(1);
    const act = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM mailbox_activation WHERE mailbox_id = ?1",
    )
      .bind(mb.id)
      .first<{ n: number }>();
    expect(act?.n).toBe(0);
  });

  it("wrong code increments tries and flashes the error", async () => {
    const user = await createUser(env.DB);
    const mb = await createMailbox(
      env.DB,
      user.id,
      `verify2-${user.id}@example.com`,
      {
        verified: 0,
      },
    );
    await insertActivation(mb.id, "right-code");
    const cookie = await sessionCookieFor(user.id);
    const res = await get(
      `/dashboard/mailbox_verify?mailbox_id=${mb.id}&code=wrong`,
      cookie,
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/mailbox");
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "error",
        message: "Cannot verify mailbox: Invalid activation code",
      },
    ]);
    const act = await env.DB.prepare(
      "SELECT tries FROM mailbox_activation WHERE mailbox_id = ?1",
    )
      .bind(mb.id)
      .first<{ tries: number }>();
    expect(act?.tries).toBe(1);
  });

  it("missing mailbox_id / missing code flash the invalid-link errors", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const res = await get("/dashboard/mailbox_verify", cookie);
    expect(res.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      { category: "error", message: "You followed an invalid link" },
    ]);
    await clearFlashes(cookie);
    const res2 = await get("/dashboard/mailbox_verify?mailbox_id=1", cookie);
    expect(res2.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "error",
        message: "Invalid link. Please delete and re-add your mailbox",
      },
    ]);
  });
});

// ---------------------------------------------------------------------------

describe("route 3: /dashboard/mailbox/<id>", () => {
  async function setup(): Promise<{
    user: UserRow;
    mb: MailboxRow;
    cookie: string;
    csrf: string;
  }> {
    const user = await createUser(env.DB);
    const mb = (await env.DB.prepare("SELECT * FROM mailbox WHERE user_id = ?1")
      .bind(user.id)
      .first<MailboxRow>()) as MailboxRow;
    const cookie = await sessionCookieFor(user.id, true);
    const csrf = await getCsrf(`/dashboard/mailbox/${mb.id}`, cookie);
    return { user, mb, cookie, csrf };
  }

  it("GET renders the detail page", async () => {
    const { mb, cookie } = await setup();
    const res = await get(`/dashboard/mailbox/${mb.id}`, cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Change Mailbox Address");
    expect(html).toContain(mb.email);
    expect(html).toContain('name="form-name" value="pgp"');
  });

  it("another user's mailbox is rejected", async () => {
    const { cookie } = await setup();
    const stranger = await createUser(env.DB);
    const strangerMb = await env.DB.prepare(
      "SELECT id FROM mailbox WHERE user_id = ?1",
    )
      .bind(stranger.id)
      .first<{ id: number }>();
    const res = await get(`/dashboard/mailbox/${strangerMb?.id}`, cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect(await getFlashes(cookie)).toEqual([
      { category: "warning", message: "You cannot see this page" },
    ]);
  });

  it("POST with a bad CSRF token flashes Invalid request for every branch", async () => {
    const { mb, cookie } = await setup();
    const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "generic-subject",
      csrf_token: "bad",
      action: "save",
      "generic-subject": "x",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`/dashboard/mailbox/${mb.id}`);
    expect(await getFlashes(cookie)).toEqual([
      { category: "warning", message: "Invalid request" },
    ]);
  });

  it("update-email sets new_email and mails the new address", async () => {
    const { mb, cookie, csrf } = await setup();
    sentEmails.length = 0;
    const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "update-email",
      csrf_token: csrf,
      email: `changed-${mb.id}@example.com`,
    });
    expect(res.status).toBe(302);
    const row = await env.DB.prepare(
      "SELECT new_email FROM mailbox WHERE id = ?1",
    )
      .bind(mb.id)
      .first<{ new_email: string }>();
    expect(row?.new_email).toBe(`changed-${mb.id}@example.com`);
    expect(sentEmails[0].to).toBe(`changed-${mb.id}@example.com`);
    expect(sentEmails[0].subject).toBe("Confirm mailbox change on SimpleLogin");
    // flash names the OLD email (faithful)
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "success",
        message: `You are going to receive an email to confirm ${mb.email}.`,
      },
    ]);
  });

  it("update-email with the same email flashes Same email", async () => {
    const { mb, cookie, csrf } = await setup();
    const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "update-email",
      csrf_token: csrf,
      email: mb.email,
    });
    expect(res.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      { category: "error", message: "Same email" },
    ]);
  });

  it("update-email with an invalid email re-renders with the field error", async () => {
    const { mb, cookie, csrf } = await setup();
    const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "update-email",
      csrf_token: csrf,
      email: "nope",
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Invalid email address.");
  });

  it("update-email with a space in the local part re-renders with the field error", async () => {
    const { mb, cookie, csrf } = await setup();
    sentEmails.length = 0;
    const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "update-email",
      csrf_token: csrf,
      email: "joe doe@gmail.com",
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Invalid email address.");
    const row = await env.DB.prepare(
      "SELECT new_email FROM mailbox WHERE id = ?1",
    )
      .bind(mb.id)
      .first<{ new_email: string | null }>();
    expect(row?.new_email).toBeNull();
    expect(sentEmails.length).toBe(0);
  });

  it("update-email to a domain with no MX records flashes the error", async () => {
    const { mb, cookie, csrf } = await setup();
    mxRecords.set("nomx-change.example.com", []);
    sentEmails.length = 0;
    const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "update-email",
      csrf_token: csrf,
      email: `x-${mb.id}@nomx-change.example.com`,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`/dashboard/mailbox/${mb.id}`);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "error",
        message:
          "Invalid email: We couldn't get any MX records configured for this domain",
      },
    ]);
    const row = await env.DB.prepare(
      "SELECT new_email FROM mailbox WHERE id = ?1",
    )
      .bind(mb.id)
      .first<{ new_email: string | null }>();
    expect(row?.new_email).toBeNull();
    expect(sentEmails.length).toBe(0);
  });

  it("add/delete authorized address", async () => {
    const { mb, cookie, csrf } = await setup();
    const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "add-authorized-address",
      csrf_token: csrf,
      email: `boss-${mb.id}@example.com`,
    });
    expect(res.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "success",
        message: `boss-${mb.id}@example.com added as authorized address`,
      },
    ]);
    await clearFlashes(cookie);
    const row = await env.DB.prepare(
      "SELECT id FROM authorized_address WHERE mailbox_id = ?1",
    )
      .bind(mb.id)
      .first<{ id: number }>();
    expect(row).toBeTruthy();
    const res2 = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "delete-authorized-address",
      csrf_token: csrf,
      "authorized-address-id": String(row?.id),
    });
    expect(res2.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "success",
        message: `boss-${mb.id}@example.com has been deleted`,
      },
    ]);
  });

  it("generic-subject save/remove", async () => {
    const { mb, cookie, csrf } = await setup();
    const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "generic-subject",
      csrf_token: csrf,
      action: "save",
      "generic-subject": "Encrypted Email",
    });
    expect(res.status).toBe(302);
    const row = await env.DB.prepare(
      "SELECT generic_subject FROM mailbox WHERE id = ?1",
    )
      .bind(mb.id)
      .first<{ generic_subject: string }>();
    expect(row?.generic_subject).toBe("Encrypted Email");
    expect(await getFlashes(cookie)).toEqual([
      { category: "success", message: "Generic subject is enabled" },
    ]);
  });

  it("toggle-pgp flips disable_pgp", async () => {
    const { mb, cookie, csrf } = await setup();
    const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "toggle-pgp",
      csrf_token: csrf,
      // no pgp-enabled field => disable
    });
    expect(res.status).toBe(302);
    const row = await env.DB.prepare(
      "SELECT disable_pgp FROM mailbox WHERE id = ?1",
    )
      .bind(mb.id)
      .first<{ disable_pgp: number }>();
    expect(row?.disable_pgp).toBe(1);
    expect(await getFlashes(cookie)).toEqual([
      { category: "info", message: `PGP is disabled on ${mb.email}` },
    ]);
  });

  // full PGP coverage (valid key save/remove, forward-phase encryption) in
  // test/pgp.test.ts
  it("pgp save with an invalid key flashes the PGP error and stores nothing", async () => {
    const { mb, cookie, csrf } = await setup();
    const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "pgp",
      csrf_token: csrf,
      action: "save",
      pgp: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      "Cannot add the public key, please verify it",
    );
    const row = await env.DB.prepare(
      "SELECT pgp_public_key FROM mailbox WHERE id = ?1",
    )
      .bind(mb.id)
      .first<{ pgp_public_key: string | null }>();
    expect(row?.pgp_public_key).toBeNull();
  });

  it("force-spf flash replicates Flask's operator-precedence bug", async () => {
    const { mb, cookie, csrf } = await setup();
    const envx = env as unknown as Record<string, unknown>;
    envx.ENFORCE_SPF = "1";
    try {
      // spf-status='off': the DB write keys on == 'on' (disabled) but the
      // flash keys on truthiness (mailbox_detail.py L89-94) -> "enabled"
      const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
        "form-name": "force-spf",
        csrf_token: csrf,
        "spf-status": "off",
      });
      expect(res.status).toBe(302);
      expect(res.headers.get("location")).toBe(`/dashboard/mailbox/${mb.id}`);
      const row = await env.DB.prepare(
        "SELECT force_spf FROM mailbox WHERE id = ?1",
      )
        .bind(mb.id)
        .first<{ force_spf: number }>();
      expect(row?.force_spf).toBe(0);
      expect(await getFlashes(cookie)).toEqual([
        { category: "success", message: "SPF enforcement was enabled" },
      ]);
      await clearFlashes(cookie);

      // spf-status='on': enabled + "enabled" flash
      await post(`/dashboard/mailbox/${mb.id}`, cookie, {
        "form-name": "force-spf",
        csrf_token: csrf,
        "spf-status": "on",
      });
      const row2 = await env.DB.prepare(
        "SELECT force_spf FROM mailbox WHERE id = ?1",
      )
        .bind(mb.id)
        .first<{ force_spf: number }>();
      expect(row2?.force_spf).toBe(1);
      expect(await getFlashes(cookie)).toEqual([
        { category: "success", message: "SPF enforcement was enabled" },
      ]);
      await clearFlashes(cookie);

      // spf-status absent: disabled + "disabled successfully" flash
      await post(`/dashboard/mailbox/${mb.id}`, cookie, {
        "form-name": "force-spf",
        csrf_token: csrf,
      });
      const row3 = await env.DB.prepare(
        "SELECT force_spf FROM mailbox WHERE id = ?1",
      )
        .bind(mb.id)
        .first<{ force_spf: number }>();
      expect(row3?.force_spf).toBe(0);
      expect(await getFlashes(cookie)).toEqual([
        { category: "success", message: "disabled successfully" },
      ]);
    } finally {
      delete envx.ENFORCE_SPF;
    }
  });

  it("force-spf is rejected when ENFORCE_SPF is not configured", async () => {
    const { mb, cookie, csrf } = await setup();
    const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "force-spf",
      csrf_token: csrf,
      "spf-status": "on",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect(await getFlashes(cookie)).toEqual([
      { category: "error", message: "SPF enforcement globally not enabled" },
    ]);
  });
});

// ---------------------------------------------------------------------------

describe("routes 4+5: cancel_email_change / confirm_change", () => {
  it("cancel_email_change clears the pending change (GET side effect)", async () => {
    const user = await createUser(env.DB);
    const mb = (await env.DB.prepare("SELECT * FROM mailbox WHERE user_id = ?1")
      .bind(user.id)
      .first<MailboxRow>()) as MailboxRow;
    await env.DB.prepare("UPDATE mailbox SET new_email = ?1 WHERE id = ?2")
      .bind(`pending-${mb.id}@example.com`, mb.id)
      .run();
    await insertActivation(mb.id, "abc");
    const cookie = await sessionCookieFor(user.id);
    const res = await get(
      `/dashboard/mailbox/${mb.id}/cancel_email_change`,
      cookie,
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`/dashboard/mailbox/${mb.id}`);
    const row = await env.DB.prepare(
      "SELECT new_email FROM mailbox WHERE id = ?1",
    )
      .bind(mb.id)
      .first<{ new_email: string | null }>();
    expect(row?.new_email).toBeNull();
    expect(await getFlashes(cookie)).toEqual([
      { category: "success", message: "Your mailbox change is cancelled" },
    ]);
  });

  it("cancel_email_change on someone else's mailbox flashes Invalid mailbox", async () => {
    const user = await createUser(env.DB);
    const stranger = await createUser(env.DB);
    const strangerMb = await env.DB.prepare(
      "SELECT id FROM mailbox WHERE user_id = ?1",
    )
      .bind(stranger.id)
      .first<{ id: number }>();
    const cookie = await sessionCookieFor(user.id);
    const res = await get(
      `/dashboard/mailbox/${strangerMb?.id}/cancel_email_change`,
      cookie,
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect(await getFlashes(cookie)).toEqual([
      { category: "warning", message: "Invalid mailbox" },
    ]);
  });

  it("confirm_change swaps the email with a valid code", async () => {
    const user = await createUser(env.DB);
    const mb = (await env.DB.prepare("SELECT * FROM mailbox WHERE user_id = ?1")
      .bind(user.id)
      .first<MailboxRow>()) as MailboxRow;
    const newEmail = `swapped-${mb.id}@example.com`;
    await env.DB.prepare("UPDATE mailbox SET new_email = ?1 WHERE id = ?2")
      .bind(newEmail, mb.id)
      .run();
    await insertActivation(mb.id, "swap-code");
    const cookie = await sessionCookieFor(user.id);
    const res = await get(
      `/dashboard/mailbox/confirm_change?mailbox_id=${mb.id}&code=swap-code`,
      cookie,
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`/dashboard/mailbox/${mb.id}`);
    const row = await env.DB.prepare(
      "SELECT email, new_email FROM mailbox WHERE id = ?1",
    )
      .bind(mb.id)
      .first<{ email: string; new_email: string | null }>();
    expect(row?.email).toBe(newEmail);
    expect(row?.new_email).toBeNull();
    expect(await getFlashes(cookie)).toEqual([
      { category: "success", message: "Successfully changed mailbox email" },
    ]);
  });

  it("confirm_change without code flashes Invalid link", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const res = await get("/dashboard/mailbox/confirm_change", cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect(await getFlashes(cookie)).toEqual([
      { category: "error", message: "Invalid link" },
    ]);
  });
});

// ---------------------------------------------------------------------------

describe("route 6: /dashboard/custom_domain", () => {
  it("GET renders and POST create makes the domain + redirects to DNS setup", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const res = await get("/dashboard/custom_domain", cookie);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("New Domain");

    const csrf = await getCsrf("/dashboard/custom_domain", cookie);
    const domain = `d${user.id}.example.org`;
    const res2 = await post("/dashboard/custom_domain", cookie, {
      "form-name": "create",
      csrf_token: csrf,
      domain: `HTTPS://${domain}`,
    });
    expect(res2.status).toBe(302);
    const row = await env.DB.prepare(
      "SELECT * FROM custom_domain WHERE domain = ?1",
    )
      .bind(domain)
      .first<{ id: number; ownership_txt_token: string }>();
    expect(row).toBeTruthy();
    expect(row?.ownership_txt_token).toHaveLength(30);
    expect(res2.headers.get("location")).toBe(
      `/dashboard/domains/${row?.id}/dns`,
    );
    expect(await getFlashes(cookie)).toEqual([
      { category: "success", message: `New domain ${domain} is created` },
    ]);
  });

  it("POST create with an invalid domain re-renders with the error flash", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/custom_domain", cookie);
    const res = await post("/dashboard/custom_domain", cookie, {
      "form-name": "create",
      csrf_token: csrf,
      domain: "-bad-.example.org",
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("This is not a valid domain");
  });

  it("POST create with an already-used domain re-renders with the error", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const domain = `dup${user.id}.example.org`;
    await env.DB.prepare(
      "INSERT INTO custom_domain (user_id, domain) VALUES (?1, ?2)",
    )
      .bind(user.id, domain)
      .run();
    const csrf = await getCsrf("/dashboard/custom_domain", cookie);
    const res = await post("/dashboard/custom_domain", cookie, {
      "form-name": "create",
      csrf_token: csrf,
      domain,
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(`${domain} already used`);
  });

  it("POST create with a domain in deleted_subdomain 500s like Flask", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const domain = `trashed${user.id}.subs.example.com`;
    await env.DB.prepare("INSERT INTO deleted_subdomain (domain) VALUES (?1)")
      .bind(domain)
      .run();
    const csrf = await getCsrf("/dashboard/custom_domain", cookie);
    const res = await post("/dashboard/custom_domain", cookie, {
      "form-name": "create",
      csrf_token: csrf,
      domain,
    });
    // CustomDomain.create raises SubdomainInTrashError, uncaught by the view
    expect(res.status).toBe(500);
    expect(
      await env.DB.prepare("SELECT 1 FROM custom_domain WHERE domain = ?1")
        .bind(domain)
        .first(),
    ).toBeNull();
  });

  it("non-premium users cannot create custom domains", async () => {
    const user = await createUser(env.DB, { trial_end: null });
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/custom_domain", cookie);
    const res = await post("/dashboard/custom_domain", cookie, {
      "form-name": "create",
      csrf_token: csrf,
      domain: "free.example.org",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/custom_domain");
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "warning",
        message: "Only premium plan can add custom domain",
      },
    ]);
  });
});

// ---------------------------------------------------------------------------

describe("route 7: /dashboard/domains/<id>/dns", () => {
  async function makeDomain(userId: number, domain: string): Promise<number> {
    const row = await env.DB.prepare(
      "INSERT INTO custom_domain (user_id, domain, ownership_txt_token) VALUES (?1, ?2, ?3) RETURNING id",
    )
      .bind(userId, domain, "tok-abcdef")
      .first<{ id: number }>();
    return row?.id as number;
  }

  it("GET renders the expected records", async () => {
    const user = await createUser(env.DB);
    const id = await makeDomain(user.id, `dns${user.id}.example.org`);
    const cookie = await sessionCookieFor(user.id);
    const res = await get(`/dashboard/domains/${id}/dns`, cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("sl-verification=tok-abcdef");
    // EMAIL_SERVERS_WITH_PRIORITY is "" (unset) in tests -> mx1/mx2 fallback
    expect(html).toContain("mx1.sl.example.com.");
    expect(html).toContain("mx2.sl.example.com.");
    // Cloudflare deviation: the SPF include is Email Sending's, not EMAIL_DOMAIN
    expect(html).toContain("v=spf1 include:_spf.mx.cloudflare.net ~all");
    expect(html).toContain("dkim._domainkey.sl.example.com");
    expect(html).toContain("v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s");
    // Cloudflare Email Routing note on the MX section
    expect(html).toContain("Email Routing");
    expect(html).toContain("scripts/provision-domain.mjs");
  });

  it("GET renders the route MX hosts when EMAIL_SERVERS_WITH_PRIORITY is set", async () => {
    const user = await createUser(env.DB);
    const id = await makeDomain(user.id, `dnsmx${user.id}.example.org`);
    const cookie = await sessionCookieFor(user.id);
    const envx = env as unknown as Record<string, unknown>;
    envx.EMAIL_SERVERS_WITH_PRIORITY =
      "10 route1.mx.cloudflare.net.,20 route2.mx.cloudflare.net.,30 route3.mx.cloudflare.net.";
    try {
      const res = await get(`/dashboard/domains/${id}/dns`, cookie);
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain("route1.mx.cloudflare.net.");
      expect(html).toContain("route2.mx.cloudflare.net.");
      expect(html).toContain("route3.mx.cloudflare.net.");
      expect(html).not.toContain("mx1.sl.example.com.");
    } finally {
      // "" is the pinned "unset" spelling (vitest.config.ts)
      envx.EMAIL_SERVERS_WITH_PRIORITY = "";
    }
  });

  it("GET lazily generates a missing ownership token", async () => {
    const user = await createUser(env.DB);
    const row = await env.DB.prepare(
      "INSERT INTO custom_domain (user_id, domain) VALUES (?1, ?2) RETURNING id",
    )
      .bind(user.id, `lazy${user.id}.example.org`)
      .first<{ id: number }>();
    const cookie = await sessionCookieFor(user.id);
    await get(`/dashboard/domains/${row?.id}/dns`, cookie);
    const after = await env.DB.prepare(
      "SELECT ownership_txt_token FROM custom_domain WHERE id = ?1",
    )
      .bind(row?.id)
      .first<{ ownership_txt_token: string }>();
    expect(after?.ownership_txt_token).toHaveLength(30);
  });

  it("POST check-ownership on an unresolvable domain shows the TXT error", async () => {
    const user = await createUser(env.DB);
    const id = await makeDomain(
      user.id,
      `no-such-${user.id}.invalid-tld-for-tests.test`,
    );
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf(`/dashboard/domains/${id}/dns`, cookie);
    const res = await post(`/dashboard/domains/${id}/dns`, cookie, {
      "form-name": "check-ownership",
      csrf_token: csrf,
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("We can&#39;t find the needed TXT record");
    const row = await env.DB.prepare(
      "SELECT ownership_verified FROM custom_domain WHERE id = ?1",
    )
      .bind(id)
      .first<{ ownership_verified: number }>();
    expect(row?.ownership_verified).toBe(0);
  });

  it("POST check-mx on an MX-less domain warns and keeps verified=0", async () => {
    const user = await createUser(env.DB);
    const id = await makeDomain(
      user.id,
      `no-mx-${user.id}.invalid-tld-for-tests.test`,
    );
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf(`/dashboard/domains/${id}/dns`, cookie);
    const res = await post(`/dashboard/domains/${id}/dns`, cookie, {
      "form-name": "check-mx",
      csrf_token: csrf,
    });
    expect(res.status).toBe(200); // failure falls through to render
    const html = await res.text();
    expect(html).toContain("The MX record is not correctly set");
    expect(html).toContain("(Empty)");
    const row = await env.DB.prepare(
      "SELECT verified FROM custom_domain WHERE id = ?1",
    )
      .bind(id)
      .first<{ verified: number }>();
    expect(row?.verified).toBe(0);
  });

  it("POST check-mx failure does NOT clear a previously verified domain", async () => {
    const user = await createUser(env.DB);
    const id = await makeDomain(
      user.id,
      `was-ok-${user.id}.invalid-tld-for-tests.test`,
    );
    await env.DB.prepare("UPDATE custom_domain SET verified = 1 WHERE id = ?1")
      .bind(id)
      .run();
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf(`/dashboard/domains/${id}/dns`, cookie);
    const res = await post(`/dashboard/domains/${id}/dns`, cookie, {
      "form-name": "check-mx",
      csrf_token: csrf,
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    // template shows the special still-verified warning
    expect(html).toContain("Without the MX record set up correctly");
    const row = await env.DB.prepare(
      "SELECT verified FROM custom_domain WHERE id = ?1",
    )
      .bind(id)
      .first<{ verified: number }>();
    expect(row?.verified).toBe(1);
  });

  it("POST check-spf failure names the Cloudflare include and un-verifies", async () => {
    const user = await createUser(env.DB);
    const id = await makeDomain(
      user.id,
      `no-spf-${user.id}.invalid-tld-for-tests.test`,
    );
    await env.DB.prepare(
      "UPDATE custom_domain SET spf_verified = 1 WHERE id = ?1",
    )
      .bind(id)
      .run();
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf(`/dashboard/domains/${id}/dns`, cookie);
    const res = await post(`/dashboard/domains/${id}/dns`, cookie, {
      "form-name": "check-spf",
      csrf_token: csrf,
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(
      "SPF: _spf.mx.cloudflare.net is not included in your SPF record.",
    );
    const row = await env.DB.prepare(
      "SELECT spf_verified FROM custom_domain WHERE id = ?1",
    )
      .bind(id)
      .first<{ spf_verified: number }>();
    expect(row?.spf_verified).toBe(0); // failure un-verifies (faithful)
  });

  it("POST with a bad CSRF token flashes Invalid request and redirects", async () => {
    const user = await createUser(env.DB);
    const id = await makeDomain(user.id, `csrf${user.id}.example.org`);
    const cookie = await sessionCookieFor(user.id);
    await getCsrf(`/dashboard/domains/${id}/dns`, cookie);
    const res = await post(`/dashboard/domains/${id}/dns`, cookie, {
      "form-name": "check-ownership",
      csrf_token: "bad",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`/dashboard/domains/${id}/dns`);
    expect(await getFlashes(cookie)).toEqual([
      { category: "warning", message: "Invalid request" },
    ]);
  });

  it("another user's domain is rejected", async () => {
    const user = await createUser(env.DB);
    const stranger = await createUser(env.DB);
    const id = await makeDomain(stranger.id, `other${stranger.id}.example.org`);
    const cookie = await sessionCookieFor(user.id);
    const res = await get(`/dashboard/domains/${id}/dns`, cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect(await getFlashes(cookie)).toEqual([
      { category: "warning", message: "You cannot see this page" },
    ]);
  });
});

// ---------------------------------------------------------------------------
// Pure unit tests for the MX matcher + EMAIL_SERVERS_WITH_PRIORITY parsing
// (deliberate deviation from Flask's positional is_mx_equivalent — see
// src/web/mailbox-domain-pages.ts isMxHostSetEquivalent).
// ---------------------------------------------------------------------------

describe("isMxHostSetEquivalent / expectedMxRecords", () => {
  const ROUTES = [
    "route1.mx.cloudflare.net.",
    "route2.mx.cloudflare.net.",
    "route3.mx.cloudflare.net.",
  ];
  const expected = (hosts: string[]) =>
    hosts.map((h, i) => ({
      priority: (i + 1) * 10,
      recommended: h,
      allowed: [h],
    }));

  it("accepts the same host set regardless of priorities and order", () => {
    // Cloudflare-style unpredictable per-zone priorities, shuffled order
    const found = new Map<number, string[]>([
      [76, ["route2.mx.cloudflare.net."]],
      [5, ["route3.mx.cloudflare.net."]],
      [48, ["route1.mx.cloudflare.net."]],
    ]);
    expect(isMxHostSetEquivalent(found, expected(ROUTES))).toBe(true);
    // several hosts sharing one priority is fine too
    const samePrio = new Map<number, string[]>([[10, [...ROUTES]]]);
    expect(isMxHostSetEquivalent(samePrio, expected(ROUTES))).toBe(true);
  });

  it("normalizes case and trailing dots", () => {
    const found = new Map<number, string[]>([
      [1, ["ROUTE1.MX.CLOUDFLARE.NET"]],
      [2, ["Route2.mx.Cloudflare.net."]],
      [3, ["route3.mx.cloudflare.net"]],
    ]);
    expect(isMxHostSetEquivalent(found, expected(ROUTES))).toBe(true);
  });

  it("rejects subsets (a missing host)", () => {
    const found = new Map<number, string[]>([
      [10, ["route1.mx.cloudflare.net."]],
      [20, ["route2.mx.cloudflare.net."]],
    ]);
    expect(isMxHostSetEquivalent(found, expected(ROUTES))).toBe(false);
  });

  it("rejects supersets (an extra/leftover host)", () => {
    const found = new Map<number, string[]>([
      [10, ["route1.mx.cloudflare.net."]],
      [20, ["route2.mx.cloudflare.net."]],
      [30, ["route3.mx.cloudflare.net."]],
      [40, ["mx.old-provider.example."]],
    ]);
    expect(isMxHostSetEquivalent(found, expected(ROUTES))).toBe(false);
  });

  it("rejects a wrong host and an empty MX set", () => {
    const found = new Map<number, string[]>([
      [10, ["route1.mx.cloudflare.net."]],
      [20, ["route2.mx.cloudflare.net."]],
      [30, ["mx.wrong.example."]],
    ]);
    expect(isMxHostSetEquivalent(found, expected(ROUTES))).toBe(false);
    expect(isMxHostSetEquivalent(new Map(), expected(ROUTES))).toBe(false);
  });

  it("parses the production EMAIL_SERVERS_WITH_PRIORITY value", () => {
    const records = expectedMxRecords({
      EMAIL_DOMAIN: "sl.example.com",
      EMAIL_SERVERS_WITH_PRIORITY:
        "10 route1.mx.cloudflare.net.,20 route2.mx.cloudflare.net.,30 route3.mx.cloudflare.net.",
    });
    expect(records).toEqual([
      {
        priority: 10,
        recommended: "route1.mx.cloudflare.net.",
        allowed: ["route1.mx.cloudflare.net."],
      },
      {
        priority: 20,
        recommended: "route2.mx.cloudflare.net.",
        allowed: ["route2.mx.cloudflare.net."],
      },
      {
        priority: 30,
        recommended: "route3.mx.cloudflare.net.",
        allowed: ["route3.mx.cloudflare.net."],
      },
    ]);
    // tolerant spellings: spaces after commas, missing trailing dot
    const tolerant = expectedMxRecords({
      EMAIL_DOMAIN: "sl.example.com",
      EMAIL_SERVERS_WITH_PRIORITY: "20 mx-b.example.net, 10 mx-a.example.net.",
    });
    expect(tolerant.map((r) => `${r.priority} ${r.recommended}`)).toEqual([
      "10 mx-a.example.net.",
      "20 mx-b.example.net.",
    ]);
  });

  it('"" and unset fall back to mx1/mx2.{EMAIL_DOMAIN}', () => {
    for (const value of ["", undefined]) {
      const records = expectedMxRecords({
        EMAIL_DOMAIN: "sl.example.com",
        EMAIL_SERVERS_WITH_PRIORITY: value,
      });
      expect(records.map((r) => `${r.priority} ${r.recommended}`)).toEqual([
        "10 mx1.sl.example.com.",
        "20 mx2.sl.example.com.",
      ]);
    }
  });
});

// ---------------------------------------------------------------------------

describe("route 8: /dashboard/domains/<id>/info", () => {
  async function setup() {
    const user = await createUser(env.DB);
    const row = await env.DB.prepare(
      "INSERT INTO custom_domain (user_id, domain, ownership_verified, verified) VALUES (?1, ?2, 1, 1) RETURNING *",
    )
      .bind(user.id, `info${user.id}.example.org`)
      .first<{ id: number; domain: string }>();
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf(`/dashboard/domains/${row?.id}/info`, cookie);
    return {
      user,
      id: row?.id as number,
      domain: row?.domain as string,
      cookie,
      csrf,
    };
  }

  it("GET renders the info page", async () => {
    const { id, domain, cookie } = await setup();
    const res = await get(`/dashboard/domains/${id}/info`, cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(domain);
    expect(html).toContain('value="switch-catch-all"');
  });

  it("switch-catch-all toggles and flashes", async () => {
    const { id, domain, cookie, csrf } = await setup();
    const res = await post(`/dashboard/domains/${id}/info`, cookie, {
      "form-name": "switch-catch-all",
      csrf_token: csrf,
    });
    expect(res.status).toBe(302);
    const row = await env.DB.prepare(
      "SELECT catch_all FROM custom_domain WHERE id = ?1",
    )
      .bind(id)
      .first<{ catch_all: number }>();
    expect(row?.catch_all).toBe(1);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "success",
        message: `The catch-all has been enabled for ${domain}`,
      },
    ]);
  });

  it("update replaces the domain mailboxes", async () => {
    const { user, id, domain, cookie, csrf } = await setup();
    const res = await post(`/dashboard/domains/${id}/info`, cookie, {
      "form-name": "update",
      csrf_token: csrf,
      mailbox_ids: [String(user.default_mailbox_id)],
    });
    expect(res.status).toBe(302);
    const rows = await env.DB.prepare(
      "SELECT mailbox_id FROM domain_mailbox WHERE domain_id = ?1",
    )
      .bind(id)
      .all<{ mailbox_id: number }>();
    expect(rows.results.map((r) => r.mailbox_id)).toEqual([
      user.default_mailbox_id,
    ]);
    expect(await getFlashes(cookie)).toEqual([
      { category: "success", message: `${domain} mailboxes has been updated` },
    ]);
  });

  it("update with duplicate mailbox_ids fails cleanly like Flask", async () => {
    const { user, id, cookie, csrf } = await setup();
    // establish an existing link first
    await post(`/dashboard/domains/${id}/info`, cookie, {
      "form-name": "update",
      csrf_token: csrf,
      mailbox_ids: [String(user.default_mailbox_id)],
    });
    await clearFlashes(cookie);
    const res = await post(`/dashboard/domains/${id}/info`, cookie, {
      "form-name": "update",
      csrf_token: csrf,
      mailbox_ids: [
        String(user.default_mailbox_id),
        String(user.default_mailbox_id),
      ],
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`/dashboard/domains/${id}/info`);
    expect(await getFlashes(cookie)).toEqual([
      { category: "warning", message: "Something went wrong, please retry" },
    ]);
    // existing links are untouched (Flask fails before any delete/insert)
    const rows = await env.DB.prepare(
      "SELECT mailbox_id FROM domain_mailbox WHERE domain_id = ?1",
    )
      .bind(id)
      .all<{ mailbox_id: number }>();
    expect(rows.results.map((r) => r.mailbox_id)).toEqual([
      user.default_mailbox_id,
    ]);
  });

  it("update without mailboxes flashes the warning", async () => {
    const { id, cookie, csrf } = await setup();
    const res = await post(`/dashboard/domains/${id}/info`, cookie, {
      "form-name": "update",
      csrf_token: csrf,
    });
    expect(res.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      { category: "warning", message: "You must select at least 1 mailbox" },
    ]);
  });

  it("set-name saves and removes the default alias name", async () => {
    const { id, domain, cookie, csrf } = await setup();
    const res = await post(`/dashboard/domains/${id}/info`, cookie, {
      "form-name": "set-name",
      csrf_token: csrf,
      action: "save",
      "alias-name": "My Name",
    });
    expect(res.status).toBe(302);
    const row = await env.DB.prepare(
      "SELECT name FROM custom_domain WHERE id = ?1",
    )
      .bind(id)
      .first<{ name: string }>();
    expect(row?.name).toBe("My Name");
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "success",
        message: `Default alias name for Domain ${domain} has been set`,
      },
    ]);
  });

  it("delete marks pending_deletion and enqueues delete-domain", async () => {
    const { id, domain, cookie, csrf } = await setup();
    const res = await post(`/dashboard/domains/${id}/info`, cookie, {
      "form-name": "delete",
      csrf_token: csrf,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/custom_domain");
    const row = await env.DB.prepare(
      "SELECT pending_deletion FROM custom_domain WHERE id = ?1",
    )
      .bind(id)
      .first<{ pending_deletion: number }>();
    expect(row?.pending_deletion).toBe(1);
    const job = await env.DB.prepare(
      "SELECT payload FROM job WHERE name = 'delete-domain' ORDER BY id DESC LIMIT 1",
    ).first<{ payload: string }>();
    expect(JSON.parse(job?.payload ?? "{}")).toEqual({ custom_domain_id: id });
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "success",
        message:
          `${domain} scheduled for deletion.` +
          "You will receive a confirmation email when the deletion is finished",
      },
    ]);
  });
});

// ---------------------------------------------------------------------------

describe("route 9: /dashboard/domains/<id>/trash", () => {
  it("lists, removes single, and empties the domain trash", async () => {
    const user = await createUser(env.DB);
    const cd = await env.DB.prepare(
      "INSERT INTO custom_domain (user_id, domain) VALUES (?1, ?2) RETURNING id",
    )
      .bind(user.id, `trash${user.id}.example.org`)
      .first<{ id: number }>();
    const dda = await env.DB.prepare(
      "INSERT INTO domain_deleted_alias (email, domain_id, user_id) VALUES (?1, ?2, ?3) RETURNING id",
    )
      .bind(`gone@trash${user.id}.example.org`, cd?.id, user.id)
      .first<{ id: number }>();
    await env.DB.prepare(
      "INSERT INTO domain_deleted_alias (email, domain_id, user_id) VALUES (?1, ?2, ?3)",
    )
      .bind(`gone2@trash${user.id}.example.org`, cd?.id, user.id)
      .run();
    const cookie = await sessionCookieFor(user.id);
    const res = await get(`/dashboard/domains/${cd?.id}/trash`, cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(`gone@trash${user.id}.example.org`);
    expect(html).toContain("Empty Trash");

    const csrf = await getCsrf(`/dashboard/domains/${cd?.id}/trash`, cookie);
    const res2 = await post(`/dashboard/domains/${cd?.id}/trash`, cookie, {
      "form-name": "remove-single",
      csrf_token: csrf,
      "deleted-alias-id": String(dda?.id),
    });
    expect(res2.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "success",
        message: `gone@trash${user.id}.example.org can now be re-created`,
      },
    ]);
    await clearFlashes(cookie);

    const res3 = await post(`/dashboard/domains/${cd?.id}/trash`, cookie, {
      "form-name": "empty-all",
      csrf_token: csrf,
    });
    expect(res3.status).toBe(302);
    const count = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM domain_deleted_alias WHERE domain_id = ?1",
    )
      .bind(cd?.id)
      .first<{ n: number }>();
    expect(count?.n).toBe(0);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "success",
        message: "All deleted aliases can now be re-created",
      },
    ]);
  });
});

// ---------------------------------------------------------------------------

describe("route 10: /dashboard/domains/<id>/auto-create", () => {
  async function setup() {
    const user = await createUser(env.DB);
    const cd = await env.DB.prepare(
      "INSERT INTO custom_domain (user_id, domain, ownership_verified, verified) VALUES (?1, ?2, 1, 1) RETURNING *",
    )
      .bind(user.id, `auto${user.id}.example.org`)
      .first<{ id: number; domain: string }>();
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf(
      `/dashboard/domains/${cd?.id}/auto-create`,
      cookie,
    );
    return {
      user,
      id: cd?.id as number,
      domain: cd?.domain as string,
      cookie,
      csrf,
    };
  }

  it("create rule, test it, then delete it (delete has no CSRF)", async () => {
    const { user, id, domain, cookie, csrf } = await setup();
    const path = `/dashboard/domains/${id}/auto-create`;
    const res = await post(path, cookie, {
      "form-name": "create-auto-create-rule",
      csrf_token: csrf,
      regex: "prefix.*",
      display_name: "",
      order: "1",
      mailbox_ids: [String(user.default_mailbox_id)],
    });
    expect(res.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      { category: "success", message: "New auto create rule has been created" },
    ]);
    await clearFlashes(cookie);
    const rule = await env.DB.prepare(
      "SELECT * FROM auto_create_rule WHERE custom_domain_id = ?1",
    )
      .bind(id)
      .first<{ id: number; regex: string }>();
    expect(rule?.regex).toBe("prefix.*");

    // test passes
    const res2 = await post(path, cookie, {
      "form-name": "test-auto-create-rule",
      csrf_token: csrf,
      local: "prefix123",
    });
    expect(res2.status).toBe(200);
    expect(await res2.text()).toContain(`prefix123@${domain} passes rule #1`);

    // test fails
    const res3 = await post(path, cookie, {
      "form-name": "test-auto-create-rule",
      csrf_token: csrf,
      local: "nomatch",
    });
    expect(await res3.text()).toContain(
      `nomatch@${domain} doesn&#39;t pass any rule`,
    );

    // delete without csrf (faithful hole)
    const res4 = await post(path, cookie, {
      "form-name": "delete-auto-create-rule",
      "rule-id": String(rule?.id),
    });
    expect(res4.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      { category: "success", message: "Rule #1 has been deleted" },
    ]);
  });

  it("duplicate order re-renders with the error flash", async () => {
    const { user, id, cookie, csrf } = await setup();
    const path = `/dashboard/domains/${id}/auto-create`;
    await post(path, cookie, {
      "form-name": "create-auto-create-rule",
      csrf_token: csrf,
      regex: "a.*",
      order: "5",
      mailbox_ids: [String(user.default_mailbox_id)],
    });
    await clearFlashes(cookie);
    const res = await post(path, cookie, {
      "form-name": "create-auto-create-rule",
      csrf_token: csrf,
      regex: "b.*",
      order: "5",
      mailbox_ids: [String(user.default_mailbox_id)],
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      "Another rule with the same order already exists",
    );
  });

  it("regex validation/matching follows Python re, not JS RegExp", async () => {
    const { user, id, domain, cookie, csrf } = await setup();
    const path = `/dashboard/domains/${id}/auto-create`;
    // Python-only named-group syntax is accepted (re.compile allows it)
    const res = await post(path, cookie, {
      "form-name": "create-auto-create-rule",
      csrf_token: csrf,
      regex: "(?P<u>[a-z]+)",
      display_name: "",
      order: "3",
      mailbox_ids: [String(user.default_mailbox_id)],
    });
    expect(res.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      { category: "success", message: "New auto create rule has been created" },
    ]);
    await clearFlashes(cookie);
    const rule = await env.DB.prepare(
      "SELECT regex FROM auto_create_rule WHERE custom_domain_id = ?1",
    )
      .bind(id)
      .first<{ regex: string }>();
    expect(rule?.regex).toBe("(?P<u>[a-z]+)");

    // the test form matches the stored Python pattern (re2/re fullmatch)
    const res2 = await post(path, cookie, {
      "form-name": "test-auto-create-rule",
      csrf_token: csrf,
      local: "abc",
    });
    expect(res2.status).toBe(200);
    expect(await res2.text()).toContain(`abc@${domain} passes rule #3`);

    // JS-only named-group syntax is an "unknown extension" for Python re
    const res3 = await post(path, cookie, {
      "form-name": "create-auto-create-rule",
      csrf_token: csrf,
      regex: "(?<u>[a-z]+)",
      display_name: "",
      order: "4",
      mailbox_ids: [String(user.default_mailbox_id)],
    });
    expect(res3.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      { category: "error", message: "Invalid regex (?<u>[a-z]+)" },
    ]);
    const count = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM auto_create_rule WHERE custom_domain_id = ?1",
    )
      .bind(id)
      .first<{ n: number }>();
    expect(count?.n).toBe(1);
  });

  it("missing mailbox selection flashes the warning", async () => {
    const { id, cookie, csrf } = await setup();
    const res = await post(`/dashboard/domains/${id}/auto-create`, cookie, {
      "form-name": "create-auto-create-rule",
      csrf_token: csrf,
      regex: "c.*",
      order: "7",
    });
    expect(res.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      { category: "warning", message: "You must select at least 1 mailbox" },
    ]);
  });
});

// ---------------------------------------------------------------------------

describe("route 11: /dashboard/subdomain", () => {
  it("redirects to the dashboard when no SLDomain allows subdomains", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const res = await get("/dashboard/subdomain", cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "error",
        message: "Unknown error, redirect to the home page",
      },
    ]);
  });

  it("creates a subdomain and decrements the quota", async () => {
    await env.DB.prepare(
      "INSERT INTO public_domain (domain, can_use_subdomain) VALUES ('subs.example.com', 1)",
    ).run();
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const res = await get("/dashboard/subdomain", cookie);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("New Subdomain");

    const csrf = await getCsrf("/dashboard/subdomain", cookie);
    const res2 = await post("/dashboard/subdomain", cookie, {
      "form-name": "create",
      csrf_token: csrf,
      subdomain: `mysub${user.id}`,
      domain: "subs.example.com",
    });
    expect(res2.status).toBe(302);
    const row = await env.DB.prepare(
      "SELECT * FROM custom_domain WHERE domain = ?1",
    )
      .bind(`mysub${user.id}.subs.example.com`)
      .first<{
        id: number;
        is_sl_subdomain: number;
        catch_all: number;
        verified: number;
        ownership_verified: number;
      }>();
    expect(row).toBeTruthy();
    expect(row?.is_sl_subdomain).toBe(1);
    expect(row?.catch_all).toBe(1);
    expect(row?.verified).toBe(1);
    expect(row?.ownership_verified).toBe(1);
    expect(res2.headers.get("location")).toBe(
      `/dashboard/domains/${row?.id}/info`,
    );
    const quota = await env.DB.prepare(
      "SELECT subdomain_quota FROM users WHERE id = ?1",
    )
      .bind(user.id)
      .first<{ subdomain_quota: number }>();
    expect(quota?.subdomain_quota).toBe(4);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "success",
        message: `New subdomain mysub${user.id}.subs.example.com is created`,
      },
    ]);
  });

  it("rejects too-short and malformed subdomains", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/subdomain", cookie);
    const res = await post("/dashboard/subdomain", cookie, {
      "form-name": "create",
      csrf_token: csrf,
      subdomain: "ab",
      domain: "subs.example.com",
    });
    expect(res.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "error",
        message: "Subdomain must have at least 3 characters",
      },
    ]);
    await clearFlashes(cookie);
    const res2 = await post("/dashboard/subdomain", cookie, {
      "form-name": "create",
      csrf_token: csrf,
      subdomain: "bad_sub",
      domain: "subs.example.com",
    });
    expect(res2.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "error",
        message:
          "Subdomain can only contain lowercase letters, numbers and dashes (-)",
      },
    ]);
  });

  it("form without csrf flashes Invalid new subdomain", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await getCsrf("/dashboard/subdomain", cookie);
    const res = await post("/dashboard/subdomain", cookie, {
      "form-name": "create",
      csrf_token: "bad",
      subdomain: "abc",
      domain: "subs.example.com",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/subdomain");
    expect(await getFlashes(cookie)).toEqual([
      { category: "warning", message: "Invalid new subdomain" },
    ]);
  });

  it("MAX_NB_SUBDOMAIN env var caps the subdomain quota", async () => {
    await env.DB.prepare(
      "INSERT OR IGNORE INTO public_domain (domain, can_use_subdomain) VALUES ('subs.example.com', 1)",
    ).run();
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/subdomain", cookie);
    const envx = env as unknown as Record<string, unknown>;
    envx.MAX_NB_SUBDOMAIN = "0";
    try {
      const res = await post("/dashboard/subdomain", cookie, {
        "form-name": "create",
        csrf_token: csrf,
        subdomain: `quotasub${user.id}`,
        domain: "subs.example.com",
      });
      expect(res.status).toBe(302);
      expect(await getFlashes(cookie)).toEqual([
        {
          category: "error",
          message: "You can't create more than 0 subdomains",
        },
      ]);
    } finally {
      delete envx.MAX_NB_SUBDOMAIN;
    }
  });
});

// ---------------------------------------------------------------------------

describe("route 12: /dashboard/directory", () => {
  it("GET renders the directory page", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const res = await get("/dashboard/directory", cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toMatch(/<title>\s*Directory\s*\| SimpleLogin\s*<\/title>/);
    expect(html).toContain("New Directory");
  });

  it("POST create makes the directory, links mailboxes, decrements quota", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/directory", cookie);
    const name = `mydir${user.id}`;
    const res = await post("/dashboard/directory", cookie, {
      "form-name": "create",
      csrf_token: csrf,
      name,
      mailbox_ids: [String(user.default_mailbox_id)],
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/directory");
    const dir = await env.DB.prepare("SELECT * FROM directory WHERE name = ?1")
      .bind(name)
      .first<{ id: number }>();
    expect(dir).toBeTruthy();
    const link = await env.DB.prepare(
      "SELECT mailbox_id FROM directory_mailbox WHERE directory_id = ?1",
    )
      .bind(dir?.id)
      .first<{ mailbox_id: number }>();
    expect(link?.mailbox_id).toBe(user.default_mailbox_id);
    const quota = await env.DB.prepare(
      "SELECT directory_quota FROM users WHERE id = ?1",
    )
      .bind(user.id)
      .first<{ directory_quota: number }>();
    expect(quota?.directory_quota).toBe(49);
    expect(await getFlashes(cookie)).toEqual([
      { category: "success", message: `Directory ${name} is created` },
    ]);
  });

  it("MAX_NB_DIRECTORY env var caps the directory quota", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/directory", cookie);
    const envx = env as unknown as Record<string, unknown>;
    envx.MAX_NB_DIRECTORY = "0";
    try {
      const res = await post("/dashboard/directory", cookie, {
        "form-name": "create",
        csrf_token: csrf,
        name: `quotadir${user.id}`,
      });
      expect(res.status).toBe(302);
      expect(await getFlashes(cookie)).toEqual([
        {
          category: "warning",
          message: "You cannot have more than 0 directories",
        },
      ]);
    } finally {
      delete envx.MAX_NB_DIRECTORY;
    }
  });

  it("reserved names are refused", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/directory", cookie);
    const res = await post("/dashboard/directory", cookie, {
      "form-name": "create",
      csrf_token: csrf,
      name: "bounces",
    });
    expect(res.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "warning",
        message: "this directory name is reserved, please choose another name",
      },
    ]);
  });

  it("toggle-directory disables and flashes the warning", async () => {
    const user = await createUser(env.DB);
    const dir = await env.DB.prepare(
      "INSERT INTO directory (user_id, name) VALUES (?1, ?2) RETURNING *",
    )
      .bind(user.id, `toggledir${user.id}`)
      .first<{ id: number; name: string }>();
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/directory", cookie);
    const res = await post("/dashboard/directory", cookie, {
      "form-name": "toggle-directory",
      csrf_token: csrf,
      directory_id: String(dir?.id),
      // no directory_enabled field => disable
    });
    expect(res.status).toBe(302);
    const row = await env.DB.prepare(
      "SELECT disabled FROM directory WHERE id = ?1",
    )
      .bind(dir?.id)
      .first<{ disabled: number }>();
    expect(row?.disabled).toBe(1);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "warning",
        message: `On-the-fly is disabled for ${dir?.name}`,
      },
    ]);
  });

  it("delete removes the directory, its aliases and blocks the name", async () => {
    const user = await createUser(env.DB);
    const dir = await env.DB.prepare(
      "INSERT INTO directory (user_id, name) VALUES (?1, ?2) RETURNING *",
    )
      .bind(user.id, `deldir${user.id}`)
      .first<{ id: number; name: string }>();
    const alias = await createAlias(
      env.DB,
      user.id,
      user.default_mailbox_id as number,
      { directory_id: dir?.id },
    );
    const cookie = await sessionCookieFor(user.id);
    const csrf = await getCsrf("/dashboard/directory", cookie);
    const res = await post("/dashboard/directory", cookie, {
      "form-name": "delete",
      csrf_token: csrf,
      directory_id: String(dir?.id),
    });
    expect(res.status).toBe(302);
    expect(
      await env.DB.prepare("SELECT 1 FROM directory WHERE id = ?1")
        .bind(dir?.id)
        .first(),
    ).toBeNull();
    expect(
      await env.DB.prepare("SELECT 1 FROM deleted_directory WHERE name = ?1")
        .bind(dir?.name)
        .first(),
    ).toBeTruthy();
    // default alias_delete_action = MoveToTrash -> delete_on set
    const aliasRow = await env.DB.prepare(
      "SELECT delete_on FROM alias WHERE id = ?1",
    )
      .bind(alias.id)
      .first<{ delete_on: string | null }>();
    expect(aliasRow?.delete_on).not.toBeNull();
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "success",
        message: `Directory ${dir?.name} has been deleted`,
      },
    ]);
  });

  it("invalid form (missing csrf) flashes Invalid request", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await getCsrf("/dashboard/directory", cookie);
    const res = await post("/dashboard/directory", cookie, {
      "form-name": "delete",
      csrf_token: "bad",
      directory_id: "1",
    });
    expect(res.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      { category: "warning", message: "Invalid request" },
    ]);
  });
});

// ---------------------------------------------------------------------------

describe("route 13: /dashboard/batch_import", () => {
  it("GET renders with the no-verified-domain warning flash", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id, true);
    const res = await get("/dashboard/batch_import", cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Alias Batch Import");
    expect(html).toContain(
      "Alias batch import is only available for custom domains",
    );
  });

  it("POST uploads the CSV to KV and enqueues the batch-import job", async () => {
    const user = await createUser(env.DB);
    await env.DB.prepare(
      "INSERT INTO custom_domain (user_id, domain, ownership_verified) VALUES (?1, ?2, 1)",
    )
      .bind(user.id, `imp${user.id}.example.org`)
      .run();
    const cookie = await sessionCookieFor(user.id, true);
    const csrf = await getCsrf("/dashboard/batch_import", cookie);
    const fd = new FormData();
    fd.append("csrf_token", csrf);
    fd.append(
      "alias-file",
      new File(["alias,note\nx@y.com,hi\n"], "import.csv", {
        type: "text/csv",
      }),
    );
    const res = await SELF.fetch(`${BASE}/dashboard/batch_import`, {
      method: "POST",
      headers: { Cookie: cookie },
      body: fd,
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/batch_import");
    const file = await env.DB.prepare(
      "SELECT * FROM file WHERE user_id = ?1 ORDER BY id DESC LIMIT 1",
    )
      .bind(user.id)
      .first<{ id: number; path: string }>();
    expect(file).toBeTruthy();
    expect(await env.KV.get(`file:${file?.path}`)).toContain("alias,note");
    const bi = await env.DB.prepare(
      "SELECT id FROM batch_import WHERE user_id = ?1",
    )
      .bind(user.id)
      .first<{ id: number }>();
    expect(bi).toBeTruthy();
    const job = await env.DB.prepare(
      "SELECT payload FROM job WHERE name = 'batch-import' ORDER BY id DESC LIMIT 1",
    ).first<{ payload: string }>();
    expect(JSON.parse(job?.payload ?? "{}")).toEqual({
      batch_import_id: bi?.id,
    });
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "success",
        message:
          "The file has been uploaded successfully and the import will start shortly",
      },
    ]);

    // the uploaded file is downloadable via the presigned-URL replacement
    const dl = await get(`/dashboard/files/${file?.path}`, cookie);
    expect(dl.status).toBe(200);
    expect(await dl.text()).toContain("alias,note");
  });

  it("users with disable_import are turned away", async () => {
    const user = await createUser(env.DB, { disable_import: 1 });
    const cookie = await sessionCookieFor(user.id, true);
    const res = await get("/dashboard/batch_import", cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    const flashes = await getFlashes(cookie);
    expect(flashes).toContainEqual({
      category: "error",
      message:
        "you cannot use the import feature, please contact SimpleLogin team",
    });
  });
});

// ---------------------------------------------------------------------------

describe("route 14: /dashboard/refused_email", () => {
  it("GET renders the quarantine list", async () => {
    const user = await createUser(env.DB);
    const alias = await createAlias(
      env.DB,
      user.id,
      user.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, user.id, alias.id);
    const refused = await env.DB.prepare(
      "INSERT INTO refused_email (full_report_path, path, user_id, delete_at) VALUES (?1, ?2, ?3, ?4) RETURNING id",
    )
      .bind(
        `refused-${user.id}.eml`,
        null,
        user.id,
        "2030-01-01 00:00:00+00:00",
      )
      .first<{ id: number }>();
    const log = await createEmailLog(env.DB, user.id, contact.id, {
      refused_email_id: refused?.id,
      bounced: 1,
    });
    const cookie = await sessionCookieFor(user.id);
    const res = await get("/dashboard/refused_email", cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toMatch(/<title>\s*Quarantine\s*\| SimpleLogin\s*<\/title>/);
    expect(html).toContain(contact.website_email);
    expect(html).toContain(alias.email);
    expect(html).toContain("Bounce");

    // POST behaves like GET; highlight_id parses
    const res2 = await SELF.fetch(
      `${BASE}/dashboard/refused_email?highlight_id=${log.id}`,
      { method: "POST", headers: { Cookie: cookie }, redirect: "manual" },
    );
    expect(res2.status).toBe(200);
    expect(await res2.text()).toContain("highlight-row");
  });
});
