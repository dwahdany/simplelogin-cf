/**
 * Integration tests for the alias-centric dashboard pages
 * (specs/web/02-alias-pages.md). Exercised through SELF.fetch so the
 * strict-slash middleware, error pages and KV session plumbing all apply.
 */

import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { timestampSign } from "../src/lib/crypto";
import { sentEmails } from "../src/lib/mailer";
import type {
  AliasRow,
  ContactRow,
  MailboxRow,
  UserRow,
} from "../src/lib/rows";
import {
  createAlias,
  createContact,
  createEmailLog,
  createMailbox,
  createUser,
} from "./fixtures";

const BASE = "https://app.sl.example.com";
const FLASK_SECRET = "test-flask-secret";

let tokenSeq = 0;

interface WebSession {
  user: UserRow;
  cookie: string;
  token: string;
  /** valid csrf_token form-field value for this session */
  csrf: string;
}

async function webSession(
  userOverrides: Record<string, unknown> = {},
  sessionExtra: Record<string, unknown> = {},
  existingUser?: UserRow,
): Promise<WebSession> {
  const user = existingUser ?? (await createUser(env.DB, userOverrides));
  const token = `webtest-${++tokenSeq}`;
  const csrfSecret = `csrfsecret${tokenSeq}`.padEnd(40, "0");
  await env.KV.put(
    `session:${token}`,
    JSON.stringify({ user_id: user.id, csrf: csrfSecret, ...sessionExtra }),
  );
  const csrf = await timestampSign(`${FLASK_SECRET}wtf-csrf-token`, csrfSecret);
  return { user, cookie: `slapp=${token}`, token, csrf };
}

async function flashes(
  token: string,
): Promise<Array<{ category: string; message: string }>> {
  const raw = await env.KV.get(`session:${token}`);
  if (!raw) return [];
  return (JSON.parse(raw).flashes ?? []) as Array<{
    category: string;
    message: string;
  }>;
}

function get(path: string, cookie?: string): Promise<Response> {
  return SELF.fetch(BASE + path, {
    headers: cookie ? { Cookie: cookie } : {},
    redirect: "manual",
  });
}

function post(
  path: string,
  cookie: string,
  data: Record<string, string | string[]>,
): Promise<Response> {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(data)) {
    if (Array.isArray(v)) for (const x of v) params.append(k, x);
    else params.append(k, v);
  }
  return SELF.fetch(BASE + path, {
    method: "POST",
    headers: {
      Cookie: cookie,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params.toString(),
    redirect: "manual",
  });
}

function defaultMailbox(user: UserRow): Promise<MailboxRow | null> {
  return env.DB.prepare("SELECT * FROM mailbox WHERE id = ?1")
    .bind(user.default_mailbox_id)
    .first<MailboxRow>();
}

function aliasRow(id: number): Promise<AliasRow | null> {
  return env.DB.prepare("SELECT * FROM alias WHERE id = ?1")
    .bind(id)
    .first<AliasRow>();
}

async function seedPublicDomain(): Promise<void> {
  await env.DB.prepare(
    "INSERT OR IGNORE INTO public_domain (domain) VALUES ('sl.example.com')",
  ).run();
}

// ---------------------------------------------------------------------------
// auth gating
// ---------------------------------------------------------------------------

describe("auth gating", () => {
  it("redirects anonymous GET /dashboard/ to login with next=", async () => {
    const res = await get("/dashboard/");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      "/auth/login?next=%2Fdashboard%3F",
    );
  });

  it("gates every route in the group", async () => {
    for (const path of [
      "/dashboard/custom_alias",
      "/dashboard/alias_log/1",
      "/dashboard/alias_export",
      "/dashboard/alias_transfer/send/1",
      "/dashboard/alias_transfer/receive",
      "/dashboard/alias_contact_manager/1",
      "/dashboard/contact/1",
    ]) {
      const res = await get(path);
      expect(res.status, path).toBe(302);
      expect(res.headers.get("location"), path).toMatch(
        /^\/auth\/login\?next=/,
      );
    }
  });

  it("404s non-integer path params before the handler", async () => {
    const s = await webSession();
    const res = await get("/dashboard/alias_log/abc", s.cookie);
    expect(res.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// 1. GET /dashboard/ — alias list
// ---------------------------------------------------------------------------

describe("index page (GET)", () => {
  it("renders alias cards, stats and marks intro_shown", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, s.user.id, alias.id);
    await createEmailLog(env.DB, s.user.id, contact.id);

    const res = await get("/dashboard/", s.cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(alias.email);
    expect(html).toContain(contact.website_email);
    expect(html).toContain('name="form-name" value="create-random-email"');
    expect(html).toContain("Sort by most recent activity");

    const row = await env.DB.prepare(
      "SELECT intro_shown FROM users WHERE id = ?1",
    )
      .bind(s.user.id)
      .first<{ intro_shown: number }>();
    expect(row?.intro_shown).toBe(1);
  });

  it("applies the disabled filter", async () => {
    const s = await webSession();
    const mbId = s.user.default_mailbox_id as number;
    const enabled = await createAlias(env.DB, s.user.id, mbId, { enabled: 1 });
    const disabled = await createAlias(env.DB, s.user.id, mbId, { enabled: 0 });

    const res = await get("/dashboard/?filter=disabled", s.cookie);
    const html = await res.text();
    expect(html).toContain(disabled.email);
    expect(html).not.toContain(`id="alias-container-${enabled.id}"`);
  });
});

// ---------------------------------------------------------------------------
// 1. POST /dashboard/ — index actions
// ---------------------------------------------------------------------------

describe("index page (POST)", () => {
  it("rejects an invalid CSRF token with a flash + redirect", async () => {
    const s = await webSession();
    const res = await post("/dashboard/", s.cookie, {
      "form-name": "create-random-email",
      csrf_token: "bogus",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard");
    const f = await flashes(s.token);
    expect(f).toContainEqual({
      category: "warning",
      message: "Invalid request",
    });
  });

  it("creates a random word alias and redirects with highlight", async () => {
    const s = await webSession();
    const res = await post("/dashboard/", s.cookie, {
      "form-name": "create-random-email",
      csrf_token: s.csrf,
    });
    expect(res.status).toBe(302);
    const loc = res.headers.get("location") ?? "";
    const m = loc.match(
      /^\/dashboard\/\?highlight_alias_id=(\d+)&query=&sort=&filter=$/,
    );
    expect(m, loc).toBeTruthy();
    const alias = await aliasRow(Number(m?.[1]));
    expect(alias?.user_id).toBe(s.user.id);
    expect(alias?.email).toMatch(/@sl\.example\.com$/);
    const f = await flashes(s.token);
    expect(f[0].category).toBe("success");
    expect(f[0].message).toBe(`Alias ${alias?.email} has been created`);
  });

  it("creates a uuid alias when generator_scheme=2", async () => {
    const s = await webSession();
    const res = await post("/dashboard/", s.cookie, {
      "form-name": "create-random-email",
      generator_scheme: "2",
      csrf_token: s.csrf,
    });
    const loc = res.headers.get("location") ?? "";
    const id = Number(loc.match(/highlight_alias_id=(\d+)/)?.[1]);
    const alias = await aliasRow(id);
    expect(alias?.email).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@sl\.example\.com$/,
    );
  });

  it("redirects create-custom-email to the custom alias page", async () => {
    const s = await webSession();
    const res = await post("/dashboard/", s.cookie, {
      "form-name": "create-custom-email",
      csrf_token: s.csrf,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/custom_alias");
  });

  it("moves an alias to the trash on delete (MoveToTrash default)", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const res = await post("/dashboard/", s.cookie, {
      "form-name": "delete-alias",
      "alias-id": String(alias.id),
      csrf_token: s.csrf,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      "/dashboard/?query=&sort=&filter=&page=0",
    );
    const row = await aliasRow(alias.id);
    expect(row?.delete_on).not.toBeNull();
    expect(row?.enabled).toBe(0);
    const f = await flashes(s.token);
    expect(f[0].message).toBe(
      `Alias ${alias.email} has been moved to the trash`,
    );
  });

  it("hard-deletes when alias_delete_action=DeleteImmediately", async () => {
    const s = await webSession({ alias_delete_action: 1 });
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    await post("/dashboard/", s.cookie, {
      "form-name": "delete-alias",
      "alias-id": String(alias.id),
      csrf_token: s.csrf,
    });
    expect(await aliasRow(alias.id)).toBeNull();
    const deleted = await env.DB.prepare(
      "SELECT * FROM deleted_alias WHERE email = ?1",
    )
      .bind(alias.email)
      .first();
    expect(deleted).not.toBeNull();
    const f = await flashes(s.token);
    expect(f[0].message).toBe(`Alias ${alias.email} has been deleted`);
  });

  it("disables an alias", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    await post("/dashboard/", s.cookie, {
      "form-name": "disable-alias",
      "alias-id": String(alias.id),
      csrf_token: s.csrf,
    });
    const row = await aliasRow(alias.id);
    expect(row?.enabled).toBe(0);
    const f = await flashes(s.token);
    expect(f[0].message).toBe(`Alias ${alias.email} has been disabled`);
  });

  it("flashes an error when deleting someone else's alias", async () => {
    const s = await webSession();
    const other = await createUser(env.DB);
    const alias = await createAlias(
      env.DB,
      other.id,
      other.default_mailbox_id as number,
    );
    const res = await post("/dashboard/", s.cookie, {
      "form-name": "delete-alias",
      "alias-id": String(alias.id),
      csrf_token: s.csrf,
    });
    expect(res.headers.get("location")).toBe(
      "/dashboard/?query=&sort=&filter=",
    );
    const f = await flashes(s.token);
    expect(f[0]).toEqual({
      category: "error",
      message: "Unknown error, sorry for the inconvenience",
    });
    expect(await aliasRow(alias.id)).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 2. POST /dashboard/contacts/<id>/toggle — htmx partial
// ---------------------------------------------------------------------------

describe("toggle contact (htmx)", () => {
  it("returns plain 400 on CSRF failure", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, s.user.id, alias.id);
    const res = await post(
      `/dashboard/contacts/${contact.id}/toggle`,
      s.cookie,
      {
        csrf_token: "bad",
      },
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("Invalid request");
  });

  it("returns plain 403 for another user's contact", async () => {
    const s = await webSession();
    const other = await createUser(env.DB);
    const alias = await createAlias(
      env.DB,
      other.id,
      other.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, other.id, alias.id);
    const res = await post(
      `/dashboard/contacts/${contact.id}/toggle`,
      s.cookie,
      {
        csrf_token: s.csrf,
      },
    );
    expect(res.status).toBe(403);
    expect(await res.text()).toBe("Forbidden");
  });

  it("toggles block_forward and returns the partial with the toast", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, s.user.id, alias.id);
    const res = await post(
      `/dashboard/contacts/${contact.id}/toggle`,
      s.cookie,
      {
        csrf_token: s.csrf,
      },
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(
      `hx-post="/dashboard/contacts/${contact.id}/toggle"`,
    );
    expect(html).toContain(
      `${contact.website_email} can no longer send emails to ${alias.email}`,
    );
    const row = await env.DB.prepare(
      "SELECT block_forward FROM contact WHERE id = ?1",
    )
      .bind(contact.id)
      .first<{ block_forward: number }>();
    expect(row?.block_forward).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// 3. /dashboard/custom_alias
// ---------------------------------------------------------------------------

describe("custom alias page", () => {
  it("GET renders the suffix select and mailboxes", async () => {
    await seedPublicDomain();
    const s = await webSession();
    const res = await get("/dashboard/custom_alias", s.cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('name="signed-alias-suffix"');
    expect(html).toContain('name="prefix"');
    expect(html).toContain("(Public domain)");
    const mb = await defaultMailbox(s.user);
    expect(html).toContain(mb?.email ?? "@@nope@@");
  });

  it("redirects free users at their alias limit", async () => {
    const s = await webSession({ trial_end: null });
    const mbId = s.user.default_mailbox_id as number;
    // MAX_NB_EMAIL_FREE_PLAN=3 in wrangler vars
    for (let i = 0; i < 3; i++) await createAlias(env.DB, s.user.id, mbId);
    const res = await get("/dashboard/custom_alias", s.cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    const f = await flashes(s.token);
    expect(f[0]).toEqual({
      category: "warning",
      message:
        "You have reached free plan limit, please upgrade to create new aliases",
    });
  });

  it("creates a custom alias (happy path, two mailboxes)", async () => {
    await seedPublicDomain();
    const s = await webSession();
    const mb2 = await createMailbox(
      env.DB,
      s.user.id,
      `second-${s.user.id}@example.com`,
    );
    const suffix = ".wxyz@sl.example.com";
    const signed = await timestampSign(`${FLASK_SECRET}custom_alias`, suffix);
    const res = await post("/dashboard/custom_alias", s.cookie, {
      prefix: "Hello Prefix",
      "signed-alias-suffix": signed,
      mailboxes: [String(s.user.default_mailbox_id), String(mb2.id)],
      note: "my note",
      csrf_token: s.csrf,
    });
    expect(res.status).toBe(302);
    const loc = res.headers.get("location") ?? "";
    const id = Number(
      loc.match(/^\/dashboard\/\?highlight_alias_id=(\d+)$/)?.[1],
    );
    const alias = await aliasRow(id);
    expect(alias?.email).toBe(`helloprefix${suffix}`);
    expect(alias?.note).toBe("my note");
    expect(alias?.mailbox_id).toBe(s.user.default_mailbox_id);
    const extra = await env.DB.prepare(
      "SELECT mailbox_id FROM alias_mailbox WHERE alias_id = ?1",
    )
      .bind(id)
      .all<{ mailbox_id: number }>();
    expect(extra.results.map((r) => r.mailbox_id)).toEqual([mb2.id]);
    const f = await flashes(s.token);
    expect(f[0].message).toBe(`Alias ${alias?.email} has been created`);
  });

  it("rejects a bad prefix with the exact flash", async () => {
    await seedPublicDomain();
    const s = await webSession();
    const signed = await timestampSign(
      `${FLASK_SECRET}custom_alias`,
      ".abcd@sl.example.com",
    );
    const res = await post("/dashboard/custom_alias", s.cookie, {
      prefix: "Bad!Prefix",
      "signed-alias-suffix": signed,
      mailboxes: [String(s.user.default_mailbox_id)],
      csrf_token: s.csrf,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/custom_alias");
    const f = await flashes(s.token);
    expect(f[0]).toEqual({
      category: "error",
      message:
        "Only lowercase letters, numbers, dashes (-), dots (.) and underscores (_) are currently supported for alias prefix. Cannot be more than 40 letters",
    });
  });

  it("flashes the expired message for a tampered suffix", async () => {
    await seedPublicDomain();
    const s = await webSession();
    const res = await post("/dashboard/custom_alias", s.cookie, {
      prefix: "hello",
      "signed-alias-suffix": "not-a-signature",
      mailboxes: [String(s.user.default_mailbox_id)],
      csrf_token: s.csrf,
    });
    expect(res.status).toBe(302);
    const f = await flashes(s.token);
    expect(f[0]).toEqual({
      category: "warning",
      message: "Alias creation time is expired, please retry",
    });
  });

  it("re-renders (200) when the alias already belongs to the user", async () => {
    await seedPublicDomain();
    const s = await webSession();
    const suffix = ".dupx@sl.example.com";
    const signed = await timestampSign(`${FLASK_SECRET}custom_alias`, suffix);
    await createAlias(env.DB, s.user.id, s.user.default_mailbox_id as number, {
      email: `mine${suffix}`,
    });
    const res = await post("/dashboard/custom_alias", s.cookie, {
      prefix: "mine",
      "signed-alias-suffix": signed,
      mailboxes: [String(s.user.default_mailbox_id)],
      csrf_token: s.csrf,
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(`You already have this alias mine${suffix}`);
  });

  it("requires at least one mailbox", async () => {
    await seedPublicDomain();
    const s = await webSession();
    const signed = await timestampSign(
      `${FLASK_SECRET}custom_alias`,
      ".mbxx@sl.example.com",
    );
    const res = await post("/dashboard/custom_alias", s.cookie, {
      prefix: "hello",
      "signed-alias-suffix": signed,
      csrf_token: s.csrf,
    });
    expect(res.status).toBe(302);
    const f = await flashes(s.token);
    expect(f[0]).toEqual({
      category: "error",
      message: "At least one mailbox must be selected",
    });
  });
});

// ---------------------------------------------------------------------------
// 4. /dashboard/alias_log
// ---------------------------------------------------------------------------

describe("alias log", () => {
  it("renders counters and log lines", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, s.user.id, alias.id);
    await createEmailLog(env.DB, s.user.id, contact.id); // forward
    await createEmailLog(env.DB, s.user.id, contact.id, { is_reply: 1 });
    await createEmailLog(env.DB, s.user.id, contact.id, { blocked: 1 });

    const res = await get(`/dashboard/alias_log/${alias.id}`, s.cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(alias.email);
    expect(html).toContain(contact.website_email);
    // paginated variant also works
    const res2 = await get(`/dashboard/alias_log/${alias.id}/0`, s.cookie);
    expect(res2.status).toBe(200);
  });

  it("redirects with a flash for someone else's alias", async () => {
    const s = await webSession();
    const other = await createUser(env.DB);
    const alias = await createAlias(
      env.DB,
      other.id,
      other.default_mailbox_id as number,
    );
    const res = await get(`/dashboard/alias_log/${alias.id}`, s.cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    const f = await flashes(s.token);
    expect(f[0]).toEqual({
      category: "warning",
      message: "You do not have access to this page",
    });
  });
});

// ---------------------------------------------------------------------------
// 5. /dashboard/alias_export — CSV, sudo
// ---------------------------------------------------------------------------

describe("alias export", () => {
  it("redirects to enter_sudo without a fresh sudo_time", async () => {
    const s = await webSession();
    const res = await get("/dashboard/alias_export", s.cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      "/dashboard/enter_sudo?next=%2Fdashboard%2Falias_export",
    );
  });

  it("returns the CSV when sudo is fresh", async () => {
    const s = await webSession(
      {},
      { sudo_time: Math.floor(Date.now() / 1000) },
    );
    const mb = await defaultMailbox(s.user);
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
      {
        note: 'note with, comma and "quote"',
        enabled: 1,
      },
    );
    const res = await get("/dashboard/alias_export", s.cookie);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/csv");
    expect(res.headers.get("content-disposition")).toBe(
      "attachment; filename=aliases.csv",
    );
    const body = await res.text();
    const lines = body.split("\r\n");
    expect(lines[0]).toBe("alias,note,enabled,mailboxes");
    expect(body).toContain(
      `${alias.email},"note with, comma and ""quote""",True,${mb?.email}`,
    );
  });
});

// ---------------------------------------------------------------------------
// 6+7. alias transfer send / receive
// ---------------------------------------------------------------------------

describe("alias transfer", () => {
  const sudo = () => ({ sudo_time: Math.floor(Date.now() / 1000) });

  it("send page requires sudo", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const res = await get(
      `/dashboard/alias_transfer/send/${alias.id}`,
      s.cookie,
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      `/dashboard/enter_sudo?next=%2Fdashboard%2Falias_transfer%2Fsend%2F${alias.id}`,
    );
  });

  it("guards against transferring someone else's alias", async () => {
    const s = await webSession({}, sudo());
    const other = await createUser(env.DB);
    const alias = await createAlias(
      env.DB,
      other.id,
      other.default_mailbox_id as number,
    );
    const res = await get(
      `/dashboard/alias_transfer/send/${alias.id}`,
      s.cookie,
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    const f = await flashes(s.token);
    expect(f[0]).toEqual({
      category: "warning",
      message: "You cannot see this page",
    });
  });

  it("creates and removes a transfer URL", async () => {
    const s = await webSession({}, sudo());
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );

    const createRes = await post(
      `/dashboard/alias_transfer/send/${alias.id}`,
      s.cookie,
      { "form-name": "create", csrf_token: s.csrf },
    );
    expect(createRes.status).toBe(200);
    const html = await createRes.text();
    const m = html.match(
      /\/dashboard\/alias_transfer\/receive\?token=([A-Za-z0-9_\-.]+)/,
    );
    expect(m).toBeTruthy();
    const plaintext = m?.[1] as string;
    expect(plaintext.startsWith(`${alias.id}.`)).toBe(true);
    const row = await aliasRow(alias.id);
    expect(row?.transfer_token).not.toBeNull();
    expect(row?.transfer_token).not.toBe(plaintext); // stored hashed
    expect(row?.transfer_token_expiration).not.toBeNull();
    expect(html).toContain("Share alias URL created");

    const removeRes = await post(
      `/dashboard/alias_transfer/send/${alias.id}`,
      s.cookie,
      { "form-name": "remove", csrf_token: s.csrf },
    );
    expect(removeRes.status).toBe(200);
    const row2 = await aliasRow(alias.id);
    expect(row2?.transfer_token).toBeNull();
    expect(row2?.transfer_token_expiration).toBeNull();
    expect(await removeRes.text()).toContain("Share URL deleted");
  });

  it("rejects a missing/invalid receive token", async () => {
    const s = await webSession();
    const res = await get("/dashboard/alias_transfer/receive", s.cookie);
    expect(res.status).toBe(302);
    let f = await flashes(s.token);
    expect(f[0]).toEqual({
      category: "error",
      message: "Invalid transfer token",
    });

    const res2 = await get(
      "/dashboard/alias_transfer/receive?token=nope",
      s.cookie,
    );
    expect(res2.status).toBe(302);
    f = await flashes(s.token);
    expect(f[1]).toEqual({ category: "error", message: "Invalid link" });
  });

  it("transfers ownership end-to-end (last mailbox becomes primary)", async () => {
    sentEmails.length = 0;
    const sender = await webSession({}, sudo());
    const alias = await createAlias(
      env.DB,
      sender.user.id,
      sender.user.default_mailbox_id as number,
      { pinned: 1 },
    );

    const createRes = await post(
      `/dashboard/alias_transfer/send/${alias.id}`,
      sender.cookie,
      { "form-name": "create", csrf_token: sender.csrf },
    );
    const token = (await createRes.text()).match(
      /receive\?token=([A-Za-z0-9_\-.]+)/,
    )?.[1] as string;

    const receiver = await webSession();
    const mb2 = await createMailbox(
      env.DB,
      receiver.user.id,
      `recv2-${receiver.user.id}@example.com`,
    );

    const getRes = await get(
      `/dashboard/alias_transfer/receive?token=${token}`,
      receiver.cookie,
    );
    expect(getRes.status).toBe(200);
    expect(await getRes.text()).toContain(`Receive ${alias.email}`);

    const postRes = await post(
      `/dashboard/alias_transfer/receive?token=${token}`,
      receiver.cookie,
      {
        mailbox_ids: [String(receiver.user.default_mailbox_id), String(mb2.id)],
        csrf_token: receiver.csrf,
      },
    );
    expect(postRes.status).toBe(302);
    expect(postRes.headers.get("location")).toBe(
      `/dashboard/?highlight_alias_id=${alias.id}`,
    );

    const row = await aliasRow(alias.id);
    expect(row?.user_id).toBe(receiver.user.id);
    expect(row?.mailbox_id).toBe(mb2.id); // .pop() gotcha: LAST is primary
    expect(row?.pinned).toBe(0);
    expect(row?.original_owner_id).toBe(sender.user.id);
    expect(row?.transfer_token).toBeNull();
    const extra = await env.DB.prepare(
      "SELECT mailbox_id FROM alias_mailbox WHERE alias_id = ?1",
    )
      .bind(alias.id)
      .all<{ mailbox_id: number }>();
    expect(extra.results.map((r) => r.mailbox_id)).toEqual([
      receiver.user.default_mailbox_id,
    ]);

    const f = await flashes(receiver.token);
    expect(f[0]).toEqual({
      category: "success",
      message: `You are now owner of ${alias.email}`,
    });
    expect(
      sentEmails.some(
        (e) =>
          e.to === sender.user.email &&
          e.subject === `Alias ${alias.email} has been received`,
      ),
    ).toBe(true);
  });

  it("rejects receiving your own alias", async () => {
    const s = await webSession({}, sudo());
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const createRes = await post(
      `/dashboard/alias_transfer/send/${alias.id}`,
      s.cookie,
      { "form-name": "create", csrf_token: s.csrf },
    );
    const token = (await createRes.text()).match(
      /receive\?token=([A-Za-z0-9_\-.]+)/,
    )?.[1] as string;
    const res = await get(
      `/dashboard/alias_transfer/receive?token=${token}`,
      s.cookie,
    );
    expect(res.status).toBe(302);
    const f = await flashes(s.token);
    expect(f.at(-1)).toEqual({
      category: "warning",
      message: "You already own this alias",
    });
  });
});

// ---------------------------------------------------------------------------
// 8. /dashboard/alias_contact_manager
// ---------------------------------------------------------------------------

describe("alias contact manager", () => {
  it("GET renders contacts + create form", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, s.user.id, alias.id);
    const res = await get(
      `/dashboard/alias_contact_manager/${alias.id}`,
      s.cookie,
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(`${alias.email} contacts`);
    expect(html).toContain(contact.website_email);
    expect(html).toContain("Create reverse-alias");
  });

  it("guards other users' aliases", async () => {
    const s = await webSession();
    const other = await createUser(env.DB);
    const alias = await createAlias(
      env.DB,
      other.id,
      other.default_mailbox_id as number,
    );
    const res = await get(
      `/dashboard/alias_contact_manager/${alias.id}`,
      s.cookie,
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    const f = await flashes(s.token);
    expect(f[0]).toEqual({
      category: "warning",
      message: "You do not have access to this page",
    });
  });

  it("creates a contact (happy path)", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const res = await post(
      `/dashboard/alias_contact_manager/${alias.id}`,
      s.cookie,
      {
        "form-name": "create",
        email: "First Last <someone@example.net>",
        csrf_token: s.csrf,
      },
    );
    expect(res.status).toBe(302);
    const contact = await env.DB.prepare(
      "SELECT * FROM contact WHERE alias_id = ?1 AND website_email = ?2",
    )
      .bind(alias.id, "someone@example.net")
      .first<ContactRow>();
    expect(contact).not.toBeNull();
    expect(contact?.name).toBe("First Last");
    expect(contact?.reply_email).toMatch(/@sl\.example\.com$/);
    expect(res.headers.get("location")).toBe(
      `/dashboard/alias_contact_manager/${alias.id}?highlight_contact_id=${contact?.id}`,
    );
    const f = await flashes(s.token);
    expect(f[0]).toEqual({
      category: "success",
      message: "Reverse alias for First Last <someone@example.net> is created",
    });
  });

  it("re-renders with a field error on an invalid address", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const res = await post(
      `/dashboard/alias_contact_manager/${alias.id}`,
      s.cookie,
      { "form-name": "create", email: "not-an-email", csrf_token: s.csrf },
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(
      "Invalid email format. Email must be either email@example.com or *First Last &lt;email@example.com&gt;*",
    );
  });

  it("flashes 'is already added' for duplicates", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    await createContact(env.DB, s.user.id, alias.id, {
      website_email: "dup@example.net",
    });
    const res = await post(
      `/dashboard/alias_contact_manager/${alias.id}`,
      s.cookie,
      { "form-name": "create", email: "dup@example.net", csrf_token: s.csrf },
    );
    expect(res.status).toBe(302);
    const f = await flashes(s.token);
    expect(f[0]).toEqual({
      category: "error",
      message: "dup@example.net is already added",
    });
  });

  it("deletes a contact", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, s.user.id, alias.id);
    const res = await post(
      `/dashboard/alias_contact_manager/${alias.id}`,
      s.cookie,
      {
        "form-name": "delete",
        "contact-id": String(contact.id),
        csrf_token: s.csrf,
      },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      `/dashboard/alias_contact_manager/${alias.id}`,
    );
    const gone = await env.DB.prepare("SELECT 1 FROM contact WHERE id = ?1")
      .bind(contact.id)
      .first();
    expect(gone).toBeNull();
    const f = await flashes(s.token);
    expect(f[0]).toEqual({
      category: "success",
      message: `Reverse-alias for ${contact.website_email} has been deleted`,
    });
  });

  it("search POST redirects with the query", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const res = await post(
      `/dashboard/alias_contact_manager/${alias.id}`,
      s.cookie,
      { "form-name": "search", query: "abc", csrf_token: s.csrf },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      `/dashboard/alias_contact_manager/${alias.id}?query=abc`,
    );
  });

  it("rejects a bad CSRF token with flash + redirect", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const res = await post(
      `/dashboard/alias_contact_manager/${alias.id}`,
      s.cookie,
      { "form-name": "create", email: "x@example.net", csrf_token: "bad" },
    );
    expect(res.status).toBe(302);
    const f = await flashes(s.token);
    expect(f[0]).toEqual({ category: "warning", message: "Invalid request" });
  });
});

// ---------------------------------------------------------------------------
// 9. /dashboard/contact/<id> — PGP page
// ---------------------------------------------------------------------------

describe("contact detail (PGP)", () => {
  it("GET renders the PGP card", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, s.user.id, alias.id);
    const res = await get(`/dashboard/contact/${contact.id}`, s.cookie);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Pretty Good Privacy (PGP)");
    expect(html).toContain(contact.website_email);
  });

  it("guards contacts of other users", async () => {
    const s = await webSession();
    const other = await createUser(env.DB);
    const alias = await createAlias(
      env.DB,
      other.id,
      other.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, other.id, alias.id);
    const res = await get(`/dashboard/contact/${contact.id}`, s.cookie);
    expect(res.status).toBe(302);
    const f = await flashes(s.token);
    expect(f[0]).toEqual({
      category: "warning",
      message: "You cannot see this page",
    });
  });

  it("save flashes the PGP failure (deferred GnuPG) and keeps DB unchanged", async () => {
    const s = await webSession(); // trial => premium
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, s.user.id, alias.id);
    const res = await post(`/dashboard/contact/${contact.id}`, s.cookie, {
      "form-name": "pgp",
      action: "save",
      pgp: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxyz",
      csrf_token: s.csrf,
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Cannot add the public key, please verify it");
    // in-memory only: rejected key shown once, DB unchanged
    expect(html).toContain("BEGIN PGP PUBLIC KEY BLOCK");
    const row = await env.DB.prepare(
      "SELECT pgp_public_key FROM contact WHERE id = ?1",
    )
      .bind(contact.id)
      .first<{ pgp_public_key: string | null }>();
    expect(row?.pgp_public_key).toBeNull();
  });

  it("save with an empty key flashes 'Invalid pgp key'", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, s.user.id, alias.id);
    const res = await post(`/dashboard/contact/${contact.id}`, s.cookie, {
      "form-name": "pgp",
      action: "save",
      pgp: "",
      csrf_token: s.csrf,
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Invalid pgp key");
  });

  it("free users cannot save but the premium flash redirects", async () => {
    const s = await webSession({ trial_end: null });
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, s.user.id, alias.id);
    const res = await post(`/dashboard/contact/${contact.id}`, s.cookie, {
      "form-name": "pgp",
      action: "save",
      pgp: "whatever",
      csrf_token: s.csrf,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      `/dashboard/contact/${contact.id}`,
    );
    const f = await flashes(s.token);
    expect(f[0]).toEqual({
      category: "warning",
      message: "Only premium plan can add PGP Key",
    });
  });

  it("remove clears the key (works for free users)", async () => {
    const s = await webSession({ trial_end: null });
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, s.user.id, alias.id, {
      pgp_public_key: "KEY",
      pgp_finger_print: "FP",
    });
    const res = await post(`/dashboard/contact/${contact.id}`, s.cookie, {
      "form-name": "pgp",
      action: "remove",
      csrf_token: s.csrf,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      `/dashboard/contact/${contact.id}`,
    );
    const row = await env.DB.prepare(
      "SELECT pgp_public_key, pgp_finger_print FROM contact WHERE id = ?1",
    )
      .bind(contact.id)
      .first<{
        pgp_public_key: string | null;
        pgp_finger_print: string | null;
      }>();
    expect(row?.pgp_public_key).toBeNull();
    expect(row?.pgp_finger_print).toBeNull();
    const f = await flashes(s.token);
    expect(f[0]).toEqual({
      category: "success",
      message: `PGP public key for ${contact.website_email} is removed`,
    });
  });

  it("flashes Invalid request on a bad action or CSRF", async () => {
    const s = await webSession();
    const alias = await createAlias(
      env.DB,
      s.user.id,
      s.user.default_mailbox_id as number,
    );
    const contact = await createContact(env.DB, s.user.id, alias.id);
    const res = await post(`/dashboard/contact/${contact.id}`, s.cookie, {
      "form-name": "pgp",
      action: "explode",
      csrf_token: s.csrf,
    });
    expect(res.status).toBe(302);
    const f = await flashes(s.token);
    expect(f[0]).toEqual({ category: "warning", message: "Invalid request" });
  });
});
