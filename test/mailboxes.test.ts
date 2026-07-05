import { env, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { toEpoch } from "../src/lib/dates";
import { sentEmails } from "../src/lib/mailer";
import type {
  CustomDomainRow,
  DomainDeletedAliasRow,
  JobRow,
  MailboxRow,
  UserRow,
} from "../src/lib/rows";
import {
  createAlias,
  createApiKey,
  createMailbox,
  createUser,
} from "./fixtures";

// ---- local fixtures / helpers ----

let seq = 0;
const uniq = () => ++seq;

/** Fresh client IP per call so IP-keyed rate limits never interfere. */
let ipSeq = 0;
function nextIp(): string {
  const n = ++ipSeq;
  return `10.7.${Math.floor(n / 250)}.${(n % 250) + 1}`;
}

async function insertRow<T>(
  table: string,
  values: Record<string, unknown>,
): Promise<T> {
  const cols = Object.keys(values);
  const placeholders = cols.map((_, i) => `?${i + 1}`).join(", ");
  const columnList = cols.map((c) => `"${c}"`).join(", ");
  const row = await env.DB.prepare(
    `INSERT INTO ${table} (${columnList}) VALUES (${placeholders}) RETURNING *`,
  )
    .bind(...cols.map((c) => values[c]))
    .first<T>();
  if (!row) throw new Error(`insert into ${table} returned no row`);
  return row;
}

function createCustomDomain(
  userId: number,
  overrides: Record<string, unknown> = {},
): Promise<CustomDomainRow> {
  return insertRow<CustomDomainRow>("custom_domain", {
    user_id: userId,
    domain: `d${uniq()}.example.com`,
    ...overrides,
  });
}

function createDomainDeletedAlias(
  userId: number,
  domainId: number,
  email: string,
): Promise<DomainDeletedAliasRow> {
  return insertRow<DomainDeletedAliasRow>("domain_deleted_alias", {
    user_id: userId,
    domain_id: domainId,
    email,
  });
}

function linkDomainMailbox(domainId: number, mailboxId: number) {
  return insertRow("domain_mailbox", {
    domain_id: domainId,
    mailbox_id: mailboxId,
  });
}

function linkAliasMailbox(aliasId: number, mailboxId: number) {
  return insertRow("alias_mailbox", {
    alias_id: aliasId,
    mailbox_id: mailboxId,
  });
}

async function setup(overrides: Record<string, unknown> = {}) {
  const user = await createUser(env.DB, overrides);
  const apiKey = await createApiKey(env.DB, user.id);
  const defaultMailbox = await env.DB.prepare(
    "SELECT * FROM mailbox WHERE id = ?1",
  )
    .bind(user.default_mailbox_id)
    .first<MailboxRow>();
  if (!defaultMailbox) throw new Error("fixture default mailbox missing");
  return { user, code: apiKey.code, defaultMailbox };
}

interface ReqOpts {
  code?: string;
  body?: unknown;
  ip?: string;
}

function req(method: string, path: string, opts: ReqOpts = {}) {
  const headers: Record<string, string> = {
    "CF-Connecting-IP": opts.ip ?? nextIp(),
  };
  if (opts.code) headers.Authentication = opts.code;
  const init: RequestInit = { method, headers };
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  return SELF.fetch(`https://sl.test/api${path}`, init);
}

/** Pre-fill a fixed-window counter so a single request trips the limit. */
async function primeRateLimit(name: string, ip: string, count: number) {
  const windowStart = Math.floor(Date.now() / 1000 / 3600);
  await env.DB.prepare(
    "INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, ?3)",
  )
    .bind(`rl:${name}:ip:${ip}:3600`, windowStart, count)
    .run();
}

function mailboxDict(
  mb: MailboxRow,
  over: Partial<{
    verified: boolean;
    default: boolean;
    nb_alias: number;
  }> = {},
) {
  return {
    id: mb.id,
    email: mb.email,
    verified: over.verified ?? !!mb.verified,
    default: over.default ?? false,
    creation_timestamp: toEpoch(mb.created_at),
    nb_alias: over.nb_alias ?? 0,
  };
}

async function getMailboxRow(id: number): Promise<MailboxRow> {
  const row = await env.DB.prepare("SELECT * FROM mailbox WHERE id = ?1")
    .bind(id)
    .first<MailboxRow>();
  if (!row) throw new Error(`mailbox ${id} not found`);
  return row;
}

async function getUserRow(id: number): Promise<UserRow> {
  const row = await env.DB.prepare("SELECT * FROM users WHERE id = ?1")
    .bind(id)
    .first<UserRow>();
  if (!row) throw new Error(`user ${id} not found`);
  return row;
}

function getActivations(mailboxId: number) {
  return env.DB.prepare(
    "SELECT * FROM mailbox_activation WHERE mailbox_id = ?1 ORDER BY id",
  )
    .bind(mailboxId)
    .all<{ id: number; code: string; tries: number }>();
}

beforeEach(() => {
  sentEmails.length = 0;
});

// ---- POST /api/mailboxes ----

describe("POST /api/mailboxes", () => {
  it("creates a mailbox, stores an activation code and sends the verification email", async () => {
    const { user, code } = await setup();
    const res = await req("POST", "/mailboxes", {
      code,
      body: { email: " New-MB@Example.ORG " },
    });
    expect(res.status).toBe(201);

    const row = await env.DB.prepare(
      "SELECT * FROM mailbox WHERE user_id = ?1 AND email = ?2",
    )
      .bind(user.id, "new-mb@example.org")
      .first<MailboxRow>();
    expect(row).not.toBeNull();
    expect(row?.verified).toBe(0);

    expect(await res.json()).toEqual({
      id: row?.id,
      email: "new-mb@example.org",
      verified: false,
      default: false,
      creation_timestamp: toEpoch(row?.created_at as string),
      nb_alias: 0,
    });

    const activations = await getActivations(row?.id as number);
    expect(activations.results).toHaveLength(1);
    expect(activations.results[0].code).toHaveLength(22);
    expect(activations.results[0].tries).toBe(0);

    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].to).toBe("new-mb@example.org");
    expect(sentEmails[0].subject).toBe(
      "Please confirm your mailbox new-mb@example.org",
    );
    expect(sentEmails[0].text).toContain(
      `https://app.sl.example.com/dashboard/mailbox_verify?mailbox_id=${row?.id}&code=${activations.results[0].code}`,
    );
  });

  it("returns 401 Wrong api key without valid auth", async () => {
    const res = await req("POST", "/mailboxes", {
      code: "not-a-real-code",
      body: { email: "a@b.com" },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "Wrong api key" });
  });

  it("400 Invalid email when the email field is missing or empty", async () => {
    const { code } = await setup();
    for (const body of [{}, { email: "" }]) {
      const res = await req("POST", "/mailboxes", { code, body });
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "Invalid email" });
    }
  });

  it("400 Only available for paid plans for free users", async () => {
    const { code } = await setup({ trial_end: null });
    const res = await req("POST", "/mailboxes", {
      code,
      body: { email: "paid@example.org" },
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "Only available for paid plans",
    });
  });

  it("400 Invalid email for syntactically invalid addresses", async () => {
    const { code } = await setup();
    for (const email of ["not-an-email", "a@nodot", "a b@x.com@", "a@-x.com"]) {
      const res = await req("POST", "/mailboxes", { code, body: { email } });
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "Invalid email" });
    }
  });

  it("400 Email already used when this user already has the mailbox", async () => {
    const { user, code } = await setup();
    const res = await req("POST", "/mailboxes", {
      code,
      body: { email: user.email },
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Email already used" });
  });

  it("allows an email already used by another (non-disabled) user's mailbox", async () => {
    const other = await createUser(env.DB);
    const { code } = await setup();
    const res = await req("POST", "/mailboxes", {
      code,
      body: { email: other.email },
    });
    expect(res.status).toBe(201);
  });

  it("400 Invalid email: SimpleLogin domain", async () => {
    await insertRow("public_domain", { domain: "pub.example.com" });
    const { code } = await setup();
    const res = await req("POST", "/mailboxes", {
      code,
      body: { email: "me@pub.example.com" },
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "Invalid email: This email is a SimpleLogin domain",
    });
  });

  it("rejects a verified custom domain but allows an unverified one", async () => {
    const other = await createUser(env.DB);
    await createCustomDomain(other.id, {
      domain: "taken.example.com",
      verified: 1,
    });
    await createCustomDomain(other.id, {
      domain: "free.example.com",
      verified: 0,
    });
    const { code } = await setup();

    const rejected = await req("POST", "/mailboxes", {
      code,
      body: { email: "me@taken.example.com" },
    });
    expect(rejected.status).toBe(400);
    expect(await rejected.json()).toEqual({
      error:
        "Invalid email: This email address belongs to a custom domain that has already been registered",
    });

    const ok = await req("POST", "/mailboxes", {
      code,
      body: { email: "me@free.example.com" },
    });
    expect(ok.status).toBe(201);
  });

  it("rejects the account email and mailbox emails of disabled users", async () => {
    const disabled = await createUser(env.DB, { disabled: 1 });
    await createMailbox(env.DB, disabled.id, "extra@dis.example.com");
    const { code } = await setup();

    for (const email of [disabled.email, "extra@dis.example.com"]) {
      const res = await req("POST", "/mailboxes", { code, body: { email } });
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({
        error: "Invalid email: This email address is not allowed",
      });
    }
  });

  it("rate limits at 20/hour per IP, counted before auth like Flask", async () => {
    const ip = nextIp();
    for (let i = 0; i < 20; i++) {
      const res = await req("POST", "/mailboxes", {
        ip,
        body: { email: "x@y.com" },
      });
      expect(res.status).toBe(401); // limiter passes, auth then rejects
    }
    const res = await req("POST", "/mailboxes", {
      ip,
      body: { email: "x@y.com" },
    });
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });
});

// ---- DELETE /api/mailboxes/<id> ----

describe("DELETE /api/mailboxes/:id", () => {
  it("403 Forbidden for another user's mailbox and for unknown ids", async () => {
    const other = await createUser(env.DB);
    const { code } = await setup();
    for (const id of [other.default_mailbox_id, 987654]) {
      const res = await req("DELETE", `/mailboxes/${id}`, { code });
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "Forbidden" });
    }
  });

  it("404 for a non-integer id (Flask int converter)", async () => {
    const { code } = await setup();
    const res = await req("DELETE", "/mailboxes/abc", { code });
    expect(res.status).toBe(404);
  });

  it("400 when deleting the default mailbox", async () => {
    const { user, code } = await setup();
    const res = await req("DELETE", `/mailboxes/${user.default_mailbox_id}`, {
      code,
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "Cannot delete your default mailbox",
    });
  });

  it("400 for an admin-disabled mailbox", async () => {
    const { user, code } = await setup();
    const mb = await createMailbox(env.DB, user.id, "dis@example.com", {
      flags: 1,
    });
    const res = await req("DELETE", `/mailboxes/${mb.id}`, { code });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error:
        "This mailbox has been disabled and cannot be deleted. Please contact support.",
    });
  });

  it("schedules a delete-mailbox job and keeps the row (async deletion)", async () => {
    const { user, code } = await setup();
    const mb = await createMailbox(env.DB, user.id, "gone@example.com");
    const res = await req("DELETE", `/mailboxes/${mb.id}`, { code });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ deleted: true });

    const job = await env.DB.prepare(
      "SELECT * FROM job WHERE name = 'delete-mailbox' ORDER BY id DESC",
    ).first<JobRow>();
    expect(job).not.toBeNull();
    expect(JSON.parse(job?.payload as string)).toEqual({
      mailbox_id: mb.id,
      transfer_mailbox_id: null,
      send_mail: true,
    });
    expect(job?.run_at).toBeTruthy();

    // mailbox still exists until the job runner processes it
    expect(await getMailboxRow(mb.id)).toBeTruthy();
  });

  it('treats transfer_aliases_to -1 and "0" as no transfer', async () => {
    const { user, code } = await setup();
    for (const transfer of [-1, "0", null]) {
      const mb = await createMailbox(env.DB, user.id, `t${uniq()}@example.com`);
      const res = await req("DELETE", `/mailboxes/${mb.id}`, {
        code,
        body: { transfer_aliases_to: transfer },
      });
      expect(res.status).toBe(200);
      const job = await env.DB.prepare(
        "SELECT * FROM job WHERE name = 'delete-mailbox' ORDER BY id DESC",
      ).first<JobRow>();
      expect(JSON.parse(job?.payload as string).transfer_mailbox_id).toBeNull();
    }
  });

  it("records a valid transfer mailbox in the job payload", async () => {
    const { user, code } = await setup();
    const mb = await createMailbox(env.DB, user.id, "from@example.com");
    const target = await createMailbox(env.DB, user.id, "to@example.com");
    const res = await req("DELETE", `/mailboxes/${mb.id}`, {
      code,
      body: { transfer_aliases_to: target.id },
    });
    expect(res.status).toBe(200);
    const job = await env.DB.prepare(
      "SELECT * FROM job WHERE name = 'delete-mailbox' ORDER BY id DESC",
    ).first<JobRow>();
    expect(JSON.parse(job?.payload as string)).toEqual({
      mailbox_id: mb.id,
      transfer_mailbox_id: target.id,
      send_mail: true,
    });
  });

  it("validates the transfer mailbox with exact error strings", async () => {
    const other = await createUser(env.DB);
    const { user, code } = await setup();
    const mb = await createMailbox(env.DB, user.id, "from@example.com");
    const unverified = await createMailbox(env.DB, user.id, "u@example.com", {
      verified: 0,
    });

    const cases: Array<[unknown, string]> = [
      [999999, "You must transfer the aliases to a mailbox you own"],
      [
        other.default_mailbox_id,
        "You must transfer the aliases to a mailbox you own",
      ],
      [
        mb.id,
        "You can not transfer the aliases to the mailbox you want to delete",
      ],
      [unverified.id, "Your new mailbox is not verified"],
    ];
    for (const [transfer, error] of cases) {
      const res = await req("DELETE", `/mailboxes/${mb.id}`, {
        code,
        body: { transfer_aliases_to: transfer },
      });
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error });
    }
  });

  it("400 Bad Request for a non-numeric transfer_aliases_to (Flask 500)", async () => {
    const { user, code } = await setup();
    const mb = await createMailbox(env.DB, user.id, "x@example.com");
    const res = await req("DELETE", `/mailboxes/${mb.id}`, {
      code,
      body: { transfer_aliases_to: "abc" },
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Bad Request" });
  });

  it("429 once the 100/hour window is exhausted", async () => {
    const { user, code } = await setup();
    const mb = await createMailbox(env.DB, user.id, "rl@example.com");
    const ip = nextIp();
    await primeRateLimit("delete_mailbox", ip, 100);
    const res = await req("DELETE", `/mailboxes/${mb.id}`, { code, ip });
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });
});

// ---- PUT /api/mailboxes/<id> ----

describe("PUT /api/mailboxes/:id", () => {
  it("401 / 403 / admin-disabled guards", async () => {
    const other = await createUser(env.DB);
    const { user, code } = await setup();

    const unauth = await req("PUT", `/mailboxes/${user.default_mailbox_id}`, {
      body: { default: true },
    });
    expect(unauth.status).toBe(401);
    expect(await unauth.json()).toEqual({ error: "Wrong api key" });

    const foreign = await req("PUT", `/mailboxes/${other.default_mailbox_id}`, {
      code,
      body: { default: true },
    });
    expect(foreign.status).toBe(403);
    expect(await foreign.json()).toEqual({ error: "Forbidden" });

    const disabled = await createMailbox(env.DB, user.id, "d@example.com", {
      flags: 1,
    });
    const res = await req("PUT", `/mailboxes/${disabled.id}`, {
      code,
      body: { default: true },
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "This mailbox has been disabled. Please contact support.",
    });
  });

  it("sets a verified mailbox as default", async () => {
    const { user, code } = await setup();
    const mb = await createMailbox(env.DB, user.id, "second@example.com");
    const res = await req("PUT", `/mailboxes/${mb.id}`, {
      code,
      body: { default: true },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ updated: true });
    expect((await getUserRow(user.id)).default_mailbox_id).toBe(mb.id);
  });

  it("refuses an unverified mailbox as default; falsy default is a no-op", async () => {
    const { user, code } = await setup();
    const mb = await createMailbox(env.DB, user.id, "unv@example.com", {
      verified: 0,
    });
    const res = await req("PUT", `/mailboxes/${mb.id}`, {
      code,
      body: { default: true },
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "Unverified mailbox cannot be used as default mailbox",
    });

    const noop = await req("PUT", `/mailboxes/${mb.id}`, {
      code,
      body: { default: false },
    });
    expect(noop.status).toBe(200);
    expect(await noop.json()).toEqual({ updated: true });
    expect((await getUserRow(user.id)).default_mailbox_id).toBe(
      user.default_mailbox_id,
    );
  });

  it("requests an email change: sets new_email, activation code and email", async () => {
    const { user, code } = await setup();
    const mbId = user.default_mailbox_id as number;
    const res = await req("PUT", `/mailboxes/${mbId}`, {
      code,
      body: { email: " NEW-Addr@Example.NET " },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ updated: true });

    const row = await getMailboxRow(mbId);
    expect(row.new_email).toBe("new-addr@example.net");

    const activations = await getActivations(mbId);
    expect(activations.results).toHaveLength(1);
    expect(activations.results[0].code).toHaveLength(22);

    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].to).toBe("new-addr@example.net");
    expect(sentEmails[0].subject).toBe("Confirm mailbox change on SimpleLogin");
    expect(sentEmails[0].text).toContain(
      `https://app.sl.example.com/dashboard/mailbox/confirm_change?mailbox_id=${mbId}&code=${activations.results[0].code}`,
    );
  });

  it("email change error strings: Same email / Invalid email / Email already used", async () => {
    const { user, code } = await setup();
    const mb = await createMailbox(env.DB, user.id, "second@example.com");

    const cases: Array<[unknown, string]> = [
      ["second@example.com", "Same email"],
      ["bogus", "Invalid email"],
      [null, "Invalid email"], // Flask 500s on sanitize_email(None)
      [user.email, "Email already used"],
    ];
    for (const [email, error] of cases) {
      const res = await req("PUT", `/mailboxes/${mb.id}`, {
        code,
        body: { email },
      });
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error });
    }
  });

  it("400 Email already in use when new_email is pending elsewhere (global unique)", async () => {
    const other = await createUser(env.DB);
    await createMailbox(env.DB, other.id, "othermb@example.com", {
      new_email: "pending@example.net",
    });
    const { user, code } = await setup();
    const res = await req("PUT", `/mailboxes/${user.default_mailbox_id}`, {
      code,
      body: { email: "pending@example.net" },
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Email already in use" });
  });

  it("cancel_email_change clears new_email and activation codes", async () => {
    const { user, code } = await setup();
    const mbId = user.default_mailbox_id as number;
    await req("PUT", `/mailboxes/${mbId}`, {
      code,
      body: { email: "change@example.net" },
    });
    expect((await getMailboxRow(mbId)).new_email).toBe("change@example.net");

    const res = await req("PUT", `/mailboxes/${mbId}`, {
      code,
      body: { cancel_email_change: true },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ updated: true });
    expect((await getMailboxRow(mbId)).new_email).toBeNull();
    expect((await getActivations(mbId)).results).toHaveLength(0);
  });

  it("returns updated:true even when no recognized field is present", async () => {
    const { user, code } = await setup();
    const res = await req("PUT", `/mailboxes/${user.default_mailbox_id}`, {
      code,
      body: { something: 1 },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ updated: true });
  });

  it("auth runs before the 100/hour limit (Flask decorator order), then 429", async () => {
    const { user, code } = await setup();
    const ip = nextIp();
    await primeRateLimit("update_mailbox", ip, 100);

    // unauthenticated request from the exhausted IP: 401, not 429
    const unauth = await req("PUT", `/mailboxes/${user.default_mailbox_id}`, {
      ip,
      body: { default: true },
    });
    expect(unauth.status).toBe(401);
    expect(await unauth.json()).toEqual({ error: "Wrong api key" });

    const limited = await req("PUT", `/mailboxes/${user.default_mailbox_id}`, {
      code,
      ip,
      body: { default: true },
    });
    expect(limited.status).toBe(429);
    expect(await limited.json()).toEqual({ error: "Rate limit exceeded" });
  });
});

// ---- GET /api/mailboxes + /api/v2/mailboxes ----

describe("GET /api/mailboxes and /api/v2/mailboxes", () => {
  it("v1 lists only verified mailboxes; v2 lists all; nb_alias ignores trash", async () => {
    const { user, code, defaultMailbox } = await setup();
    const mb2 = await createMailbox(env.DB, user.id, "mb2@example.com");
    const mb3 = await createMailbox(env.DB, user.id, "mb3@example.com", {
      verified: 0,
    });

    const a1 = await createAlias(env.DB, user.id, defaultMailbox.id);
    const a2 = await createAlias(env.DB, user.id, mb2.id);
    await linkAliasMailbox(a2.id, defaultMailbox.id); // secondary
    await createAlias(env.DB, user.id, mb2.id, {
      delete_on: "2026-01-01 00:00:00+00:00", // trashed
    });
    await linkAliasMailbox(a1.id, mb3.id); // secondary on unverified

    const v1 = await req("GET", "/mailboxes", { code });
    expect(v1.status).toBe(200);
    expect(await v1.json()).toEqual({
      mailboxes: [
        mailboxDict(defaultMailbox, { default: true, nb_alias: 2 }),
        mailboxDict(mb2, { nb_alias: 1 }),
      ],
    });

    const v2 = await req("GET", "/v2/mailboxes", { code });
    expect(v2.status).toBe(200);
    expect(await v2.json()).toEqual({
      mailboxes: [
        mailboxDict(defaultMailbox, { default: true, nb_alias: 2 }),
        mailboxDict(mb2, { nb_alias: 1 }),
        mailboxDict(mb3, { verified: false, nb_alias: 1 }),
      ],
    });
  });

  it("401 without auth on both versions", async () => {
    for (const path of ["/mailboxes", "/v2/mailboxes"]) {
      const res = await req("GET", path);
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "Wrong api key" });
    }
  });
});

// ---- GET /api/custom_domains ----

describe("GET /api/custom_domains", () => {
  it("serializes domains, excluding SL subdomains and other users", async () => {
    const other = await createUser(env.DB);
    await createCustomDomain(other.id, { domain: "other.example.com" });

    const { user, code, defaultMailbox } = await setup();
    const mb2 = await createMailbox(env.DB, user.id, "mb2@example.com");

    const d1 = await createCustomDomain(user.id, {
      domain: "one.example.com",
      verified: 1,
      catch_all: 1,
      random_prefix_generation: 1,
      name: "D One",
    });
    await linkDomainMailbox(d1.id, mb2.id);
    await linkDomainMailbox(d1.id, defaultMailbox.id);
    await createAlias(env.DB, user.id, defaultMailbox.id, {
      custom_domain_id: d1.id,
    });
    await createAlias(env.DB, user.id, defaultMailbox.id, {
      custom_domain_id: d1.id,
    });
    await createAlias(env.DB, user.id, defaultMailbox.id, {
      custom_domain_id: d1.id,
      delete_on: "2026-01-01 00:00:00+00:00", // trashed, excluded
    });

    const d2 = await createCustomDomain(user.id, { domain: "two.example.com" });
    await createCustomDomain(user.id, {
      domain: "sub.sl.example.com",
      is_sl_subdomain: 1,
    });

    const res = await req("GET", "/custom_domains", { code });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      custom_domains: [
        {
          id: d1.id,
          domain_name: "one.example.com",
          is_verified: true,
          nb_alias: 2,
          creation_date: d1.created_at,
          creation_timestamp: toEpoch(d1.created_at),
          catch_all: true,
          name: "D One",
          random_prefix_generation: true,
          mailboxes: [
            { id: mb2.id, email: "mb2@example.com" },
            { id: defaultMailbox.id, email: defaultMailbox.email },
          ],
        },
        {
          id: d2.id,
          domain_name: "two.example.com",
          is_verified: false,
          nb_alias: 0,
          creation_date: d2.created_at,
          creation_timestamp: toEpoch(d2.created_at),
          catch_all: false,
          name: null,
          random_prefix_generation: false,
          // no domain_mailbox rows -> falls back to the default mailbox
          mailboxes: [{ id: defaultMailbox.id, email: defaultMailbox.email }],
        },
      ],
    });
  });

  it("401 without auth", async () => {
    const res = await req("GET", "/custom_domains");
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "Wrong api key" });
  });
});

// ---- GET /api/custom_domains/<id>/trash ----

describe("GET /api/custom_domains/:id/trash", () => {
  it("403 Forbidden for foreign or unknown domains", async () => {
    const other = await createUser(env.DB);
    const foreignDomain = await createCustomDomain(other.id);
    const { code } = await setup();
    for (const id of [foreignDomain.id, 424242]) {
      const res = await req("GET", `/custom_domains/${id}/trash`, { code });
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "Forbidden" });
    }
  });

  it("lists deleted aliases with deletion timestamps", async () => {
    const { user, code } = await setup();
    const d1 = await createCustomDomain(user.id);
    const d2 = await createCustomDomain(user.id);
    const dda1 = await createDomainDeletedAlias(user.id, d1.id, "a@x.com");
    const dda2 = await createDomainDeletedAlias(user.id, d1.id, "b@x.com");
    await createDomainDeletedAlias(user.id, d2.id, "c@x.com"); // other domain

    const res = await req("GET", `/custom_domains/${d1.id}/trash`, { code });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      aliases: [
        { alias: "a@x.com", deletion_timestamp: toEpoch(dda1.created_at) },
        { alias: "b@x.com", deletion_timestamp: toEpoch(dda2.created_at) },
      ],
    });
  });
});

// ---- PATCH /api/custom_domains/<id> ----

describe("PATCH /api/custom_domains/:id", () => {
  it("400 when the body is empty and 403 for foreign domains", async () => {
    const other = await createUser(env.DB);
    const foreignDomain = await createCustomDomain(other.id);
    const { user, code } = await setup();
    const d = await createCustomDomain(user.id);

    const empty = await req("PATCH", `/custom_domains/${d.id}`, {
      code,
      body: {},
    });
    expect(empty.status).toBe(400);
    expect(await empty.json()).toEqual({
      error: "request body cannot be empty",
    });

    const foreign = await req("PATCH", `/custom_domains/${foreignDomain.id}`, {
      code,
      body: { catch_all: true },
    });
    expect(foreign.status).toBe(403);
    expect(await foreign.json()).toEqual({ error: "Forbidden" });
  });

  it("updates catch_all, random_prefix_generation and name", async () => {
    const { user, code, defaultMailbox } = await setup();
    const d = await createCustomDomain(user.id, { domain: "up.example.com" });

    const res = await req("PATCH", `/custom_domains/${d.id}`, {
      code,
      body: { catch_all: true, random_prefix_generation: true, name: "Nice" },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      custom_domain: {
        id: d.id,
        domain_name: "up.example.com",
        is_verified: false,
        nb_alias: 0,
        creation_date: d.created_at,
        creation_timestamp: toEpoch(d.created_at),
        catch_all: true,
        name: "Nice",
        random_prefix_generation: true,
        mailboxes: [{ id: defaultMailbox.id, email: defaultMailbox.email }],
      },
    });

    // name can be reset to null
    const cleared = await req("PATCH", `/custom_domains/${d.id}`, {
      code,
      body: { name: null },
    });
    const body = (await cleared.json()) as {
      custom_domain: { name: string | null; catch_all: boolean };
    };
    expect(body.custom_domain.name).toBeNull();
    expect(body.custom_domain.catch_all).toBe(true); // untouched
  });

  it("replaces domain mailboxes via mailbox_ids", async () => {
    const { user, code, defaultMailbox } = await setup();
    const mb2 = await createMailbox(env.DB, user.id, "mb2@example.com");
    const d = await createCustomDomain(user.id);

    const res = await req("PATCH", `/custom_domains/${d.id}`, {
      code,
      body: { mailbox_ids: [mb2.id, defaultMailbox.id] },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      custom_domain: { mailboxes: Array<{ id: number; email: string }> };
    };
    expect(body.custom_domain.mailboxes).toEqual([
      { id: defaultMailbox.id, email: defaultMailbox.email },
      { id: mb2.id, email: "mb2@example.com" },
    ]);

    // second update replaces, not appends
    const res2 = await req("PATCH", `/custom_domains/${d.id}`, {
      code,
      body: { mailbox_ids: [mb2.id] },
    });
    const body2 = (await res2.json()) as {
      custom_domain: { mailboxes: Array<{ id: number; email: string }> };
    };
    expect(body2.custom_domain.mailboxes).toEqual([
      { id: mb2.id, email: "mb2@example.com" },
    ]);
    const links = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM domain_mailbox WHERE domain_id = ?1",
    )
      .bind(d.id)
      .first<{ n: number }>();
    expect(links?.n).toBe(1);
  });

  it('invalid mailbox_ids return 400 {"error":"Forbidden"}', async () => {
    const other = await createUser(env.DB);
    const { user, code, defaultMailbox } = await setup();
    const unverified = await createMailbox(env.DB, user.id, "u@example.com", {
      verified: 0,
    });
    const d = await createCustomDomain(user.id);

    const badLists: unknown[][] = [
      [], // NoMailboxes
      [999999], // unknown
      [other.default_mailbox_id], // foreign
      [unverified.id], // unverified
      [defaultMailbox.id, defaultMailbox.id], // duplicates
      Array.from({ length: 21 }, (_, i) => i + 1), // TooManyMailboxes
    ];
    for (const mailbox_ids of badLists) {
      const res = await req("PATCH", `/custom_domains/${d.id}`, {
        code,
        body: { mailbox_ids },
      });
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "Forbidden" });
    }

    // failure leaves existing links untouched
    const links = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM domain_mailbox WHERE domain_id = ?1",
    )
      .bind(d.id)
      .first<{ n: number }>();
    expect(links?.n).toBe(0);
  });

  it("no-op PATCH with unrecognized fields returns the current state", async () => {
    const { user, code, defaultMailbox } = await setup();
    const d = await createCustomDomain(user.id, { catch_all: 1 });
    const res = await req("PATCH", `/custom_domains/${d.id}`, {
      code,
      body: { foo: 1 },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      custom_domain: {
        id: d.id,
        domain_name: d.domain,
        is_verified: false,
        nb_alias: 0,
        creation_date: d.created_at,
        creation_timestamp: toEpoch(d.created_at),
        catch_all: true,
        name: null,
        random_prefix_generation: false,
        mailboxes: [{ id: defaultMailbox.id, email: defaultMailbox.email }],
      },
    });
  });

  it("429 once the 100/hour window is exhausted", async () => {
    const { user, code } = await setup();
    const d = await createCustomDomain(user.id);
    const ip = nextIp();
    await primeRateLimit("update_custom_domain", ip, 100);
    const res = await req("PATCH", `/custom_domains/${d.id}`, {
      code,
      ip,
      body: { catch_all: true },
    });
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });
});
