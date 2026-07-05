/**
 * Integration tests for the alias & contact routes (specs/02-aliases.md).
 * Field-exact bodies: error strings, status codes, key sets, date formats.
 */

import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { toEpoch } from "../src/lib/dates";
import type {
  AliasMailboxRow,
  AliasRow,
  ContactRow,
  CustomDomainRow,
  DeletedAliasRow,
  DomainDeletedAliasRow,
  MailboxRow,
  UserRow,
} from "../src/lib/rows";
import {
  authHeaders,
  createAlias,
  createApiKey,
  createContact,
  createEmailLog,
  createMailbox,
  createUser,
} from "./fixtures";

const BASE = "https://sl.test";
const DATE_RE = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\+00:00$/;

let ipSeq = 0;
/** Distinct client IP per call site: IP-keyed rate limits stay isolated. */
function nextIp(): string {
  ipSeq += 1;
  return `10.0.${Math.floor(ipSeq / 250)}.${(ipSeq % 250) + 1}`;
}

interface Session {
  user: UserRow;
  mailbox: MailboxRow;
  headers: Record<string, string>;
}

/** User + api key + their default (verified) mailbox row. */
async function setup(
  userOverrides: Record<string, unknown> = {},
): Promise<Session> {
  const user = await createUser(env.DB, userOverrides);
  const apiKey = await createApiKey(env.DB, user.id);
  const mailbox = await env.DB.prepare("SELECT * FROM mailbox WHERE id = ?1")
    .bind(user.default_mailbox_id)
    .first<MailboxRow>();
  if (!mailbox) throw new Error("default mailbox missing");
  return { user, mailbox, headers: authHeaders(apiKey.code) };
}

function createCustomDomain(
  userId: number,
  domain: string,
): Promise<CustomDomainRow | null> {
  return env.DB.prepare(
    "INSERT INTO custom_domain (user_id, domain, verified) VALUES (?1, ?2, 1) RETURNING *",
  )
    .bind(userId, domain)
    .first<CustomDomainRow>();
}

function linkAliasMailbox(
  aliasId: number,
  mailboxId: number,
): Promise<AliasMailboxRow | null> {
  return env.DB.prepare(
    "INSERT INTO alias_mailbox (alias_id, mailbox_id) VALUES (?1, ?2) RETURNING *",
  )
    .bind(aliasId, mailboxId)
    .first<AliasMailboxRow>();
}

function getAliasRow(id: number): Promise<AliasRow | null> {
  return env.DB.prepare("SELECT * FROM alias WHERE id = ?1")
    .bind(id)
    .first<AliasRow>();
}

// ---------------------------------------------------------------------------
// auth
// ---------------------------------------------------------------------------

describe("authentication", () => {
  it("returns 401 Wrong api key on every route without credentials", async () => {
    const routes: [string, string][] = [
      ["GET", "/api/aliases?page_id=0"],
      ["POST", "/api/aliases?page_id=0"],
      ["GET", "/api/v2/aliases?page_id=0"],
      ["GET", "/api/aliases/1"],
      ["PUT", "/api/aliases/1"],
      ["PATCH", "/api/aliases/1"],
      ["DELETE", "/api/aliases/1"],
      ["POST", "/api/aliases/1/toggle"],
      ["GET", "/api/aliases/1/activities?page_id=0"],
      ["GET", "/api/aliases/1/contacts?page_id=0"],
      ["POST", "/api/aliases/1/contacts"],
      ["DELETE", "/api/contacts/1"],
      ["POST", "/api/contacts/1/toggle"],
    ];
    for (const [method, path] of routes) {
      const res = await SELF.fetch(`${BASE}${path}`, {
        method,
        headers: { "CF-Connecting-IP": nextIp() },
      });
      expect(res.status, `${method} ${path}`).toBe(401);
      expect(await res.json()).toEqual({ error: "Wrong api key" });
    }
  });

  it("rejects a bogus api key", async () => {
    const res = await SELF.fetch(`${BASE}/api/aliases?page_id=0`, {
      headers: authHeaders("not-a-real-code"),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "Wrong api key" });
  });

  it("404s non-integer path ids before the handler", async () => {
    const s = await setup();
    const res = await SELF.fetch(`${BASE}/api/aliases/abc`, {
      headers: s.headers,
    });
    expect(res.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// GET|POST /api/aliases (v1)
// ---------------------------------------------------------------------------

describe("GET/POST /api/aliases (v1)", () => {
  it("requires an integer page_id", async () => {
    const s = await setup();
    for (const qs of ["", "?page_id=", "?page_id=abc", "?page_id=1.5"]) {
      const res = await SELF.fetch(`${BASE}/api/aliases${qs}`, {
        headers: s.headers,
      });
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({
        error: "page_id must be provided in request query",
      });
    }
  });

  it("lists aliases newest-first with exact v1 shape and counts", async () => {
    const s = await setup();
    const older = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      created_at: "2023-01-01 10:00:00+00:00",
      note: "older note",
    });
    const newer = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      created_at: "2023-02-01 10:00:00+00:00",
    });
    const contact = await createContact(env.DB, s.user.id, older.id);
    // forward / blocked / reply / bounced-but-not-blocked (counts as forward in v1)
    await createEmailLog(env.DB, s.user.id, contact.id);
    await createEmailLog(env.DB, s.user.id, contact.id, { blocked: 1 });
    await createEmailLog(env.DB, s.user.id, contact.id, { is_reply: 1 });
    await createEmailLog(env.DB, s.user.id, contact.id, { bounced: 1 });

    const res = await SELF.fetch(`${BASE}/api/aliases?page_id=0`, {
      headers: s.headers,
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({
      aliases: [
        {
          id: newer.id,
          email: newer.email,
          creation_date: "2023-02-01 10:00:00+00:00",
          creation_timestamp: toEpoch("2023-02-01 10:00:00+00:00"),
          enabled: true,
          note: null,
          nb_forward: 0,
          nb_block: 0,
          nb_reply: 0,
        },
        {
          id: older.id,
          email: older.email,
          creation_date: "2023-01-01 10:00:00+00:00",
          creation_timestamp: toEpoch("2023-01-01 10:00:00+00:00"),
          enabled: true,
          note: "older note",
          nb_forward: 2,
          nb_block: 1,
          nb_reply: 1,
        },
      ],
    });
  });

  it("excludes trashed aliases and paginates", async () => {
    const s = await setup();
    const kept = await createAlias(env.DB, s.user.id, s.mailbox.id);
    await createAlias(env.DB, s.user.id, s.mailbox.id, {
      delete_on: "2030-01-01 00:00:00+00:00",
    });

    const page0 = await SELF.fetch(`${BASE}/api/aliases?page_id=0`, {
      headers: s.headers,
    });
    const body0 = (await page0.json()) as { aliases: { id: number }[] };
    expect(body0.aliases.map((a) => a.id)).toEqual([kept.id]);

    const page1 = await SELF.fetch(`${BASE}/api/aliases?page_id=1`, {
      headers: s.headers,
    });
    expect(await page1.json()).toEqual({ aliases: [] });
  });

  it("filters on email or note via the POST query body", async () => {
    const s = await setup();
    const byEmail = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      email: "abcfoo@sl.test",
      created_at: "2023-01-02 00:00:00+00:00",
    });
    const byNote = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      email: "bar@sl.test",
      note: "foobar note",
      created_at: "2023-01-01 00:00:00+00:00",
    });
    await createAlias(env.DB, s.user.id, s.mailbox.id, {
      email: "unrelated@sl.test",
    });

    const both = await SELF.fetch(`${BASE}/api/aliases?page_id=0`, {
      method: "POST",
      headers: { ...s.headers, "Content-Type": "application/json" },
      body: JSON.stringify({ query: "foo" }),
    });
    const bothBody = (await both.json()) as { aliases: { id: number }[] };
    expect(bothBody.aliases.map((a) => a.id)).toEqual([byEmail.id, byNote.id]);

    const one = await SELF.fetch(`${BASE}/api/aliases?page_id=0`, {
      method: "POST",
      headers: { ...s.headers, "Content-Type": "application/json" },
      body: JSON.stringify({ query: "abc" }),
    });
    const oneBody = (await one.json()) as { aliases: { id: number }[] };
    expect(oneBody.aliases.map((a) => a.id)).toEqual([byEmail.id]);
  });

  it("ignores the query body without a JSON Content-Type (get_json silent=True)", async () => {
    const s = await setup();
    const a1 = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      note: "ctfilter haystack",
    });
    const a2 = await createAlias(env.DB, s.user.id, s.mailbox.id);

    const res = await SELF.fetch(`${BASE}/api/aliases?page_id=0`, {
      method: "POST",
      headers: { ...s.headers, "Content-Type": "text/plain" },
      body: JSON.stringify({ query: "ctfilter" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { aliases: { id: number }[] };
    // unfiltered — Flask's get_json returns None for text/plain
    expect(body.aliases.map((a) => a.id).sort()).toEqual([a1.id, a2.id].sort());
  });

  it("returns Flask's 500 Internal error for a negative page_id", async () => {
    const s = await setup();
    await createAlias(env.DB, s.user.id, s.mailbox.id);
    const res = await SELF.fetch(`${BASE}/api/aliases?page_id=-1`, {
      headers: s.headers,
    });
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "Internal error" });
  });

  it("rate limits at 10/minute per user", async () => {
    const s = await setup();
    for (let i = 0; i < 10; i++) {
      const res = await SELF.fetch(`${BASE}/api/aliases?page_id=0`, {
        headers: s.headers,
      });
      expect(res.status).toBe(200);
    }
    const blocked = await SELF.fetch(`${BASE}/api/aliases?page_id=0`, {
      headers: s.headers,
    });
    expect(blocked.status).toBe(429);
    expect(await blocked.json()).toEqual({ error: "Rate limit exceeded" });
  });
});

// ---------------------------------------------------------------------------
// GET|POST /api/v2/aliases
// ---------------------------------------------------------------------------

describe("GET/POST /api/v2/aliases", () => {
  it("requires an integer page_id", async () => {
    const s = await setup();
    const res = await SELF.fetch(`${BASE}/api/v2/aliases`, {
      headers: s.headers,
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "page_id must be provided in request query",
    });
  });

  it("serializes the full v2 shape with latest_activity and no has_more", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      created_at: "2023-01-01 00:00:00+00:00",
      note: "my note",
      name: "My Alias",
    });
    const contact = await createContact(env.DB, s.user.id, alias.id, {
      website_email: "john@wick.com",
      name: "John Wick",
      reply_email: "rev123@sl.example.com",
    });
    await createEmailLog(env.DB, s.user.id, contact.id, {
      created_at: "2023-01-02 00:00:00+00:00",
    });
    await createEmailLog(env.DB, s.user.id, contact.id, {
      created_at: "2023-01-03 00:00:00+00:00",
      is_reply: 1,
    });

    const res = await SELF.fetch(`${BASE}/api/v2/aliases?page_id=0`, {
      headers: s.headers,
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(Object.keys(body)).toEqual(["aliases"]); // no has_more field
    expect(body.aliases).toEqual([
      {
        id: alias.id,
        email: alias.email,
        creation_date: "2023-01-01 00:00:00+00:00",
        creation_timestamp: toEpoch("2023-01-01 00:00:00+00:00"),
        enabled: true,
        note: "my note",
        name: "My Alias",
        nb_forward: 1,
        nb_block: 0,
        nb_reply: 1,
        mailbox: { id: s.mailbox.id, email: s.mailbox.email },
        mailboxes: [{ id: s.mailbox.id, email: s.mailbox.email }],
        support_pgp: false,
        disable_pgp: false,
        latest_activity: {
          timestamp: toEpoch("2023-01-03 00:00:00+00:00"),
          action: "reply",
          contact: {
            email: "john@wick.com",
            name: "John Wick",
            reverse_alias:
              '"John Wick | john at wick.com" <rev123@sl.example.com>',
          },
        },
        pinned: false,
      },
    ]);
  });

  it("applies presence-based filters with pinned > disabled > enabled", async () => {
    const s = await setup();
    const pinned = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      pinned: 1,
      created_at: "2023-01-03 00:00:00+00:00",
    });
    const disabled = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      enabled: 0,
      created_at: "2023-01-02 00:00:00+00:00",
    });
    const enabled = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      created_at: "2023-01-01 00:00:00+00:00",
    });

    const ids = async (qs: string) => {
      const res = await SELF.fetch(`${BASE}/api/v2/aliases?page_id=0${qs}`, {
        headers: s.headers,
      });
      const body = (await res.json()) as { aliases: { id: number }[] };
      return body.aliases.map((a) => a.id);
    };

    // ?pinned=false still filters (presence-based)
    expect(await ids("&pinned=false")).toEqual([pinned.id]);
    expect(await ids("&disabled")).toEqual([disabled.id]);
    expect(await ids("&enabled")).toEqual([pinned.id, enabled.id]);
    // precedence: pinned wins over the other two
    expect(await ids("&enabled&disabled&pinned")).toEqual([pinned.id]);
  });

  it("filters with the POST query body", async () => {
    const s = await setup();
    const hit = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      note: "needle in a haystack",
    });
    await createAlias(env.DB, s.user.id, s.mailbox.id);

    const res = await SELF.fetch(`${BASE}/api/v2/aliases?page_id=0`, {
      method: "POST",
      headers: { ...s.headers, "Content-Type": "application/json" },
      body: JSON.stringify({ query: "needle" }),
    });
    const body = (await res.json()) as { aliases: { id: number }[] };
    expect(body.aliases.map((a) => a.id)).toEqual([hit.id]);
  });

  it("query matches English-stemmed note words (Postgres full-text)", async () => {
    const s = await setup();
    const hit = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      note: "run daily",
    });
    await createAlias(env.DB, s.user.id, s.mailbox.id, {
      note: "cycling weekly",
    });

    // 'running' stems to 'run' — LIKE '%running%' would never match
    const res = await SELF.fetch(`${BASE}/api/v2/aliases?page_id=0`, {
      method: "POST",
      headers: { ...s.headers, "Content-Type": "application/json" },
      body: JSON.stringify({ query: "running" }),
    });
    const body = (await res.json()) as { aliases: { id: number }[] };
    expect(body.aliases.map((a) => a.id)).toEqual([hit.id]);
  });

  it("query matches non-ASCII case-insensitively (ILIKE)", async () => {
    const s = await setup();
    const hit = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      note: "Über alles",
    });
    await createAlias(env.DB, s.user.id, s.mailbox.id);

    const res = await SELF.fetch(`${BASE}/api/v2/aliases?page_id=0`, {
      method: "POST",
      headers: { ...s.headers, "Content-Type": "application/json" },
      body: JSON.stringify({ query: "über" }),
    });
    const body = (await res.json()) as { aliases: { id: number }[] };
    expect(body.aliases.map((a) => a.id)).toEqual([hit.id]);
  });

  it("ignores the query body without a JSON Content-Type (get_json silent=True)", async () => {
    const s = await setup();
    const a1 = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      note: "needle in a haystack",
    });
    const a2 = await createAlias(env.DB, s.user.id, s.mailbox.id);

    const res = await SELF.fetch(`${BASE}/api/v2/aliases?page_id=0`, {
      method: "POST",
      headers: { ...s.headers, "Content-Type": "text/plain" },
      body: JSON.stringify({ query: "needle" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { aliases: { id: number }[] };
    expect(body.aliases.map((a) => a.id).sort()).toEqual([a1.id, a2.id].sort());
  });

  it("returns Flask's 500 Internal error for a negative page_id", async () => {
    const s = await setup();
    const res = await SELF.fetch(`${BASE}/api/v2/aliases?page_id=-2`, {
      headers: s.headers,
    });
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "Internal error" });
  });

  it("rate limits at 50/minute per user", async () => {
    const s = await setup();
    for (let i = 0; i < 50; i++) {
      const res = await SELF.fetch(`${BASE}/api/v2/aliases?page_id=0`, {
        headers: s.headers,
      });
      expect(res.status).toBe(200);
    }
    const blocked = await SELF.fetch(`${BASE}/api/v2/aliases?page_id=0`, {
      headers: s.headers,
    });
    expect(blocked.status).toBe(429);
    expect(await blocked.json()).toEqual({ error: "Rate limit exceeded" });
  });
});

// ---------------------------------------------------------------------------
// GET /api/aliases/:id
// ---------------------------------------------------------------------------

describe("GET /api/aliases/:id", () => {
  it("returns 400 Unknown error for a missing alias (not 404)", async () => {
    const s = await setup();
    const res = await SELF.fetch(`${BASE}/api/aliases/999999`, {
      headers: s.headers,
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Unknown error" });
  });

  it("returns 403 for someone else's alias", async () => {
    const s = await setup();
    const other = await setup();
    const alias = await createAlias(env.DB, other.user.id, other.mailbox.id);
    const res = await SELF.fetch(`${BASE}/api/aliases/${alias.id}`, {
      headers: s.headers,
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "Forbidden" });
  });

  it("serializes one alias incl. unverified secondary mailboxes", async () => {
    const s = await setup();
    const unverified = await createMailbox(
      env.DB,
      s.user.id,
      `extra-${s.user.id}@example.com`,
      { verified: 0 },
    );
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      created_at: "2023-01-01 00:00:00+00:00",
    });
    await linkAliasMailbox(alias.id, unverified.id);
    const contact = await createContact(env.DB, s.user.id, alias.id, {
      website_email: "sender@site.com",
      reply_email: "rvx@sl.example.com",
    });
    await createEmailLog(env.DB, s.user.id, contact.id, {
      created_at: "2023-01-05 00:00:00+00:00",
    });

    const res = await SELF.fetch(`${BASE}/api/aliases/${alias.id}`, {
      headers: s.headers,
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({
      id: alias.id,
      email: alias.email,
      creation_date: "2023-01-01 00:00:00+00:00",
      creation_timestamp: toEpoch("2023-01-01 00:00:00+00:00"),
      enabled: true,
      note: null,
      name: null,
      nb_forward: 1,
      nb_block: 0,
      nb_reply: 0,
      mailbox: { id: s.mailbox.id, email: s.mailbox.email },
      // unlike the list endpoint, the single-alias endpoint includes
      // unverified secondary mailboxes
      mailboxes: expect.arrayContaining([
        { id: s.mailbox.id, email: s.mailbox.email },
        { id: unverified.id, email: unverified.email },
      ]),
      support_pgp: false,
      disable_pgp: false,
      latest_activity: {
        timestamp: toEpoch("2023-01-05 00:00:00+00:00"),
        action: "forward",
        contact: {
          email: "sender@site.com",
          name: null,
          reverse_alias: '"sender at site.com" <rvx@sl.example.com>',
        },
      },
      pinned: false,
    });
    expect((body.mailboxes as unknown[]).length).toBe(2);
  });

  it("ignores email logs at or before the alias creation time", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      created_at: "2023-06-01 00:00:00+00:00",
    });
    const contact = await createContact(env.DB, s.user.id, alias.id);
    // strictly-greater comparison: an equal timestamp is NOT latest activity
    await createEmailLog(env.DB, s.user.id, contact.id, {
      created_at: "2023-06-01 00:00:00+00:00",
    });

    const res = await SELF.fetch(`${BASE}/api/aliases/${alias.id}`, {
      headers: s.headers,
    });
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.latest_activity).toBeNull();
    expect(body.nb_forward).toBe(1); // still counted
  });
});

// ---------------------------------------------------------------------------
// PUT|PATCH /api/aliases/:id
// ---------------------------------------------------------------------------

describe("PUT/PATCH /api/aliases/:id", () => {
  async function update(
    s: Session,
    aliasId: number,
    body: unknown,
    method = "PUT",
  ) {
    return SELF.fetch(`${BASE}/api/aliases/${aliasId}`, {
      method,
      headers: { ...s.headers, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  it("rejects an empty JSON body", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const res = await update(s, alias.id, {});
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "request body cannot be empty" });
  });

  it("treats a body without a JSON Content-Type as empty (Flask get_json -> None)", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);

    // no body, no Content-Type
    const noBody = await SELF.fetch(`${BASE}/api/aliases/${alias.id}`, {
      method: "PUT",
      headers: s.headers,
    });
    expect(noBody.status).toBe(400);
    expect(await noBody.json()).toEqual({
      error: "request body cannot be empty",
    });

    // a VALID JSON body sent as text/plain is ignored: 400, note unchanged
    const textPlain = await SELF.fetch(`${BASE}/api/aliases/${alias.id}`, {
      method: "PUT",
      headers: { ...s.headers, "Content-Type": "text/plain" },
      body: JSON.stringify({ note: "smuggled" }),
    });
    expect(textPlain.status).toBe(400);
    expect(await textPlain.json()).toEqual({
      error: "request body cannot be empty",
    });
    expect((await getAliasRow(alias.id))?.note).toBeNull();

    // application/*+json counts as JSON (Flask Request.is_json)
    const suffixJson = await SELF.fetch(`${BASE}/api/aliases/${alias.id}`, {
      method: "PUT",
      headers: { ...s.headers, "Content-Type": "application/vnd.api+json" },
      body: JSON.stringify({ note: "via +json" }),
    });
    expect(suffixJson.status).toBe(200);
    expect((await getAliasRow(alias.id))?.note).toBe("via +json");
  });

  it("maps a malformed application/json body to the global 400", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const res = await SELF.fetch(`${BASE}/api/aliases/${alias.id}`, {
      method: "PUT",
      headers: { ...s.headers, "Content-Type": "application/json" },
      body: "{not json",
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Bad Request" });
  });

  it("403s for a foreign alias", async () => {
    const s = await setup();
    const other = await setup();
    const alias = await createAlias(env.DB, other.user.id, other.mailbox.id);
    const res = await update(s, alias.id, { note: "x" });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "Forbidden" });
  });

  it("updates and clears the note", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const res = await update(s, alias.id, { note: "hello" });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect((await getAliasRow(alias.id))?.note).toBe("hello");

    await update(s, alias.id, { note: null }, "PATCH");
    expect((await getAliasRow(alias.id))?.note).toBeNull();
  });

  it("rejects unverified or foreign mailbox_id with 400 Forbidden", async () => {
    const s = await setup();
    const other = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const unverified = await createMailbox(
      env.DB,
      s.user.id,
      `unv-${s.user.id}@x.com`,
      { verified: 0 },
    );

    for (const bad of [unverified.id, other.mailbox.id, 999999]) {
      const res = await update(s, alias.id, { mailbox_id: bad });
      expect(res.status).toBe(400); // 400 with body "Forbidden" — faithful
      expect(await res.json()).toEqual({ error: "Forbidden" });
    }
    expect((await getAliasRow(alias.id))?.mailbox_id).toBe(s.mailbox.id);
  });

  it("sets a valid mailbox_id", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const mb2 = await createMailbox(
      env.DB,
      s.user.id,
      `mb2-${s.user.id}@x.com`,
    );
    const res = await update(s, alias.id, { mailbox_id: mb2.id });
    expect(await res.json()).toEqual({ ok: true });
    expect((await getAliasRow(alias.id))?.mailbox_id).toBe(mb2.id);
  });

  it("validates mailbox_ids", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);

    let res = await update(s, alias.id, { mailbox_ids: [] });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "Must choose at least one mailbox",
    });

    res = await update(s, alias.id, {
      mailbox_ids: Array.from({ length: 21 }, (_, i) => i + 1),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Too many mailboxes" });

    res = await update(s, alias.id, { mailbox_ids: ["abc"] });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Invalid mailbox_id" });

    res = await update(s, alias.id, { mailbox_ids: [999999] });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Forbidden" });

    // duplicates count-mismatch -> Forbidden
    res = await update(s, alias.id, {
      mailbox_ids: [s.mailbox.id, s.mailbox.id],
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Forbidden" });

    // admin-disabled mailbox -> Forbidden
    const disabledMb = await createMailbox(
      env.DB,
      s.user.id,
      `adm-${s.user.id}@x.com`,
      { flags: 1 },
    );
    res = await update(s, alias.id, { mailbox_ids: [disabledMb.id] });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Forbidden" });
  });

  it("iterates a string mailbox_ids per character, like Python int() over str", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);

    // Python iterates "12" into mailbox ids [1, 2], so the user must OWN
    // verified mailboxes with those single-digit ids: claim (or create) them.
    for (const id of [1, 2]) {
      await env.DB.prepare(
        "INSERT OR IGNORE INTO mailbox (id, user_id, email, verified) VALUES (?1, ?2, ?3, 1)",
      )
        .bind(id, s.user.id, `digit${id}-${s.user.id}@x.com`)
        .run();
      await env.DB.prepare(
        "UPDATE mailbox SET user_id = ?1, verified = 1, flags = 0 WHERE id = ?2",
      )
        .bind(s.user.id, id)
        .run();
    }

    // Flask: [int(m_id) for m_id in "12"] == [1, 2] -> update succeeds
    const ok = await update(s, alias.id, { mailbox_ids: "12" });
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ ok: true });
    expect((await getAliasRow(alias.id))?.mailbox_id).toBe(1);
    const links = await env.DB.prepare(
      "SELECT mailbox_id FROM alias_mailbox WHERE alias_id = ?1",
    )
      .bind(alias.id)
      .all<{ mailbox_id: number }>();
    expect(links.results.map((r) => r.mailbox_id)).toEqual([2]);

    // digits that are not the user's mailboxes -> 400 "Forbidden" (NOT
    // "Invalid mailbox_id": the string itself parses fine)
    const notOwned = await update(s, alias.id, { mailbox_ids: "9" });
    expect(notOwned.status).toBe(400);
    expect(await notOwned.json()).toEqual({ error: "Forbidden" });

    // non-digit characters raise ValueError -> 400 Invalid mailbox_id
    const nonDigit = await update(s, alias.id, { mailbox_ids: "1a" });
    expect(nonDigit.status).toBe(400);
    expect(await nonDigit.json()).toEqual({ error: "Invalid mailbox_id" });

    // empty string iterates to [] -> EmptyMailboxes error
    const emptyStr = await update(s, alias.id, { mailbox_ids: "" });
    expect(emptyStr.status).toBe(400);
    expect(await emptyStr.json()).toEqual({
      error: "Must choose at least one mailbox",
    });

    // non-iterables (numbers, bools, null) raise TypeError -> Invalid mailbox_id
    for (const bad of [12, true, null]) {
      const res = await update(s, alias.id, { mailbox_ids: bad });
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "Invalid mailbox_id" });
    }
  });

  it("rewrites mailboxes: lowest id becomes primary, rest go to alias_mailbox", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const mb2 = await createMailbox(env.DB, s.user.id, `m2-${s.user.id}@x.com`);
    const mb3 = await createMailbox(env.DB, s.user.id, `m3-${s.user.id}@x.com`);

    // request order is irrelevant: sorting is by mailbox id ASC
    const res = await update(s, alias.id, {
      mailbox_ids: [mb3.id, s.mailbox.id, mb2.id],
    });
    expect(await res.json()).toEqual({ ok: true });

    expect((await getAliasRow(alias.id))?.mailbox_id).toBe(s.mailbox.id);
    const links = await env.DB.prepare(
      "SELECT mailbox_id FROM alias_mailbox WHERE alias_id = ?1 ORDER BY mailbox_id",
    )
      .bind(alias.id)
      .all<{ mailbox_id: number }>();
    expect(links.results.map((r) => r.mailbox_id)).toEqual([mb2.id, mb3.id]);
  });

  it("validates and normalizes the name", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);

    const long = await update(s, alias.id, { name: "x".repeat(129) });
    expect(long.status).toBe(400);
    expect(await long.json()).toEqual({
      error: "Name can't be longer than 128 characters",
    });

    await update(s, alias.id, { name: "line\nbreak" });
    expect((await getAliasRow(alias.id))?.name).toBe("linebreak");

    await update(s, alias.id, { name: null });
    expect((await getAliasRow(alias.id))?.name).toBeNull();
  });

  it("sets disable_pgp and pinned", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const res = await update(s, alias.id, { disable_pgp: true, pinned: true });
    expect(await res.json()).toEqual({ ok: true });
    const row = await getAliasRow(alias.id);
    expect(row?.disable_pgp).toBe(1);
    expect(row?.pinned).toBe(1);
  });

  it("returns ok even when no known field is present", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const res = await update(s, alias.id, { bogus: 1 });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });
});

// ---------------------------------------------------------------------------
// DELETE /api/aliases/:id
// ---------------------------------------------------------------------------

describe("DELETE /api/aliases/:id", () => {
  it("403s for missing or foreign aliases", async () => {
    const s = await setup();
    const other = await setup();
    const foreign = await createAlias(env.DB, other.user.id, other.mailbox.id);
    for (const id of [999999, foreign.id]) {
      const res = await SELF.fetch(`${BASE}/api/aliases/${id}`, {
        method: "DELETE",
        headers: s.headers,
      });
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "Forbidden" });
    }
  });

  it("moves the alias to trash by default (30 days, disabled)", async () => {
    const s = await setup(); // alias_delete_action defaults to MoveToTrash
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const res = await SELF.fetch(`${BASE}/api/aliases/${alias.id}`, {
      method: "DELETE",
      headers: s.headers,
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ deleted: true });

    const row = await getAliasRow(alias.id);
    expect(row).not.toBeNull();
    expect(row?.enabled).toBe(0);
    expect(row?.delete_reason).toBe(2); // ManualAction
    const deleteOn = toEpoch(row?.delete_on ?? "");
    const nowSecs = Date.now() / 1000;
    expect(deleteOn).toBeGreaterThan(nowSecs + 29 * 86400);
    expect(deleteOn).toBeLessThan(nowSecs + 31 * 86400);

    // no global-trash row for a soft delete
    const deletedRows = await env.DB.prepare(
      "SELECT * FROM deleted_alias WHERE email = ?1",
    )
      .bind(alias.email)
      .all();
    expect(deletedRows.results).toEqual([]);

    // trashed aliases disappear from the list endpoints
    const list = await SELF.fetch(`${BASE}/api/v2/aliases?page_id=0`, {
      headers: s.headers,
    });
    expect(await list.json()).toEqual({ aliases: [] });
  });

  it("hard-deletes when the user chose DeleteImmediately", async () => {
    const s = await setup({ alias_delete_action: 1 });
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const res = await SELF.fetch(`${BASE}/api/aliases/${alias.id}`, {
      method: "DELETE",
      headers: s.headers,
    });
    expect(await res.json()).toEqual({ deleted: true });

    expect(await getAliasRow(alias.id)).toBeNull();
    const trash = await env.DB.prepare(
      "SELECT * FROM deleted_alias WHERE email = ?1",
    )
      .bind(alias.email)
      .first<DeletedAliasRow>();
    expect(trash?.reason).toBe(2);
    expect(trash?.alias_id).toBe(alias.id);
  });

  it("hard-deletes an already-trashed alias, keeping its trash reason", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      delete_on: "2030-01-01 00:00:00+00:00",
      delete_reason: 4, // MailboxDeleted
    });
    const res = await SELF.fetch(`${BASE}/api/aliases/${alias.id}`, {
      method: "DELETE",
      headers: s.headers,
    });
    expect(await res.json()).toEqual({ deleted: true });
    expect(await getAliasRow(alias.id)).toBeNull();
    const trash = await env.DB.prepare(
      "SELECT * FROM deleted_alias WHERE email = ?1",
    )
      .bind(alias.email)
      .first<DeletedAliasRow>();
    expect(trash?.reason).toBe(4);
  });

  it("never soft-trashes custom-domain aliases", async () => {
    const s = await setup(); // MoveToTrash user
    const cd = await createCustomDomain(s.user.id, `cd-${s.user.id}.com`);
    if (!cd) throw new Error("custom domain fixture failed");
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      email: `contactus@${cd.domain}`,
      custom_domain_id: cd.id,
    });

    const res = await SELF.fetch(`${BASE}/api/aliases/${alias.id}`, {
      method: "DELETE",
      headers: s.headers,
    });
    expect(await res.json()).toEqual({ deleted: true });

    expect(await getAliasRow(alias.id)).toBeNull();
    const domainTrash = await env.DB.prepare(
      "SELECT * FROM domain_deleted_alias WHERE email = ?1 AND domain_id = ?2",
    )
      .bind(alias.email, cd.id)
      .first<DomainDeletedAliasRow>();
    expect(domainTrash?.user_id).toBe(s.user.id);
    expect(domainTrash?.reason).toBe(2);
    expect(domainTrash?.alias_id).toBe(alias.id);
    // and nothing in the GLOBAL trash
    const globalTrash = await env.DB.prepare(
      "SELECT * FROM deleted_alias WHERE email = ?1",
    )
      .bind(alias.email)
      .all();
    expect(globalTrash.results).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// POST /api/aliases/:id/toggle
// ---------------------------------------------------------------------------

describe("POST /api/aliases/:id/toggle", () => {
  it("403s for foreign aliases", async () => {
    const s = await setup();
    const other = await setup();
    const alias = await createAlias(env.DB, other.user.id, other.mailbox.id);
    const res = await SELF.fetch(`${BASE}/api/aliases/${alias.id}/toggle`, {
      method: "POST",
      headers: { ...s.headers, "CF-Connecting-IP": nextIp() },
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "Forbidden" });
  });

  it("flips enabled back and forth", async () => {
    const s = await setup();
    const ip = nextIp();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);

    const off = await SELF.fetch(`${BASE}/api/aliases/${alias.id}/toggle`, {
      method: "POST",
      headers: { ...s.headers, "CF-Connecting-IP": ip },
    });
    expect(off.status).toBe(200);
    expect(await off.json()).toEqual({ enabled: false });
    expect((await getAliasRow(alias.id))?.enabled).toBe(0);

    const on = await SELF.fetch(`${BASE}/api/aliases/${alias.id}/toggle`, {
      method: "POST",
      headers: { ...s.headers, "CF-Connecting-IP": ip },
    });
    expect(await on.json()).toEqual({ enabled: true });
    expect((await getAliasRow(alias.id))?.enabled).toBe(1);
  });

  it("rate limits at 100/hour per client IP", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const ip = nextIp(); // ONE fixed key to hammer
    for (let i = 0; i < 100; i++) {
      const res = await SELF.fetch(`${BASE}/api/aliases/${alias.id}/toggle`, {
        method: "POST",
        headers: { ...s.headers, "CF-Connecting-IP": ip },
      });
      expect(res.status).toBe(200);
    }
    const blocked = await SELF.fetch(`${BASE}/api/aliases/${alias.id}/toggle`, {
      method: "POST",
      headers: { ...s.headers, "CF-Connecting-IP": ip },
    });
    expect(blocked.status).toBe(429);
    expect(await blocked.json()).toEqual({ error: "Rate limit exceeded" });
  });
});

// ---------------------------------------------------------------------------
// GET /api/aliases/:id/activities
// ---------------------------------------------------------------------------

describe("GET /api/aliases/:id/activities", () => {
  it("requires page_id (before the alias check) and 403s foreign aliases", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);

    const noPage = await SELF.fetch(
      `${BASE}/api/aliases/${alias.id}/activities`,
      { headers: { ...s.headers, "CF-Connecting-IP": nextIp() } },
    );
    expect(noPage.status).toBe(400);
    expect(await noPage.json()).toEqual({
      error: "page_id must be provided in request query",
    });

    const other = await setup();
    const foreign = await createAlias(env.DB, other.user.id, other.mailbox.id);
    const res = await SELF.fetch(
      `${BASE}/api/aliases/${foreign.id}/activities?page_id=0`,
      { headers: { ...s.headers, "CF-Connecting-IP": nextIp() } },
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "Forbidden" });
  });

  it("returns Flask's 500 Internal error for a negative page_id (after ownership)", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);

    // ownership is checked before the query runs: foreign alias still 403s
    const other = await setup();
    const foreign = await createAlias(env.DB, other.user.id, other.mailbox.id);
    const foreignRes = await SELF.fetch(
      `${BASE}/api/aliases/${foreign.id}/activities?page_id=-1`,
      { headers: { ...s.headers, "CF-Connecting-IP": nextIp() } },
    );
    expect(foreignRes.status).toBe(403);
    expect(await foreignRes.json()).toEqual({ error: "Forbidden" });

    const res = await SELF.fetch(
      `${BASE}/api/aliases/${alias.id}/activities?page_id=-1`,
      { headers: { ...s.headers, "CF-Connecting-IP": nextIp() } },
    );
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "Internal error" });
  });

  it("serializes activities newest-first with exact fields", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const contact = await createContact(env.DB, s.user.id, alias.id, {
      website_email: "x@y.com",
      reply_email: "rep@sl.example.com",
    });
    await createEmailLog(env.DB, s.user.id, contact.id, {
      created_at: "2023-01-02 00:00:00+00:00",
    });
    await createEmailLog(env.DB, s.user.id, contact.id, {
      created_at: "2023-01-03 00:00:00+00:00",
      is_reply: 1,
    });
    await createEmailLog(env.DB, s.user.id, contact.id, {
      created_at: "2023-01-04 00:00:00+00:00",
      blocked: 1,
    });
    await createEmailLog(env.DB, s.user.id, contact.id, {
      created_at: "2023-01-05 00:00:00+00:00",
      bounced: 1,
    });

    const res = await SELF.fetch(
      `${BASE}/api/aliases/${alias.id}/activities?page_id=0`,
      { headers: { ...s.headers, "CF-Connecting-IP": nextIp() } },
    );
    expect(res.status).toBe(200);
    const reverseAlias = '"x at y.com" <rep@sl.example.com>';
    expect(await res.json()).toEqual({
      activities: [
        {
          timestamp: toEpoch("2023-01-05 00:00:00+00:00"),
          reverse_alias: reverseAlias,
          reverse_alias_address: "rep@sl.example.com",
          to: alias.email,
          from: "x@y.com",
          action: "bounced",
        },
        {
          timestamp: toEpoch("2023-01-04 00:00:00+00:00"),
          reverse_alias: reverseAlias,
          reverse_alias_address: "rep@sl.example.com",
          to: alias.email,
          from: "x@y.com",
          action: "block",
        },
        {
          timestamp: toEpoch("2023-01-03 00:00:00+00:00"),
          reverse_alias: reverseAlias,
          reverse_alias_address: "rep@sl.example.com",
          from: alias.email,
          to: "x@y.com",
          action: "reply",
        },
        {
          timestamp: toEpoch("2023-01-02 00:00:00+00:00"),
          reverse_alias: reverseAlias,
          reverse_alias_address: "rep@sl.example.com",
          to: alias.email,
          from: "x@y.com",
          action: "forward",
        },
      ],
    });

    const page1 = await SELF.fetch(
      `${BASE}/api/aliases/${alias.id}/activities?page_id=1`,
      { headers: { ...s.headers, "CF-Connecting-IP": nextIp() } },
    );
    expect(await page1.json()).toEqual({ activities: [] });
  });

  it("rate limits at 30/minute per client IP", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const ip = nextIp();
    for (let i = 0; i < 30; i++) {
      const res = await SELF.fetch(
        `${BASE}/api/aliases/${alias.id}/activities?page_id=0`,
        { headers: { ...s.headers, "CF-Connecting-IP": ip } },
      );
      expect(res.status).toBe(200);
    }
    const blocked = await SELF.fetch(
      `${BASE}/api/aliases/${alias.id}/activities?page_id=0`,
      { headers: { ...s.headers, "CF-Connecting-IP": ip } },
    );
    expect(blocked.status).toBe(429);
    expect(await blocked.json()).toEqual({ error: "Rate limit exceeded" });
  });
});

// ---------------------------------------------------------------------------
// GET /api/aliases/:id/contacts
// ---------------------------------------------------------------------------

describe("GET /api/aliases/:id/contacts", () => {
  it("requires page_id, 404s missing aliases, 403s foreign ones", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);

    const noPage = await SELF.fetch(
      `${BASE}/api/aliases/${alias.id}/contacts`,
      { headers: s.headers },
    );
    expect(noPage.status).toBe(400);
    expect(await noPage.json()).toEqual({
      error: "page_id must be provided in request query",
    });

    const missing = await SELF.fetch(
      `${BASE}/api/aliases/999999/contacts?page_id=0`,
      { headers: s.headers },
    );
    expect(missing.status).toBe(404);
    expect(await missing.json()).toEqual({ error: "No such alias" });

    const other = await setup();
    const foreign = await createAlias(env.DB, other.user.id, other.mailbox.id);
    const res = await SELF.fetch(
      `${BASE}/api/aliases/${foreign.id}/contacts?page_id=0`,
      { headers: s.headers },
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "Forbidden" });
  });

  it("returns Flask's 500 Internal error for a negative page_id (after 404/403)", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);

    // the 404 for a missing alias still wins over the offset crash
    const missing = await SELF.fetch(
      `${BASE}/api/aliases/999999/contacts?page_id=-1`,
      { headers: s.headers },
    );
    expect(missing.status).toBe(404);
    expect(await missing.json()).toEqual({ error: "No such alias" });

    const res = await SELF.fetch(
      `${BASE}/api/aliases/${alias.id}/contacts?page_id=-1`,
      { headers: s.headers },
    );
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "Internal error" });
  });

  it("lists contacts id-desc with last_email_sent from replies only", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const c1 = await createContact(env.DB, s.user.id, alias.id, {
      website_email: "one@site.com",
      reply_email: "r-one@sl.example.com",
      created_at: "2023-01-01 00:00:00+00:00",
    });
    const c2 = await createContact(env.DB, s.user.id, alias.id, {
      website_email: "two@site.com",
      reply_email: "r-two@sl.example.com",
      created_at: "2023-01-02 00:00:00+00:00",
      block_forward: 1,
    });
    // a forward does NOT populate last_email_sent; a reply does
    await createEmailLog(env.DB, s.user.id, c1.id, {
      created_at: "2023-02-01 00:00:00+00:00",
    });
    await createEmailLog(env.DB, s.user.id, c1.id, {
      created_at: "2023-02-02 00:00:00+00:00",
      is_reply: 1,
    });

    const res = await SELF.fetch(
      `${BASE}/api/aliases/${alias.id}/contacts?page_id=0`,
      { headers: s.headers },
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      contacts: [
        {
          id: c2.id,
          creation_date: "2023-01-02 00:00:00+00:00",
          creation_timestamp: toEpoch("2023-01-02 00:00:00+00:00"),
          last_email_sent_date: null,
          last_email_sent_timestamp: null,
          contact: "two@site.com",
          reverse_alias: '"two at site.com" <r-two@sl.example.com>',
          reverse_alias_address: "r-two@sl.example.com",
          existed: false,
          block_forward: true,
        },
        {
          id: c1.id,
          creation_date: "2023-01-01 00:00:00+00:00",
          creation_timestamp: toEpoch("2023-01-01 00:00:00+00:00"),
          last_email_sent_date: "2023-02-02 00:00:00+00:00",
          last_email_sent_timestamp: toEpoch("2023-02-02 00:00:00+00:00"),
          contact: "one@site.com",
          reverse_alias: '"one at site.com" <r-one@sl.example.com>',
          reverse_alias_address: "r-one@sl.example.com",
          existed: false,
          block_forward: false,
        },
      ],
    });

    const page1 = await SELF.fetch(
      `${BASE}/api/aliases/${alias.id}/contacts?page_id=1`,
      { headers: s.headers },
    );
    expect(await page1.json()).toEqual({ contacts: [] });
  });
});

// ---------------------------------------------------------------------------
// POST /api/aliases/:id/contacts
// ---------------------------------------------------------------------------

describe("POST /api/aliases/:id/contacts", () => {
  function post(s: Session, aliasId: number, body: unknown) {
    return SELF.fetch(`${BASE}/api/aliases/${aliasId}/contacts`, {
      method: "POST",
      headers: { ...s.headers, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  }

  it("validates body, ownership and the address", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);

    const empty = await post(s, alias.id, {});
    expect(empty.status).toBe(400);
    expect(await empty.json()).toEqual({
      error: "request body cannot be empty",
    });

    // valid JSON body without a JSON Content-Type: Flask's get_json returns
    // None -> same "empty body" 400, no contact created
    const textPlain = await SELF.fetch(
      `${BASE}/api/aliases/${alias.id}/contacts`,
      {
        method: "POST",
        headers: { ...s.headers, "Content-Type": "text/plain" },
        body: JSON.stringify({ contact: "a@b.com" }),
      },
    );
    expect(textPlain.status).toBe(400);
    expect(await textPlain.json()).toEqual({
      error: "request body cannot be empty",
    });
    const created = await env.DB.prepare(
      "SELECT 1 FROM contact WHERE alias_id = ?1 LIMIT 1",
    )
      .bind(alias.id)
      .first();
    expect(created).toBeNull();

    const other = await setup();
    const foreign = await createAlias(env.DB, other.user.id, other.mailbox.id);
    const notMine = await post(s, foreign.id, { contact: "a@b.com" });
    expect(notMine.status).toBe(403);
    expect(await notMine.json()).toEqual({ error: "Forbidden" });

    const noContact = await post(s, alias.id, { other: 1 });
    expect(noContact.status).toBe(400);
    expect(await noContact.json()).toEqual({
      error: "Empty address is not a valid email address",
    });

    const invalid = await post(s, alias.id, {
      contact: "with space@gmail.com",
    });
    expect(invalid.status).toBe(400);
    expect(await invalid.json()).toEqual({
      // the error echoes the ORIGINAL body value
      error: "with space@gmail.com is not a valid email address",
    });
  });

  it("creates a contact with a new-format reverse alias (201)", async () => {
    // include_sender_in_reverse_alias defaults to ON for new users; turn it
    // off to get the pure-random reverse-alias format
    const s = await setup({ include_sender_in_reverse_alias: 0 });
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);

    const res = await post(s, alias.id, {
      contact: "First Last <First@Example.com>",
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({
      id: expect.any(Number),
      creation_date: expect.stringMatching(DATE_RE),
      creation_timestamp: expect.any(Number),
      last_email_sent_date: null,
      last_email_sent_timestamp: null,
      contact: "First@Example.com", // case preserved
      reverse_alias: `"First Last | First at Example.com" <${body.reverse_alias_address}>`,
      // new format: random lowercase letters, no ra+ prefix
      reverse_alias_address: expect.stringMatching(
        /^[a-z]{20,50}@sl\.example\.com$/,
      ),
      existed: false,
      block_forward: false,
    });

    const row = await env.DB.prepare("SELECT * FROM contact WHERE id = ?1")
      .bind(body.id)
      .first<ContactRow>();
    expect(row?.website_email).toBe("First@Example.com");
    expect(row?.name).toBe("First Last");
    expect(row?.reply_email).toBe(body.reverse_alias_address);
    expect(row?.automatic_created).toBe(0);
    expect(row?.invalid_email).toBe(0);
  });

  it("returns the existing contact with 200/existed and updates its name", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);

    const first = await post(s, alias.id, { contact: "dup@site.com" });
    expect(first.status).toBe(201);
    const created = (await first.json()) as { id: number };

    const second = await post(s, alias.id, {
      contact: "New Name <dup@site.com>",
    });
    expect(second.status).toBe(200);
    const body = (await second.json()) as Record<string, unknown>;
    expect(body.id).toBe(created.id);
    expect(body.existed).toBe(true);
    expect(body.reverse_alias).toBe(
      `"New Name | dup at site.com" <${body.reverse_alias_address}>`,
    );
    const row = await env.DB.prepare("SELECT name FROM contact WHERE id = ?1")
      .bind(created.id)
      .first<{ name: string }>();
    expect(row?.name).toBe("New Name");
  });

  it("refuses creating a contact for an existing reverse alias", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    await createContact(env.DB, s.user.id, alias.id, {
      website_email: "someone@site.com",
      reply_email: "clash@sl.example.com",
    });

    const res = await post(s, alias.id, { contact: "clash@sl.example.com" });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "clash@sl.example.com is not a valid email address",
    });
  });

  it("prefixes the sender when include_sender_in_reverse_alias is on", async () => {
    const s = await setup({ include_sender_in_reverse_alias: 1 });
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const res = await post(s, alias.id, { contact: "John.Doe@Gmail.com" });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { reverse_alias_address: string };
    expect(body.reverse_alias_address).toMatch(
      /^john_doe_at_gmail_com_[a-z]{5,10}@sl\.example\.com$/,
    );
  });

  it("uses the alias domain when the SL domain is a reverse-alias domain", async () => {
    const s = await setup({ include_sender_in_reverse_alias: 0 });
    await env.DB.prepare(
      "INSERT INTO public_domain (domain, use_as_reverse_alias) VALUES (?1, 1)",
    )
      .bind("pub.test")
      .run();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id, {
      email: `hello-${s.user.id}@pub.test`,
    });
    const res = await post(s, alias.id, { contact: "who@ever.com" });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { reverse_alias_address: string };
    expect(body.reverse_alias_address).toMatch(/^[a-z]{20,50}@pub\.test$/);
  });
});

// ---------------------------------------------------------------------------
// DELETE /api/contacts/:id + POST /api/contacts/:id/toggle
// ---------------------------------------------------------------------------

describe("DELETE /api/contacts/:id", () => {
  it("403s for missing or foreign contacts", async () => {
    const s = await setup();
    const other = await setup();
    const foreignAlias = await createAlias(
      env.DB,
      other.user.id,
      other.mailbox.id,
    );
    const foreign = await createContact(env.DB, other.user.id, foreignAlias.id);
    for (const id of [999999, foreign.id]) {
      const res = await SELF.fetch(`${BASE}/api/contacts/${id}`, {
        method: "DELETE",
        headers: s.headers,
      });
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "Forbidden" });
    }
  });

  it("deletes an owned contact", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const contact = await createContact(env.DB, s.user.id, alias.id);
    const res = await SELF.fetch(`${BASE}/api/contacts/${contact.id}`, {
      method: "DELETE",
      headers: s.headers,
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ deleted: true });
    const row = await env.DB.prepare("SELECT 1 FROM contact WHERE id = ?1")
      .bind(contact.id)
      .first();
    expect(row).toBeNull();
  });
});

describe("POST /api/contacts/:id/toggle", () => {
  it("403s for foreign contacts", async () => {
    const s = await setup();
    const other = await setup();
    const foreignAlias = await createAlias(
      env.DB,
      other.user.id,
      other.mailbox.id,
    );
    const foreign = await createContact(env.DB, other.user.id, foreignAlias.id);
    const res = await SELF.fetch(`${BASE}/api/contacts/${foreign.id}/toggle`, {
      method: "POST",
      headers: s.headers,
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "Forbidden" });
  });

  it("flips block_forward back and forth", async () => {
    const s = await setup();
    const alias = await createAlias(env.DB, s.user.id, s.mailbox.id);
    const contact = await createContact(env.DB, s.user.id, alias.id);

    const on = await SELF.fetch(`${BASE}/api/contacts/${contact.id}/toggle`, {
      method: "POST",
      headers: s.headers,
    });
    expect(on.status).toBe(200);
    expect(await on.json()).toEqual({ block_forward: true });

    const off = await SELF.fetch(`${BASE}/api/contacts/${contact.id}/toggle`, {
      method: "POST",
      headers: s.headers,
    });
    expect(await off.json()).toEqual({ block_forward: false });
    const row = await env.DB.prepare(
      "SELECT block_forward FROM contact WHERE id = ?1",
    )
      .bind(contact.id)
      .first<{ block_forward: number }>();
    expect(row?.block_forward).toBe(0);
  });
});
