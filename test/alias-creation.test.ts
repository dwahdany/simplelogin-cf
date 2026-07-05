/**
 * Integration tests for the alias-creation route group (specs/03):
 *   GET  /api/v4/alias/options, GET /api/v5/alias/options
 *   POST /api/v2/alias/custom/new, POST /api/v3/alias/custom/new
 *   POST /api/alias/random/new
 *
 * Rate limits are ACTIVE (DISABLE_RATE_LIMIT unset): every creation request
 * gets its own CF-Connecting-IP so the per-IP 5/minute window never starves
 * other tests; the dedicated 429 tests use one fixed IP / seeded counters.
 * Storage is only isolated per test FILE, so every test seeds its own unique
 * domains/users instead of relying on rollbacks.
 */

import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { timestampSign, timestampUnsign } from "../src/lib/crypto";
import type {
  AliasRow,
  CustomDomainRow,
  PublicDomainRow,
  UserRow,
} from "../src/lib/rows";
import {
  authHeaders,
  createAlias,
  createApiKey,
  createMailbox,
  createUser,
} from "./fixtures";

const SECRET = "test-flask-secretcustom_alias"; // FLASK_SECRET + "custom_alias"
const DATE_RE = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\+00:00$/;

const sign = (suffix: string, nowSecs?: number) =>
  timestampSign(SECRET, suffix, nowSecs);

/** ".word123@<domain>" — random word suffixes (words may contain hyphens). */
function wordSuffixRe(domain: string): RegExp {
  return new RegExp(`^\\.[a-z-]+\\d{3}@${domain.replaceAll(".", "\\.")}$`);
}

// ---- local fixtures --------------------------------------------------------

let seq = 0;

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

/** Unique public_domain (SLDomain) row per call — storage persists in-file. */
function createSlDomain(
  overrides: Record<string, unknown> = {},
): Promise<PublicDomainRow> {
  return insertRow<PublicDomainRow>("public_domain", {
    domain: `sl${++seq}.example.com`,
    ...overrides,
  });
}

/**
 * SL domains are global (not per-user), so tests that assert on the FULL
 * suffix list wipe the table first (tests in a file run sequentially and
 * storage rolls back per file, not per test).
 */
async function clearSlDomains(): Promise<void> {
  await env.DB.prepare("DELETE FROM public_domain").run();
}

/** Unique verified custom domain (ownership + MX verified by default). */
function createCustomDomain(
  userId: number,
  overrides: Record<string, unknown> = {},
): Promise<CustomDomainRow> {
  return insertRow<CustomDomainRow>("custom_domain", {
    user_id: userId,
    domain: `cd${++seq}.example`,
    ownership_verified: 1,
    verified: 1,
    ...overrides,
  });
}

function createUsedOn(
  aliasId: number,
  userId: number,
  hostname: string,
  createdAt?: string,
): Promise<Record<string, unknown>> {
  return insertRow("alias_used_on", {
    alias_id: aliasId,
    user_id: userId,
    hostname,
    ...(createdAt ? { created_at: createdAt } : {}),
  });
}

async function setupUser(overrides: Record<string, unknown> = {}) {
  const user = await createUser(env.DB, overrides);
  const apiKey = await createApiKey(env.DB, user.id);
  return { user, code: apiKey.code };
}

async function setDefaultCustomDomain(userId: number, cdId: number) {
  await env.DB.prepare(
    "UPDATE users SET default_alias_custom_domain_id = ?1 WHERE id = ?2",
  )
    .bind(cdId, userId)
    .run();
}

function defaultMailbox(user: UserRow): { id: number; email: string } {
  return { id: user.default_mailbox_id as number, email: user.email };
}

// ---- request helpers -------------------------------------------------------

let ipSeq = 0;
function ip(): Record<string, string> {
  ipSeq += 1;
  return {
    "CF-Connecting-IP": `10.${Math.floor(ipSeq / 200)}.9.${ipSeq % 200}`,
  };
}

function getOptions(version: 4 | 5, code: string, qs = ""): Promise<Response> {
  return SELF.fetch(`https://sl.test/api/v${version}/alias/options${qs}`, {
    headers: authHeaders(code),
  });
}

function post(
  path: string,
  code: string,
  body?: unknown,
  extraHeaders: Record<string, string> = {},
): Promise<Response> {
  const headers: Record<string, string> = {
    ...authHeaders(code),
    ...ip(),
    ...extraHeaders,
  };
  let payload: string | undefined;
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = typeof body === "string" ? body : JSON.stringify(body);
  }
  return SELF.fetch(`https://sl.test${path}`, {
    method: "POST",
    headers,
    body: payload,
  });
}

/** Full serialize_alias_info_v2 body (+ top-level "alias") for a new alias. */
function newAliasBody(
  email: string,
  mailbox: { id: number; email: string },
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    alias: email,
    id: expect.any(Number),
    email,
    creation_date: expect.stringMatching(DATE_RE),
    creation_timestamp: expect.any(Number),
    enabled: true,
    note: null,
    name: null,
    nb_forward: 0,
    nb_block: 0,
    nb_reply: 0,
    mailbox: { id: mailbox.id, email: mailbox.email },
    mailboxes: [{ id: mailbox.id, email: mailbox.email }],
    support_pgp: false,
    disable_pgp: false,
    latest_activity: null,
    pinned: false,
    ...extra,
  };
}

// ---------------------------------------------------------------------------
// GET /api/v4/alias/options and /api/v5/alias/options
// ---------------------------------------------------------------------------

describe("GET /api/v4/alias/options", () => {
  it("requires an api key", async () => {
    const res = await SELF.fetch("https://sl.test/api/v4/alias/options");
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "Wrong api key" });
  });

  it("returns signed suffix pairs for SL domains (premium user in trial sees premium domains)", async () => {
    await clearSlDomains();
    const { code } = await setupUser();
    const sl = await createSlDomain({ order: 0 });
    const premium = await createSlDomain({ premium_only: 1, order: 1 });
    await createSlDomain({ hidden: 1, order: 2 });

    const res = await getOptions(4, code);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      can_create: boolean;
      prefix_suggestion: string;
      suffixes: [string, string][];
    };
    expect(body.can_create).toBe(true);
    expect(body.prefix_suggestion).toBe("");
    expect(body).not.toHaveProperty("recommendation");
    expect(body.suffixes).toHaveLength(2);

    const [first, second] = body.suffixes;
    expect(first[0]).toMatch(wordSuffixRe(sl.domain));
    expect(second[0]).toMatch(wordSuffixRe(premium.domain));
    // signed_suffix round-trips through the TimestampSigner with our secret
    expect(await timestampUnsign(SECRET, first[1], 600)).toBe(first[0]);
    expect(await timestampUnsign(SECRET, second[1], 600)).toBe(second[0]);
  });

  it("hides premium domains from free users", async () => {
    await clearSlDomains();
    const { code } = await setupUser({ trial_end: null });
    const sl = await createSlDomain({ order: 0 });
    await createSlDomain({ premium_only: 1, order: 1 });

    const res = await getOptions(4, code);
    const body = (await res.json()) as { suffixes: [string, string][] };
    expect(body.suffixes).toHaveLength(1);
    expect(body.suffixes[0][0]).toMatch(wordSuffixRe(sl.domain));
  });

  it("returns prefix_suggestion and the latest-used alias as recommendation", async () => {
    const { user, code } = await setupUser();
    await createSlDomain();
    const mbId = user.default_mailbox_id as number;
    const older = await createAlias(env.DB, user.id, mbId);
    const newer = await createAlias(env.DB, user.id, mbId);
    const hostname = `www.groupon${++seq}.com`;
    await createUsedOn(
      older.id,
      user.id,
      hostname,
      "2023-01-01 00:00:00+00:00",
    );
    await createUsedOn(
      newer.id,
      user.id,
      hostname,
      "2024-01-01 00:00:00+00:00",
    );

    const res = await getOptions(4, code, `?hostname=${hostname}`);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.prefix_suggestion).toBe(`groupon${seq}`);
    expect(body.recommendation).toEqual({ alias: newer.email, hostname });
  });

  it("puts the default custom domain first", async () => {
    await clearSlDomains();
    const { user, code } = await setupUser();
    const sl = await createSlDomain();
    // "zz..." sorts after "cd..." — the default must still come first
    const cd = await createCustomDomain(user.id, {
      domain: `zz${++seq}.example`,
    });
    const other = await createCustomDomain(user.id);
    await setDefaultCustomDomain(user.id, cd.id);

    const res = await getOptions(4, code);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { suffixes: [string, string][] };
    expect(body.suffixes.map((s) => s[0])).toEqual([
      `@${cd.domain}`,
      `@${other.domain}`,
      expect.stringMatching(wordSuffixRe(sl.domain)),
    ]);
  });

  it("uses a 5-char alphanumeric suffix when random_alias_suffix=1", async () => {
    await clearSlDomains();
    const { code } = await setupUser({ random_alias_suffix: 1 });
    const sl = await createSlDomain();
    const res = await getOptions(4, code);
    const body = (await res.json()) as { suffixes: [string, string][] };
    expect(body.suffixes[0][0]).toMatch(
      new RegExp(`^\\.[a-z0-9]{5}@${sl.domain.replaceAll(".", "\\.")}$`),
    );
  });

  it("reports can_create false once the free-plan cap is reached", async () => {
    const { user, code } = await setupUser();
    await createSlDomain();
    const mbId = user.default_mailbox_id as number;
    for (let i = 0; i < 3; i++) await createAlias(env.DB, user.id, mbId);

    const res = await getOptions(4, code);
    const body = (await res.json()) as { can_create: boolean };
    expect(body.can_create).toBe(false);
  });
});

describe("GET /api/v5/alias/options", () => {
  it("requires an api key", async () => {
    const res = await SELF.fetch("https://sl.test/api/v5/alias/options");
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "Wrong api key" });
  });

  it("returns suffix objects with is_custom/is_premium, default SL domain first", async () => {
    await clearSlDomains();
    const { user, code } = await setupUser();
    const slDefault = await createSlDomain({ order: 1 });
    const premium = await createSlDomain({ premium_only: 1, order: 0 });
    const cd = await createCustomDomain(user.id);
    await env.DB.prepare(
      "UPDATE users SET default_alias_public_domain_id = ?1 WHERE id = ?2",
    )
      .bind(slDefault.id, user.id)
      .run();

    const res = await getOptions(5, code);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      suffixes: {
        suffix: string;
        signed_suffix: string;
        is_custom: boolean;
        is_premium: boolean;
      }[];
    };
    // default public domain unshifted ahead of the custom domain
    expect(body.suffixes).toHaveLength(3);
    expect(body.suffixes[0].suffix).toMatch(wordSuffixRe(slDefault.domain));
    expect(body.suffixes[0].is_custom).toBe(false);
    expect(body.suffixes[0].is_premium).toBe(false);
    expect(body.suffixes[1]).toEqual({
      suffix: `@${cd.domain}`,
      signed_suffix: expect.any(String),
      is_custom: true,
      is_premium: false,
    });
    expect(body.suffixes[2].suffix).toMatch(wordSuffixRe(premium.domain));
    expect(body.suffixes[2].is_custom).toBe(false);
    expect(body.suffixes[2].is_premium).toBe(true);
    expect(Object.keys(body.suffixes[0]).sort()).toEqual([
      "is_custom",
      "is_premium",
      "signed_suffix",
      "suffix",
    ]);
  });
});

// ---------------------------------------------------------------------------
// POST /api/v2/alias/custom/new
// ---------------------------------------------------------------------------

describe("POST /api/v2/alias/custom/new", () => {
  it("requires an api key", async () => {
    const res = await SELF.fetch("https://sl.test/api/v2/alias/custom/new", {
      method: "POST",
      headers: ip(),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "Wrong api key" });
  });

  it("creates the alias and records alias_used_on for ?hostname", async () => {
    const { user, code } = await setupUser();
    const sl = await createSlDomain();
    const signed = await sign(`.test123@${sl.domain}`);

    const res = await post(
      "/api/v2/alias/custom/new?hostname=www.groupon.com",
      code,
      { alias_prefix: " Hello World ", signed_suffix: signed, note: "a note" },
    );
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual(
      newAliasBody(`helloworld.test123@${sl.domain}`, defaultMailbox(user), {
        note: "a note",
      }),
    );

    const aliasRow = await env.DB.prepare(
      "SELECT * FROM alias WHERE email = ?1",
    )
      .bind(`helloworld.test123@${sl.domain}`)
      .first<AliasRow>();
    expect(aliasRow?.user_id).toBe(user.id);
    expect(aliasRow?.mailbox_id).toBe(user.default_mailbox_id);
    const usedOn = await env.DB.prepare(
      "SELECT hostname, user_id FROM alias_used_on WHERE alias_id = ?1",
    )
      .bind(aliasRow?.id)
      .first<{ hostname: string; user_id: number }>();
    expect(usedOn).toEqual({ hostname: "www.groupon.com", user_id: user.id });
  });

  it("rejects a free account at the alias cap with the exact message", async () => {
    const { user, code } = await setupUser();
    const sl = await createSlDomain();
    const mbId = user.default_mailbox_id as number;
    for (let i = 0; i < 3; i++) await createAlias(env.DB, user.id, mbId);

    const res = await post("/api/v2/alias/custom/new", code, {
      alias_prefix: "x",
      signed_suffix: await sign(`.x123@${sl.domain}`),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error:
        "You have reached the limitation of a free account with the maximum of 3 aliases, please upgrade your plan to create more aliases",
    });
  });

  it("400s on empty body variants", async () => {
    const { code } = await setupUser();

    // no body / no JSON content type
    const res1 = await post("/api/v2/alias/custom/new", code);
    expect(res1.status).toBe(400);
    expect(await res1.json()).toEqual({
      error: "request body cannot be empty",
    });

    // empty JSON object
    const res2 = await post("/api/v2/alias/custom/new", code, {});
    expect(res2.status).toBe(400);
    expect(await res2.json()).toEqual({
      error: "request body cannot be empty",
    });

    // malformed JSON with a JSON content type -> framework 400
    const res3 = await post("/api/v2/alias/custom/new", code, "{not json");
    expect(res3.status).toBe(400);
    expect(await res3.json()).toEqual({ error: "Bad Request" });
  });

  it("validates alias_prefix and signed_suffix presence/type", async () => {
    const { code } = await setupUser();

    const res1 = await post("/api/v2/alias/custom/new", code, {
      signed_suffix: "x",
    });
    expect(res1.status).toBe(400);
    expect(await res1.json()).toEqual({
      error: "invalid value for alias_prefix",
    });

    const res2 = await post("/api/v2/alias/custom/new", code, {
      alias_prefix: 123,
      signed_suffix: "x",
    });
    expect(res2.status).toBe(400);
    expect(await res2.json()).toEqual({
      error: "invalid value for alias_prefix",
    });

    const res3 = await post("/api/v2/alias/custom/new", code, {
      alias_prefix: "abc",
    });
    expect(res3.status).toBe(400);
    expect(await res3.json()).toEqual({
      error: "invalid value for signed_suffix",
    });
  });

  it("412s on expired and on tampered signatures", async () => {
    const { code } = await setupUser();
    const sl = await createSlDomain();

    const expired = await sign(
      `.test123@${sl.domain}`,
      Math.floor(Date.now() / 1000) - 601,
    );
    const res1 = await post("/api/v2/alias/custom/new", code, {
      alias_prefix: "abc",
      signed_suffix: expired,
    });
    expect(res1.status).toBe(412);
    expect(await res1.json()).toEqual({
      error: "Alias creation time is expired, please retry",
    });

    const tampered = await timestampSign(
      "wrong-secret",
      `.test123@${sl.domain}`,
    );
    const res2 = await post("/api/v2/alias/custom/new", code, {
      alias_prefix: "abc",
      signed_suffix: tampered,
    });
    expect(res2.status).toBe(412);
    expect(await res2.json()).toEqual({
      error: "Alias creation time is expired, please retry",
    });
  });

  it("400s on a wrong prefix/suffix combination", async () => {
    const { code } = await setupUser();
    const sl = await createSlDomain();

    // SL-domain suffix must start with "." when DISABLE_ALIAS_SUFFIX is unset
    const res1 = await post("/api/v2/alias/custom/new", code, {
      alias_prefix: "abc",
      signed_suffix: await sign(`@${sl.domain}`),
    });
    expect(res1.status).toBe(400);
    expect(await res1.json()).toEqual({
      error: "wrong alias prefix or suffix",
    });

    // domain not available to the user
    const res2 = await post("/api/v2/alias/custom/new", code, {
      alias_prefix: "abc",
      signed_suffix: await sign(".x123@not-available.example"),
    });
    expect(res2.status).toBe(400);
    expect(await res2.json()).toEqual({
      error: "wrong alias prefix or suffix",
    });
  });

  it("409s when the alias exists or is in the trash", async () => {
    const { user, code } = await setupUser();
    const sl = await createSlDomain();
    await createAlias(env.DB, user.id, user.default_mailbox_id as number, {
      email: `taken.x123@${sl.domain}`,
    });
    const res1 = await post("/api/v2/alias/custom/new", code, {
      alias_prefix: "taken",
      signed_suffix: await sign(`.x123@${sl.domain}`),
    });
    expect(res1.status).toBe(409);
    expect(await res1.json()).toEqual({
      error: `alias taken.x123@${sl.domain} already exists`,
    });

    await insertRow("deleted_alias", { email: `gone.x123@${sl.domain}` });
    const res2 = await post("/api/v2/alias/custom/new", code, {
      alias_prefix: "gone",
      signed_suffix: await sign(`.x123@${sl.domain}`),
    });
    expect(res2.status).toBe(409);
    expect(await res2.json()).toEqual({
      error: `alias gone.x123@${sl.domain} already exists`,
    });
  });

  it("400s on two consecutive dots", async () => {
    const { code } = await setupUser();
    const sl = await createSlDomain();
    const res = await post("/api/v2/alias/custom/new", code, {
      alias_prefix: "foo.",
      signed_suffix: await sign(`.x123@${sl.domain}`),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "2 consecutive dot signs aren't allowed in an email address",
    });
  });

  it('400s "Email is not valid" for an invalid full alias', async () => {
    const { user, code } = await setupUser();
    const cd = await createCustomDomain(user.id);
    // "foo.@<domain>" — trailing dot in the local part
    const res = await post("/api/v2/alias/custom/new", code, {
      alias_prefix: "foo.",
      signed_suffix: await sign(`@${cd.domain}`),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Email is not valid" });
  });

  it("creates an alias on a verified custom domain and links it", async () => {
    const { user, code } = await setupUser();
    const cd = await createCustomDomain(user.id);
    const res = await post("/api/v2/alias/custom/new", code, {
      alias_prefix: "contact",
      signed_suffix: await sign(`@${cd.domain}`),
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { alias: string; id: number };
    expect(body.alias).toBe(`contact@${cd.domain}`);
    const row = await env.DB.prepare(
      "SELECT custom_domain_id FROM alias WHERE id = ?1",
    )
      .bind(body.id)
      .first<{ custom_domain_id: number | null }>();
    expect(row?.custom_domain_id).toBe(cd.id);
  });
});

// ---------------------------------------------------------------------------
// POST /api/v3/alias/custom/new
// ---------------------------------------------------------------------------

describe("POST /api/v3/alias/custom/new", () => {
  it("requires an api key", async () => {
    const res = await SELF.fetch("https://sl.test/api/v3/alias/custom/new", {
      method: "POST",
      headers: ip(),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "Wrong api key" });
  });

  it("creates the alias with several mailboxes, name and note", async () => {
    const { user, code } = await setupUser();
    const sl = await createSlDomain();
    const mb2 = await createMailbox(
      env.DB,
      user.id,
      `second${++seq}@example.com`,
    );

    const res = await post("/api/v3/alias/custom/new", code, {
      alias_prefix: "prefix",
      signed_suffix: await sign(`.test123@${sl.domain}`),
      mailbox_ids: [user.default_mailbox_id, mb2.id],
      note: "test note",
      name: "John\n Wick",
    });
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual(
      newAliasBody(`prefix.test123@${sl.domain}`, defaultMailbox(user), {
        note: "test note",
        name: "John Wick",
        mailboxes: [
          { id: user.default_mailbox_id, email: user.email },
          { id: mb2.id, email: mb2.email },
        ],
      }),
    );

    const am = await env.DB.prepare(
      "SELECT am.mailbox_id FROM alias_mailbox am JOIN alias a ON am.alias_id = a.id WHERE a.email = ?1",
    )
      .bind(`prefix.test123@${sl.domain}`)
      .all<{ mailbox_id: number }>();
    expect(am.results).toEqual([{ mailbox_id: mb2.id }]);
  });

  it("400s when the body is not an object", async () => {
    const { code } = await setupUser();

    const res1 = await post("/api/v3/alias/custom/new", code, '"a string"');
    expect(res1.status).toBe(400);
    expect(await res1.json()).toEqual({
      error: "request body does not follow the required format",
    });

    // non-string alias_prefix (truthy) -> same error
    const res2 = await post("/api/v3/alias/custom/new", code, {
      alias_prefix: 12345,
      signed_suffix: "x",
      mailbox_ids: [],
    });
    expect(res2.status).toBe(400);
    expect(await res2.json()).toEqual({
      error: "request body does not follow the required format",
    });
  });

  it("validates the alias prefix", async () => {
    const { user, code } = await setupUser();
    const sl = await createSlDomain();

    const res1 = await post("/api/v3/alias/custom/new", code, {
      alias_prefix: "a".repeat(41),
      signed_suffix: await sign(`.x123@${sl.domain}`),
      mailbox_ids: [user.default_mailbox_id],
    });
    expect(res1.status).toBe(400);
    expect(await res1.json()).toEqual({
      error: "alias prefix invalid format or too long",
    });

    const res2 = await post("/api/v3/alias/custom/new", code, {
      alias_prefix: "",
      signed_suffix: await sign(`.x123@${sl.domain}`),
      mailbox_ids: [user.default_mailbox_id],
    });
    expect(res2.status).toBe(400);
    expect(await res2.json()).toEqual({
      error: "alias prefix invalid format or too long",
    });
  });

  it("validates mailbox_ids", async () => {
    const { user, code } = await setupUser();
    const sl = await createSlDomain();
    const signed = await sign(`.x123@${sl.domain}`);

    const notArray = await post("/api/v3/alias/custom/new", code, {
      alias_prefix: "abc",
      signed_suffix: signed,
      mailbox_ids: 7,
    });
    expect(notArray.status).toBe(400);
    expect(await notArray.json()).toEqual({
      error: "mailbox_ids must be an array of id",
    });

    const missing = await post("/api/v3/alias/custom/new", code, {
      alias_prefix: "abc",
      signed_suffix: signed,
      mailbox_ids: [999999],
    });
    expect(missing.status).toBe(400);
    expect(await missing.json()).toEqual({ error: "Errors with Mailbox" });

    const otherUser = await createUser(env.DB);
    const foreign = await post("/api/v3/alias/custom/new", code, {
      alias_prefix: "abc",
      signed_suffix: signed,
      mailbox_ids: [otherUser.default_mailbox_id],
    });
    expect(foreign.status).toBe(400);
    expect(await foreign.json()).toEqual({ error: "Errors with Mailbox" });

    const unverified = await createMailbox(
      env.DB,
      user.id,
      `unverified${++seq}@example.com`,
      { verified: 0 },
    );
    const unv = await post("/api/v3/alias/custom/new", code, {
      alias_prefix: "abc",
      signed_suffix: signed,
      mailbox_ids: [unverified.id],
    });
    expect(unv.status).toBe(400);
    expect(await unv.json()).toEqual({ error: "Errors with Mailbox" });

    const empty = await post("/api/v3/alias/custom/new", code, {
      alias_prefix: "abc",
      signed_suffix: signed,
      mailbox_ids: [],
    });
    expect(empty.status).toBe(400);
    expect(await empty.json()).toEqual({
      error: "At least one mailbox must be selected",
    });
  });

  it("412s on an expired signature", async () => {
    const { user, code } = await setupUser();
    const sl = await createSlDomain();
    const expired = await sign(
      `.x123@${sl.domain}`,
      Math.floor(Date.now() / 1000) - 601,
    );
    const res = await post("/api/v3/alias/custom/new", code, {
      alias_prefix: "abc",
      signed_suffix: expired,
      mailbox_ids: [user.default_mailbox_id],
    });
    expect(res.status).toBe(412);
    expect(await res.json()).toEqual({
      error: "Alias creation time is expired, please retry",
    });
  });

  it("409s when the alias already exists", async () => {
    const { user, code } = await setupUser();
    const sl = await createSlDomain();
    await createAlias(env.DB, user.id, user.default_mailbox_id as number, {
      email: `abc.x123@${sl.domain}`,
    });
    const res = await post("/api/v3/alias/custom/new", code, {
      alias_prefix: "abc",
      signed_suffix: await sign(`.x123@${sl.domain}`),
      mailbox_ids: [user.default_mailbox_id],
    });
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({
      error: `alias abc.x123@${sl.domain} already exists`,
    });
  });

  it('400s "Email alias is invalid" for an invalid full alias', async () => {
    const { user, code } = await setupUser();
    const cd = await createCustomDomain(user.id);
    const res = await post("/api/v3/alias/custom/new", code, {
      alias_prefix: "foo.",
      signed_suffix: await sign(`@${cd.domain}`),
      mailbox_ids: [user.default_mailbox_id],
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Email alias is invalid" });
  });
});

// ---------------------------------------------------------------------------
// POST /api/alias/random/new
// ---------------------------------------------------------------------------

describe("POST /api/alias/random/new", () => {
  it("requires an api key", async () => {
    const res = await SELF.fetch("https://sl.test/api/alias/random/new", {
      method: "POST",
      headers: ip(),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "Wrong api key" });
  });

  it("creates a word alias on FIRST_ALIAS_DOMAIN by default, with note", async () => {
    const { user, code } = await setupUser();
    const res = await post("/api/alias/random/new", code, { note: "rnd note" });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { alias: string };
    expect(body.alias).toMatch(/^[a-z-]+_[a-z-]+\d{3}@sl\.example\.com$/);
    expect(body).toEqual(
      newAliasBody(body.alias, defaultMailbox(user), { note: "rnd note" }),
    );
  });

  it("creates a uuid alias with ?mode=uuid", async () => {
    const { code } = await setupUser();
    const res = await post("/api/alias/random/new?mode=uuid", code);
    expect(res.status).toBe(201);
    const body = (await res.json()) as { alias: string };
    expect(body.alias).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}@sl\.example\.com$/,
    );
  });

  it("400s on an invalid mode", async () => {
    const { code } = await setupUser();
    const res = await post("/api/alias/random/new?mode=foo", code);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "foo must be either word or uuid",
    });
  });

  it("rejects a free account at the alias cap", async () => {
    const { user, code } = await setupUser();
    const mbId = user.default_mailbox_id as number;
    for (let i = 0; i < 3; i++) await createAlias(env.DB, user.id, mbId);
    const res = await post("/api/alias/random/new", code);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error:
        "You have reached the limitation of a free account with the maximum of 3 aliases, please upgrade your plan to create more aliases",
    });
  });

  it("builds a one-click alias from the hostname and the first suffix", async () => {
    const { user, code } = await setupUser();
    const cd = await createCustomDomain(user.id);
    await setDefaultCustomDomain(user.id, cd.id);
    const hostname = `www.shop${++seq}.com`;

    const res = await post(`/api/alias/random/new?hostname=${hostname}`, code);
    expect(res.status).toBe(201);
    const body = (await res.json()) as { alias: string; id: number };
    expect(body.alias).toBe(`shop${seq}@${cd.domain}`);
    const usedOn = await env.DB.prepare(
      "SELECT 1 AS x FROM alias_used_on WHERE alias_id = ?1 AND hostname = ?2",
    )
      .bind(body.id, hostname)
      .first();
    expect(usedOn).toBeTruthy();
  });

  it("reuses an existing alias only when it was created for the hostname", async () => {
    const { user, code } = await setupUser();
    const cd = await createCustomDomain(user.id);
    await setDefaultCustomDomain(user.id, cd.id);
    const hostname = `www.shop${++seq}.com`;
    const existing = await createAlias(
      env.DB,
      user.id,
      user.default_mailbox_id as number,
      { email: `shop${seq}@${cd.domain}` },
    );
    await createUsedOn(existing.id, user.id, hostname);

    const res = await post(`/api/alias/random/new?hostname=${hostname}`, code);
    expect(res.status).toBe(201);
    const body = (await res.json()) as { alias: string; id: number };
    expect(body.id).toBe(existing.id);
    expect(body.alias).toBe(`shop${seq}@${cd.domain}`);
  });

  it("falls back to a random alias when the suggested alias was not used on the hostname", async () => {
    const { user, code } = await setupUser();
    const cd = await createCustomDomain(user.id);
    await setDefaultCustomDomain(user.id, cd.id);
    const hostname = `www.shop${++seq}.com`;
    // exists but has no alias_used_on row for this hostname
    await createAlias(env.DB, user.id, user.default_mailbox_id as number, {
      email: `shop${seq}@${cd.domain}`,
    });

    const res = await post(`/api/alias/random/new?hostname=${hostname}`, code);
    expect(res.status).toBe(201);
    const body = (await res.json()) as { alias: string; id: number };
    // random word alias on the default custom domain
    expect(body.alias).toMatch(
      new RegExp(`^[a-z-]+_[a-z-]+\\d{3}@${cd.domain.replaceAll(".", "\\.")}$`),
    );
    const usedOn = await env.DB.prepare(
      "SELECT 1 AS x FROM alias_used_on WHERE alias_id = ?1 AND hostname = ?2",
    )
      .bind(body.id, hostname)
      .first();
    expect(usedOn).toBeTruthy();
  });

  it("skips a premium default public domain for a non-premium user", async () => {
    const premiumDomain = await createSlDomain({ premium_only: 1 });
    const { code } = await setupUser({
      trial_end: null,
      default_alias_public_domain_id: premiumDomain.id,
    });
    const res = await post("/api/alias/random/new", code);
    expect(res.status).toBe(201);
    const body = (await res.json()) as { alias: string };
    // falls back to FIRST_ALIAS_DOMAIN (= EMAIL_DOMAIN)
    expect(body.alias).toMatch(/@sl\.example\.com$/);
  });
});

// ---------------------------------------------------------------------------
// Rate limiting / locking
// ---------------------------------------------------------------------------

describe("alias creation rate limits", () => {
  it("429s after 5 creations per minute from one IP", async () => {
    const { code } = await setupUser({ lifetime: 1, trial_end: null });
    const fixedIp = { "CF-Connecting-IP": "203.0.113.77" };
    for (let i = 0; i < 5; i++) {
      const res = await post("/api/alias/random/new", code, undefined, fixedIp);
      expect(res.status).toBe(201);
    }
    const res = await post("/api/alias/random/new", code, undefined, fixedIp);
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });

  it("keys the ALIAS_LIMIT by client IP: 6 requests from 6 IPs all pass", async () => {
    const { code } = await setupUser({ lifetime: 1, trial_end: null });
    for (let i = 0; i < 6; i++) {
      const res = await post("/api/alias/random/new", code);
      expect(res.status).toBe(201);
    }
  });

  it("429s while the alias_creation lock is held for the user", async () => {
    const { user, code } = await setupUser({ lifetime: 1, trial_end: null });
    await env.DB.prepare(
      "INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, 1)",
    )
      .bind(
        `lock:user:${user.id}:alias_creation`,
        Math.floor(Date.now() / 1000),
      )
      .run();
    const res = await post("/api/alias/random/new", code);
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });

  it("429s when the per-user creation bucket is exhausted (10/15min free)", async () => {
    const { user, code } = await setupUser();
    const nowSec = Math.floor(Date.now() / 1000);
    // seed the current and the next 900s bucket so the boundary can't flake
    for (const base of [0, 900]) {
      const bucketId = nowSec - (nowSec % 900) + base;
      await env.DB.prepare(
        "INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, ?3)",
      )
        .bind(`bl:alias_create_900:${user.id}:${bucketId}`, bucketId, 10)
        .run();
    }
    const res = await post("/api/alias/random/new", code);
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });

  it("does not rate-limit the options endpoints", async () => {
    const { code } = await setupUser();
    await createSlDomain();
    for (let i = 0; i < 7; i++) {
      const res = await SELF.fetch("https://sl.test/api/v4/alias/options", {
        headers: { ...authHeaders(code), "CF-Connecting-IP": "203.0.113.99" },
      });
      expect(res.status).toBe(200);
    }
  });
});
