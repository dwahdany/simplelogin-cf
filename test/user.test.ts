/**
 * Integration tests for the user/settings/misc route group (spec 05).
 * Field-exact assertions against the Flask contract.
 */

import { env, SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { hashPassword } from "../src/lib/crypto";
import {
  addDays,
  addHours,
  addMinutes,
  nowStr,
  toEpoch,
  toStr,
} from "../src/lib/dates";
import type {
  ApiKeyRow,
  AppleSubscriptionRow,
  FileRow,
  JobRow,
  NotificationRow,
  UserRow,
} from "../src/lib/rows";
import { ensureClientTable, ensurePhoneTables } from "../src/routes/user";
import {
  authHeaders,
  createAlias,
  createApiKey,
  createContact,
  createEmailLog,
  createMailbox,
  createUser,
} from "./fixtures";

const B = "https://sl.test/api";

// PNG magic number + a few payload bytes.
const PNG_BYTES = new Uint8Array([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4,
]);

function b64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

async function insertRow<T>(
  table: string,
  values: Record<string, unknown>,
): Promise<T> {
  const cols = Object.keys(values);
  const sql = `INSERT INTO ${table} (${cols.map((c) => `"${c}"`).join(", ")})
    VALUES (${cols.map((_, i) => `?${i + 1}`).join(", ")}) RETURNING *`;
  const row = await env.DB.prepare(sql)
    .bind(...cols.map((c) => values[c]))
    .first<T>();
  if (!row) throw new Error(`insert into ${table} returned no row`);
  return row;
}

async function newUserWithKey(overrides: Record<string, unknown> = {}) {
  const user = await createUser(env.DB, overrides);
  const apiKey = await createApiKey(env.DB, user.id);
  return { user, apiKey };
}

async function giveSudo(apiKeyId: number): Promise<void> {
  await env.DB.prepare("UPDATE api_key SET sudo_mode_at = ?1 WHERE id = ?2")
    .bind(nowStr(), apiKeyId)
    .run();
}

function jsonHeaders(code: string, ip?: string): Record<string, string> {
  return {
    ...authHeaders(code),
    "Content-Type": "application/json",
    ...(ip ? { "CF-Connecting-IP": ip } : {}),
  };
}

/** KV-backed web session + the headers for the cookie-auth fallback. */
async function cookieSession(userId: number) {
  const token = crypto.randomUUID();
  await env.KV.put(`session:${token}`, JSON.stringify({ user_id: userId }));
  return {
    token,
    headers: { Cookie: `slapp=${token}`, "X-Sl-Allowcookies": "1" },
  };
}

function insertNotification(
  userId: number,
  overrides: Record<string, unknown> = {},
): Promise<NotificationRow> {
  return insertRow<NotificationRow>("notification", {
    user_id: userId,
    message: "a message",
    ...overrides,
  });
}

async function getUser(id: number): Promise<UserRow> {
  const row = await env.DB.prepare("SELECT * FROM users WHERE id = ?1")
    .bind(id)
    .first<UserRow>();
  if (!row) throw new Error("user disappeared");
  return row;
}

// --------------------------------------------------------------------------
// auth plumbing
// --------------------------------------------------------------------------

it("rejects every authed route without a valid api key", async () => {
  const routes: [string, string][] = [
    ["GET", "/user_info"],
    ["PATCH", "/user_info"],
    ["POST", "/api_key"],
    ["GET", "/logout"],
    ["GET", "/stats"],
    ["DELETE", "/user"],
    ["GET", "/user/cookie_token"],
    ["PATCH", "/sudo"],
    ["GET", "/setting"],
    ["PATCH", "/setting"],
    ["GET", "/setting/domains"],
    ["GET", "/v2/setting/domains"],
    ["DELETE", "/setting/unlink_proton_account"],
    ["GET", "/notifications?page=0"],
    ["POST", "/notifications/1/read"],
    ["GET", "/export/data"],
    ["GET", "/export/aliases"],
    ["GET", "/phone/reservations/1"],
    ["POST", "/phone/reservations/1"],
    ["POST", "/apple/process_payment"],
  ];
  for (const [method, path] of routes) {
    const res = await SELF.fetch(`${B}${path}`, {
      method,
      headers: { Authentication: "bogus", "CF-Connecting-IP": "10.99.0.1" },
    });
    expect(res.status, `${method} ${path}`).toBe(401);
    expect(await res.json(), `${method} ${path}`).toEqual({
      error: "Wrong api key",
    });
  }
});

// --------------------------------------------------------------------------
// GET /user_info
// --------------------------------------------------------------------------

describe("GET /user_info", () => {
  it("returns the full user dict for a trial user", async () => {
    const { user, apiKey } = await newUserWithKey();
    const res = await SELF.fetch(`${B}/user_info`, {
      headers: authHeaders(apiKey.code),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      name: "",
      is_premium: true,
      email: user.email,
      in_trial: true,
      trial_end_timestamp: toEpoch(user.trial_end as string),
      max_alias_free_plan: 3,
      connected_proton_address: null,
      can_create_reverse_alias: true,
      profile_picture_url: null,
    });
  });

  it("reports an expired trial as non-premium but keeps the timestamp", async () => {
    const trialEnd = toStr(addDays(new Date(), -1));
    const { apiKey } = await newUserWithKey({
      trial_end: trialEnd,
      name: "Old Timer",
    });
    const res = await SELF.fetch(`${B}/user_info`, {
      headers: authHeaders(apiKey.code),
    });
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.is_premium).toBe(false);
    expect(body.in_trial).toBe(false);
    expect(body.trial_end_timestamp).toBe(toEpoch(trialEnd));
    expect(body.name).toBe("Old Timer");
  });

  it("treats lifetime users as premium, never in trial", async () => {
    const { apiKey } = await newUserWithKey({ lifetime: 1, trial_end: null });
    const res = await SELF.fetch(`${B}/user_info`, {
      headers: authHeaders(apiKey.code),
    });
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.is_premium).toBe(true);
    expect(body.in_trial).toBe(false);
    expect(body.trial_end_timestamp).toBeNull();
  });

  it("uses the old free-plan limit when FLAG_FREE_OLD_ALIAS_LIMIT is set", async () => {
    const { apiKey } = await newUserWithKey({ flags: 4 });
    const res = await SELF.fetch(`${B}/user_info`, {
      headers: authHeaders(apiKey.code),
    });
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.max_alias_free_plan).toBe(15);
  });
});

// --------------------------------------------------------------------------
// PATCH /user_info
// --------------------------------------------------------------------------

describe("PATCH /user_info", () => {
  it("updates the name (and null clears it back to '')", async () => {
    const { user, apiKey } = await newUserWithKey();
    let res = await SELF.fetch(`${B}/user_info`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code),
      body: JSON.stringify({ name: "John Wick" }),
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as Record<string, unknown>).name).toBe(
      "John Wick",
    );
    expect((await getUser(user.id)).name).toBe("John Wick");

    res = await SELF.fetch(`${B}/user_info`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code),
      body: JSON.stringify({ name: null }),
    });
    expect(((await res.json()) as Record<string, unknown>).name).toBe("");
    expect((await getUser(user.id)).name).toBeNull();
  });

  it("accepts a missing body as a no-op", async () => {
    const { user, apiKey } = await newUserWithKey();
    const res = await SELF.fetch(`${B}/user_info`, {
      method: "PATCH",
      headers: authHeaders(apiKey.code),
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as Record<string, unknown>).email).toBe(
      user.email,
    );
  });

  it("uploads a base64 PNG profile picture (file row + KV blob)", async () => {
    const { user, apiKey } = await newUserWithKey();
    const res = await SELF.fetch(`${B}/user_info`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code),
      body: JSON.stringify({ profile_picture: b64(PNG_BYTES) }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.profile_picture_url).toMatch(
      /^https:\/\/app\.sl\.example\.com\/static\/upload\/[a-z]{30}$/,
    );
    const path = (body.profile_picture_url as string)
      .split("/")
      .pop() as string;

    const file = await env.DB.prepare("SELECT * FROM file WHERE path = ?1")
      .bind(path)
      .first<FileRow>();
    expect(file?.user_id).toBe(user.id);
    expect((await getUser(user.id)).profile_picture_id).toBe(file?.id);

    const stored = await env.KV.get(`file:${path}`, "arrayBuffer");
    expect(stored).not.toBeNull();
    expect(new Uint8Array(stored as ArrayBuffer)).toEqual(PNG_BYTES);
  });

  it("tolerates whitespace in the base64 payload like base64.decodebytes", async () => {
    const { apiKey } = await newUserWithKey();
    const withNewlines = `${b64(PNG_BYTES).slice(0, 6)}\n${b64(PNG_BYTES).slice(6)}`;
    const res = await SELF.fetch(`${B}/user_info`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code),
      body: JSON.stringify({ profile_picture: withNewlines }),
    });
    expect(res.status).toBe(200);
  });

  it("removes the picture when profile_picture is null", async () => {
    const { user, apiKey } = await newUserWithKey();
    await SELF.fetch(`${B}/user_info`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code),
      body: JSON.stringify({ profile_picture: b64(PNG_BYTES) }),
    });
    const withPicture = await getUser(user.id);
    const file = await env.DB.prepare("SELECT * FROM file WHERE id = ?1")
      .bind(withPicture.profile_picture_id)
      .first<FileRow>();

    const res = await SELF.fetch(`${B}/user_info`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code),
      body: JSON.stringify({ profile_picture: null }),
    });
    expect(res.status).toBe(200);
    expect(
      ((await res.json()) as Record<string, unknown>).profile_picture_url,
    ).toBeNull();
    expect((await getUser(user.id)).profile_picture_id).toBeNull();
    const gone = await env.DB.prepare("SELECT * FROM file WHERE id = ?1")
      .bind(file?.id)
      .first();
    expect(gone).toBeNull();
    expect(await env.KV.get(`file:${file?.path}`)).toBeNull();
  });

  it("rejects unsupported image formats after removing the old picture", async () => {
    const { user, apiKey } = await newUserWithKey();
    await SELF.fetch(`${B}/user_info`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code),
      body: JSON.stringify({ profile_picture: b64(PNG_BYTES) }),
    });

    const res = await SELF.fetch(`${B}/user_info`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code),
      body: JSON.stringify({
        profile_picture: b64(new TextEncoder().encode("hello world")),
      }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Unsupported image format" });
    // Flask deletes the previous picture before validating the new one.
    expect((await getUser(user.id)).profile_picture_id).toBeNull();
  });
});

// --------------------------------------------------------------------------
// POST /api_key (sudo)
// --------------------------------------------------------------------------

describe("POST /api_key", () => {
  it("requires sudo mode (440)", async () => {
    const { apiKey } = await newUserWithKey();
    const res = await SELF.fetch(`${B}/api_key`, {
      method: "POST",
      headers: jsonHeaders(apiKey.code),
      body: JSON.stringify({ device: "Test" }),
    });
    expect(res.status).toBe(440);
    expect(await res.json()).toEqual({ error: "Need sudo" });
  });

  it("creates a 60-char lowercase key with the device name", async () => {
    const { user, apiKey } = await newUserWithKey();
    await giveSudo(apiKey.id);
    const res = await SELF.fetch(`${B}/api_key`, {
      method: "POST",
      headers: jsonHeaders(apiKey.code),
      body: JSON.stringify({ device: "Firefox" }),
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { api_key: string };
    expect(body.api_key).toMatch(/^[a-z]{60}$/);
    const row = await env.DB.prepare("SELECT * FROM api_key WHERE code = ?1")
      .bind(body.api_key)
      .first<ApiKeyRow>();
    expect(row?.user_id).toBe(user.id);
    expect(row?.name).toBe("Firefox");
  });

  it("rejects a missing body and an empty JSON object", async () => {
    const { apiKey } = await newUserWithKey();
    await giveSudo(apiKey.id);
    for (const init of [
      { method: "POST", headers: authHeaders(apiKey.code) },
      {
        method: "POST",
        headers: jsonHeaders(apiKey.code),
        body: JSON.stringify({}),
      },
    ]) {
      const res = await SELF.fetch(`${B}/api_key`, init);
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({
        error: "request body cannot be empty",
      });
    }
  });

  it("cleans up the oldest unused keys beyond MAX_API_KEYS", async () => {
    const { user, apiKey } = await newUserWithKey();
    await giveSudo(apiKey.id);
    const extras: ApiKeyRow[] = [];
    for (let i = 0; i < 31; i++) {
      extras.push(
        await insertRow<ApiKeyRow>("api_key", {
          user_id: user.id,
          code: `extra-key-${i}-${user.id}`,
          created_at: toStr(addDays(new Date(), -40 + i)),
        }),
      );
    }
    // 32 keys total; creating one more deletes the 2 oldest unused first.
    const res = await SELF.fetch(`${B}/api_key`, {
      method: "POST",
      headers: jsonHeaders(apiKey.code),
      body: JSON.stringify({ device: "New" }),
    });
    expect(res.status).toBe(201);
    const count = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM api_key WHERE user_id = ?1",
    )
      .bind(user.id)
      .first<{ n: number }>();
    expect(count?.n).toBe(31);
    for (const [i, extra] of extras.entries()) {
      const still = await env.DB.prepare("SELECT id FROM api_key WHERE id = ?1")
        .bind(extra.id)
        .first();
      if (i < 2) expect(still, `extra ${i} should be deleted`).toBeNull();
      else expect(still, `extra ${i} should survive`).not.toBeNull();
    }
  });
});

// --------------------------------------------------------------------------
// PATCH /sudo
// --------------------------------------------------------------------------

describe("PATCH /sudo", () => {
  let passwordHash: string;
  beforeAll(async () => {
    passwordHash = await hashPassword("S3cret pass");
  });

  it("enters sudo mode with the correct password", async () => {
    const { apiKey } = await newUserWithKey({ password: passwordHash });
    const res = await SELF.fetch(`${B}/sudo`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code, "10.1.0.1"),
      body: JSON.stringify({ password: "S3cret pass" }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    const row = await env.DB.prepare(
      "SELECT sudo_mode_at FROM api_key WHERE id = ?1",
    )
      .bind(apiKey.id)
      .first<{ sudo_mode_at: string | null }>();
    expect(row?.sudo_mode_at).not.toBeNull();

    // sudo mode now unlocks sudo-protected routes
    const created = await SELF.fetch(`${B}/api_key`, {
      method: "POST",
      headers: jsonHeaders(apiKey.code, "10.1.0.1"),
      body: JSON.stringify({ device: "after sudo" }),
    });
    expect(created.status).toBe(201);
  });

  it("rejects a wrong or missing password with 403", async () => {
    const { apiKey } = await newUserWithKey({ password: passwordHash });
    let res = await SELF.fetch(`${B}/sudo`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code, "10.1.0.2"),
      body: JSON.stringify({ password: "wrong" }),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "Invalid password" });

    res = await SELF.fetch(`${B}/sudo`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code, "10.1.0.3"),
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "Invalid password" });
  });

  it("rejects users without a password set", async () => {
    const { apiKey } = await newUserWithKey({ password: null });
    const res = await SELF.fetch(`${B}/sudo`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code, "10.1.0.4"),
      body: JSON.stringify({ password: "anything" }),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "Invalid password" });
  });

  it("answers cookie-authenticated sudo attempts with a clean 400", async () => {
    const user = await createUser(env.DB, { password: passwordHash });
    const { headers } = await cookieSession(user.id);
    const res = await SELF.fetch(`${B}/sudo`, {
      method: "PATCH",
      headers: {
        ...headers,
        "Content-Type": "application/json",
        "CF-Connecting-IP": "10.1.0.5",
      },
      body: JSON.stringify({ password: "S3cret pass" }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Sudo requires an API key" });
  });

  it("rate limits at 5/minute per client IP", async () => {
    const { apiKey } = await newUserWithKey();
    for (let i = 0; i < 5; i++) {
      const res = await SELF.fetch(`${B}/sudo`, {
        method: "PATCH",
        headers: jsonHeaders(apiKey.code, "10.1.0.99"),
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(403);
    }
    const res = await SELF.fetch(`${B}/sudo`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code, "10.1.0.99"),
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });
});

// --------------------------------------------------------------------------
// DELETE /user
// --------------------------------------------------------------------------

describe("DELETE /user", () => {
  it("requires sudo (440)", async () => {
    const { apiKey } = await newUserWithKey();
    const res = await SELF.fetch(`${B}/user`, {
      method: "DELETE",
      headers: authHeaders(apiKey.code),
    });
    expect(res.status).toBe(440);
    expect(await res.json()).toEqual({ error: "Need sudo" });
  });

  it("schedules the delete-account job and writes the audit log", async () => {
    const { user, apiKey } = await newUserWithKey();
    await giveSudo(apiKey.id);
    const res = await SELF.fetch(`${B}/user`, {
      method: "DELETE",
      headers: authHeaders(apiKey.code),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });

    const job = await env.DB.prepare(
      "SELECT * FROM job WHERE name = 'delete-account'",
    ).first<JobRow>();
    expect(job).not.toBeNull();
    expect(JSON.parse(job?.payload as string)).toEqual({ user_id: user.id });
    expect(job?.run_at).not.toBeNull();

    const audit = await env.DB.prepare(
      "SELECT * FROM user_audit_log WHERE user_id = ?1",
    )
      .bind(user.id)
      .first<{ user_email: string; action: string; message: string }>();
    expect(audit?.action).toBe("user_marked_for_deletion");
    expect(audit?.user_email).toBe(user.email);
    expect(audit?.message).toBe(
      `Marked user ${user.id} (${user.email}) for deletion from API`,
    );
  });
});

// --------------------------------------------------------------------------
// GET /user/cookie_token
// --------------------------------------------------------------------------

describe("GET /user/cookie_token", () => {
  it("creates a one-time token for api-key auth", async () => {
    const { user, apiKey } = await newUserWithKey();
    const res = await SELF.fetch(`${B}/user/cookie_token`, {
      headers: jsonHeaders(apiKey.code, "10.2.0.1"),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { token: string };
    expect(body.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const row = await env.DB.prepare(
      "SELECT * FROM api_cookie_token WHERE code = ?1",
    )
      .bind(body.token)
      .first<{ user_id: number; api_key_id: number }>();
    expect(row?.user_id).toBe(user.id);
    expect(row?.api_key_id).toBe(apiKey.id);
  });

  it("returns 401 {ok:false} for cookie-authenticated requests", async () => {
    const user = await createUser(env.DB);
    const { headers } = await cookieSession(user.id);
    const res = await SELF.fetch(`${B}/user/cookie_token`, {
      headers: { ...headers, "CF-Connecting-IP": "10.2.0.2" },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ ok: false });
  });

  it("rate limits at 5/minute per client IP", async () => {
    const { apiKey } = await newUserWithKey();
    for (let i = 0; i < 5; i++) {
      const res = await SELF.fetch(`${B}/user/cookie_token`, {
        headers: jsonHeaders(apiKey.code, "10.2.0.9"),
      });
      expect(res.status).toBe(200);
    }
    const res = await SELF.fetch(`${B}/user/cookie_token`, {
      headers: jsonHeaders(apiKey.code, "10.2.0.9"),
    });
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });
});

// --------------------------------------------------------------------------
// GET /logout
// --------------------------------------------------------------------------

describe("GET /logout", () => {
  it("destroys the web session and expires the slapp cookie", async () => {
    const user = await createUser(env.DB);
    const { token, headers } = await cookieSession(user.id);
    const res = await SELF.fetch(`${B}/logout`, { headers });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ msg: "User is logged out" });
    expect(res.headers.get("set-cookie")).toContain("slapp=;");
    expect(await env.KV.get(`session:${token}`)).toBeNull();
  });

  it("works with plain api-key auth too", async () => {
    const { apiKey } = await newUserWithKey();
    const res = await SELF.fetch(`${B}/logout`, {
      headers: authHeaders(apiKey.code),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ msg: "User is logged out" });
  });
});

// --------------------------------------------------------------------------
// GET /stats
// --------------------------------------------------------------------------

it("GET /stats aggregates alias and email-log counts", async () => {
  const { user, apiKey } = await newUserWithKey();
  const alias = await createAlias(
    env.DB,
    user.id,
    user.default_mailbox_id as number,
  );
  await createAlias(env.DB, user.id, user.default_mailbox_id as number, {
    delete_on: nowStr(), // trashed: not counted
  });
  const contact = await createContact(env.DB, user.id, alias.id);
  await createEmailLog(env.DB, user.id, contact.id, {});
  await createEmailLog(env.DB, user.id, contact.id, {});
  await createEmailLog(env.DB, user.id, contact.id, { is_reply: 1 });
  await createEmailLog(env.DB, user.id, contact.id, { blocked: 1 });
  await createEmailLog(env.DB, user.id, contact.id, { bounced: 1 });

  const res = await SELF.fetch(`${B}/stats`, {
    headers: authHeaders(apiKey.code),
  });
  expect(res.status).toBe(200);
  expect(await res.json()).toEqual({
    nb_alias: 1,
    nb_forward: 2,
    nb_reply: 1,
    nb_block: 1,
  });
});

// --------------------------------------------------------------------------
// GET/PATCH /setting
// --------------------------------------------------------------------------

describe("/setting", () => {
  it("GET returns the default settings", async () => {
    const { apiKey } = await newUserWithKey();
    const res = await SELF.fetch(`${B}/setting`, {
      headers: authHeaders(apiKey.code),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      notification: true,
      alias_generator: "word",
      random_alias_default_domain: "sl.example.com",
      sender_format: "AT",
      random_alias_suffix: "word",
    });
  });

  it("PATCH updates every simple field", async () => {
    const { user, apiKey } = await newUserWithKey();
    const res = await SELF.fetch(`${B}/setting`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code),
      body: JSON.stringify({
        notification: false,
        alias_generator: "uuid",
        sender_format: "NAME_ONLY",
        random_alias_suffix: "random_string",
      }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      notification: false,
      alias_generator: "uuid",
      random_alias_default_domain: "sl.example.com",
      sender_format: "NAME_ONLY",
      random_alias_suffix: "random_string",
    });
    const fresh = await getUser(user.id);
    expect(fresh.sender_format).toBe(5);
    expect(fresh.sender_format_updated_at).not.toBeNull();
    expect(fresh.random_alias_suffix).toBe(1);
  });

  it("PATCH rejects invalid enum values with exact errors", async () => {
    const { user, apiKey } = await newUserWithKey();
    const cases: [Record<string, unknown>, string][] = [
      [{ alias_generator: "banana" }, "Invalid alias_generator"],
      [{ sender_format: "banana" }, "Invalid sender_format"],
      [{ random_alias_suffix: "banana" }, "Invalid random_alias_suffix"],
    ];
    for (const [body, error] of cases) {
      const res = await SELF.fetch(`${B}/setting`, {
        method: "PATCH",
        headers: jsonHeaders(apiKey.code),
        body: JSON.stringify(body),
      });
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error });
    }
    // an invalid later field must not commit earlier fields
    const res = await SELF.fetch(`${B}/setting`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code),
      body: JSON.stringify({ notification: false, alias_generator: "banana" }),
    });
    expect(res.status).toBe(400);
    expect((await getUser(user.id)).notification).toBe(1);
  });

  it("PATCH random_alias_default_domain handles SL domains", async () => {
    await insertRow("public_domain", {
      domain: "premium-d.example",
      premium_only: 1,
    });
    await insertRow("public_domain", { domain: "free-d.example" });

    // trial user => premium => can pick the premium domain
    const { user, apiKey } = await newUserWithKey();
    let res = await SELF.fetch(`${B}/setting`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code),
      body: JSON.stringify({
        random_alias_default_domain: "premium-d.example",
      }),
    });
    expect(res.status).toBe(200);
    expect(
      ((await res.json()) as Record<string, unknown>)
        .random_alias_default_domain,
    ).toBe("premium-d.example");
    const fresh = await getUser(user.id);
    expect(fresh.default_alias_public_domain_id).not.toBeNull();
    expect(fresh.default_alias_custom_domain_id).toBeNull();

    // free user cannot
    const free = await newUserWithKey({ trial_end: null });
    res = await SELF.fetch(`${B}/setting`, {
      method: "PATCH",
      headers: jsonHeaders(free.apiKey.code),
      body: JSON.stringify({
        random_alias_default_domain: "premium-d.example",
      }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "You cannot use this domain" });
  });

  it("PATCH random_alias_default_domain handles custom domains", async () => {
    const { user, apiKey } = await newUserWithKey();
    const other = await createUser(env.DB);
    await insertRow("custom_domain", {
      user_id: user.id,
      domain: "own-verified.example",
      verified: 1,
    });
    await insertRow("custom_domain", {
      user_id: user.id,
      domain: "own-unverified.example",
      verified: 0,
    });
    await insertRow("custom_domain", {
      user_id: other.id,
      domain: "not-mine.example",
      verified: 1,
    });

    for (const domain of [
      "unknown.example",
      "own-unverified.example",
      "not-mine.example",
    ]) {
      const res = await SELF.fetch(`${B}/setting`, {
        method: "PATCH",
        headers: jsonHeaders(apiKey.code),
        body: JSON.stringify({ random_alias_default_domain: domain }),
      });
      expect(res.status, domain).toBe(400);
      expect(await res.json()).toEqual({ error: "invalid domain" });
    }

    const res = await SELF.fetch(`${B}/setting`, {
      method: "PATCH",
      headers: jsonHeaders(apiKey.code),
      body: JSON.stringify({
        random_alias_default_domain: "own-verified.example",
      }),
    });
    expect(res.status).toBe(200);
    expect(
      ((await res.json()) as Record<string, unknown>)
        .random_alias_default_domain,
    ).toBe("own-verified.example");
    const fresh = await getUser(user.id);
    expect(fresh.default_alias_custom_domain_id).not.toBeNull();
    expect(fresh.default_alias_public_domain_id).toBeNull();
  });
});

// --------------------------------------------------------------------------
// GET /setting/domains + /v2/setting/domains
// --------------------------------------------------------------------------

describe("setting domains", () => {
  let seedSeq = 0;
  async function seedDomains(userId: number, otherUserId: number) {
    // Storage is shared across tests: start from a clean public_domain table
    // (global rows) and use unique custom-domain names so the exact-array
    // assertions below are deterministic.
    await env.DB.prepare("DELETE FROM public_domain").run();
    const s = ++seedSeq;
    await insertRow("public_domain", {
      domain: "d-a.example",
      order: 2,
    });
    await insertRow("public_domain", {
      domain: "d-b.example",
      premium_only: 1,
      order: 1,
    });
    await insertRow("public_domain", {
      domain: "d-hidden.example",
      hidden: 1,
    });
    const cd1 = `cd1-${s}.example`;
    await insertRow("custom_domain", {
      user_id: userId,
      domain: cd1,
      verified: 1,
      ownership_verified: 1,
    });
    await insertRow("custom_domain", {
      user_id: userId,
      domain: `cd2-${s}.example`,
      verified: 1,
      ownership_verified: 0,
    });
    await insertRow("custom_domain", {
      user_id: otherUserId,
      domain: `cd3-${s}.example`,
      verified: 1,
      ownership_verified: 1,
    });
    return { cd1 };
  }

  it("v1 returns [is_sl, domain] pairs, SL domains first", async () => {
    const { user, apiKey } = await newUserWithKey(); // trial => premium
    const other = await createUser(env.DB);
    const { cd1 } = await seedDomains(user.id, other.id);
    const res = await SELF.fetch(`${B}/setting/domains`, {
      headers: authHeaders(apiKey.code),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual([
      [true, "d-b.example"],
      [true, "d-a.example"],
      [false, cd1],
    ]);
  });

  it("v1 hides premium-only domains from free users", async () => {
    const { user, apiKey } = await newUserWithKey({ trial_end: null });
    const other = await createUser(env.DB);
    const { cd1 } = await seedDomains(user.id, other.id);
    const res = await SELF.fetch(`${B}/setting/domains`, {
      headers: authHeaders(apiKey.code),
    });
    expect(await res.json()).toEqual([
      [true, "d-a.example"],
      [false, cd1],
    ]);
  });

  it("v2 returns {domain, is_custom} objects", async () => {
    const { user, apiKey } = await newUserWithKey();
    const other = await createUser(env.DB);
    const { cd1 } = await seedDomains(user.id, other.id);
    const res = await SELF.fetch(`${B}/v2/setting/domains`, {
      headers: authHeaders(apiKey.code),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual([
      { domain: "d-b.example", is_custom: false },
      { domain: "d-a.example", is_custom: false },
      { domain: cd1, is_custom: true },
    ]);
  });
});

// --------------------------------------------------------------------------
// DELETE /setting/unlink_proton_account
// --------------------------------------------------------------------------

describe("DELETE /setting/unlink_proton_account", () => {
  it("refuses accounts created from the partner", async () => {
    const { apiKey } = await newUserWithKey({ flags: 2 });
    const res = await SELF.fetch(`${B}/setting/unlink_proton_account`, {
      method: "DELETE",
      headers: authHeaders(apiKey.code),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "The account cannot be unlinked",
    });
  });

  it("refuses accounts that were never linked (clean 4xx deviation)", async () => {
    const { apiKey } = await newUserWithKey();
    const res = await SELF.fetch(`${B}/setting/unlink_proton_account`, {
      method: "DELETE",
      headers: authHeaders(apiKey.code),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "The account cannot be unlinked",
    });
  });

  it("unlinks a linked Proton account and writes the audit log", async () => {
    const { user, apiKey } = await newUserWithKey();
    const partner = await insertRow<{ id: number }>("partner", {
      name: "Proton",
      contact_email: "proton@example.com",
    });
    const partnerUser = await insertRow<{ id: number }>("partner_user", {
      user_id: user.id,
      partner_id: partner.id,
      external_user_id: "ext-42",
      partner_email: "u@proton.me",
    });

    const res = await SELF.fetch(`${B}/setting/unlink_proton_account`, {
      method: "DELETE",
      headers: authHeaders(apiKey.code),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });

    const gone = await env.DB.prepare(
      "SELECT * FROM partner_user WHERE id = ?1",
    )
      .bind(partnerUser.id)
      .first();
    expect(gone).toBeNull();
    const audit = await env.DB.prepare(
      "SELECT * FROM user_audit_log WHERE user_id = ?1",
    )
      .bind(user.id)
      .first<{ action: string; message: string }>();
    expect(audit?.action).toBe("unlink_account");
    expect(audit?.message).toBe(
      "User has unlinked the account (email=u@proton.me | external_user_id=ext-42)",
    );
  });
});

// --------------------------------------------------------------------------
// notifications
// --------------------------------------------------------------------------

describe("GET /notifications", () => {
  it("requires a numeric page query param", async () => {
    const { apiKey } = await newUserWithKey();
    for (const qs of ["", "?page=abc", "?page=1.5"]) {
      const res = await SELF.fetch(`${B}/notifications${qs}`, {
        headers: authHeaders(apiKey.code),
      });
      expect(res.status, qs).toBe(400);
      expect(await res.json()).toEqual({
        error: "page must be provided in request query",
      });
    }
  });

  it("orders unread first, newest first, with humanized created_at", async () => {
    const { user, apiKey } = await newUserWithKey();
    const now = new Date();
    const n1 = await insertNotification(user.id, {
      message: "read now",
      read: 1,
      created_at: nowStr(),
    });
    const n2 = await insertNotification(user.id, {
      message: "unread 5m",
      created_at: toStr(addMinutes(now, -5)),
    });
    const n3 = await insertNotification(user.id, {
      message: "unread 2d",
      created_at: toStr(addDays(now, -2)),
    });
    const n4 = await insertNotification(user.id, {
      message: "read 3d",
      title: "The Title",
      read: 1,
      created_at: toStr(addDays(now, -3)),
    });

    const res = await SELF.fetch(`${B}/notifications?page=0`, {
      headers: authHeaders(apiKey.code),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      more: false,
      notifications: [
        {
          id: n2.id,
          message: "unread 5m",
          title: null,
          read: false,
          created_at: "5 minutes ago",
        },
        {
          id: n3.id,
          message: "unread 2d",
          title: null,
          read: false,
          created_at: "2 days ago",
        },
        {
          id: n1.id,
          message: "read now",
          title: null,
          read: true,
          created_at: "just now",
        },
        {
          id: n4.id,
          message: "read 3d",
          title: "The Title",
          read: true,
          created_at: "3 days ago",
        },
      ],
    });
  });

  it("paginates 20 per page with a lookahead `more` flag", async () => {
    const { user, apiKey } = await newUserWithKey();
    const now = new Date();
    for (let i = 0; i < 21; i++) {
      await insertNotification(user.id, {
        message: `n${i}`,
        created_at: toStr(addMinutes(now, -(i + 1))),
      });
    }
    let res = await SELF.fetch(`${B}/notifications?page=0`, {
      headers: authHeaders(apiKey.code),
    });
    let body = (await res.json()) as {
      more: boolean;
      notifications: { message: string }[];
    };
    expect(body.more).toBe(true);
    expect(body.notifications).toHaveLength(20);
    expect(body.notifications[0].message).toBe("n0");

    res = await SELF.fetch(`${B}/notifications?page=1`, {
      headers: authHeaders(apiKey.code),
    });
    body = (await res.json()) as typeof body;
    expect(body.more).toBe(false);
    expect(body.notifications).toHaveLength(1);
    expect(body.notifications[0].message).toBe("n20");
  });
});

describe("POST /notifications/:id/read", () => {
  it("marks an own notification as read", async () => {
    const { user, apiKey } = await newUserWithKey();
    const n = await insertNotification(user.id);
    const res = await SELF.fetch(`${B}/notifications/${n.id}/read`, {
      method: "POST",
      headers: authHeaders(apiKey.code),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ done: true });
    const fresh = await env.DB.prepare(
      "SELECT read FROM notification WHERE id = ?1",
    )
      .bind(n.id)
      .first<{ read: number }>();
    expect(fresh?.read).toBe(1);
  });

  it("returns 403 Forbidden for missing or foreign notifications", async () => {
    const { apiKey } = await newUserWithKey();
    const other = await createUser(env.DB);
    const foreign = await insertNotification(other.id);
    for (const id of [999999, foreign.id]) {
      const res = await SELF.fetch(`${B}/notifications/${id}/read`, {
        method: "POST",
        headers: authHeaders(apiKey.code),
      });
      expect(res.status, String(id)).toBe(403);
      expect(await res.json()).toEqual({ error: "Forbidden" });
    }
  });
});

// --------------------------------------------------------------------------
// export
// --------------------------------------------------------------------------

describe("export", () => {
  it("GET /export/data returns aliases (incl. trashed), apps and domains", async () => {
    const { user, apiKey } = await newUserWithKey();
    const a1 = await createAlias(
      env.DB,
      user.id,
      user.default_mailbox_id as number,
    );
    const a2 = await createAlias(
      env.DB,
      user.id,
      user.default_mailbox_id as number,
      { enabled: 0, delete_on: nowStr() },
    );
    await insertRow("custom_domain", {
      user_id: user.id,
      domain: "cd-export.example",
      verified: 0,
    });
    await ensureClientTable(env.DB);
    await insertRow("client", {
      user_id: user.id,
      name: "MyApp",
      home_url: "https://myapp.example",
    });
    await insertRow("client", { user_id: user.id, name: "NoUrl" });

    const res = await SELF.fetch(`${B}/export/data`, {
      headers: authHeaders(apiKey.code),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      email: user.email,
      name: null,
      aliases: [
        { email: a1.email, enabled: true },
        { email: a2.email, enabled: false },
      ],
      apps: [
        { name: "MyApp", home_url: "https://myapp.example" },
        { name: "NoUrl", home_url: null },
      ],
      custom_domains: ["cd-export.example"],
    });
  });

  it("GET /export/aliases returns the exact CSV attachment", async () => {
    const { user, apiKey } = await newUserWithKey();
    const extra = await createMailbox(env.DB, user.id, "aa@extra.example");
    const unverified = await createMailbox(env.DB, user.id, "ab@x.example", {
      verified: 0,
    });
    const a1 = await createAlias(
      env.DB,
      user.id,
      user.default_mailbox_id as number,
      { note: "hello, world" },
    );
    await insertRow("alias_mailbox", { alias_id: a1.id, mailbox_id: extra.id });
    await insertRow("alias_mailbox", {
      alias_id: a1.id,
      mailbox_id: unverified.id,
    });
    const a2 = await createAlias(
      env.DB,
      user.id,
      user.default_mailbox_id as number,
      { enabled: 0 },
    );
    // trashed aliases are excluded from the CSV
    await createAlias(env.DB, user.id, user.default_mailbox_id as number, {
      delete_on: nowStr(),
    });

    const res = await SELF.fetch(`${B}/export/aliases`, {
      headers: authHeaders(apiKey.code),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/csv");
    expect(res.headers.get("content-disposition")).toBe(
      "attachment; filename=aliases.csv",
    );
    expect(await res.text()).toBe(
      "alias,note,enabled,mailboxes\r\n" +
        `${a1.email},"hello, world",True,${user.email} aa@extra.example\r\n` +
        `${a2.email},,False,${user.email}\r\n`,
    );
  });
});

// --------------------------------------------------------------------------
// phone reservations
// --------------------------------------------------------------------------

describe("/phone/reservations/:id", () => {
  async function seedReservation(
    userId: number,
    startOffsetH: number,
    endOffsetH: number,
  ) {
    await ensurePhoneTables(env.DB);
    const number = await insertRow<{ id: number }>("phone_number", {
      number: `+336${Math.floor(Math.random() * 1e8)}`,
    });
    const reservation = await insertRow<{ id: number }>("phone_reservation", {
      number_id: number.id,
      user_id: userId,
      start: toStr(addHours(new Date(), startOffsetH)),
      end: toStr(addHours(new Date(), endOffsetH)),
    });
    return { number, reservation };
  }

  it("returns messages inside the reservation window", async () => {
    const { user, apiKey } = await newUserWithKey();
    const { number, reservation } = await seedReservation(user.id, -2, 1);
    const inWindow = await insertRow<{ id: number }>("phone_message", {
      number_id: number.id,
      from_number: "+33111",
      body: "hi there",
      created_at: toStr(addMinutes(new Date(), -5)),
    });
    await insertRow("phone_message", {
      number_id: number.id,
      from_number: "+33222",
      body: "too old",
      created_at: toStr(addHours(new Date(), -3)),
    });
    await insertRow("phone_message", {
      number_id: number.id,
      from_number: "+33333",
      body: "too new",
      created_at: toStr(addHours(new Date(), 2)),
    });

    for (const method of ["GET", "POST"]) {
      const res = await SELF.fetch(
        `${B}/phone/reservations/${reservation.id}`,
        { method, headers: authHeaders(apiKey.code) },
      );
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({
        ended: false,
        messages: [
          {
            id: inWindow.id,
            from_number: "+33111",
            body: "hi there",
            created_at: "5 minutes ago",
          },
        ],
      });
    }
  });

  it("flags ended reservations", async () => {
    const { user, apiKey } = await newUserWithKey();
    const { reservation } = await seedReservation(user.id, -3, -1);
    const res = await SELF.fetch(`${B}/phone/reservations/${reservation.id}`, {
      headers: authHeaders(apiKey.code),
    });
    expect(await res.json()).toEqual({ ended: true, messages: [] });
  });

  it("rejects missing or foreign reservations", async () => {
    const { apiKey } = await newUserWithKey();
    const other = await createUser(env.DB);
    const { reservation } = await seedReservation(other.id, -1, 1);
    for (const id of [424242, reservation.id]) {
      const res = await SELF.fetch(`${B}/phone/reservations/${id}`, {
        headers: authHeaders(apiKey.code),
      });
      expect(res.status, String(id)).toBe(400);
      expect(await res.json()).toEqual({ error: "Invalid reservation" });
    }
  });
});

// --------------------------------------------------------------------------
// apple
// --------------------------------------------------------------------------

describe("apple", () => {
  it("POST /apple/process_payment fails cleanly without Apple credentials", async () => {
    const { apiKey } = await newUserWithKey();
    const res = await SELF.fetch(`${B}/apple/process_payment`, {
      method: "POST",
      headers: jsonHeaders(apiKey.code),
      body: JSON.stringify({ receipt_data: "abc", is_macapp: true }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Processing failed" });
  });

  it("POST /apple/update_notification rejects payloads without receipt info", async () => {
    for (const body of [
      {},
      { unified_receipt: {} },
      { unified_receipt: { latest_receipt_info: [] } },
    ]) {
      const res = await SELF.fetch(`${B}/apple/update_notification`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "Empty Response" });
    }
  });

  it("POST /apple/update_notification 400s for unknown transactions", async () => {
    const res = await SELF.fetch(`${B}/apple/update_notification`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        unified_receipt: {
          latest_receipt: "r",
          latest_receipt_info: [
            {
              original_transaction_id: "does-not-exist",
              expires_date_ms: "1587442317000",
              product_id: "io.simplelogin.ios_app.subscription.premium.yearly",
            },
          ],
        },
      }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Processing failed" });
  });

  it("POST /apple/update_notification updates the newest transaction", async () => {
    const user = await createUser(env.DB);
    const sub = await insertRow<AppleSubscriptionRow>("apple_subscription", {
      user_id: user.id,
      expires_date: toStr(addDays(new Date(), -30)),
      original_transaction_id: "OT-1",
      receipt_data: "old-receipt",
      plan: "yearly",
      product_id: "old-product",
    });

    const monthly = "io.simplelogin.ios_app.subscription.premium.monthly";
    const res = await SELF.fetch(`${B}/apple/update_notification`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        unified_receipt: {
          latest_receipt: "new-receipt-data",
          latest_receipt_info: [
            {
              original_transaction_id: "OT-1",
              expires_date_ms: "1587438717000",
              product_id: monthly,
            },
            {
              original_transaction_id: "OT-1",
              expires_date_ms: "1587442317000",
              product_id: monthly,
            },
          ],
        },
      }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });

    const fresh = await env.DB.prepare(
      "SELECT * FROM apple_subscription WHERE id = ?1",
    )
      .bind(sub.id)
      .first<AppleSubscriptionRow>();
    expect(fresh?.receipt_data).toBe("new-receipt-data");
    expect(fresh?.plan).toBe("monthly");
    expect(fresh?.product_id).toBe(monthly);
    // arrow.get(1587442317000/1000) == 2020-04-21 04:11:57 UTC
    expect(fresh?.expires_date).toBe("2020-04-21 04:11:57+00:00");
  });
});
