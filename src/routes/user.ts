/**
 * User info, settings, sudo, notifications, export, phone and Apple IAP
 * routes — spec 05 (app/api/views/{user_info,user,sudo,setting,notification,
 * export,phone,apple}.py).
 *
 * Deliberate deviations from Flask (documented in the port notes):
 * - Profile pictures are stored in KV under `file:<path>` (plus a `file` row)
 *   instead of S3; `profile_picture_url` uses the LOCAL_FILE_UPLOAD shape
 *   `${URL}/static/upload/<path>`.
 * - Flask paths that 500 on real bugs return clean 4xx here: PATCH /sudo via
 *   cookie auth, unlink_proton_account when never linked, invalid base64 in
 *   `profile_picture`, CSV export with an unverified primary mailbox.
 * - Apple receipt verification requires Apple credentials + network; this
 *   deployment has neither, so /apple/process_payment always answers the
 *   Flask failure body `400 {"error": "Processing failed"}`.
 * - user_audit_log / phone_* / client tables are not in the D1 migrations;
 *   this module creates them on demand (CREATE TABLE IF NOT EXISTS).
 */

import { Hono } from "hono";
import { type AppEnv, requireApiAuth, requireApiSudo } from "../lib/auth";
import { checkPassword, randomString, tokenUrlsafe } from "../lib/crypto";
import { humanize, nowStr, toDate, toEpoch, toStr } from "../lib/dates";
import type { Env } from "../lib/env";
import { badRequest, forbidden, jsonError } from "../lib/errors";
import {
  defaultRandomAliasDomain,
  FLAG_CREATED_FROM_PARTNER,
  FLAG_FREE_DISABLE_CREATE_CONTACTS,
  getSLDomains,
  inTrial,
  isPremium,
  lifetimeOrActiveSubscription,
  maxAliasForFreeAccount,
  premiumInputsForUser,
  userIsPremium,
} from "../lib/models";
import { rateLimit } from "../lib/ratelimit";
import type {
  AliasRow,
  AppleSubscriptionRow,
  FileRow,
  MailboxRow,
  NotificationRow,
  PartnerUserRow,
  PublicDomainRow,
  UserRow,
} from "../lib/rows";
import { destroySession, getSession } from "../lib/session";

export const userRoutes = new Hono<AppEnv>();

const PAGE_LIMIT = 20; // config.PAGE_LIMIT
const DEFAULT_MAX_API_KEYS = 30; // config.MAX_API_KEYS

/** Env vars not in the shared Env typing (presence flags & Apple secrets). */
type ExtraVars = Record<string, string | undefined>;

// --------------------------------------------------------------------------
// small local helpers
// --------------------------------------------------------------------------

/**
 * Flask 1.x `request.get_json()`: returns None unless the Content-Type is
 * JSON; malformed JSON raises → the /api error handler answers
 * 400 {"error": "Bad Request"} (a SyntaxError thrown here is caught by
 * app.onError in index.ts).
 */
async function jsonBody(c: {
  req: { header(name: string): string | undefined; text(): Promise<string> };
}): Promise<unknown> {
  const ct = (c.req.header("Content-Type") ?? "")
    .split(";")[0]
    .trim()
    .toLowerCase();
  if (ct !== "application/json" && !ct.endsWith("+json")) return null;
  return JSON.parse(await c.req.text());
}

/** Python `int(str)` — optional sign, digits only, surrounding whitespace ok. */
function parsePyInt(raw: string | undefined): number | null {
  if (raw === undefined) return null;
  const s = raw.trim();
  if (!/^[+-]?\d+$/.test(s)) return null;
  return Number.parseInt(s, 10);
}

/**
 * base64.decodebytes-ish lenient decode: ignore whitespace/foreign chars,
 * null on anything atob still rejects (Flask 500s there; we 400 cleanly).
 */
function decodeBase64Lenient(s: string): Uint8Array | null {
  const cleaned = s.replace(/[^A-Za-z0-9+/=]/g, "");
  try {
    const bin = atob(cleaned);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** app/image_validation.py detect_image_format — PNG / JFIF-JPG / RIFF only. */
function imageFormatIsSupported(b: Uint8Array): boolean {
  const startsWith = (sig: number[]) => sig.every((v, i) => b[i] === v);
  return (
    startsWith([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) ||
    startsWith([0xff, 0xd8, 0xff, 0xe0]) ||
    startsWith([0x52, 0x49, 0x46, 0x46])
  );
}

/** User.can_create_contacts() (models.py L1276). */
function canCreateContacts(user: UserRow, premium: boolean, env: Env): boolean {
  if (premium) return true;
  if ((user.flags & FLAG_FREE_DISABLE_CREATE_CONTACTS) === 0) return true;
  // NOT presence-based: os.environ.get(..., False) — empty string is falsy.
  return !(env as unknown as ExtraVars).DISABLE_CREATE_CONTACTS_FOR_FREE_USERS;
}

/** Tables used here but absent from migrations/ (see file header). */
export async function ensureUserAuditLogTable(db: D1Database): Promise<void> {
  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS user_audit_log (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
         updated_at TEXT,
         user_id INTEGER NOT NULL,
         user_email VARCHAR(255) NOT NULL,
         action VARCHAR(255) NOT NULL,
         message TEXT
       )`,
    )
    .run();
}

export async function ensureClientTable(db: D1Database): Promise<void> {
  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS client (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
         updated_at TEXT,
         oauth_client_id VARCHAR(128),
         oauth_client_secret VARCHAR(128),
         name VARCHAR(128) NOT NULL,
         home_url VARCHAR(1024),
         user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
         icon_id INTEGER,
         approved INTEGER NOT NULL DEFAULT 0,
         description TEXT,
         referral_id INTEGER
       )`,
    )
    .run();
}

export async function ensurePhoneTables(db: D1Database): Promise<void> {
  await db.batch([
    db.prepare(
      `CREATE TABLE IF NOT EXISTS phone_number (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
         updated_at TEXT,
         country_id INTEGER,
         number VARCHAR(128) NOT NULL UNIQUE,
         active INTEGER NOT NULL DEFAULT 1,
         comment TEXT
       )`,
    ),
    db.prepare(
      `CREATE TABLE IF NOT EXISTS phone_reservation (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
         updated_at TEXT,
         number_id INTEGER NOT NULL REFERENCES phone_number(id) ON DELETE CASCADE,
         user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
         "start" TEXT NOT NULL,
         "end" TEXT NOT NULL
       )`,
    ),
    db.prepare(
      `CREATE TABLE IF NOT EXISTS phone_message (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
         updated_at TEXT,
         number_id INTEGER NOT NULL REFERENCES phone_number(id) ON DELETE CASCADE,
         from_number VARCHAR(128) NOT NULL,
         body TEXT
       )`,
    ),
  ]);
}

interface PhoneReservationRow {
  id: number;
  number_id: number;
  user_id: number;
  start: string;
  end: string;
}

interface PhoneMessageRow {
  id: number;
  created_at: string;
  number_id: number;
  from_number: string;
  body: string | null;
}

// --------------------------------------------------------------------------
// user_info.py — user_to_dict + GET/PATCH /user_info
// --------------------------------------------------------------------------

async function userToDict(
  db: D1Database,
  env: Env,
  user: UserRow,
): Promise<Record<string, unknown>> {
  const now = new Date();
  const inputs = await premiumInputsForUser(db, user);
  const premium = isPremium(inputs, now);
  const inTrialNow =
    !lifetimeOrActiveSubscription(inputs, now) && inTrial(user, now);

  let connectedProton: string | null = null;
  if ((env as unknown as ExtraVars).CONNECT_WITH_PROTON !== undefined) {
    const row = await db
      .prepare(
        `SELECT pu.partner_email FROM partner_user pu
         JOIN partner p ON pu.partner_id = p.id
         WHERE pu.user_id = ?1 AND p.name = 'Proton'`,
      )
      .bind(user.id)
      .first<{ partner_email: string | null }>();
    connectedProton = row?.partner_email ?? null;
  }

  let profilePictureUrl: string | null = null;
  if (user.profile_picture_id) {
    const file = await db
      .prepare("SELECT * FROM file WHERE id = ?1")
      .bind(user.profile_picture_id)
      .first<FileRow>();
    if (file) profilePictureUrl = `${env.URL}/static/upload/${file.path}`;
  }

  return {
    name: user.name ?? "",
    is_premium: premium,
    email: user.email,
    in_trial: inTrialNow,
    trial_end_timestamp: user.trial_end ? toEpoch(user.trial_end) : null,
    max_alias_free_plan: maxAliasForFreeAccount(user, env),
    connected_proton_address: connectedProton,
    can_create_reverse_alias: canCreateContacts(user, premium, env),
    profile_picture_url: profilePictureUrl,
  };
}

userRoutes.get("/user_info", requireApiAuth, async (c) => {
  return c.json(await userToDict(c.env.DB, c.env, c.get("user")));
});

userRoutes.patch("/user_info", requireApiAuth, async (c) => {
  const db = c.env.DB;
  let user = c.get("user");
  const data = ((await jsonBody(c)) ?? {}) as Record<string, unknown>;

  if ("profile_picture" in data) {
    // Flask removes the current picture first, before validating the new one,
    // but only with Session.flush(): the blob delete (s3.delete, KV here) is
    // immediate, while the DB changes roll back when the 400 below returns
    // before Session.commit(). D1 statements auto-commit, so defer them until
    // validation has passed.
    const oldFile = user.profile_picture_id
      ? await db
          .prepare("SELECT * FROM file WHERE id = ?1")
          .bind(user.profile_picture_id)
          .first<FileRow>()
      : null;
    if (oldFile) await c.env.KV.delete(`file:${oldFile.path}`);

    let raw: Uint8Array | null = null;
    if (data.profile_picture !== null) {
      raw =
        typeof data.profile_picture === "string"
          ? decodeBase64Lenient(data.profile_picture)
          : null;
      if (!raw || !imageFormatIsSupported(raw)) {
        return badRequest(c, "Unsupported image format");
      }
    }

    if (user.profile_picture_id) {
      await db
        .prepare(
          "UPDATE users SET profile_picture_id = NULL, updated_at = ?1 WHERE id = ?2",
        )
        .bind(nowStr(), user.id)
        .run();
      user = { ...user, profile_picture_id: null };
      if (oldFile) {
        await db
          .prepare("DELETE FROM file WHERE id = ?1")
          .bind(oldFile.id)
          .run();
      }
    }
    if (raw) {
      const path = randomString(30);
      const file = await db
        .prepare("INSERT INTO file (path, user_id) VALUES (?1, ?2) RETURNING *")
        .bind(path, user.id)
        .first<FileRow>();
      await c.env.KV.put(`file:${path}`, raw);
      await db
        .prepare(
          "UPDATE users SET profile_picture_id = ?1, updated_at = ?2 WHERE id = ?3",
        )
        .bind(file?.id ?? null, nowStr(), user.id)
        .run();
      user = { ...user, profile_picture_id: file?.id ?? null };
    }
  }

  if ("name" in data) {
    const name = (data.name ?? null) as string | null;
    await db
      .prepare("UPDATE users SET name = ?1, updated_at = ?2 WHERE id = ?3")
      .bind(name, nowStr(), user.id)
      .run();
    user = { ...user, name };
  }

  return c.json(await userToDict(db, c.env, user));
});

// --------------------------------------------------------------------------
// POST /api_key (sudo) — user_info.py create_api_key
// --------------------------------------------------------------------------

/** app/dashboard/views/api_key.py clean_up_unused_or_old_api_keys. */
async function cleanUpUnusedOrOldApiKeys(
  env: Env,
  userId: number,
): Promise<void> {
  const maxKeys =
    parsePyInt((env as unknown as ExtraVars).MAX_API_KEYS) ??
    DEFAULT_MAX_API_KEYS;
  const countRow = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM api_key WHERE user_id = ?1",
  )
    .bind(userId)
    .first<{ n: number }>();
  let total = countRow?.n ?? 0;
  if (total <= maxKeys) return;

  // Remove oldest unused keys first, then oldest used ones.
  const unused = await env.DB.prepare(
    "SELECT id FROM api_key WHERE user_id = ?1 AND last_used IS NULL ORDER BY created_at ASC",
  )
    .bind(userId)
    .all<{ id: number }>();
  for (const key of unused.results) {
    await env.DB.prepare("DELETE FROM api_key WHERE id = ?1")
      .bind(key.id)
      .run();
    total -= 1;
    if (total <= maxKeys) return;
  }
  const used = await env.DB.prepare(
    "SELECT id FROM api_key WHERE user_id = ?1 ORDER BY last_used ASC",
  )
    .bind(userId)
    .all<{ id: number }>();
  for (const key of used.results) {
    await env.DB.prepare("DELETE FROM api_key WHERE id = ?1")
      .bind(key.id)
      .run();
    total -= 1;
    if (total <= maxKeys) return;
  }
}

userRoutes.post("/api_key", requireApiSudo, async (c) => {
  const data = await jsonBody(c);
  // Python truthiness: None, {} and [] are all "empty body".
  const empty =
    !data || (typeof data === "object" && Object.keys(data).length === 0);
  if (empty) return badRequest(c, "request body cannot be empty");

  // Truthy non-dict bodies ("x", 123, [1], true): Flask's data.get("device")
  // raises AttributeError → 500 {"error": "Internal error"}, no key created.
  if (typeof data !== "object" || Array.isArray(data)) {
    return jsonError(c, 500, "Internal error");
  }

  const device = (data as Record<string, unknown>).device ?? null;
  const user = c.get("user");
  await cleanUpUnusedOrOldApiKeys(c.env, user.id);
  const code = randomString(60);
  await c.env.DB.prepare(
    "INSERT INTO api_key (user_id, code, name) VALUES (?1, ?2, ?3)",
  )
    .bind(user.id, code, device as string | null)
    .run();
  return c.json({ api_key: code }, 201);
});

// --------------------------------------------------------------------------
// GET /logout, GET /stats — user_info.py
// --------------------------------------------------------------------------

userRoutes.get("/logout", requireApiAuth, async (c) => {
  await destroySession(c);
  return c.json({ msg: "User is logged out" });
});

userRoutes.get("/stats", requireApiAuth, async (c) => {
  const db = c.env.DB;
  const userId = c.get("user").id;
  const count = async (sql: string) =>
    (await db.prepare(sql).bind(userId).first<{ n: number }>())?.n ?? 0;

  const [nbAlias, nbForward, nbReply, nbBlock] = await Promise.all([
    count(
      "SELECT COUNT(*) AS n FROM alias WHERE user_id = ?1 AND delete_on IS NULL",
    ),
    count(
      "SELECT COUNT(*) AS n FROM email_log WHERE user_id = ?1 AND is_reply = 0 AND blocked = 0 AND bounced = 0",
    ),
    count(
      "SELECT COUNT(*) AS n FROM email_log WHERE user_id = ?1 AND is_reply = 1 AND blocked = 0 AND bounced = 0",
    ),
    count(
      "SELECT COUNT(*) AS n FROM email_log WHERE user_id = ?1 AND is_reply = 0 AND blocked = 1 AND bounced = 0",
    ),
  ]);

  return c.json({
    nb_alias: nbAlias,
    nb_forward: nbForward,
    nb_reply: nbReply,
    nb_block: nbBlock,
  });
});

// --------------------------------------------------------------------------
// DELETE /user, GET /user/cookie_token — user.py
// --------------------------------------------------------------------------

userRoutes.delete("/user", requireApiSudo, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  await ensureUserAuditLogTable(db);
  await db
    .prepare(
      "INSERT INTO user_audit_log (user_id, user_email, action, message) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(
      user.id,
      user.email,
      "user_marked_for_deletion",
      `Marked user ${user.id} (${user.email}) for deletion from API`,
    )
    .run();
  await db
    .prepare("INSERT INTO job (name, payload, run_at) VALUES (?1, ?2, ?3)")
    .bind("delete-account", JSON.stringify({ user_id: user.id }), nowStr())
    .run();
  return c.json({ ok: true });
});

userRoutes.get(
  "/user/cookie_token",
  requireApiAuth,
  rateLimit("cookie_token", "5/minute"),
  async (c) => {
    const apiKey = c.get("apiKey");
    if (!apiKey) return c.json({ ok: false }, 401);
    const code = tokenUrlsafe(32);
    await c.env.DB.prepare(
      "INSERT INTO api_cookie_token (code, user_id, api_key_id) VALUES (?1, ?2, ?3)",
    )
      .bind(code, c.get("user").id, apiKey.id)
      .run();
    return c.json({ token: code });
  },
);

// --------------------------------------------------------------------------
// PATCH /sudo — sudo.py (rate limit runs BEFORE auth, like the Flask
// decorator order)
// --------------------------------------------------------------------------

userRoutes.patch(
  "/sudo",
  // flask-limiter's key func runs before API auth but sees flask-login's
  // lazily-loaded current_user: cookie-session requests are keyed per-user,
  // only anonymous/API-key traffic per-IP. Load the session for the limiter.
  async (c, next) => {
    c.set("session", await getSession(c));
    await next();
  },
  rateLimit("sudo", "5/minute"),
  requireApiAuth,
  async (c) => {
    const user = c.get("user");
    const data = ((await jsonBody(c)) ?? {}) as Record<string, unknown>;
    if (!("password" in data)) return jsonError(c, 403, "Invalid password");
    const password = data.password;
    if (
      typeof password !== "string" ||
      !(await checkPassword(user.password, password))
    ) {
      return jsonError(c, 403, "Invalid password");
    }
    const apiKey = c.get("apiKey");
    if (!apiKey) {
      // Flask 500s here (g.api_key is None); clean 4xx deviation.
      return badRequest(c, "Sudo requires an API key");
    }
    await c.env.DB.prepare(
      "UPDATE api_key SET sudo_mode_at = ?1, updated_at = ?1 WHERE id = ?2",
    )
      .bind(nowStr(), apiKey.id)
      .run();
    return c.json({ ok: true });
  },
);

// --------------------------------------------------------------------------
// setting.py — GET/PATCH /setting, domains v1/v2, unlink_proton_account
// --------------------------------------------------------------------------

const SENDER_FORMAT_NAMES: Record<number, string> = {
  0: "AT",
  2: "A",
  5: "NAME_ONLY",
  6: "AT_ONLY",
  7: "NO_NAME",
};
const SENDER_FORMAT_VALUES: Record<string, number> = {
  AT: 0,
  A: 2,
  NAME_ONLY: 5,
  AT_ONLY: 6,
  NO_NAME: 7,
};
const ALIAS_SUFFIX_NAMES: Record<number, string> = {
  0: "word",
  1: "random_string",
};

async function settingToDict(
  db: D1Database,
  env: Env,
  user: UserRow,
): Promise<Record<string, unknown>> {
  return {
    notification: !!user.notification,
    alias_generator: user.alias_generator === 1 ? "word" : "uuid",
    random_alias_default_domain: await defaultRandomAliasDomain(db, user, env),
    sender_format: SENDER_FORMAT_NAMES[user.sender_format] ?? "AT",
    random_alias_suffix: ALIAS_SUFFIX_NAMES[user.random_alias_suffix] ?? null,
  };
}

userRoutes.get("/setting", requireApiAuth, async (c) => {
  return c.json(await settingToDict(c.env.DB, c.env, c.get("user")));
});

userRoutes.patch("/setting", requireApiAuth, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const data = ((await jsonBody(c)) ?? {}) as Record<string, unknown>;

  // Stage updates, then write: a validation error mid-way must not commit
  // earlier fields (Flask rolls the uncommitted session back).
  const sets: string[] = [];
  const binds: unknown[] = [];
  const stage = (column: string, value: unknown) => {
    binds.push(value);
    sets.push(`${column} = ?${binds.length}`);
  };

  if ("notification" in data) stage("notification", data.notification ? 1 : 0);

  if ("alias_generator" in data) {
    const aliasGenerator = data.alias_generator;
    if (aliasGenerator !== "word" && aliasGenerator !== "uuid") {
      return badRequest(c, "Invalid alias_generator");
    }
    stage("alias_generator", aliasGenerator === "word" ? 1 : 2);
  }

  if ("sender_format" in data) {
    const value = SENDER_FORMAT_VALUES[data.sender_format as string];
    if (value === undefined) return badRequest(c, "Invalid sender_format");
    stage("sender_format", value);
    stage("sender_format_updated_at", nowStr());
  }

  if ("random_alias_suffix" in data) {
    const suffix = data.random_alias_suffix;
    if (suffix !== "word" && suffix !== "random_string") {
      return badRequest(c, "Invalid random_alias_suffix");
    }
    stage("random_alias_suffix", suffix === "word" ? 0 : 1);
  }

  if ("random_alias_default_domain" in data) {
    const domain = data.random_alias_default_domain as string;
    const slDomain = await db
      .prepare("SELECT * FROM public_domain WHERE domain = ?1")
      .bind(domain)
      .first<PublicDomainRow>();
    if (slDomain) {
      if (slDomain.premium_only && !(await userIsPremium(db, user))) {
        return badRequest(c, "You cannot use this domain");
      }
      stage("default_alias_public_domain_id", slDomain.id);
      stage("default_alias_custom_domain_id", null);
    } else {
      const customDomain = await db
        .prepare("SELECT * FROM custom_domain WHERE domain = ?1")
        .bind(domain)
        .first<{ id: number; user_id: number; verified: number }>();
      if (
        !customDomain ||
        customDomain.user_id !== user.id ||
        !customDomain.verified
      ) {
        return badRequest(c, "invalid domain");
      }
      stage("default_alias_custom_domain_id", customDomain.id);
      stage("default_alias_public_domain_id", null);
    }
  }

  if (sets.length > 0) {
    stage("updated_at", nowStr());
    binds.push(user.id);
    await db
      .prepare(
        `UPDATE users SET ${sets.join(", ")} WHERE id = ?${binds.length}`,
      )
      .bind(...binds)
      .run();
  }

  const fresh = await db
    .prepare("SELECT * FROM users WHERE id = ?1")
    .bind(user.id)
    .first<UserRow>();
  return c.json(await settingToDict(db, c.env, fresh ?? user));
});

/** User.available_domains_for_random_alias(): [is_sl, domain] pairs. */
async function availableDomainsForRandomAlias(
  db: D1Database,
  env: Env,
  user: UserRow,
): Promise<[boolean, string][]> {
  const result: [boolean, string][] = [];
  for (const slDomain of await getSLDomains(db, user, env)) {
    result.push([true, slDomain.domain]);
  }
  const custom = await db
    .prepare(
      "SELECT domain FROM custom_domain WHERE user_id = ?1 AND ownership_verified = 1 ORDER BY domain ASC",
    )
    .bind(user.id)
    .all<{ domain: string }>();
  for (const row of custom.results) result.push([false, row.domain]);
  return result;
}

userRoutes.get("/setting/domains", requireApiAuth, async (c) => {
  const pairs = await availableDomainsForRandomAlias(
    c.env.DB,
    c.env,
    c.get("user"),
  );
  return c.json(pairs);
});

userRoutes.get("/v2/setting/domains", requireApiAuth, async (c) => {
  const pairs = await availableDomainsForRandomAlias(
    c.env.DB,
    c.env,
    c.get("user"),
  );
  return c.json(pairs.map(([isSl, domain]) => ({ domain, is_custom: !isSl })));
});

userRoutes.delete(
  "/setting/unlink_proton_account",
  requireApiAuth,
  async (c) => {
    const db = c.env.DB;
    const user = c.get("user");
    if (user.flags & FLAG_CREATED_FROM_PARTNER) {
      return badRequest(c, "The account cannot be unlinked");
    }
    const partnerUser = await db
      .prepare(
        `SELECT pu.* FROM partner_user pu
       JOIN partner p ON pu.partner_id = p.id
       WHERE pu.user_id = ?1 AND p.name = 'Proton'`,
      )
      .bind(user.id)
      .first<PartnerUserRow>();
    if (!partnerUser) {
      // Flask 500s (AttributeError on None); clean 4xx deviation.
      return badRequest(c, "The account cannot be unlinked");
    }
    await ensureUserAuditLogTable(db);
    await db
      .prepare(
        "INSERT INTO user_audit_log (user_id, user_email, action, message) VALUES (?1, ?2, ?3, ?4)",
      )
      .bind(
        user.id,
        user.email,
        "unlink_account",
        `User has unlinked the account (email=${partnerUser.partner_email} | external_user_id=${partnerUser.external_user_id})`,
      )
      .run();
    await db
      .prepare("DELETE FROM partner_user WHERE id = ?1")
      .bind(partnerUser.id)
      .run();
    return c.json({ ok: true });
  },
);

// --------------------------------------------------------------------------
// notification.py
// --------------------------------------------------------------------------

userRoutes.get("/notifications", requireApiAuth, async (c) => {
  const page = parsePyInt(c.req.query("page"));
  if (page === null) {
    return badRequest(c, "page must be provided in request query");
  }
  if (page < 0) {
    // Postgres rejects the negative OFFSET ("OFFSET must not be negative")
    // → Flask 500s; SQLite would silently treat it as 0.
    return jsonError(c, 500, "Internal error");
  }
  const res = await c.env.DB.prepare(
    `SELECT * FROM notification WHERE user_id = ?1
     ORDER BY read ASC, created_at DESC LIMIT ?2 OFFSET ?3`,
  )
    .bind(c.get("user").id, PAGE_LIMIT + 1, page * PAGE_LIMIT)
    .all<NotificationRow>();

  return c.json({
    more: res.results.length > PAGE_LIMIT,
    notifications: res.results.slice(0, PAGE_LIMIT).map((n) => ({
      id: n.id,
      message: n.message,
      title: n.title,
      read: !!n.read,
      created_at: humanize(n.created_at),
    })),
  });
});

userRoutes.post(
  "/notifications/:notification_id{[0-9]+}/read",
  requireApiAuth,
  async (c) => {
    const id = Number(c.req.param("notification_id"));
    const notification = await c.env.DB.prepare(
      "SELECT * FROM notification WHERE id = ?1",
    )
      .bind(id)
      .first<NotificationRow>();
    if (!notification || notification.user_id !== c.get("user").id) {
      return forbidden(c);
    }
    await c.env.DB.prepare(
      "UPDATE notification SET read = 1, updated_at = ?1 WHERE id = ?2",
    )
      .bind(nowStr(), id)
      .run();
    return c.json({ done: true });
  },
);

// --------------------------------------------------------------------------
// export.py
// --------------------------------------------------------------------------

userRoutes.get("/export/data", requireApiAuth, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  await ensureClientTable(db);

  const aliases = await db
    .prepare("SELECT email, enabled FROM alias WHERE user_id = ?1")
    .bind(user.id)
    .all<{ email: string; enabled: number }>();
  const customDomains = await db
    .prepare("SELECT domain FROM custom_domain WHERE user_id = ?1")
    .bind(user.id)
    .all<{ domain: string }>();
  const apps = await db
    .prepare("SELECT name, home_url FROM client WHERE user_id = ?1")
    .bind(user.id)
    .all<{ name: string; home_url: string | null }>();

  return c.json({
    email: user.email,
    name: user.name,
    aliases: aliases.results.map((a) => ({
      email: a.email,
      enabled: !!a.enabled,
    })),
    apps: apps.results.map((a) => ({ name: a.name, home_url: a.home_url })),
    custom_domains: customDomains.results.map((d) => d.domain),
  });
});

/** Python csv.writer defaults: QUOTE_MINIMAL, '"' quotechar, CRLF rows. */
function csvField(value: string): string {
  if (/[",\r\n]/.test(value)) return `"${value.replaceAll('"', '""')}"`;
  return value;
}

userRoutes.get("/export/aliases", requireApiAuth, async (c) => {
  const db = c.env.DB;
  const user = c.get("user");
  const aliases = await db
    .prepare("SELECT * FROM alias WHERE user_id = ?1 AND delete_on IS NULL")
    .bind(user.id)
    .all<AliasRow>();

  const rows: string[][] = [["alias", "note", "enabled", "mailboxes"]];
  for (const alias of aliases.results) {
    // Alias.mailboxes: primary + m2m extras, verified only, email-sorted;
    // the export then moves the primary mailbox back to the front.
    const primary = await db
      .prepare("SELECT * FROM mailbox WHERE id = ?1")
      .bind(alias.mailbox_id)
      .first<MailboxRow>();
    const extras = await db
      .prepare(
        `SELECT m.* FROM mailbox m
         JOIN alias_mailbox am ON am.mailbox_id = m.id
         WHERE am.alias_id = ?1`,
      )
      .bind(alias.id)
      .all<MailboxRow>();
    let mailboxes = primary ? [primary] : [];
    for (const m of extras.results) {
      if (m.id !== alias.mailbox_id) mailboxes.push(m);
    }
    mailboxes = mailboxes
      .filter((m) => m.verified)
      .sort((a, b) => (a.email < b.email ? -1 : a.email > b.email ? 1 : 0));
    const primaryIdx = mailboxes.findIndex((m) => m.id === alias.mailbox_id);
    if (primaryIdx > 0) {
      const [p] = mailboxes.splice(primaryIdx, 1);
      mailboxes.unshift(p);
    }
    // (Flask 500s when the primary mailbox is unverified; we export as-is.)
    rows.push([
      alias.email,
      alias.note ?? "",
      alias.enabled ? "True" : "False",
      mailboxes.map((m) => m.email).join(" "),
    ]);
  }

  const csv = `${rows.map((r) => r.map(csvField).join(",")).join("\r\n")}\r\n`;
  return c.body(csv, 200, {
    "Content-Type": "text/csv",
    "Content-Disposition": "attachment; filename=aliases.csv",
  });
});

// --------------------------------------------------------------------------
// phone.py
// --------------------------------------------------------------------------

userRoutes.on(
  ["GET", "POST"],
  "/phone/reservations/:reservation_id{[0-9]+}",
  requireApiAuth,
  async (c) => {
    const db = c.env.DB;
    await ensurePhoneTables(db);
    const id = Number(c.req.param("reservation_id"));
    const reservation = await db
      .prepare("SELECT * FROM phone_reservation WHERE id = ?1")
      .bind(id)
      .first<PhoneReservationRow>();
    if (!reservation || reservation.user_id !== c.get("user").id) {
      return badRequest(c, "Invalid reservation");
    }
    const messages = await db
      .prepare(
        `SELECT * FROM phone_message
         WHERE number_id = ?1 AND created_at > ?2 AND created_at < ?3`,
      )
      .bind(reservation.number_id, reservation.start, reservation.end)
      .all<PhoneMessageRow>();

    return c.json({
      ended: toDate(reservation.end).getTime() < Date.now(),
      messages: messages.results.map((m) => ({
        id: m.id,
        from_number: m.from_number,
        body: m.body,
        created_at: humanize(m.created_at),
      })),
    });
  },
);

// --------------------------------------------------------------------------
// apple.py
// --------------------------------------------------------------------------

const APPLE_MONTHLY_PRODUCT_IDS = [
  "io.simplelogin.ios_app.subscription.premium.monthly",
  "io.simplelogin.macapp.subscription.premium.monthly",
  "me.proton.simplelogin.macos.premium.monthly",
];

userRoutes.post("/apple/process_payment", requireApiAuth, async (c) => {
  // Parse the request like Flask (missing body 500s there; clean 4xx here).
  const data = ((await jsonBody(c)) ?? {}) as Record<string, unknown>;
  void data.receipt_data;
  void (data.is_macapp === true);
  // verify_receipt requires Apple credentials + outbound network, neither of
  // which exist in this deployment — every verification fails, which Flask
  // reports with this exact body.
  return badRequest(c, "Processing failed");
});

userRoutes.post("/apple/update_notification", async (c) => {
  const db = c.env.DB;
  const extra = c.env as unknown as ExtraVars;
  const data = (await jsonBody(c)) as Record<string, unknown> | null;

  if (extra.APPLE_WEBHOOK_SECRET_CHECK_ENABLED !== undefined) {
    const password = data?.password;
    if (
      !data ||
      !password ||
      (password !== extra.APPLE_API_SECRET &&
        password !== extra.MACAPP_APPLE_API_SECRET)
    ) {
      return jsonError(c, 401, "Unauthorized");
    }
  }

  const unified = data?.unified_receipt as
    | { latest_receipt?: string; latest_receipt_info?: unknown }
    | undefined;
  const transactions = unified?.latest_receipt_info;
  // Python truthiness: empty dicts {} are falsy too, not just empty arrays.
  if (
    !data ||
    !unified ||
    !transactions ||
    (typeof transactions === "object" && Object.keys(transactions).length === 0)
  ) {
    return badRequest(c, "Empty Response");
  }

  // Keep the transaction with the largest expires_date_ms per
  // original_transaction_id. NB: string comparison, bug-compatible with
  // Flask (correct only while all values have the same digit count).
  const latestTransactions: Record<string, Record<string, unknown>> = {};
  for (const t of transactions as Record<string, unknown>[]) {
    const otid = String(t.original_transaction_id);
    if (!latestTransactions[otid]) latestTransactions[otid] = t;
    if (
      String(t.expires_date_ms) >
      String(latestTransactions[otid].expires_date_ms)
    ) {
      latestTransactions[otid] = t;
    }
  }

  // Flask returns inside the first loop iteration either way.
  for (const [otid, t] of Object.entries(latestTransactions)) {
    const expiresDate = toStr(
      new Date(Number.parseInt(String(t.expires_date_ms), 10)),
    );
    const plan = APPLE_MONTHLY_PRODUCT_IDS.includes(String(t.product_id))
      ? "monthly"
      : "yearly";
    const appleSub = await db
      .prepare(
        "SELECT * FROM apple_subscription WHERE original_transaction_id = ?1",
      )
      .bind(otid)
      .first<AppleSubscriptionRow>();
    if (appleSub) {
      if (!("latest_receipt" in unified)) {
        // Flask: data["unified_receipt"]["latest_receipt"] raises KeyError
        // → 500 {"error": "Internal error"}, nothing committed.
        return jsonError(c, 500, "Internal error");
      }
      await db
        .prepare(
          `UPDATE apple_subscription SET receipt_data = ?1, expires_date = ?2,
             plan = ?3, product_id = ?4, updated_at = ?5 WHERE id = ?6`,
        )
        .bind(
          // null propagates: receipt_data is NOT NULL, so a JSON null fails
          // the UPDATE → 500, matching Flask's IntegrityError on commit.
          unified.latest_receipt ?? null,
          expiresDate,
          plan,
          (t.product_id as string | null) ?? null,
          nowStr(),
          appleSub.id,
        )
        .run();
      // (Flask also fires the subscription webhook / sync event here —
      // that infrastructure is not part of this port.)
      return c.json({ ok: true });
    }
    return badRequest(c, "Processing failed");
  }
  // Unreachable in practice; Flask falls through to a 500 here.
  return badRequest(c, "Processing failed");
});
