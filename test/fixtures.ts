/**
 * Shared test helpers. All functions take an explicit `db: D1Database` (call
 * sites pass `env.DB` from "cloudflare:test"). Rows are inserted with sane
 * activated defaults; every timestamp/flag is overridable so sort and
 * latest-activity behaviour can be made deterministic.
 */

import type {
  AliasRow,
  ApiKeyRow,
  ContactRow,
  EmailLogRow,
  MailboxRow,
  UserRow,
} from "../src/lib/rows";
import { addDays, addHours, nowStr, toStr } from "../src/lib/dates";

let seq = 0;
const uniq = () => ++seq;

type Overrides = Record<string, unknown>;

async function insertRow<T>(db: D1Database, table: string, values: Overrides): Promise<T> {
  const cols = Object.keys(values);
  const placeholders = cols.map((_, i) => `?${i + 1}`).join(", ");
  const columnList = cols.map((c) => `"${c}"`).join(", ");
  const sql = `INSERT INTO ${table} (${columnList}) VALUES (${placeholders}) RETURNING *`;
  const row = await db
    .prepare(sql)
    .bind(...cols.map((c) => values[c]))
    .first<T>();
  if (!row) throw new Error(`insert into ${table} returned no row`);
  return row;
}

/** 60 lowercase a-z chars, like ApiKey.create's random_string(60). */
function randomCode(len = 60): string {
  const chars = "abcdefghijklmnopqrstuvwxyz";
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  let out = "";
  for (let i = 0; i < len; i++) out += chars[bytes[i] % 26];
  return out;
}

/**
 * Insert an activated user (trial_end 7d1h in the future, flags=1, uuid
 * alternative_id) plus a verified default mailbox, and wire up default_mailbox_id.
 */
export async function createUser(db: D1Database, overrides: Overrides = {}): Promise<UserRow> {
  const n = uniq();
  const values: Overrides = {
    email: `user${n}@example.com`,
    activated: 1,
    trial_end: toStr(addHours(addDays(new Date(), 7), 1)),
    alternative_id: crypto.randomUUID(),
    flags: 1,
    ...overrides,
  };
  const user = await insertRow<UserRow>(db, "users", values);
  const mailbox = await createMailbox(db, user.id, user.email, { verified: 1 });
  await db
    .prepare("UPDATE users SET default_mailbox_id = ?1, updated_at = ?2 WHERE id = ?3")
    .bind(mailbox.id, nowStr(), user.id)
    .run();
  return { ...user, default_mailbox_id: mailbox.id };
}

export function createApiKey(db: D1Database, userId: number, code?: string): Promise<ApiKeyRow> {
  return insertRow<ApiKeyRow>(db, "api_key", { user_id: userId, code: code ?? randomCode() });
}

export function createMailbox(
  db: D1Database,
  userId: number,
  email: string,
  overrides: Overrides = {},
): Promise<MailboxRow> {
  return insertRow<MailboxRow>(db, "mailbox", { user_id: userId, email, verified: 1, ...overrides });
}

export function createAlias(
  db: D1Database,
  userId: number,
  mailboxId: number,
  overrides: Overrides = {},
): Promise<AliasRow> {
  const n = uniq();
  return insertRow<AliasRow>(db, "alias", {
    user_id: userId,
    email: `alias${n}@sl.test`,
    mailbox_id: mailboxId,
    ...overrides,
  });
}

export function createContact(
  db: D1Database,
  userId: number,
  aliasId: number,
  overrides: Overrides = {},
): Promise<ContactRow> {
  const n = uniq();
  return insertRow<ContactRow>(db, "contact", {
    user_id: userId,
    alias_id: aliasId,
    website_email: `contact${n}@example.com`,
    reply_email: `reply${n}@sl.test`,
    ...overrides,
  });
}

/**
 * Insert an email_log and (like EmailLog.create) point its alias's
 * last_email_log_id at it. alias_id is taken from overrides, else derived from
 * the contact. message_id is truncated to 250 chars.
 */
export async function createEmailLog(
  db: D1Database,
  userId: number,
  contactId: number,
  overrides: Overrides = {},
): Promise<EmailLogRow> {
  let aliasId: number | null;
  if (Object.prototype.hasOwnProperty.call(overrides, "alias_id")) {
    aliasId = overrides.alias_id as number | null;
  } else {
    const c = await db
      .prepare("SELECT alias_id FROM contact WHERE id = ?1")
      .bind(contactId)
      .first<{ alias_id: number }>();
    aliasId = c?.alias_id ?? null;
  }

  const values: Overrides = { user_id: userId, contact_id: contactId, alias_id: aliasId, ...overrides };
  if (typeof values.message_id === "string") values.message_id = values.message_id.slice(0, 250);

  const log = await insertRow<EmailLogRow>(db, "email_log", values);
  if (aliasId != null) {
    await db
      .prepare("UPDATE alias SET last_email_log_id = ?1, updated_at = ?2 WHERE id = ?3")
      .bind(log.id, nowStr(), aliasId)
      .run();
  }
  return log;
}

export function authHeaders(code: string): Record<string, string> {
  return { Authentication: code };
}
