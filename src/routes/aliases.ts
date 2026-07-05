/**
 * Alias & contact management routes — port of app/api/views/alias.py
 * (specs/02-aliases.md). All paths are mounted under /api by src/index.ts.
 *
 * Ownership/error semantics are copied exactly (clients string-match bodies):
 * - GET /aliases/<id> missing alias -> 400 {"error": "Unknown error"}
 * - contacts endpoints -> 404 {"error": "No such alias"}
 * - update mailbox_id failure -> 400 with body "Forbidden"
 * Deliberate deviations from Flask (per HANDOVER §1): paths that 500 in Flask
 * due to bugs (non-numeric mailbox_id, non-object JSON bodies) return clean
 * 4xx; alias audit log + event dispatch are skipped (no table/event system).
 */

import type { Context } from "hono";
import { Hono } from "hono";
import { type AppEnv, requireApiAuth } from "../lib/auth";
import { randomString, sanitizeEmail } from "../lib/crypto";
import { addDays, nowStr, toDate, toEpoch, toStr } from "../lib/dates";
import type { Env } from "../lib/env";
import { badRequest, forbidden, jsonError, notFound } from "../lib/errors";
import {
  availableSlEmail,
  FLAG_FREE_DISABLE_CREATE_CONTACTS,
  getAliasById,
  getContactById,
  userIsPremium,
} from "../lib/models";
import { rateLimit } from "../lib/ratelimit";
import type {
  AliasRow,
  ContactRow,
  EmailLogRow,
  MailboxRow,
  PublicDomainRow,
  UserRow,
} from "../lib/rows";
import {
  type AliasInfo,
  getAliasInfosWithPaginationV3,
  getAliasInfoV2,
  reverseAliasDisplay,
  serializeAliasInfo,
  serializeAliasInfoV2,
  serializeContact,
} from "../lib/serializer";

export const aliasRoutes = new Hono<AppEnv>();

const PAGE_LIMIT = 20; // config.PAGE_LIMIT

// AliasDeleteReason.ManualAction (models.py enum)
const REASON_MANUAL_ACTION = 2;
// UserAliasDeleteAction.DeleteImmediately
const DELETE_IMMEDIATELY = 1;
// config.ALIAS_TRASH_DAYS default (specs/08 §2)
const ALIAS_TRASH_DAYS = 30;
// Mailbox.FLAG_ADMIN_DISABLED
const MAILBOX_FLAG_ADMIN_DISABLED = 1;
// alias_mailbox_utils._MAX_MAILBOXES_PER_ALIAS
const MAX_MAILBOXES_PER_ALIAS = 20;

type Ctx = Context<AppEnv>;

// ---------------------------------------------------------------------------
// small parsing helpers (Python-compatible)
// ---------------------------------------------------------------------------

/** Python `int(request.args.get("page_id"))`: None/non-int -> null (=> 400). */
function parsePageId(raw: string | undefined): number | null {
  if (raw === undefined) return null;
  const t = raw.trim();
  if (!/^[+-]?\d+$/.test(t)) return null;
  return Number.parseInt(t, 10);
}

/** Python `int(x)` over JSON values: numbers truncate, bools are 0/1,
 * numeric strings parse; everything else is a failure (null). */
function pyInt(v: unknown): number | null {
  if (typeof v === "number") {
    if (!Number.isFinite(v)) return null;
    return Math.trunc(v);
  }
  if (typeof v === "boolean") return v ? 1 : 0;
  if (typeof v === "string") {
    const t = v.trim();
    if (/^[+-]?\d+$/.test(t)) return Number.parseInt(t, 10);
  }
  return null;
}

/** request.get_json(silent=True) + `data.get("query")` for the list routes. */
async function readQueryBody(c: Ctx): Promise<string | null> {
  let data: unknown;
  try {
    data = await c.req.json();
  } catch {
    return null;
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) return null;
  const q = (data as Record<string, unknown>).query;
  // Flask: `if query:` — falsy values are treated as no filter.
  return q ? String(q) : null;
}

/**
 * request.get_json() for mutation routes. Malformed JSON propagates as a
 * SyntaxError -> global 400 {"error": "Bad Request"} handler (like Flask's
 * BadRequest). Falsy or non-object JSON -> null (=> "request body cannot be
 * empty"; Flask 500s on non-dict truthy JSON — clean 4xx here).
 */
async function readBody(c: Ctx): Promise<Record<string, unknown> | null> {
  const data: unknown = await c.req.json();
  if (!data || typeof data !== "object" || Array.isArray(data)) return null;
  if (Object.keys(data as object).length === 0) return null; // {} is falsy in Python
  return data as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// v1 list — get_alias_infos_with_pagination + get_alias_info
// (lib only ships the v3 variant; this is the deprecated v1 query)
// ---------------------------------------------------------------------------

async function getAliasInfosV1(
  db: D1Database,
  user: UserRow,
  pageId: number,
  query: string | null,
): Promise<AliasInfo[]> {
  let sql = "SELECT * FROM alias WHERE user_id = ?1 AND delete_on IS NULL";
  const params: unknown[] = [user.id];
  if (query) {
    sql += " AND (email LIKE '%' || ?2 || '%' OR note LIKE '%' || ?2 || '%')";
    params.push(query);
  }
  sql += ` ORDER BY created_at DESC, id DESC LIMIT ${PAGE_LIMIT} OFFSET ?${params.length + 1}`;
  params.push(pageId * PAGE_LIMIT);

  const aliases = await db
    .prepare(sql)
    .bind(...params)
    .all<AliasRow>();

  const infos: AliasInfo[] = [];
  for (const alias of aliases.results) {
    // get_alias_info: counts over (Contact, EmailLog) joined via contact_id.
    const counts = await db
      .prepare(
        `SELECT
           SUM(CASE WHEN el.is_reply = 1 THEN 1 ELSE 0 END) AS nb_reply,
           SUM(CASE WHEN el.is_reply = 0 AND el.blocked = 1 THEN 1 ELSE 0 END) AS nb_blocked,
           SUM(CASE WHEN el.is_reply = 0 AND el.blocked = 0 THEN 1 ELSE 0 END) AS nb_forward
         FROM email_log el JOIN contact ct ON el.contact_id = ct.id
         WHERE ct.alias_id = ?1`,
      )
      .bind(alias.id)
      .first<{
        nb_reply: number | null;
        nb_blocked: number | null;
        nb_forward: number | null;
      }>();
    infos.push({
      alias,
      mailbox: { id: alias.mailbox_id, email: "" },
      mailboxes: [],
      nb_forward: counts?.nb_forward ?? 0,
      nb_blocked: counts?.nb_blocked ?? 0,
      nb_reply: counts?.nb_reply ?? 0,
      supportPgp: false,
      latestEmailLog: null,
      latestContact: null,
      senderFormat: user.sender_format,
    });
  }
  return infos;
}

// ---------------------------------------------------------------------------
// alias deletion — app/alias_delete.py
// ---------------------------------------------------------------------------

/** __delete_if_custom_domain: custom-domain aliases always hard-delete into
 * domain_deleted_alias (they are never soft-trashed). */
async function deleteIfCustomDomain(
  db: D1Database,
  alias: AliasRow,
  user: UserRow,
  reason: number,
): Promise<boolean> {
  if (!alias.custom_domain_id) return false;
  const existing = await db
    .prepare(
      "SELECT 1 FROM domain_deleted_alias WHERE email = ?1 AND domain_id = ?2 LIMIT 1",
    )
    .bind(alias.email, alias.custom_domain_id)
    .first();
  if (!existing) {
    await db
      .prepare(
        `INSERT INTO domain_deleted_alias (user_id, email, domain_id, reason, alias_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
      )
      .bind(
        user.id,
        alias.email,
        alias.custom_domain_id,
        reason,
        alias.id,
        nowStr(),
      )
      .run();
  }
  await db.prepare("DELETE FROM alias WHERE id = ?1").bind(alias.id).run();
  return true;
}

async function performAliasDeletion(
  db: D1Database,
  alias: AliasRow,
  user: UserRow,
  reason: number,
): Promise<void> {
  if (await deleteIfCustomDomain(db, alias, user, reason)) return;
  const existing = await db
    .prepare("SELECT 1 FROM deleted_alias WHERE email = ?1 LIMIT 1")
    .bind(alias.email)
    .first();
  if (!existing) {
    await db
      .prepare(
        "INSERT INTO deleted_alias (email, reason, alias_id, created_at) VALUES (?1, ?2, ?3, ?4)",
      )
      // Python `alias.delete_reason or reason` — 0 (Unspecified) also falls back
      .bind(alias.email, alias.delete_reason || reason, alias.id, nowStr())
      .run();
  }
  await db.prepare("DELETE FROM alias WHERE id = ?1").bind(alias.id).run();
}

async function moveAliasToTrash(
  db: D1Database,
  alias: AliasRow,
  user: UserRow,
  reason: number,
): Promise<void> {
  if (await deleteIfCustomDomain(db, alias, user, reason)) return;
  await db
    .prepare(
      "UPDATE alias SET delete_on = ?1, delete_reason = ?2, enabled = 0, updated_at = ?3 WHERE id = ?4",
    )
    .bind(
      toStr(addDays(new Date(), ALIAS_TRASH_DAYS)),
      reason,
      nowStr(),
      alias.id,
    )
    .run();
}

/** alias_delete.delete_alias: trash vs hard-delete decision. */
async function deleteAliasForUser(
  db: D1Database,
  alias: AliasRow,
  user: UserRow,
  reason: number,
): Promise<void> {
  if (
    alias.delete_on !== null ||
    user.alias_delete_action === DELETE_IMMEDIATELY
  ) {
    await performAliasDeletion(db, alias, user, reason);
  } else {
    await moveAliasToTrash(db, alias, user, reason);
  }
}

// ---------------------------------------------------------------------------
// contact creation — app/contact_utils.py + app/email_utils.py
// ---------------------------------------------------------------------------

const ALNUM_ALLOWED =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";

/** utils.convert_to_alphanumeric: disallowed chars become "_". */
function convertToAlphanumeric(s: string): string {
  let out = "";
  for (const ch of s) out += ALNUM_ALLOWED.includes(ch) ? ch : "_";
  return out;
}

/** utils.convert_to_id — lowercase, ASCII-fold (approximate unidecode via
 * NFKD + combining-mark strip), drop spaces, then alphanumeric[:64]. */
function convertToId(s: string): string {
  let t = s.toLowerCase();
  t = t.normalize("NFKD").replace(/[\u0300-\u036f]/g, "");
  t = [...t].filter((ch) => ch.charCodeAt(0) < 128).join("");
  t = t.replaceAll(" ", "");
  return convertToAlphanumeric(t).slice(0, 64);
}

/** email_utils.parse_full_address (flanker): "Name <a@b>" -> {name, email};
 * bare address -> {"", addr}; unparseable -> both "". */
function parseFullAddress(raw: string): { name: string; email: string } {
  const m = raw.match(/^\s*(.*?)\s*<([^<>]+)>\s*$/);
  if (m) {
    let name = m[1];
    if (name.length >= 2 && name.startsWith('"') && name.endsWith('"')) {
      name = name.slice(1, -1).trim();
    }
    return { name, email: m[2].trim() };
  }
  const trimmed = raw.trim();
  // flanker only accepts a bare addr-spec (no whitespace, no angle brackets)
  if (trimmed.includes("@") && !/[<>\s]/.test(trimmed)) {
    return { name: "", email: trimmed };
  }
  return { name: "", email: "" };
}

/** email_validation.is_valid_email — email_validator with
 * check_deliverability=False, allow_smtputf8=False (ASCII only, dotted
 * domain, no quoted local part). */
function isValidEmail(email: string): boolean {
  if (!email || email.length > 254) return false;
  for (const ch of email) if (ch.charCodeAt(0) > 127) return false;
  const at = email.indexOf("@");
  if (at <= 0 || at !== email.lastIndexOf("@")) return false;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (local.length > 64) return false;
  if (
    !/^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+(\.[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+)*$/.test(
      local,
    )
  ) {
    return false;
  }
  if (domain.length > 253) return false;
  if (
    !/^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/.test(
      domain,
    )
  ) {
    return false;
  }
  const tld = domain.split(".").pop() ?? "";
  if (/^\d+$/.test(tld)) return false;
  return true;
}

/** random.randint(min, max) — inclusive bounds. */
function randInt(min: number, max: number): number {
  return min + Math.floor(Math.random() * (max - min + 1));
}

/** email_utils.generate_reply_email — new-format reverse alias (no ra+). */
async function generateReplyEmail(
  db: D1Database,
  env: Env,
  contactEmail: string,
  alias: AliasRow,
  user: UserRow,
): Promise<string> {
  const includeSender = !!user.include_sender_in_reverse_alias;
  let senderPart = contactEmail;
  if (includeSender && senderPart) {
    senderPart = senderPart.replaceAll("@", "_at_").replaceAll(".", "_");
    senderPart = convertToId(senderPart);
    senderPart = sanitizeEmail(senderPart);
    senderPart = senderPart.slice(0, 45);
    senderPart = convertToAlphanumeric(senderPart);
  }

  let replyDomain = env.EMAIL_DOMAIN;
  const sanitized = sanitizeEmail(alias.email);
  const aliasDomain = sanitized.slice(sanitized.indexOf("@") + 1);
  const slDomain = await db
    .prepare("SELECT * FROM public_domain WHERE domain = ?1")
    .bind(aliasDomain)
    .first<PublicDomainRow>();
  if (slDomain?.use_as_reverse_alias) replyDomain = aliasDomain;

  for (let i = 0; i < 1000; i++) {
    const candidate =
      includeSender && senderPart
        ? `${senderPart}_${randomString(randInt(5, 10))}@${replyDomain}`
        : `${randomString(randInt(20, 50))}@${replyDomain}`;
    if (await availableSlEmail(db, candidate)) return candidate;
  }
  throw new Error("Cannot generate reply email");
}

/** User.can_create_contacts() (models.py L1276). */
async function canCreateContacts(
  db: D1Database,
  env: Env,
  user: UserRow,
): Promise<boolean> {
  if (await userIsPremium(db, user)) return true;
  if ((user.flags & FLAG_FREE_DISABLE_CREATE_CONTACTS) === 0) return true;
  // env.ts doesn't type this config knob; presence-based like the Flask
  // `os.environ.get(..., False)` (any non-empty string is truthy).
  const disabled = (env as unknown as Record<string, string | undefined>)
    .DISABLE_CREATE_CONTACTS_FOR_FREE_USERS;
  return !disabled;
}

/** Contact.last_reply(): latest is_reply email_log for the contact. */
function lastReply(
  db: D1Database,
  contactId: number,
): Promise<EmailLogRow | null> {
  return db
    .prepare(
      "SELECT * FROM email_log WHERE contact_id = ?1 AND is_reply = 1 ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(contactId)
    .first<EmailLogRow>();
}

/** __update_contact_if_needed (name only — mail_from is always null here). */
async function updateContactNameIfNeeded(
  db: D1Database,
  contact: ContactRow,
  name: string | null,
): Promise<ContactRow> {
  if (name && contact.name !== name) {
    await db
      .prepare("UPDATE contact SET name = ?1, updated_at = ?2 WHERE id = ?3")
      .bind(name, nowStr(), contact.id)
      .run();
    return { ...contact, name };
  }
  return contact;
}

// ---------------------------------------------------------------------------
// 1. GET|POST /aliases — deprecated v1 list (10/minute, keyed by user id)
// ---------------------------------------------------------------------------

aliasRoutes.on(
  ["GET", "POST"],
  "/aliases",
  requireApiAuth,
  rateLimit("get_aliases", "10/minute", "user"),
  async (c) => {
    const user = c.get("user");
    const pageId = parsePageId(c.req.query("page_id"));
    if (pageId === null) {
      return badRequest(c, "page_id must be provided in request query");
    }
    const query = await readQueryBody(c);
    const infos = await getAliasInfosV1(c.env.DB, user, pageId, query);
    return c.json({ aliases: infos.map(serializeAliasInfo) });
  },
);

// ---------------------------------------------------------------------------
// 2. GET|POST /v2/aliases — v2 list (50/minute, keyed by user id)
// ---------------------------------------------------------------------------

aliasRoutes.on(
  ["GET", "POST"],
  "/v2/aliases",
  requireApiAuth,
  rateLimit("get_aliases_v2", "50/minute", "user"),
  async (c) => {
    const user = c.get("user");
    const pageId = parsePageId(c.req.query("page_id"));
    if (pageId === null) {
      return badRequest(c, "page_id must be provided in request query");
    }
    // Presence-based flags: `"pinned" in request.args` (?pinned=false counts).
    // Precedence pinned > disabled > enabled is applied by the lib helper.
    const pinned = c.req.query("pinned") !== undefined;
    const disabled = c.req.query("disabled") !== undefined;
    const enabled = c.req.query("enabled") !== undefined;
    const query = await readQueryBody(c);

    const infos = await getAliasInfosWithPaginationV3(c.env.DB, user, pageId, {
      query,
      pinned,
      disabled,
      enabled,
    });
    return c.json({ aliases: infos.map(serializeAliasInfoV2) });
  },
);

// ---------------------------------------------------------------------------
// 3. GET /aliases/<int:alias_id> — one alias, v2 serialization
// ---------------------------------------------------------------------------

aliasRoutes.get("/aliases/:alias_id{[0-9]+}", requireApiAuth, async (c) => {
  const user = c.get("user");
  const alias = await getAliasById(c.env.DB, Number(c.req.param("alias_id")));
  if (!alias) return badRequest(c, "Unknown error"); // NOT 404 — faithful
  if (alias.user_id !== user.id) return forbidden(c);
  const info = await getAliasInfoV2(c.env.DB, alias, user);
  return c.json(serializeAliasInfoV2(info));
});

// ---------------------------------------------------------------------------
// 4. DELETE /aliases/<int:alias_id>
// ---------------------------------------------------------------------------

aliasRoutes.delete("/aliases/:alias_id{[0-9]+}", requireApiAuth, async (c) => {
  const user = c.get("user");
  const alias = await getAliasById(c.env.DB, Number(c.req.param("alias_id")));
  if (!alias || alias.user_id !== user.id) return forbidden(c);
  await deleteAliasForUser(c.env.DB, alias, user, REASON_MANUAL_ACTION);
  return c.json({ deleted: true });
});

// ---------------------------------------------------------------------------
// 5. POST /aliases/<int:alias_id>/toggle (100/hour, default key => IP)
// ---------------------------------------------------------------------------

aliasRoutes.post(
  "/aliases/:alias_id{[0-9]+}/toggle",
  requireApiAuth,
  rateLimit("toggle_alias", "100/hour", "default"),
  async (c) => {
    const user = c.get("user");
    const alias = await getAliasById(c.env.DB, Number(c.req.param("alias_id")));
    if (!alias || alias.user_id !== user.id) return forbidden(c);
    const newEnabled = alias.enabled ? 0 : 1;
    await c.env.DB.prepare(
      "UPDATE alias SET enabled = ?1, updated_at = ?2 WHERE id = ?3",
    )
      .bind(newEnabled, nowStr(), alias.id)
      .run();
    return c.json({ enabled: !!newEnabled });
  },
);

// ---------------------------------------------------------------------------
// 6. GET /aliases/<int:alias_id>/activities (30/minute, default key => IP)
// ---------------------------------------------------------------------------

interface ActivityRow {
  el_id: number;
  el_created_at: string;
  is_reply: number;
  blocked: number;
  bounced: number;
  website_email: string;
  contact_name: string | null;
  website_from: string | null;
  reply_email: string;
}

aliasRoutes.get(
  "/aliases/:alias_id{[0-9]+}/activities",
  requireApiAuth,
  rateLimit("get_alias_activities", "30/minute", "default"),
  async (c) => {
    const user = c.get("user");
    const pageId = parsePageId(c.req.query("page_id"));
    if (pageId === null) {
      return badRequest(c, "page_id must be provided in request query");
    }
    const alias = await getAliasById(c.env.DB, Number(c.req.param("alias_id")));
    if (!alias || alias.user_id !== user.id) return forbidden(c);

    // get_alias_log: page by email_log.id DESC, then re-sort by created_at
    // DESC (stable, so id-desc order is kept for equal timestamps).
    const rows = await c.env.DB.prepare(
      `SELECT el.id AS el_id, el.created_at AS el_created_at, el.is_reply,
              el.blocked, el.bounced, ct.website_email,
              ct.name AS contact_name, ct.website_from, ct.reply_email
       FROM email_log el JOIN contact ct ON ct.id = el.contact_id
       WHERE ct.alias_id = ?1
       ORDER BY el.id DESC LIMIT ${PAGE_LIMIT} OFFSET ?2`,
    )
      .bind(alias.id, pageId * PAGE_LIMIT)
      .all<ActivityRow>();

    const sorted = [...rows.results].sort(
      (a, b) =>
        toDate(b.el_created_at).getTime() - toDate(a.el_created_at).getTime(),
    );

    const activities = sorted.map((r) => {
      const contactish = {
        website_email: r.website_email,
        name: r.contact_name,
        website_from: r.website_from,
        reply_email: r.reply_email,
      } as ContactRow;
      const activity: Record<string, unknown> = {
        timestamp: toEpoch(r.el_created_at),
        reverse_alias: reverseAliasDisplay(contactish, user.sender_format),
        reverse_alias_address: r.reply_email,
      };
      if (r.is_reply) {
        activity.from = alias.email;
        activity.to = r.website_email;
        activity.action = "reply";
      } else {
        activity.to = alias.email;
        activity.from = r.website_email;
        activity.action = r.bounced
          ? "bounced"
          : r.blocked
            ? "block"
            : "forward";
      }
      return activity;
    });

    return c.json({ activities });
  },
);

// ---------------------------------------------------------------------------
// 7. PUT|PATCH /aliases/<int:alias_id> — update alias
// ---------------------------------------------------------------------------

aliasRoutes.on(
  ["PUT", "PATCH"],
  "/aliases/:alias_id{[0-9]+}",
  requireApiAuth,
  async (c) => {
    const data = await readBody(c);
    if (!data) return badRequest(c, "request body cannot be empty");

    const user = c.get("user");
    const db = c.env.DB;
    const alias = await getAliasById(db, Number(c.req.param("alias_id")));
    if (!alias || alias.user_id !== user.id) return forbidden(c);

    // Field-presence driven, processed in Flask's order; all writes are
    // deferred to the end so an error mid-way leaves nothing changed (Flask
    // achieves the same via session rollback on early return).
    const updates: Record<string, unknown> = {};
    let newMailboxes: MailboxRow[] | null = null;

    if (Object.hasOwn(data, "note")) {
      updates.note = data.note ?? null;
    }

    if (Object.hasOwn(data, "mailbox_id")) {
      const mailboxId = pyInt(data.mailbox_id);
      // Flask 500s on non-numeric input; clean 400 here.
      if (mailboxId === null) return badRequest(c, "Invalid mailbox_id");
      const mailbox = await db
        .prepare("SELECT * FROM mailbox WHERE id = ?1")
        .bind(mailboxId)
        .first<MailboxRow>();
      if (!mailbox || mailbox.user_id !== user.id || !mailbox.verified) {
        // status 400 with body "Forbidden" — faithful oddity
        return jsonError(c, 400, "Forbidden");
      }
      updates.mailbox_id = mailboxId;
    }

    if (Object.hasOwn(data, "mailbox_ids")) {
      const rawIds = data.mailbox_ids;
      if (!Array.isArray(rawIds)) return badRequest(c, "Invalid mailbox_id");
      const mailboxIds: number[] = [];
      for (const rawId of rawIds) {
        const parsed = pyInt(rawId);
        if (parsed === null) return badRequest(c, "Invalid mailbox_id");
        mailboxIds.push(parsed);
      }

      // set_mailboxes_for_alias (app/alias_mailbox_utils.py)
      if (mailboxIds.length === 0) {
        return badRequest(c, "Must choose at least one mailbox");
      }
      if (mailboxIds.length > MAX_MAILBOXES_PER_ALIAS) {
        return badRequest(c, "Too many mailboxes");
      }
      const placeholders = mailboxIds.map((_, i) => `?${i + 2}`).join(", ");
      const found = await db
        .prepare(
          `SELECT * FROM mailbox WHERE id IN (${placeholders})
           AND user_id = ?1 AND verified = 1 ORDER BY id ASC`,
        )
        .bind(user.id, ...mailboxIds)
        .all<MailboxRow>();
      if (found.results.length !== mailboxIds.length) {
        return badRequest(c, "Forbidden");
      }
      for (const mb of found.results) {
        if (mb.flags & MAILBOX_FLAG_ADMIN_DISABLED) {
          return badRequest(c, "Forbidden");
        }
      }
      newMailboxes = found.results;
      // primary mailbox becomes the LOWEST-id one (id-ASC order, not request order)
      updates.mailbox_id = newMailboxes[0].id;
    }

    if (Object.hasOwn(data, "name")) {
      const rawName = data.name;
      let newName: string | null = rawName == null ? null : String(rawName);
      if (newName && newName.length > 128) {
        return badRequest(c, "Name can't be longer than 128 characters");
      }
      if (newName) newName = newName.replaceAll("\n", "");
      updates.name = newName;
    }

    if (Object.hasOwn(data, "disable_pgp")) {
      updates.disable_pgp = data.disable_pgp ? 1 : 0;
    }

    if (Object.hasOwn(data, "pinned")) {
      updates.pinned = data.pinned ? 1 : 0;
    }

    // apply
    if (newMailboxes) {
      await db
        .prepare("DELETE FROM alias_mailbox WHERE alias_id = ?1")
        .bind(alias.id)
        .run();
      for (const mb of newMailboxes.slice(1)) {
        await db
          .prepare(
            "INSERT INTO alias_mailbox (alias_id, mailbox_id, created_at) VALUES (?1, ?2, ?3)",
          )
          .bind(alias.id, mb.id, nowStr())
          .run();
      }
    }
    const cols = Object.keys(updates);
    if (cols.length > 0) {
      const assignments = cols.map((col, i) => `${col} = ?${i + 1}`).join(", ");
      await db
        .prepare(
          `UPDATE alias SET ${assignments}, updated_at = ?${cols.length + 1} WHERE id = ?${cols.length + 2}`,
        )
        .bind(...cols.map((col) => updates[col]), nowStr(), alias.id)
        .run();
    }

    return c.json({ ok: true });
  },
);

// ---------------------------------------------------------------------------
// 8. GET /aliases/<int:alias_id>/contacts
// ---------------------------------------------------------------------------

aliasRoutes.get(
  "/aliases/:alias_id{[0-9]+}/contacts",
  requireApiAuth,
  async (c) => {
    const user = c.get("user");
    const pageId = parsePageId(c.req.query("page_id"));
    if (pageId === null) {
      return badRequest(c, "page_id must be provided in request query");
    }
    const alias = await getAliasById(c.env.DB, Number(c.req.param("alias_id")));
    if (!alias) return notFound(c, "No such alias");
    if (alias.user_id !== user.id) return forbidden(c);

    const contacts = await c.env.DB.prepare(
      `SELECT * FROM contact WHERE alias_id = ?1 ORDER BY id DESC LIMIT ${PAGE_LIMIT} OFFSET ?2`,
    )
      .bind(alias.id, pageId * PAGE_LIMIT)
      .all<ContactRow>();

    const serialized: Record<string, unknown>[] = [];
    for (const contact of contacts.results) {
      const reply = await lastReply(c.env.DB, contact.id);
      serialized.push(serializeContact(contact, false, user, reply));
    }
    return c.json({ contacts: serialized });
  },
);

// ---------------------------------------------------------------------------
// 9. POST /aliases/<int:alias_id>/contacts — create contact
// ---------------------------------------------------------------------------

aliasRoutes.post(
  "/aliases/:alias_id{[0-9]+}/contacts",
  requireApiAuth,
  async (c) => {
    const data = await readBody(c);
    if (!data) return badRequest(c, "request body cannot be empty");

    const user = c.get("user");
    const db = c.env.DB;
    const alias = await db
      .prepare("SELECT * FROM alias WHERE id = ?1 AND user_id = ?2")
      .bind(Number(c.req.param("alias_id")), user.id)
      .first<AliasRow>();
    if (!alias) return forbidden(c);

    const contactAddress = data.contact ? String(data.contact) : "";
    if (!contactAddress) {
      // ErrAddressInvalid("Empty address")
      return badRequest(c, "Empty address is not a valid email address");
    }

    if (!(await canCreateContacts(db, c.env, user))) {
      return jsonError(
        c,
        403,
        "Please upgrade to premium to create reverse-alias",
      );
    }

    const parsed = parseFullAddress(contactAddress);
    // contact_utils: name from the parsed display name, truncated to 512.
    let name: string | null = parsed.name.slice(0, 512);
    if (!name) name = null;
    if (name?.includes("\x00")) name = "";

    // sanitize_email(not_lower=True): stored website_email preserves case
    const email = sanitizeEmail(parsed.email, true);
    if (!isValidEmail(email)) {
      // error message carries the ORIGINAL body value
      return badRequest(c, `${contactAddress} is not a valid email address`);
    }

    const existing = await db
      .prepare(
        "SELECT * FROM contact WHERE alias_id = ?1 AND website_email = ?2",
      )
      .bind(alias.id, email)
      .first<ContactRow>();
    if (existing) {
      const updated = await updateContactNameIfNeeded(db, existing, name);
      const reply = await lastReply(db, updated.id);
      return c.json(serializeContact(updated, true, user, reply), 200);
    }

    // Contact.create guard: website_email must not be another contact's
    // reverse alias (compared lowercased, NOREPLIES excepted) -> the API
    // surfaces it as an invalid-address 400 (contact_utils maps the error).
    const lowered = sanitizeEmail(email);
    if (lowered !== `noreply@${c.env.EMAIL_DOMAIN}`) {
      const clash = await db
        .prepare("SELECT 1 FROM contact WHERE reply_email = ?1 LIMIT 1")
        .bind(lowered)
        .first();
      if (clash) {
        return badRequest(c, `${contactAddress} is not a valid email address`);
      }
    }

    const replyEmail = await generateReplyEmail(db, c.env, email, alias, user);

    let contact: ContactRow | null = null;
    try {
      contact = await db
        .prepare(
          `INSERT INTO contact (user_id, alias_id, website_email, name, reply_email,
             mail_from, automatic_created, flags, invalid_email, created_at)
           VALUES (?1, ?2, ?3, ?4, ?5, NULL, 0, 0, ?6, ?7) RETURNING *`,
        )
        .bind(
          alias.user_id,
          alias.id,
          email,
          name,
          replyEmail,
          email === "" ? 1 : 0,
          nowStr(),
        )
        .first<ContactRow>();
    } catch (e) {
      // IntegrityError path: unique (alias_id, website_email) race
      if (!(e instanceof Error) || !e.message.includes("UNIQUE constraint")) {
        throw e;
      }
      const raced = await db
        .prepare(
          "SELECT * FROM contact WHERE alias_id = ?1 AND website_email = ?2",
        )
        .bind(alias.id, email)
        .first<ContactRow>();
      if (raced) {
        const updated = await updateContactNameIfNeeded(db, raced, name);
        const reply = await lastReply(db, updated.id);
        return c.json(serializeContact(updated, true, user, reply), 200);
      }
      // ContactCreateError.Unknown -> ErrAddressInvalid("Invalid address")
      return badRequest(c, "Invalid address is not a valid email address");
    }
    if (!contact) {
      return badRequest(c, "Invalid address is not a valid email address");
    }

    return c.json(serializeContact(contact, false, user, null), 201);
  },
);

// ---------------------------------------------------------------------------
// 10. DELETE /contacts/<int:contact_id> + POST /contacts/<int:contact_id>/toggle
// ---------------------------------------------------------------------------

/** Ownership is checked via the contact's ALIAS owner (contact.alias.user_id). */
async function getOwnedContact(
  c: Ctx,
): Promise<{ contact: ContactRow; alias: AliasRow } | null> {
  const contact = await getContactById(
    c.env.DB,
    Number(c.req.param("contact_id")),
  );
  if (!contact) return null;
  const alias = await getAliasById(c.env.DB, contact.alias_id);
  if (!alias || alias.user_id !== c.get("user").id) return null;
  return { contact, alias };
}

aliasRoutes.delete(
  "/contacts/:contact_id{[0-9]+}",
  requireApiAuth,
  async (c) => {
    const owned = await getOwnedContact(c);
    if (!owned) return forbidden(c);
    await c.env.DB.prepare("DELETE FROM contact WHERE id = ?1")
      .bind(owned.contact.id)
      .run();
    return c.json({ deleted: true });
  },
);

aliasRoutes.post(
  "/contacts/:contact_id{[0-9]+}/toggle",
  requireApiAuth,
  async (c) => {
    const owned = await getOwnedContact(c);
    if (!owned) return forbidden(c);
    const newBlocked = owned.contact.block_forward ? 0 : 1;
    await c.env.DB.prepare(
      "UPDATE contact SET block_forward = ?1, updated_at = ?2 WHERE id = ?3",
    )
      .bind(newBlocked, nowStr(), owned.contact.id)
      .run();
    return c.json({ block_forward: !!newBlocked });
  },
);
