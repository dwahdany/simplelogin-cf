/**
 * Alias-centric dashboard pages (specs/web/02-alias-pages.md):
 *
 *   1. GET|POST /dashboard/                                — alias list
 *   2. POST     /dashboard/contacts/<id>/toggle            — htmx block toggle
 *   3. GET|POST /dashboard/custom_alias                    — new custom alias
 *   4. GET      /dashboard/alias_log/<id>[/<page>]         — activity
 *   5. GET      /dashboard/alias_export                    — CSV (sudo)
 *   6. GET|POST /dashboard/alias_transfer/send/<id>        — transfer (sudo)
 *   7. GET|POST /dashboard/alias_transfer/receive          — transfer accept
 *   8. GET|POST /dashboard/alias_contact_manager/<id>      — contacts
 *   9. GET|POST /dashboard/contact/<id>                    — contact PGP page
 *
 * Flash strings, redirect targets and form field names are byte-exact with
 * the Flask app. Some helpers are duplicated from src/routes/* because they
 * are module-private there and this module must not modify shared files.
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha3_224 } from "@noble/hashes/sha3.js";
import type { Context } from "hono";
import { Hono } from "hono";
import {
  randomWords,
  sanitizeEmail,
  timestampSign,
  timestampUnsign,
  tokenUrlsafe,
} from "../lib/crypto";
import { addDays, nowStr, toDate, toStr } from "../lib/dates";
import type { Env } from "../lib/env";
import { sendTransactionalEmail } from "../lib/mailer";
import {
  availableSlEmail,
  canCreateNewAlias,
  defaultRandomAliasDomain,
  FLAG_FREE_DISABLE_CREATE_CONTACTS,
  getContactById,
  getMailboxById,
  getSLDomains,
  userInTrial,
  userIsPremium,
} from "../lib/models";
import type {
  AliasRow,
  ContactRow,
  CustomDomainRow,
  EmailLogRow,
  MailboxRow,
  PublicDomainRow,
  UserRow,
} from "../lib/rows";
import { reverseAliasDisplay } from "../lib/serializer";
import {
  csrfTokenField,
  generateCsrfToken,
  makeField,
  validateCsrfToken,
} from "../lib/web/forms";
import {
  buildCurrentUser,
  type FlashCategory,
  flash,
  renderErrorPage,
  webRender,
} from "../lib/web/render";
import { renderTemplate } from "../lib/web/templates";
import { urlFor } from "../lib/web/urls";
import {
  requireWebLogin,
  requireWebSudo,
  type WebEnv,
} from "../lib/web/webauth";

export const webAliasPagesRoutes = new Hono<WebEnv>();

type Ctx = Context<WebEnv>;

const PAGE_LIMIT = 20;
const MAILBOX_FLAG_ADMIN_DISABLED = 1;
const ALIAS_TRASH_DAYS = 30;
const DELETE_IMMEDIATELY = 1; // UserAliasDeleteAction.DeleteImmediately
const REASON_MANUAL_ACTION = 2; // AliasDeleteReason.ManualAction
const AliasGenerator = { word: 1, uuid: 2 } as const;

// env knobs not part of the typed Env contract
function envStr(env: Env, key: string): string | undefined {
  return (env as unknown as Record<string, string | undefined>)[key];
}

// ---------------------------------------------------------------------------
// small request helpers
// ---------------------------------------------------------------------------

/** Python int(str) — trimmed, optional sign, digits only. */
function pyInt(v: string | undefined | null): number | null {
  if (v === undefined || v === null) return null;
  const t = v.trim();
  if (!/^[+-]?\d+$/.test(t)) return null;
  return Number.parseInt(t, 10);
}

/** Flask redirect(request.url) equivalent (path + query string). */
function reqUrl(c: Ctx): string {
  const url = new URL(c.req.url);
  return url.pathname + url.search;
}

type FormBody = Record<string, unknown>;

async function readForm(c: Ctx): Promise<FormBody> {
  try {
    return await c.req.parseBody({ all: true });
  } catch {
    return {};
  }
}

/** request.form.get(key) — first value, strings only. */
function formGet(body: FormBody, key: string): string | undefined {
  const v = body[key];
  if (typeof v === "string") return v;
  if (Array.isArray(v) && typeof v[0] === "string") return v[0] as string;
  return undefined;
}

/** request.form.getlist(key). */
function formGetList(body: FormBody, key: string): string[] {
  const v = body[key];
  if (typeof v === "string") return [v];
  if (Array.isArray(v))
    return v.filter((x): x is string => typeof x === "string");
  return [];
}

/** csrf_form.validate() — true when the submitted token is valid. */
async function csrfOk(c: Ctx, body: FormBody): Promise<boolean> {
  const err = await validateCsrfToken(
    c,
    formGet(body, "csrf_token") ?? null,
    c.get("webSession"),
  );
  return err === null;
}

async function csrfFormCtx(c: Ctx): Promise<{ csrf_token: unknown }> {
  const token = await generateCsrfToken(c);
  return { csrf_token: csrfTokenField(token) };
}

/** User.mailboxes(): verified mailboxes, insertion order. */
async function verifiedMailboxes(
  db: D1Database,
  userId: number,
): Promise<MailboxRow[]> {
  const res = await db
    .prepare(
      "SELECT * FROM mailbox WHERE user_id = ?1 AND verified = 1 ORDER BY id",
    )
    .bind(userId)
    .all<MailboxRow>();
  return res.results;
}

function isAdminDisabled(mb: MailboxRow): boolean {
  return (mb.flags & MAILBOX_FLAG_ADMIN_DISABLED) !== 0;
}

// ---------------------------------------------------------------------------
// email validation (email_validator approximation, duplicated from routes)
// ---------------------------------------------------------------------------

const LOCAL_PART_RE =
  /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+(?:\.[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+)*$/;
const DOMAIN_LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

function isValidEmail(email: string): boolean {
  if (!email || email.length > 254) return false;
  for (const ch of email) if (ch.charCodeAt(0) > 127) return false;
  const at = email.indexOf("@");
  if (at <= 0 || at !== email.lastIndexOf("@")) return false;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (local.length > 64 || !LOCAL_PART_RE.test(local)) return false;
  if (domain.length > 253) return false;
  const labels = domain.split(".");
  if (labels.length < 2) return false;
  for (const label of labels) if (!DOMAIN_LABEL_RE.test(label)) return false;
  if (!/[A-Za-z]/.test(labels[labels.length - 1])) return false;
  return true;
}

/** email_validator.validate_email raising — returns the flashable message.
 * Messages and check order mirror email-validator 2.2.0 (pinned by Flask):
 * local-part checks run before domain checks, and within the local part:
 * empty -> too long -> dot-atom -> trailing dot -> leading dot -> "..". */
function validateEmailMessage(email: string): string | null {
  const at = email.indexOf("@");
  if (at === -1) return "An email address must have an @-sign.";
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (local.length === 0) return "There must be something before the @-sign.";
  if (local.length > 64) {
    const over = local.length - 64;
    return `The email address is too long before the @-sign (${over} character${over === 1 ? "" : "s"} too many).`;
  }
  if (!LOCAL_PART_RE.test(local)) {
    if (local.endsWith(".")) {
      return "An email address cannot have a period immediately before the @-sign.";
    }
    if (local.startsWith(".")) {
      return "An email address cannot start with a period.";
    }
    if (local.includes("..")) {
      return "An email address cannot have two periods in a row.";
    }
    return "The email address contains invalid characters before the @-sign.";
  }
  if (domain.length === 0) return "There must be something after the @-sign.";
  // Remaining (domain-side) failures are unreachable from the custom-alias
  // flow: suffixes come from verified domains.
  if (!isValidEmail(email)) return "The email address is not valid.";
  return null;
}

// ---------------------------------------------------------------------------
// alias listing view-model (web-only sorts/filters over the v3 query)
// ---------------------------------------------------------------------------

interface MailboxLite {
  id: number;
  email: string;
}

interface WebAliasInfo {
  alias: AliasRow;
  mailbox: MailboxLite | null;
  mailboxes: MailboxLite[];
  mailbox_ids: number[];
  has_admin_disabled_mailbox: boolean;
  nb_forward: number;
  nb_blocked: number;
  nb_reply: number;
  support_pgp: boolean;
  pgp_enabled: boolean;
  latest_email_log: EmailLogRow | null;
  latest_contact: ContactRow | null;
  nb_hibp_breaches: number;
  custom_domain: {
    name: string | null;
    verified: boolean;
    trash_url: string;
  } | null;
}

interface AliasPageOpts {
  query?: string;
  sort?: string;
  mailboxId?: number | null;
  directoryId?: number | null;
  filter?: string;
  aliasId?: number | null;
  limit: number;
  offset: number;
}

async function fetchWebAliasInfos(
  db: D1Database,
  env: Env,
  user: UserRow,
  opts: AliasPageOpts,
): Promise<WebAliasInfo[]> {
  const conds: string[] = [];
  const params: unknown[] = [];

  if (opts.query) {
    conds.push(
      "(a.email LIKE '%' || ? || '%' OR a.note LIKE '%' || ? || '%' OR a.name LIKE '%' || ? || '%')",
    );
    params.push(opts.query, opts.query, opts.query);
  }
  if (opts.filter === "pinned") conds.push("a.pinned = 1");
  else if (opts.filter === "disabled") conds.push("a.enabled = 0");
  else if (opts.filter === "enabled") conds.push("a.enabled = 1");
  else if (opts.filter === "hibp") {
    conds.push("EXISTS (SELECT 1 FROM alias_hibp ah WHERE ah.alias_id = a.id)");
  }
  // Python `if mailbox_id:` / `if directory_id:` — id 0 is falsy and skips
  // the filter entirely (serializer.py get_alias_infos_with_pagination_v3).
  if (opts.mailboxId) {
    conds.push(
      "(a.mailbox_id = ? OR EXISTS (SELECT 1 FROM alias_mailbox am WHERE am.alias_id = a.id AND am.mailbox_id = ?))",
    );
    params.push(opts.mailboxId, opts.mailboxId);
  }
  if (opts.directoryId) {
    conds.push("a.directory_id = ?");
    params.push(opts.directoryId);
  }
  if (opts.aliasId != null) {
    conds.push("a.id = ?");
    params.push(opts.aliasId);
  }
  const whereExtra = conds.length ? ` AND ${conds.join(" AND ")}` : "";

  let orderBy: string;
  switch (opts.sort) {
    case "old2new":
      orderBy = "a.created_at ASC";
      break;
    case "new2old":
      orderBy = "a.created_at DESC";
      break;
    case "a2z":
      orderBy = "a.email ASC";
      break;
    case "z2a":
      orderBy = "a.email DESC";
      break;
    default:
      orderBy =
        "a.pinned DESC, MAX(a.created_at, IFNULL(el.created_at, a.created_at)) DESC, a.id DESC";
  }

  const sql = `
    SELECT a.*,
           sub.nb_reply AS _nb_reply,
           sub.nb_blocked AS _nb_blocked,
           sub.nb_forward AS _nb_forward
    FROM alias a
    JOIN (
      SELECT alias.id AS aid,
        SUM(CASE WHEN email_log.is_reply = 1 THEN 1 ELSE 0 END) AS nb_reply,
        SUM(CASE WHEN email_log.is_reply = 0 AND email_log.blocked = 1 THEN 1 ELSE 0 END) AS nb_blocked,
        SUM(CASE WHEN email_log.is_reply = 0 AND email_log.blocked = 0 THEN 1 ELSE 0 END) AS nb_forward
      FROM alias LEFT OUTER JOIN email_log ON alias.id = email_log.alias_id
      WHERE alias.user_id = ? AND alias.delete_on IS NULL
      GROUP BY alias.id
    ) sub ON a.id = sub.aid
    LEFT OUTER JOIN email_log el ON a.last_email_log_id = el.id
    WHERE 1 = 1${whereExtra}
    ORDER BY ${orderBy}
    LIMIT ? OFFSET ?`;

  const rows = await db
    .prepare(sql)
    .bind(user.id, ...params, opts.limit, opts.offset)
    .all<
      AliasRow & { _nb_reply: number; _nb_blocked: number; _nb_forward: number }
    >();
  if (rows.results.length === 0) return [];

  const aliasIds = rows.results.map((r) => r.id);
  const ph = aliasIds.map((_, i) => `?${i + 1}`).join(", ");

  // alias_mailbox additional mailboxes
  const amRes = await db
    .prepare(
      `SELECT alias_id, mailbox_id FROM alias_mailbox WHERE alias_id IN (${ph}) ORDER BY id`,
    )
    .bind(...aliasIds)
    .all<{ alias_id: number; mailbox_id: number }>();
  const additionalByAlias = new Map<number, number[]>();
  for (const r of amRes.results) {
    const list = additionalByAlias.get(r.alias_id) ?? [];
    list.push(r.mailbox_id);
    additionalByAlias.set(r.alias_id, list);
  }

  const allMailboxIds = new Set<number>();
  for (const r of rows.results) allMailboxIds.add(r.mailbox_id);
  for (const list of additionalByAlias.values())
    for (const id of list) allMailboxIds.add(id);
  const mbMap = new Map<number, MailboxRow>();
  if (allMailboxIds.size > 0) {
    const ids = [...allMailboxIds];
    const mph = ids.map((_, i) => `?${i + 1}`).join(", ");
    const res = await db
      .prepare(`SELECT * FROM mailbox WHERE id IN (${mph})`)
      .bind(...ids)
      .all<MailboxRow>();
    for (const m of res.results) mbMap.set(m.id, m);
  }

  // hibp breach counts
  const hibpRes = await db
    .prepare(
      `SELECT alias_id, COUNT(*) AS n FROM alias_hibp WHERE alias_id IN (${ph}) GROUP BY alias_id`,
    )
    .bind(...aliasIds)
    .all<{ alias_id: number; n: number }>()
    .catch(() => ({ results: [] as Array<{ alias_id: number; n: number }> }));
  const hibpMap = new Map<number, number>();
  for (const r of hibpRes.results) hibpMap.set(r.alias_id, r.n);

  // custom domains
  const cdIds = [
    ...new Set(
      rows.results
        .map((r) => r.custom_domain_id)
        .filter((v): v is number => v !== null),
    ),
  ];
  const cdMap = new Map<number, CustomDomainRow>();
  if (cdIds.length > 0) {
    const cph = cdIds.map((_, i) => `?${i + 1}`).join(", ");
    const res = await db
      .prepare(`SELECT * FROM custom_domain WHERE id IN (${cph})`)
      .bind(...cdIds)
      .all<CustomDomainRow>();
    for (const cd of res.results) cdMap.set(cd.id, cd);
  }

  // latest email logs + contacts
  const logIds = [
    ...new Set(
      rows.results
        .map((r) => r.last_email_log_id)
        .filter((v): v is number => v !== null),
    ),
  ];
  const logMap = new Map<number, EmailLogRow>();
  if (logIds.length > 0) {
    const lph = logIds.map((_, i) => `?${i + 1}`).join(", ");
    const res = await db
      .prepare(`SELECT * FROM email_log WHERE id IN (${lph})`)
      .bind(...logIds)
      .all<EmailLogRow>();
    for (const l of res.results) logMap.set(l.id, l);
  }
  const contactIds = [
    ...new Set([...logMap.values()].map((l) => l.contact_id)),
  ];
  const contactMap = new Map<number, ContactRow>();
  if (contactIds.length > 0) {
    const cph = contactIds.map((_, i) => `?${i + 1}`).join(", ");
    const res = await db
      .prepare(`SELECT * FROM contact WHERE id IN (${cph})`)
      .bind(...contactIds)
      .all<ContactRow>();
    for (const ct of res.results) contactMap.set(ct.id, ct);
  }

  return rows.results.map((row) => {
    const { _nb_reply, _nb_blocked, _nb_forward, ...aliasCols } = row;
    const alias = aliasCols as AliasRow;

    const ids = [alias.mailbox_id];
    for (const id of additionalByAlias.get(alias.id) ?? [])
      if (!ids.includes(id)) ids.push(id);
    const verified = ids
      .map((id) => mbMap.get(id))
      .filter((m): m is MailboxRow => !!m && !!m.verified)
      .sort((a, b) => (a.email < b.email ? -1 : a.email > b.email ? 1 : 0));
    const supportPgp = verified.some(
      (m) => !!m.pgp_finger_print && !m.disable_pgp,
    );

    const primary = mbMap.get(alias.mailbox_id) ?? null;
    const latestEmailLog = alias.last_email_log_id
      ? (logMap.get(alias.last_email_log_id) ?? null)
      : null;
    const latestContact = latestEmailLog
      ? (contactMap.get(latestEmailLog.contact_id) ?? null)
      : null;
    const cd = alias.custom_domain_id
      ? (cdMap.get(alias.custom_domain_id) ?? null)
      : null;

    return {
      alias,
      mailbox: primary ? { id: primary.id, email: primary.email } : null,
      mailboxes: verified.map((m) => ({ id: m.id, email: m.email })),
      mailbox_ids: verified.map((m) => m.id),
      has_admin_disabled_mailbox: verified.some(isAdminDisabled),
      nb_forward: _nb_forward,
      nb_blocked: _nb_blocked,
      nb_reply: _nb_reply,
      support_pgp: supportPgp,
      pgp_enabled: supportPgp && !alias.disable_pgp,
      latest_email_log: latestEmailLog,
      latest_contact: latestContact,
      nb_hibp_breaches: hibpMap.get(alias.id) ?? 0,
      custom_domain: cd
        ? {
            name: cd.name ?? null,
            verified: !!cd.verified,
            trash_url: `${env.URL}/dashboard/domains/${cd.id}/trash`,
          }
        : null,
    };
  });
}

// ---------------------------------------------------------------------------
// alias delete/trash (duplicated from src/routes/aliases.ts — module-private)
// ---------------------------------------------------------------------------

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

/** alias_delete.delete_alias — trash vs hard-delete decision. */
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
// alias creation helpers (duplicated from src/routes/alias-creation.ts)
// ---------------------------------------------------------------------------

class BucketRateLimitError extends Error {}
class AliasInTrashError extends Error {}

const ALIAS_CREATE_RATE_LIMIT_FREE: ReadonlyArray<readonly [number, number]> = [
  [10, 900],
  [50, 3600],
];
const ALIAS_CREATE_RATE_LIMIT_PAID: ReadonlyArray<readonly [number, number]> = [
  [50, 900],
  [200, 3600],
];

function customAliasSecret(env: Env): string {
  return `${env.FLASK_SECRET}custom_alias`;
}

async function checkBucketLimits(
  db: D1Database,
  env: Env,
  user: UserRow,
): Promise<void> {
  if (env.DISABLE_RATE_LIMIT !== undefined) return;
  const now = new Date();
  const premium = await userIsPremium(db, user, now);
  const trial = await userInTrial(db, user, now);
  const limits =
    premium && !trial
      ? ALIAS_CREATE_RATE_LIMIT_PAID
      : ALIAS_CREATE_RATE_LIMIT_FREE;
  const nowSec = Math.floor(now.getTime() / 1000);
  for (const [maxHits, bucketSeconds] of limits) {
    const bucketId = nowSec - (nowSec % bucketSeconds);
    const key = `bl:alias_create_${bucketSeconds}:${user.id}:${bucketId}`;
    const row = await db
      .prepare(
        `INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, 1)
         ON CONFLICT(key) DO UPDATE SET count = count + 1 RETURNING count`,
      )
      .bind(key, bucketId)
      .first<{ count: number }>();
    if ((row?.count ?? 1) > maxHits) throw new BucketRateLimitError();
  }
}

async function getCustomDomainForEmail(
  db: D1Database,
  email: string,
): Promise<CustomDomainRow | null> {
  const domain = email.slice(email.lastIndexOf("@") + 1).toLowerCase();
  const sl = await db
    .prepare("SELECT 1 FROM public_domain WHERE domain = ?1 LIMIT 1")
    .bind(domain)
    .first();
  if (sl) return null;
  return db
    .prepare("SELECT * FROM custom_domain WHERE domain = ?1 LIMIT 1")
    .bind(domain)
    .first<CustomDomainRow>();
}

interface NewAliasInput {
  email: string;
  mailboxId: number | null;
  note: string | null;
}

/** Alias.create — bucket limits, trash check, custom-domain detection, insert. */
async function insertAliasWeb(
  db: D1Database,
  env: Env,
  user: UserRow,
  input: NewAliasInput,
): Promise<AliasRow> {
  await checkBucketLimits(db, env, user);

  const sanitized = sanitizeEmail(input.email);
  const trashed = await db
    .prepare(
      `SELECT 1 AS x FROM deleted_alias WHERE email = ?1
       UNION SELECT 1 FROM domain_deleted_alias WHERE email = ?1 LIMIT 1`,
    )
    .bind(sanitized)
    .first();
  if (trashed) throw new AliasInTrashError(sanitized);

  const customDomain = await getCustomDomainForEmail(db, sanitized);
  let customDomainId: number | null = null;
  if (customDomain) {
    if (customDomain.user_id !== user.id) {
      throw new Error(`alias domain ${customDomain.domain} is forbidden`);
    }
    customDomainId = customDomain.id;
  }

  const row = await db
    .prepare(
      `INSERT INTO alias (user_id, email, note, mailbox_id, custom_domain_id, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6) RETURNING *`,
    )
    .bind(
      user.id,
      input.email,
      input.note,
      input.mailboxId,
      customDomainId,
      nowStr(),
    )
    .first<AliasRow>();
  if (!row) throw new Error("alias insert returned no row");
  return row;
}

/** Alias.create_new_random — word/uuid local part, default-domain choice. */
async function createNewRandomAlias(
  db: D1Database,
  env: Env,
  user: UserRow,
  scheme: number,
): Promise<AliasRow> {
  const preferredDomain = await defaultRandomAliasDomain(db, user, env);
  const fallback = (env.FIRST_ALIAS_DOMAIN || env.EMAIL_DOMAIN).toLowerCase();
  let email: string | null = null;
  for (let i = 0; i < 10; i++) {
    const domain = i === 0 ? preferredDomain : fallback;
    const local =
      scheme === AliasGenerator.uuid ? crypto.randomUUID() : randomWords(2, 3);
    const candidate = `${local}@${domain}`.toLowerCase().trim();
    if (await availableSlEmail(db, candidate)) {
      email = candidate;
      break;
    }
  }
  if (!email) throw new Error("Cannot generate alias after many retries");
  return insertAliasWeb(db, env, user, {
    email,
    mailboxId: user.default_mailbox_id,
    note: null,
  });
}

// --- alias suffixes (app/alias_suffix.py, duplicated) ----------------------

interface AliasSuffix {
  is_custom: boolean;
  suffix: string;
  signed_suffix: string;
  is_premium: boolean;
  domain: string;
  mx_verified: boolean;
}

const LOWER_ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789";

function randomIndex(n: number): number {
  const RANGE = 2 ** 32;
  const limit = RANGE - (RANGE % n);
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}

function randomLowerAlnum(length: number): string {
  let out = "";
  for (let i = 0; i < length; i++)
    out += LOWER_ALNUM[randomIndex(LOWER_ALNUM.length)];
  return out;
}

function getRandomAliasSuffix(
  user: UserRow,
  customDomain?: CustomDomainRow | null,
): string {
  if (user.random_alias_suffix === 1) return randomLowerAlnum(5);
  if (!customDomain) return randomWords(1, 3);
  return randomWords(1);
}

async function verifiedCustomDomains(
  db: D1Database,
  userId: number,
): Promise<CustomDomainRow[]> {
  const res = await db
    .prepare(
      "SELECT * FROM custom_domain WHERE user_id = ?1 AND ownership_verified = 1 ORDER BY domain ASC",
    )
    .bind(userId)
    .all<CustomDomainRow>();
  return res.results;
}

async function getAliasSuffixes(
  db: D1Database,
  env: Env,
  user: UserRow,
): Promise<AliasSuffix[]> {
  const secret = customAliasSecret(env);
  const disableSuffix = env.DISABLE_ALIAS_SUFFIX !== undefined;
  const suffixes: AliasSuffix[] = [];

  for (const cd of await verifiedCustomDomains(db, user.id)) {
    if (cd.random_prefix_generation) {
      const suffix = `.${getRandomAliasSuffix(user, cd)}@${cd.domain}`;
      const s: AliasSuffix = {
        is_custom: true,
        suffix,
        signed_suffix: await timestampSign(secret, suffix),
        is_premium: false,
        domain: cd.domain,
        mx_verified: !!cd.verified,
      };
      if (user.default_alias_custom_domain_id === cd.id) suffixes.unshift(s);
      else suffixes.push(s);
    }
    const suffix = `@${cd.domain}`;
    const s: AliasSuffix = {
      is_custom: true,
      suffix,
      signed_suffix: await timestampSign(secret, suffix),
      is_premium: false,
      domain: cd.domain,
      mx_verified: !!cd.verified,
    };
    if (
      user.default_alias_custom_domain_id === cd.id &&
      !cd.random_prefix_generation
    ) {
      suffixes.unshift(s);
    } else {
      suffixes.push(s);
    }
  }

  const slDomains = await getSLDomains(db, user, env);
  let defaultDomainFound = false;
  for (const sl of slDomains) {
    const prefix = disableSuffix ? "" : `.${getRandomAliasSuffix(user)}`;
    const suffix = `${prefix}@${sl.domain}`;
    const s: AliasSuffix = {
      is_custom: false,
      suffix,
      signed_suffix: await timestampSign(secret, suffix),
      is_premium: !!sl.premium_only,
      domain: sl.domain,
      mx_verified: true,
    };
    if (
      user.default_alias_public_domain_id === null ||
      user.default_alias_public_domain_id !== sl.id
    ) {
      suffixes.push(s);
    } else {
      defaultDomainFound = true;
      suffixes.unshift(s);
    }
  }

  if (!defaultDomainFound && user.default_alias_public_domain_id !== null) {
    const premium = await userIsPremium(db, user);
    const sql = premium
      ? "SELECT * FROM public_domain WHERE id = ?1 AND hidden = 0"
      : "SELECT * FROM public_domain WHERE id = ?1 AND hidden = 0 AND premium_only = 0";
    const sl = await db
      .prepare(sql)
      .bind(user.default_alias_public_domain_id)
      .first<PublicDomainRow>();
    if (sl) {
      const prefix = disableSuffix ? "" : `.${getRandomAliasSuffix(user)}`;
      const suffix = `${prefix}@${sl.domain}`;
      suffixes.unshift({
        is_custom: false,
        suffix,
        signed_suffix: await timestampSign(secret, suffix),
        is_premium: !!sl.premium_only,
        domain: sl.domain,
        mx_verified: true,
      });
    }
  }
  return suffixes;
}

/** check_alias_prefix: 1-40 chars of [0-9a-z-_.]. */
function checkAliasPrefix(prefix: string): boolean {
  if (prefix.length > 40) return false;
  return /^[0-9a-z\-_.]+$/.test(prefix);
}

function verifyPrefixSuffix(
  env: Env,
  aliasPrefix: string,
  aliasSuffix: string,
  slDomains: PublicDomainRow[],
  customDomains: CustomDomainRow[],
): boolean {
  if (!aliasPrefix || !aliasSuffix) return false;
  const userCustomDomains = customDomains.map((cd) => cd.domain);
  const suffix = aliasSuffix.trim();
  const at = suffix.indexOf("@");
  if (at < 0) return false;
  const aliasDomainPrefix = suffix.slice(0, at);
  const aliasDomain = suffix.slice(at + 1);

  const availableSlDomains = slDomains.map((d) => d.domain);
  const availableDomains = new Set([
    ...availableSlDomains,
    ...userCustomDomains,
  ]);
  if (!availableDomains.has(aliasDomain)) return false;

  const disableSuffix = env.DISABLE_ALIAS_SUFFIX !== undefined;
  if (
    availableSlDomains.includes(aliasDomain) &&
    !userCustomDomains.includes(aliasDomain) &&
    !disableSuffix
  ) {
    if (!aliasDomainPrefix.startsWith(".")) return false;
  } else if (!userCustomDomains.includes(aliasDomain)) {
    if (!disableSuffix) return false;
    if (!availableSlDomains.includes(aliasDomain)) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// contact creation helpers (duplicated from src/routes/aliases.ts)
// ---------------------------------------------------------------------------

const ALNUM_ALLOWED =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";

function convertToAlphanumeric(s: string): string {
  let out = "";
  for (const ch of s) out += ALNUM_ALLOWED.includes(ch) ? ch : "_";
  return out;
}

function convertToId(s: string): string {
  let t = s.toLowerCase();
  t = t.normalize("NFKD").replace(/[\u0300-\u036f]/g, "");
  t = [...t].filter((ch) => ch.charCodeAt(0) < 128).join("");
  t = t.replaceAll(" ", "");
  return convertToAlphanumeric(t).slice(0, 64);
}

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
  if (trimmed.includes("@") && !/[<>\s]/.test(trimmed)) {
    return { name: "", email: trimmed };
  }
  return { name: "", email: "" };
}

function randInt(min: number, max: number): number {
  return min + Math.floor(Math.random() * (max - min + 1));
}

function randomStringLower(length: number): string {
  const chars = "abcdefghijklmnopqrstuvwxyz";
  let out = "";
  for (let i = 0; i < length; i++) out += chars[randomIndex(chars.length)];
  return out;
}

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
        ? `${senderPart}_${randomStringLower(randInt(5, 10))}@${replyDomain}`
        : `${randomStringLower(randInt(20, 50))}@${replyDomain}`;
    if (await availableSlEmail(db, candidate)) return candidate;
  }
  throw new Error("Cannot generate reply email");
}

async function canCreateContactsWeb(
  db: D1Database,
  env: Env,
  user: UserRow,
): Promise<boolean> {
  if (await userIsPremium(db, user)) return true;
  if ((user.flags & FLAG_FREE_DISABLE_CREATE_CONTACTS) === 0) return true;
  return !envStr(env, "DISABLE_CREATE_CONTACTS_FOR_FREE_USERS");
}

/** contact_utils.__update_contact_if_needed (name only — mail_from is always
 * null here): rename the existing contact before the "already added" error. */
async function updateContactNameIfNeededWeb(
  db: D1Database,
  contact: ContactRow,
  name: string | null,
): Promise<void> {
  if (name && contact.name !== name) {
    await db
      .prepare("UPDATE contact SET name = ?1, updated_at = ?2 WHERE id = ?3")
      .bind(name, nowStr(), contact.id)
      .run();
  }
}

/** create_contact web wrapper — returns the row or a flashable error message. */
async function createContactWeb(
  db: D1Database,
  env: Env,
  user: UserRow,
  alias: AliasRow,
  contactAddress: string,
): Promise<{ contact?: ContactRow; error?: string }> {
  if (!contactAddress) {
    return { error: "Empty address is not a valid email address" };
  }
  if (!(await canCreateContactsWeb(db, env, user))) {
    return { error: "Please upgrade to premium to create reverse-alias" };
  }

  const parsed = parseFullAddress(contactAddress);
  let name: string | null = parsed.name.slice(0, 512);
  if (!name) name = null;
  if (name?.includes("\x00")) name = "";

  const email = sanitizeEmail(parsed.email, true);
  if (!isValidEmail(email)) {
    return { error: `${contactAddress} is not a valid email address` };
  }

  const existing = await db
    .prepare("SELECT * FROM contact WHERE alias_id = ?1 AND website_email = ?2")
    .bind(alias.id, email)
    .first<ContactRow>();
  if (existing) {
    await updateContactNameIfNeededWeb(db, existing, name);
    return { error: `${existing.website_email} is already added` };
  }

  const lowered = sanitizeEmail(email);
  if (lowered !== `noreply@${env.EMAIL_DOMAIN}`) {
    const clash = await db
      .prepare("SELECT 1 FROM contact WHERE reply_email = ?1 LIMIT 1")
      .bind(lowered)
      .first();
    if (clash) {
      return { error: `${contactAddress} is not a valid email address` };
    }
  }

  const replyEmail = await generateReplyEmail(db, env, email, alias, user);
  try {
    const contact = await db
      .prepare(
        `INSERT INTO contact (user_id, alias_id, website_email, name, reply_email,
           mail_from, automatic_created, flags, invalid_email, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, 0, 0, 0, ?6) RETURNING *`,
      )
      .bind(alias.user_id, alias.id, email, name, replyEmail, nowStr())
      .first<ContactRow>();
    if (!contact)
      return { error: "Invalid address is not a valid email address" };
    return { contact };
  } catch (e) {
    if (e instanceof Error && e.message.includes("UNIQUE constraint")) {
      // IntegrityError path: fetch the winner and update its name too.
      const winner = await db
        .prepare(
          "SELECT * FROM contact WHERE alias_id = ?1 AND website_email = ?2",
        )
        .bind(alias.id, email)
        .first<ContactRow>();
      if (winner) {
        await updateContactNameIfNeededWeb(db, winner, name);
        return { error: `${winner.website_email} is already added` };
      }
      // ContactCreateError.Unknown -> ErrAddressInvalid("Invalid address")
      return { error: "Invalid address is not a valid email address" };
    }
    throw e;
  }
}

// ---------------------------------------------------------------------------
// transfer-token scheme (HMAC-SHA3-224, byte-compatible with Flask)
// ---------------------------------------------------------------------------

function transferTokenSecret(env: Env): string {
  return (
    envStr(env, "ALIAS_TRANSFER_TOKEN_SECRET") ??
    `${env.FLASK_SECRET}aliastransfertoken`
  );
}

function hashTransferToken(secret: string, token: string): string {
  const enc = new TextEncoder();
  const mac = hmac(sha3_224, enc.encode(secret), enc.encode(token));
  let bin = "";
  for (const b of mac) bin += String.fromCharCode(b);
  return btoa(bin)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

// ---------------------------------------------------------------------------
// 1. GET|POST /dashboard/ — alias list
// ---------------------------------------------------------------------------

function indexQueryParams(c: Ctx): {
  query: string;
  sort: string;
  filter: string;
  page: number;
  highlightAliasId: number | null;
} {
  const query = c.req.query("query") ?? "";
  const sort = c.req.query("sort") ?? "";
  const filter = c.req.query("filter") ?? "";
  const page = pyInt(c.req.query("page")) ?? 0;
  const rawHighlight = c.req.query("highlight_alias_id");
  const highlightAliasId =
    rawHighlight !== undefined ? pyInt(rawHighlight) : null;
  return { query, sort, filter, page, highlightAliasId };
}

webAliasPagesRoutes.on(["GET", "POST"], "/", requireWebLogin, async (c) => {
  const user = c.get("webUser");
  const db = c.env.DB;
  const { query, sort, filter, page, highlightAliasId } = indexQueryParams(c);

  if (c.req.method === "POST") {
    const body = await readForm(c);
    if (!(await csrfOk(c, body))) {
      await flash(c, "Invalid request", "warning");
      return c.redirect(reqUrl(c), 302);
    }

    const formName = formGet(body, "form-name");

    if (formName === "create-custom-email") {
      if (await canCreateNewAlias(db, c.env, user)) {
        return c.redirect(urlFor("dashboard.custom_alias"), 302);
      }
      await flash(
        c,
        "You need to upgrade your plan to create new alias.",
        "warning",
      );
    } else if (formName === "create-random-email") {
      if (await canCreateNewAlias(db, c.env, user)) {
        const rawScheme = formGet(body, "generator_scheme");
        let scheme: number;
        if (rawScheme) {
          const parsed = pyInt(rawScheme);
          // Flask: int() on a non-numeric value raises -> 500 page.
          if (parsed === null)
            throw new Error(`invalid generator_scheme ${rawScheme}`);
          scheme = parsed;
        } else {
          scheme = user.alias_generator;
        }
        if (
          !scheme ||
          (scheme !== AliasGenerator.word && scheme !== AliasGenerator.uuid)
        ) {
          scheme = user.alias_generator;
        }
        let alias: AliasRow;
        try {
          alias = await createNewRandomAlias(db, c.env, user, scheme);
        } catch (e) {
          if (e instanceof BucketRateLimitError) return renderErrorPage(c, 429);
          throw e;
        }
        await flash(c, `Alias ${alias.email} has been created`, "success");
        return c.redirect(
          urlFor("dashboard.index", {
            highlight_alias_id: alias.id,
            query,
            sort,
            filter,
          }),
          302,
        );
      }
      await flash(
        c,
        "You need to upgrade your plan to create new alias.",
        "warning",
      );
    } else if (formName === "delete-alias" || formName === "disable-alias") {
      const rawAliasId = formGet(body, "alias-id");
      // Flask: int(None) raises TypeError -> 500 page.
      if (rawAliasId === undefined) throw new Error("missing alias-id");
      const aliasId = pyInt(rawAliasId);
      if (aliasId === null) {
        await flash(c, "unknown error", "error");
        return c.redirect(reqUrl(c), 302);
      }
      // Alias.get also returns trashed aliases.
      const alias = await db
        .prepare("SELECT * FROM alias WHERE id = ?1")
        .bind(aliasId)
        .first<AliasRow>();
      if (!alias || alias.user_id !== user.id) {
        await flash(c, "Unknown error, sorry for the inconvenience", "error");
        return c.redirect(
          urlFor("dashboard.index", { query, sort, filter }),
          302,
        );
      }
      if (formName === "delete-alias") {
        await deleteAliasForUser(db, alias, user, REASON_MANUAL_ACTION);
        if (user.alias_delete_action !== DELETE_IMMEDIATELY) {
          await flash(
            c,
            `Alias ${alias.email} has been moved to the trash`,
            "success",
          );
        } else {
          await flash(c, `Alias ${alias.email} has been deleted`, "success");
        }
      } else {
        await db
          .prepare(
            "UPDATE alias SET enabled = 0, updated_at = ?1 WHERE id = ?2",
          )
          .bind(nowStr(), alias.id)
          .run();
        await flash(c, `Alias ${alias.email} has been disabled`, "success");
      }
    }
    // Common final redirect (also for unknown form-name).
    return c.redirect(
      urlFor("dashboard.index", { query, sort, filter, page }),
      302,
    );
  }

  // ---- GET ----
  const allMailboxes = await verifiedMailboxes(db, user.id);
  const mailboxes = allMailboxes.filter((m) => !isAdminDisabled(m));

  let showIntro = false;
  if (!user.intro_shown) {
    showIntro = true;
    await db
      .prepare(
        "UPDATE users SET intro_shown = 1, updated_at = ?1 WHERE id = ?2",
      )
      .bind(nowStr(), user.id)
      .run();
  }

  const [nbAlias, nbForward, nbReply, nbBlock] = await Promise.all([
    db
      .prepare(
        "SELECT COUNT(*) AS n FROM alias WHERE user_id = ?1 AND delete_on IS NULL",
      )
      .bind(user.id)
      .first<{ n: number }>(),
    db
      .prepare(
        "SELECT COUNT(*) AS n FROM email_log WHERE user_id = ?1 AND is_reply = 0 AND blocked = 0 AND bounced = 0",
      )
      .bind(user.id)
      .first<{ n: number }>(),
    db
      .prepare(
        "SELECT COUNT(*) AS n FROM email_log WHERE user_id = ?1 AND is_reply = 1 AND blocked = 0 AND bounced = 0",
      )
      .bind(user.id)
      .first<{ n: number }>(),
    db
      .prepare(
        "SELECT COUNT(*) AS n FROM email_log WHERE user_id = ?1 AND is_reply = 0 AND blocked = 1 AND bounced = 0",
      )
      .bind(user.id)
      .first<{ n: number }>(),
  ]);
  const stats = {
    nb_alias: nbAlias?.n ?? 0,
    nb_forward: nbForward?.n ?? 0,
    nb_reply: nbReply?.n ?? 0,
    nb_block: nbBlock?.n ?? 0,
  };

  let mailboxId: number | null = null;
  let directoryId: number | null = null;
  if (filter.startsWith("mailbox:")) {
    mailboxId = pyInt(filter.slice(8));
    // Flask: int() raises -> 500 page.
    if (mailboxId === null) throw new Error(`invalid mailbox filter ${filter}`);
  } else if (filter.startsWith("directory:")) {
    directoryId = pyInt(filter.slice(10));
    if (directoryId === null)
      throw new Error(`invalid directory filter ${filter}`);
  }

  let aliasInfos = await fetchWebAliasInfos(db, c.env, user, {
    query,
    sort,
    filter,
    mailboxId,
    directoryId,
    limit: PAGE_LIMIT + 1,
    offset: page * PAGE_LIMIT,
  });
  const lastPage = aliasInfos.length <= PAGE_LIMIT;
  aliasInfos = aliasInfos.slice(0, PAGE_LIMIT);

  if (
    highlightAliasId !== null &&
    !aliasInfos.some((ai) => ai.alias.id === highlightAliasId)
  ) {
    const highlighted = await fetchWebAliasInfos(db, c.env, user, {
      aliasId: highlightAliasId,
      limit: 1,
      offset: 0,
    });
    if (highlighted.length > 0) aliasInfos.unshift(highlighted[0]);
  }

  const directories = await db
    .prepare("SELECT id, name FROM directory WHERE user_id = ?1 ORDER BY id")
    .bind(user.id)
    .all<{ id: number; name: string }>()
    .catch(() => ({ results: [] as Array<{ id: number; name: string }> }));

  const currentUser = await buildCurrentUser(c, user);
  const csrfForm = await csrfFormCtx(c);

  return webRender(
    c,
    "dashboard/index.html",
    {
      alias_infos: aliasInfos,
      highlight_alias_id: highlightAliasId,
      query,
      sort,
      filter,
      AliasGeneratorEnum: { word: { value: 1 }, uuid: { value: 2 } },
      UserAliasDeleteAction: { MoveToTrash: { name: "MoveToTrash" } },
      mailboxes: mailboxes.map((m) => ({ id: m.id, email: m.email })),
      filter_mailboxes: allMailboxes.map((m) => ({ id: m.id, email: m.email })),
      directories: directories.results,
      show_intro: showIntro,
      page,
      last_page: lastPage,
      stats,
      csrf_form: csrfForm,
      expand_alias_info: !!user.expand_alias_info,
      alias_delete_action_name:
        user.alias_delete_action === DELETE_IMMEDIATELY
          ? "DeleteImmediately"
          : "MoveToTrash",
    },
    { currentUser },
  );
});

// ---------------------------------------------------------------------------
// 2. POST /dashboard/contacts/<id>/toggle — htmx block/unblock
// ---------------------------------------------------------------------------

webAliasPagesRoutes.post(
  "/contacts/:contact_id{[0-9]+}/toggle",
  requireWebLogin,
  async (c) => {
    const user = c.get("webUser");
    const db = c.env.DB;
    const body = await readForm(c);
    if (!(await csrfOk(c, body))) {
      return c.text("Invalid request", 400);
    }
    const contact = await getContactById(db, Number(c.req.param("contact_id")));
    let alias: AliasRow | null = null;
    if (contact) {
      alias = await db
        .prepare("SELECT * FROM alias WHERE id = ?1")
        .bind(contact.alias_id)
        .first<AliasRow>();
    }
    if (!contact || !alias || alias.user_id !== user.id) {
      return c.text("Forbidden", 403);
    }

    const newBlocked = contact.block_forward ? 0 : 1;
    await db
      .prepare(
        "UPDATE contact SET block_forward = ?1, updated_at = ?2 WHERE id = ?3",
      )
      .bind(newBlocked, nowStr(), contact.id)
      .run();

    const toastMsg = newBlocked
      ? `${contact.website_email} can no longer send emails to ${alias.email}`
      : `${contact.website_email} can now send emails to ${alias.email}`;

    const csrfForm = await csrfFormCtx(c);
    const html = renderTemplate("dashboard/toggle_contact.html", {
      contact: { ...contact, block_forward: newBlocked },
      toast_msg: toastMsg,
      csrf_form: csrfForm,
      url_for: (endpoint: string, params?: Record<string, unknown>) =>
        urlFor(endpoint, params),
    });
    return c.html(html);
  },
);

// ---------------------------------------------------------------------------
// 3. GET|POST /dashboard/custom_alias
// ---------------------------------------------------------------------------

interface CustomAliasCtx {
  user_custom_domains: string[];
  alias_suffixes: AliasSuffix[];
  at_least_a_premium_domain: boolean;
  mailboxes: Array<{ id: number; email: string }>;
  default_mailbox_id: number | null;
}

async function customAliasContext(
  c: Ctx,
  user: UserRow,
): Promise<CustomAliasCtx> {
  const db = c.env.DB;
  const customDomains = await verifiedCustomDomains(db, user.id);
  const aliasSuffixes = await getAliasSuffixes(db, c.env, user);
  const mailboxes = (await verifiedMailboxes(db, user.id)).filter(
    (m) => !isAdminDisabled(m),
  );
  return {
    user_custom_domains: customDomains.map((cd) => cd.domain),
    alias_suffixes: aliasSuffixes,
    at_least_a_premium_domain: aliasSuffixes.some(
      (s) => !s.is_custom && s.is_premium,
    ),
    mailboxes: mailboxes.map((m) => ({ id: m.id, email: m.email })),
    default_mailbox_id: user.default_mailbox_id,
  };
}

async function renderCustomAlias(
  c: Ctx,
  user: UserRow,
  ctx: CustomAliasCtx,
): Promise<Response> {
  const currentUser = await buildCurrentUser(c, user);
  const csrfForm = await csrfFormCtx(c);
  return webRender(
    c,
    "dashboard/custom_alias.html",
    { ...ctx, csrf_form: csrfForm },
    { currentUser },
  );
}

webAliasPagesRoutes.on(
  ["GET", "POST"],
  "/custom_alias",
  requireWebLogin,
  async (c) => {
    const user = c.get("webUser");
    const db = c.env.DB;

    if (!(await canCreateNewAlias(db, c.env, user))) {
      await flash(
        c,
        "You have reached free plan limit, please upgrade to create new aliases",
        "warning",
      );
      return c.redirect(urlFor("dashboard.index"), 302);
    }

    const ctx = await customAliasContext(c, user);

    if (c.req.method === "GET") return renderCustomAlias(c, user, ctx);

    // ---- POST ----
    const body = await readForm(c);
    if (!(await csrfOk(c, body))) {
      await flash(c, "Invalid request", "warning");
      return c.redirect(reqUrl(c), 302);
    }

    const rawPrefix = formGet(body, "prefix");
    // Flask: None.strip() raises AttributeError -> 500 page.
    if (rawPrefix === undefined) throw new Error("missing prefix");
    const aliasPrefix = rawPrefix.trim().toLowerCase().replaceAll(" ", "");

    if (!checkAliasPrefix(aliasPrefix)) {
      await flash(
        c,
        "Only lowercase letters, numbers, dashes (-), dots (.) and underscores (_) are currently supported for alias prefix. Cannot be more than 40 letters",
        "error",
      );
      return c.redirect(reqUrl(c), 302);
    }

    // Mailbox validation
    const mailboxIds = formGetList(body, "mailboxes");
    const mailboxes: MailboxRow[] = [];
    for (const rawId of mailboxIds) {
      const id = pyInt(rawId);
      const mailbox = id !== null ? await getMailboxById(db, id) : null;
      if (!mailbox || mailbox.user_id !== user.id || !mailbox.verified) {
        await flash(c, "Something went wrong, please retry", "warning");
        return c.redirect(reqUrl(c), 302);
      }
      if (isAdminDisabled(mailbox)) {
        await flash(
          c,
          "Cannot assign admin-disabled mailbox to alias. Please contact support.",
          "error",
        );
        return c.redirect(reqUrl(c), 302);
      }
      mailboxes.push(mailbox);
    }
    if (mailboxes.length === 0) {
      await flash(c, "At least one mailbox must be selected", "error");
      return c.redirect(reqUrl(c), 302);
    }
    // Later re-renders show only the POSTed mailboxes (Flask locals gotcha).
    ctx.mailboxes = mailboxes.map((m) => ({ id: m.id, email: m.email }));

    const signedSuffix = formGet(body, "signed-alias-suffix");
    // Flask: check_suffix_signature(None) raises a non-BadSignature exception
    // (want_bytes(None)) caught by `except Exception` -> distinct flash.
    if (signedSuffix === undefined) {
      await flash(c, "Unknown error, refresh the page", "error");
      return c.redirect(reqUrl(c), 302);
    }
    const suffix = await timestampUnsign(
      customAliasSecret(c.env),
      signedSuffix.trim(),
      600,
    );
    if (!suffix) {
      await flash(c, "Alias creation time is expired, please retry", "warning");
      return c.redirect(reqUrl(c), 302);
    }

    const customDomains = await verifiedCustomDomains(db, user.id);
    const slDomains = await getSLDomains(db, user, c.env);
    if (
      !verifyPrefixSuffix(c.env, aliasPrefix, suffix, slDomains, customDomains)
    ) {
      await flash(c, "something went wrong", "warning");
      return renderCustomAlias(c, user, ctx);
    }

    const fullAlias = aliasPrefix + suffix;
    if (fullAlias.includes("..")) {
      await flash(
        c,
        "Your alias can't contain 2 consecutive dots (..)",
        "error",
      );
      return c.redirect(reqUrl(c), 302);
    }

    const emailErr = validateEmailMessage(fullAlias);
    if (emailErr) {
      await flash(c, emailErr, "error");
      return c.redirect(reqUrl(c), 302);
    }

    // Existence checks — flash + re-render (200).
    const existingAlias = await db
      .prepare("SELECT * FROM alias WHERE email = ?1")
      .bind(fullAlias)
      .first<AliasRow>();
    if (existingAlias) {
      if (existingAlias.user_id === user.id) {
        await flash(c, `You already have this alias ${fullAlias}`, "error");
      } else {
        await flash(c, `${fullAlias} cannot be used`, "error");
      }
      return renderCustomAlias(c, user, ctx);
    }
    const domainDeleted = await db
      .prepare(
        `SELECT cd.domain AS domain FROM domain_deleted_alias dda
         JOIN custom_domain cd ON dda.domain_id = cd.id
         WHERE dda.email = ?1 LIMIT 1`,
      )
      .bind(fullAlias)
      .first<{ domain: string }>();
    if (domainDeleted) {
      await flash(
        c,
        `You have deleted this alias before. If you want to re-create it, please delete it from ${domainDeleted.domain} 'Deleted Alias' page`,
        "error",
      );
      return renderCustomAlias(c, user, ctx);
    }
    const deleted = await db
      .prepare("SELECT 1 FROM deleted_alias WHERE email = ?1 LIMIT 1")
      .bind(fullAlias)
      .first();
    if (deleted) {
      await flash(c, `${fullAlias} cannot be used`, "error");
      return renderCustomAlias(c, user, ctx);
    }

    // Create
    const aliasNote = formGet(body, "note") ?? "";
    let alias: AliasRow;
    try {
      alias = await insertAliasWeb(db, c.env, user, {
        email: fullAlias,
        mailboxId: mailboxes[0].id,
        note: aliasNote,
      });
    } catch (e) {
      if (e instanceof BucketRateLimitError) return renderErrorPage(c, 429);
      if (e instanceof Error && e.message.includes("UNIQUE constraint")) {
        await flash(c, "Unknown error, please retry", "error");
        return c.redirect(urlFor("dashboard.custom_alias"), 302);
      }
      throw e;
    }
    for (let i = 1; i < mailboxes.length; i++) {
      await db
        .prepare(
          "INSERT INTO alias_mailbox (alias_id, mailbox_id, created_at) VALUES (?1, ?2, ?3)",
        )
        .bind(alias.id, mailboxes[i].id, nowStr())
        .run();
    }
    await flash(c, `Alias ${fullAlias} has been created`, "success");
    return c.redirect(
      urlFor("dashboard.index", { highlight_alias_id: alias.id }),
      302,
    );
  },
);

// ---------------------------------------------------------------------------
// 4. GET /dashboard/alias_log/<alias_id>[/<page_id>]
// ---------------------------------------------------------------------------

async function handleAliasLog(c: Ctx, pageId: number): Promise<Response> {
  const user = c.get("webUser");
  const db = c.env.DB;
  const aliasId = Number(c.req.param("alias_id"));

  const alias = await db
    .prepare("SELECT * FROM alias WHERE id = ?1")
    .bind(aliasId)
    .first<AliasRow>();
  if (!alias || alias.user_id !== user.id) {
    await flash(c, "You do not have access to this page", "warning");
    return c.redirect(urlFor("dashboard.index"), 302);
  }

  const logRows = await db
    .prepare(
      `SELECT el.*, ct.website_email AS _website_email, ct.name AS _contact_name,
              ct.website_from AS _website_from, ct.reply_email AS _reply_email
       FROM email_log el JOIN contact ct ON el.contact_id = ct.id
       WHERE ct.alias_id = ?1
       ORDER BY el.id DESC LIMIT ${PAGE_LIMIT} OFFSET ?2`,
    )
    .bind(alias.id, pageId * PAGE_LIMIT)
    .all<
      EmailLogRow & {
        _website_email: string;
        _contact_name: string | null;
        _website_from: string | null;
        _reply_email: string;
      }
    >();

  // bounced_mailbox() legacy fallback: contact.alias.mailboxes[0].email —
  // Alias.mailboxes is primary + alias_mailbox rows, verified only, sorted
  // alphabetically by email. Flask 500s (IndexError) when the list is empty;
  // we render "" instead (documented Flask-500 -> clean deviation).
  const fallbackMb = await db
    .prepare(
      `SELECT email FROM mailbox
       WHERE verified = 1 AND (id = ?1 OR id IN
         (SELECT mailbox_id FROM alias_mailbox WHERE alias_id = ?2))
       ORDER BY email LIMIT 1`,
    )
    .bind(alias.mailbox_id, alias.id)
    .first<{ email: string }>();
  const fallbackMailboxEmail = fallbackMb?.email ?? "";

  const logs = await Promise.all(
    logRows.results.map(async (r) => {
      let bouncedMailbox = "";
      if (r.bounced) {
        if (r.bounced_mailbox_id) {
          const mb = await getMailboxById(db, r.bounced_mailbox_id);
          bouncedMailbox = mb?.email ?? "";
        } else {
          bouncedMailbox = fallbackMailboxEmail;
        }
      }
      return {
        website_email: r._website_email,
        alias: alias.email,
        when: r.created_at,
        is_reply: !!r.is_reply,
        blocked: !!r.blocked,
        bounced: !!r.bounced,
        bounced_mailbox: bouncedMailbox,
      };
    }),
  );
  // Flask re-sorts by created_at DESC.
  logs.sort((a, b) => (a.when < b.when ? 1 : a.when > b.when ? -1 : 0));

  const counters = await db
    .prepare(
      `SELECT COUNT(*) AS total,
              SUM(CASE WHEN el.is_reply = 0 AND el.blocked = 0 THEN 1 ELSE 0 END) AS forwarded,
              SUM(CASE WHEN el.is_reply = 1 THEN 1 ELSE 0 END) AS replied,
              SUM(CASE WHEN el.blocked = 1 THEN 1 ELSE 0 END) AS blocked
       FROM email_log el JOIN contact ct ON el.contact_id = ct.id
       WHERE ct.alias_id = ?1`,
    )
    .bind(alias.id)
    .first<{
      total: number;
      forwarded: number;
      replied: number;
      blocked: number;
    }>();

  const currentUser = await buildCurrentUser(c, user);
  return webRender(
    c,
    "dashboard/alias_log.html",
    {
      alias,
      alias_id: alias.id,
      page_id: pageId,
      logs,
      total: counters?.total ?? 0,
      email_forwarded: counters?.forwarded ?? 0,
      email_replied: counters?.replied ?? 0,
      email_blocked: counters?.blocked ?? 0,
      last_page: logs.length < PAGE_LIMIT,
    },
    { currentUser },
  );
}

webAliasPagesRoutes.get("/alias_log/:alias_id{[0-9]+}", requireWebLogin, (c) =>
  handleAliasLog(c, 0),
);
webAliasPagesRoutes.get(
  "/alias_log/:alias_id{[0-9]+}/:page_id{[0-9]+}",
  requireWebLogin,
  (c) => handleAliasLog(c, Number(c.req.param("page_id"))),
);

// ---------------------------------------------------------------------------
// 5. GET /dashboard/alias_export — CSV (sudo)
// ---------------------------------------------------------------------------

function csvField(v: string): string {
  return /[",\r\n]/.test(v) ? `"${v.replaceAll('"', '""')}"` : v;
}

webAliasPagesRoutes.get(
  "/alias_export",
  requireWebLogin,
  requireWebSudo,
  async (c) => {
    const user = c.get("webUser");
    const db = c.env.DB;

    const aliases = await db
      .prepare(
        "SELECT * FROM alias WHERE user_id = ?1 AND delete_on IS NULL ORDER BY id",
      )
      .bind(user.id)
      .all<AliasRow>();

    const lines: string[] = ["alias,note,enabled,mailboxes"];
    for (const alias of aliases.results) {
      const amRows = await db
        .prepare(
          "SELECT mailbox_id FROM alias_mailbox WHERE alias_id = ?1 ORDER BY id",
        )
        .bind(alias.id)
        .all<{ mailbox_id: number }>();
      const ids = [alias.mailbox_id];
      for (const r of amRows.results)
        if (!ids.includes(r.mailbox_id)) ids.push(r.mailbox_id);
      const mbRows: MailboxRow[] = [];
      for (const id of ids) {
        const mb = await getMailboxById(db, id);
        if (mb?.verified) mbRows.push(mb);
      }
      mbRows.sort((a, b) =>
        a.email < b.email ? -1 : a.email > b.email ? 1 : 0,
      );
      // primary mailbox first
      const emails = mbRows.map((m) => m.email);
      const primary = mbRows.find((m) => m.id === alias.mailbox_id);
      let ordered = emails;
      if (primary) {
        ordered = [primary.email, ...emails.filter((e) => e !== primary.email)];
      }
      lines.push(
        [
          csvField(alias.email),
          csvField(alias.note ?? ""),
          alias.enabled ? "True" : "False",
          csvField(ordered.join(" ")),
        ].join(","),
      );
    }
    const csv = `${lines.join("\r\n")}\r\n`;
    return c.body(csv, 200, {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": "attachment; filename=aliases.csv",
    });
  },
);

// ---------------------------------------------------------------------------
// 6. GET|POST /dashboard/alias_transfer/send/<alias_id> (sudo)
// ---------------------------------------------------------------------------

webAliasPagesRoutes.on(
  ["GET", "POST"],
  "/alias_transfer/send/:alias_id{[0-9]+}",
  requireWebLogin,
  requireWebSudo,
  async (c) => {
    const user = c.get("webUser");
    const db = c.env.DB;
    const aliasId = Number(c.req.param("alias_id"));

    const alias = await db
      .prepare("SELECT * FROM alias WHERE id = ?1")
      .bind(aliasId)
      .first<AliasRow>();
    if (!alias || alias.user_id !== user.id) {
      await flash(c, "You cannot see this page", "warning");
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    if (user.newsletter_alias_id === alias.id) {
      await flash(
        c,
        "This alias is currently used for receiving the newsletter and cannot be transferred",
        "error",
      );
      return c.redirect(urlFor("dashboard.index"), 302);
    }

    let aliasTransferUrl: string | null = null;
    let tokenState = {
      transfer_token: alias.transfer_token,
      transfer_token_expiration: alias.transfer_token_expiration,
    };

    if (c.req.method === "POST") {
      const body = await readForm(c);
      if (!(await csrfOk(c, body))) {
        await flash(c, "Invalid request", "warning");
        return c.redirect(reqUrl(c), 302);
      }
      if (formGet(body, "form-name") === "create") {
        const transferToken = `${alias.id}.${tokenUrlsafe(32)}`;
        const hashed = hashTransferToken(
          transferTokenSecret(c.env),
          transferToken,
        );
        const expiration = toStr(addDays(new Date(), 1));
        await db
          .prepare(
            "UPDATE alias SET transfer_token = ?1, transfer_token_expiration = ?2, updated_at = ?3 WHERE id = ?4",
          )
          .bind(hashed, expiration, nowStr(), alias.id)
          .run();
        tokenState = {
          transfer_token: hashed,
          transfer_token_expiration: expiration,
        };
        aliasTransferUrl = `${c.env.URL}/dashboard/alias_transfer/receive?token=${transferToken}`;
        await flash(c, "Share alias URL created", "success");
      } else {
        await db
          .prepare(
            "UPDATE alias SET transfer_token = NULL, transfer_token_expiration = NULL, updated_at = ?1 WHERE id = ?2",
          )
          .bind(nowStr(), alias.id)
          .run();
        tokenState = { transfer_token: null, transfer_token_expiration: null };
        aliasTransferUrl = null;
        await flash(c, "Share URL deleted", "success");
      }
    }

    const linkActive =
      tokenState.transfer_token_expiration !== null &&
      toDate(tokenState.transfer_token_expiration).getTime() > Date.now();

    const currentUser = await buildCurrentUser(c, user);
    const csrfForm = await csrfFormCtx(c);
    return webRender(
      c,
      "dashboard/alias_transfer_send.html",
      {
        alias,
        alias_transfer_url: aliasTransferUrl,
        link_active: linkActive,
        csrf_form: csrfForm,
      },
      { currentUser },
    );
  },
);

// ---------------------------------------------------------------------------
// 7. GET|POST /dashboard/alias_transfer/receive
// ---------------------------------------------------------------------------

webAliasPagesRoutes.on(
  ["GET", "POST"],
  "/alias_transfer/receive",
  requireWebLogin,
  async (c) => {
    const user = c.get("webUser");
    const db = c.env.DB;
    const token = c.req.query("token");

    if (!token) {
      await flash(c, "Invalid transfer token", "error");
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    const hashed = hashTransferToken(transferTokenSecret(c.env), token);
    // Legacy plaintext tokens are still honored.
    const alias = await db
      .prepare(
        "SELECT * FROM alias WHERE transfer_token = ?1 OR transfer_token = ?2 LIMIT 1",
      )
      .bind(token, hashed)
      .first<AliasRow>();
    if (!alias) {
      await flash(c, "Invalid link", "error");
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    if (
      alias.transfer_token_expiration !== null &&
      toDate(alias.transfer_token_expiration).getTime() < Date.now()
    ) {
      await flash(c, "Expired link, please request a new one", "error");
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    if (alias.user_id === user.id) {
      await flash(c, "You already own this alias", "warning");
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    if (!(await canCreateNewAlias(db, c.env, user))) {
      await flash(
        c,
        "You have reached free plan limit, please upgrade to create new aliases",
        "warning",
      );
      return c.redirect(urlFor("dashboard.index"), 302);
    }

    const mailboxes = (await verifiedMailboxes(db, user.id)).filter(
      (m) => !isAdminDisabled(m),
    );

    if (c.req.method === "GET") {
      const currentUser = await buildCurrentUser(c, user);
      const csrfForm = await csrfFormCtx(c);
      return webRender(
        c,
        "dashboard/alias_transfer_receive.html",
        {
          alias,
          mailboxes: mailboxes.map((m) => ({ id: m.id, email: m.email })),
          default_mailbox_id: user.default_mailbox_id,
          csrf_form: csrfForm,
        },
        { currentUser },
      );
    }

    // ---- POST ----
    const body = await readForm(c);
    if (!(await csrfOk(c, body))) {
      await flash(c, "Invalid request", "warning");
      return c.redirect(reqUrl(c), 302);
    }
    const mailboxIds = formGetList(body, "mailbox_ids");
    const chosen: MailboxRow[] = [];
    for (const rawId of mailboxIds) {
      const id = pyInt(rawId);
      const mailbox = id !== null ? await getMailboxById(db, id) : null;
      if (!mailbox || mailbox.user_id !== user.id || !mailbox.verified) {
        await flash(c, "Something went wrong, please retry", "warning");
        return c.redirect(reqUrl(c), 302);
      }
      if (isAdminDisabled(mailbox)) {
        await flash(
          c,
          "Cannot assign admin-disabled mailbox. Please contact support.",
          "error",
        );
        return c.redirect(reqUrl(c), 302);
      }
      chosen.push(mailbox);
    }
    if (chosen.length === 0) {
      await flash(c, "You must select at least 1 mailbox", "warning");
      return c.redirect(reqUrl(c), 302);
    }

    // transfer_alias(alias, new_user, mailboxes)
    const newsletterUser = await db
      .prepare("SELECT 1 FROM users WHERE newsletter_alias_id = ?1 LIMIT 1")
      .bind(alias.id)
      .first();
    if (newsletterUser) {
      throw new Error(
        `Alias ${alias.id} is used exclusively by user as newsletter alias`,
      );
    }

    const oldUser = await db
      .prepare("SELECT * FROM users WHERE id = ?1")
      .bind(alias.user_id)
      .first<UserRow>();

    const now = nowStr();
    await db
      .prepare(
        "UPDATE contact SET user_id = ?1, updated_at = ?2 WHERE alias_id = ?3",
      )
      .bind(user.id, now, alias.id)
      .run();
    await db
      .prepare("UPDATE alias_used_on SET user_id = ?1 WHERE alias_id = ?2")
      .bind(user.id, alias.id)
      .run();
    await db
      .prepare("UPDATE client_user SET user_id = ?1 WHERE alias_id = ?2")
      .bind(user.id, alias.id)
      .run()
      .catch(() => undefined);
    await db
      .prepare("DELETE FROM alias_mailbox WHERE alias_id = ?1")
      .bind(alias.id)
      .run();

    // GOTCHA kept: .pop() — the LAST submitted mailbox becomes primary.
    const remaining = [...chosen];
    const primary = remaining.pop() as MailboxRow;
    await db
      .prepare(
        `UPDATE alias SET user_id = ?1, mailbox_id = ?2,
           original_owner_id = COALESCE(original_owner_id, ?3),
           disable_pgp = 0, pinned = 0,
           transfer_token = NULL, transfer_token_expiration = NULL,
           updated_at = ?4
         WHERE id = ?5`,
      )
      .bind(user.id, primary.id, alias.user_id, now, alias.id)
      .run();
    for (const mb of remaining) {
      await db
        .prepare(
          "INSERT INTO alias_mailbox (alias_id, mailbox_id, created_at) VALUES (?1, ?2, ?3)",
        )
        .bind(alias.id, mb.id, now)
        .run();
    }

    if (oldUser && !oldUser.disabled && oldUser.delete_on === null) {
      await sendTransactionalEmail(c.env, {
        to: oldUser.email,
        subject: `Alias ${alias.email} has been received`,
        text: `${alias.email} has been transferred.\n\nYour (previously) alias ${alias.email} has been received by another user.`,
        html: `<h1>${alias.email} has been transferred.</h1><p>Your (previously) alias ${alias.email} has been received by another user.</p>`,
      });
    }

    await flash(c, `You are now owner of ${alias.email}`, "success");
    return c.redirect(
      urlFor("dashboard.index", { highlight_alias_id: alias.id }),
      302,
    );
  },
);

// ---------------------------------------------------------------------------
// 8. GET|POST /dashboard/alias_contact_manager/<alias_id>
// ---------------------------------------------------------------------------

interface ContactInfoVM {
  contact: ContactRow;
  nb_forward: number;
  nb_reply: number;
  latest_email_log: EmailLogRow | null;
  website_send_to: string;
}

async function getContactInfos(
  db: D1Database,
  user: UserRow,
  alias: AliasRow,
  opts: { page?: number; contactId?: number | null; query?: string },
): Promise<ContactInfoVM[]> {
  const conds: string[] = [];
  const params: unknown[] = [alias.id, alias.id];
  if (opts.query) {
    conds.push(
      "(c.website_email LIKE '%' || ? || '%' OR c.name LIKE '%' || ? || '%')",
    );
    params.push(opts.query, opts.query);
  }
  if (opts.contactId != null) {
    conds.push("c.id = ?");
    params.push(opts.contactId);
  }
  const whereExtra = conds.length ? ` AND ${conds.join(" AND ")}` : "";
  const page = opts.page ?? 0;

  const rows = await db
    .prepare(
      `SELECT c.*, sub.nb_reply AS _nb_reply, sub.nb_forward AS _nb_forward,
              el.id AS _el_id
       FROM contact c
       JOIN (
         SELECT contact.id AS cid,
                SUM(CASE WHEN email_log.is_reply = 1 THEN 1 ELSE 0 END) AS nb_reply,
                SUM(CASE WHEN email_log.is_reply = 0 AND email_log.blocked = 0 THEN 1 ELSE 0 END) AS nb_forward,
                MAX(email_log.created_at) AS max_created
         FROM contact LEFT OUTER JOIN email_log ON email_log.contact_id = contact.id
         WHERE contact.alias_id = ?1
         GROUP BY contact.id
       ) sub ON c.id = sub.cid
       LEFT OUTER JOIN email_log el
         ON el.contact_id = c.id AND el.created_at = sub.max_created
       WHERE c.alias_id = ?2${whereExtra}
       ORDER BY MAX(IFNULL(el.created_at, c.created_at), c.created_at) DESC, c.id DESC
       LIMIT ${PAGE_LIMIT} OFFSET ${page * PAGE_LIMIT}`,
    )
    .bind(...params)
    .all<
      ContactRow & {
        _nb_reply: number;
        _nb_forward: number;
        _el_id: number | null;
      }
    >();

  const logIds = [
    ...new Set(
      rows.results.map((r) => r._el_id).filter((v): v is number => v !== null),
    ),
  ];
  const logMap = new Map<number, EmailLogRow>();
  if (logIds.length > 0) {
    const ph = logIds.map((_, i) => `?${i + 1}`).join(", ");
    const res = await db
      .prepare(`SELECT * FROM email_log WHERE id IN (${ph})`)
      .bind(...logIds)
      .all<EmailLogRow>();
    for (const l of res.results) logMap.set(l.id, l);
  }

  return rows.results.map((row) => {
    const { _nb_reply, _nb_forward, _el_id, ...contactCols } = row;
    const contact = contactCols as ContactRow;
    return {
      contact,
      nb_forward: _nb_forward ?? 0,
      nb_reply: _nb_reply ?? 0,
      latest_email_log: _el_id !== null ? (logMap.get(_el_id) ?? null) : null,
      website_send_to: reverseAliasDisplay(contact, user.sender_format),
    };
  });
}

async function renderContactManager(
  c: Ctx,
  user: UserRow,
  alias: AliasRow,
  opts: {
    page: number;
    query: string;
    highlightContactId: number | null;
    emailFieldValue?: string;
    emailFieldErrors?: string[];
  },
): Promise<Response> {
  const db = c.env.DB;
  let contactInfos = await getContactInfos(db, user, alias, {
    page: opts.page,
    query: opts.query,
  });
  const lastPage = contactInfos.length < PAGE_LIMIT;
  const nbContact = await db
    .prepare("SELECT COUNT(*) AS n FROM contact WHERE alias_id = ?1")
    .bind(alias.id)
    .first<{ n: number }>();

  if (
    opts.highlightContactId !== null &&
    !contactInfos.some((ci) => ci.contact.id === opts.highlightContactId)
  ) {
    const highlighted = await getContactInfos(db, user, alias, {
      contactId: opts.highlightContactId,
      query: opts.query,
    });
    contactInfos = [...highlighted, ...contactInfos];
  }

  // alias.mailboxes for the "How to use" box
  const amRows = await db
    .prepare(
      "SELECT mailbox_id FROM alias_mailbox WHERE alias_id = ?1 ORDER BY id",
    )
    .bind(alias.id)
    .all<{ mailbox_id: number }>();
  const mbIds = [alias.mailbox_id];
  for (const r of amRows.results)
    if (!mbIds.includes(r.mailbox_id)) mbIds.push(r.mailbox_id);
  const aliasMailboxes: MailboxRow[] = [];
  for (const id of mbIds) {
    const mb = await getMailboxById(db, id);
    if (mb?.verified) aliasMailboxes.push(mb);
  }
  aliasMailboxes.sort((a, b) =>
    a.email < b.email ? -1 : a.email > b.email ? 1 : 0,
  );
  const primaryMb = await getMailboxById(db, alias.mailbox_id);

  const currentUser = await buildCurrentUser(c, user);
  const token = await generateCsrfToken(c);
  const csrfForm = { csrf_token: csrfTokenField(token) };
  const newContactForm = {
    csrf_token: csrfTokenField(token),
    email: makeField(
      { name: "email", label: "Email", value: opts.emailFieldValue ?? "" },
      opts.emailFieldErrors ?? [],
    ),
  };

  return webRender(
    c,
    "dashboard/alias_contact_manager.html",
    {
      contact_infos: contactInfos,
      alias,
      alias_mailboxes: aliasMailboxes.map((m) => ({
        id: m.id,
        email: m.email,
      })),
      alias_mailbox_email: primaryMb?.email ?? "",
      new_contact_form: newContactForm,
      highlight_contact_id: opts.highlightContactId,
      page: opts.page,
      last_page: lastPage,
      query: opts.query,
      nb_contact: nbContact?.n ?? 0,
      can_create_contacts: await canCreateContactsWeb(db, c.env, user),
      csrf_form: csrfForm,
    },
    { currentUser },
  );
}

webAliasPagesRoutes.on(
  ["GET", "POST"],
  "/alias_contact_manager/:alias_id{[0-9]+}",
  requireWebLogin,
  async (c) => {
    const user = c.get("webUser");
    const db = c.env.DB;
    const aliasId = Number(c.req.param("alias_id"));

    let highlightContactId: number | null = null;
    const rawHighlight = c.req.query("highlight_contact_id");
    if (rawHighlight) {
      highlightContactId = pyInt(rawHighlight);
      if (highlightContactId === null) {
        await flash(c, "Invalid contact id", "error");
        return c.redirect(urlFor("dashboard.index"), 302);
      }
    }
    const page = pyInt(c.req.query("page")) ?? 0;
    const query = c.req.query("query") ?? "";

    const alias = await db
      .prepare("SELECT * FROM alias WHERE id = ?1")
      .bind(aliasId)
      .first<AliasRow>();
    if (!alias || alias.user_id !== user.id) {
      await flash(c, "You do not have access to this page", "warning");
      return c.redirect(urlFor("dashboard.index"), 302);
    }

    if (c.req.method === "POST") {
      const body = await readForm(c);
      if (!(await csrfOk(c, body))) {
        await flash(c, "Invalid request", "warning");
        return c.redirect(reqUrl(c), 302);
      }
      const formName = formGet(body, "form-name");

      if (formName === "create") {
        // NewContactForm validation
        const rawEmail = formGet(body, "email") ?? "";
        const errors: string[] = [];
        if (!rawEmail) {
          errors.push("This field is required.");
        } else {
          const stripped = rawEmail.trim();
          let emailPart = stripped;
          const lt = stripped.indexOf("<");
          const gt = stripped.indexOf(">");
          if (lt >= 0 && gt >= 0 && lt + 1 < gt) {
            emailPart = stripped.slice(lt + 1, gt).trim();
          }
          if (!isValidEmail(emailPart)) {
            errors.push(
              "Invalid email format. Email must be either email@example.com or *First Last <email@example.com>*",
            );
          }
        }
        if (errors.length > 0) {
          return renderContactManager(c, user, alias, {
            page,
            query,
            highlightContactId,
            emailFieldValue: rawEmail,
            emailFieldErrors: errors,
          });
        }
        const contactAddress = rawEmail.trim();
        const result = await createContactWeb(
          db,
          c.env,
          user,
          alias,
          contactAddress,
        );
        if (result.error) {
          await flash(c, result.error, "error");
          return c.redirect(reqUrl(c), 302);
        }
        await flash(
          c,
          `Reverse alias for ${contactAddress} is created`,
          "success",
        );
        return c.redirect(
          urlFor("dashboard.alias_contact_manager", {
            alias_id: aliasId,
            highlight_contact_id: result.contact?.id,
          }),
          302,
        );
      }

      if (formName === "delete") {
        const rawContactId = formGet(body, "contact-id");
        const contactId = pyInt(rawContactId ?? "");
        const contact =
          contactId !== null ? await getContactById(db, contactId) : null;
        if (!contact) {
          await flash(c, "Unknown error. Refresh the page", "warning");
        } else if (contact.alias_id !== alias.id) {
          await flash(c, "You cannot delete reverse-alias", "warning");
        } else {
          await db
            .prepare("DELETE FROM contact WHERE id = ?1")
            .bind(contact.id)
            .run();
          await flash(
            c,
            `Reverse-alias for ${contact.website_email} has been deleted`,
            "success",
          );
        }
        return c.redirect(
          urlFor("dashboard.alias_contact_manager", { alias_id: aliasId }),
          302,
        );
      }

      if (formName === "search") {
        const q = formGet(body, "query") ?? "";
        return c.redirect(
          urlFor("dashboard.alias_contact_manager", {
            alias_id: aliasId,
            query: q,
            highlight_contact_id: highlightContactId,
          }),
          302,
        );
      }
      // unknown form-name: fall through to render
    }

    return renderContactManager(c, user, alias, {
      page,
      query,
      highlightContactId,
    });
  },
);

// ---------------------------------------------------------------------------
// 9. GET|POST /dashboard/contact/<contact_id> — PGP page
// ---------------------------------------------------------------------------

webAliasPagesRoutes.on(
  ["GET", "POST"],
  "/contact/:contact_id{[0-9]+}",
  requireWebLogin,
  async (c) => {
    const user = c.get("webUser");
    const db = c.env.DB;
    const contactId = Number(c.req.param("contact_id"));

    const contact = await getContactById(db, contactId);
    // NB: this page checks the contact's own user_id column.
    if (!contact || contact.user_id !== user.id) {
      await flash(c, "You cannot see this page", "warning");
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    const alias = await db
      .prepare("SELECT * FROM alias WHERE id = ?1")
      .bind(contact.alias_id)
      .first<AliasRow>();

    // pgp_public_key shown in the textarea (in-memory mutation on failed save)
    let displayedKey = contact.pgp_public_key;

    if (c.req.method === "POST") {
      const body = await readForm(c);
      if (formGet(body, "form-name") === "pgp") {
        const action = formGet(body, "action");
        const csrfErr = await validateCsrfToken(
          c,
          formGet(body, "csrf_token") ?? null,
          c.get("webSession"),
        );
        const validAction = action === "save" || action === "remove";
        if (csrfErr !== null || !validAction) {
          await flash(c, "Invalid request", "warning");
          return c.redirect(reqUrl(c), 302);
        }
        if (action === "save") {
          const premium = await userIsPremium(db, user);
          if (!premium) {
            await flash(c, "Only premium plan can add PGP Key", "warning");
            return c.redirect(
              urlFor("dashboard.contact_detail_route", {
                contact_id: contactId,
              }),
              302,
            );
          }
          const pgp = formGet(body, "pgp") ?? "";
          if (!pgp) {
            // Flask: flash("Invalid pgp key") — no category -> "message"
            await flash(c, "Invalid pgp key", "message" as FlashCategory);
            // falls through to re-render
          } else {
            // BLOCKER B1: no GnuPG/OpenPGP on Workers yet — behave like a
            // PGPException: show the rejected key once, do not persist.
            displayedKey = pgp;
            await flash(
              c,
              "Cannot add the public key, please verify it",
              "error",
            );
            // falls through to re-render
          }
        } else {
          // remove — allowed for free users too
          await db
            .prepare(
              "UPDATE contact SET pgp_public_key = NULL, pgp_finger_print = NULL, updated_at = ?1 WHERE id = ?2",
            )
            .bind(nowStr(), contact.id)
            .run();
          await flash(
            c,
            `PGP public key for ${contact.website_email} is removed`,
            "success",
          );
          return c.redirect(
            urlFor("dashboard.contact_detail_route", { contact_id: contactId }),
            302,
          );
        }
      }
      // form-name != "pgp" (or fall-through above): re-render, no flash
    }

    const currentUser = await buildCurrentUser(c, user);
    const token = await generateCsrfToken(c);
    return webRender(
      c,
      "dashboard/contact_detail.html",
      {
        contact: {
          id: contact.id,
          email: contact.website_email,
          pgp_public_key: displayedKey,
          pgp_finger_print: contact.pgp_finger_print,
        },
        alias,
        pgp_form: { csrf_token: csrfTokenField(token) },
      },
      { currentUser },
    );
  },
);
