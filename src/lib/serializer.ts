/**
 * Alias & contact serializers ported from app/api/serializer.py + the relevant
 * Contact/EmailLog methods in app/models.py. See specs/02-aliases.md.
 *
 * Date fields: `creation_date` etc. are returned verbatim from the stored
 * column (already arrow's "YYYY-MM-DD HH:MM:SS+00:00"); `*_timestamp` are
 * integer unix seconds via toEpoch. Booleans are emitted as JSON true/false.
 */

import type { AliasRow, ContactRow, EmailLogRow, MailboxRow, UserRow } from "./rows";
import { toDate, toEpoch } from "./dates";
import { getContactById, getMailboxById } from "./models";

const PAGE_LIMIT = 20; // config.PAGE_LIMIT

// SenderFormatEnum values (models.py L209): AT=0, A=2, NAME_ONLY=5, AT_ONLY=6, NO_NAME=7
const SENDER_FORMAT_VALUES = new Set([0, 2, 5, 6, 7]);

interface MailboxLite {
  id: number;
  email: string;
}

/** Mirror of app.api.serializer.AliasInfo (the fields the serializers read). */
export interface AliasInfo {
  alias: AliasRow;
  /** primary mailbox = alias.mailbox */
  mailbox: MailboxLite;
  mailboxes: MailboxLite[];
  nb_forward: number;
  nb_blocked: number;
  nb_reply: number;
  /** Alias.mailbox_support_pgp() — computed over verified mailboxes. */
  supportPgp: boolean;
  latestEmailLog: EmailLogRow | null;
  latestContact: ContactRow | null;
  /** owner user's sender_format, for the reverse_alias display string. */
  senderFormat: number;
}

/** EmailLog.get_action(): reply | bounced | block | forward (models.py L2333). */
export function emailLogAction(log: EmailLogRow): "reply" | "bounced" | "block" | "forward" {
  if (log.is_reply) return "reply";
  if (log.bounced) return "bounced";
  if (log.blocked) return "block";
  return "forward";
}

/**
 * Best-effort flanker `address.parse(...).display_name`: pull the display name
 * out of a "Name <email>" header, stripping surrounding quotes. Bare addresses
 * (and unparseable input) yield "".
 */
function parseDisplayName(raw: string): string {
  const m = raw.match(/^\s*(.*?)\s*<[^>]*>\s*$/);
  if (!m) return "";
  let name = m[1].trim();
  if (name.length >= 2 && name.startsWith('"') && name.endsWith('"')) {
    name = name.slice(1, -1);
  }
  return name;
}

/**
 * Contact.website_send_to() (models.py L2161) — the "reverse_alias" display
 * string `"{name} | {email}" <reply_email>` where the email's "@" is rewritten
 * per the owner's sender_format. When senderFormat is null/unknown/AT the "@"
 * becomes " at "; A(2) uses "(a)"; 5/6/7 leave the address untouched.
 */
export function reverseAliasDisplay(contact: ContactRow, senderFormat: number | null): string {
  let email = contact.website_email;
  const known = senderFormat !== null && SENDER_FORMAT_VALUES.has(senderFormat);
  if (senderFormat === null || !known || senderFormat === 0) {
    email = email.replaceAll("@", " at ");
  } else if (senderFormat === 2) {
    email = email.replaceAll("@", "(a)");
  }

  let name = contact.name;
  if (!name && contact.website_from) name = parseDisplayName(contact.website_from);
  if (name) name = name.replaceAll('"', "");

  const display = name ? `${name} | ${email}` : email;
  return `"${display}" <${contact.reply_email}>`;
}

/** serialize_alias_info (v1) — note the key is `nb_block`, not `nb_blocked`. */
export function serializeAliasInfo(info: AliasInfo): Record<string, unknown> {
  return {
    id: info.alias.id,
    email: info.alias.email,
    creation_date: info.alias.created_at,
    creation_timestamp: toEpoch(info.alias.created_at),
    enabled: !!info.alias.enabled,
    note: info.alias.note,
    nb_forward: info.nb_forward,
    nb_block: info.nb_blocked,
    nb_reply: info.nb_reply,
  };
}

/** serialize_alias_info_v2. */
export function serializeAliasInfoV2(info: AliasInfo): Record<string, unknown> {
  const res: Record<string, unknown> = {
    id: info.alias.id,
    email: info.alias.email,
    creation_date: info.alias.created_at,
    creation_timestamp: toEpoch(info.alias.created_at),
    enabled: !!info.alias.enabled,
    note: info.alias.note,
    name: info.alias.name,
    nb_forward: info.nb_forward,
    nb_block: info.nb_blocked,
    nb_reply: info.nb_reply,
    mailbox: { id: info.mailbox.id, email: info.mailbox.email },
    mailboxes: info.mailboxes.map((m) => ({ id: m.id, email: m.email })),
    support_pgp: info.supportPgp,
    disable_pgp: !!info.alias.disable_pgp,
    latest_activity: null,
    pinned: !!info.alias.pinned,
  };

  if (info.latestEmailLog && info.latestContact) {
    const log = info.latestEmailLog;
    const contact = info.latestContact;
    res.latest_activity = {
      timestamp: toEpoch(log.created_at),
      action: emailLogAction(log),
      contact: {
        email: contact.website_email,
        name: contact.name,
        reverse_alias: reverseAliasDisplay(contact, info.senderFormat),
      },
    };
  }
  return res;
}

/**
 * serialize_contact (specs/02 §11). `lastReply` is Contact.last_reply() — the
 * caller passes it (the serializer is otherwise pure); when omitted the
 * last_email_sent_* fields stay null.
 */
export function serializeContact(
  contact: ContactRow,
  existed = false,
  user?: UserRow,
  lastReply?: EmailLogRow | null,
): Record<string, unknown> {
  const res: Record<string, unknown> = {
    id: contact.id,
    creation_date: contact.created_at,
    creation_timestamp: toEpoch(contact.created_at),
    last_email_sent_date: null,
    last_email_sent_timestamp: null,
    contact: contact.website_email,
    reverse_alias: reverseAliasDisplay(contact, user?.sender_format ?? null),
    reverse_alias_address: contact.reply_email,
    existed,
    block_forward: !!contact.block_forward,
  };
  if (lastReply) {
    res.last_email_sent_date = lastReply.created_at;
    res.last_email_sent_timestamp = toEpoch(lastReply.created_at);
  }
  return res;
}

async function fetchMailboxMap(db: D1Database, ids: number[]): Promise<Map<number, MailboxRow>> {
  const map = new Map<number, MailboxRow>();
  if (ids.length === 0) return map;
  const placeholders = ids.map((_, i) => `?${i + 1}`).join(", ");
  const res = await db
    .prepare(`SELECT * FROM mailbox WHERE id IN (${placeholders})`)
    .bind(...ids)
    .all<MailboxRow>();
  for (const m of res.results) map.set(m.id, m);
  return map;
}

/**
 * get_alias_info_v2 (specs/02 §3): counts iterate ALL (contact, email_log) for
 * the alias; latest activity is the log with created_at *strictly greater* than
 * alias.created_at. Mailboxes are set-based and *include unverified* secondary
 * mailboxes (unlike the list endpoints); support_pgp is still computed over the
 * verified mailboxes only.
 */
export async function getAliasInfoV2(db: D1Database, alias: AliasRow, user: UserRow): Promise<AliasInfo> {
  const primary = await getMailboxById(db, alias.mailbox_id);

  const amRows = await db
    .prepare("SELECT mailbox_id FROM alias_mailbox WHERE alias_id = ?1 ORDER BY id")
    .bind(alias.id)
    .all<{ mailbox_id: number }>();
  const ids = [alias.mailbox_id];
  for (const r of amRows.results) if (!ids.includes(r.mailbox_id)) ids.push(r.mailbox_id);

  const mbMap = await fetchMailboxMap(db, ids);
  const mailboxes: MailboxLite[] = ids
    .map((id) => mbMap.get(id))
    .filter((m): m is MailboxRow => !!m)
    .map((m) => ({ id: m.id, email: m.email }));
  const supportPgp = ids.some((id) => {
    const m = mbMap.get(id);
    return !!m && !!m.verified && !!m.pgp_finger_print && !m.disable_pgp;
  });

  const logs = await db
    .prepare(
      `SELECT el.* FROM email_log el JOIN contact c ON el.contact_id = c.id
       WHERE c.alias_id = ?1 ORDER BY el.created_at, el.id`,
    )
    .bind(alias.id)
    .all<EmailLogRow>();

  let nbReply = 0;
  let nbBlocked = 0;
  let nbForward = 0;
  let latestEmailLog: EmailLogRow | null = null;
  let latestActivity = toDate(alias.created_at).getTime();
  for (const el of logs.results) {
    if (el.is_reply) nbReply++;
    else if (el.blocked) nbBlocked++;
    else nbForward++;

    const t = toDate(el.created_at).getTime();
    if (t > latestActivity) {
      latestActivity = t;
      latestEmailLog = el;
    }
  }

  const latestContact = latestEmailLog ? await getContactById(db, latestEmailLog.contact_id) : null;

  return {
    alias,
    mailbox: primary ? { id: primary.id, email: primary.email } : { id: alias.mailbox_id, email: "" },
    mailboxes,
    nb_forward: nbForward,
    nb_blocked: nbBlocked,
    nb_reply: nbReply,
    supportPgp,
    latestEmailLog,
    latestContact,
    senderFormat: user.sender_format,
  };
}

export interface AliasListOptions {
  query?: string | null;
  /** presence-based filters, precedence pinned > disabled > enabled */
  pinned?: boolean;
  disabled?: boolean;
  enabled?: boolean;
}

/**
 * get_alias_infos_with_pagination_v3 (specs/02 §2) translated to SQLite.
 *
 * Counts come from an activity subquery joined on alias.id = email_log.alias_id.
 * Latest activity comes from the alias.last_email_log_id join (NOT a MAX()).
 * Default sort: pinned DESC, then MAX(created_at, latest-log created_at) DESC
 * (SQLite MAX(a,b) returns NULL if either arg is NULL, so IFNULL emulates
 * Postgres GREATEST's NULL-skipping), with id DESC as a deterministic tiebreak
 * (spec 06 recommends an id tiebreak given second-precision timestamps).
 *
 * The `query` filter approximates the Postgres note ts_vector full-text branch
 * with a LIKE over note, plus LIKE over email and name (wildcards in the raw
 * query are preserved by concatenating into the LIKE pattern, like ILIKE did).
 */
export async function getAliasInfosWithPaginationV3(
  db: D1Database,
  user: UserRow,
  pageId: number,
  opts: AliasListOptions = {},
): Promise<AliasInfo[]> {
  const conds: string[] = [];
  const filterParams: unknown[] = [];

  if (opts.query) {
    conds.push("(a.email LIKE '%' || ? || '%' OR a.note LIKE '%' || ? || '%' OR a.name LIKE '%' || ? || '%')");
    filterParams.push(opts.query, opts.query, opts.query);
  }
  if (opts.pinned) conds.push("a.pinned = 1");
  else if (opts.disabled) conds.push("a.enabled = 0");
  else if (opts.enabled) conds.push("a.enabled = 1");

  const whereExtra = conds.length ? ` AND ${conds.join(" AND ")}` : "";

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
    ORDER BY a.pinned DESC,
             MAX(a.created_at, IFNULL(el.created_at, a.created_at)) DESC,
             a.id DESC
    LIMIT ? OFFSET ?`;

  const bind = [user.id, ...filterParams, PAGE_LIMIT, pageId * PAGE_LIMIT];
  const rows = await db
    .prepare(sql)
    .bind(...bind)
    .all<AliasRow & { _nb_reply: number; _nb_blocked: number; _nb_forward: number }>();

  if (rows.results.length === 0) return [];

  // Batch-load the latest email_log + contact for the page.
  const logIds = [
    ...new Set(rows.results.map((r) => r.last_email_log_id).filter((v): v is number => v !== null)),
  ];
  const logMap = new Map<number, EmailLogRow>();
  if (logIds.length > 0) {
    const ph = logIds.map((_, i) => `?${i + 1}`).join(", ");
    const res = await db.prepare(`SELECT * FROM email_log WHERE id IN (${ph})`).bind(...logIds).all<EmailLogRow>();
    for (const l of res.results) logMap.set(l.id, l);
  }
  const contactIds = [...new Set([...logMap.values()].map((l) => l.contact_id))];
  const contactMap = new Map<number, ContactRow>();
  if (contactIds.length > 0) {
    const ph = contactIds.map((_, i) => `?${i + 1}`).join(", ");
    const res = await db.prepare(`SELECT * FROM contact WHERE id IN (${ph})`).bind(...contactIds).all<ContactRow>();
    for (const c of res.results) contactMap.set(c.id, c);
  }

  // Batch-load mailboxes (primary + additional) for the page.
  const aliasIds = rows.results.map((r) => r.id);
  const amPh = aliasIds.map((_, i) => `?${i + 1}`).join(", ");
  const amRes = await db
    .prepare(`SELECT alias_id, mailbox_id FROM alias_mailbox WHERE alias_id IN (${amPh}) ORDER BY id`)
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
  for (const list of additionalByAlias.values()) for (const id of list) allMailboxIds.add(id);
  const mbMap = await fetchMailboxMap(db, [...allMailboxIds]);

  return rows.results.map((row) => {
    const { _nb_reply, _nb_blocked, _nb_forward, ...aliasCols } = row;
    const alias = aliasCols as AliasRow;

    // Alias.mailboxes property: [primary] + additional, deduped, verified-only, email-sorted.
    const ids = [alias.mailbox_id];
    for (const id of additionalByAlias.get(alias.id) ?? []) if (!ids.includes(id)) ids.push(id);
    const verified = ids
      .map((id) => mbMap.get(id))
      .filter((m): m is MailboxRow => !!m && !!m.verified)
      .sort((a, b) => (a.email < b.email ? -1 : a.email > b.email ? 1 : 0));
    const mailboxes: MailboxLite[] = verified.map((m) => ({ id: m.id, email: m.email }));
    const supportPgp = verified.some((m) => !!m.pgp_finger_print && !m.disable_pgp);

    const primary = mbMap.get(alias.mailbox_id);
    const latestEmailLog = alias.last_email_log_id ? logMap.get(alias.last_email_log_id) ?? null : null;
    const latestContact = latestEmailLog ? contactMap.get(latestEmailLog.contact_id) ?? null : null;

    return {
      alias,
      mailbox: primary ? { id: primary.id, email: primary.email } : { id: alias.mailbox_id, email: "" },
      mailboxes,
      nb_forward: _nb_forward,
      nb_blocked: _nb_blocked,
      nb_reply: _nb_reply,
      supportPgp,
      latestEmailLog,
      latestContact,
      senderFormat: user.sender_format,
    };
  });
}
