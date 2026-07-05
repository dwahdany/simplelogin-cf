/**
 * Server-rendered mailbox / custom-domain / subdomain / directory /
 * batch-import / refused-email dashboard pages, ported per
 * specs/web/03-mailbox-domain-pages.md (Flask sources:
 * app/dashboard/views/{mailbox,mailbox_detail,custom_domain,domain_detail,
 * subdomain,directory,batch_import,refused_email}.py).
 *
 * Mounted at /dashboard (src/index.ts) — all paths here are relative.
 *
 * Deliberate deviations (documented in the port contract / agent notes):
 * - user_audit_log emission skipped (no table in the D1 schema, port-wide stance).
 * - parallel_limiter.lock is a no-op (Flask behavior without Redis).
 * - DNS checks go through DNS-over-HTTPS (cloudflare-dns.com); any lookup
 *   error behaves as "no records", like Flask swallowing dnspython errors.
 * - PGP key import is DEFERRED (no GPG on Workers): `form-name=pgp action=save`
 *   flashes the exact PGPException message and stores nothing.
 * - Mailbox.is_proton() uses only the static domain list (no MX lookup).
 * - S3 uploads/presigned URLs are replaced by KV objects (`file:<path>`)
 *   served from GET /dashboard/files/<path> with an ownership check.
 * - Legacy itsdangerous-signed links (mailbox_verify / confirm_change without
 *   `code`) are rejected with the documented "Invalid link" flashes.
 */

import type { Context, MiddlewareHandler } from "hono";
import { Hono } from "hono";
import { randomString, sanitizeEmail, tokenUrlsafe } from "../lib/crypto";
import { addDays, nowStr, toDate, toStr } from "../lib/dates";
import type { Env } from "../lib/env";
import { sendTransactionalEmail } from "../lib/mailer";
import {
  getCustomDomainById,
  getMailboxById,
  userIsPremium,
} from "../lib/models";
import type {
  AliasRow,
  CustomDomainRow,
  DirectoryRow,
  DomainDeletedAliasRow,
  MailboxRow,
  PublicDomainRow,
  UserRow,
} from "../lib/rows";
import {
  csrfTokenField,
  generateCsrfToken,
  makeField,
  validateCsrfToken,
} from "../lib/web/forms";
import {
  buildCurrentUser,
  type CurrentUserCtx,
  flash,
  renderErrorPage,
  webRender,
} from "../lib/web/render";
import { urlFor } from "../lib/web/urls";
import {
  requireWebLogin,
  requireWebSudo,
  type WebEnv,
} from "../lib/web/webauth";

export const webMailboxDomainPagesRoutes = new Hono<WebEnv>();

type C = Context<WebEnv>;

// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

const FLAG_ADMIN_DISABLED = 1; // Mailbox.FLAG_ADMIN_DISABLED
const MAX_ACTIVATION_TRIES = 3;
const MAX_MAILBOXES_PER_DOMAIN = 20;
const MAX_NB_SUBDOMAIN = 5;
const MAX_NB_DIRECTORY = 50;
const ALIAS_TRASH_DAYS = 30;
const DELETE_IMMEDIATELY = 1; // UserAliasDeleteAction.DeleteImmediately
const REASON_DIRECTORY_DELETED = 3; // AliasDeleteReason.DirectoryDeleted
const DMARC_RECORD = "v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s";
const PROTON_EMAIL_DOMAINS = [
  "proton.me",
  "protonmail.com",
  "protonmail.ch",
  "proton.ch",
  "pm.me",
];

type EnvX = Env & Record<string, string | undefined>;

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

function redirectSelf(c: C): Response {
  const u = new URL(c.req.url);
  return c.redirect(u.pathname + u.search, 302);
}

/** Read a form field as a string (files -> null). */
function field(fd: FormData, name: string): string | null {
  const v = fd.get(name);
  return typeof v === "string" ? v : null;
}

// NB: render paths call `generateCsrfToken(c)` WITHOUT the middleware's
// webSession snapshot — the helper saves the session it is given, and saving a
// stale snapshot would clobber flashes queued earlier in the same request.
async function csrfOk(c: C, fd: FormData): Promise<boolean> {
  const err = await validateCsrfToken(
    c,
    field(fd, "csrf_token"),
    c.get("webSession"),
  );
  return err === null;
}

/** wtforms IntegerField coercion + DataRequired (0 is falsy => required error). */
function intFieldRequired(raw: string | null): number | null {
  if (raw === null || raw.trim() === "") return null;
  if (!/^[+-]?\d+$/.test(raw.trim())) return null;
  const n = Number.parseInt(raw.trim(), 10);
  return n === 0 ? null : n;
}

/** wtforms 2.3.3 Email() validator regex `^.+@([^.@][^@]+)$` — spaces pass! */
function isEmailFieldValid(v: string): boolean {
  return /^.+@[^.@][^@]+$/.test(v);
}

/** is_valid_domain (RFC-1035 label check, app/custom_domain_utils.py). */
function isValidDomain(domain: string): boolean {
  let d = domain;
  if (d.endsWith(".")) d = d.slice(0, -1);
  if (d.length === 0 || d.length > 255) return false;
  return d
    .split(".")
    .every(
      (label) =>
        /^[A-Za-z0-9-]{1,63}$/.test(label) &&
        !label.startsWith("-") &&
        !label.endsWith("-"),
    );
}

function isAdminDisabled(mb: MailboxRow): boolean {
  return (mb.flags & FLAG_ADMIN_DISABLED) === FLAG_ADMIN_DISABLED;
}

/** Mailbox.is_proton() — static domain-suffix half only (MX half deferred). */
function isProton(mb: MailboxRow): boolean {
  const domain = mb.email.slice(mb.email.lastIndexOf("@") + 1);
  return PROTON_EMAIL_DOMAINS.includes(domain);
}

/** Web rate limit (flask-limiter key userid:{id}); 429 -> HTML error page. */
function webRateLimit(
  name: string,
  limit: number,
  seconds: number,
  methods?: string[],
): MiddlewareHandler<WebEnv> {
  return async (c, next) => {
    if (c.env.DISABLE_RATE_LIMIT) return next();
    if (methods && !methods.includes(c.req.method)) return next();
    const user = c.get("webUser");
    const windowStart = Math.floor(Date.now() / 1000 / seconds);
    const row = await c.env.DB.prepare(
      `INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, 1)
       ON CONFLICT(key) DO UPDATE SET
         count = CASE WHEN window_start = ?2 THEN count + 1 ELSE 1 END,
         window_start = ?2
       RETURNING count`,
    )
      .bind(`rlweb:${name}:userid:${user.id}:${seconds}`, windowStart)
      .first<{ count: number }>();
    if ((row?.count ?? 1) > limit) {
      return renderErrorPage(c, 429, await buildCurrentUser(c, user));
    }
    return next();
  };
}

// ---------------------------------------------------------------------------
// current_user view-model extras used by this page group's templates
// ---------------------------------------------------------------------------

async function buildPageUser(c: C, user: UserRow): Promise<CurrentUserCtx> {
  const db = c.env.DB;
  const base = await buildCurrentUser(c, user);
  const defaultMailbox = user.default_mailbox_id
    ? await getMailboxById(db, user.default_mailbox_id)
    : null;
  const subCount = await db
    .prepare(
      "SELECT COUNT(*) AS n FROM custom_domain WHERE user_id = ?1 AND is_sl_subdomain = 1",
    )
    .bind(user.id)
    .first<{ n: number }>();
  const dirCount = await db
    .prepare("SELECT COUNT(*) AS n FROM directory WHERE user_id = ?1")
    .bind(user.id)
    .first<{ n: number }>();
  return {
    ...base,
    default_mailbox_id: user.default_mailbox_id,
    default_mailbox: { email: defaultMailbox?.email ?? "" },
    include_sender_in_reverse_alias: !!user.include_sender_in_reverse_alias,
    subdomain_quota: Math.min(
      user.subdomain_quota,
      MAX_NB_SUBDOMAIN - (subCount?.n ?? 0),
    ),
    directory_quota: Math.min(
      user.directory_quota,
      MAX_NB_DIRECTORY - (dirCount?.n ?? 0),
    ),
  } as CurrentUserCtx;
}

async function render(
  c: C,
  template: string,
  activePage: string | null,
  pageCtx: Record<string, unknown>,
  status = 200,
): Promise<Response> {
  const currentUser = await buildPageUser(c, c.get("webUser"));
  return webRender(
    c,
    template,
    { active_page: activePage, ...pageCtx },
    { currentUser, status },
  );
}

// ---------------------------------------------------------------------------
// mailbox helpers (private ports of app/mailbox_utils.py, mirroring
// src/routes/mailboxes.ts which cannot be imported from here)
// ---------------------------------------------------------------------------

const ATEXT = "A-Za-z0-9!#$%&'*+\\-/=?^_`{|}~";
const LOCAL_RE = new RegExp(`^[${ATEXT}]+(?:\\.[${ATEXT}]+)*$`);
const DOMAIN_LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

function isValidMailboxDomainSyntax(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  if (!domain.includes(".")) return false;
  if (!/[A-Za-z]$/.test(domain)) return false;
  for (const label of domain.split(".")) {
    if (!DOMAIN_LABEL_RE.test(label)) return false;
  }
  return true;
}

/** app/email_validation.py is_valid_email — RFC dot-atom, ASCII only. */
function isValidEmail(email: string): boolean {
  if (!email || email.length > 254) return false;
  if (!/^[\x21-\x7e]+$/.test(email)) return false;
  const at = email.lastIndexOf("@");
  if (at <= 0 || at === email.length - 1) return false;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (local.length > 64) return false;
  if (!LOCAL_RE.test(local)) return false;
  return isValidMailboxDomainSyntax(domain);
}

async function emailCannotBeUsedReason(
  db: D1Database,
  email: string,
): Promise<string | null> {
  const domain = email.slice(email.lastIndexOf("@") + 1);
  if (!domain.includes(".")) return "This email domain is not valid";
  const slDomain = await db
    .prepare("SELECT 1 FROM public_domain WHERE domain = ?1")
    .bind(domain)
    .first();
  if (slDomain) return "This email is a SimpleLogin domain";
  const customDomain = await db
    .prepare("SELECT 1 FROM custom_domain WHERE domain = ?1 AND verified = 1")
    .bind(domain)
    .first();
  if (customDomain) {
    return "This email address belongs to a custom domain that has already been registered";
  }
  const disabledUser = await db
    .prepare("SELECT 1 FROM users WHERE email = ?1 AND disabled = 1")
    .bind(email)
    .first();
  if (disabledUser) return "This email address is not allowed";
  const disabledMailboxOwner = await db
    .prepare(
      `SELECT 1 FROM mailbox m JOIN users u ON u.id = m.user_id
       WHERE m.email = ?1 AND u.disabled = 1 LIMIT 1`,
    )
    .bind(email)
    .first();
  if (disabledMailboxOwner) return "This email address is not allowed";
  return null;
}

/** check_email_for_mailbox: MailboxError message or null. */
async function checkEmailForMailbox(
  db: D1Database,
  email: string,
  user: UserRow,
): Promise<string | null> {
  if (!isValidEmail(email)) return "Invalid email";
  const alreadyUsed = await db
    .prepare("SELECT 1 FROM mailbox WHERE email = ?1 AND user_id = ?2")
    .bind(email, user.id)
    .first();
  if (alreadyUsed) return "Email already used";
  const reason = await emailCannotBeUsedReason(db, email);
  if (reason) return `Invalid email: ${reason}`;
  return null;
}

/** mailbox.nb_alias(): trashed aliases excluded. */
async function countMailboxAliases(
  db: D1Database,
  mailboxId: number,
): Promise<number> {
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS n FROM (
         SELECT am.alias_id AS aid FROM alias_mailbox am
           JOIN alias a ON a.id = am.alias_id
          WHERE am.mailbox_id = ?1 AND a.delete_on IS NULL
         UNION
         SELECT id AS aid FROM alias
          WHERE mailbox_id = ?1 AND delete_on IS NULL
       )`,
    )
    .bind(mailboxId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

async function generateActivationCode(
  db: D1Database,
  mailboxId: number,
): Promise<string> {
  await db
    .prepare("DELETE FROM mailbox_activation WHERE mailbox_id = ?1")
    .bind(mailboxId)
    .run();
  const code = tokenUrlsafe(16);
  await db
    .prepare(
      "INSERT INTO mailbox_activation (mailbox_id, code, tries) VALUES (?1, ?2, 0)",
    )
    .bind(mailboxId, code)
    .run();
  return code;
}

async function clearActivationCodes(
  db: D1Database,
  mailboxId: number,
): Promise<void> {
  await db
    .prepare("DELETE FROM mailbox_activation WHERE mailbox_id = ?1")
    .bind(mailboxId)
    .run();
}

class MailboxError extends Error {
  constructor(public msg: string) {
    super(msg);
  }
}

/** mailbox_utils.verify_mailbox_code (also performs a pending email swap). */
async function verifyMailboxCode(
  db: D1Database,
  user: UserRow,
  mailboxId: number,
  code: string,
): Promise<MailboxRow> {
  const mailbox = Number.isFinite(mailboxId)
    ? await getMailboxById(db, mailboxId)
    : null;
  if (!mailbox || mailbox.user_id !== user.id) {
    throw new MailboxError("Invalid mailbox");
  }
  if (mailbox.verified && !mailbox.new_email) {
    await clearActivationCodes(db, mailbox.id);
    return mailbox;
  }
  const activation = await db
    .prepare(
      "SELECT * FROM mailbox_activation WHERE mailbox_id = ?1 ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(mailbox.id)
    .first<{ id: number; code: string; tries: number; created_at: string }>();
  if (!activation) throw new MailboxError("Invalid code");
  if (activation.tries >= MAX_ACTIVATION_TRIES) {
    await clearActivationCodes(db, mailbox.id);
    throw new MailboxError(
      "Invalid activation code. Please request another code.",
    );
  }
  if (toDate(activation.created_at).getTime() < Date.now() - 15 * 60 * 1000) {
    await clearActivationCodes(db, mailbox.id);
    throw new MailboxError(
      "Invalid activation code. Please request another code.",
    );
  }
  if (code !== activation.code) {
    await db
      .prepare("UPDATE mailbox_activation SET tries = tries + 1 WHERE id = ?1")
      .bind(activation.id)
      .run();
    throw new MailboxError("Invalid activation code");
  }
  if (mailbox.new_email) {
    await db
      .prepare(
        "UPDATE mailbox SET email = ?1, new_email = NULL, verified = 1, updated_at = ?2 WHERE id = ?3",
      )
      .bind(mailbox.new_email, nowStr(), mailbox.id)
      .run();
    mailbox.email = mailbox.new_email;
    mailbox.new_email = null;
    mailbox.verified = 1;
  } else if (!mailbox.verified) {
    await db
      .prepare("UPDATE mailbox SET verified = 1, updated_at = ?1 WHERE id = ?2")
      .bind(nowStr(), mailbox.id)
      .run();
    mailbox.verified = 1;
  }
  await clearActivationCodes(db, mailbox.id);
  return mailbox;
}

interface MailboxVM {
  id: number;
  email: string;
  verified: boolean;
  is_admin_disabled: boolean;
  pgp_enabled: boolean;
  created_at: string;
  nb_alias: number;
}

async function mailboxViewModel(
  db: D1Database,
  mb: MailboxRow,
): Promise<MailboxVM> {
  return {
    id: mb.id,
    email: mb.email,
    verified: !!mb.verified,
    is_admin_disabled: isAdminDisabled(mb),
    pgp_enabled: !!mb.pgp_finger_print && !mb.disable_pgp,
    created_at: mb.created_at,
    nb_alias: await countMailboxAliases(db, mb.id),
  };
}

/** Verified, non-admin-disabled mailboxes (routes 8/10/12 selects). */
async function selectableMailboxes(
  db: D1Database,
  userId: number,
): Promise<MailboxRow[]> {
  const res = await db
    .prepare("SELECT * FROM mailbox WHERE user_id = ?1 AND verified = 1")
    .bind(userId)
    .all<MailboxRow>();
  return res.results.filter((m) => !isAdminDisabled(m));
}

// ---------------------------------------------------------------------------
// DNS-over-HTTPS client (BLOCKER stance: replaces dns_utils.NetworkDNSClient;
// any lookup error behaves as "no records", never a 5xx)
// ---------------------------------------------------------------------------

interface DnsAnswer {
  name: string;
  type: number;
  data: string;
}

async function dohLookup(
  name: string,
  type: "TXT" | "MX" | "CNAME",
): Promise<DnsAnswer[]> {
  const typeNum = { TXT: 16, MX: 15, CNAME: 5 }[type];
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { accept: "application/dns-json" } },
    );
    if (!res.ok) return [];
    const json = (await res.json()) as { Answer?: DnsAnswer[] };
    return (json.Answer ?? []).filter((a) => a.type === typeNum);
  } catch {
    return [];
  }
}

/** TXT character-strings come back quoted (possibly chunked) — join + strip. */
function parseTxtData(data: string): string {
  const chunks = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
  return chunks.length ? chunks.join("") : data;
}

async function getTxtRecords(domain: string): Promise<string[]> {
  return (await dohLookup(domain, "TXT")).map((a) => parseTxtData(a.data));
}

/** MX records as {priority: [target-with-trailing-dot, ...]}. */
async function getMxDomains(domain: string): Promise<Map<number, string[]>> {
  const map = new Map<number, string[]>();
  for (const a of await dohLookup(domain, "MX")) {
    const m = a.data.match(/^(\d+)\s+(\S+)$/);
    if (!m) continue;
    const prio = Number(m[1]);
    let target = m[2];
    if (!target.endsWith(".")) target += ".";
    const list = map.get(prio) ?? [];
    list.push(target);
    map.set(prio, list);
  }
  return map;
}

async function getCnameRecord(name: string): Promise<string | null> {
  const answers = await dohLookup(name, "CNAME");
  if (answers.length === 0) return null;
  let data = answers[0].data;
  if (data.endsWith(".")) data = data.slice(0, -1);
  return data;
}

interface ExpectedMx {
  priority: number;
  recommended: string;
  allowed: string[];
}

/** config.EMAIL_SERVERS_WITH_PRIORITY, e.g. "10 mx1.sl.example.com., 20 mx2...". */
function expectedMxRecords(env: EnvX): ExpectedMx[] {
  const raw = env.EMAIL_SERVERS_WITH_PRIORITY;
  const records: ExpectedMx[] = [];
  if (raw) {
    for (const part of raw.split(",")) {
      const m = part.trim().match(/^(\d+)\s+(\S+)$/);
      if (!m) continue;
      let target = m[2];
      if (!target.endsWith(".")) target += ".";
      records.push({
        priority: Number(m[1]),
        recommended: target,
        allowed: [target],
      });
    }
  }
  if (records.length === 0) {
    records.push(
      {
        priority: 10,
        recommended: `mx1.${env.EMAIL_DOMAIN}.`,
        allowed: [`mx1.${env.EMAIL_DOMAIN}.`],
      },
      {
        priority: 20,
        recommended: `mx2.${env.EMAIL_DOMAIN}.`,
        allowed: [`mx2.${env.EMAIL_DOMAIN}.`],
      },
    );
  }
  return records.sort((a, b) => a.priority - b.priority);
}

/** dns_utils.is_mx_equivalent: positional match over ascending priorities. */
function isMxEquivalent(
  found: Map<number, string[]>,
  expected: ExpectedMx[],
): boolean {
  const prios = [...found.keys()].sort((a, b) => a - b);
  if (prios.length !== expected.length) return false;
  for (let i = 0; i < prios.length; i++) {
    const targets = found.get(prios[i]) ?? [];
    for (const t of targets) {
      if (!expected[i].allowed.includes(t)) return false;
    }
  }
  return true;
}

const DKIM_PREFIXES = [
  "dkim._domainkey",
  "dkim02._domainkey",
  "dkim03._domainkey",
];

// ---------------------------------------------------------------------------
// forms rendered by the templates
// ---------------------------------------------------------------------------

function csrfForm(token: string) {
  return { csrf_token: csrfTokenField(token) };
}

function emailForm(token: string, errors: string[] = [], value?: string) {
  return {
    csrf_token: csrfTokenField(token),
    email: makeField(
      { name: "email", type: "email", label: "email", value },
      errors,
    ),
  };
}

// ===========================================================================
// Route 1: GET|POST /mailbox
// ===========================================================================

async function renderMailboxPage(
  c: C,
  emailErrors: string[] = [],
): Promise<Response> {
  const db = c.env.DB;
  const user = c.get("webUser");
  const rows = await db
    .prepare(
      "SELECT * FROM mailbox WHERE user_id = ?1 ORDER BY created_at DESC, id DESC",
    )
    .bind(user.id)
    .all<MailboxRow>();
  const mailboxes = [];
  for (const mb of rows.results) mailboxes.push(await mailboxViewModel(db, mb));
  const token = await generateCsrfToken(c);
  return render(c, "dashboard-mailbox/mailbox.html", "mailbox", {
    mailboxes,
    new_mailbox_form: emailForm(token, emailErrors),
    delete_mailbox_form: csrfForm(token),
    csrf_form: csrfForm(token),
  });
}

webMailboxDomainPagesRoutes.on(
  ["GET", "POST"],
  "/mailbox",
  requireWebLogin,
  async (c) => {
    const db = c.env.DB;
    const user = c.get("webUser");
    if (c.req.method === "POST") {
      const fd = await c.req.formData();
      const formName = field(fd, "form-name");

      if (formName === "delete") {
        const ok = await csrfOk(c, fd);
        const mailboxId = intFieldRequired(field(fd, "mailbox_id"));
        const transferRaw = field(fd, "transfer_mailbox_id");
        let transferValid = true;
        let transferMailboxId: number | null = null;
        if (transferRaw !== null && transferRaw.trim() !== "") {
          if (!/^[+-]?\d+$/.test(transferRaw.trim())) transferValid = false;
          else transferMailboxId = Number.parseInt(transferRaw.trim(), 10);
        }
        if (!ok || mailboxId === null || !transferValid) {
          await flash(c, "Invalid request", "warning");
          return redirectSelf(c);
        }
        // admin-disabled pre-check happens BEFORE the ownership check (faithful)
        const anyMailbox = await getMailboxById(db, mailboxId);
        if (anyMailbox && isAdminDisabled(anyMailbox)) {
          await flash(
            c,
            "You cannot modify that mailbox. Please contact support.",
            "error",
          );
          return c.redirect(urlFor("dashboard.mailbox_route"), 302);
        }
        // mailbox_utils.delete_mailbox
        const mailbox =
          anyMailbox && anyMailbox.user_id === user.id ? anyMailbox : null;
        const fail = async (msg: string) => {
          await flash(c, msg, "warning");
          return c.redirect(urlFor("dashboard.mailbox_route"), 302);
        };
        if (!mailbox) return fail("Invalid mailbox");
        if (mailbox.id === user.default_mailbox_id) {
          return fail("Cannot delete your default mailbox");
        }
        const transferId =
          transferMailboxId !== null && transferMailboxId > 0
            ? transferMailboxId
            : null;
        if (transferId) {
          const transferMailbox = await getMailboxById(db, transferId);
          if (!transferMailbox || transferMailbox.user_id !== user.id) {
            return fail("You must transfer the aliases to a mailbox you own");
          }
          if (transferMailbox.id === mailbox.id) {
            return fail(
              "You can not transfer the aliases to the mailbox you want to delete",
            );
          }
          if (!transferMailbox.verified) {
            return fail("Your new mailbox is not verified");
          }
        }
        await db
          .prepare(
            "INSERT INTO job (name, payload, run_at) VALUES ('delete-mailbox', ?1, ?2)",
          )
          .bind(
            JSON.stringify({
              mailbox_id: mailbox.id,
              transfer_mailbox_id: transferId,
              send_mail: true,
            }),
            nowStr(),
          )
          .run();
        await flash(
          c,
          `Mailbox ${mailbox.email} scheduled for deletion.` +
            "You will receive a confirmation email when the deletion is finished",
          "success",
        );
        return c.redirect(urlFor("dashboard.mailbox_route"), 302);
      }

      if (formName === "set-default") {
        if (!(await csrfOk(c, fd))) {
          await flash(c, "Invalid request", "warning");
          return redirectSelf(c);
        }
        const rawId = field(fd, "mailbox_id");
        const mailboxId = rawId && /^\d+$/.test(rawId) ? Number(rawId) : NaN;
        const anyMailbox = Number.isFinite(mailboxId)
          ? await getMailboxById(db, mailboxId)
          : null;
        if (anyMailbox && isAdminDisabled(anyMailbox)) {
          await flash(
            c,
            "You cannot modify that mailbox. Please contact support.",
            "error",
          );
          return c.redirect(urlFor("dashboard.mailbox_route"), 302);
        }
        // user_settings.set_default_mailbox
        if (!anyMailbox || anyMailbox.user_id !== user.id) {
          await flash(c, "Invalid mailbox", "warning");
          return c.redirect(urlFor("dashboard.mailbox_route"), 302);
        }
        if (!anyMailbox.verified) {
          await flash(c, "This is mailbox is not verified", "warning");
          return c.redirect(urlFor("dashboard.mailbox_route"), 302);
        }
        if (anyMailbox.id !== user.default_mailbox_id) {
          await db
            .prepare(
              "UPDATE users SET default_mailbox_id = ?1, updated_at = ?2 WHERE id = ?3",
            )
            .bind(anyMailbox.id, nowStr(), user.id)
            .run();
        }
        await flash(
          c,
          `Mailbox ${anyMailbox.email} is set as Default Mailbox`,
          "success",
        );
        return c.redirect(urlFor("dashboard.mailbox_route"), 302);
      }

      if (formName === "create") {
        const email = field(fd, "email") ?? "";
        const formValid =
          (await csrfOk(c, fd)) &&
          email.trim() !== "" &&
          isEmailFieldValid(email);
        if (!formValid) {
          await flash(c, "Invalid request", "warning");
          return redirectSelf(c);
        }
        const mailboxEmail = email.toLowerCase().trim().replaceAll(" ", "");
        // mailbox_utils.create_mailbox
        if (!(await userIsPremium(db, user))) {
          await flash(c, "Only available for paid plans", "warning");
          return c.redirect(urlFor("dashboard.mailbox_route"), 302);
        }
        const err = await checkEmailForMailbox(db, mailboxEmail, user);
        if (err) {
          await flash(c, err, "warning");
          return c.redirect(urlFor("dashboard.mailbox_route"), 302);
        }
        const mailbox = await db
          .prepare(
            "INSERT INTO mailbox (user_id, email, verified) VALUES (?1, ?2, 0) RETURNING *",
          )
          .bind(user.id, mailboxEmail)
          .first<MailboxRow>();
        if (!mailbox) {
          await flash(c, "Invalid email", "warning");
          return c.redirect(urlFor("dashboard.mailbox_route"), 302);
        }
        const code = await generateActivationCode(db, mailbox.id);
        const link = `${c.env.URL}/dashboard/mailbox_verify?mailbox_id=${mailbox.id}&code=${code}`;
        await sendTransactionalEmail(c.env, {
          to: mailbox.email,
          subject: `Please confirm your mailbox ${mailbox.email}`,
          text:
            `Hi,\n\nYou have added ${mailbox.email} as an additional mailbox.\n\n` +
            `To confirm, please click on the following link:\n\n${link}\n\n` +
            `Or enter ${code} as the verification code.\n\n` +
            "Best,\nSimpleLogin team.",
        });
        await flash(
          c,
          `You are going to receive an email to confirm ${mailbox.email}.`,
          "success",
        );
        return c.redirect(
          urlFor("dashboard.mailbox_detail_route", { mailbox_id: mailbox.id }),
          302,
        );
      }
      // unknown form-name falls through to the GET render (faithful)
    }
    return renderMailboxPage(c);
  },
);

// ===========================================================================
// Route 2: GET /mailbox_verify (side effects on GET)
// ===========================================================================

webMailboxDomainPagesRoutes.get(
  "/mailbox_verify",
  requireWebLogin,
  async (c) => {
    const user = c.get("webUser");
    const mailboxIdRaw = c.req.query("mailbox_id");
    const code = c.req.query("code");
    if (!mailboxIdRaw) {
      await flash(c, "You followed an invalid link", "error");
      return c.redirect(urlFor("dashboard.mailbox_route"), 302);
    }
    if (!code) {
      // Legacy signed-secret links: broken in Flask (500); intended behavior.
      await flash(
        c,
        "Invalid link. Please delete and re-add your mailbox",
        "error",
      );
      return c.redirect(urlFor("dashboard.mailbox_route"), 302);
    }
    let mailbox: MailboxRow;
    try {
      mailbox = await verifyMailboxCode(
        c.env.DB,
        user,
        Number(mailboxIdRaw),
        code,
      );
    } catch (e) {
      if (e instanceof MailboxError) {
        await flash(c, `Cannot verify mailbox: ${e.msg}`, "error");
        return c.redirect(urlFor("dashboard.mailbox_route"), 302);
      }
      throw e;
    }
    return render(c, "dashboard-mailbox/mailbox_validation.html", null, {
      mailbox: { email: mailbox.email },
    });
  },
);

// ===========================================================================
// Route 5: GET /mailbox/confirm_change (declared before /mailbox/:id)
// ===========================================================================

webMailboxDomainPagesRoutes.get(
  "/mailbox/confirm_change",
  requireWebLogin,
  webRateLimit("mailbox_confirm_change", 3, 60),
  async (c) => {
    const user = c.get("webUser");
    const mailboxIdRaw = c.req.query("mailbox_id");
    const code = c.req.query("code");
    if (!code) {
      // Legacy itsdangerous path not ported.
      await flash(c, "Invalid link", "error");
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    try {
      const mailbox = await verifyMailboxCode(
        c.env.DB,
        user,
        Number(mailboxIdRaw),
        code,
      );
      await flash(c, "Successfully changed mailbox email", "success");
      return c.redirect(
        urlFor("dashboard.mailbox_detail_route", { mailbox_id: mailbox.id }),
        302,
      );
    } catch (e) {
      if (e instanceof MailboxError) {
        await flash(c, `Cannot verify mailbox: ${e.msg}`, "error");
        return c.redirect(urlFor("dashboard.mailbox_route"), 302);
      }
      throw e;
    }
  },
);

// ===========================================================================
// Route 4: GET|POST /mailbox/:id/cancel_email_change (no CSRF, GET side effects)
// ===========================================================================

webMailboxDomainPagesRoutes.on(
  ["GET", "POST"],
  "/mailbox/:mailbox_id{[0-9]+}/cancel_email_change",
  requireWebLogin,
  async (c) => {
    const db = c.env.DB;
    const user = c.get("webUser");
    const mailbox = await getMailboxById(db, Number(c.req.param("mailbox_id")));
    if (!mailbox || mailbox.user_id !== user.id) {
      await flash(c, "Invalid mailbox", "warning");
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    await db
      .prepare(
        "UPDATE mailbox SET new_email = NULL, updated_at = ?1 WHERE id = ?2",
      )
      .bind(nowStr(), mailbox.id)
      .run();
    await clearActivationCodes(db, mailbox.id);
    await flash(c, "Your mailbox change is cancelled", "success");
    return c.redirect(
      urlFor("dashboard.mailbox_detail_route", { mailbox_id: mailbox.id }),
      302,
    );
  },
);

// ===========================================================================
// Route 3: GET|POST /mailbox/:id (sudo, 20/minute POST)
// ===========================================================================

async function renderMailboxDetail(
  c: C,
  mailbox: MailboxRow,
  emailErrors: string[] = [],
): Promise<Response> {
  const db = c.env.DB;
  const token = await generateCsrfToken(c);
  const authorized = await db
    .prepare(
      "SELECT id, email FROM authorized_address WHERE mailbox_id = ?1 ORDER BY id",
    )
    .bind(mailbox.id)
    .all<{ id: number; email: string }>();
  const envx = c.env as EnvX;
  return render(c, "dashboard-mailbox/mailbox_detail.html", "mailbox", {
    mailbox_id: mailbox.id,
    mailbox: {
      id: mailbox.id,
      email: mailbox.email,
      verified: !!mailbox.verified,
      is_admin_disabled: isAdminDisabled(mailbox),
      is_proton: isProton(mailbox),
      pgp_enabled: !!mailbox.pgp_finger_print && !mailbox.disable_pgp,
      pgp_finger_print: mailbox.pgp_finger_print,
      pgp_public_key: mailbox.pgp_public_key,
      disable_pgp: !!mailbox.disable_pgp,
      generic_subject: mailbox.generic_subject,
      force_spf: !!mailbox.force_spf,
      authorized_addresses: authorized.results,
    },
    change_email_form: emailForm(token, emailErrors, mailbox.email),
    csrf_form: csrfForm(token),
    pending_email: mailbox.new_email,
    email_readonly: mailbox.new_email !== null,
    spf_available: envx.ENFORCE_SPF !== undefined,
  });
}

webMailboxDomainPagesRoutes.on(
  ["GET", "POST"],
  "/mailbox/:mailbox_id{[0-9]+}",
  requireWebLogin,
  requireWebSudo,
  webRateLimit("mailbox_detail", 20, 60, ["POST"]),
  async (c) => {
    const db = c.env.DB;
    const user = c.get("webUser");
    let mailbox = await getMailboxById(db, Number(c.req.param("mailbox_id")));
    if (!mailbox || mailbox.user_id !== user.id) {
      await flash(c, "You cannot see this page", "warning");
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    if (isAdminDisabled(mailbox)) {
      await flash(
        c,
        "You cannot modify that mailbox. Please contact support.",
        "error",
      );
      return c.redirect(urlFor("dashboard.mailbox_route"), 302);
    }
    const detailUrl = urlFor("dashboard.mailbox_detail_route", {
      mailbox_id: mailbox.id,
    });

    if (c.req.method === "POST") {
      const fd = await c.req.formData();
      if (!(await csrfOk(c, fd))) {
        await flash(c, "Invalid request", "warning");
        return redirectSelf(c);
      }
      const formName = field(fd, "form-name");

      if (formName === "update-email") {
        const email = field(fd, "email") ?? "";
        if (email.trim() === "" || !isEmailFieldValid(email)) {
          // invalid field -> fall through to render with field errors, no flash
          const errors =
            email.trim() === ""
              ? ["This field is required."]
              : ["Invalid email address."];
          return renderMailboxDetail(c, mailbox, errors);
        }
        // mailbox_utils.request_mailbox_email_change
        const newEmail = sanitizeEmail(email);
        const fail = async (msg: string) => {
          await flash(c, msg, "error");
          return c.redirect(detailUrl, 302);
        };
        if (newEmail === mailbox.email) return fail("Same email");
        const err = await checkEmailForMailbox(db, newEmail, user);
        if (err) return fail(err);
        try {
          await db
            .prepare(
              "UPDATE mailbox SET new_email = ?1, updated_at = ?2 WHERE id = ?3",
            )
            .bind(newEmail, nowStr(), mailbox.id)
            .run();
        } catch (e) {
          if (String(e).includes("UNIQUE constraint failed")) {
            return fail("Email already in use");
          }
          throw e;
        }
        const code = await generateActivationCode(db, mailbox.id);
        const link = `${c.env.URL}/dashboard/mailbox/confirm_change?mailbox_id=${mailbox.id}&code=${code}`;
        await sendTransactionalEmail(c.env, {
          to: newEmail,
          subject: "Confirm mailbox change on SimpleLogin",
          text:
            `Hi,\n\nYou have requested to change your mailbox from ${mailbox.email} ` +
            `to ${newEmail}.\n\nTo confirm, please click on the following link:\n\n` +
            `${link}\n\nBest,\nSimpleLogin team.`,
        });
        await flash(
          c,
          `You are going to receive an email to confirm ${mailbox.email}.`,
          "success",
        );
        return c.redirect(detailUrl, 302);
      }

      if (formName === "force-spf") {
        const envx = c.env as EnvX;
        if (envx.ENFORCE_SPF === undefined) {
          await flash(c, "SPF enforcement globally not enabled", "error");
          return c.redirect(urlFor("dashboard.index"), 302);
        }
        const enabled = field(fd, "spf-status") === "on";
        await db
          .prepare(
            "UPDATE mailbox SET force_spf = ?1, updated_at = ?2 WHERE id = ?3",
          )
          .bind(enabled ? 1 : 0, nowStr(), mailbox.id)
          .run();
        // Faithful operator-precedence bug in the Flask flash message.
        await flash(
          c,
          enabled ? "SPF enforcement was enabled" : "disabled successfully",
          "success",
        );
        return c.redirect(detailUrl, 302);
      }

      if (formName === "add-authorized-address") {
        const address = sanitizeEmail(field(fd, "email") ?? "");
        if (!isValidEmail(address)) {
          await flash(c, `invalid ${address}`, "error");
        } else {
          const existing = await db
            .prepare(
              "SELECT 1 FROM authorized_address WHERE mailbox_id = ?1 AND email = ?2",
            )
            .bind(mailbox.id, address)
            .first();
          if (existing) {
            await flash(c, `${address} already added`, "error");
          } else {
            await db
              .prepare(
                "INSERT INTO authorized_address (user_id, mailbox_id, email) VALUES (?1, ?2, ?3)",
              )
              .bind(user.id, mailbox.id, address)
              .run();
            await flash(c, `${address} added as authorized address`, "success");
          }
        }
        return c.redirect(detailUrl, 302);
      }

      if (formName === "delete-authorized-address") {
        const idRaw = field(fd, "authorized-address-id");
        const row = idRaw
          ? await db
              .prepare("SELECT * FROM authorized_address WHERE id = ?1")
              .bind(Number(idRaw))
              .first<{ id: number; mailbox_id: number; email: string }>()
          : null;
        if (!row || row.mailbox_id !== mailbox.id) {
          await flash(c, "Unknown error. Refresh the page", "warning");
        } else {
          await db
            .prepare("DELETE FROM authorized_address WHERE id = ?1")
            .bind(row.id)
            .run();
          await flash(c, `${row.email} has been deleted`, "success");
        }
        return c.redirect(detailUrl, 302);
      }

      if (formName === "pgp") {
        const action = field(fd, "action");
        if (action === "save") {
          if (!(await userIsPremium(db, user))) {
            await flash(c, "Only premium plan can add PGP Key", "warning");
            return c.redirect(detailUrl, 302);
          }
          if (isProton(mailbox)) {
            await flash(
              c,
              "Enabling PGP for a Proton Mail mailbox is redundant and does not add any security benefit",
              "info",
            );
            return c.redirect(detailUrl, 302);
          }
          // DEFERRED (no GPG on Workers): behave like PGPException — nothing
          // stored, error flash, fall through to render.
          await flash(
            c,
            "Cannot add the public key, please verify it",
            "error",
          );
          return renderMailboxDetail(c, mailbox);
        }
        if (action === "remove") {
          await db
            .prepare(
              `UPDATE mailbox SET pgp_public_key = NULL, pgp_finger_print = NULL,
               disable_pgp = 0, updated_at = ?1 WHERE id = ?2`,
            )
            .bind(nowStr(), mailbox.id)
            .run();
          await flash(
            c,
            "Your PGP public key is removed successfully",
            "success",
          );
          return c.redirect(detailUrl, 302);
        }
        // other/missing action: no-op render
        return renderMailboxDetail(c, mailbox);
      }

      if (formName === "toggle-pgp") {
        if (field(fd, "pgp-enabled") === "on") {
          if (isProton(mailbox)) {
            await db
              .prepare(
                "UPDATE mailbox SET disable_pgp = 1, updated_at = ?1 WHERE id = ?2",
              )
              .bind(nowStr(), mailbox.id)
              .run();
            await flash(
              c,
              "Enabling PGP for a Proton Mail mailbox is redundant and does not add any security benefit",
              "info",
            );
          } else {
            await db
              .prepare(
                "UPDATE mailbox SET disable_pgp = 0, updated_at = ?1 WHERE id = ?2",
              )
              .bind(nowStr(), mailbox.id)
              .run();
            await flash(c, `PGP is enabled on ${mailbox.email}`, "info");
          }
        } else {
          await db
            .prepare(
              "UPDATE mailbox SET disable_pgp = 1, updated_at = ?1 WHERE id = ?2",
            )
            .bind(nowStr(), mailbox.id)
            .run();
          await flash(c, `PGP is disabled on ${mailbox.email}`, "info");
        }
        return c.redirect(detailUrl, 302);
      }

      if (formName === "generic-subject") {
        const action = field(fd, "action");
        if (action === "save") {
          await db
            .prepare(
              "UPDATE mailbox SET generic_subject = ?1, updated_at = ?2 WHERE id = ?3",
            )
            .bind(field(fd, "generic-subject"), nowStr(), mailbox.id)
            .run();
          await flash(c, "Generic subject is enabled", "success");
          return c.redirect(detailUrl, 302);
        }
        if (action === "remove") {
          await db
            .prepare(
              "UPDATE mailbox SET generic_subject = NULL, updated_at = ?1 WHERE id = ?2",
            )
            .bind(nowStr(), mailbox.id)
            .run();
          await flash(c, "Generic subject is disabled", "success");
          return c.redirect(detailUrl, 302);
        }
      }
      // unknown form-name falls through to render
      mailbox = (await getMailboxById(db, mailbox.id)) ?? mailbox;
    }
    return renderMailboxDetail(c, mailbox);
  },
);

// ===========================================================================
// Route 6: GET|POST /custom_domain
// ===========================================================================

interface DomainVM {
  id: number;
  domain: string;
  ownership_verified: boolean;
  verified: boolean;
  created_at: string;
  nb_alias: number;
}

async function domainViewModel(
  db: D1Database,
  cd: CustomDomainRow,
): Promise<DomainVM> {
  const row = await db
    .prepare(
      "SELECT COUNT(*) AS n FROM alias WHERE custom_domain_id = ?1 AND delete_on IS NULL",
    )
    .bind(cd.id)
    .first<{ n: number }>();
  return {
    id: cd.id,
    domain: cd.domain,
    ownership_verified: !!cd.ownership_verified,
    verified: !!cd.verified,
    created_at: cd.created_at,
    nb_alias: row?.n ?? 0,
  };
}

async function renderCustomDomainPage(
  c: C,
  domainErrors: string[] = [],
  domainValue?: string,
): Promise<Response> {
  const db = c.env.DB;
  const user = c.get("webUser");
  const rows = await db
    .prepare(
      `SELECT * FROM custom_domain
       WHERE user_id = ?1 AND is_sl_subdomain = 0 AND pending_deletion = 0
       ORDER BY id`,
    )
    .bind(user.id)
    .all<CustomDomainRow>();
  const customDomains = [];
  for (const cd of rows.results)
    customDomains.push(await domainViewModel(db, cd));
  const token = await generateCsrfToken(c);
  return render(c, "dashboard-mailbox/custom_domain.html", "custom_domain", {
    custom_domains: customDomains,
    new_custom_domain_form: {
      csrf_token: csrfTokenField(token),
      domain: makeField(
        { name: "domain", label: "domain", value: domainValue },
        domainErrors,
      ),
    },
  });
}

webMailboxDomainPagesRoutes.on(
  ["GET", "POST"],
  "/custom_domain",
  requireWebLogin,
  async (c) => {
    const db = c.env.DB;
    const user = c.get("webUser");
    if (c.req.method === "POST") {
      const fd = await c.req.formData();
      if (field(fd, "form-name") === "create") {
        // Premium is checked BEFORE form validation (faithful).
        if (!(await userIsPremium(db, user))) {
          await flash(c, "Only premium plan can add custom domain", "warning");
          return c.redirect(urlFor("dashboard.custom_domain"), 302);
        }
        const raw = field(fd, "domain") ?? "";
        const fieldErrors: string[] = [];
        if (raw.trim() === "") fieldErrors.push("This field is required.");
        else if (raw.length > 128) {
          fieldErrors.push("Field cannot be longer than 128 characters.");
        }
        if (!(await csrfOk(c, fd)) || fieldErrors.length > 0) {
          // form invalid -> re-render with field errors, 200, no flash
          return renderCustomDomainPage(c, fieldErrors, raw);
        }
        // custom_domain_utils.create_custom_domain
        let domain = raw.toLowerCase().trim();
        if (domain.startsWith("http://")) domain = domain.slice(7);
        if (domain.startsWith("https://")) domain = domain.slice(8);

        const failRender = async (msg: string) => {
          await flash(c, msg, "error");
          return renderCustomDomainPage(c, [], raw);
        };
        if (!isValidDomain(domain)) {
          return failRender("This is not a valid domain");
        }
        if (
          await db
            .prepare("SELECT 1 FROM public_domain WHERE domain = ?1")
            .bind(domain)
            .first()
        ) {
          return failRender("A custom domain cannot be a built-in domain.");
        }
        if (
          await db
            .prepare("SELECT 1 FROM custom_domain WHERE domain = ?1")
            .bind(domain)
            .first()
        ) {
          return failRender(`${domain} already used`);
        }
        if (user.email.slice(user.email.lastIndexOf("@") + 1) === domain) {
          return failRender(
            "You cannot add a domain that you are currently using for your personal email. " +
              "Please change your personal email to your real email",
          );
        }
        if (
          await db
            .prepare(
              "SELECT 1 FROM mailbox WHERE verified = 1 AND email LIKE ?1 LIMIT 1",
            )
            .bind(`%@${domain}`)
            .first()
        ) {
          return failRender(`${domain} already used in a SimpleLogin mailbox`);
        }
        // ownership inheritance from a verified parent domain of the same user
        const parents = await db
          .prepare(
            "SELECT domain FROM custom_domain WHERE user_id = ?1 AND ownership_verified = 1",
          )
          .bind(user.id)
          .all<{ domain: string }>();
        const inherited = parents.results.some((p) =>
          domain.endsWith(`.${p.domain}`),
        );
        const created = await db
          .prepare(
            `INSERT INTO custom_domain (user_id, domain, ownership_txt_token, ownership_verified)
             VALUES (?1, ?2, ?3, ?4) RETURNING *`,
          )
          .bind(user.id, domain, randomString(30), inherited ? 1 : 0)
          .first<CustomDomainRow>();
        await flash(c, `New domain ${domain} is created`, "success");
        return c.redirect(
          urlFor("dashboard.domain_detail_dns", {
            custom_domain_id: created?.id,
          }),
          302,
        );
      }
      // unknown form-name falls through to the GET render
    }
    return renderCustomDomainPage(c);
  },
);

// ===========================================================================
// Domain detail shared guard
// ===========================================================================

async function loadOwnedDomain(c: C): Promise<CustomDomainRow | Response> {
  const cd = await getCustomDomainById(
    c.env.DB,
    Number(c.req.param("custom_domain_id")),
  );
  if (!cd || cd.user_id !== c.get("webUser").id) {
    await flash(c, "You cannot see this page", "warning");
    return c.redirect(urlFor("dashboard.index"), 302);
  }
  return cd;
}

function domainCtx(cd: CustomDomainRow) {
  return {
    id: cd.id,
    domain: cd.domain,
    name: cd.name,
    verified: !!cd.verified,
    spf_verified: !!cd.spf_verified,
    dkim_verified: !!cd.dkim_verified,
    dmarc_verified: !!cd.dmarc_verified,
    ownership_verified: !!cd.ownership_verified,
    catch_all: !!cd.catch_all,
    random_prefix_generation: !!cd.random_prefix_generation,
    is_sl_subdomain: !!cd.is_sl_subdomain,
    created_at: cd.created_at,
  };
}

// ===========================================================================
// Route 7: GET|POST /domains/:id/dns
// ===========================================================================

interface DnsPageState {
  ownership_ok: boolean;
  ownership_errors: string[];
  mx_ok: boolean;
  mx_errors: string[];
  spf_ok: boolean;
  spf_errors: string[];
  dkim_ok: boolean;
  dkim_errors: Array<{ custom_record: string; retrieved_cname: string }>;
  dmarc_ok: boolean;
  dmarc_errors: string[];
}

const dnsStateDefaults = (): DnsPageState => ({
  ownership_ok: true,
  ownership_errors: [],
  mx_ok: true,
  mx_errors: [],
  spf_ok: true,
  spf_errors: [],
  dkim_ok: true,
  dkim_errors: [],
  dmarc_ok: true,
  dmarc_errors: [],
});

async function renderDnsPage(
  c: C,
  cd: CustomDomainRow,
  state: DnsPageState,
): Promise<Response> {
  const envx = c.env as EnvX;
  const token = await generateCsrfToken(c);
  const mx = expectedMxRecords(envx);
  return render(
    c,
    "dashboard-mailbox/domain_detail_dns.html",
    cd.is_sl_subdomain ? "subdomain" : "custom_domain",
    {
      domain_detail_page: "dns",
      custom_domain: domainCtx(cd),
      csrf_form: csrfForm(token),
      ownership_records: {
        recommended: `sl-verification=${cd.ownership_txt_token ?? ""}`,
      },
      expected_mx_records: mx,
      spf_record: `v=spf1 include:${envx.EMAIL_DOMAIN} ~all`,
      dkim_records: DKIM_PREFIXES.map((prefix) => ({
        domain: prefix,
        recommended: `${prefix}.${envx.EMAIL_DOMAIN}`,
      })),
      dmarc_record: DMARC_RECORD,
      ...state,
    },
  );
}

webMailboxDomainPagesRoutes.on(
  ["GET", "POST"],
  "/domains/:custom_domain_id{[0-9]+}/dns",
  requireWebLogin,
  async (c) => {
    const db = c.env.DB;
    const envx = c.env as EnvX;
    const loaded = await loadOwnedDomain(c);
    if (loaded instanceof Response) return loaded;
    let cd = loaded;

    // GET/POST side effect: lazily generate the ownership token
    if (!cd.ownership_verified && !cd.ownership_txt_token) {
      const token = randomString(30);
      await db
        .prepare(
          "UPDATE custom_domain SET ownership_txt_token = ?1, updated_at = ?2 WHERE id = ?3",
        )
        .bind(token, nowStr(), cd.id)
        .run();
      cd = { ...cd, ownership_txt_token: token };
    }

    const state = dnsStateDefaults();

    if (c.req.method === "POST") {
      const fd = await c.req.formData();
      if (!(await csrfOk(c, fd))) {
        await flash(c, "Invalid request", "warning");
        return redirectSelf(c);
      }
      const formName = field(fd, "form-name");

      if (formName === "check-ownership") {
        const expected = `sl-verification=${cd.ownership_txt_token}`;
        const txt = await getTxtRecords(cd.domain);
        if (txt.includes(expected)) {
          await db
            .prepare(
              "UPDATE custom_domain SET ownership_verified = 1, updated_at = ?1 WHERE id = ?2",
            )
            .bind(nowStr(), cd.id)
            .run();
          await flash(
            c,
            "Domain ownership is verified. Please proceed to the other records setup",
            "success",
          );
          return c.redirect(
            urlFor("dashboard.domain_detail_dns", {
              custom_domain_id: cd.id,
              _anchor: "dns-setup",
            }),
            302,
          );
        }
        await flash(c, "We can't find the needed TXT record", "error");
        state.ownership_ok = false;
        state.ownership_errors = txt;
      } else if (formName === "check-mx") {
        const found = await getMxDomains(cd.domain);
        if (isMxEquivalent(found, expectedMxRecords(envx))) {
          await db
            .prepare(
              "UPDATE custom_domain SET verified = 1, updated_at = ?1 WHERE id = ?2",
            )
            .bind(nowStr(), cd.id)
            .run();
          await flash(
            c,
            "Your domain can start receiving emails. You can now use it to create alias",
            "success",
          );
          return c.redirect(
            urlFor("dashboard.domain_detail_dns", { custom_domain_id: cd.id }),
            302,
          );
        }
        await flash(c, "The MX record is not correctly set", "warning");
        state.mx_ok = false;
        state.mx_errors = [...found.entries()]
          .sort((a, b) => a[0] - b[0])
          .flatMap(([prio, targets]) => targets.map((t) => `${prio} ${t}`));
      } else if (formName === "check-spf") {
        const txt = await getTxtRecords(cd.domain);
        const includes = new Set<string>();
        for (const r of txt) {
          if (!r.startsWith("v=spf1")) continue;
          for (const part of r.split(/\s+/)) {
            if (part.startsWith("include:")) includes.add(part.slice(8));
          }
        }
        if (includes.has(envx.EMAIL_DOMAIN)) {
          await db
            .prepare(
              "UPDATE custom_domain SET spf_verified = 1, updated_at = ?1 WHERE id = ?2",
            )
            .bind(nowStr(), cd.id)
            .run();
          await flash(c, "SPF is setup correctly", "success");
          return c.redirect(
            urlFor("dashboard.domain_detail_dns", { custom_domain_id: cd.id }),
            302,
          );
        }
        await db
          .prepare(
            "UPDATE custom_domain SET spf_verified = 0, updated_at = ?1 WHERE id = ?2",
          )
          .bind(nowStr(), cd.id)
          .run();
        cd = { ...cd, spf_verified: 0 };
        await flash(
          c,
          `SPF: ${envx.EMAIL_DOMAIN} is not included in your SPF record.`,
          "warning",
        );
        state.spf_ok = false;
        const ownershipRecord = `sl-verification=${cd.ownership_txt_token}`;
        state.spf_errors = txt.filter((r) => r !== ownershipRecord);
      } else if (formName === "check-dkim") {
        const errors: Array<{
          custom_record: string;
          retrieved_cname: string;
        }> = [];
        for (const prefix of DKIM_PREFIXES) {
          const host = `${prefix}.${cd.domain}`;
          const expected = `${prefix}.${envx.EMAIL_DOMAIN}`;
          const cname = await getCnameRecord(host);
          if (cname !== expected) {
            errors.push({
              custom_record: host,
              retrieved_cname: cname ?? "empty",
            });
          }
        }
        if (errors.length === 0) {
          await db
            .prepare(
              "UPDATE custom_domain SET dkim_verified = 1, updated_at = ?1 WHERE id = ?2",
            )
            .bind(nowStr(), cd.id)
            .run();
          await flash(c, "DKIM is setup correctly.", "success");
          return c.redirect(
            urlFor("dashboard.domain_detail_dns", { custom_domain_id: cd.id }),
            302,
          );
        }
        // legacy grace: keep dkim_verified while dkim._domainkey is still correct
        const mainStillOk = !errors.some(
          (e) => e.custom_record === `dkim._domainkey.${cd.domain}`,
        );
        const newVerified = cd.dkim_verified && mainStillOk ? 1 : 0;
        await db
          .prepare(
            "UPDATE custom_domain SET dkim_verified = ?1, updated_at = ?2 WHERE id = ?3",
          )
          .bind(newVerified, nowStr(), cd.id)
          .run();
        cd = { ...cd, dkim_verified: newVerified };
        await flash(
          c,
          "DKIM: the CNAME record is not correctly set",
          "warning",
        );
        state.dkim_ok = false;
        state.dkim_errors = errors;
      } else if (formName === "check-dmarc") {
        const txt = await getTxtRecords(`_dmarc.${cd.domain}`);
        if (txt.includes(DMARC_RECORD)) {
          await db
            .prepare(
              "UPDATE custom_domain SET dmarc_verified = 1, updated_at = ?1 WHERE id = ?2",
            )
            .bind(nowStr(), cd.id)
            .run();
          await flash(c, "DMARC is setup correctly", "success");
          return c.redirect(
            urlFor("dashboard.domain_detail_dns", { custom_domain_id: cd.id }),
            302,
          );
        }
        await db
          .prepare(
            "UPDATE custom_domain SET dmarc_verified = 0, updated_at = ?1 WHERE id = ?2",
          )
          .bind(nowStr(), cd.id)
          .run();
        cd = { ...cd, dmarc_verified: 0 };
        await flash(c, "DMARC: The TXT record is not correctly set", "warning");
        state.dmarc_ok = false;
        state.dmarc_errors = txt;
      }
    }
    return renderDnsPage(c, cd, state);
  },
);

// ===========================================================================
// Route 8: GET|POST /domains/:id/info
// ===========================================================================

async function domainMailboxIds(
  db: D1Database,
  cd: CustomDomainRow,
  user: UserRow,
): Promise<number[]> {
  const linked = await db
    .prepare(
      "SELECT mailbox_id FROM domain_mailbox WHERE domain_id = ?1 ORDER BY id",
    )
    .bind(cd.id)
    .all<{ mailbox_id: number }>();
  if (linked.results.length > 0) return linked.results.map((r) => r.mailbox_id);
  return user.default_mailbox_id !== null ? [user.default_mailbox_id] : [];
}

webMailboxDomainPagesRoutes.on(
  ["GET", "POST"],
  "/domains/:custom_domain_id{[0-9]+}/info",
  requireWebLogin,
  async (c) => {
    const db = c.env.DB;
    const user = c.get("webUser");
    const loaded = await loadOwnedDomain(c);
    if (loaded instanceof Response) return loaded;
    let cd = loaded;
    const selfUrl = urlFor("dashboard.domain_detail", {
      custom_domain_id: cd.id,
    });

    if (c.req.method === "POST") {
      const fd = await c.req.formData();
      if (!(await csrfOk(c, fd))) {
        await flash(c, "Invalid request", "warning");
        return redirectSelf(c);
      }
      const formName = field(fd, "form-name");

      if (formName === "switch-catch-all") {
        const newVal = cd.catch_all ? 0 : 1;
        await db
          .prepare(
            "UPDATE custom_domain SET catch_all = ?1, updated_at = ?2 WHERE id = ?3",
          )
          .bind(newVal, nowStr(), cd.id)
          .run();
        if (newVal) {
          await flash(
            c,
            `The catch-all has been enabled for ${cd.domain}`,
            "success",
          );
        } else {
          await flash(
            c,
            `The catch-all has been disabled for ${cd.domain}`,
            "warning",
          );
        }
        return c.redirect(selfUrl, 302);
      }

      if (formName === "set-name") {
        if (field(fd, "action") === "save") {
          const name = (field(fd, "alias-name") ?? "").replaceAll("\n", "");
          await db
            .prepare(
              "UPDATE custom_domain SET name = ?1, updated_at = ?2 WHERE id = ?3",
            )
            .bind(name, nowStr(), cd.id)
            .run();
          await flash(
            c,
            `Default alias name for Domain ${cd.domain} has been set`,
            "success",
          );
        } else {
          await db
            .prepare(
              "UPDATE custom_domain SET name = NULL, updated_at = ?1 WHERE id = ?2",
            )
            .bind(nowStr(), cd.id)
            .run();
          await flash(
            c,
            `Default alias name for Domain ${cd.domain} has been removed`,
            "info",
          );
        }
        return c.redirect(selfUrl, 302);
      }

      if (formName === "switch-random-prefix-generation") {
        const newVal = cd.random_prefix_generation ? 0 : 1;
        await db
          .prepare(
            "UPDATE custom_domain SET random_prefix_generation = ?1, updated_at = ?2 WHERE id = ?3",
          )
          .bind(newVal, nowStr(), cd.id)
          .run();
        if (newVal) {
          await flash(
            c,
            `Random prefix generation has been enabled for ${cd.domain}`,
            "success",
          );
        } else {
          await flash(
            c,
            `Random prefix generation has been disabled for ${cd.domain}`,
            "warning",
          );
        }
        return c.redirect(selfUrl, 302);
      }

      if (formName === "update") {
        // custom_domain_utils.set_custom_domain_mailboxes
        const ids = fd
          .getAll("mailbox_ids")
          .filter((v): v is string => typeof v === "string");
        const failWarn = async (msg: string) => {
          await flash(c, msg, "warning");
          return c.redirect(selfUrl, 302);
        };
        if (ids.length === 0) {
          return failWarn("You must select at least 1 mailbox");
        }
        if (ids.length > MAX_MAILBOXES_PER_DOMAIN) {
          return failWarn("You can only set up to 20 mailboxes per domain");
        }
        const mailboxIds: number[] = [];
        for (const raw of ids) {
          if (!/^\d+$/.test(raw))
            return failWarn("Something went wrong, please retry");
          mailboxIds.push(Number(raw));
        }
        const found: MailboxRow[] = [];
        for (const id of mailboxIds) {
          const mb = await getMailboxById(db, id);
          if (
            !mb ||
            mb.user_id !== user.id ||
            !mb.verified ||
            isAdminDisabled(mb)
          ) {
            return failWarn("Something went wrong, please retry");
          }
          found.push(mb);
        }
        await db
          .prepare("DELETE FROM domain_mailbox WHERE domain_id = ?1")
          .bind(cd.id)
          .run();
        for (const mb of found) {
          await db
            .prepare(
              "INSERT INTO domain_mailbox (domain_id, mailbox_id) VALUES (?1, ?2)",
            )
            .bind(cd.id, mb.id)
            .run();
        }
        await flash(c, `${cd.domain} mailboxes has been updated`, "success");
        return c.redirect(selfUrl, 302);
      }

      if (formName === "delete") {
        const name = cd.domain;
        await db
          .prepare(
            "UPDATE custom_domain SET pending_deletion = 1, updated_at = ?1 WHERE id = ?2",
          )
          .bind(nowStr(), cd.id)
          .run();
        await db
          .prepare(
            "INSERT INTO job (name, payload, run_at) VALUES ('delete-domain', ?1, ?2)",
          )
          .bind(JSON.stringify({ custom_domain_id: cd.id }), nowStr())
          .run();
        await flash(
          c,
          `${name} scheduled for deletion.` +
            "You will receive a confirmation email when the deletion is finished",
          "success",
        );
        return c.redirect(
          cd.is_sl_subdomain
            ? urlFor("dashboard.subdomain_route")
            : urlFor("dashboard.custom_domain"),
          302,
        );
      }
      // unknown form-name falls through to render
      cd = (await getCustomDomainById(db, cd.id)) ?? cd;
    }

    const nbAlias = await db
      .prepare("SELECT COUNT(*) AS n FROM alias WHERE custom_domain_id = ?1")
      .bind(cd.id)
      .first<{ n: number }>();
    const mailboxes = await selectableMailboxes(db, user.id);
    const token = await generateCsrfToken(c);
    return render(
      c,
      "dashboard-mailbox/domain_detail_info.html",
      cd.is_sl_subdomain ? "subdomain" : "custom_domain",
      {
        domain_detail_page: "info",
        custom_domain: domainCtx(cd),
        csrf_form: csrfForm(token),
        mailboxes: mailboxes.map((m) => ({ id: m.id, email: m.email })),
        domain_mailbox_ids: await domainMailboxIds(db, cd, user),
        nb_alias: nbAlias?.n ?? 0,
      },
    );
  },
);

// ===========================================================================
// Route 9: GET|POST /domains/:id/trash
// ===========================================================================

webMailboxDomainPagesRoutes.on(
  ["GET", "POST"],
  "/domains/:custom_domain_id{[0-9]+}/trash",
  requireWebLogin,
  async (c) => {
    const db = c.env.DB;
    const loaded = await loadOwnedDomain(c);
    if (loaded instanceof Response) return loaded;
    const cd = loaded;
    const selfUrl = urlFor("dashboard.domain_detail_trash", {
      custom_domain_id: cd.id,
    });

    if (c.req.method === "POST") {
      const fd = await c.req.formData();
      if (!(await csrfOk(c, fd))) {
        await flash(c, "Invalid request", "warning");
        return redirectSelf(c);
      }
      const formName = field(fd, "form-name");
      if (formName === "empty-all") {
        await db
          .prepare("DELETE FROM domain_deleted_alias WHERE domain_id = ?1")
          .bind(cd.id)
          .run();
        await flash(c, "All deleted aliases can now be re-created", "success");
        return c.redirect(selfUrl, 302);
      }
      if (formName === "remove-single") {
        const idRaw = field(fd, "deleted-alias-id");
        const row =
          idRaw && /^\d+$/.test(idRaw)
            ? await db
                .prepare("SELECT * FROM domain_deleted_alias WHERE id = ?1")
                .bind(Number(idRaw))
                .first<DomainDeletedAliasRow>()
            : null;
        if (!row || row.domain_id !== cd.id) {
          await flash(c, "Unknown error, refresh the page", "warning");
          return c.redirect(selfUrl, 302);
        }
        await db
          .prepare("DELETE FROM domain_deleted_alias WHERE id = ?1")
          .bind(row.id)
          .run();
        await flash(c, `${row.email} can now be re-created`, "success");
        return c.redirect(selfUrl, 302);
      }
    }

    const rows = await db
      .prepare(
        "SELECT * FROM domain_deleted_alias WHERE domain_id = ?1 ORDER BY id",
      )
      .bind(cd.id)
      .all<DomainDeletedAliasRow>();
    const token = await generateCsrfToken(c);
    return render(
      c,
      "dashboard-mailbox/domain_detail_trash.html",
      cd.is_sl_subdomain ? "subdomain" : "custom_domain",
      {
        domain_detail_page: "trash",
        custom_domain: domainCtx(cd),
        csrf_form: csrfForm(token),
        domain_deleted_aliases: rows.results.map((r) => ({
          id: r.id,
          email: r.email,
          created_at: r.created_at,
        })),
      },
    );
  },
);

// ===========================================================================
// Route 10: GET|POST /domains/:id/auto-create
// ===========================================================================

interface AutoCreateRuleRow {
  id: number;
  custom_domain_id: number;
  regex: string;
  order: number;
  display_name: string | null;
}

async function autoCreateRules(
  db: D1Database,
  domainId: number,
): Promise<AutoCreateRuleRow[]> {
  const res = await db
    .prepare(
      `SELECT * FROM auto_create_rule WHERE custom_domain_id = ?1 ORDER BY "order"`,
    )
    .bind(domainId)
    .all<AutoCreateRuleRow>();
  return res.results;
}

webMailboxDomainPagesRoutes.on(
  ["GET", "POST"],
  "/domains/:custom_domain_id{[0-9]+}/auto-create",
  requireWebLogin,
  async (c) => {
    const db = c.env.DB;
    const user = c.get("webUser");
    const loaded = await loadOwnedDomain(c);
    if (loaded instanceof Response) return loaded;
    const cd = loaded;
    const selfUrl = urlFor("dashboard.domain_detail_auto_create", {
      custom_domain_id: cd.id,
    });

    let autoCreateTestLocal = "";
    let autoCreateTestResult = "";
    let autoCreateTestPassed = false;
    const newRuleErrors: Record<string, string[]> = {
      regex: [],
      display_name: [],
      order: [],
    };
    const testErrors: string[] = [];

    if (c.req.method === "POST") {
      const fd = await c.req.formData();
      const formName = field(fd, "form-name");

      if (formName === "create-auto-create-rule") {
        const regexRaw = field(fd, "regex") ?? "";
        const displayNameRaw = field(fd, "display_name") ?? "";
        const orderRaw = field(fd, "order") ?? "";
        if (regexRaw.trim() === "")
          newRuleErrors.regex.push("This field is required.");
        else if (regexRaw.length > 128) {
          newRuleErrors.regex.push(
            "Field cannot be longer than 128 characters.",
          );
        }
        if (displayNameRaw.length > 128) {
          newRuleErrors.display_name.push(
            "Field cannot be longer than 128 characters.",
          );
        }
        let order: number | null = null;
        if (orderRaw.trim() === "") {
          newRuleErrors.order.push("This field is required.");
        } else if (!/^[+-]?\d+$/.test(orderRaw.trim())) {
          newRuleErrors.order.push("Not a valid integer value");
        } else {
          order = Number.parseInt(orderRaw.trim(), 10);
          if (order === 0) newRuleErrors.order.push("This field is required.");
          else if (order < 0 || order > 100) {
            newRuleErrors.order.push("Number must be between 0 and 100.");
          }
        }
        const csrfValid = await csrfOk(c, fd);
        const formValid =
          csrfValid &&
          newRuleErrors.regex.length === 0 &&
          newRuleErrors.display_name.length === 0 &&
          newRuleErrors.order.length === 0;

        if (formValid && order !== null) {
          const rules = await autoCreateRules(db, cd.id);
          if (rules.some((r) => r.order === order)) {
            await flash(
              c,
              "Another rule with the same order already exists",
              "error",
            );
            // falls through to render
          } else {
            const ids = fd
              .getAll("mailbox_ids")
              .filter((v): v is string => typeof v === "string");
            const mailboxes: MailboxRow[] = [];
            for (const raw of ids) {
              const mb = /^\d+$/.test(raw)
                ? await getMailboxById(db, Number(raw))
                : null;
              if (!mb || mb.user_id !== user.id || !mb.verified) {
                await flash(c, "Something went wrong, please retry", "warning");
                return c.redirect(selfUrl, 302);
              }
              if (isAdminDisabled(mb)) {
                await flash(
                  c,
                  "Cannot assign admin-disabled mailbox. Please contact support.",
                  "error",
                );
                return c.redirect(selfUrl, 302);
              }
              mailboxes.push(mb);
            }
            if (mailboxes.length === 0) {
              await flash(c, "You must select at least 1 mailbox", "warning");
              return c.redirect(selfUrl, 302);
            }
            let regexOk = true;
            try {
              new RegExp(regexRaw);
            } catch {
              regexOk = false;
            }
            if (!regexOk) {
              await flash(c, `Invalid regex ${regexRaw}`, "error");
              return c.redirect(selfUrl, 302);
            }
            let displayName: string | null = displayNameRaw
              .replaceAll("\r", " ")
              .replaceAll("\n", " ")
              .trim();
            if (!displayName) displayName = null;
            const rule = await db
              .prepare(
                `INSERT INTO auto_create_rule (custom_domain_id, "order", regex, display_name)
                 VALUES (?1, ?2, ?3, ?4) RETURNING id`,
              )
              .bind(cd.id, order, regexRaw, displayName)
              .first<{ id: number }>();
            for (const mb of mailboxes) {
              await db
                .prepare(
                  "INSERT INTO auto_create_rule__mailbox (auto_create_rule_id, mailbox_id) VALUES (?1, ?2)",
                )
                .bind(rule?.id, mb.id)
                .run();
            }
            await flash(c, "New auto create rule has been created", "success");
            return c.redirect(selfUrl, 302);
          }
        }
        // invalid form / duplicate order falls through to render with errors
      } else if (formName === "delete-auto-create-rule") {
        // NO CSRF validation (faithful hole)
        const idRaw = field(fd, "rule-id");
        const rule =
          idRaw && /^\d+$/.test(idRaw.trim())
            ? await db
                .prepare("SELECT * FROM auto_create_rule WHERE id = ?1")
                .bind(Number(idRaw))
                .first<AutoCreateRuleRow>()
            : null;
        if (!rule || rule.custom_domain_id !== cd.id) {
          await flash(c, "Something wrong, please retry", "error");
          return c.redirect(selfUrl, 302);
        }
        await db
          .prepare("DELETE FROM auto_create_rule WHERE id = ?1")
          .bind(rule.id)
          .run();
        await flash(c, `Rule #${rule.order} has been deleted`, "success");
        return c.redirect(selfUrl, 302);
      } else if (formName === "test-auto-create-rule") {
        const local = field(fd, "local") ?? "";
        if (local.trim() === "") testErrors.push("This field is required.");
        else if (local.length > 128) {
          testErrors.push("Field cannot be longer than 128 characters.");
        }
        if ((await csrfOk(c, fd)) && testErrors.length === 0) {
          autoCreateTestLocal = local;
          const rules = await autoCreateRules(db, cd.id);
          let matched: AutoCreateRuleRow | null = null;
          for (const rule of rules) {
            try {
              if (new RegExp(`^(?:${rule.regex})$`).test(local)) {
                matched = rule;
                break;
              }
            } catch {
              // Python-only regex syntax: treated as non-matching
            }
          }
          if (matched) {
            autoCreateTestResult = `${local}@${cd.domain} passes rule #${matched.order}`;
            autoCreateTestPassed = true;
          } else {
            autoCreateTestResult = `${local}@${cd.domain} doesn't pass any rule`;
          }
        }
      }
    }

    const rules = await autoCreateRules(db, cd.id);
    const ruleVMs = [];
    for (const rule of rules) {
      const mbs = await db
        .prepare(
          `SELECT m.email FROM auto_create_rule__mailbox rm
           JOIN mailbox m ON m.id = rm.mailbox_id
           WHERE rm.auto_create_rule_id = ?1 ORDER BY rm.id`,
        )
        .bind(rule.id)
        .all<{ email: string }>();
      ruleVMs.push({
        id: rule.id,
        order: rule.order,
        regex: rule.regex,
        display_name: rule.display_name,
        mailboxes: mbs.results,
      });
    }
    const mailboxes = await selectableMailboxes(db, user.id);
    const token = await generateCsrfToken(c);
    return render(
      c,
      "dashboard-mailbox/domain_detail_auto_create.html",
      cd.is_sl_subdomain ? "subdomain" : "custom_domain",
      {
        domain_detail_page: "auto_create",
        custom_domain: {
          ...domainCtx(cd),
          auto_create_rules: ruleVMs,
        },
        mailboxes: mailboxes.map((m) => ({ id: m.id, email: m.email })),
        new_auto_create_rule_form: {
          csrf_token: csrfTokenField(token),
          regex: makeField(
            { name: "regex", label: "regex" },
            newRuleErrors.regex,
          ),
          display_name: makeField(
            { name: "display_name", label: "display name" },
            newRuleErrors.display_name,
          ),
          order: makeField(
            { name: "order", label: "order" },
            newRuleErrors.order,
          ),
        },
        auto_create_test_form: {
          csrf_token: csrfTokenField(token),
          local: makeField({ name: "local", label: "local part" }, testErrors),
        },
        auto_create_test_local: autoCreateTestLocal,
        auto_create_test_result: autoCreateTestResult,
        auto_create_test_passed: autoCreateTestPassed,
      },
    );
  },
);

// ===========================================================================
// Route 11: GET|POST /subdomain
// ===========================================================================

webMailboxDomainPagesRoutes.on(
  ["GET", "POST"],
  "/subdomain",
  requireWebLogin,
  async (c) => {
    const db = c.env.DB;
    const user = c.get("webUser");
    const available = await db
      .prepare(
        "SELECT COUNT(*) AS n FROM public_domain WHERE can_use_subdomain = 1",
      )
      .first<{ n: number }>();
    if ((available?.n ?? 0) === 0) {
      await flash(c, "Unknown error, redirect to the home page", "error");
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    const slDomains = await db
      .prepare(
        `SELECT * FROM public_domain WHERE can_use_subdomain = 1 ORDER BY "order", id`,
      )
      .all<PublicDomainRow>();

    if (c.req.method === "POST") {
      const fd = await c.req.formData();
      if (field(fd, "form-name") === "create") {
        const domainRaw = field(fd, "domain") ?? "";
        const subdomainRaw = field(fd, "subdomain") ?? "";
        const formValid =
          (await csrfOk(c, fd)) &&
          domainRaw.trim() !== "" &&
          domainRaw.length <= 64 &&
          subdomainRaw.trim() !== "" &&
          subdomainRaw.length <= 64;
        if (!formValid) {
          await flash(c, "Invalid new subdomain", "warning");
          return c.redirect(urlFor("dashboard.subdomain_route"), 302);
        }
        if (!(await userIsPremium(db, user))) {
          await flash(c, "Only premium plan can add subdomain", "warning");
          return redirectSelf(c);
        }
        const subCount = await db
          .prepare(
            "SELECT COUNT(*) AS n FROM custom_domain WHERE user_id = ?1 AND is_sl_subdomain = 1",
          )
          .bind(user.id)
          .first<{ n: number }>();
        const quota = Math.min(
          user.subdomain_quota,
          MAX_NB_SUBDOMAIN - (subCount?.n ?? 0),
        );
        const failRedirect = async (msg: string) => {
          await flash(c, msg, "error");
          return redirectSelf(c);
        };
        if (quota <= 0) {
          return failRedirect(
            `You can't create more than ${MAX_NB_SUBDOMAIN} subdomains`,
          );
        }
        const subdomain = subdomainRaw.toLowerCase().trim();
        const domain = domainRaw.toLowerCase().trim();
        if (subdomain.length < 3) {
          return failRedirect("Subdomain must have at least 3 characters");
        }
        if (!/^[0-9a-z-]+$/.test(subdomain)) {
          return failRedirect(
            "Subdomain can only contain lowercase letters, numbers and dashes (-)",
          );
        }
        if (subdomain.endsWith("-")) {
          return failRedirect("Subdomain can't end with dash (-)");
        }
        if (!slDomains.results.some((d) => d.domain === domain)) {
          return failRedirect("Unknown error, refresh the page");
        }
        const fullDomain = `${subdomain}.${domain}`;

        const failRender = async (msg: string) => {
          await flash(c, msg, "error");
          return renderSubdomainPage(c, slDomains.results);
        };
        if (
          await db
            .prepare("SELECT 1 FROM custom_domain WHERE domain = ?1")
            .bind(fullDomain)
            .first()
        ) {
          return failRender(`${fullDomain} already used`);
        }
        if (
          await db
            .prepare(
              "SELECT 1 FROM mailbox WHERE verified = 1 AND email LIKE ?1 LIMIT 1",
            )
            .bind(`%@${fullDomain}`)
            .first()
        ) {
          return failRender(
            `${fullDomain} already used in a SimpleLogin mailbox`,
          );
        }
        if (
          await db
            .prepare("SELECT 1 FROM deleted_subdomain WHERE domain = ?1")
            .bind(fullDomain)
            .first()
        ) {
          return failRender(
            `${fullDomain} has been used before and cannot be reused`,
          );
        }
        const created = await db
          .prepare(
            `INSERT INTO custom_domain
               (user_id, domain, is_sl_subdomain, catch_all, verified, dkim_verified,
                spf_verified, dmarc_verified, ownership_verified, ownership_txt_token)
             VALUES (?1, ?2, 1, 1, 1, 0, 1, 0, 1, ?3) RETURNING *`,
          )
          .bind(user.id, fullDomain, randomString(30))
          .first<CustomDomainRow>();
        // CustomDomain.create permanently decrements the user's quota column
        await db
          .prepare(
            "UPDATE users SET subdomain_quota = subdomain_quota - 1, updated_at = ?1 WHERE id = ?2",
          )
          .bind(nowStr(), user.id)
          .run();
        await flash(
          c,
          `New subdomain ${created?.domain} is created`,
          "success",
        );
        return c.redirect(
          urlFor("dashboard.domain_detail", { custom_domain_id: created?.id }),
          302,
        );
      }
      // unknown form-name falls through to render
    }
    return renderSubdomainPage(c, slDomains.results);
  },
);

async function renderSubdomainPage(
  c: C,
  slDomains: PublicDomainRow[],
): Promise<Response> {
  const db = c.env.DB;
  const user = c.get("webUser");
  const rows = await db
    .prepare(
      "SELECT * FROM custom_domain WHERE user_id = ?1 AND is_sl_subdomain = 1 ORDER BY id",
    )
    .bind(user.id)
    .all<CustomDomainRow>();
  const subdomains = [];
  for (const cd of rows.results) subdomains.push(await domainViewModel(db, cd));
  const token = await generateCsrfToken(c);
  return render(c, "dashboard-mailbox/subdomain.html", "subdomain", {
    sl_domains: slDomains.map((d) => ({ domain: d.domain })),
    subdomains,
    new_subdomain_form: csrfForm(token),
  });
}

// ===========================================================================
// Route 12: GET|POST /directory
// ===========================================================================

const RESERVED_DIR_NAMES = [
  "reply",
  "ra",
  "bounces",
  "bounce",
  "transactional",
];

async function renderDirectoryPage(
  c: C,
  nameErrors: string[] = [],
  nameValue?: string,
): Promise<Response> {
  const db = c.env.DB;
  const user = c.get("webUser");
  const envx = c.env as EnvX;
  const dirsRes = await db
    .prepare(
      "SELECT * FROM directory WHERE user_id = ?1 ORDER BY created_at DESC, id DESC",
    )
    .bind(user.id)
    .all<DirectoryRow>();
  const dirs = [];
  for (const d of dirsRes.results) {
    const nb = await db
      .prepare("SELECT COUNT(*) AS n FROM alias WHERE directory_id = ?1")
      .bind(d.id)
      .first<{ n: number }>();
    const linked = await db
      .prepare(
        "SELECT mailbox_id FROM directory_mailbox WHERE directory_id = ?1 ORDER BY id",
      )
      .bind(d.id)
      .all<{ mailbox_id: number }>();
    const mailboxIds =
      linked.results.length > 0
        ? linked.results.map((r) => r.mailbox_id)
        : user.default_mailbox_id !== null
          ? [user.default_mailbox_id]
          : [];
    dirs.push({
      id: d.id,
      name: d.name,
      disabled: !!d.disabled,
      created_at: d.created_at,
      nb_alias: nb?.n ?? 0,
      mailbox_ids: mailboxIds,
    });
  }
  const mailboxes = await selectableMailboxes(db, user.id);
  const token = await generateCsrfToken(c);
  return render(c, "dashboard-mailbox/directory.html", "directory", {
    dirs,
    mailboxes: mailboxes.map((m) => ({ id: m.id, email: m.email })),
    toggle_dir_form: {
      csrf_token: csrfTokenField(token),
      directory_id: makeField({ name: "directory_id", type: "hidden" }),
      directory_enabled: makeField({
        name: "directory_enabled",
        type: "checkbox",
        value: "y",
      }),
    },
    update_dir_form: {
      csrf_token: csrfTokenField(token),
      directory_id: makeField({ name: "directory_id", type: "hidden" }),
    },
    delete_dir_form: {
      csrf_token: csrfTokenField(token),
      directory_id: makeField({ name: "directory_id", type: "hidden" }),
    },
    new_dir_form: {
      csrf_token: csrfTokenField(token),
      name: makeField(
        { name: "name", label: "name", value: nameValue },
        nameErrors,
      ),
    },
    ALIAS_DOMAINS: (envx.ALIAS_DOMAINS ?? "")
      .split(",")
      .map((d) => d.trim())
      .filter(Boolean),
  });
}

/** Port of alias_delete.delete_alias for the synchronous directory deletion. */
async function deleteAliasForDirectory(
  db: D1Database,
  alias: AliasRow,
  user: UserRow,
): Promise<void> {
  const reason = REASON_DIRECTORY_DELETED;
  // custom-domain aliases always hard-delete into domain_deleted_alias
  if (alias.custom_domain_id) {
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
    return;
  }
  if (
    alias.delete_on !== null ||
    user.alias_delete_action === DELETE_IMMEDIATELY
  ) {
    const existing = await db
      .prepare("SELECT 1 FROM deleted_alias WHERE email = ?1 LIMIT 1")
      .bind(alias.email)
      .first();
    if (!existing) {
      await db
        .prepare(
          "INSERT INTO deleted_alias (email, reason, alias_id, created_at) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(alias.email, alias.delete_reason || reason, alias.id, nowStr())
        .run();
    }
    await db.prepare("DELETE FROM alias WHERE id = ?1").bind(alias.id).run();
    return;
  }
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

webMailboxDomainPagesRoutes.on(
  ["GET", "POST"],
  "/directory",
  requireWebLogin,
  async (c) => {
    const db = c.env.DB;
    const envx = c.env as EnvX;
    const user = c.get("webUser");

    if (c.req.method === "POST") {
      const fd = await c.req.formData();
      const formName = field(fd, "form-name");
      const dirUrl = urlFor("dashboard.directory");
      const invalidRequest = async () => {
        await flash(c, "Invalid request", "warning");
        return c.redirect(dirUrl, 302);
      };
      const loadDir = async (): Promise<DirectoryRow | null> => {
        const id = intFieldRequired(field(fd, "directory_id"));
        if (id === null) return null;
        return db
          .prepare("SELECT * FROM directory WHERE id = ?1")
          .bind(id)
          .first<DirectoryRow>();
      };

      if (formName === "delete") {
        const dirId = intFieldRequired(field(fd, "directory_id"));
        if (!(await csrfOk(c, fd)) || dirId === null) return invalidRequest();
        const dir = await db
          .prepare("SELECT * FROM directory WHERE id = ?1")
          .bind(dirId)
          .first<DirectoryRow>();
        if (!dir) {
          await flash(c, "Unknown error. Refresh the page", "warning");
          return c.redirect(dirUrl, 302);
        }
        if (dir.user_id !== user.id) {
          await flash(c, "You cannot delete this directory", "warning");
          return c.redirect(dirUrl, 302);
        }
        // synchronous: delete every alias of the directory first
        const aliases = await db
          .prepare("SELECT * FROM alias WHERE directory_id = ?1")
          .bind(dir.id)
          .all<AliasRow>();
        for (const alias of aliases.results) {
          await deleteAliasForDirectory(db, alias, user);
        }
        await db
          .prepare("INSERT INTO deleted_directory (name) VALUES (?1)")
          .bind(dir.name)
          .run();
        await db
          .prepare("DELETE FROM directory WHERE id = ?1")
          .bind(dir.id)
          .run();
        await flash(c, `Directory ${dir.name} has been deleted`, "success");
        return c.redirect(dirUrl, 302);
      }

      if (formName === "toggle-directory") {
        const dirId = intFieldRequired(field(fd, "directory_id"));
        if (!(await csrfOk(c, fd)) || dirId === null) return invalidRequest();
        const dir = await loadDir();
        if (!dir || dir.user_id !== user.id) {
          await flash(c, "Unknown error. Refresh the page", "warning");
          return c.redirect(dirUrl, 302);
        }
        const enabled = !!field(fd, "directory_enabled");
        await db
          .prepare(
            "UPDATE directory SET disabled = ?1, updated_at = ?2 WHERE id = ?3",
          )
          .bind(enabled ? 0 : 1, nowStr(), dir.id)
          .run();
        if (enabled) {
          await flash(c, `On-the-fly is enabled for ${dir.name}`, "success");
        } else {
          await flash(c, `On-the-fly is disabled for ${dir.name}`, "warning");
        }
        return c.redirect(dirUrl, 302);
      }

      if (formName === "update") {
        const dirId = intFieldRequired(field(fd, "directory_id"));
        const ids = fd
          .getAll("mailbox_ids")
          .filter((v): v is string => typeof v === "string");
        // UpdateDirForm.mailbox_ids has DataRequired -> empty = invalid form
        if (!(await csrfOk(c, fd)) || dirId === null || ids.length === 0) {
          return invalidRequest();
        }
        const dir = await loadDir();
        if (!dir || dir.user_id !== user.id) {
          await flash(c, "Unknown error. Refresh the page", "warning");
          return c.redirect(dirUrl, 302);
        }
        const mailboxes: MailboxRow[] = [];
        for (const raw of ids) {
          const mb = /^\d+$/.test(raw)
            ? await getMailboxById(db, Number(raw))
            : null;
          if (!mb || mb.user_id !== user.id || !mb.verified) {
            await flash(c, "Something went wrong, please retry", "warning");
            return c.redirect(dirUrl, 302);
          }
          mailboxes.push(mb);
        }
        await db
          .prepare("DELETE FROM directory_mailbox WHERE directory_id = ?1")
          .bind(dir.id)
          .run();
        for (const mb of mailboxes) {
          await db
            .prepare(
              "INSERT INTO directory_mailbox (directory_id, mailbox_id) VALUES (?1, ?2)",
            )
            .bind(dir.id, mb.id)
            .run();
        }
        await flash(c, `Directory ${dir.name} has been updated`, "success");
        return c.redirect(dirUrl, 302);
      }

      if (formName === "create") {
        if (!(await userIsPremium(db, user))) {
          await flash(c, "Only premium plan can add directory", "warning");
          return c.redirect(dirUrl, 302);
        }
        const dirCount = await db
          .prepare("SELECT COUNT(*) AS n FROM directory WHERE user_id = ?1")
          .bind(user.id)
          .first<{ n: number }>();
        const quota = Math.min(
          user.directory_quota,
          MAX_NB_DIRECTORY - (dirCount?.n ?? 0),
        );
        if (quota <= 0) {
          await flash(
            c,
            `You cannot have more than ${MAX_NB_DIRECTORY} directories`,
            "warning",
          );
          return c.redirect(dirUrl, 302);
        }
        const nameRaw = field(fd, "name") ?? "";
        const nameErrors: string[] = [];
        if (nameRaw.trim() === "") nameErrors.push("This field is required.");
        else {
          if (nameRaw.length < 3) {
            nameErrors.push("Field must be at least 3 characters long.");
          }
          if (!/^[a-zA-Z0-9][a-zA-Z0-9-_]+$/.test(nameRaw)) {
            nameErrors.push("Invalid input.");
          }
        }
        if (!(await csrfOk(c, fd)) || nameErrors.length > 0) {
          // form invalid -> fall through to render with field errors
          return renderDirectoryPage(c, nameErrors, nameRaw);
        }
        const newDirName = nameRaw.toLowerCase().trim();
        if (
          await db
            .prepare("SELECT 1 FROM directory WHERE name = ?1")
            .bind(newDirName)
            .first()
        ) {
          await flash(c, `${newDirName} already used`, "warning");
          return c.redirect(dirUrl, 302);
        }
        const reserved = [
          ...RESERVED_DIR_NAMES,
          envx.BOUNCE_PREFIX_FOR_REPLY_PHASE ?? "bounce_reply",
        ];
        if (reserved.includes(newDirName)) {
          await flash(
            c,
            "this directory name is reserved, please choose another name",
            "warning",
          );
          return c.redirect(dirUrl, 302);
        }
        if (
          await db
            .prepare("SELECT 1 FROM deleted_directory WHERE name = ?1")
            .bind(newDirName)
            .first()
        ) {
          await flash(
            c,
            `${newDirName} has been used before and cannot be reused`,
            "error",
          );
          return c.redirect(dirUrl, 302);
        }
        const newDir = await db
          .prepare(
            "INSERT INTO directory (user_id, name) VALUES (?1, ?2) RETURNING *",
          )
          .bind(user.id, newDirName)
          .first<DirectoryRow>();
        // Directory.create permanently decrements the quota column
        await db
          .prepare(
            "UPDATE users SET directory_quota = directory_quota - 1, updated_at = ?1 WHERE id = ?2",
          )
          .bind(nowStr(), user.id)
          .run();
        const ids = fd
          .getAll("mailbox_ids")
          .filter((v): v is string => typeof v === "string");
        if (ids.length > 0) {
          const mailboxes: MailboxRow[] = [];
          for (const raw of ids) {
            const mb = /^\d+$/.test(raw)
              ? await getMailboxById(db, Number(raw))
              : null;
            if (!mb || mb.user_id !== user.id || !mb.verified) {
              await flash(c, "Something went wrong, please retry", "warning");
              return c.redirect(dirUrl, 302);
            }
            if (isAdminDisabled(mb)) {
              await flash(
                c,
                "Cannot assign admin-disabled mailbox. Please contact support.",
                "error",
              );
              return c.redirect(dirUrl, 302);
            }
            mailboxes.push(mb);
          }
          for (const mb of mailboxes) {
            await db
              .prepare(
                "INSERT INTO directory_mailbox (directory_id, mailbox_id) VALUES (?1, ?2)",
              )
              .bind(newDir?.id, mb.id)
              .run();
          }
        }
        await flash(c, `Directory ${newDir?.name} is created`, "success");
        return c.redirect(dirUrl, 302);
      }
      // unknown form-name falls through to render
    }
    return renderDirectoryPage(c);
  },
);

// ===========================================================================
// Route 13: GET|POST /batch_import (sudo, 10/minute POST)
// ===========================================================================

webMailboxDomainPagesRoutes.on(
  ["GET", "POST"],
  "/batch_import",
  requireWebLogin,
  requireWebSudo,
  webRateLimit("batch_import", 10, 60, ["POST"]),
  async (c) => {
    const db = c.env.DB;
    const user = c.get("webUser");
    const verifiedDomains = await db
      .prepare(
        "SELECT COUNT(*) AS n FROM custom_domain WHERE user_id = ?1 AND ownership_verified = 1",
      )
      .bind(user.id)
      .first<{ n: number }>();
    if ((verifiedDomains?.n ?? 0) === 0) {
      await flash(
        c,
        "Alias batch import is only available for custom domains",
        "warning",
      );
    }
    if (user.disable_import) {
      await flash(
        c,
        "you cannot use the import feature, please contact SimpleLogin team",
        "error",
      );
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    const batchImportsRes = await db
      .prepare(
        "SELECT * FROM batch_import WHERE user_id = ?1 AND processed = 0 ORDER BY id",
      )
      .bind(user.id)
      .all<{ id: number; created_at: string; processed: number }>();
    const batchImports = batchImportsRes.results;

    const renderPage = async (status = 200) => {
      const token = await generateCsrfToken(c);
      const vms = [];
      for (const bi of batchImports) {
        const nb = await db
          .prepare("SELECT COUNT(*) AS n FROM alias WHERE batch_import_id = ?1")
          .bind(bi.id)
          .first<{ n: number }>();
        vms.push({
          created_at: bi.created_at,
          processed: !!bi.processed,
          nb_alias: nb?.n ?? 0,
        });
      }
      return render(
        c,
        "dashboard-mailbox/batch_import.html",
        "setting",
        { batch_imports: vms, csrf_form: csrfForm(token) },
        status,
      );
    };

    if (c.req.method === "POST") {
      const fd = await c.req.formData();
      if (!(await csrfOk(c, fd))) {
        await flash(c, "Invalid request", "warning");
        return redirectSelf(c);
      }
      if (batchImports.length > 10) {
        await flash(
          c,
          "You have too many imports already. Please wait until some get cleaned up",
          "error",
        );
        return renderPage();
      }
      const file = fd.get("alias-file");
      if (!(file instanceof File)) {
        // Flask: request.files[...] KeyError -> 400
        return renderErrorPage(c, 400, await buildCurrentUser(c, user));
      }
      const filePath = `${randomString(20)}.csv`;
      const fileRow = await db
        .prepare(
          "INSERT INTO file (path, user_id) VALUES (?1, ?2) RETURNING id",
        )
        .bind(filePath, user.id)
        .first<{ id: number }>();
      // S3 BLOCKER stance: store the CSV in KV, served by /dashboard/files/<path>
      await c.env.KV.put(`file:${filePath}`, await file.arrayBuffer());
      const bi = await db
        .prepare(
          "INSERT INTO batch_import (user_id, file_id) VALUES (?1, ?2) RETURNING id",
        )
        .bind(user.id, fileRow?.id)
        .first<{ id: number }>();
      await db
        .prepare(
          "INSERT INTO job (name, payload, run_at) VALUES ('batch-import', ?1, ?2)",
        )
        .bind(JSON.stringify({ batch_import_id: bi?.id }), nowStr())
        .run();
      await flash(
        c,
        "The file has been uploaded successfully and the import will start shortly",
        "success",
      );
      return c.redirect(urlFor("dashboard.batch_import_route"), 302);
    }
    return renderPage();
  },
);

// ===========================================================================
// Route 14: GET|POST /refused_email (POST behaves exactly like GET)
// ===========================================================================

webMailboxDomainPagesRoutes.on(
  ["GET", "POST"],
  "/refused_email",
  requireWebLogin,
  async (c) => {
    const db = c.env.DB;
    const user = c.get("webUser");
    const highlightRaw = c.req.query("highlight_id");
    const highlightId =
      highlightRaw && /^[+-]?\d+$/.test(highlightRaw.trim())
        ? Number.parseInt(highlightRaw.trim(), 10)
        : null;

    const rows = await db
      .prepare(
        `SELECT el.id AS id, el.bounced AS bounced, el.is_reply AS is_reply,
                ct.website_email AS website_email,
                a.email AS alias_email, a.id AS alias_id,
                re.created_at AS re_created_at, re.deleted AS re_deleted,
                re.delete_at AS re_delete_at, re.path AS re_path,
                re.full_report_path AS re_full_report_path
         FROM email_log el
         JOIN refused_email re ON re.id = el.refused_email_id
         LEFT JOIN contact ct ON ct.id = el.contact_id
         LEFT JOIN alias a ON a.id = ct.alias_id
         WHERE el.user_id = ?1 AND el.refused_email_id IS NOT NULL
         ORDER BY el.id DESC`,
      )
      .bind(user.id)
      .all<{
        id: number;
        bounced: number;
        is_reply: number;
        website_email: string | null;
        alias_email: string | null;
        alias_id: number | null;
        re_created_at: string;
        re_deleted: number;
        re_delete_at: string;
        re_path: string | null;
        re_full_report_path: string;
      }>();

    const emailLogs = rows.results.map((r) => ({
      id: r.id,
      bounced: !!r.bounced,
      is_reply: !!r.is_reply,
      website_email: r.website_email ?? "",
      alias_email: r.alias_email ?? "",
      alias_id: r.alias_id,
      refused_email: {
        created_at: r.re_created_at,
        deleted: !!r.re_deleted,
        delete_at: r.re_delete_at,
        // S3 presigned URL replaced by an authenticated worker route
        url: `/dashboard/files/${encodeURIComponent(r.re_path ?? r.re_full_report_path)}`,
      },
    }));

    if (highlightId !== null) {
      const idx = emailLogs.findIndex((l) => l.id === highlightId);
      // `if highlight_index:` — index 0 is falsy, faithful
      if (idx > 0) {
        const [hl] = emailLogs.splice(idx, 1);
        emailLogs.unshift(hl);
      }
    }

    return render(c, "dashboard-mailbox/refused_email.html", "setting", {
      email_logs: emailLogs,
      highlight_id: highlightId,
    });
  },
);

// ===========================================================================
// File download route (S3 presigned-URL replacement, port stance)
// ===========================================================================

webMailboxDomainPagesRoutes.get("/files/:path", requireWebLogin, async (c) => {
  const db = c.env.DB;
  const user = c.get("webUser");
  const path = c.req.param("path");
  const owned = await db
    .prepare(
      `SELECT 1 FROM file WHERE path = ?1 AND user_id = ?2
       UNION
       SELECT 1 FROM refused_email
        WHERE (path = ?1 OR full_report_path = ?1) AND user_id = ?2`,
    )
    .bind(path, user.id)
    .first();
  if (!owned) return renderErrorPage(c, 404, await buildCurrentUser(c, user));
  const body = await c.env.KV.get(`file:${path}`, "arrayBuffer");
  if (!body) return renderErrorPage(c, 404, await buildCurrentUser(c, user));
  return new Response(body, {
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="${path}"`,
    },
  });
});
