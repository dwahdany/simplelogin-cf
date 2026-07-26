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
 * - PGP key import runs on openpgp.js instead of gnupg (src/lib/pgp.ts):
 *   same load-and-test-encrypt semantics and UPPERCASE hex fingerprint as
 *   Flask's load_public_key_and_check, same flashes.
 * - Mailbox.is_proton() uses only the static domain list (no MX lookup).
 * - S3 uploads/presigned URLs are replaced by KV objects (`file:<path>`)
 *   served from GET /dashboard/files/<path> with an ownership check.
 * - Legacy itsdangerous-signed links (mailbox_verify / confirm_change without
 *   `code`) are rejected with the documented "Invalid link" flashes.
 * - Custom-domain DNS verification is adapted to this deployment's mail
 *   platform (Cloudflare Email Routing inbound / Email Sending outbound):
 *   the MX check compares host SETS ignoring priorities (see
 *   isMxHostSetEquivalent), the expected SPF include is Cloudflare's
 *   _spf.mx.cloudflare.net instead of Flask's {EMAIL_DOMAIN} (see
 *   SPF_INCLUDE_DOMAIN), and DKIM verifies on the primary dkim._domainkey
 *   CNAME alone (see the check-dkim branch). Rationale at each site.
 */

import type { Context, MiddlewareHandler } from "hono";
import { Hono } from "hono";
import {
  CatchAllConflictError,
  CfApiError,
  type CfCatchAllRule,
  CfClient,
  type CfTokenProvider,
  catchAllConflict,
  ensureCatchAllToWorker,
  ensureEmailRouting,
  ensureTxtRecord,
  ForeignMxError,
} from "../lib/cfapi";
import { REFRESH_SKEW_SECS, resolveAccessToken } from "../lib/cfoauth";
import { randomString, sanitizeEmail, tokenUrlsafe } from "../lib/crypto";
import { addDays, nowStr, toDate, toStr } from "../lib/dates";
import type { Env } from "../lib/env";
import { sendTransactionalEmail } from "../lib/mailer";
import {
  getCustomDomainById,
  getMailboxById,
  userIsPremium,
} from "../lib/models";
import { loadPublicKeyAndCheck, PGPException } from "../lib/pgp";
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
import { webLimiter } from "../lib/web/limiter";
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
import {
  type CfOauthPageStatus,
  cfOauthPageStatus,
  operatorAccountId,
} from "./cloudflare-pages";

export const webMailboxDomainPagesRoutes = new Hono<WebEnv>();

type C = Context<WebEnv>;

// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

const FLAG_ADMIN_DISABLED = 1; // Mailbox.FLAG_ADMIN_DISABLED
const MAX_ACTIVATION_TRIES = 3;
const MAX_MAILBOXES_PER_DOMAIN = 20;
const ALIAS_TRASH_DAYS = 30;
const DELETE_IMMEDIATELY = 1; // UserAliasDeleteAction.DeleteImmediately
const REASON_DIRECTORY_DELETED = 3; // AliasDeleteReason.DirectoryDeleted
const DMARC_RECORD = "v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s";

/**
 * Expected SPF include for custom domains. DELIBERATE DEVIATION from Flask
 * (custom_domain_validation.py get_expected_spf_domain L113-121: the include
 * is config.EMAIL_DOMAIN, i.e. simplelogin.co on the original deployment):
 * on this deployment outbound alias mail is sent through Cloudflare Email
 * Sending, so the SPF include that actually authorizes the sending servers
 * is Cloudflare's, not the worker's EMAIL_DOMAIN (whose zone publishes the
 * same include itself). The check-spf failure flash (Flask domain_detail.py
 * L103 names config.EMAIL_DOMAIN) names this domain for the same reason.
 */
const SPF_INCLUDE_DOMAIN = "_spf.mx.cloudflare.net";

// Flask config.py L142-143 hardcodes MAX_NB_DIRECTORY = 50 and
// MAX_NB_SUBDOMAIN = 5; this port reads env vars of the same name
// (src/lib/env.ts) with the Flask values as defaults (unset/"" or a
// non-numeric value counts as unset).
const DEFAULT_MAX_NB_SUBDOMAIN = 5;
const DEFAULT_MAX_NB_DIRECTORY = 50;

function envInt(raw: string | undefined, fallback: number): number {
  const n = Number.parseInt(raw ?? "", 10);
  return Number.isNaN(n) ? fallback : n;
}

function maxNbSubdomain(env: EnvX): number {
  return envInt(env.MAX_NB_SUBDOMAIN, DEFAULT_MAX_NB_SUBDOMAIN);
}

function maxNbDirectory(env: EnvX): number {
  return envInt(env.MAX_NB_DIRECTORY, DEFAULT_MAX_NB_DIRECTORY);
}

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

// wtforms 2.3.3 Email() delegates to the email_validator package
// (check_deliverability=False, allow_smtputf8=True, allow_empty_local=False).
// Syntax-only port: dot-atom local part (unicode allowed by smtputf8),
// hostname-shaped domain with at least one dot whose TLD ends in a letter.
// No IDNA library on Workers: non-ASCII labels are accepted as-is.
const EV_LOCAL_ATOM_RE = /^[A-Za-z0-9_!#$%&'*+\-/=?^`{|}~\u{80}-\u{10FFFF}]+$/u;
const EV_DOMAIN_LABEL_RE =
  /^[A-Za-z0-9\u{80}-\u{10FFFF}](?:[A-Za-z0-9\-\u{80}-\u{10FFFF}]{0,61}[A-Za-z0-9\u{80}-\u{10FFFF}])?$/u;

/** wtforms 2.3.3 Email() validator (via email_validator ~=2.2). */
function isEmailFieldValid(v: string): boolean {
  if (v.length > 254) return false; // EMAIL_MAX_LENGTH
  const at = v.lastIndexOf("@");
  if (at === -1) return false;
  const local = v.slice(0, at);
  const domain = v.slice(at + 1);
  // validate_email_local_part: non-empty dot-atom, <= 64 chars
  if (local.length === 0 || local.length > 64) return false;
  for (const atom of local.split(".")) {
    if (!EV_LOCAL_ATOM_RE.test(atom)) return false;
  }
  // validate_email_domain_name (globally_deliverable=True)
  if (domain.length === 0 || domain.length > 253) return false;
  if (!domain.includes(".")) return false;
  for (const label of domain.split(".")) {
    if (!EV_DOMAIN_LABEL_RE.test(label)) return false;
    // RFC 5890 R-LDH labels: "??--" is only allowed as Punycode ("xn--")
    if (/^(?!xn)..--/i.test(label)) return false;
  }
  // "all TLDs currently end with a letter" (email_validator DOMAIN_NAME_REGEX)
  return /[A-Za-z\u{80}-\u{10FFFF}]$/u.test(domain);
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

/**
 * Python `re` pattern → JS RegExp source+flags. Flask validates auto-create
 * rule regexes with re.compile (domain_detail.py L437-443) and matches with
 * re2/re fullmatch (regex_utils.py), whose syntax differs from JS RegExp:
 * - `(?P<name>...)` / `(?P=name)` are Python-only → translated to the JS
 *   equivalents `(?<name>...)` / `\k<name>`;
 * - bare `(?<name>...)` and `\k<name>` are Python ERRORS ("unknown extension
 *   ?<n" / "bad escape \k") even though JS accepts them → rejected;
 * - global inline flags like `(?i)` (start of pattern only, as required by
 *   Python 3.11+) become JS flags.
 * Exotic Python-only syntax ((?x) verbose mode, \A/\Z, conditionals) is not
 * modeled: it throws here / at RegExp() and counts as an invalid pattern.
 */
function translatePythonRegex(pattern: string): {
  source: string;
  flags: string;
} {
  let src = pattern;
  let flags = "";
  const flagsMatch = /^\(\?([aiLmsux]+)\)/.exec(src);
  if (flagsMatch) {
    if (/[Lx]/.test(flagsMatch[1])) {
      throw new Error(`unsupported inline flags ${flagsMatch[1]}`);
    }
    for (const f of flagsMatch[1]) if ("ims".includes(f)) flags += f;
    src = src.slice(flagsMatch[0].length);
  }
  let out = "";
  let inClass = false;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (ch === "\\") {
      const next = src[i + 1] ?? "";
      // Python re: "bad escape \k" (JS would read it as a named backref)
      if (!inClass && next === "k") throw new Error("bad escape \\k");
      out += ch + next;
      i++;
      continue;
    }
    if (inClass) {
      if (ch === "]") inClass = false;
      out += ch;
      continue;
    }
    if (ch === "[") {
      inClass = true;
      out += ch;
      continue;
    }
    if (ch === "(" && src.startsWith("(?P<", i)) {
      out += "(?"; // drop the "P": JS named-group syntax
      i += 2; // loop's i++ lands on "<"
      continue;
    }
    if (ch === "(" && src.startsWith("(?P=", i)) {
      const end = src.indexOf(")", i);
      if (end === -1) throw new Error("missing ), unterminated name");
      const name = src.slice(i + 4, end);
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
        throw new Error(`bad character in group name ${name}`);
      }
      out += `\\k<${name}>`;
      i = end;
      continue;
    }
    if (
      ch === "(" &&
      src.startsWith("(?<", i) &&
      src[i + 3] !== "=" &&
      src[i + 3] !== "!"
    ) {
      // Python re: "unknown extension ?<x" — only lookbehinds use (?<
      throw new Error(`unknown extension ?<${src[i + 3] ?? ""}`);
    }
    out += ch;
  }
  return { source: out, flags };
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
      maxNbSubdomain(c.env as EnvX) - (subCount?.n ?? 0),
    ),
    directory_quota: Math.min(
      user.directory_quota,
      maxNbDirectory(c.env as EnvX) - (dirCount?.n ?? 0),
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

/** True when `e` is D1 telling us the (optional) blocklist table is absent. */
function isMissingTableError(e: unknown): boolean {
  return String(e).includes("no such table");
}

/**
 * is_invalid_mailbox_domain (email_utils.py L793): the domain or ANY parent
 * suffix (excluding the bare TLD) is listed in invalid_mailbox_domain. A
 * missing table counts as an empty blocklist (optional table, like the API).
 */
async function isInvalidMailboxDomain(
  db: D1Database,
  domain: string,
): Promise<boolean> {
  const parts = domain.split(".");
  const suffixes: string[] = [];
  for (let i = 0; i < parts.length - 1; i++) {
    suffixes.push(parts.slice(i).join("."));
  }
  if (suffixes.length === 0) return false;
  const placeholders = suffixes.map((_, i) => `?${i + 1}`).join(", ");
  try {
    const row = await db
      .prepare(
        `SELECT 1 FROM invalid_mailbox_domain WHERE domain IN (${placeholders}) LIMIT 1`,
      )
      .bind(...suffixes)
      .first();
    return !!row;
  } catch (e) {
    if (isMissingTableError(e)) return false;
    throw e;
  }
}

/** ForbiddenMxIp.filter(ip.in_(mx_ips)) — missing table = empty blocklist. */
async function hasForbiddenMxIp(
  db: D1Database,
  ips: string[],
): Promise<boolean> {
  const placeholders = ips.map((_, i) => `?${i + 1}`).join(", ");
  try {
    const row = await db
      .prepare(
        `SELECT 1 FROM forbidden_mx_ip WHERE ip IN (${placeholders}) LIMIT 1`,
      )
      .bind(...ips)
      .first();
    return !!row;
  } catch (e) {
    if (isMissingTableError(e)) return false;
    throw e;
  }
}

/**
 * email_can_be_used_as_mailbox_with_reason() + check_domain_for_mailbox()
 * (email_utils.py L660-L779): returns the reason value string or null.
 * The domain is always ASCII here — isValidEmail() ran first.
 */
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
  if (await isInvalidMailboxDomain(db, domain)) {
    return "We don't allow mailboxes using this domain";
  }
  // SKIP_MX_LOOKUP_ON_CHECK is hardcoded False (config.py, tests only).
  const mxDomains = await mailboxDnsClient.getMxDomainList(domain);
  if (mxDomains.length === 0) {
    return "We couldn't get any MX records configured for this domain";
  }
  const mxIps = new Set<string>();
  for (const mxDomain of mxDomains) {
    if (await isInvalidMailboxDomain(db, mxDomain)) {
      return "We don't allow mailboxes using this domain";
    }
    const aRecord = await mailboxDnsClient.getARecord(mxDomain);
    if (aRecord !== null) mxIps.add(aRecord);
  }
  if (mxIps.size > 0 && (await hasForbiddenMxIp(db, [...mxIps]))) {
    return "We don't allow mailbox domains that point to these MX records";
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
  type: "TXT" | "MX" | "CNAME" | "A",
): Promise<DnsAnswer[]> {
  const typeNum = { TXT: 16, MX: 15, CNAME: 5, A: 1 }[type];
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

/**
 * DNS client used by the mailbox-domain checks (get_mx_domain_list +
 * get_a_record in app/email_utils.py check_domain_for_mailbox), with the
 * same test seam as src/routes/mailboxes.ts `setDnsClient` (which cannot be
 * imported from here).
 */
export interface MailboxDnsClient {
  /** get_mx_domain_list(): MX hosts without the trailing dot; [] on failure. */
  getMxDomainList(hostname: string): Promise<string[]>;
  /** get_a_record(): first A-record IP for the hostname, or null. */
  getARecord(hostname: string): Promise<string | null>;
}

const dohMailboxDnsClient: MailboxDnsClient = {
  async getMxDomainList(hostname) {
    const mxDomains: string[] = [];
    for (const answer of await dohLookup(hostname, "MX")) {
      // record data looks like "20 alt2.aspmx.l.google.com."
      const host = answer.data.split(" ")[1];
      if (host) mxDomains.push(host.endsWith(".") ? host.slice(0, -1) : host);
    }
    return mxDomains;
  },
  async getARecord(hostname) {
    const answers = await dohLookup(hostname, "A");
    return answers[0]?.data ?? null;
  },
};

let mailboxDnsClient: MailboxDnsClient = dohMailboxDnsClient;

/** Test seam (tests run in the same isolate as SELF). `null` restores DoH. */
export function setMailboxDnsClient(client: MailboxDnsClient | null): void {
  mailboxDnsClient = client ?? dohMailboxDnsClient;
}

async function getCnameRecord(name: string): Promise<string | null> {
  const answers = await dohLookup(name, "CNAME");
  if (answers.length === 0) return null;
  let data = answers[0].data;
  if (data.endsWith(".")) data = data.slice(0, -1);
  return data;
}

/**
 * DNS client used by the custom-domain DNS checks (route 7 check-ownership /
 * check-mx / check-spf / check-dkim / check-dmarc and the cf-provision
 * re-verification), with the same test-seam pattern as setMailboxDnsClient
 * below. Production resolves over DoH; tests substitute an in-memory view.
 */
export interface DomainDnsClient {
  /** TXT character-strings at `domain`, unquoted/joined; [] on failure. */
  getTxtRecords(domain: string): Promise<string[]>;
  /** MX records as {priority: [target-with-trailing-dot, ...]}. */
  getMxDomains(domain: string): Promise<Map<number, string[]>>;
  /** CNAME target without the trailing dot, or null. */
  getCnameRecord(name: string): Promise<string | null>;
}

const dohDomainDnsClient: DomainDnsClient = {
  getTxtRecords,
  getMxDomains,
  getCnameRecord,
};

let domainDnsClient: DomainDnsClient = dohDomainDnsClient;

/** Test seam (tests run in the same isolate as SELF). `null` restores DoH. */
export function setDomainDnsClient(client: DomainDnsClient | null): void {
  domainDnsClient = client ?? dohDomainDnsClient;
}

export interface ExpectedMx {
  priority: number;
  recommended: string;
  allowed: string[];
}

/**
 * config.EMAIL_SERVERS_WITH_PRIORITY -> [(priority, host), ...] (config.py
 * L184-186). Flask reads a Python literal via literal_eval, e.g.
 * `[(10, "mx1.simplelogin.co."), (20, "mx2.simplelogin.co.")]`; this port
 * keeps the same semantics with a TS-friendly spelling: comma-separated
 * "<priority> <host>" pairs. Production value on this deployment (Cloudflare
 * Email Routing's hosts):
 * "10 route1.mx.cloudflare.net.,20 route2.mx.cloudflare.net.,30 route3.mx.cloudflare.net."
 * A trailing dot is appended when missing. "" counts as unset (src/lib/env.ts)
 * and keeps the fallback mx1/mx2.{EMAIL_DOMAIN} pair (Flask has no fallback —
 * the var is mandatory there). Exported for unit tests.
 */
export function expectedMxRecords(env: {
  EMAIL_DOMAIN: string;
  EMAIL_SERVERS_WITH_PRIORITY?: string;
}): ExpectedMx[] {
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

/**
 * MX verification passes when the domain's actual MX HOST SET equals the
 * expected host set — hosts compared case-insensitively with a normalized
 * trailing dot — IGNORING priorities and record order.
 *
 * DELIBERATE DEVIATION from Flask's is_mx_equivalent
 * (custom_domain_validation.py L28-52), which requires the found priority
 * COUNT to equal the expected record count and, walking found priorities in
 * ascending order, every host at position i to be allowed by the i-th
 * expected record: Cloudflare Email Routing creates the
 * route1/2/3.mx.cloudflare.net records itself with per-zone priorities the
 * operator can neither predict nor configure, so the positional check could
 * never accept a correctly-onboarded zone. Host-set equality keeps the
 * strictness that matters (no missing hosts, no extra/leftover MX hosts that
 * could siphon mail) while tolerating Cloudflare-assigned priorities.
 * Pure function, exported so tests can unit-test it without DoH.
 */
export function isMxHostSetEquivalent(
  mxDomains: Map<number, string[]>,
  expectedMxDomains: ExpectedMx[],
): boolean {
  const normalize = (host: string) => {
    const h = host.trim().toLowerCase();
    return h.endsWith(".") ? h : `${h}.`;
  };
  const found = new Set<string>();
  for (const targets of mxDomains.values()) {
    for (const target of targets) found.add(normalize(target));
  }
  const expected = new Set<string>();
  for (const record of expectedMxDomains) {
    for (const target of record.allowed) expected.add(normalize(target));
  }
  if (found.size !== expected.size) return false;
  for (const host of found) {
    if (!expected.has(host)) return false;
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
        if (transferRaw !== null) {
          // wtforms IntegerField coerces ANY submitted value: int('') raises,
          // so a present-but-empty field is a validation error, not "absent"
          // (DeleteMailboxForm has no Optional() — mailbox.py L29-33).
          const trimmed = transferRaw.trim();
          if (!/^[+-]?\d+$/.test(trimmed)) transferValid = false;
          else transferMailboxId = Number.parseInt(trimmed, 10);
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
        const spfStatus = field(fd, "spf-status");
        const enabled = spfStatus === "on";
        await db
          .prepare(
            "UPDATE mailbox SET force_spf = ?1, updated_at = ?2 WHERE id = ?3",
          )
          .bind(enabled ? 1 : 0, nowStr(), mailbox.id)
          .run();
        // Faithful operator-precedence bug (mailbox_detail.py L89-94): the
        // message is keyed on the TRUTHINESS of spf-status (any non-empty
        // value), while the DB write is keyed on == "on".
        await flash(
          c,
          spfStatus ? "SPF enforcement was enabled" : "disabled successfully",
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
          // mailbox_detail.py L164-181: validate with a test encryption, then
          // store key + fingerprint. On PGPException Flask flashes and falls
          // through to render — WITHOUT rolling back the in-session
          // `mailbox.pgp_public_key = <submitted>` assignment (L164), so the
          // rendered textarea shows the rejected key (never committed).
          const submitted = field(fd, "pgp");
          let fingerprint: string;
          try {
            fingerprint = await loadPublicKeyAndCheck(submitted ?? "");
          } catch (e) {
            if (!(e instanceof PGPException)) throw e;
            await flash(
              c,
              "Cannot add the public key, please verify it",
              "error",
            );
            return renderMailboxDetail(c, {
              ...mailbox,
              pgp_public_key: submitted,
            });
          }
          await db
            .prepare(
              `UPDATE mailbox SET pgp_public_key = ?1, pgp_finger_print = ?2,
               updated_at = ?3 WHERE id = ?4`,
            )
            .bind(submitted, fingerprint, nowStr(), mailbox.id)
            .run();
          await flash(
            c,
            "Your PGP public key is saved successfully",
            "success",
          );
          return c.redirect(detailUrl, 302);
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
        // CustomDomain.create raises SubdomainInTrashError for ANY domain in
        // deleted_subdomain (models.py L2682-2686); the custom_domain view
        // does not catch it, so Flask 500s with no row created. Same here:
        // throw and let app.onError render the 500 page.
        if (
          await db
            .prepare("SELECT 1 FROM deleted_subdomain WHERE domain = ?1")
            .bind(domain)
            .first()
        ) {
          throw new Error(`SubdomainInTrashError: ${domain}`);
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
// One-click Cloudflare provisioning ("Auto-configure on Cloudflare"): the
// dashboard-side port of scripts/provision-domain.mjs, run from route 7's
// cf-provision form via src/lib/cfapi.ts.
// ===========================================================================

/**
 * Feature gate. EITHER credential enables the action (see
 * cfProvisionCredential for the preference order):
 * - the acting user's Cloudflare OAuth grant (src/lib/cfoauth.ts), or
 * - the operator-wide static API token (wrangler secret CF_API_TOKEN; ""
 *   counts as unset like the other presence-based vars, src/lib/env.ts).
 * With neither, the button is not rendered and the POST branch behaves as an
 * unknown form-name.
 *
 * A grant that exists but currently yields no access token (refresh failed)
 * still counts as available: the click then reports precisely what is wrong
 * instead of the button silently disappearing — and the panel says so up
 * front when the row itself already proves it (CfOauthPageStatus
 * `needs_reconnect`: expired with no refresh token).
 */
function cfProvisionAvailableWith(
  envx: EnvX,
  oauth: CfOauthPageStatus | null,
): boolean {
  return !!oauth?.connected || (envx.CF_API_TOKEN ?? "") !== "";
}

/** Same predicate for callers that have not fetched the OAuth status. */
async function cfProvisionAvailable(
  envx: EnvX,
  userId: number,
): Promise<boolean> {
  // the static token short-circuits the D1 read
  if ((envx.CF_API_TOKEN ?? "") !== "") return true;
  return cfProvisionAvailableWith(envx, await cfOauthPageStatus(envx, userId));
}

/**
 * Which Cloudflare credential the provision action runs under, in preference
 * order:
 *
 * 1. the ACTING USER's OAuth grant — delegated, revocable by them from the
 *    Cloudflare dashboard, and limited to the account they connected;
 * 2. the operator-wide static CF_API_TOKEN.
 *
 * A grant that exists but yields NO token right now ("stale-grant") is a
 * refusal, NOT a silent downgrade: falling back would run the whole thing
 * under the operator's account-wide credential — the one that can "prove"
 * ownership of any zone it can edit — while both the panel and the DNS page
 * tell the user their delegated access is what is in use, and while a user
 * could force that downgrade at will by revoking the app at Cloudflare.
 *
 * The OAuth access token is resolved ONCE and then held for the run, and
 * re-resolved only when it actually enters the 60 s refresh skew window
 * (CfTokenProvider is called before every one of the ~10 API calls, and each
 * resolution otherwise costs a D1 read plus two AES-GCM decrypts — and, for
 * a short-lived token, a POST to the token endpoint plus a D1 write). A
 * token that ages out mid-run is therefore still replaced transparently.
 * It deliberately does NOT fall back to CF_API_TOKEN mid-run either —
 * switching identity halfway would finish writing to the zone under an
 * authorization the user never granted. A grant that dies mid-run surfaces
 * as a CfApiError 401, which handleCfProvision turns into the reconnect
 * flash.
 */
type CfCredentialChoice =
  | { source: "oauth"; provider: CfTokenProvider }
  | { source: "token"; token: string }
  /** grant row exists but produces no token: refuse, never downgrade */
  | { source: "stale-grant" }
  | { source: "none" };

async function cfProvisionCredential(
  envx: EnvX,
  userId: number,
): Promise<CfCredentialChoice> {
  const status = await cfOauthPageStatus(envx, userId);
  if (status.connected) {
    const first = await resolveAccessToken(envx, userId);
    if (!first) return { source: "stale-grant" };
    let cached = first;
    return {
      source: "oauth",
      provider: async () => {
        const staleAtMs =
          cached.expiresAtMs === null
            ? Number.POSITIVE_INFINITY
            : cached.expiresAtMs - REFRESH_SKEW_SECS * 1000;
        if (Date.now() < staleAtMs) return cached.token;
        const fresh = await resolveAccessToken(envx, userId);
        if (!fresh) {
          throw new CfApiError(
            "the Cloudflare OAuth grant is no longer usable",
            401,
          );
        }
        cached = fresh;
        return fresh.token;
      },
    };
  }
  const token = envx.CF_API_TOKEN ?? "";
  return token !== "" ? { source: "token", token } : { source: "none" };
}

/**
 * SECURITY guards. The provision action plants the ownership TXT record with
 * a Cloudflare credential the dashboard user does not necessarily own, and
 * then runs the ownership check against it — i.e. clicking the button
 * "proves" domain ownership for any zone that credential can edit. Under the
 * operator-wide CF_API_TOKEN that is every zone in the operator's account:
 * a non-operator dashboard user who adds a custom domain whose zone lives
 * there (most plausibly the deployment's own zones) could hijack its mail
 * that way. Registration is closed on this deployment, but the code must not
 * assume that forever — and CF_API_TOKEN should additionally be zone-scoped
 * to only the zones the operator intends for SimpleLogin. A per-user OAuth
 * grant narrows the blast radius to the account that user connected, but
 * these guards apply to BOTH credentials (one code path). Two layers:
 *
 * 1. cfProvisionCollision (string-level, before any API call): refuse when
 *    the domain equals, is a subdomain of, or is a PARENT of any deployment
 *    mail domain (a parent's zone contains the deployment domain, and
 *    custom_domain rows for parents of verified domains are otherwise
 *    creatable).
 * 2. cfProvisionZoneCollision (zone-level, after findZone): refuse when the
 *    RESOLVED ZONE contains (or is) a deployment mail domain. This is what
 *    blocks SIBLING hostnames — e.g. EMAIL_DOMAIN mail.example.com lives
 *    in zone example.com, and foo.example.com passes the string guard while
 *    findZone still lands in the operator's own zone. Token zone-scoping
 *    cannot cover this case: the token must be able to edit the very zone
 *    hosting EMAIL_DOMAIN.
 *
 * The deployment set covers EMAIL_DOMAIN, FIRST_ALIAS_DOMAIN, ALIAS_DOMAINS,
 * PREMIUM_ALIAS_DOMAINS AND every `public_domain` row (public domains — the
 * source of SL subdomains — are valid alias domains even when not mirrored
 * into ALIAS_DOMAINS; see src/email.ts isValidAliasAddressDomain).
 */
async function deploymentMailDomains(
  db: D1Database,
  envx: EnvX,
): Promise<string[]> {
  const rows = await db
    .prepare("SELECT domain FROM public_domain")
    .all<{ domain: string }>();
  const out: string[] = [];
  for (const raw of [
    envx.EMAIL_DOMAIN,
    envx.FIRST_ALIAS_DOMAIN,
    ...(envx.ALIAS_DOMAINS ?? "").split(","),
    ...(envx.PREMIUM_ALIAS_DOMAINS ?? "").split(","),
    ...rows.results.map((r) => r.domain),
  ]) {
    const p = (raw ?? "").trim().toLowerCase().replace(/\.$/, "");
    if (p && !out.includes(p)) out.push(p);
  }
  return out;
}

/** Layer 1: the domain string overlaps a deployment domain (see above). */
function cfProvisionCollision(
  deployment: string[],
  domain: string,
): string | null {
  const d = domain.toLowerCase().replace(/\.$/, "");
  for (const p of deployment) {
    if (d === p || d.endsWith(`.${p}`) || p.endsWith(`.${d}`)) return p;
  }
  return null;
}

/** Layer 2: the resolved zone hosts a deployment domain (see above). */
function cfProvisionZoneCollision(
  deployment: string[],
  zoneName: string,
): string | null {
  const z = zoneName.toLowerCase().replace(/\.$/, "");
  for (const p of deployment) {
    if (p === z || p.endsWith(`.${z}`)) return p;
  }
  return null;
}

/**
 * POST cf-provision: perform scripts/provision-domain.mjs server-side (zone
 * lookup -> read-only conflict preflight -> Email Routing -> catch-all ->
 * ownership TXT -> DMARC), then re-run the page's ownership/MX/SPF/DMARC
 * checks in-process, persisting the flags exactly like the manual check
 * buttons (success only — a failed re-check never clears a flag). Every
 * step is check-before-write (safe to re-click), every refusal condition
 * (foreign catch-all, foreign MX, deployment-zone collision) is evaluated
 * BEFORE the first write, and the final flash reports done/skipped per step
 * plus the two manual leftovers: Email Sending onboarding (no public write
 * API as of 2026-07-26) and destination-address verification
 * (docs/DOMAINS.md §1.4/§1.6).
 *
 * Runs under the acting user's Cloudflare OAuth grant when they have one,
 * else the operator's CF_API_TOKEN (cfProvisionCredential) — and refuses
 * outright, rather than downgrading to CF_API_TOKEN, when a grant exists but
 * is no longer usable. The credential choice changes NOTHING else: both go
 * through the very same gauntlet (deployment-domain collision, zone-boundary
 * collision, worker-account check, read-only catch-all + foreign-MX
 * preflight before the first write, rate limit) — there is exactly one
 * provisioning code path.
 *
 * Flashes never include zone names/ids, tokens or raw Cloudflare API error
 * text (request paths contain zone ids; error bodies contain token-scope
 * details) — full errors go to console.error for the operator.
 */
async function handleCfProvision(c: C, cd: CustomDomainRow): Promise<Response> {
  const db = c.env.DB;
  const envx = c.env as EnvX;
  const back = () =>
    c.redirect(
      urlFor("dashboard.domain_detail_dns", { custom_domain_id: cd.id }),
      302,
    );

  const deployment = await deploymentMailDomains(db, envx);
  const collision = cfProvisionCollision(deployment, cd.domain);
  if (collision) {
    await flash(
      c,
      `Auto-configuration is not available for ${cd.domain}: it overlaps ` +
        `with this SimpleLogin deployment's own domain ${collision}. ` +
        "Please set up the DNS records manually.",
      "error",
    );
    return back();
  }

  // Credential: the user's OAuth grant first, then the operator's token.
  const credential = await cfProvisionCredential(envx, c.get("webUser").id);
  if (credential.source === "none") {
    // Only reachable when the grant went away between the page render (or
    // the gate check) and this POST.
    await flash(
      c,
      "Auto-configuration is not available right now: this SimpleLogin " +
        "instance has no usable Cloudflare credential. Connect your " +
        "Cloudflare account again, or ask the operator to configure one",
      "error",
    );
    return back();
  }
  if (credential.source === "stale-grant") {
    // A grant exists but produced no access token (refresh failed, or the
    // authorization was revoked at Cloudflare). We do NOT quietly continue
    // under the operator's account-wide CF_API_TOKEN: the pages say the
    // delegated access is what runs, and a user must not be able to trade
    // down to the operator's credential by revoking us at Cloudflare.
    // Wording note: getValidAccessToken has usually just DELETED the dead
    // row, so there is no Disconnect button left to press — never tell the
    // user to "disconnect and reconnect", only to connect again.
    await flash(
      c,
      "Your connected Cloudflare account could not be used (the " +
        "authorization expired or was revoked at Cloudflare), so nothing " +
        "was changed. Please connect your Cloudflare account again, then " +
        "retry",
      "error",
    );
    return back();
  }
  const client = new CfClient(
    credential.source === "oauth" ? credential.provider : credential.token,
  );
  const worker = envx.CF_WORKER_NAME || "simplelogin";
  const done: string[] = [];

  try {
    // 1. zone lookup (exact name, then walking up parent labels)
    const zone = await client.findZone(cd.domain);
    if (!zone) {
      // The lookup ran against whichever account the CREDENTIAL belongs to,
      // so name that one: under a grant it is the user's own connected
      // account (which they can fix themselves), under CF_API_TOKEN the
      // operator's (which they cannot).
      await flash(
        c,
        credential.source === "oauth"
          ? `No zone for ${cd.domain} was found in the Cloudflare account ` +
              "you connected. Add the domain to that Cloudflare account " +
              "first (Account Home > Add a domain), then retry — or connect " +
              "the Cloudflare account that holds this domain's zone"
          : `No zone for ${cd.domain} was found in the operator's Cloudflare ` +
              "account. Add the domain to that Cloudflare account first " +
              "(Account Home > Add a domain), then retry",
        "error",
      );
      return back();
    }
    // 2. zone-boundary guard: the resolved zone must not host any of this
    // deployment's own mail domains — otherwise clicking the button would
    // let a user plant records (and self-verify a sibling hostname) inside
    // the operator's own zone. See cfProvisionZoneCollision above.
    if (cfProvisionZoneCollision(deployment, zone.name)) {
      await flash(
        c,
        `Auto-configuration is not available for ${cd.domain}: its zone ` +
          "hosts this SimpleLogin deployment's own domains. Please set up " +
          "the DNS records manually.",
        "error",
      );
      return back();
    }
    // 2b. account guard: Cloudflare Email Routing can only deliver a zone's
    // mail to a Worker in the SAME account, and the catch-all this code
    // writes names CF_WORKER_NAME with no account qualifier. A zone in
    // another account therefore CANNOT be finished: the Email-Routing enable
    // would succeed (writing + locking MX), and the catch-all PUT would then
    // fail — leaving the zone advertising Cloudflare MX with no rule behind
    // them, i.e. rejecting its own mail. Refuse before the first write.
    // Fails OPEN when either side is unknown (no CF_ACCOUNT_ID pinned, or a
    // /zones response without `account`): this must never be the reason a
    // correctly-configured instance stops working.
    const pinnedAccount = operatorAccountId(envx);
    const zoneAccount = zone.account?.id;
    if (pinnedAccount && zoneAccount && zoneAccount !== pinnedAccount) {
      console.error(
        `cf-provision: zone for ${cd.domain} is in account ${zoneAccount}, ` +
          `worker account is ${pinnedAccount}`,
      );
      await flash(
        c,
        `Auto-configuration is not available for ${cd.domain}: its zone is ` +
          "not in the Cloudflare account that hosts this instance's mail " +
          "worker, and Cloudflare Email Routing can only deliver a zone's " +
          "mail to a worker in the same account. Move the zone to that " +
          "account, or set up the DNS records manually",
        "error",
      );
      return back();
    }
    done.push("zone found");

    // 3. read-only preflight + writes, refusing on any foreign live mail
    // configuration BEFORE the first write: the apex Email Routing enable
    // creates + locks the MX/SPF set, which must never happen to a zone
    // whose mail currently goes elsewhere (and a refusal after it would
    // leave the zone half-configured).
    try {
      // catch-all first (the GET may legitimately fail on a zone where
      // routing was never enabled — then ensureCatchAllToWorker re-reads it
      // after the enable, when the endpoint is guaranteed to exist).
      let preRule: CfCatchAllRule | null | undefined;
      try {
        preRule = await client.getCatchAll(zone.id);
      } catch (e) {
        if (!(e instanceof CfApiError)) throw e;
        // "Routing was never enabled here" is a 404/4xx about the RESOURCE.
        // An AUTHORIZATION failure means the opposite: we do not know the
        // zone's catch-all state, and the very next step (ensureEmailRouting
        // -> enableEmailRouting on an apex) is a WRITE that creates and locks
        // the zone's MX/SPF set. Swallowing a 401/403 here would enable
        // Cloudflare mail on the zone and only then fail on the catch-all,
        // leaving inbound mail rejected — and every retry would repeat it.
        // This is the likely shape of a scope misconfiguration: the catch-all
        // endpoints are the ones gated on Email Routing Rules, so an OAuth
        // client with correct dns.*/zone-settings.* but wrong
        // email-routing-rule.* ids 403s exactly (and only) here.
        if (e.status === 401 || e.status === 403) throw e;
        preRule = undefined;
      }
      if (preRule !== undefined) {
        const conflict = catchAllConflict(preRule, worker);
        if (conflict) throw new CatchAllConflictError(zone.name, conflict);
      }

      // Email Routing: enable on the apex, or register the subdomain.
      // Refuses (before writing) when the name already has foreign MX.
      const routing = await ensureEmailRouting(client, zone, cd.domain);
      done.push(
        routing === "already"
          ? "Email Routing already enabled"
          : "Email Routing enabled (MX + SPF records created)",
      );

      // catch-all -> worker (re-checks the conflict on the same rule)
      const catchAll = await ensureCatchAllToWorker(
        client,
        zone,
        worker,
        preRule,
      );
      done.push(
        catchAll === "already"
          ? `catch-all already routes to worker ${worker}`
          : `catch-all now routes to worker ${worker}`,
      );
    } catch (e) {
      if (e instanceof ForeignMxError) {
        await flash(
          c,
          `Refusing to enable Email Routing for ${cd.domain}: it already ` +
            "has MX records pointing somewhere else, and adding " +
            "Cloudflare's next to them would break the existing mail " +
            "setup. Remove the old MX records first, then retry",
          "error",
        );
        return back();
      }
      if (!(e instanceof CatchAllConflictError)) throw e;
      await flash(
        c,
        `Refusing to change the catch-all rule of ${cd.domain}'s zone: it ` +
          "routes (or is configured to route) mail somewhere else, and the " +
          "catch-all is zone-wide — overwriting it could reroute or drop " +
          "the zone's other mail. Review it in the Cloudflare dashboard " +
          "(Email Routing > Routing rules) and retry",
        "error",
      );
      return back();
    }

    // 4. ownership TXT — plants the EXACT record the page displays and the
    // check-ownership branch expects (sl-verification=<token>)
    if (cd.ownership_verified) {
      done.push("ownership TXT skipped (already verified)");
    } else {
      const ownership = await ensureTxtRecord(
        client,
        zone.id,
        cd.domain,
        `sl-verification=${cd.ownership_txt_token}`,
        { comment: "SimpleLogin ownership verification (auto-configure)" },
      );
      done.push(
        ownership === "already"
          ? "ownership TXT already present"
          : "ownership TXT created",
      );
    }

    // 5. DMARC, create-if-absent (an existing _dmarc record — e.g. from
    // Email Sending onboarding — is never modified)
    const dmarc = await ensureTxtRecord(
      client,
      zone.id,
      `_dmarc.${cd.domain}`,
      DMARC_RECORD,
      { skipIfAnyAtName: true, comment: "SimpleLogin (auto-configure)" },
    );
    done.push(
      dmarc === "already"
        ? "DMARC record already present"
        : "DMARC record created",
    );
  } catch (e) {
    if (!(e instanceof CfApiError)) throw e;
    // Full detail (request path with zone id, raw CF error body) is for the
    // operator's logs only; users get the CF error messages without paths,
    // plus what already succeeded — completed steps are persisted at
    // Cloudflare and every step is safe to re-run.
    console.error(`cf-provision failed for ${cd.domain}: ${e.message}`);
    const reason =
      e.errors
        .map((x) => x.message)
        .filter(Boolean)
        .join("; ") || "request failed";
    const steps =
      done.length > 0
        ? ` Steps completed before the error: ${done.join("; ")}.`
        : "";
    // AUTHORIZATION failure under a delegated grant: distinct from any other
    // API error, because the user can fix it themselves (reconnect) and
    // because of a specific Cloudflare permission trap — GET/POST
    // /zones/{id}/email/routing[/enable|/dns] is gated on ZONE SETTINGS, not
    // on Email Routing Rules, so an OAuth client registered without the
    // zone-settings scopes authorizes fine and then 403s exactly at the
    // routing-enable step (docs/DOMAINS.md §3, "one-click provisioning").
    // No token, no zone name and no zone id appear here.
    if (
      credential.source === "oauth" &&
      (e.status === 401 || e.status === 403)
    ) {
      await flash(
        c,
        `Cloudflare refused the request for ${cd.domain} (${reason}): the ` +
          "connected Cloudflare account's authorization is missing a " +
          "permission or has expired. Please connect your Cloudflare " +
          "account again, then retry. If it keeps failing at the same step, " +
          "ask the operator to check the OAuth client's scopes — enabling " +
          "Email Routing is gated on Zone Settings (zone-settings.read and " +
          "zone-settings.write), NOT on Email Routing Rules, while the " +
          "catch-all rule needs email-routing-rule.read and " +
          "email-routing-rule.write; a client registered without either set " +
          "is refused at exactly that step." +
          steps +
          " Every step is safe to retry",
        "error",
      );
      return back();
    }
    await flash(
      c,
      `Cloudflare API error while configuring ${cd.domain}: ${reason}.` +
        steps +
        " Every step is safe to retry — click the button again once the " +
        "problem is resolved, or contact the operator",
      "error",
    );
    return back();
  }

  // 6. re-run the page's ownership/MX/SPF/DMARC checks in-process,
  // persisting the flags exactly like the manual check buttons — but ONLY
  // on success: the manual buttons' failure paths clear the flag, which
  // here would clobber flags on mere DNS lag. (DKIM is not re-checked: the
  // provisioning steps do not create the DKIM CNAMEs.)
  if (cd.ownership_verified) {
    done.push("ownership already verified");
  } else {
    const txt = await domainDnsClient.getTxtRecords(cd.domain);
    if (txt.includes(`sl-verification=${cd.ownership_txt_token}`)) {
      await db
        .prepare(
          "UPDATE custom_domain SET ownership_verified = 1, updated_at = ?1 WHERE id = ?2",
        )
        .bind(nowStr(), cd.id)
        .run();
      done.push("ownership verified");
    } else {
      done.push(
        "ownership not verified yet (DNS may need a moment — use the Verify button below)",
      );
    }
  }
  if (cd.verified) {
    done.push("MX already verified");
  } else {
    const found = await domainDnsClient.getMxDomains(cd.domain);
    if (isMxHostSetEquivalent(found, expectedMxRecords(envx))) {
      await db
        .prepare(
          "UPDATE custom_domain SET verified = 1, updated_at = ?1 WHERE id = ?2",
        )
        .bind(nowStr(), cd.id)
        .run();
      done.push("MX verified — the domain can start receiving emails");
    } else {
      done.push(
        "MX not verified yet (DNS may need a moment — use the Verify button below)",
      );
    }
  }
  if (cd.spf_verified) {
    done.push("SPF already verified");
  } else {
    // same parse as the check-spf branch (Email Routing creates the record)
    const txt = await domainDnsClient.getTxtRecords(cd.domain);
    const includes = new Set<string>();
    for (const r of txt) {
      if (!r.startsWith("v=spf1")) continue;
      for (const part of r.split(/\s+/)) {
        if (part.startsWith("include:")) includes.add(part.slice(8));
      }
    }
    if (includes.has(SPF_INCLUDE_DOMAIN)) {
      await db
        .prepare(
          "UPDATE custom_domain SET spf_verified = 1, updated_at = ?1 WHERE id = ?2",
        )
        .bind(nowStr(), cd.id)
        .run();
      done.push("SPF verified");
    } else {
      done.push("SPF not verified yet (DNS may need a moment)");
    }
  }
  if (cd.dmarc_verified) {
    done.push("DMARC already verified");
  } else {
    const txt = await domainDnsClient.getTxtRecords(`_dmarc.${cd.domain}`);
    if (txt.includes(DMARC_RECORD)) {
      await db
        .prepare(
          "UPDATE custom_domain SET dmarc_verified = 1, updated_at = ?1 WHERE id = ?2",
        )
        .bind(nowStr(), cd.id)
        .run();
      done.push("DMARC verified");
    } else {
      done.push("DMARC not verified yet (DNS may need a moment)");
    }
  }

  await flash(
    c,
    `Auto-configuration for ${cd.domain}: ${done.join("; ")}. Manual steps ` +
      "remaining: the operator must onboard the domain onto Email Sending " +
      "in the Cloudflare dashboard (Compute > Email Service > Email " +
      "Sending > Onboard Domain — needed for replies sent from this " +
      "domain's aliases) and verify each mailbox this domain forwards to " +
      "as an Email Routing destination address (Cloudflare only delivers " +
      "forwarded mail to verified destinations)",
    "success",
  );
  return back();
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
  // SL subdomains are born fully provisioned on a deployment public domain:
  // neither the provisioning button nor the Cloudflare-account panel has any
  // purpose there, so the whole card stays out of that page.
  const cfOauth = cd.is_sl_subdomain
    ? null
    : await cfOauthPageStatus(envx, c.get("webUser").id);
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
      spf_record: `v=spf1 include:${SPF_INCLUDE_DOMAIN} ~all`,
      dkim_records: DKIM_PREFIXES.map((prefix) => ({
        domain: prefix,
        recommended: `${prefix}.${envx.EMAIL_DOMAIN}`,
      })),
      dmarc_record: DMARC_RECORD,
      // SL subdomains live on a deployment public domain (already fully
      // provisioned + verified at creation) — never offer provisioning.
      cf_provision_available:
        !cd.is_sl_subdomain && cfProvisionAvailableWith(envx, cfOauth),
      // connect/disconnect panel (templates/dashboard-mailbox/
      // _cloudflare_connect.html); null/unconfigured renders nothing
      cf_oauth: cfOauth,
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
        const txt = await domainDnsClient.getTxtRecords(cd.domain);
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
        const found = await domainDnsClient.getMxDomains(cd.domain);
        if (isMxHostSetEquivalent(found, expectedMxRecords(envx))) {
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
        const txt = await domainDnsClient.getTxtRecords(cd.domain);
        const includes = new Set<string>();
        for (const r of txt) {
          if (!r.startsWith("v=spf1")) continue;
          for (const part of r.split(/\s+/)) {
            if (part.startsWith("include:")) includes.add(part.slice(8));
          }
        }
        // Cloudflare's include, not Flask's EMAIL_DOMAIN — see SPF_INCLUDE_DOMAIN.
        if (includes.has(SPF_INCLUDE_DOMAIN)) {
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
          `SPF: ${SPF_INCLUDE_DOMAIN} is not included in your SPF record.`,
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
          const cname = await domainDnsClient.getCnameRecord(host);
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
        // DELIBERATE DEVIATION from Flask (custom_domain_validation.py
        // L170-192: a NEW verification needs all three CNAMEs; only domains
        // that are already dkim_verified keep the flag when just
        // dkim._domainkey is still correct — the "legacy grace"): this worker
        // only DKIM-signs with the single EMAIL_DOMAIN key, and custom-domain
        // DKIM actually comes from Cloudflare Email Sending onboarding, so
        // dkim02/dkim03 are pure legacy here. The primary record alone
        // verifies (first time too), while missing dkim02/03 records are
        // still reported below like Flask's grace path does.
        const mainOk = !errors.some(
          (e) => e.custom_record === `dkim._domainkey.${cd.domain}`,
        );
        const newVerified = mainOk ? 1 : 0;
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
        const txt = await domainDnsClient.getTxtRecords(`_dmarc.${cd.domain}`);
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
      } else if (
        formName === "cf-provision" &&
        !cd.is_sl_subdomain &&
        (await cfProvisionAvailable(envx, c.get("webUser").id))
      ) {
        // Feature-gated: with neither a connected Cloudflare account nor
        // CF_API_TOKEN (or for SL-subdomain rows, which are born verified on
        // a deployment public domain) this form-name is unknown and falls
        // through to the GET render like the other unknown form-names.
        // Rate-limited: each click spends up to ~9 authenticated Cloudflare
        // API calls of the operator's account-wide quota (1200 req/5min) —
        // same webLimiter idiom as web_alias_export in alias-pages.ts.
        const limiter = await webLimiter(
          c,
          "web_cf_provision",
          "3/minute;20/hour",
        );
        if (limiter.exceeded) {
          return renderErrorPage(
            c,
            429,
            await buildCurrentUser(c, c.get("webUser")),
          );
        }
        await limiter.deduct();
        return handleCfProvision(c, cd);
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
        // set_custom_domain_mailboxes fetches with IN(): duplicate ids
        // collapse to fewer rows and the count check fails
        // (custom_domain_utils.py L178-190).
        if (new Set(mailboxIds).size !== mailboxIds.length) {
          return failWarn("Something went wrong, please retry");
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
            // re.compile() semantics (domain_detail.py L437-443), see
            // translatePythonRegex.
            let regexOk = true;
            try {
              const t = translatePythonRegex(regexRaw);
              new RegExp(t.source, t.flags);
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
              // regex_match() = re2/re fullmatch (regex_utils.py); Python
              // patterns are translated first (translatePythonRegex).
              const t = translatePythonRegex(rule.regex);
              if (new RegExp(`^(?:${t.source})$`, t.flags).test(local)) {
                matched = rule;
                break;
              }
            } catch {
              // untranslatable Python-only syntax: treated as non-matching
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
        const maxSubdomains = maxNbSubdomain(c.env as EnvX);
        const quota = Math.min(
          user.subdomain_quota,
          maxSubdomains - (subCount?.n ?? 0),
        );
        const failRedirect = async (msg: string) => {
          await flash(c, msg, "error");
          return redirectSelf(c);
        };
        if (quota <= 0) {
          return failRedirect(
            `You can't create more than ${maxSubdomains} subdomains`,
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
        const maxDirectories = maxNbDirectory(c.env as EnvX);
        const quota = Math.min(
          user.directory_quota,
          maxDirectories - (dirCount?.n ?? 0),
        );
        if (quota <= 0) {
          await flash(
            c,
            `You cannot have more than ${maxDirectories} directories`,
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
