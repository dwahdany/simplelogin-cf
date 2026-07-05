import type { Context } from "hono";
import { Hono } from "hono";
import { type AppEnv, requireApiAuth } from "../lib/auth";
import { sanitizeEmail, tokenUrlsafe } from "../lib/crypto";
import { nowStr, toEpoch } from "../lib/dates";
import { badRequest, forbidden } from "../lib/errors";
import { sendTransactionalEmail } from "../lib/mailer";
import {
  getCustomDomainById,
  getMailboxById,
  userIsPremium,
} from "../lib/models";
import { rateLimit } from "../lib/ratelimit";
import type {
  CustomDomainRow,
  DomainDeletedAliasRow,
  MailboxRow,
  UserRow,
} from "../lib/rows";

/**
 * Mailbox + custom-domain API routes, ported from app/api/views/mailbox.py,
 * app/api/views/custom_domain.py, app/mailbox_utils.py and
 * app/custom_domain_utils.py (spec 04).
 *
 * Deliberate deviations from Flask (documented in the port contract):
 * - No user audit log table in the D1 schema -> audit-log emission skipped.
 * - DNS resolution goes through DNS-over-HTTPS (cloudflare-dns.com JSON API)
 *   instead of dnspython + NAMESERVERS; tests install an in-memory client via
 *   `setDnsClient`, mirroring Flask's `set_global_dns_client`.
 * - The invalid_mailbox_domain / forbidden_mx_ip blocklists are enforced when
 *   those tables exist in the D1 database; a missing table is treated as an
 *   empty blocklist.
 * - Flask paths that 500 (non-numeric transfer_aliases_to / mailbox_ids,
 *   non-object JSON bodies, non-JSON Content-Type on POST /mailboxes, PATCH
 *   values Postgres rejects at commit) return clean 4xxs instead — and, like
 *   Flask's failed commit, persist nothing.
 */

export const mailboxDomainRoutes = new Hono<AppEnv>();

// Mailbox.FLAG_ADMIN_DISABLED = 1 << 0 (models.py L2983)
const FLAG_ADMIN_DISABLED = 1;
// app/custom_domain_utils.py _MAX_MAILBOXES_PER_DOMAIN
const MAX_MAILBOXES_PER_DOMAIN = 20;

// ---- email syntax validation (private port of email_validator ~=2.2 as ----
// ---- used by is_valid_email: syntax only, no smtputf8, no deliverability) --

const ATEXT = "A-Za-z0-9!#$%&'*+\\-/=?^_`{|}~";
const LOCAL_RE = new RegExp(`^[${ATEXT}]+(?:\\.[${ATEXT}]+)*$`);
const DOMAIN_LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

/** Domain part of an FQDN-looking mailbox domain. ASCII-only (no IDNA). */
function isValidMailboxDomainSyntax(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  if (!domain.includes(".")) return false;
  // email_validator: a globally deliverable TLD must end with a letter.
  if (!/[A-Za-z]$/.test(domain)) return false;
  for (const label of domain.split(".")) {
    if (!DOMAIN_LABEL_RE.test(label)) return false;
  }
  return true;
}

/**
 * IDNA/UTS-46 encode a (possibly internationalized) domain via the WHATWG URL
 * parser, which lowercases and punycode-encodes the hostname. Returns null
 * when the domain cannot be encoded.
 */
function idnaEncodeDomain(domain: string): string | null {
  if (!domain) return null;
  // ASCII characters other than letters/digits/hyphen/dot can never appear in
  // a hostname and could change how the URL below parses -> reject upfront.
  // Codepoints >= U+0080 are left to the URL parser's IDNA mapping.
  if (!/^[A-Za-z0-9.\-\u0080-\u{10FFFF}]+$/u.test(domain)) return null;
  try {
    return new URL(`http://${domain}/`).hostname;
  } catch {
    return null;
  }
}

/**
 * app/email_validation.py is_valid_email — email_validator ~=2.2 with
 * allow_smtputf8=False: only the LOCAL part is restricted to ASCII dot-atom;
 * an internationalized domain is IDNA-encoded before the syntax checks.
 */
function isValidEmail(email: string): boolean {
  if (!email) return false;
  const at = email.lastIndexOf("@");
  if (at <= 0 || at === email.length - 1) return false;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (local.length > 64) return false;
  // ASCII-only dot-atom (allow_smtputf8=False rejects unicode local parts)
  if (!LOCAL_RE.test(local)) return false;
  const asciiDomain = idnaEncodeDomain(domain);
  if (asciiDomain === null) return false;
  if (!isValidMailboxDomainSyntax(asciiDomain)) return false;
  // email_validator checks the total length on the ASCII form (max 254)
  if (local.length + 1 + asciiDomain.length > 254) return false;
  return true;
}

// ---- DNS (app/dns_utils.py, resolved over DoH in the Workers port) ----

export interface DnsClient {
  /** get_mx_domain_list(): MX hosts without the trailing dot; [] on failure. */
  getMxDomainList(hostname: string): Promise<string[]>;
  /** get_a_record(): first A-record IP for the hostname, or null. */
  getARecord(hostname: string): Promise<string | null>;
}

const DNS_TYPE_A = 1;
const DNS_TYPE_MX = 15;

interface DohAnswer {
  type: number;
  data: string;
}

/** cloudflare-dns.com JSON API query; any failure resolves to no answers. */
async function dohQuery(name: string, type: "MX" | "A"): Promise<DohAnswer[]> {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { accept: "application/dns-json" } },
    );
    if (!res.ok) return [];
    const body = (await res.json()) as { Answer?: DohAnswer[] };
    return body.Answer ?? [];
  } catch {
    return [];
  }
}

const dohDnsClient: DnsClient = {
  async getMxDomainList(hostname) {
    const mxDomains: string[] = [];
    for (const answer of await dohQuery(hostname, "MX")) {
      if (answer.type !== DNS_TYPE_MX) continue;
      // record data looks like "20 alt2.aspmx.l.google.com."
      const host = answer.data.split(" ")[1];
      if (host) mxDomains.push(host.endsWith(".") ? host.slice(0, -1) : host);
    }
    return mxDomains;
  },
  async getARecord(hostname) {
    for (const answer of await dohQuery(hostname, "A")) {
      if (answer.type === DNS_TYPE_A) return answer.data;
    }
    return null;
  },
};

let dnsClient: DnsClient = dohDnsClient;

/**
 * Test seam mirroring app/dns_utils.py `set_global_dns_client`: tests run in
 * the same isolate as SELF, so an in-memory client installed here is used by
 * the routes. `null` restores the DoH client.
 */
export function setDnsClient(client: DnsClient | null): void {
  dnsClient = client ?? dohDnsClient;
}

// ---- mailbox email validation (app/mailbox_utils.py + app/email_utils.py) --

// EmailCannotBeUsedReason values (email_utils.py L630)
const REASON_INVALID_DOMAIN = "This email domain is not valid";
const REASON_SL_DOMAIN = "This email is a SimpleLogin domain";
const REASON_CUSTOM_DOMAIN =
  "This email address belongs to a custom domain that has already been registered";
const REASON_INVALID_MAILBOX_DOMAIN =
  "We don't allow mailboxes using this domain";
const REASON_NO_MX_RECORD =
  "We couldn't get any MX records configured for this domain";
const REASON_FORBIDDEN_MX =
  "We don't allow mailbox domains that point to these MX records";
const REASON_NOT_ALLOWED = "This email address is not allowed";

/** True when `e` is D1 telling us the (optional) blocklist table is absent. */
function isMissingTableError(e: unknown): boolean {
  return String(e).includes("no such table");
}

/**
 * is_invalid_mailbox_domain (email_utils.py L793): the domain or ANY parent
 * suffix (excluding the bare TLD) is listed in invalid_mailbox_domain. A
 * missing table counts as an empty blocklist (see file header).
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
 */
async function emailCannotBeUsedReason(
  db: D1Database,
  email: string,
): Promise<string | null> {
  const domain = email.slice(email.lastIndexOf("@") + 1);
  if (!domain.includes(".")) return REASON_INVALID_DOMAIN;

  const slDomain = await db
    .prepare("SELECT 1 FROM public_domain WHERE domain = ?1")
    .bind(domain)
    .first();
  if (slDomain) return REASON_SL_DOMAIN;

  const customDomain = await db
    .prepare("SELECT 1 FROM custom_domain WHERE domain = ?1 AND verified = 1")
    .bind(domain)
    .first();
  if (customDomain) return REASON_CUSTOM_DOMAIN;

  if (await isInvalidMailboxDomain(db, domain)) {
    return REASON_INVALID_MAILBOX_DOMAIN;
  }

  // DNS goes through the IDNA/ASCII form, like dnspython does in Flask.
  // SKIP_MX_LOOKUP_ON_CHECK is hardcoded False (config.py L634, tests only).
  const asciiDomain = idnaEncodeDomain(domain) ?? domain;
  const mxDomains = await dnsClient.getMxDomainList(asciiDomain);
  if (mxDomains.length === 0) return REASON_NO_MX_RECORD;

  const mxIps = new Set<string>();
  for (const mxDomain of mxDomains) {
    if (await isInvalidMailboxDomain(db, mxDomain)) {
      return REASON_INVALID_MAILBOX_DOMAIN;
    }
    const aRecord = await dnsClient.getARecord(mxDomain);
    if (aRecord !== null) mxIps.add(aRecord);
  }
  if (mxIps.size > 0 && (await hasForbiddenMxIp(db, [...mxIps]))) {
    return REASON_FORBIDDEN_MX;
  }

  const disabledUser = await db
    .prepare("SELECT 1 FROM users WHERE email = ?1 AND disabled = 1")
    .bind(email)
    .first();
  if (disabledUser) return REASON_NOT_ALLOWED;

  const disabledMailboxOwner = await db
    .prepare(
      `SELECT 1 FROM mailbox m JOIN users u ON u.id = m.user_id
       WHERE m.email = ?1 AND u.disabled = 1 LIMIT 1`,
    )
    .bind(email)
    .first();
  if (disabledMailboxOwner) return REASON_NOT_ALLOWED;

  return null;
}

/**
 * check_email_for_mailbox(): first failure wins. Returns the MailboxError
 * message or null when the email can be used.
 */
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

// ---- serializers ----

/** mailbox.nb_alias() -> count_mailbox_aliases (mailbox_utils.py L535). */
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

/** mailbox_to_dict (app/api/views/mailbox.py L15). */
async function mailboxToDict(db: D1Database, user: UserRow, mb: MailboxRow) {
  return {
    id: mb.id,
    email: mb.email,
    verified: !!mb.verified,
    default: user.default_mailbox_id === mb.id,
    creation_timestamp: toEpoch(mb.created_at),
    nb_alias: await countMailboxAliases(db, mb.id),
  };
}

/** custom_domain_to_dict (app/api/views/custom_domain.py L12). */
async function customDomainToDict(
  db: D1Database,
  user: UserRow,
  cd: CustomDomainRow,
) {
  const nbAlias = await db
    .prepare(
      "SELECT COUNT(*) AS n FROM alias WHERE custom_domain_id = ?1 AND delete_on IS NULL",
    )
    .bind(cd.id)
    .first<{ n: number }>();

  // CustomDomain.mailboxes: domain_mailbox links, else [user.default_mailbox]
  const linked = await db
    .prepare(
      `SELECT m.id AS id, m.email AS email FROM domain_mailbox dm
       JOIN mailbox m ON m.id = dm.mailbox_id
       WHERE dm.domain_id = ?1 ORDER BY dm.id`,
    )
    .bind(cd.id)
    .all<{ id: number; email: string }>();
  let mailboxes = linked.results;
  if (mailboxes.length === 0 && user.default_mailbox_id !== null) {
    const def = await db
      .prepare("SELECT id, email FROM mailbox WHERE id = ?1")
      .bind(user.default_mailbox_id)
      .first<{ id: number; email: string }>();
    if (def) mailboxes = [def];
  }

  return {
    id: cd.id,
    domain_name: cd.domain,
    is_verified: !!cd.verified,
    nb_alias: nbAlias?.n ?? 0,
    creation_date: cd.created_at,
    creation_timestamp: toEpoch(cd.created_at),
    catch_all: !!cd.catch_all,
    name: cd.name,
    random_prefix_generation: !!cd.random_prefix_generation,
    mailboxes,
  };
}

// ---- small helpers ----

/**
 * Werkzeug `Request.is_json` (Flask 1.1.2): the body only counts as JSON when
 * the Content-Type mimetype is application/json or application/*+json —
 * otherwise `request.get_json()` returns None and the body is ignored.
 */
function requestIsJson(c: Context<AppEnv>): boolean {
  const contentType = c.req.header("content-type") ?? "";
  const mimetype = contentType.split(";")[0].trim().toLowerCase();
  return (
    mimetype === "application/json" ||
    (mimetype.startsWith("application/") && mimetype.endsWith("+json"))
  );
}

/**
 * `request.get_json() or {}` equivalent: non-JSON Content-Type or empty body
 * -> {}; malformed JSON throws SyntaxError (index.ts onError -> 400 "Bad
 * Request"); non-object JSON -> {} (Flask would 500 on `.get`; clean-4xx
 * deviation).
 */
async function parseOptionalJson(
  c: Context<AppEnv>,
): Promise<Record<string, unknown>> {
  if (!requestIsJson(c)) return {};
  const text = await c.req.text();
  if (!text.trim()) return {};
  const parsed = JSON.parse(text);
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    return parsed as Record<string, unknown>;
  }
  return {};
}

/** Python int(x) for JSON values; throws on anything int() would reject. */
function pyInt(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.trunc(value);
  }
  if (typeof value === "boolean") return value ? 1 : 0;
  if (typeof value === "string" && /^[+-]?[0-9]+$/.test(value.trim())) {
    return Number.parseInt(value.trim(), 10);
  }
  throw new TypeError(`invalid int: ${value}`);
}

/** generate_activation_code (API path): clear old codes, token_urlsafe(16). */
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

function isAdminDisabled(mb: MailboxRow): boolean {
  return (mb.flags & FLAG_ADMIN_DISABLED) === FLAG_ADMIN_DISABLED;
}

/** SQLite boolean columns want 0/1; other JSON values pass through as-is. */
function toDbValue(v: unknown): unknown {
  if (v === true) return 1;
  if (v === false) return 0;
  return v;
}

/**
 * Values SQLAlchemy 1.3's Boolean type accepts for a NOT NULL Postgres column
 * (`value in (True, False, 1, 0)`; None would hit the NOT NULL constraint).
 * Anything else makes Flask's commit raise -> 500, nothing persisted.
 */
function isPgBooleanValue(v: unknown): boolean {
  return v === true || v === false || v === 0 || v === 1;
}

// ---- POST /mailboxes (limiter outside auth, like the Flask decorators) ----

mailboxDomainRoutes.post(
  "/mailboxes",
  rateLimit("create_mailbox", "20/hour"),
  requireApiAuth,
  async (c) => {
    const user = c.get("user");
    if (!requestIsJson(c)) {
      // Flask: request.get_json() is None -> .get() AttributeError -> 500;
      // clean 4xx here (see file header).
      return badRequest(c, "Bad Request");
    }
    const body: unknown = await c.req.json();
    const email =
      body && typeof body === "object" && !Array.isArray(body)
        ? (body as Record<string, unknown>).email
        : undefined;
    if (!email || typeof email !== "string") {
      return badRequest(c, "Invalid email");
    }

    const mailboxEmail = sanitizeEmail(email);

    // mailbox_utils.create_mailbox(user, email)
    if (!(await userIsPremium(c.env.DB, user))) {
      return badRequest(c, "Only available for paid plans");
    }
    const err = await checkEmailForMailbox(c.env.DB, mailboxEmail, user);
    if (err) return badRequest(c, err);

    const mailbox = await c.env.DB.prepare(
      "INSERT INTO mailbox (user_id, email, verified) VALUES (?1, ?2, 0) RETURNING *",
    )
      .bind(user.id, mailboxEmail)
      .first<MailboxRow>();
    if (!mailbox) return badRequest(c, "Invalid email");

    const code = await generateActivationCode(c.env.DB, mailbox.id);
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

    return c.json(await mailboxToDict(c.env.DB, user, mailbox), 201);
  },
);

// ---- DELETE /mailboxes/<id> (limiter outside auth) ----

mailboxDomainRoutes.delete(
  "/mailboxes/:mailbox_id{[0-9]+}",
  rateLimit("delete_mailbox", "100/hour"),
  requireApiAuth,
  async (c) => {
    const user = c.get("user");
    const db = c.env.DB;
    const mailbox = await getMailboxById(db, Number(c.req.param("mailbox_id")));
    if (!mailbox || mailbox.user_id !== user.id) return forbidden(c);
    if (isAdminDisabled(mailbox)) {
      return badRequest(
        c,
        "This mailbox has been disabled and cannot be deleted. Please contact support.",
      );
    }

    const data = await parseOptionalJson(c);
    const raw = data.transfer_aliases_to;
    let transferMailboxId: number | null = null;
    if (raw) {
      let n: number;
      try {
        n = pyInt(raw);
      } catch {
        // Flask 500s on int(<non-numeric>); clean 4xx here.
        return badRequest(c, "Bad Request");
      }
      if (n >= 0) transferMailboxId = n;
    }

    // mailbox_utils.delete_mailbox(user, mailbox_id, transfer_mailbox_id)
    if (mailbox.id === user.default_mailbox_id) {
      return badRequest(c, "Cannot delete your default mailbox");
    }
    if (transferMailboxId && transferMailboxId > 0) {
      const transferMailbox = await getMailboxById(db, transferMailboxId);
      if (!transferMailbox || transferMailbox.user_id !== user.id) {
        return badRequest(
          c,
          "You must transfer the aliases to a mailbox you own",
        );
      }
      if (transferMailbox.id === mailbox.id) {
        return badRequest(
          c,
          "You can not transfer the aliases to the mailbox you want to delete",
        );
      }
      if (!transferMailbox.verified) {
        return badRequest(c, "Your new mailbox is not verified");
      }
    }

    // Deletion is asynchronous: only a job row is created here.
    await db
      .prepare(
        "INSERT INTO job (name, payload, run_at) VALUES ('delete-mailbox', ?1, ?2)",
      )
      .bind(
        JSON.stringify({
          mailbox_id: mailbox.id,
          transfer_mailbox_id:
            transferMailboxId && transferMailboxId > 0
              ? transferMailboxId
              : null,
          send_mail: true,
        }),
        nowStr(),
      )
      .run();

    return c.json({ deleted: true }, 200);
  },
);

// ---- PUT /mailboxes/<id> (auth outside limiter, like the Flask decorators) --

mailboxDomainRoutes.put(
  "/mailboxes/:mailbox_id{[0-9]+}",
  requireApiAuth,
  rateLimit("update_mailbox", "100/hour"),
  async (c) => {
    const user = c.get("user");
    const db = c.env.DB;
    const mailbox = await getMailboxById(db, Number(c.req.param("mailbox_id")));
    if (!mailbox || mailbox.user_id !== user.id) return forbidden(c);
    if (isAdminDisabled(mailbox)) {
      return badRequest(
        c,
        "This mailbox has been disabled. Please contact support.",
      );
    }

    const data = await parseOptionalJson(c);

    // "default": validated first; persisted only if the rest succeeds
    // (Flask commits everything at once and rolls back on MailboxError).
    let setDefault = false;
    if ("default" in data) {
      if (data.default) {
        if (!mailbox.verified) {
          return badRequest(
            c,
            "Unverified mailbox cannot be used as default mailbox",
          );
        }
        setDefault = true;
      }
    }

    if ("email" in data) {
      const rawEmail = data.email;
      // Flask 500s on sanitize_email(None); clean 4xx via "" -> "Invalid email"
      const newEmail = sanitizeEmail(
        typeof rawEmail === "string" ? rawEmail : "",
      );

      // mailbox_utils.request_mailbox_email_change
      if (newEmail === mailbox.email) return badRequest(c, "Same email");
      const err = await checkEmailForMailbox(db, newEmail, user);
      if (err) return badRequest(c, err);

      try {
        await db
          .prepare(
            "UPDATE mailbox SET new_email = ?1, updated_at = ?2 WHERE id = ?3",
          )
          .bind(newEmail, nowStr(), mailbox.id)
          .run();
      } catch (e) {
        // mailbox.new_email is globally unique -> IntegrityError in Flask
        if (String(e).includes("UNIQUE constraint failed")) {
          return badRequest(c, "Email already in use");
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
    }

    if ("cancel_email_change" in data && data.cancel_email_change) {
      // mailbox_utils.cancel_email_change
      await db
        .prepare(
          "UPDATE mailbox SET new_email = NULL, updated_at = ?1 WHERE id = ?2",
        )
        .bind(nowStr(), mailbox.id)
        .run();
      await db
        .prepare("DELETE FROM mailbox_activation WHERE mailbox_id = ?1")
        .bind(mailbox.id)
        .run();
    }

    if (setDefault) {
      await db
        .prepare(
          "UPDATE users SET default_mailbox_id = ?1, updated_at = ?2 WHERE id = ?3",
        )
        .bind(mailbox.id, nowStr(), user.id)
        .run();
    }

    return c.json({ updated: true }, 200);
  },
);

// ---- GET /mailboxes — verified only ----

mailboxDomainRoutes.get("/mailboxes", requireApiAuth, async (c) => {
  const user = c.get("user");
  const res = await c.env.DB.prepare(
    "SELECT * FROM mailbox WHERE user_id = ?1 AND verified = 1 ORDER BY id",
  )
    .bind(user.id)
    .all<MailboxRow>();
  const mailboxes = [];
  for (const mb of res.results) {
    mailboxes.push(await mailboxToDict(c.env.DB, user, mb));
  }
  return c.json({ mailboxes }, 200);
});

// ---- GET /v2/mailboxes — ALL mailboxes ----

mailboxDomainRoutes.get("/v2/mailboxes", requireApiAuth, async (c) => {
  const user = c.get("user");
  const res = await c.env.DB.prepare(
    "SELECT * FROM mailbox WHERE user_id = ?1 ORDER BY id",
  )
    .bind(user.id)
    .all<MailboxRow>();
  const mailboxes = [];
  for (const mb of res.results) {
    mailboxes.push(await mailboxToDict(c.env.DB, user, mb));
  }
  return c.json({ mailboxes }, 200);
});

// ---- GET /custom_domains ----

mailboxDomainRoutes.get("/custom_domains", requireApiAuth, async (c) => {
  const user = c.get("user");
  const res = await c.env.DB.prepare(
    "SELECT * FROM custom_domain WHERE user_id = ?1 AND is_sl_subdomain = 0 ORDER BY id",
  )
    .bind(user.id)
    .all<CustomDomainRow>();
  const customDomains = [];
  for (const cd of res.results) {
    customDomains.push(await customDomainToDict(c.env.DB, user, cd));
  }
  return c.json({ custom_domains: customDomains }, 200);
});

// ---- GET /custom_domains/<id>/trash ----

mailboxDomainRoutes.get(
  "/custom_domains/:custom_domain_id{[0-9]+}/trash",
  requireApiAuth,
  async (c) => {
    const user = c.get("user");
    const customDomain = await getCustomDomainById(
      c.env.DB,
      Number(c.req.param("custom_domain_id")),
    );
    if (!customDomain || customDomain.user_id !== user.id) return forbidden(c);

    const res = await c.env.DB.prepare(
      "SELECT * FROM domain_deleted_alias WHERE domain_id = ?1 ORDER BY id",
    )
      .bind(customDomain.id)
      .all<DomainDeletedAliasRow>();
    return c.json(
      {
        aliases: res.results.map((dda) => ({
          alias: dda.email,
          deletion_timestamp: toEpoch(dda.created_at),
        })),
      },
      200,
    );
  },
);

// ---- PATCH /custom_domains/<id> (auth outside limiter) ----

mailboxDomainRoutes.patch(
  "/custom_domains/:custom_domain_id{[0-9]+}",
  requireApiAuth,
  rateLimit("update_custom_domain", "100/hour"),
  async (c) => {
    const user = c.get("user");
    const db = c.env.DB;

    // request.get_json(): None unless the Content-Type is JSON (Flask 1.1.2)
    let parsed: unknown = null;
    if (requestIsJson(c)) {
      const text = await c.req.text();
      parsed = text.trim() ? JSON.parse(text) : null;
    }
    const isEmpty =
      !parsed ||
      (typeof parsed === "object" &&
        (Array.isArray(parsed)
          ? parsed.length === 0
          : Object.keys(parsed).length === 0));
    if (isEmpty) return badRequest(c, "request body cannot be empty");
    const data: Record<string, unknown> =
      parsed && typeof parsed === "object" && !Array.isArray(parsed)
        ? (parsed as Record<string, unknown>)
        : {};

    const domainId = Number(c.req.param("custom_domain_id"));
    const customDomain = await getCustomDomainById(db, domainId);
    if (!customDomain || customDomain.user_id !== user.id) return forbidden(c);

    const sets: string[] = [];
    const params: unknown[] = [];
    if ("catch_all" in data) {
      sets.push(`catch_all = ?${params.length + 1}`);
      params.push(toDbValue(data.catch_all));
    }
    if ("random_prefix_generation" in data) {
      sets.push(`random_prefix_generation = ?${params.length + 1}`);
      params.push(toDbValue(data.random_prefix_generation));
    }
    if ("name" in data) {
      sets.push(`name = ?${params.length + 1}`);
      params.push(toDbValue(data.name));
    }

    // mailbox_ids -> set_custom_domain_mailboxes (validated BEFORE any write,
    // like Flask where a failure prevents the commit of the other fields)
    let newMailboxIds: number[] | null = null;
    if ("mailbox_ids" in data) {
      const rawIds = data.mailbox_ids;
      if (!Array.isArray(rawIds)) {
        // Flask 500s (TypeError) on non-iterable; clean 4xx here.
        return badRequest(c, "Bad Request");
      }
      let mailboxIds: number[];
      try {
        mailboxIds = rawIds.map(pyInt);
      } catch {
        // Flask 500s (ValueError) on non-numeric ids; clean 4xx here.
        return badRequest(c, "Bad Request");
      }

      if (
        mailboxIds.length === 0 ||
        mailboxIds.length > MAX_MAILBOXES_PER_DOMAIN
      ) {
        return badRequest(c, "Forbidden");
      }
      const placeholders = mailboxIds.map((_, i) => `?${i + 2}`).join(", ");
      const found = await db
        .prepare(
          `SELECT * FROM mailbox WHERE user_id = ?1 AND verified = 1
           AND id IN (${placeholders}) ORDER BY id`,
        )
        .bind(user.id, ...mailboxIds)
        .all<MailboxRow>();
      if (found.results.length !== mailboxIds.length) {
        return badRequest(c, "Forbidden");
      }
      if (found.results.some(isAdminDisabled)) {
        return badRequest(c, "Forbidden");
      }
      newMailboxIds = found.results.map((m) => m.id);
    }

    // Values Postgres would reject when Flask commits (500 "Internal error",
    // NOTHING persisted): non-boolean catch_all / random_prefix_generation
    // (models.py L2611: Boolean NOT NULL) and a non-string or >128-char name
    // (models.py L2594: varchar(128)). Clean 4xx deviation — checked after
    // mailbox_ids like Flask, where those 400s fire before the commit.
    if ("catch_all" in data && !isPgBooleanValue(data.catch_all)) {
      return badRequest(c, "Bad Request");
    }
    if (
      "random_prefix_generation" in data &&
      !isPgBooleanValue(data.random_prefix_generation)
    ) {
      return badRequest(c, "Bad Request");
    }
    if ("name" in data) {
      const name = data.name;
      if (
        !(name === null || (typeof name === "string" && name.length <= 128))
      ) {
        return badRequest(c, "Bad Request");
      }
    }

    if (sets.length > 0) {
      params.push(nowStr(), customDomain.id);
      await db
        .prepare(
          `UPDATE custom_domain SET ${sets.join(", ")},
           updated_at = ?${params.length - 1} WHERE id = ?${params.length}`,
        )
        .bind(...params)
        .run();
    }

    if (newMailboxIds) {
      await db
        .prepare("DELETE FROM domain_mailbox WHERE domain_id = ?1")
        .bind(customDomain.id)
        .run();
      for (const mailboxId of newMailboxIds) {
        await db
          .prepare(
            "INSERT INTO domain_mailbox (domain_id, mailbox_id) VALUES (?1, ?2)",
          )
          .bind(customDomain.id, mailboxId)
          .run();
      }
    }

    // refresh, like the Flask route
    const refreshed = await getCustomDomainById(db, domainId);
    if (!refreshed) return forbidden(c);
    return c.json(
      { custom_domain: await customDomainToDict(db, user, refreshed) },
      200,
    );
  },
);
