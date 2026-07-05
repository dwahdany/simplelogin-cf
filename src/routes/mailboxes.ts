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
 * - Mailbox-domain MX/DNS checks (NoMxRecordFound, ForbiddenMxRecordFound) and
 *   the invalid_mailbox_domain suffix check are skipped: no DNS in Workers
 *   without DoH and those tables are absent from the D1 schema.
 * - Flask paths that 500 (non-numeric transfer_aliases_to / mailbox_ids,
 *   non-object JSON bodies) return clean 4xxs instead.
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

/** app/email_validation.py is_valid_email — RFC dot-atom, ASCII only. */
function isValidEmail(email: string): boolean {
  if (!email || email.length > 254) return false;
  // printable ASCII only (rejects spaces, control chars, unicode)
  if (!/^[\x21-\x7e]+$/.test(email)) return false;
  const at = email.lastIndexOf("@");
  if (at <= 0 || at === email.length - 1) return false;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (local.length > 64) return false;
  if (!LOCAL_RE.test(local)) return false;
  return isValidMailboxDomainSyntax(domain);
}

// ---- mailbox email validation (app/mailbox_utils.py + app/email_utils.py) --

// EmailCannotBeUsedReason values (email_utils.py L630)
const REASON_INVALID_DOMAIN = "This email domain is not valid";
const REASON_SL_DOMAIN = "This email is a SimpleLogin domain";
const REASON_CUSTOM_DOMAIN =
  "This email address belongs to a custom domain that has already been registered";
const REASON_NOT_ALLOWED = "This email address is not allowed";

/**
 * email_can_be_used_as_mailbox_with_reason(): returns the reason value string
 * or null. MX/invalid-mailbox-domain checks are skipped (see file header).
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
 * `request.get_json() or {}` equivalent: empty body -> {}; malformed JSON
 * throws SyntaxError (index.ts onError -> 400 "Bad Request"); non-object JSON
 * -> {} (Flask would 500 on `.get`; clean-4xx deviation).
 */
async function parseOptionalJson(
  c: Context<AppEnv>,
): Promise<Record<string, unknown>> {
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

// ---- POST /mailboxes (limiter outside auth, like the Flask decorators) ----

mailboxDomainRoutes.post(
  "/mailboxes",
  rateLimit("create_mailbox", "20/hour"),
  requireApiAuth,
  async (c) => {
    const user = c.get("user");
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

    const text = await c.req.text();
    const parsed: unknown = text.trim() ? JSON.parse(text) : null;
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
