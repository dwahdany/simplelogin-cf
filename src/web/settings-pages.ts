/**
 * Web dashboard: settings + security pages (specs/web/04-settings-security-pages.md).
 *
 * Routes (relative to the /dashboard mount, plus Flask parity gotchas):
 *   1  GET|POST /setting                       login, 5/min POST
 *   2  GET|POST /account_setting               login+sudo, 5/min POST
 *   3  GET|POST /resend_email_change           login+sudo, 5/hour all methods
 *   4  GET|POST /cancel_email_change           login+sudo
 *   5  POST     /unlink_proton_account         login+sudo
 *   6  GET|POST /api_key                       login+sudo, 100/hour all methods
 *   7  GET|POST /enter_sudo                    login, 3/min all methods
 *   8  GET|POST /mfa_setup                     login+sudo
 *   9  GET|POST /mfa_cancel                    login+sudo
 *   10 GET|POST /fido_setup                    login+sudo — WebAuthn BLOCKER, gated
 *   11 GET|POST /fido_manage                   login+sudo
 *   12 GET|POST /delete_account                login+sudo
 *   13 GET|POST /notification/<id>             login (no int converter!)
 *   14 GET|POST /notifications                 login
 *   15 GET|POST /unsubscribe/<int:alias_id>    login (RFC 8058 One-Click exempt)
 *   16 GET|POST /block_contact/<int:contact_id> login
 *   17 GET      /unsubscribe/encoded/<payload> login — SHA3 signer deferred
 * (/internal/exit-sudo-mode is owned by src/web/infra.ts.)
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha3_224 } from "@noble/hashes/sha3.js";
import type { Context, MiddlewareHandler } from "hono";
import { Hono } from "hono";
import { Secret, TOTP } from "otpauth";
import {
  canonicalizeEmail,
  checkPassword,
  randomString,
  tokenUrlsafe,
} from "../lib/crypto";
import { addHours, nowStr, toDate, toStr } from "../lib/dates";
import type { Env } from "../lib/env";
import { sendTransactionalEmail } from "../lib/mailer";
import {
  appleValid,
  coinbaseActive,
  defaultRandomAliasDomain,
  FLAG_CREATED_FROM_PARTNER,
  getSLDomains,
  isPremium,
  lifetimeOrActiveSubscription,
  manualActive,
  paddleActive,
  partnerActive,
  premiumInputsForUser,
} from "../lib/models";
import { clientIp, parseLimits } from "../lib/ratelimit";
import type {
  AliasRow,
  ApiKeyRow,
  ContactRow,
  NotificationRow,
  PublicDomainRow,
  UserRow,
} from "../lib/rows";
import { saveSession } from "../lib/session";
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

export const webSettingsPagesRoutes = new Hono<WebEnv>();

type Ctx = Context<WebEnv>;
type ExtraEnv = Env & Record<string, string | undefined>;

const MAX_API_KEYS = 30;

// ---------------------------------------------------------------------------
// small local helpers (this module may not touch src/lib/**)
// ---------------------------------------------------------------------------

/** Parse a POSTed form (urlencoded or multipart); {} when unparsable/GET. */
async function formBody(c: Ctx): Promise<Record<string, string | File>> {
  if (c.req.method === "GET") return {};
  try {
    return await c.req.parseBody();
  } catch {
    return {};
  }
}

function field(body: Record<string, unknown>, name: string): string | null {
  const v = body[name];
  return typeof v === "string" ? v : null;
}

/** flask-wtf CSRF check on the posted csrf_token field. */
async function csrfOk(c: Ctx, body: Record<string, unknown>): Promise<boolean> {
  const token = field(body, "csrf_token");
  return (await validateCsrfToken(c, token)) === null;
}

/** UPDATE users SET ... (+ updated_at) WHERE id = ?. */
async function updateUser(
  db: D1Database,
  id: number,
  sets: Record<string, unknown>,
): Promise<void> {
  const cols = Object.keys(sets);
  const sql = `UPDATE users SET ${cols
    .map((col, i) => `"${col}" = ?${i + 1}`)
    .join(
      ", ",
    )}, updated_at = ?${cols.length + 1} WHERE id = ?${cols.length + 2}`;
  await db
    .prepare(sql)
    .bind(...cols.map((k) => sets[k]), nowStr(), id)
    .run();
}

function freshUser(db: D1Database, id: number): Promise<UserRow | null> {
  return db
    .prepare("SELECT * FROM users WHERE id = ?1")
    .bind(id)
    .first<UserRow>();
}

/**
 * flask-limiter equivalent for WEB routes: same D1 fixed windows as
 * lib/ratelimit.ts but breaches render the HTML error/429.html page (the
 * lib middleware answers JSON and is typed for the API stack).
 * Runs after requireWebLogin so it keys on the session user like Flask.
 */
function webRateLimit(
  name: string,
  spec: string,
  methods?: string[],
): MiddlewareHandler<WebEnv> {
  const windows = parseLimits(spec);
  return async (c, next) => {
    if (c.env.DISABLE_RATE_LIMIT) return next();
    if (methods && !methods.includes(c.req.method)) return next();
    const session = c.get("webSession");
    const subject =
      session?.user_id != null
        ? `user:${session.user_id}`
        : `ip:${clientIp(c.req.raw.headers)}`;
    const now = Date.now() / 1000;
    for (const win of windows) {
      const windowStart = Math.floor(now / win.seconds);
      const row = await c.env.DB.prepare(
        `INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, 1)
         ON CONFLICT(key) DO UPDATE SET
           count = CASE WHEN window_start = ?2 THEN count + 1 ELSE 1 END,
           window_start = ?2
         RETURNING count`,
      )
        .bind(`rl:${name}:${subject}:${win.seconds}`, windowStart)
        .first<{ count: number }>();
      if ((row?.count ?? 1) > win.limit) return renderErrorPage(c, 429);
    }
    return next();
  };
}

/** app/utils.py sanitize_next_url (no ALLOWED_REDIRECT_DOMAINS configured). */
function sanitizeNextUrl(next: string | null | undefined): string | null {
  if (!next) return null;
  const replaced = next.replaceAll("\\", "/");
  // absolute URL (scheme or protocol-relative) => hostname => rejected
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(replaced)) return null;
  if (replaced.startsWith("//")) return null;
  if (replaced.startsWith("/")) return replaced;
  return null;
}

/** User.can_send_or_receive(). */
function canSendOrReceive(user: UserRow): boolean {
  return !user.disabled && user.delete_on === null;
}

/** User.two_factor_authentication_enabled(). */
function twoFactorEnabled(user: {
  enable_otp: number | boolean;
  fido_uuid: string | null;
}): boolean {
  return !!user.enable_otp || user.fido_uuid !== null;
}

const enc = new TextEncoder();

function b64urlNoPad(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** RecoveryCode._hash_code: base64url(HMAC-SHA3-224(secret, raw)) no padding. */
function hashRecoveryCode(secret: string, raw: string): string {
  return b64urlNoPad(hmac(sha3_224, enc.encode(secret), enc.encode(raw)));
}

function recoveryHmacSecret(env: ExtraEnv): string {
  return env.RECOVERY_CODE_HMAC_SECRET ?? env.FLASK_SECRET;
}

/** RecoveryCode.generate(user): wipe + insert 8 raw codes, return the raws. */
async function generateRecoveryCodes(
  c: Ctx,
  userId: number,
): Promise<string[]> {
  const db = c.env.DB;
  const secret = recoveryHmacSecret(c.env as ExtraEnv);
  await db
    .prepare("DELETE FROM recovery_code WHERE user_id = ?1")
    .bind(userId)
    .run();
  const raws: string[] = [];
  while (raws.length < 8) {
    const raw = randomString(8);
    const res = await db
      .prepare(
        "INSERT OR IGNORE INTO recovery_code (user_id, code) VALUES (?1, ?2)",
      )
      .bind(userId, hashRecoveryCode(secret, raw))
      .run();
    if (res.meta.changes > 0) raws.push(raw);
  }
  return raws;
}

/** pyotp.random_base32(): 32 chars A–Z2–7. */
function randomBase32(): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += alphabet[b % 32];
  return out;
}

/**
 * TOTP verify with valid_window=0 (mfa_setup gotcha — the shared
 * lib verifyTotp hardcodes the login-time ±2 window).
 */
function verifyTotpExact(secret: string, code: string): boolean {
  try {
    const totp = new TOTP({
      secret: Secret.fromBase32(secret.replace(/\s/g, "").toUpperCase()),
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    });
    return totp.validate({ token: code.normalize("NFKC"), window: 0 }) !== null;
  } catch {
    return false;
  }
}

/**
 * regenerate_user_alternative_id + keep the CURRENT session logged in
 * (all other sessions die because the loader compares alternative_id).
 */
async function regenerateAlternativeId(c: Ctx, userId: number): Promise<void> {
  const newId = crypto.randomUUID();
  await updateUser(c.env.DB, userId, { alternative_id: newId });
  const session = c.get("webSession");
  session.alternative_id = newId;
  await saveSession(c, session);
}

async function emitUserAuditLog(
  db: D1Database,
  user: UserRow,
  action: string,
  message: string,
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO user_audit_log (user_id, user_email, action, message) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(user.id, user.email, action, message)
    .run();
}

async function emitAliasAuditLog(
  db: D1Database,
  alias: { id: number; user_id: number; email: string },
  action: string,
  message: string,
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO alias_audit_log (user_id, alias_id, alias_email, action, message) VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(alias.user_id, alias.id, alias.email, action, message)
    .run();
}

// --- email validity helpers (private to src/routes/auth.ts, re-implemented) --

function isValidEmail(email: string): boolean {
  const parts = email.split("@");
  if (parts.length !== 2) return false;
  const [local, domain] = parts;
  if (!local || local.length > 64) return false;
  if (!/^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$/.test(local)) return false;
  if (local.startsWith(".") || local.endsWith(".") || local.includes(".."))
    return false;
  if (!domain || domain.length > 255 || !domain.includes(".")) return false;
  for (const label of domain.split(".")) {
    if (!label || label.length > 63) return false;
    if (!/^[A-Za-z0-9-]+$/.test(label)) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
  }
  return !/^\d+$/.test(domain.split(".").pop() as string);
}

/** email_can_be_used_as_mailbox (MX/disposable checks skipped like the API port). */
async function emailCanBeUsedAsMailbox(
  db: D1Database,
  email: string,
): Promise<boolean> {
  if (!isValidEmail(email)) return false;
  const domain = email.split("@")[1];
  if (
    await db
      .prepare("SELECT 1 FROM public_domain WHERE domain = ?1")
      .bind(domain)
      .first()
  )
    return false;
  if (
    await db
      .prepare("SELECT 1 FROM custom_domain WHERE domain = ?1 AND verified = 1")
      .bind(domain)
      .first()
  )
    return false;
  const owner = await db
    .prepare("SELECT disabled FROM users WHERE email = ?1")
    .bind(email)
    .first<{ disabled: number }>();
  if (owner?.disabled) return false;
  const disabledMailboxOwner = await db
    .prepare(
      `SELECT 1 FROM users u JOIN mailbox m ON u.id = m.user_id
       WHERE m.email = ?1 AND u.disabled = 1 LIMIT 1`,
    )
    .bind(email)
    .first();
  return !disabledMailboxOwner;
}

interface EmailChangeRow {
  id: number;
  user_id: number;
  new_email: string;
  code: string;
  expired: string;
}

function getEmailChange(
  db: D1Database,
  userId: number,
): Promise<EmailChangeRow | null> {
  return db
    .prepare("SELECT * FROM email_change WHERE user_id = ?1")
    .bind(userId)
    .first<EmailChangeRow>();
}

async function sendChangeEmailConfirmation(
  env: Env,
  user: UserRow,
  newEmail: string,
  code: string,
): Promise<void> {
  if (!canSendOrReceive(user)) return;
  const link = `${env.URL}/auth/change_email?code=${code}`;
  await sendTransactionalEmail(env, {
    to: newEmail,
    subject: "Confirm email update on SimpleLogin",
    text: `You have asked to change your email address on SimpleLogin. To confirm, please click on this link:\n\n${link}\n`,
  });
}

/** partner_user.partner_email for the Proton partner, or null. */
async function protonLinkedAccount(
  db: D1Database,
  userId: number,
): Promise<string | null> {
  const row = await db
    .prepare(
      `SELECT pu.partner_email AS partner_email FROM partner_user pu
       JOIN partner p ON pu.partner_id = p.id
       WHERE pu.user_id = ?1 AND p.name = 'Proton'`,
    )
    .bind(userId)
    .first<{ partner_email: string | null }>();
  return row?.partner_email ?? null;
}

// ---------------------------------------------------------------------------
// shared render plumbing
// ---------------------------------------------------------------------------

/** csrf_form context: `{{ csrf_form.csrf_token }}` hidden input. */
async function csrfFormCtx(c: Ctx): Promise<{ csrf_token: unknown }> {
  return { csrf_token: csrfTokenField(await generateCsrfToken(c)) };
}

/** current_user view-model + the raw user columns the settings templates read. */
async function settingsCurrentUser(
  c: Ctx,
  user: UserRow,
): Promise<CurrentUserCtx> {
  const base = await buildCurrentUser(c, user);
  const inputs = await premiumInputsForUser(c.env.DB, user);
  const now = new Date();
  const loa = lifetimeOrActiveSubscription(inputs, now);
  return {
    ...base,
    lifetime: !!user.lifetime,
    notification: !!user.notification,
    alias_generator: user.alias_generator,
    random_alias_suffix: user.random_alias_suffix,
    enable_data_breach_check: !!user.enable_data_breach_check,
    sender_format: user.sender_format,
    replace_reverse_alias: !!user.replace_reverse_alias,
    include_sender_in_reverse_alias: !!user.include_sender_in_reverse_alias,
    expand_alias_info: !!user.expand_alias_info,
    include_website_in_one_click_alias:
      !!user.include_website_in_one_click_alias,
    unsub_behaviour: user.unsub_behaviour,
    block_behaviour: user.block_behaviour === "return_5xx" ? 1 : 0,
    alias_delete_action: user.alias_delete_action,
    include_header_email_header: !!user.include_header_email_header,
    enable_otp: !!user.enable_otp,
    fido_uuid: user.fido_uuid,
    otp_secret: user.otp_secret,
    default_alias_custom_domain_id: user.default_alias_custom_domain_id,
    default_alias_public_domain_id: user.default_alias_public_domain_id,
    lifetime_or_active_subscription: () => loa,
  } as unknown as CurrentUserCtx;
}

/** GET /dashboard/setting render (also the POST fall-through target). */
async function renderSettingPage(c: Ctx, user: UserRow): Promise<Response> {
  const db = c.env.DB;
  const env = c.env as ExtraEnv;
  const now = new Date();
  const inputs = await premiumInputsForUser(db, user);
  const premium = isPremium(inputs, now);

  // available_domains_for_random_alias() — array of objects (nunjucks
  // cannot tuple-unpack arrays-of-pairs).
  const slDomains: PublicDomainRow[] = await getSLDomains(db, user, c.env, now);
  const customDomains = await db
    .prepare(
      "SELECT domain FROM custom_domain WHERE user_id = ?1 AND ownership_verified = 1 ORDER BY domain ASC",
    )
    .bind(user.id)
    .all<{ domain: string }>();
  const hasDefault =
    user.default_alias_custom_domain_id !== null ||
    user.default_alias_public_domain_id !== null;
  const defaultDomain = await defaultRandomAliasDomain(db, user, c.env, now);
  const randomAliasDomains = [
    ...slDomains.map((d) => ({ domain: d.domain, is_public: true })),
    ...customDomains.results.map((d) => ({
      domain: d.domain,
      is_public: false,
    })),
  ].map((d) => ({ ...d, selected: hasDefault && d.domain === defaultDomain }));

  // Current-plan card view-model (BLOCKER B4 — pure DB reads).
  const paddleSub =
    inputs.paddle && paddleActive(inputs.paddle, now)
      ? {
          plan_name: inputs.paddle.plan === "yearly" ? "Yearly" : "Monthly",
          cancelled: !!inputs.paddle.cancelled,
        }
      : null;
  const manualSub = inputs.manual
    ? {
        active: manualActive(inputs.manual, now),
        end_at: inputs.manual.end_at,
        end_at_date: inputs.manual.end_at.slice(0, 10),
        is_giveaway: !!inputs.manual.is_giveaway,
      }
    : null;
  const appleSub = inputs.apple
    ? {
        valid: appleValid(inputs.apple, now),
        expires_date: inputs.apple.expires_date,
        expires_date_date: inputs.apple.expires_date.slice(0, 10),
      }
    : null;
  const coinbaseSub = inputs.coinbase
    ? {
        active: coinbaseActive(inputs.coinbase, now),
        end_at_date: inputs.coinbase.end_at.slice(0, 10),
      }
    : null;
  let partnerSub: { lifetime: boolean } | null = null;
  let partnerName: string | null = null;
  if (inputs.partner && partnerActive(inputs.partner, now)) {
    partnerSub = { lifetime: !!inputs.partner.lifetime };
    const row = await db
      .prepare(
        `SELECT p.name AS name FROM partner_subscription ps
         JOIN partner_user pu ON ps.partner_user_id = pu.id
         JOIN partner p ON pu.partner_id = p.id
         WHERE ps.id = ?1`,
      )
      .bind(inputs.partner.id)
      .first<{ name: string }>();
    partnerName = row?.name ?? null;
  }

  const pendingEmail = (await getEmailChange(db, user.id))?.new_email ?? null;

  return webRender(
    c,
    "dashboard-settings/setting.html",
    {
      csrf_form: await csrfFormCtx(c),
      form: {
        csrf_token: csrfTokenField(await generateCsrfToken(c)),
        name: makeField({
          name: "name",
          label: "Name",
          value: user.name ?? "",
        }),
        profile_picture: makeField({
          name: "profile_picture",
          label: "Profile Picture",
          type: "file",
        }),
      },
      pending_email: pendingEmail,
      is_premium: premium,
      paddle_sub: paddleSub,
      manual_sub: manualSub,
      apple_sub: appleSub,
      coinbase_sub: coinbaseSub,
      partner_sub: partnerSub,
      partner_name: partnerName,
      random_alias_domains: randomAliasDomains,
      ALIAS_RAND_SUFFIX_LENGTH: Number(env.ALIAS_RANDOM_SUFFIX_LENGTH ?? "5"),
      connect_with_proton: env.CONNECT_WITH_PROTON !== undefined,
      can_unlink_proton_account: (user.flags & FLAG_CREATED_FROM_PARTNER) === 0,
    },
    { currentUser: await settingsCurrentUser(c, user) },
  );
}

/** user_settings.set_default_alias_domain — returns the error string or null. */
async function setDefaultAliasDomain(
  c: Ctx,
  user: UserRow,
  domain: string,
): Promise<string | null> {
  const db = c.env.DB;
  if (!domain) {
    await updateUser(db, user.id, {
      default_alias_public_domain_id: null,
      default_alias_custom_domain_id: null,
    });
    return null;
  }
  const slDomain = await db
    .prepare("SELECT * FROM public_domain WHERE domain = ?1")
    .bind(domain)
    .first<PublicDomainRow>();
  if (slDomain) {
    if (slDomain.hidden) return "Domain does not exist";
    const inputs = await premiumInputsForUser(db, user);
    if (slDomain.premium_only && !isPremium(inputs))
      return "You cannot use this domain";
    await updateUser(db, user.id, {
      default_alias_public_domain_id: slDomain.id,
      default_alias_custom_domain_id: null,
    });
    return null;
  }
  const customDomain = await db
    .prepare(
      "SELECT id, user_id, verified FROM custom_domain WHERE domain = ?1",
    )
    .bind(domain)
    .first<{ id: number; user_id: number; verified: number }>();
  if (
    !customDomain ||
    customDomain.user_id !== user.id ||
    !customDomain.verified
  )
    return "Domain does not exist or it hasn't been verified";
  await updateUser(db, user.id, {
    default_alias_custom_domain_id: customDomain.id,
    default_alias_public_domain_id: null,
  });
  return null;
}

// ---------------------------------------------------------------------------
// 1. GET|POST /setting
// ---------------------------------------------------------------------------

webSettingsPagesRoutes.use("/setting", requireWebLogin);
webSettingsPagesRoutes.use(
  "/setting",
  webRateLimit("web_setting", "5/minute", ["POST"]),
);
webSettingsPagesRoutes.get("/setting", (c) =>
  renderSettingPage(c, c.get("webUser")),
);

webSettingsPagesRoutes.post("/setting", async (c) => {
  const db = c.env.DB;
  const user = c.get("webUser");
  const body = await formBody(c);
  const settingUrl = urlFor("dashboard.setting");

  if (!(await csrfOk(c, body))) {
    await flash(c, "Invalid request", "warning");
    return c.redirect(settingUrl, 302);
  }

  const formName = field(body, "form-name");
  const checkbox = (name: string) => field(body, name) === "on";

  switch (formName) {
    case "update-profile": {
      // BLOCKER B1 (S3/R2): profile_picture uploads are skipped — only the
      // name is updated, matching the "treat like absent config" stance.
      const name = field(body, "name") ?? "";
      if (name !== (user.name ?? "")) {
        await updateUser(db, user.id, { name });
        await flash(c, "Your profile has been updated", "success");
        return c.redirect(settingUrl, 302);
      }
      // nothing changed => fall through to re-render, no flash (Flask parity)
      return renderSettingPage(c, (await freshUser(db, user.id)) ?? user);
    }
    case "notification-preference": {
      await updateUser(db, user.id, {
        notification: checkbox("notification") ? 1 : 0,
      });
      await flash(
        c,
        "Your notification preference has been updated",
        "success",
      );
      return c.redirect(settingUrl, 302);
    }
    case "change-alias-generator": {
      const raw = field(body, "alias-generator-scheme") ?? "";
      const scheme = Number(raw);
      // int() ValueError => 500, bug-compatible
      if (raw.trim() === "" || !Number.isInteger(scheme))
        throw new Error(`invalid literal for int(): ${raw}`);
      if (scheme === 1 || scheme === 2)
        await updateUser(db, user.id, { alias_generator: scheme });
      await flash(c, "Your preference has been updated", "success");
      return c.redirect(settingUrl, 302);
    }
    case "change-random-alias-default-domain": {
      const domain = field(body, "random-alias-default-domain") ?? "";
      const err = await setDefaultAliasDomain(c, user, domain);
      if (err) {
        await flash(c, err, "error");
        return c.redirect(settingUrl, 302);
      }
      await flash(c, "Your preference has been updated", "success");
      return c.redirect(settingUrl, 302);
    }
    case "random-alias-suffix": {
      const raw = field(body, "random-alias-suffix-generator") ?? "";
      const scheme = Number(raw);
      if (raw.trim() === "" || !Number.isInteger(scheme)) {
        await flash(c, "Invalid value", "error");
        return c.redirect(settingUrl, 302);
      }
      if (scheme === 0 || scheme === 1)
        await updateUser(db, user.id, { random_alias_suffix: scheme });
      await flash(c, "Your preference has been updated", "success");
      return c.redirect(settingUrl, 302);
    }
    case "change-sender-format": {
      const raw = field(body, "sender-format") ?? "";
      const value = Number(raw);
      if (raw.trim() === "" || !Number.isInteger(value))
        throw new Error(`invalid literal for int(): ${raw}`);
      if ([0, 2, 5, 6, 7].includes(value)) {
        await updateUser(db, user.id, {
          sender_format: value,
          sender_format_updated_at: nowStr(),
        });
        await flash(
          c,
          "Your sender format preference has been updated",
          "success",
        );
      }
      return c.redirect(settingUrl, 302);
    }
    case "replace-ra": {
      await updateUser(db, user.id, {
        replace_reverse_alias: checkbox("replace-ra") ? 1 : 0,
      });
      await flash(c, "Your preference has been updated", "success");
      return c.redirect(settingUrl, 302);
    }
    case "enable_data_breach_check": {
      const inputs = await premiumInputsForUser(db, user);
      if (!isPremium(inputs)) {
        await flash(
          c,
          "Only premium plan can enable data breach monitoring",
          "warning",
        );
        return c.redirect(settingUrl, 302);
      }
      const on = checkbox("enable_data_breach_check");
      await updateUser(db, user.id, { enable_data_breach_check: on ? 1 : 0 });
      if (on) await flash(c, "Data breach monitoring is enabled", "success");
      else await flash(c, "Data breach monitoring is disabled", "info");
      return c.redirect(settingUrl, 302);
    }
    case "sender-in-ra": {
      await updateUser(db, user.id, {
        include_sender_in_reverse_alias: checkbox("enable") ? 1 : 0,
      });
      await flash(c, "Your preference has been updated", "success");
      return c.redirect(settingUrl, 302);
    }
    case "expand-alias-info": {
      await updateUser(db, user.id, {
        expand_alias_info: checkbox("enable") ? 1 : 0,
      });
      await flash(c, "Your preference has been updated", "success");
      return c.redirect(settingUrl, 302);
    }
    case "ignore-loop-email": {
      // dead form in setting.html but reachable by hand-crafted POST
      await updateUser(db, user.id, {
        ignore_loop_email: checkbox("enable") ? 1 : 0,
      });
      await flash(c, "Your preference has been updated", "success");
      return c.redirect(settingUrl, 302);
    }
    case "one-click-unsubscribe": {
      const behaviours: Record<string, number> = {
        PreserveOriginal: 2,
        DisableAlias: 0,
        BlockContact: 1,
      };
      const value = behaviours[field(body, "unsubscribe-behaviour") ?? ""];
      if (value === undefined) {
        await flash(c, "There was an error. Please try again", "warning");
        return c.redirect(settingUrl, 302);
      }
      await updateUser(db, user.id, { unsub_behaviour: value });
      await flash(c, "Your preference has been updated", "success");
      return c.redirect(settingUrl, 302);
    }
    case "include_website_in_one_click_alias": {
      await updateUser(db, user.id, {
        include_website_in_one_click_alias: checkbox("enable") ? 1 : 0,
      });
      await flash(c, "Your preference has been updated", "success");
      return c.redirect(settingUrl, 302);
    }
    case "change-blocked-behaviour": {
      const raw = field(body, "blocked-behaviour");
      const value =
        raw === "0" ? "return_2xx" : raw === "1" ? "return_5xx" : null;
      if (value === null) {
        await flash(c, "There was an error. Please try again", "warning");
        return c.redirect(settingUrl, 302);
      }
      await updateUser(db, user.id, { block_behaviour: value });
      await flash(c, "Your preference has been updated", "success");
      // Flask bug parity: NO redirect — falls through to the GET render (200).
      return renderSettingPage(c, (await freshUser(db, user.id)) ?? user);
    }
    case "sender-header": {
      await updateUser(db, user.id, {
        include_header_email_header: checkbox("enable") ? 1 : 0,
      });
      await flash(c, "Your preference has been updated", "success");
      return c.redirect(settingUrl, 302);
    }
    case "alias-delete-action": {
      const raw = field(body, "alias-delete-action");
      if (raw !== "0" && raw !== "1") {
        await flash(c, "There was an error. Please try again", "warning");
        return c.redirect(settingUrl, 302);
      }
      await updateUser(db, user.id, { alias_delete_action: Number(raw) });
      await flash(c, "Your preference has been updated", "success");
      // Flask bug parity: NO redirect (200 render).
      return renderSettingPage(c, (await freshUser(db, user.id)) ?? user);
    }
    default:
      return renderSettingPage(c, user);
  }
});

// ---------------------------------------------------------------------------
// 2. GET|POST /account_setting
// ---------------------------------------------------------------------------

async function renderAccountSettingPage(
  c: Ctx,
  user: UserRow,
  emailValue: string | null = null,
  emailErrors: string[] = [],
): Promise<Response> {
  const env = c.env as ExtraEnv;
  const pendingEmail =
    (await getEmailChange(c.env.DB, user.id))?.new_email ?? null;
  const connectWithProton = env.CONNECT_WITH_PROTON !== undefined;
  return webRender(
    c,
    "dashboard-settings/account_setting.html",
    {
      csrf_form: await csrfFormCtx(c),
      change_email_form: {
        csrf_token: csrfTokenField(await generateCsrfToken(c)),
        email: makeField(
          {
            name: "email",
            label: "email",
            type: "text",
            value: emailValue ?? user.email,
          },
          emailErrors,
        ),
      },
      pending_email: pendingEmail,
      connect_with_proton: connectWithProton,
      can_unlink_proton_account: (user.flags & FLAG_CREATED_FROM_PARTNER) === 0,
      proton_linked_account: connectWithProton
        ? await protonLinkedAccount(c.env.DB, user.id)
        : null,
      // BLOCKER B2: WebAuthn registration is gated; the setup card is hidden
      // unless a key already exists (manage is plain DB and stays reachable).
      fido_enabled: env.FIDO_ENABLED !== undefined,
    },
    { currentUser: await settingsCurrentUser(c, user) },
  );
}

webSettingsPagesRoutes.use("/account_setting", requireWebLogin, requireWebSudo);
webSettingsPagesRoutes.use(
  "/account_setting",
  webRateLimit("web_account_setting", "5/minute", ["POST"]),
);
webSettingsPagesRoutes.get("/account_setting", (c) =>
  renderAccountSettingPage(c, c.get("webUser")),
);

webSettingsPagesRoutes.post("/account_setting", async (c) => {
  const db = c.env.DB;
  const user = c.get("webUser");
  const body = await formBody(c);

  if (!(await csrfOk(c, body))) {
    await flash(c, "Invalid request", "warning");
    // Flask redirects to dashboard.setting here — NOT account_setting.
    return c.redirect(urlFor("dashboard.setting"), 302);
  }

  const formName = field(body, "form-name");

  if (formName === "update-email") {
    const rawEmail = field(body, "email") ?? "";
    // ChangeEmailForm validation: DataRequired + Email
    const errors: string[] = [];
    if (!rawEmail.trim()) errors.push("This field is required.");
    else if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(rawEmail.trim()))
      errors.push("Invalid email address.");
    if (errors.length)
      return renderAccountSettingPage(c, user, rawEmail, errors);

    const newEmail = canonicalizeEmail(rawEmail);
    const pending = await getEmailChange(db, user.id);
    if (newEmail !== user.email && !pending) {
      const emailUsed =
        (await db
          .prepare("SELECT 1 FROM users WHERE email = ?1")
          .bind(newEmail)
          .first()) ||
        (await db
          .prepare("SELECT 1 FROM alias WHERE email = ?1")
          .bind(newEmail)
          .first());
      if (emailUsed) {
        await flash(c, `Email ${newEmail} already used`, "error");
        return renderAccountSettingPage(c, user, rawEmail);
      }
      if (!(await emailCanBeUsedAsMailbox(db, newEmail))) {
        await flash(
          c,
          "You cannot use this email address as your personal inbox.",
          "error",
        );
        return renderAccountSettingPage(c, user, rawEmail);
      }
      const other = await db
        .prepare("SELECT * FROM email_change WHERE new_email = ?1")
        .bind(newEmail)
        .first<EmailChangeRow>();
      if (other) {
        if (toDate(other.expired).getTime() < Date.now()) {
          await db
            .prepare("DELETE FROM email_change WHERE id = ?1")
            .bind(other.id)
            .run();
        } else {
          await flash(
            c,
            "You cannot use this email address as your personal inbox.",
            "error",
          );
          return renderAccountSettingPage(c, user, rawEmail);
        }
      }
      const code = randomString(60);
      await db
        .prepare(
          "INSERT INTO email_change (user_id, new_email, code, expired) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(user.id, newEmail, code, toStr(addHours(new Date(), 12)))
        .run();
      await sendChangeEmailConfirmation(c.env, user, newEmail, code);
      await flash(
        c,
        "A confirmation email is on the way, please check your inbox",
        "success",
      );
      return c.redirect(urlFor("dashboard.account_setting"), 302);
    }
    // same email / pending change => silent fall-through to re-render
    return renderAccountSettingPage(c, user, rawEmail);
  }

  if (formName === "change-password") {
    // flashed BEFORE / regardless of the email actually sending
    await flash(
      c,
      "You are going to receive an email containing instructions to change your password",
      "success",
    );
    const code = tokenUrlsafe(32);
    await db
      .prepare(
        "INSERT INTO reset_password_code (user_id, code, expired) VALUES (?1, ?2, ?3)",
      )
      .bind(user.id, code, toStr(addHours(new Date(), 1)))
      .run();
    if (canSendOrReceive(user)) {
      const link = `${c.env.URL}/auth/reset_password?code=${code}`;
      await sendTransactionalEmail(c.env, {
        to: user.email,
        subject: "Reset your password on SimpleLogin",
        text: `To reset or change your password, please click on this link:\n\n${link}\n`,
      });
    }
    return c.redirect(urlFor("dashboard.account_setting"), 302);
  }

  if (formName === "send-full-user-report") {
    const existing = await db
      .prepare(
        `SELECT 1 FROM job WHERE name = 'send-user-report'
         AND payload = ?1 AND taken = 0 AND state = 0 LIMIT 1`,
      )
      .bind(JSON.stringify({ user_id: user.id }))
      .first();
    if (existing) {
      await flash(
        c,
        "An export of your data is currently in progress",
        "error",
      );
    } else {
      await db
        .prepare("INSERT INTO job (name, payload, run_at) VALUES (?1, ?2, ?3)")
        .bind(
          "send-user-report",
          JSON.stringify({ user_id: user.id }),
          nowStr(),
        )
        .run();
      await flash(
        c,
        "You will receive your SimpleLogin data via email shortly",
        "success",
      );
    }
    // no redirect — falls through to re-render (200)
    return renderAccountSettingPage(c, user);
  }

  return renderAccountSettingPage(c, user);
});

// ---------------------------------------------------------------------------
// 3./4. resend_email_change / cancel_email_change (GET works, CSRF still checked)
// ---------------------------------------------------------------------------

webSettingsPagesRoutes.use(
  "/resend_email_change",
  requireWebLogin,
  requireWebSudo,
  webRateLimit("web_resend_email_change", "5/hour"),
);
webSettingsPagesRoutes.on(
  ["GET", "POST"],
  "/resend_email_change",
  async (c) => {
    const db = c.env.DB;
    const user = c.get("webUser");
    const body = await formBody(c);
    if (!(await csrfOk(c, body))) {
      // A GET always lands here (no token in the query string) — Flask parity.
      await flash(c, "Invalid request. Please try again", "warning");
      return c.redirect(urlFor("dashboard.setting"), 302);
    }
    const emailChange = await getEmailChange(db, user.id);
    if (emailChange) {
      await db
        .prepare(
          "UPDATE email_change SET expired = ?1, updated_at = ?2 WHERE id = ?3",
        )
        .bind(toStr(addHours(new Date(), 12)), nowStr(), emailChange.id)
        .run();
      await sendChangeEmailConfirmation(
        c.env,
        user,
        emailChange.new_email,
        emailChange.code,
      );
      await flash(
        c,
        "A confirmation email is on the way, please check your inbox",
        "success",
      );
    } else {
      await flash(
        c,
        "You have no pending email change. Redirect back to Setting page",
        "warning",
      );
    }
    return c.redirect(urlFor("dashboard.account_setting"), 302);
  },
);

webSettingsPagesRoutes.use(
  "/cancel_email_change",
  requireWebLogin,
  requireWebSudo,
);
webSettingsPagesRoutes.on(
  ["GET", "POST"],
  "/cancel_email_change",
  async (c) => {
    const db = c.env.DB;
    const user = c.get("webUser");
    const body = await formBody(c);
    if (!(await csrfOk(c, body))) {
      await flash(c, "Invalid request. Please try again", "warning");
      return c.redirect(urlFor("dashboard.setting"), 302);
    }
    const emailChange = await getEmailChange(db, user.id);
    if (emailChange) {
      await db
        .prepare("DELETE FROM email_change WHERE id = ?1")
        .bind(emailChange.id)
        .run();
      await flash(c, "Your email change is cancelled", "success");
    } else {
      await flash(
        c,
        "You have no pending email change. Redirect back to Setting page",
        "warning",
      );
    }
    return c.redirect(urlFor("dashboard.account_setting"), 302);
  },
);

// ---------------------------------------------------------------------------
// 5. POST /unlink_proton_account
// ---------------------------------------------------------------------------

webSettingsPagesRoutes.use(
  "/unlink_proton_account",
  requireWebLogin,
  requireWebSudo,
);
webSettingsPagesRoutes.post("/unlink_proton_account", async (c) => {
  const db = c.env.DB;
  const user = c.get("webUser");
  const body = await formBody(c);
  if (!(await csrfOk(c, body))) {
    await flash(c, "Invalid request", "warning");
    return c.redirect(urlFor("dashboard.setting"), 302);
  }
  if (user.flags & FLAG_CREATED_FROM_PARTNER) {
    await flash(c, "Account cannot be unlinked", "warning");
    return c.redirect(urlFor("dashboard.account_setting"), 302);
  }
  const partnerUser = await db
    .prepare(
      `SELECT pu.id AS id FROM partner_user pu
       JOIN partner p ON pu.partner_id = p.id
       WHERE pu.user_id = ?1 AND p.name = 'Proton'`,
    )
    .bind(user.id)
    .first<{ id: number }>();
  if (!partnerUser) {
    // Known Flask 500 (AttributeError on None) — kept bug-compatible.
    throw new Error("user is not linked to a Proton account");
  }
  await db
    .prepare("DELETE FROM partner_user WHERE id = ?1")
    .bind(partnerUser.id)
    .run();
  await emitUserAuditLog(
    db,
    user,
    "unlink_account",
    `User ${user.id} has unlinked their Proton account`,
  );
  await flash(c, "Your Proton account has been unlinked", "success");
  return c.redirect(urlFor("dashboard.account_setting"), 302);
});

// ---------------------------------------------------------------------------
// 6. GET|POST /api_key
// ---------------------------------------------------------------------------

async function renderApiKeyPage(c: Ctx, user: UserRow): Promise<Response> {
  const apiKeys = await c.env.DB.prepare(
    "SELECT * FROM api_key WHERE user_id = ?1 ORDER BY created_at DESC",
  )
    .bind(user.id)
    .all<ApiKeyRow>();
  return webRender(
    c,
    "dashboard-settings/api_key.html",
    {
      csrf_form: await csrfFormCtx(c),
      new_api_key_form: {
        csrf_token: csrfTokenField(await generateCsrfToken(c)),
        name: makeField({ name: "name", label: "Name" }),
      },
      api_keys: apiKeys.results,
    },
    { currentUser: await settingsCurrentUser(c, user) },
  );
}

webSettingsPagesRoutes.use("/api_key", requireWebLogin, requireWebSudo);
webSettingsPagesRoutes.use("/api_key", webRateLimit("web_api_key", "100/hour"));
webSettingsPagesRoutes.get("/api_key", (c) =>
  renderApiKeyPage(c, c.get("webUser")),
);

/** clean_up_unused_or_old_api_keys(user_id). */
async function cleanUpApiKeys(db: D1Database, userId: number): Promise<void> {
  const countRow = await db
    .prepare("SELECT COUNT(*) AS n FROM api_key WHERE user_id = ?1")
    .bind(userId)
    .first<{ n: number }>();
  let total = countRow?.n ?? 0;
  if (total <= MAX_API_KEYS) return;
  // oldest never-used first
  const unused = await db
    .prepare(
      "SELECT id FROM api_key WHERE user_id = ?1 AND last_used IS NULL ORDER BY created_at ASC",
    )
    .bind(userId)
    .all<{ id: number }>();
  for (const row of unused.results) {
    if (total <= MAX_API_KEYS) return;
    await db.prepare("DELETE FROM api_key WHERE id = ?1").bind(row.id).run();
    total--;
  }
  // then least-recently-used
  const used = await db
    .prepare(
      "SELECT id FROM api_key WHERE user_id = ?1 AND last_used IS NOT NULL ORDER BY last_used ASC",
    )
    .bind(userId)
    .all<{ id: number }>();
  for (const row of used.results) {
    if (total <= MAX_API_KEYS) return;
    await db.prepare("DELETE FROM api_key WHERE id = ?1").bind(row.id).run();
    total--;
  }
}

webSettingsPagesRoutes.post("/api_key", async (c) => {
  const db = c.env.DB;
  const user = c.get("webUser");
  const body = await formBody(c);
  if (!(await csrfOk(c, body))) {
    await flash(c, "Invalid request", "warning");
    return c.redirect(c.req.url, 302);
  }
  const formName = field(body, "form-name");

  if (formName === "delete") {
    const keyId = field(body, "api-key-id") ?? "";
    const apiKey = await db
      .prepare("SELECT * FROM api_key WHERE id = ?1")
      .bind(keyId)
      .first<ApiKeyRow>();
    if (!apiKey) {
      await flash(c, "Unknown error. Refresh the page", "warning");
      return c.redirect(urlFor("dashboard.api_key"), 302);
    }
    if (apiKey.user_id !== user.id) {
      await flash(c, "You cannot delete this api key", "warning");
      return c.redirect(urlFor("dashboard.api_key"), 302);
    }
    await db.prepare("DELETE FROM api_key WHERE id = ?1").bind(apiKey.id).run();
    // Python f-string prints the literal `None` for a nameless key.
    await flash(
      c,
      `API Key ${apiKey.name ?? "None"} has been deleted`,
      "success",
    );
    return c.redirect(urlFor("dashboard.api_key"), 302);
  }

  if (formName === "create") {
    const name = field(body, "name") ?? "";
    if (!name.trim()) {
      // gotcha: no flash, no error display — plain redirect
      return c.redirect(urlFor("dashboard.api_key"), 302);
    }
    await cleanUpApiKeys(db, user.id);
    const code = randomString(60);
    const apiKey = await db
      .prepare(
        "INSERT INTO api_key (user_id, name, code) VALUES (?1, ?2, ?3) RETURNING *",
      )
      .bind(user.id, name, code)
      .first<ApiKeyRow>();
    await flash(c, `New API Key ${name} has been created`, "success");
    // The only place the secret code is ever shown (200, no redirect).
    return webRender(
      c,
      "dashboard-settings/new_api_key.html",
      { api_key: apiKey },
      { currentUser: await settingsCurrentUser(c, user) },
    );
  }

  if (formName === "delete-all") {
    await db
      .prepare("DELETE FROM api_key WHERE user_id = ?1")
      .bind(user.id)
      .run();
    await flash(c, "All API Keys have been deleted", "success");
    return c.redirect(urlFor("dashboard.api_key"), 302);
  }

  return c.redirect(urlFor("dashboard.api_key"), 302);
});

// ---------------------------------------------------------------------------
// 7. GET|POST /enter_sudo — 3/minute INCLUDING GET
// ---------------------------------------------------------------------------

async function renderEnterSudo(
  c: Ctx,
  user: UserRow,
  passwordErrors: string[] = [],
): Promise<Response> {
  const env = c.env as ExtraEnv;
  const db = c.env.DB;
  let connectWithProton = false;
  if (env.CONNECT_WITH_PROTON !== undefined) {
    connectWithProton = !!(await db
      .prepare(
        `SELECT 1 FROM partner_user pu JOIN partner p ON pu.partner_id = p.id
         WHERE pu.user_id = ?1 AND p.name = 'Proton'`,
      )
      .bind(user.id)
      .first());
  }
  let connectWithOidc = false;
  if (env.OIDC_CLIENT_ID !== undefined) {
    connectWithOidc = !!(await db
      .prepare(
        "SELECT 1 FROM social_auth WHERE user_id = ?1 AND social = 'oidc'",
      )
      .bind(user.id)
      .first());
  }
  return webRender(
    c,
    "dashboard-settings/enter_sudo.html",
    {
      password_check_form: {
        csrf_token: csrfTokenField(await generateCsrfToken(c)),
        password: makeField(
          { name: "password", label: "Password", type: "password" },
          passwordErrors,
        ),
      },
      next: c.req.query("next") ?? null,
      connect_with_proton: connectWithProton,
      connect_with_oidc: connectWithOidc,
      connect_with_oidc_icon: env.CONNECT_WITH_OIDC_ICON ?? null,
    },
    { currentUser: await settingsCurrentUser(c, user) },
  );
}

webSettingsPagesRoutes.use("/enter_sudo", requireWebLogin);
webSettingsPagesRoutes.use(
  "/enter_sudo",
  webRateLimit("web_enter_sudo", "3/minute"),
);
webSettingsPagesRoutes.get("/enter_sudo", (c) =>
  renderEnterSudo(c, c.get("webUser")),
);
webSettingsPagesRoutes.post("/enter_sudo", async (c) => {
  const user = c.get("webUser");
  const body = await formBody(c);
  const password = field(body, "password") ?? "";

  if (!(await csrfOk(c, body))) {
    // validate_on_submit() false => silent re-render (200)
    return renderEnterSudo(c, user);
  }
  if (!password) {
    return renderEnterSudo(c, user, ["This field is required."]);
  }
  if (await checkPassword(user.password, password)) {
    const session = c.get("webSession");
    session.sudo_time = Math.floor(Date.now() / 1000);
    const preserved = session.extra?._preserved_flashes as
      | Array<{ category: string; message: string }>
      | undefined;
    if (preserved?.length) {
      session.flashes = [...(session.flashes ?? []), ...preserved];
      delete session.extra?._preserved_flashes;
    }
    await saveSession(c, session);
    const nextUrl = sanitizeNextUrl(c.req.query("next"));
    return c.redirect(nextUrl ?? urlFor("dashboard.index"), 302);
  }
  await flash(c, "Incorrect password", "warning");
  return renderEnterSudo(c, user);
});

// ---------------------------------------------------------------------------
// 8. GET|POST /mfa_setup
// ---------------------------------------------------------------------------

webSettingsPagesRoutes.use("/mfa_setup", requireWebLogin, requireWebSudo);
webSettingsPagesRoutes.on(["GET", "POST"], "/mfa_setup", async (c) => {
  const db = c.env.DB;
  let user = c.get("webUser");
  if (user.enable_otp) {
    await flash(c, "you have already enabled MFA", "warning");
    return c.redirect(urlFor("dashboard.index"), 302);
  }
  // GET side effect (runs before POST validation too, like Flask)
  if (!user.otp_secret) {
    const secret = randomBase32();
    await updateUser(db, user.id, { otp_secret: secret });
    user = { ...user, otp_secret: secret };
  }

  let tokenErrors: string[] = [];
  if (c.req.method === "POST") {
    const body = await formBody(c);
    const rawToken = field(body, "token") ?? "";
    if (!(await csrfOk(c, body))) {
      // validate_on_submit false — silent re-render
    } else if (!rawToken) {
      tokenErrors = ["This field is required."];
    } else {
      const token = rawToken.replaceAll(" ", "");
      if (
        verifyTotpExact(user.otp_secret as string, token) &&
        user.last_otp !== token
      ) {
        await updateUser(db, user.id, { enable_otp: 1, last_otp: token });
        await regenerateAlternativeId(c, user.id);
        await flash(c, "MFA has been activated", "success");
        const recoveryCodes = await generateRecoveryCodes(c, user.id);
        return webRender(
          c,
          "dashboard-settings/recovery_code.html",
          { recovery_codes: recoveryCodes },
          {
            currentUser: await settingsCurrentUser(
              c,
              (await freshUser(db, user.id)) ?? user,
            ),
          },
        );
      }
      await flash(c, "Incorrect token", "warning");
    }
  }

  const otpUri = `otpauth://totp/SimpleLogin:${encodeURIComponent(user.email)}?secret=${user.otp_secret}&issuer=SimpleLogin`;
  return webRender(
    c,
    "dashboard-settings/mfa_setup.html",
    {
      otp_token_form: {
        csrf_token: csrfTokenField(await generateCsrfToken(c)),
        token: makeField({ name: "token", label: "Token" }, tokenErrors),
      },
      otp_uri: otpUri,
    },
    { currentUser: await settingsCurrentUser(c, user) },
  );
});

// ---------------------------------------------------------------------------
// 9. GET|POST /mfa_cancel
// ---------------------------------------------------------------------------

webSettingsPagesRoutes.use("/mfa_cancel", requireWebLogin, requireWebSudo);
webSettingsPagesRoutes.on(["GET", "POST"], "/mfa_cancel", async (c) => {
  const db = c.env.DB;
  const user = c.get("webUser");
  if (!user.enable_otp) {
    await flash(c, "you don't have MFA enabled", "warning");
    return c.redirect(urlFor("dashboard.index"), 302);
  }
  if (c.req.method === "POST") {
    const body = await formBody(c);
    if (!(await csrfOk(c, body))) {
      await flash(c, "Invalid request", "warning");
      return c.redirect(c.req.url, 302);
    }
    await updateUser(db, user.id, { enable_otp: 0, otp_secret: null });
    await regenerateAlternativeId(c, user.id);
    if (!twoFactorEnabled({ enable_otp: 0, fido_uuid: user.fido_uuid })) {
      await db
        .prepare("DELETE FROM recovery_code WHERE user_id = ?1")
        .bind(user.id)
        .run();
    }
    await flash(c, "TOTP is now disabled", "warning");
    return c.redirect(urlFor("dashboard.index"), 302);
  }
  return webRender(
    c,
    "dashboard-settings/mfa_cancel.html",
    { csrf_form: await csrfFormCtx(c) },
    { currentUser: await settingsCurrentUser(c, user) },
  );
});

// ---------------------------------------------------------------------------
// 10. GET|POST /fido_setup — BLOCKER B2 (WebAuthn attestation verify)
// ---------------------------------------------------------------------------

webSettingsPagesRoutes.use("/fido_setup", requireWebLogin, requireWebSudo);
webSettingsPagesRoutes.on(["GET", "POST"], "/fido_setup", async (c) => {
  // WebAuthn registration needs attestation verification that is not
  // available in this deployment yet — page is config-gated per spec B2.
  await flash(c, "WebAuthn is not supported in this deployment", "warning");
  return c.redirect(urlFor("dashboard.index"), 302);
});

// ---------------------------------------------------------------------------
// 11. GET|POST /fido_manage (plain DB — reachable only with fido_uuid set)
// ---------------------------------------------------------------------------

interface FidoRow {
  id: number;
  created_at: string;
  credential_id: string;
  uuid: string;
  name: string;
  aaguid: string | null;
}

async function renderFidoManage(c: Ctx, user: UserRow): Promise<Response> {
  const keys = await c.env.DB.prepare("SELECT * FROM fido WHERE uuid = ?1")
    .bind(user.fido_uuid)
    .all<FidoRow>();
  return webRender(
    c,
    "dashboard-settings/fido_manage.html",
    {
      fido_manage_form: {
        csrf_token: csrfTokenField(await generateCsrfToken(c)),
        credential_id: makeField({
          name: "credential_id",
          label: "credential_id",
          type: "hidden",
        }),
      },
      keys: keys.results,
    },
    { currentUser: await settingsCurrentUser(c, user) },
  );
}

webSettingsPagesRoutes.use("/fido_manage", requireWebLogin, requireWebSudo);
webSettingsPagesRoutes.on(["GET", "POST"], "/fido_manage", async (c) => {
  const db = c.env.DB;
  const user = c.get("webUser");
  if (!user.fido_uuid) {
    await flash(c, "You haven't registered a security key", "warning");
    return c.redirect(urlFor("dashboard.index"), 302);
  }
  if (c.req.method === "POST") {
    const body = await formBody(c);
    const credentialId = field(body, "credential_id") ?? "";
    if (!(await csrfOk(c, body)) || !credentialId) {
      // validate_on_submit false — silent re-render
      return renderFidoManage(c, user);
    }
    const fido = await db
      .prepare("SELECT * FROM fido WHERE uuid = ?1 AND credential_id = ?2")
      .bind(user.fido_uuid, credentialId)
      .first<FidoRow>();
    if (!fido) {
      await flash(c, "Unknown error, redirect back to manage page", "warning");
      return c.redirect(urlFor("dashboard.fido_manage"), 302);
    }
    await db.prepare("DELETE FROM fido WHERE id = ?1").bind(fido.id).run();
    await regenerateAlternativeId(c, user.id);
    await flash(c, `Key ${fido.name} successfully unlinked`, "success");
    const remaining = await db
      .prepare("SELECT COUNT(*) AS n FROM fido WHERE uuid = ?1")
      .bind(user.fido_uuid)
      .first<{ n: number }>();
    if ((remaining?.n ?? 0) === 0) {
      await updateUser(db, user.id, { fido_uuid: null });
      if (!twoFactorEnabled({ enable_otp: user.enable_otp, fido_uuid: null })) {
        await db
          .prepare("DELETE FROM recovery_code WHERE user_id = ?1")
          .bind(user.id)
          .run();
      }
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    return c.redirect(urlFor("dashboard.fido_manage"), 302);
  }
  return renderFidoManage(c, user);
});

// ---------------------------------------------------------------------------
// 12. GET|POST /delete_account
// ---------------------------------------------------------------------------

async function renderDeleteAccount(c: Ctx, user: UserRow): Promise<Response> {
  return webRender(
    c,
    "dashboard-settings/delete_account.html",
    {
      delete_form: {
        csrf_token: csrfTokenField(await generateCsrfToken(c)),
      },
    },
    { currentUser: await settingsCurrentUser(c, user) },
  );
}

webSettingsPagesRoutes.use("/delete_account", requireWebLogin, requireWebSudo);
webSettingsPagesRoutes.get("/delete_account", (c) =>
  renderDeleteAccount(c, c.get("webUser")),
);
webSettingsPagesRoutes.post("/delete_account", async (c) => {
  const db = c.env.DB;
  const user = c.get("webUser");
  const body = await formBody(c);
  if (field(body, "form-name") !== "delete-account") {
    return renderDeleteAccount(c, user);
  }
  if (!(await csrfOk(c, body))) {
    await flash(c, "Invalid request", "warning");
    // Flask re-renders (200) here, not a redirect.
    return renderDeleteAccount(c, user);
  }
  const inputs = await premiumInputsForUser(db, user);
  if (
    inputs.paddle &&
    paddleActive(inputs.paddle, new Date()) &&
    !inputs.paddle.cancelled
  ) {
    await flash(c, "Please cancel your current subscription first", "warning");
    return c.redirect(urlFor("dashboard.setting"), 302);
  }
  await emitUserAuditLog(
    db,
    user,
    "user_marked_for_deletion",
    `User ${user.id} (${user.email}) marked for deletion via webapp`,
  );
  await db
    .prepare("INSERT INTO job (name, payload, run_at) VALUES (?1, ?2, ?3)")
    .bind("delete-account", JSON.stringify({ user_id: user.id }), nowStr())
    .run();
  await flash(
    c,
    "Your account deletion has been scheduled. You'll receive an email when the deletion is finished",
    "info",
  );
  return c.redirect(urlFor("dashboard.setting"), 302);
});

// ---------------------------------------------------------------------------
// 13. GET|POST /notification/<notification_id> (no int converter)
// ---------------------------------------------------------------------------

webSettingsPagesRoutes.use("/notification/:notification_id", requireWebLogin);
webSettingsPagesRoutes.on(
  ["GET", "POST"],
  "/notification/:notification_id",
  async (c) => {
    const db = c.env.DB;
    const user = c.get("webUser");
    const id = c.req.param("notification_id");
    // Flask 500s on non-numeric ids (Postgres cast error); D1 just finds no
    // row => "Incorrect link" flash (accepted divergence, spec §13).
    const notification = await db
      .prepare("SELECT * FROM notification WHERE id = ?1")
      .bind(id)
      .first<NotificationRow>();
    if (!notification) {
      await flash(
        c,
        "Incorrect link. Redirect you to the home page",
        "warning",
      );
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    if (notification.user_id !== user.id) {
      await flash(
        c,
        "You don't have access to this page. Redirect you to the home page",
        "warning",
      );
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    if (!notification.read) {
      await db
        .prepare(
          "UPDATE notification SET read = 1, updated_at = ?1 WHERE id = ?2",
        )
        .bind(nowStr(), notification.id)
        .run();
    }
    if (c.req.method === "POST") {
      // Flask parity: NO CSRF check on this POST.
      const title = notification.title || notification.message.slice(0, 20);
      await db
        .prepare("DELETE FROM notification WHERE id = ?1")
        .bind(notification.id)
        .run();
      await flash(c, `${title} has been deleted`, "success");
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    return webRender(
      c,
      "dashboard-settings/notification.html",
      { notification },
      { currentUser: await settingsCurrentUser(c, user) },
    );
  },
);

// ---------------------------------------------------------------------------
// 14. GET|POST /notifications
// ---------------------------------------------------------------------------

webSettingsPagesRoutes.use("/notifications", requireWebLogin);
webSettingsPagesRoutes.on(["GET", "POST"], "/notifications", async (c) => {
  const db = c.env.DB;
  const user = c.get("webUser");
  const PAGE_LIMIT = 20;
  let page = Number.parseInt(c.req.query("page") ?? "", 10);
  if (Number.isNaN(page)) page = 0;
  // Flask 500s on negative OFFSET (Postgres); SQLite treats it as 0.
  const rows = await db
    .prepare(
      `SELECT * FROM notification WHERE user_id = ?1
       ORDER BY read ASC, created_at DESC LIMIT ?2 OFFSET ?3`,
    )
    .bind(user.id, PAGE_LIMIT + 1, page * PAGE_LIMIT)
    .all<NotificationRow>();
  const notifications = rows.results;
  const lastPage = notifications.length <= PAGE_LIMIT;
  // gotcha kept: the 21st row is NOT trimmed before rendering
  return webRender(
    c,
    "dashboard-settings/notifications.html",
    { notifications, page, last_page: lastPage },
    { currentUser: await settingsCurrentUser(c, user) },
  );
});

// ---------------------------------------------------------------------------
// 17. GET /unsubscribe/encoded/<encoded_request> — must precede route 15
// ---------------------------------------------------------------------------

webSettingsPagesRoutes.use(
  "/unsubscribe/encoded/:encoded_request",
  requireWebLogin,
);
webSettingsPagesRoutes.get(
  "/unsubscribe/encoded/:encoded_request",
  async (c) => {
    // BLOCKER B7: the payload signature is itsdangerous+SHA3-224 — deferred.
    // Flashing "Invalid unsubscribe request" matches the current Flask
    // behavior for web-generated links (encoder URL bug, spec §17 gotcha).
    await flash(c, "Invalid unsubscribe request", "error");
    return c.redirect(urlFor("dashboard.index"), 302);
  },
);

// ---------------------------------------------------------------------------
// 15. GET|POST /unsubscribe/<int:alias_id>
// ---------------------------------------------------------------------------

webSettingsPagesRoutes.use("/unsubscribe/:alias_id{[0-9]+}", requireWebLogin);
webSettingsPagesRoutes.on(
  ["GET", "POST"],
  "/unsubscribe/:alias_id{[0-9]+}",
  async (c) => {
    const db = c.env.DB;
    const user = c.get("webUser");
    const alias = await db
      .prepare("SELECT * FROM alias WHERE id = ?1")
      .bind(Number(c.req.param("alias_id")))
      .first<AliasRow>();
    if (!alias) {
      await flash(
        c,
        "Incorrect link. Redirect you to the home page",
        "warning",
      );
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    if (alias.user_id !== user.id) {
      await flash(
        c,
        "You don't have access to this page. Redirect you to the home page",
        "warning",
      );
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    if (c.req.method === "POST") {
      const oneClick = c.req.header("List-Unsubscribe-Post") === "One-Click";
      if (!oneClick) {
        const body = await formBody(c);
        if (!(await csrfOk(c, body))) {
          await flash(c, "Invalid request", "warning");
          return c.redirect(c.req.url, 302);
        }
      }
      await db
        .prepare("UPDATE alias SET enabled = 0, updated_at = ?1 WHERE id = ?2")
        .bind(nowStr(), alias.id)
        .run();
      await emitAliasAuditLog(
        db,
        alias,
        "change_status",
        "Set alias status to False. Set enabled=False from unsubscribe request",
      );
      await flash(c, `Alias ${alias.email} has been blocked`, "success");
      return c.redirect(
        urlFor("dashboard.index", { highlight_alias_id: alias.id }),
        302,
      );
    }
    return webRender(
      c,
      "dashboard-settings/unsubscribe.html",
      { alias: alias.email, csrf_form: await csrfFormCtx(c) },
      { currentUser: await settingsCurrentUser(c, user) },
    );
  },
);

// ---------------------------------------------------------------------------
// 16. GET|POST /block_contact/<int:contact_id>
// ---------------------------------------------------------------------------

webSettingsPagesRoutes.use(
  "/block_contact/:contact_id{[0-9]+}",
  requireWebLogin,
);
webSettingsPagesRoutes.on(
  ["GET", "POST"],
  "/block_contact/:contact_id{[0-9]+}",
  async (c) => {
    const db = c.env.DB;
    const user = c.get("webUser");
    const contact = await db
      .prepare("SELECT * FROM contact WHERE id = ?1")
      .bind(Number(c.req.param("contact_id")))
      .first<ContactRow>();
    if (!contact) {
      await flash(
        c,
        "Incorrect link. Redirect you to the home page",
        "warning",
      );
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    if (contact.user_id !== user.id) {
      await flash(
        c,
        "You don't have access to this page. Redirect you to the home page",
        "warning",
      );
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    const alias = await db
      .prepare("SELECT * FROM alias WHERE id = ?1")
      .bind(contact.alias_id)
      .first<AliasRow>();
    if (c.req.method === "POST") {
      const body = await formBody(c);
      if (!(await csrfOk(c, body))) {
        await flash(c, "Invalid request", "warning");
        return c.redirect(c.req.url, 302);
      }
      if (!contact.block_forward) {
        await db
          .prepare(
            "UPDATE contact SET block_forward = 1, updated_at = ?1 WHERE id = ?2",
          )
          .bind(nowStr(), contact.id)
          .run();
        if (alias) {
          await emitAliasAuditLog(
            db,
            alias,
            "update_contact",
            `Set contact state ${contact.id} ${contact.reply_email} -> ${contact.website_email} to blocked True`,
          );
        }
        await flash(
          c,
          `Emails sent from ${contact.website_email} are now blocked`,
          "success",
        );
      }
      return c.redirect(
        urlFor("dashboard.alias_contact_manager", {
          alias_id: contact.alias_id,
          highlight_contact_id: contact.id,
        }),
        302,
      );
    }
    return webRender(
      c,
      "dashboard-settings/block_contact.html",
      {
        contact: {
          website_email: contact.website_email,
          alias: { email: alias?.email ?? "" },
        },
        csrf_form: await csrfFormCtx(c),
      },
      { currentUser: await settingsCurrentUser(c, user) },
    );
  },
);
