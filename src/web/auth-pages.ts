/**
 * Server-rendered /auth/* pages — port of app/auth/views/* per
 * specs/web/01-auth-pages.md. Mounted at /auth in src/index.ts, so every
 * route below is relative to that prefix.
 *
 * Deliberate deviations (documented in the task report):
 * - abuser_lookup ban check on register is skipped (no table / MAC_KEY, same
 *   stance as the API port), DailyMetric counters are skipped (no table).
 * - No MX lookup in email_can_be_used_as_mailbox (as if SKIP_MX_LOOKUP_ON_CHECK).
 * - Recovery codes are HMAC-SHA256 (WebCrypto has no SHA3-224); secret =
 *   RECOVERY_CODE_HMAC_SECRET or FLASK_SECRET. See hashRecoveryCode.
 * - WebAuthn assertion verification on /auth/fido is stubbed: the page and
 *   guards work, every submitted assertion fails with the Flask warning
 *   string ("Key verification failed.") — TOTP/recovery escape hatches work.
 * - GitHub OAuth gets a config gate like the other providers (Flask has
 *   none and builds a redirect with client_id=None).
 * - Passwords / MFA tokens are never echoed back into re-rendered forms
 *   (Flask only clears them on the wrong-credentials branches).
 * - /auth/logout replaces the session cookie with a fresh anonymous session
 *   (carrying the "You are logged out" flash) instead of bare-deleting it.
 */

import type { Context } from "hono";
import { Hono } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import {
  canonicalizeEmail,
  checkPassword,
  hashPassword,
  randomString,
  randomWords,
  sanitizeEmail,
  tokenUrlsafe,
  verifyTotp,
} from "../lib/crypto";
import {
  addDays,
  addHours,
  addMinutes,
  nowStr,
  toDate,
  toStr,
} from "../lib/dates";
import type { Env } from "../lib/env";
import { sendTransactionalEmail } from "../lib/mailer";
import { availableSlEmail } from "../lib/models";
import type { BaseRow, UserRow } from "../lib/rows";
import { getSession, rotateSession, saveSession } from "../lib/session";
import {
  csrfTokenField,
  type FormField,
  generateCsrfToken,
  makeField,
  validateCsrfToken,
} from "../lib/web/forms";
import { type WebLimiter, webLimiter } from "../lib/web/limiter";
import {
  type FlashCategory,
  flash,
  renderErrorPage,
  webRender,
} from "../lib/web/render";
import { urlFor } from "../lib/web/urls";
import { loadWebUser, type WebEnv } from "../lib/web/webauth";

export const webAuthPagesRoutes = new Hono<WebEnv>();

type Ctx = Context<WebEnv>;
/** Env plus the config keys the auth pages read (all optional strings). */
type XEnv = Env & Record<string, string | undefined>;

const REQUIRED_MSG = "This field is required.";
const LENGTH_8_100_MSG = "Field must be between 8 and 100 characters long.";

// ---------------------------------------------------------------------------
// next-url sanitizer (app/utils.py NextUrlSanitizer)
// ---------------------------------------------------------------------------

function allowedRedirectDomains(env: XEnv): string[] {
  if (env.ALLOWED_REDIRECT_DOMAINS) {
    return env.ALLOWED_REDIRECT_DOMAINS.split(",")
      .map((d) => d.trim())
      .filter(Boolean);
  }
  try {
    return [new URL(env.URL).hostname];
  } catch {
    return [];
  }
}

/** Port of sanitize_next_url: backslashes → slashes, allowlisted hosts, local paths only. */
export function sanitizeNextUrl(
  url: string | null | undefined,
  allowedDomains: string[],
): string | null {
  if (!url) return null;
  const replaced = url.replaceAll("\\", "/");
  // urlparse netloc: only right after an optional scheme at the very start
  const netlocMatch = replaced.match(
    /^(?:[a-zA-Z][a-zA-Z0-9+.-]*:)?\/\/([^/?#]*)/,
  );
  if (netlocMatch) {
    const host =
      netlocMatch[1].split("@").pop()?.split(":")[0].toLowerCase() ?? "";
    return host && allowedDomains.includes(host) ? replaced : null;
  }
  const schemeMatch = replaced.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:(.*)$/);
  const rest = schemeMatch ? schemeMatch[1] : replaced;
  const noFrag = rest.split("#")[0];
  const qIdx = noFrag.indexOf("?");
  const path = qIdx >= 0 ? noFrag.slice(0, qIdx) : noFrag;
  const query = qIdx >= 0 ? noFrag.slice(qIdx + 1) : "";
  if (path.startsWith("/") && !path.startsWith("//")) {
    return query ? `${path}?${query}` : path;
  }
  return null;
}

function nextUrlOf(c: Ctx): string | null {
  return sanitizeNextUrl(
    c.req.query("next"),
    allowedRedirectDomains(c.env as XEnv),
  );
}

// Web rate limiting hoisted to src/lib/web/limiter.ts (shared with the
// dashboard page modules); flask-limiter deduct_when semantics unchanged.

// ---------------------------------------------------------------------------
// Form plumbing
// ---------------------------------------------------------------------------

function fStr(body: Record<string, unknown>, key: string): string {
  const v = body[key];
  return typeof v === "string" ? v : "";
}

/** wtforms DataRequired: empty or whitespace-only fails. */
function requiredErrors(value: string): string[] {
  return value.trim() ? [] : [REQUIRED_MSG];
}

/** DataRequired + Length(min=8, max=100) — length only runs after required. */
function passwordFieldErrors(value: string): string[] {
  if (!value.trim()) return [REQUIRED_MSG];
  const len = [...value].length; // Python len() = code points
  if (len < 8 || len > 100) return [LENGTH_8_100_MSG];
  return [];
}

/** Assemble the wtforms-like form object handed to templates. */
async function buildForm(
  c: Ctx,
  fields: Record<string, FormField>,
): Promise<Record<string, unknown>> {
  const token = await generateCsrfToken(c);
  return { csrf_token: csrfTokenField(token), ...fields };
}

/** validate_on_submit(): POST + valid CSRF + no field errors. CSRF failure is silent (200 re-render). */
async function csrfOk(c: Ctx, body: Record<string, unknown>): Promise<boolean> {
  const err = await validateCsrfToken(c, fStr(body, "csrf_token") || null);
  return err === null;
}

// ---------------------------------------------------------------------------
// Users / login helpers
// ---------------------------------------------------------------------------

function getUserByEmail(
  db: D1Database,
  email: string,
): Promise<UserRow | null> {
  return db
    .prepare("SELECT * FROM users WHERE email = ?1")
    .bind(email)
    .first<UserRow>();
}

/** `User.get_by(email=sanitized) or User.get_by(email=canonical)`. */
async function findUserByEmailInput(
  db: D1Database,
  emailInput: string,
): Promise<UserRow | null> {
  const sanitized = sanitizeEmail(emailInput);
  return (
    (await getUserByEmail(db, sanitized)) ??
    (await getUserByEmail(db, canonicalizeEmail(emailInput)))
  );
}

function getUserById(db: D1Database, id: number): Promise<UserRow | null> {
  return db
    .prepare("SELECT * FROM users WHERE id = ?1")
    .bind(id)
    .first<UserRow>();
}

function canSendOrReceive(user: UserRow): boolean {
  return !user.disabled && user.delete_on === null;
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

/** emit_alias_audit_log (app/alias_audit_log_utils.py L26). */
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

const MFA_USER_ID = "mfa_user_id";

async function setSessionExtra(
  c: Ctx,
  key: string,
  value: unknown,
): Promise<void> {
  const sess = (await getSession(c)) ?? {};
  sess.extra = { ...sess.extra, [key]: value };
  await saveSession(c, sess);
}

/**
 * login_user() with session-token rotation. IMPORTANT: any flash meant to
 * survive must be written BEFORE calling this (the rotated session carries
 * the current session data over, but post-rotation saves in the same
 * request would still target the old token).
 */
async function rotateAndLogin(
  c: Ctx,
  user: UserRow,
  opts: {
    sudo?: boolean;
    dropMfaUserId?: boolean;
    /**
     * Flash folded into the rotated session. Use this instead of a prior
     * flash() when the request may carry NO session cookie (e.g. the
     * activation link): flash() would mint one token and the rotation a
     * second one, and the browser only keeps the latter.
     */
    flashMessage?: { category: FlashCategory; message: string };
  } = {},
): Promise<void> {
  const sess = (await getSession(c)) ?? {};
  if (opts.flashMessage) {
    sess.flashes = [...(sess.flashes ?? []), opts.flashMessage];
  }
  if (opts.dropMfaUserId && sess.extra) {
    const extra = { ...sess.extra };
    delete extra[MFA_USER_ID];
    sess.extra = extra;
  }
  await rotateSession(c, {
    ...sess,
    user_id: user.id,
    alternative_id: user.alternative_id ?? undefined,
    ...(opts.sudo ? { sudo_time: Math.floor(Date.now() / 1000) } : {}),
  });
}

/** after_login(user, next_url, login_from_proton) — the post-credential dispatcher. */
async function afterLogin(
  c: Ctx,
  user: UserRow,
  nextUrl: string | null,
  loginFromProton = false,
): Promise<Response> {
  if (!loginFromProton) {
    if (user.fido_uuid !== null) {
      await setSessionExtra(c, MFA_USER_ID, user.id);
      return c.redirect(
        urlFor("auth.fido", nextUrl ? { next: nextUrl } : {}),
        302,
      );
    }
    if (user.enable_otp) {
      await setSessionExtra(c, MFA_USER_ID, user.id);
      return c.redirect(
        urlFor("auth.mfa", nextUrl ? { next: nextUrl } : {}),
        302,
      );
    }
  }
  // password login grants web sudo (TOTP/recovery completion does NOT)
  await rotateAndLogin(c, user, { sudo: true });
  return c.redirect(nextUrl ?? urlFor("dashboard.index"), 302);
}

// ---------------------------------------------------------------------------
// Registration helpers (local copies of module-private API helpers)
// ---------------------------------------------------------------------------

/** email_validator approximation — same as the API port (routes/auth.ts). */
function isValidEmail(email: string): boolean {
  if (!email || email.length > 320) return false;
  const parts = email.split("@");
  if (parts.length !== 2) return false;
  const [local, domain] = parts;
  if (!local || local.length > 64) return false;
  if (!/^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$/.test(local)) return false;
  if (local.startsWith(".") || local.endsWith(".") || local.includes(".."))
    return false;
  if (!domain || domain.length > 255 || !domain.includes(".")) return false;
  const labels = domain.split(".");
  for (const label of labels) {
    if (!label || label.length > 63) return false;
    if (!/^[A-Za-z0-9-]+$/.test(label)) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
  }
  return !/^\d+$/.test(labels[labels.length - 1]);
}

/**
 * is_invalid_mailbox_domain (email_utils.py L793): the domain or ANY parent
 * suffix (excluding the bare TLD) is listed in invalid_mailbox_domain. A
 * missing table counts as an empty blocklist (same stance as
 * src/routes/mailboxes.ts).
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
    if (String(e).includes("no such table")) return false;
    throw e;
  }
}

/** email_can_be_used_as_mailbox minus MX/abuse checks (API-port stance). */
async function emailCanBeUsedAsMailbox(
  db: D1Database,
  email: string,
): Promise<boolean> {
  if (!isValidEmail(email)) return false;
  const domain = email.split("@")[1];

  const slDomain = await db
    .prepare("SELECT 1 FROM public_domain WHERE domain = ?1")
    .bind(domain)
    .first();
  if (slDomain) return false;

  const customDomain = await db
    .prepare("SELECT 1 FROM custom_domain WHERE domain = ?1 AND verified = 1")
    .bind(domain)
    .first();
  if (customDomain) return false;

  if (await isInvalidMailboxDomain(db, domain)) return false;

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
  if (disabledMailboxOwner) return false;

  return true;
}

async function personalEmailAlreadyUsed(
  db: D1Database,
  email: string,
): Promise<boolean> {
  return (await getUserByEmail(db, email)) !== null;
}

/** get_referral(): cookie `slref` first, then session extra. */
async function getReferralId(c: Ctx): Promise<number | null> {
  const codes: string[] = [];
  const cookieRef = getCookie(c, "slref");
  if (cookieRef) codes.push(cookieRef);
  const sess = await getSession(c);
  const sessRef = sess?.extra?.slref;
  if (typeof sessRef === "string") codes.push(sessRef);
  for (const code of codes) {
    const row = await c.env.DB.prepare(
      "SELECT id FROM referral WHERE code = ?1",
    )
      .bind(code)
      .first<{ id: number }>();
    if (row) return row.id;
  }
  return null;
}

/** User.create(email, name, password, referral) + its side effects (mailbox, newsletter alias, jobs, audit log). */
async function createWebUser(
  c: Ctx,
  canonicalEmail: string,
  rawEmailInput: string,
  password: string,
): Promise<UserRow> {
  const db = c.env.DB;
  const now = new Date();
  const referralId = await getReferralId(c);

  const user = await db
    .prepare(
      `INSERT INTO users (email, name, password, alternative_id, trial_end, referral_id)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6) RETURNING *`,
    )
    .bind(
      sanitizeEmail(canonicalEmail),
      rawEmailInput.slice(0, 100),
      await hashPassword(password),
      crypto.randomUUID(),
      toStr(addHours(addDays(now, 7), 1)),
      referralId,
    )
    .first<UserRow>();
  if (!user) throw new Error("users insert returned no row");

  await emitUserAuditLog(
    db,
    user,
    "create_user",
    `Created user ${canonicalEmail}`,
  );

  const mailbox = await db
    .prepare(
      "INSERT INTO mailbox (user_id, email, verified) VALUES (?1, ?2, 1) RETURNING id",
    )
    .bind(user.id, user.email)
    .first<{ id: number }>();
  await db
    .prepare(
      "UPDATE users SET default_mailbox_id = ?1, updated_at = ?2 WHERE id = ?3",
    )
    .bind(mailbox?.id ?? null, nowStr(), user.id)
    .run();

  // first (newsletter) alias — word + 3 digits on FIRST_ALIAS_DOMAIN
  const aliasDomain = c.env.FIRST_ALIAS_DOMAIN || c.env.EMAIL_DOMAIN;
  for (let i = 0; i < 100; i++) {
    const candidate = `simplelogin-newsletter.${randomWords(1, 3)}@${aliasDomain}`;
    if (!(await availableSlEmail(db, candidate))) continue;
    const alias = await db
      .prepare(
        `INSERT INTO alias (user_id, email, note, mailbox_id)
         VALUES (?1, ?2, ?3, ?4) RETURNING id`,
      )
      .bind(
        user.id,
        candidate,
        "This is your first alias. It's used to receive SimpleLogin communications like new features announcements, newsletters.",
        mailbox?.id ?? null,
      )
      .first<{ id: number }>();
    // Alias.create -> emit_alias_audit_log(CreateAlias) (app/models.py L1862)
    if (alias) {
      await emitAliasAuditLog(
        db,
        { id: alias.id, user_id: user.id, email: candidate },
        "create",
        "New alias created",
      );
    }
    await db
      .prepare(
        "UPDATE users SET newsletter_alias_id = ?1, updated_at = ?2 WHERE id = ?3",
      )
      .bind(alias?.id ?? null, nowStr(), user.id)
      .run();
    break;
  }

  const disableOnboarding = (c.env as XEnv).DISABLE_ONBOARDING !== undefined;
  if (!disableOnboarding) {
    const payload = JSON.stringify({ user_id: user.id });
    const jobs: [string, number][] = [
      ["onboarding-1", 1],
      ["onboarding-2", 2],
      ["onboarding-4", 3],
    ];
    for (const [name, days] of jobs) {
      await db
        .prepare("INSERT INTO job (name, payload, run_at) VALUES (?1, ?2, ?3)")
        .bind(name, payload, toStr(addDays(now, days)))
        .run();
    }
  }

  return user;
}

// ---------------------------------------------------------------------------
// Emails
// ---------------------------------------------------------------------------

/** Web activation flow: 30-char link code in activation_code, 1 h expiry. */
async function sendActivationEmailWeb(
  env: Env,
  user: UserRow,
  nextUrl: string | null,
): Promise<void> {
  await env.DB.prepare("DELETE FROM activation_code WHERE user_id = ?1")
    .bind(user.id)
    .run();
  const code = randomString(30);
  await env.DB.prepare(
    "INSERT INTO activation_code (user_id, code, expired) VALUES (?1, ?2, ?3)",
  )
    .bind(user.id, code, toStr(addHours(new Date(), 1)))
    .run();

  let link = `${env.URL}/auth/activate?code=${code}`;
  if (nextUrl) link += `&next=${encodeURIComponent(nextUrl)}`;

  if (!canSendOrReceive(user)) return;
  await sendTransactionalEmail(env, {
    to: user.email,
    subject: "Just one more step to join SimpleLogin",
    text:
      "Hi,\n\nThank you for choosing SimpleLogin.\n\n" +
      `To get started, please confirm that ${user.email} is your email address using this link ${link} within 1 hour.\n\n` +
      "If it wasn't you, maybe someone entered your email by mistake. In this case you can ignore this mail.\n",
  });
}

/** send_welcome_email — to the communication email (newsletter alias when enabled). */
async function sendWelcomeEmail(env: Env, user: UserRow): Promise<void> {
  if (!user.notification || user.disabled) return;
  let to = user.email;
  if (user.newsletter_alias_id != null) {
    const alias = await env.DB.prepare(
      "SELECT email, enabled FROM alias WHERE id = ?1",
    )
      .bind(user.newsletter_alias_id)
      .first<{ email: string; enabled: number }>();
    if (alias) {
      if (!alias.enabled) return;
      to = alias.email;
    }
  }
  await sendTransactionalEmail(env, {
    to,
    subject: "Welcome to SimpleLogin",
    text:
      "Hi,\n\nWelcome to SimpleLogin!\n\n" +
      "You can now create aliases to protect your email address: whenever you need to give out your email address, use an alias instead.\n\n" +
      `Get started at ${env.URL}/dashboard/\n`,
  });
}

/** send_reset_password_email: code row is created even for disabled users; only the email is skipped. */
async function sendResetPasswordEmail(env: Env, user: UserRow): Promise<void> {
  const code = tokenUrlsafe(32);
  await env.DB.prepare(
    "INSERT INTO reset_password_code (user_id, code, expired) VALUES (?1, ?2, ?3)",
  )
    .bind(user.id, code, toStr(addHours(new Date(), 1)))
    .run();
  if (!canSendOrReceive(user)) return;
  const link = `${env.URL}/auth/reset_password?code=${code}`;
  await sendTransactionalEmail(env, {
    to: user.email,
    subject: "Reset your password on SimpleLogin",
    text: `To reset or change your password, please click on this link:\n\n${link}\n`,
  });
}

/**
 * send_invalid_totp_login_email(user, totp_type) — capped at 1/24h via
 * sent_alert. totpType is "TOTP" (mfa.py L105) or "recovery" (recovery.py L76)
 * and is interpolated into the body like the Jinja template does.
 */
async function sendInvalidTotpLoginEmail(
  env: Env,
  user: UserRow,
  totpType: "TOTP" | "recovery",
): Promise<void> {
  if (!canSendOrReceive(user)) return;
  const alertType = "invalid_totp_login";
  const toEmail = sanitizeEmail(user.email);
  const since = toStr(addDays(new Date(), -1));
  const recent = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM sent_alert
     WHERE alert_type = ?1 AND to_email = ?2 AND created_at > ?3`,
  )
    .bind(alertType, toEmail, since)
    .first<{ n: number }>();
  if ((recent?.n ?? 0) >= 1) return;
  await env.DB.prepare(
    "INSERT INTO sent_alert (user_id, to_email, alert_type) VALUES (?1, ?2, ?3)",
  )
    .bind(user.id, toEmail, alertType)
    .run();
  await sendTransactionalEmail(env, {
    to: user.email,
    subject: "Unsuccessful attempt to login to your SimpleLogin account",
    text:
      "There has been an unsuccessful attempt to login to your SimpleLogin account.\n" +
      `An invalid ${totpType} code was provided but the email and password were correct.\n\n` +
      "This request has been blocked. However, if this was not you, please change your password immediately.\n" +
      `${env.URL}/dashboard/setting#change_password\n`,
  });
}

// ---------------------------------------------------------------------------
// Recovery-code hashing
// ---------------------------------------------------------------------------

const enc = new TextEncoder();

/**
 * DIVERGENCE from Flask: RecoveryCode._hash_code uses HMAC-SHA3-224, which
 * WebCrypto does not provide. This port stores/matches HMAC-SHA256, base64url
 * without padding, keyed on RECOVERY_CODE_HMAC_SECRET (fallback FLASK_SECRET).
 * Exported so the MFA-setup page / tests hash codes identically.
 */
export async function hashRecoveryCode(
  secret: string,
  code: string,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, enc.encode(code)),
  );
  let bin = "";
  for (const b of sig) bin += String.fromCharCode(b);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function recoveryCodeSecret(env: XEnv): string {
  return env.RECOVERY_CODE_HMAC_SECRET ?? env.FLASK_SECRET;
}

// ---------------------------------------------------------------------------
// Row types local to this group
// ---------------------------------------------------------------------------

interface ActivationCodeRow extends BaseRow {
  user_id: number;
  code: string;
  expired: string;
}
interface EmailChangeRow extends BaseRow {
  user_id: number;
  new_email: string;
  code: string;
  expired: string;
}
interface MfaBrowserRow extends BaseRow {
  user_id: number;
  token: string;
  expires: string;
}
interface RecoveryCodeRow extends BaseRow {
  user_id: number;
  code: string;
  used: number;
  used_at: string | null;
}
interface FidoRow extends BaseRow {
  credential_id: string;
  uuid: string;
  public_key: string;
  sign_count: number;
  name: string;
  user_id: number | null;
  transports: string | null;
}

function isExpired(expired: string): boolean {
  return toDate(expired).getTime() < Date.now();
}

// ---------------------------------------------------------------------------
// Route 1: GET|POST /login
// ---------------------------------------------------------------------------

webAuthPagesRoutes.on(["GET", "POST"], "/login", async (c) => {
  const limiter = await webLimiter(c, "web_auth_login", "10/minute");
  if (limiter.exceeded) return renderErrorPage(c, 429);

  const nextUrl = nextUrlOf(c);
  const { user: currentUser } = await loadWebUser(c);
  if (currentUser) {
    return c.redirect(nextUrl ?? urlFor("dashboard.index"), 302);
  }

  const xenv = c.env as XEnv;
  let emailValue = "";
  let emailErrors: string[] = [];
  let passwordErrors: string[] = [];
  let showResendActivation = false;

  if (c.req.method === "POST") {
    const body = await c.req.parseBody();
    emailValue = fStr(body, "email");
    const password = fStr(body, "password");
    emailErrors = requiredErrors(emailValue);
    passwordErrors = requiredErrors(password);
    const valid =
      (await csrfOk(c, body)) &&
      emailErrors.length === 0 &&
      passwordErrors.length === 0;

    if (valid) {
      const email = sanitizeEmail(emailValue);
      const user =
        (await getUserByEmail(c.env.DB, email)) ??
        (await getUserByEmail(c.env.DB, canonicalizeEmail(email)));
      // dummy bcrypt check runs even when no user exists (timing mitigation)
      const passwordOk = await checkPassword(user?.password ?? null, password);
      if (!user || !passwordOk) {
        await limiter.deduct();
        await flash(c, "Email or password incorrect", "error");
      } else if (user.disabled) {
        await flash(
          c,
          "Your account is disabled. Please contact SimpleLogin team to re-enable your account.",
          "error",
        );
      } else if (user.delete_on !== null) {
        // Flask interpolates the Arrow repr (ISO-8601 with T separator)
        const deleteOn = toDate(user.delete_on)
          .toISOString()
          .replace(/\.\d{3}Z$/, "+00:00");
        await flash(
          c,
          `Your account is scheduled to be deleted on ${deleteOn}`,
          "error",
        );
      } else if (!user.activated) {
        showResendActivation = true;
        await flash(
          c,
          "Please check your inbox for the activation email. You can also have this email re-sent",
          "error",
        );
      } else {
        return afterLogin(c, user, nextUrl);
      }
    }
  }

  const form = await buildForm(c, {
    email: makeField(
      { name: "email", type: "email", label: "Email", value: emailValue },
      emailErrors,
    ),
    // failed login clears the password field — never echo it back
    password: makeField(
      { name: "password", type: "password", label: "Password" },
      passwordErrors,
    ),
  });
  return webRender(c, "auth/login.html", {
    form,
    next_url: nextUrl,
    show_resend_activation: showResendActivation,
    connect_with_proton: xenv.CONNECT_WITH_PROTON !== undefined,
    connect_with_oidc: xenv.OIDC_CLIENT_ID != null,
    connect_with_oidc_icon: xenv.CONNECT_WITH_OIDC_ICON ?? null,
  });
});

// ---------------------------------------------------------------------------
// Route 2: GET|POST /register
// ---------------------------------------------------------------------------

webAuthPagesRoutes.on(["GET", "POST"], "/register", async (c) => {
  const { user: currentUser } = await loadWebUser(c);
  if (currentUser) {
    await flash(c, "You are already logged in", "warning");
    return c.redirect(urlFor("dashboard.index"), 302);
  }
  if (
    c.env.DISABLE_REGISTRATION !== undefined &&
    c.env.DISABLE_REGISTRATION !== ""
  ) {
    await flash(c, "Registration is closed", "error");
    return c.redirect(urlFor("auth.login"), 302);
  }

  const xenv = c.env as XEnv;
  const nextUrl = c.req.query("next") ?? null; // raw, link-embedding only
  const db = c.env.DB;

  let emailValue = "";
  let emailErrors: string[] = [];
  let passwordErrors: string[] = [];

  const renderPage = async (reducedContext = false) => {
    const form = await buildForm(c, {
      email: makeField(
        { name: "email", type: "email", label: "Email", value: emailValue },
        emailErrors,
      ),
      password: makeField(
        { name: "password", type: "password", label: "Password" },
        passwordErrors,
      ),
    });
    const ctx: Record<string, unknown> = {
      form,
      next_url: nextUrl,
      HCAPTCHA_SITEKEY: xenv.HCAPTCHA_SITEKEY ?? null,
    };
    if (!reducedContext) {
      // gotcha replicated: the hCaptcha-failure re-render drops these
      ctx.connect_with_proton = xenv.CONNECT_WITH_PROTON !== undefined;
      ctx.connect_with_oidc = xenv.OIDC_CLIENT_ID != null;
      ctx.connect_with_oidc_icon = xenv.CONNECT_WITH_OIDC_ICON ?? null;
    }
    return webRender(c, "auth/register.html", ctx);
  };

  if (c.req.method === "POST") {
    const body = await c.req.parseBody();
    emailValue = fStr(body, "email");
    const password = fStr(body, "password");
    emailErrors = requiredErrors(emailValue);
    passwordErrors = passwordFieldErrors(password);
    const valid =
      (await csrfOk(c, body)) &&
      emailErrors.length === 0 &&
      passwordErrors.length === 0;

    if (valid) {
      if (xenv.HCAPTCHA_SECRET) {
        const params = new URLSearchParams({
          secret: xenv.HCAPTCHA_SECRET,
          response: fStr(body, "h-captcha-response"),
        });
        let success = false;
        try {
          const res = await fetch("https://hcaptcha.com/siteverify", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: params.toString(),
          });
          success =
            ((await res.json()) as { success?: boolean }).success === true;
        } catch {
          success = false;
        }
        if (!success) {
          await flash(c, "Wrong Captcha", "error");
          return renderPage(true);
        }
      }

      const email = canonicalizeEmail(emailValue);
      if (!(await emailCanBeUsedAsMailbox(db, email))) {
        await flash(
          c,
          "You cannot use this email address as your personal inbox.",
          "error",
        );
      } else {
        // abuser_lookup ban check skipped: table/MAC_KEY absent in this port
        const sanitized = sanitizeEmail(emailValue);
        if (
          (await personalEmailAlreadyUsed(db, email)) ||
          (await personalEmailAlreadyUsed(db, sanitized))
        ) {
          await flash(c, `Email ${email} already used`, "error");
        } else {
          const user = await createWebUser(c, email, emailValue, password);
          await sendActivationEmailWeb(c.env, user, nextUrl);
          // DailyMetric.nb_new_web_non_proton_user skipped (no table)
          return webRender(c, "auth/register_waiting_activation.html", {});
        }
      }
    }
  }

  return renderPage();
});

// ---------------------------------------------------------------------------
// Route 3: GET|POST /activate — GET has side effects (activates + logs in)
// ---------------------------------------------------------------------------

webAuthPagesRoutes.on(["GET", "POST"], "/activate", async (c) => {
  const limiter = await webLimiter(c, "web_auth_activate", "10/minute");
  if (limiter.exceeded) return renderErrorPage(c, 429);

  const { user: currentUser } = await loadWebUser(c);
  if (currentUser) {
    return webRender(
      c,
      "auth/activate.html",
      { error: "You are already logged in" },
      { status: 400 },
    );
  }

  const code = c.req.query("code") ?? null;
  const activation = await c.env.DB.prepare(
    "SELECT * FROM activation_code WHERE code = ?1",
  )
    .bind(code)
    .first<ActivationCodeRow>();

  if (!activation) {
    await limiter.deduct();
    return webRender(
      c,
      "auth/activate.html",
      { error: "Activation code cannot be found" },
      { status: 400 },
    );
  }
  if (isExpired(activation.expired)) {
    return webRender(
      c,
      "auth/activate.html",
      { error: "Activation code was expired", show_resend_activation: true },
      { status: 400 },
    );
  }

  const user = await getUserById(c.env.DB, activation.user_id);
  if (!user) return renderErrorPage(c, 500);

  await c.env.DB.prepare(
    "UPDATE users SET activated = 1, updated_at = ?1 WHERE id = ?2",
  )
    .bind(nowStr(), user.id)
    .run();
  await emitUserAuditLog(
    c.env.DB,
    user,
    "activate_user",
    `User has been activated: ${user.email}`,
  );
  await c.env.DB.prepare("DELETE FROM activation_code WHERE id = ?1")
    .bind(activation.id)
    .run();

  // activation logs in without MFA interstitial and without sudo_time; the
  // flash rides inside the rotated session (the request may be cookie-less)
  await rotateAndLogin(c, user, {
    flashMessage: {
      category: "success",
      message: "Your account has been activated",
    },
  });

  await sendWelcomeEmail(c.env, { ...user, activated: 1 });

  // the &next= in the activation link is deliberately ignored
  return c.redirect(urlFor("dashboard.index"), 302);
});

// ---------------------------------------------------------------------------
// Route 4: GET|POST /resend_activation — every request deducts (incl. GET)
// ---------------------------------------------------------------------------

webAuthPagesRoutes.on(["GET", "POST"], "/resend_activation", async (c) => {
  const limiter = await webLimiter(c, "web_auth_resend_activation", "10/hour");
  if (limiter.exceeded) return renderErrorPage(c, 429);
  await limiter.deduct();

  let emailValue = "";
  let emailErrors: string[] = [];

  if (c.req.method === "POST") {
    const body = await c.req.parseBody();
    emailValue = fStr(body, "email");
    emailErrors = requiredErrors(emailValue);
    if ((await csrfOk(c, body)) && emailErrors.length === 0) {
      const user = await findUserByEmailInput(c.env.DB, emailValue);
      if (!user) {
        await flash(
          c,
          "If this email is registered, an activation email has been sent.",
          "warning",
        );
      } else if (user.activated) {
        await flash(
          c,
          "Your account was already activated, please login",
          "success",
        );
        return c.redirect(urlFor("auth.login"), 302);
      } else {
        await flash(
          c,
          "An activation email has been sent to you. Please check your inbox/spam folder.",
          "warning",
        );
        await sendActivationEmailWeb(c.env, user, c.req.query("next") ?? null);
        return webRender(c, "auth/register_waiting_activation.html", {});
      }
    }
  }

  const form = await buildForm(c, {
    email: makeField(
      { name: "email", type: "email", label: "Email", value: emailValue },
      emailErrors,
    ),
  });
  return webRender(c, "auth/resend_activation.html", { form });
});

// ---------------------------------------------------------------------------
// Route 5: GET|POST /forgot_password — deducts on every valid form submit
// ---------------------------------------------------------------------------

webAuthPagesRoutes.on(["GET", "POST"], "/forgot_password", async (c) => {
  const limiter = await webLimiter(c, "web_auth_forgot_password", "10/hour");
  if (limiter.exceeded) return renderErrorPage(c, 429);

  let emailValue = "";
  let emailErrors: string[] = [];

  if (c.req.method === "POST") {
    const body = await c.req.parseBody();
    emailValue = fStr(body, "email");
    emailErrors = requiredErrors(emailValue);
    if ((await csrfOk(c, body)) && emailErrors.length === 0) {
      await limiter.deduct();
      // flashed always, before/regardless of the user lookup
      await flash(
        c,
        "If your email is correct, you are going to receive an email to reset your password",
        "success",
      );
      const user = await findUserByEmailInput(c.env.DB, emailValue);
      if (user) await sendResetPasswordEmail(c.env, user);
    }
  }

  const form = await buildForm(c, {
    email: makeField(
      { name: "email", type: "email", label: "Email", value: emailValue },
      emailErrors,
    ),
  });
  return webRender(c, "auth/forgot_password.html", { form });
});

// ---------------------------------------------------------------------------
// Route 6: GET|POST /reset_password
// ---------------------------------------------------------------------------

webAuthPagesRoutes.on(["GET", "POST"], "/reset_password", async (c) => {
  const limiter = await webLimiter(c, "web_auth_reset_password", "10/minute");
  if (limiter.exceeded) return renderErrorPage(c, 429);

  let passwordErrors: string[] = [];
  const renderPage = async (error?: string) => {
    const form = await buildForm(c, {
      password: makeField(
        { name: "password", type: "password", label: "Password" },
        passwordErrors,
      ),
    });
    return webRender(c, "auth/reset_password.html", {
      form,
      ...(error ? { error } : {}),
    });
  };

  const code = c.req.query("code") ?? null;
  const resetCode = await c.env.DB.prepare(
    "SELECT * FROM reset_password_code WHERE code = ?1",
  )
    .bind(code)
    .first<{ id: number; user_id: number; code: string; expired: string }>();

  if (!resetCode) {
    await limiter.deduct();
    return renderPage(
      "The reset password link can be used only once. Please request a new link to reset password.",
    );
  }
  if (isExpired(resetCode.expired)) {
    return renderPage(
      "The link has been already expired. Please make a new request of the reset password link",
    );
  }

  if (c.req.method === "POST") {
    const body = await c.req.parseBody();
    const newPassword = fStr(body, "password");
    passwordErrors = passwordFieldErrors(newPassword);
    if ((await csrfOk(c, body)) && passwordErrors.length === 0) {
      const user = await getUserById(c.env.DB, resetCode.user_id);
      if (!user) return renderErrorPage(c, 500);

      if (await checkPassword(user.password, newPassword)) {
        return renderPage("You cannot reuse the same password");
      }

      const newHash = await hashPassword(newPassword);
      const newAlternativeId = crypto.randomUUID();
      // new alternative_id logs the user out of every other browser
      await c.env.DB.prepare(
        `UPDATE users SET password = ?1, activated = 1, alternative_id = ?2,
                updated_at = ?3 WHERE id = ?4`,
      )
        .bind(newHash, newAlternativeId, nowStr(), user.id)
        .run();
      await emitUserAuditLog(
        c.env.DB,
        user,
        "reset_password",
        "User has reset their password",
      );
      await c.env.DB.prepare(
        "DELETE FROM reset_password_code WHERE user_id = ?1",
      )
        .bind(user.id)
        .run();

      await flash(c, "Your new password has been set", "success");
      // not login_user directly: FIDO/TOTP users get the MFA interstitial
      return afterLogin(
        c,
        {
          ...user,
          password: newHash,
          activated: 1,
          alternative_id: newAlternativeId,
        },
        urlFor("dashboard.index"),
      );
    }
  }

  return renderPage();
});

// ---------------------------------------------------------------------------
// Route 7: GET|POST /change_email — GET has side effects, 3/hour every request
// ---------------------------------------------------------------------------

webAuthPagesRoutes.on(["GET", "POST"], "/change_email", async (c) => {
  const limiter = await webLimiter(c, "web_auth_change_email", "3/hour");
  if (limiter.exceeded) return renderErrorPage(c, 429);
  await limiter.deduct();

  const code = c.req.query("code") ?? null;
  const emailChange = await c.env.DB.prepare(
    "SELECT * FROM email_change WHERE code = ?1",
  )
    .bind(code)
    .first<EmailChangeRow>();

  if (!emailChange) return webRender(c, "auth/change_email.html", {});
  if (isExpired(emailChange.expired)) {
    await c.env.DB.prepare("DELETE FROM email_change WHERE id = ?1")
      .bind(emailChange.id)
      .run();
    return webRender(c, "auth/change_email.html", {});
  }

  await c.env.DB.prepare(
    "UPDATE users SET email = ?1, updated_at = ?2 WHERE id = ?3",
  )
    .bind(emailChange.new_email, nowStr(), emailChange.user_id)
    .run();
  await c.env.DB.prepare("DELETE FROM email_change WHERE id = ?1")
    .bind(emailChange.id)
    .run();
  await c.env.DB.prepare("DELETE FROM reset_password_code WHERE user_id = ?1")
    .bind(emailChange.user_id)
    .run();

  await flash(c, "Your new email has been updated", "success");
  // deliberately no login here so MFA still applies
  return c.redirect(urlFor("auth.login"), 302);
});

// ---------------------------------------------------------------------------
// MFA interstitial shared guards
// ---------------------------------------------------------------------------

/**
 * Returns user: null when mfa_user_id points at a deleted user — /mfa and
 * /fido guard None-safely (`if not (user and ...)`, mfa.py L48 / fido.py L53)
 * while /recovery raises (recovery.py L37 calls a method on the None user).
 */
async function mfaInterstitialUser(
  c: Ctx,
): Promise<{ user: UserRow | null } | { response: Response }> {
  const sess = await getSession(c);
  const mfaUserId = sess?.extra?.[MFA_USER_ID];
  if (typeof mfaUserId !== "number") {
    await flash(c, "Unknown error, redirect back to main page", "warning");
    return { response: c.redirect(urlFor("auth.login"), 302) };
  }
  return { user: await getUserById(c.env.DB, mfaUserId) };
}

/** Device-cookie fast path shared by /mfa and /fido. Returns a redirect Response or null. */
async function mfaDeviceCookieFastPath(
  c: Ctx,
  user: UserRow,
  nextUrl: string | null,
  limiter: WebLimiter,
): Promise<Response | null> {
  const cookieToken = getCookie(c, "mfa");
  if (!cookieToken) return null;
  const browser = await c.env.DB.prepare(
    "SELECT * FROM mfa_browser WHERE token = ?1",
  )
    .bind(cookieToken)
    .first<MfaBrowserRow>();
  if (browser && !isExpired(browser.expires) && browser.user_id === user.id) {
    await flash(c, "Welcome back!", "success");
    // gotcha replicated: mfa_user_id stays in the session, no sudo_time
    await rotateAndLogin(c, user);
    return c.redirect(nextUrl ?? urlFor("dashboard.index"), 302);
  }
  await limiter.deduct();
  return null;
}

/** Set the 30-day `mfa` remember cookie + row (MfaBrowser.create_new). */
async function rememberBrowser(c: Ctx, user: UserRow): Promise<void> {
  const token = randomString(64);
  const expires = addDays(new Date(), 30);
  await c.env.DB.prepare(
    "INSERT INTO mfa_browser (user_id, token, expires) VALUES (?1, ?2, ?3)",
  )
    .bind(user.id, token, toStr(expires))
    .run();
  setCookie(c, "mfa", token, {
    path: "/",
    expires,
    secure: c.env.URL.startsWith("https"),
    httpOnly: true,
    sameSite: "Lax",
  });
}

// ---------------------------------------------------------------------------
// Route 8: GET|POST /mfa
// ---------------------------------------------------------------------------

webAuthPagesRoutes.on(["GET", "POST"], "/mfa", async (c) => {
  const limiter = await webLimiter(c, "web_auth_mfa", "10/minute");
  if (limiter.exceeded) return renderErrorPage(c, 429);

  const guard = await mfaInterstitialUser(c);
  if ("response" in guard) return guard.response;
  const user = guard.user;
  // `if not (user and user.enable_otp)` (mfa.py L48) — None-safe
  if (!user?.enable_otp) {
    await flash(
      c,
      "Only user with MFA enabled should go to this page",
      "warning",
    );
    return c.redirect(urlFor("auth.login"), 302);
  }

  const nextUrl = nextUrlOf(c);
  const fastPath = await mfaDeviceCookieFastPath(c, user, nextUrl, limiter);
  if (fastPath) return fastPath;

  let tokenErrors: string[] = [];
  let rememberChecked = false;

  if (c.req.method === "POST") {
    const body = await c.req.parseBody();
    const rawToken = fStr(body, "token");
    rememberChecked = fStr(body, "remember") !== "";
    tokenErrors = requiredErrors(rawToken);
    if ((await csrfOk(c, body)) && tokenErrors.length === 0) {
      const token = rawToken.replaceAll(" ", "");
      const valid =
        user.otp_secret !== null &&
        verifyTotp(user.otp_secret, token, user.last_otp);
      if (valid) {
        await c.env.DB.prepare(
          "UPDATE users SET last_otp = ?1, updated_at = ?2 WHERE id = ?3",
        )
          .bind(token, nowStr(), user.id)
          .run();
        await flash(c, "Welcome back!", "success");
        // TOTP completion does NOT grant sudo_time
        await rotateAndLogin(c, user, { dropMfaUserId: true });
        if (rememberChecked) await rememberBrowser(c, user);
        return c.redirect(nextUrl ?? urlFor("dashboard.index"), 302);
      }
      await flash(c, "Incorrect token", "warning");
      await limiter.deduct();
      await sendInvalidTotpLoginEmail(c.env, user, "TOTP");
      // failed TOTP clears the token field (nothing echoed below)
    }
  }

  const otpTokenForm = await buildForm(c, {
    token: makeField({ name: "token", label: "Token" }, tokenErrors),
    remember: makeField({
      name: "remember",
      type: "checkbox",
      label: "attr",
      description: "Remember this browser for 30 days",
      value: "y",
      checked: rememberChecked,
    }),
  });
  return webRender(c, "auth/mfa.html", {
    otp_token_form: otpTokenForm,
    enable_fido: user.fido_uuid !== null,
    next_url: nextUrl,
  });
});

// ---------------------------------------------------------------------------
// Route 9: GET|POST /recovery (endpoint auth.recovery_route)
// ---------------------------------------------------------------------------

webAuthPagesRoutes.on(["GET", "POST"], "/recovery", async (c) => {
  const limiter = await webLimiter(c, "web_auth_recovery", "10/minute");
  if (limiter.exceeded) return renderErrorPage(c, 429);

  const guard = await mfaInterstitialUser(c);
  if ("response" in guard) return guard.response;
  const user = guard.user;
  if (!user) {
    // recovery.py L37 calls user.two_factor_authentication_enabled() on the
    // None user and raises -> web 500 page (unlike /mfa and /fido)
    throw new Error("mfa_user_id points at a missing user");
  }
  if (!(user.enable_otp || user.fido_uuid !== null)) {
    await flash(
      c,
      "Only user with MFA enabled should go to this page",
      "warning",
    );
    return c.redirect(urlFor("auth.login"), 302);
  }

  const nextUrl = nextUrlOf(c);
  let codeErrors: string[] = [];

  if (c.req.method === "POST") {
    const body = await c.req.parseBody();
    const codeInput = fStr(body, "code");
    codeErrors = requiredErrors(codeInput);
    if ((await csrfOk(c, body)) && codeErrors.length === 0) {
      const hashed = await hashRecoveryCode(
        recoveryCodeSecret(c.env as XEnv),
        codeInput,
      );
      const recoveryCode = await c.env.DB.prepare(
        "SELECT * FROM recovery_code WHERE user_id = ?1 AND code = ?2",
      )
        .bind(user.id, hashed)
        .first<RecoveryCodeRow>();

      if (recoveryCode) {
        if (recoveryCode.used) {
          await limiter.deduct();
          await flash(c, "Code already used", "error");
        } else {
          await c.env.DB.prepare(
            "UPDATE recovery_code SET used = 1, used_at = ?1, updated_at = ?1 WHERE id = ?2",
          )
            .bind(nowStr(), recoveryCode.id)
            .run();
          await flash(c, "Welcome back!", "success");
          // no sudo_time, no mfa remember-cookie option here
          await rotateAndLogin(c, user, { dropMfaUserId: true });
          return c.redirect(nextUrl ?? urlFor("dashboard.index"), 302);
        }
      } else {
        await limiter.deduct();
        await flash(c, "Incorrect code", "error");
        await sendInvalidTotpLoginEmail(c.env, user, "recovery");
      }
    }
  }

  const recoveryForm = await buildForm(c, {
    code: makeField({ name: "code", label: "Code" }, codeErrors),
  });
  return webRender(c, "auth/recovery.html", { recovery_form: recoveryForm });
});

// ---------------------------------------------------------------------------
// Route 10: GET /logout — GET with side effects, no CSRF (Flask parity)
// ---------------------------------------------------------------------------

webAuthPagesRoutes.get("/logout", async (c) => {
  // purge the server session, then start a fresh anonymous one carrying the
  // flash (Flask: logout_session() + flash into the fresh session)
  await rotateSession(c, {
    flashes: [{ category: "success", message: "You are logged out" }],
  });
  deleteCookie(c, "mfa", { path: "/" });
  deleteCookie(c, "dark-mode", { path: "/" });
  return c.redirect(urlFor("auth.login"), 302);
});

// ---------------------------------------------------------------------------
// Route 11: GET /api_to_cookie — turns an API token into a web session
// ---------------------------------------------------------------------------

webAuthPagesRoutes.get("/api_to_cookie", async (c) => {
  const code = c.req.query("token");
  if (!code) {
    await flash(c, "Missing token", "error");
    return c.redirect(urlFor("auth.login"), 302);
  }

  const { user: currentUser } = await loadWebUser(c);
  const token = currentUser
    ? await c.env.DB.prepare(
        "SELECT * FROM api_cookie_token WHERE code = ?1 AND user_id = ?2",
      )
        .bind(code, currentUser.id)
        .first<{ id: number; user_id: number; created_at: string }>()
    : await c.env.DB.prepare("SELECT * FROM api_cookie_token WHERE code = ?1")
        .bind(code)
        .first<{ id: number; user_id: number; created_at: string }>();

  if (
    !token ||
    toDate(token.created_at).getTime() < addMinutes(new Date(), -5).getTime()
  ) {
    await flash(c, "Missing token", "error");
    return c.redirect(urlFor("auth.login"), 302);
  }

  const user = await getUserById(c.env.DB, token.user_id);
  await c.env.DB.prepare("DELETE FROM api_cookie_token WHERE id = ?1")
    .bind(token.id)
    .run();
  if (!user) {
    await flash(c, "Missing token", "error");
    return c.redirect(urlFor("auth.login"), 302);
  }

  // gotcha replicated: NO session rotation, no MFA interstitial, no sudo_time
  const sess = (await getSession(c)) ?? {};
  await saveSession(c, {
    ...sess,
    user_id: user.id,
    alternative_id: user.alternative_id ?? undefined,
  });

  const nextUrl = nextUrlOf(c);
  return c.redirect(nextUrl ?? urlFor("dashboard.index"), 302);
});

// ---------------------------------------------------------------------------
// Route 12: GET|POST /fido — WebAuthn assertion verify DEFERRED (see header)
// ---------------------------------------------------------------------------

webAuthPagesRoutes.on(["GET", "POST"], "/fido", async (c) => {
  const limiter = await webLimiter(c, "web_auth_fido", "10/minute");
  if (limiter.exceeded) return renderErrorPage(c, 429);

  const guard = await mfaInterstitialUser(c);
  if ("response" in guard) return guard.response;
  const user = guard.user;
  // `if not (user and user.fido_enabled())` (fido.py L53) — None-safe
  if (!user || user.fido_uuid === null) {
    await flash(
      c,
      "Only user with security key linked should go to this page",
      "warning",
    );
    return c.redirect(urlFor("auth.login"), 302);
  }

  const nextUrl = nextUrlOf(c);
  const fastPath = await mfaDeviceCookieFastPath(c, user, nextUrl, limiter);
  if (fastPath) return fastPath;

  let autoActivate = true;
  let skAssertionErrors: string[] = [];

  if (c.req.method === "POST") {
    const body = await c.req.parseBody();
    const skAssertion = fStr(body, "sk_assertion");
    skAssertionErrors = requiredErrors(skAssertion);
    if ((await csrfOk(c, body)) && skAssertionErrors.length === 0) {
      try {
        JSON.parse(skAssertion);
      } catch {
        await flash(
          c,
          "Key verification failed. Error: Invalid Payload",
          "warning",
        );
        return c.redirect(urlFor("auth.login"), 302);
      }
      // WebAuthn assertion verification is not implemented in this
      // deployment — fail like a bad key and keep TOTP/recovery working.
      await flash(c, "Key verification failed.", "warning");
      await limiter.deduct();
      autoActivate = false;
    }
  }

  // fresh challenge per render, stored in the session like Flask
  const challenge = tokenUrlsafe(32).replace(/=+$/, "");
  await setSessionExtra(c, "fido_challenge", challenge);

  const credentials = await c.env.DB.prepare(
    "SELECT * FROM fido WHERE uuid = ?1",
  )
    .bind(user.fido_uuid)
    .all<FidoRow>();
  let rpId = "";
  try {
    rpId = new URL(c.env.URL).hostname;
  } catch {
    rpId = "";
  }
  const assertionOptions = {
    challenge,
    timeout: 60000,
    rpId,
    allowCredentials: (credentials.results ?? []).map((f) => {
      const cred: Record<string, unknown> = {
        type: "public-key",
        id: f.credential_id,
      };
      if (f.transports) {
        try {
          cred.transports = JSON.parse(f.transports);
        } catch {
          // stored transports unparsable -> omit, like Flask drops absent ones
        }
      }
      return cred;
    }),
    userVerification: "discouraged",
  };
  // JSON string is embedded in a JS single-quoted string via |safe — escape
  // like Jinja's tojson does so </script> or quotes cannot break out.
  const optionsJson = JSON.stringify(assertionOptions)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("'", "\\u0027");

  const fidoTokenForm = await buildForm(c, {
    sk_assertion: makeField(
      { name: "sk_assertion", type: "hidden" },
      skAssertionErrors,
    ),
    remember: makeField({
      name: "remember",
      type: "checkbox",
      label: "attr",
      description: "Remember this browser for 30 days",
      value: "y",
    }),
  });
  return webRender(c, "auth/fido.html", {
    fido_token_form: fidoTokenForm,
    webauthn_assertion_options_json: optionsJson,
    enable_otp: !!user.enable_otp,
    auto_activate: autoActivate,
    next_url: nextUrl,
  });
});

// ---------------------------------------------------------------------------
// Route 13: GET|POST /social — deprecated social-login chooser
// ---------------------------------------------------------------------------

webAuthPagesRoutes.on(["GET", "POST"], "/social", async (c) => {
  const { user: currentUser } = await loadWebUser(c);
  if (currentUser) return c.redirect(urlFor("dashboard.index"), 302);
  return webRender(c, "auth/social.html", { next_url: null });
});

// ---------------------------------------------------------------------------
// Routes 14-23: social/OIDC OAuth — config-gated, flows DEFERRED
// ---------------------------------------------------------------------------

const OAUTH_PROVIDERS: Array<{
  path: string;
  idKey: string;
  secretKey: string;
}> = [
  // Flask has NO gate for github; the gate here is a documented divergence
  {
    path: "github",
    idKey: "GITHUB_CLIENT_ID",
    secretKey: "GITHUB_CLIENT_SECRET",
  },
  {
    path: "google",
    idKey: "GOOGLE_CLIENT_ID",
    secretKey: "GOOGLE_CLIENT_SECRET",
  },
  {
    path: "facebook",
    idKey: "FACEBOOK_CLIENT_ID",
    secretKey: "FACEBOOK_CLIENT_SECRET",
  },
  {
    path: "proton",
    idKey: "PROTON_CLIENT_ID",
    secretKey: "PROTON_CLIENT_SECRET",
  },
  { path: "oidc", idKey: "OIDC_CLIENT_ID", secretKey: "OIDC_CLIENT_SECRET" },
];

for (const provider of OAUTH_PROVIDERS) {
  for (const leg of ["login", "callback"] as const) {
    webAuthPagesRoutes.get(`/${provider.path}/${leg}`, (c) => {
      const xenv = c.env as XEnv;
      if (!xenv[provider.idKey] || !xenv[provider.secretKey]) {
        // unconfigured -> back to the login page (buttons are hidden anyway)
        return c.redirect(urlFor("auth.login"), 302);
      }
      // configured but the token-exchange flow is not ported: web 500 page
      // (per spec: better than a broken half-flow)
      throw new Error(
        `${provider.path} OAuth ${leg} is not supported in this deployment`,
      );
    });
  }
}
