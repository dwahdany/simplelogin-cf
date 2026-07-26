/**
 * Authentication routes — port of app/api/views/auth.py + auth_mfa.py
 * (spec: cloudflare/specs/01-auth.md).
 *
 * All routes are unauthenticated POSTs under /api. Error strings, status
 * codes (422 unactivated login, 410 activation tries exhausted, 403 FIDO,
 * 429 rate limit) are load-bearing — clients string-match them.
 *
 * Deliberate deviations from Flask (documented in HANDOVER.md §1):
 * - Flask 500s from `None` hitting sanitize/normalize (missing email on
 *   register/activate/reactivate, missing password on login) return the
 *   clean 4xx of the closest error branch here.
 * - No abuser_lookup / user_audit_log / invalid_mailbox_domain tables in the
 *   D1 schema; those side checks/writes are skipped.
 * - No MX/DNS lookup on register (Workers port behaves as if
 *   SKIP_MX_LOOKUP_ON_CHECK were set).
 * - login_user()'s Flask session cookie becomes a KV session (same "slapp"
 *   cookie name).
 */

import type { Context, MiddlewareHandler } from "hono";
import { Hono } from "hono";
import { type AppEnv, userIsActive } from "../lib/auth";
import {
  canonicalizeEmail,
  checkPassword,
  hashPassword,
  itsdangerousSign,
  itsdangerousUnsign,
  randomString,
  randomWords,
  sanitizeEmail,
  tokenUrlsafe,
  verifyTotp,
} from "../lib/crypto";
import { addDays, addHours, nowStr, toStr } from "../lib/dates";
import type { Env } from "../lib/env";
import { badRequest, jsonError } from "../lib/errors";
import { sendTransactionalEmail } from "../lib/mailer";
import { availableSlEmail, getUserById } from "../lib/models";
import { rateLimit, requestLock } from "../lib/ratelimit";
import type { AccountActivationRow, ApiKeyRow, UserRow } from "../lib/rows";
import { createSession, getSession } from "../lib/session";

export const authRoutes = new Hono<AppEnv>();

/**
 * flask-limiter key_func parity (app/extensions.py:14-19): every
 * @limiter.limit on the auth routes keys by `userid:{id}` whenever the
 * request carries a valid authenticated "slapp" session cookie (no
 * X-Sl-Allowcookies needed — flask-login's user loader runs on every
 * request), and by client IP otherwise. Likewise app/parallel_limiter.py:55-58
 * keys the /auth/mfa lock `cl:{user.id}:mfa_auth` for cookie-authenticated
 * callers. Mirror the flask-login user loader here (simplelogin_app.py
 * load_user): anonymous when the user is missing, disabled, inactive, or the
 * session's alternative_id was rotated away — then set the session/user vars
 * that rateLimit("default") and requestLock read.
 */
const loadSessionUserForLimiter: MiddlewareHandler<AppEnv> = async (
  c,
  next,
) => {
  const session = await getSession(c);
  if (session?.user_id != null) {
    const user = await getUserById(c.env.DB, session.user_id);
    const rotatedAway =
      session.alternative_id != null &&
      user?.alternative_id != null &&
      session.alternative_id !== user.alternative_id;
    if (user && !user.disabled && userIsActive(user) && !rotatedAway) {
      c.set("session", session);
      c.set("user", user);
    }
  }
  return next();
};

authRoutes.use("/auth/*", loadSessionUserForLimiter);

// --------------------------------------------------------------------------
// Local helpers (candidates for the shared lib — see libGaps in the report)
// --------------------------------------------------------------------------

/**
 * Flask `request.get_json()` + the `if not data` guard, combined:
 * - non-JSON Content-Type or no body → null (route → 400 "request body cannot
 *   be empty")
 * - JSON null / {} / [] / scalars → null (Python-falsy or Flask-500 paths,
 *   collapsed to the same 400)
 * - syntactically invalid JSON → JSON.parse throws SyntaxError → app-level
 *   handler → 400 {"error": "Bad Request"} (matches Flask BadRequest)
 */
async function getJsonBody(
  c: Context<AppEnv>,
): Promise<Record<string, unknown> | null> {
  const mime = (c.req.header("Content-Type") ?? "")
    .split(";")[0]
    .trim()
    .toLowerCase();
  if (mime !== "application/json" && !mime.endsWith("+json")) return null;
  const parsed: unknown = JSON.parse(await c.req.text());
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    Object.keys(parsed).length === 0
  ) {
    return null;
  }
  return parsed as Record<string, unknown>;
}

/** Body field as string; non-strings collapse to "" (Flask would 500). */
function strField(data: Record<string, unknown>, key: string): string {
  const v = data[key];
  return typeof v === "string" ? v : "";
}

/** ApiKey `name` semantics: the device value verbatim, null when absent. */
function deviceField(data: Record<string, unknown>): string | null {
  const v = data.device;
  return typeof v === "string" ? v : null;
}

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

/**
 * ApiKey.get_by(user_id, name=device) reuse-or-create. `IS ?2` makes a null
 * device match rows with a NULL name (SQLAlchemy `name=None` semantics).
 * Collision fallback to uuid4 mirrors ApiKey.create.
 */
async function getOrCreateApiKey(
  db: D1Database,
  userId: number,
  device: string | null,
): Promise<ApiKeyRow> {
  const existing = await db
    .prepare(
      "SELECT * FROM api_key WHERE user_id = ?1 AND name IS ?2 ORDER BY id LIMIT 1",
    )
    .bind(userId, device)
    .first<ApiKeyRow>();
  if (existing) return existing;

  let code = randomString(60);
  const clash = await db
    .prepare("SELECT 1 FROM api_key WHERE code = ?1")
    .bind(code)
    .first();
  if (clash) code = crypto.randomUUID();

  const row = await db
    .prepare(
      "INSERT INTO api_key (user_id, name, code) VALUES (?1, ?2, ?3) RETURNING *",
    )
    .bind(userId, device, code)
    .first<ApiKeyRow>();
  if (!row) throw new Error("api_key insert returned no row");
  return row;
}

/**
 * auth_payload(user, device) — login/social success body. Always contains all
 * five keys; api_key XOR mfa_key is null. Non-MFA path also logs the user in
 * on the web (slapp session cookie).
 */
async function authPayload(
  c: Context<AppEnv>,
  user: UserRow,
  device: string | null,
): Promise<Record<string, unknown>> {
  const ret: Record<string, unknown> = {
    name: user.name || "",
    email: user.email,
    mfa_enabled: !!user.enable_otp,
    mfa_key: null,
    api_key: null,
  };
  if (user.enable_otp) {
    ret.mfa_key = await itsdangerousSign(c.env.FLASK_SECRET, String(user.id));
  } else {
    const apiKey = await getOrCreateApiKey(c.env.DB, user.id, device);
    ret.api_key = apiKey.code;
    await createSession(c, user.id);
  }
  return ret;
}

/** 6 decimal digits (leading zeros allowed) — AccountActivation code. */
function randomDigits(n: number): string {
  const buf = new Uint32Array(1);
  let out = "";
  for (let i = 0; i < n; i++) {
    // rejection sampling for an unbiased digit, like secrets.choice
    const limit = 2 ** 32 - (2 ** 32 % 10);
    do {
      crypto.getRandomValues(buf);
    } while (buf[0] >= limit);
    out += String(buf[0] % 10);
  }
  return out;
}

/**
 * email_validator `validate_email(check_deliverability=False,
 * allow_smtputf8=False)` approximation: ASCII-only local part; the domain may
 * be internationalized (IDN) — it is IDNA-encoded like email_validator's
 * `idna.encode(uts46=True)` — and the resulting ascii_email is capped at
 * EMAIL_MAX_LENGTH = 254 (email_validator 2.x).
 */
function isValidEmail(email: string): boolean {
  if (!email) return false;
  const parts = email.split("@");
  if (parts.length !== 2) return false;
  const [local, domain] = parts;
  if (!local || local.length > 64) return false;
  if (!/^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$/.test(local)) return false;
  if (local.startsWith(".") || local.endsWith(".") || local.includes(".."))
    return false;
  if (!domain) return false;
  // Any ASCII char outside [A-Za-z0-9.-] can never be a valid domain char,
  // before or after IDNA (and must not reach the URL parser, which would
  // silently truncate on "/", "?", "#", ":", "@").
  let hasNonAscii = false;
  for (const ch of domain) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp > 0x7f) hasNonAscii = true;
    else if (!/[A-Za-z0-9.-]/.test(ch)) return false;
  }
  let asciiDomain = domain;
  if (hasNonAscii) {
    // IDN: domain-to-ASCII via the URL parser (UTS-46, like idna.encode)
    try {
      asciiDomain = new URL(`http://${domain}/`).hostname;
    } catch {
      return false;
    }
  }
  if (!asciiDomain.includes(".")) return false;
  const labels = asciiDomain.split(".");
  for (const label of labels) {
    if (!label || label.length > 63) return false;
    if (!/^[A-Za-z0-9-]+$/.test(label)) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
  }
  if (/^\d+$/.test(labels[labels.length - 1])) return false;
  // len(ascii_email) > 254 → EmailNotValidError("The email address is too long")
  return local.length + 1 + asciiDomain.length <= 254;
}

/**
 * email_can_be_used_as_mailbox(email): syntax + domain checks. The
 * invalid_mailbox_domain / forbidden_mx_ip / MX-record checks are skipped
 * (no table / no DNS here); SLDomain = public_domain, verified custom
 * domains, and disabled-user ownership are enforced.
 */
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

/** User.can_send_or_receive(). */
function canSendOrReceive(user: UserRow): boolean {
  return !user.disabled && user.delete_on === null;
}

/** transactional/code-activation.txt.jinja2 content block. */
function sendActivationEmail(
  env: Env,
  to: string,
  code: string,
): Promise<void> {
  return sendTransactionalEmail(env, {
    to,
    subject: "Just one more step to join SimpleLogin",
    text:
      "Hi,\n\nThank you for choosing SimpleLogin.\n\n" +
      "To get started, please activate your account by entering the following code into the application:\n\n" +
      `${code}\n`,
  });
}

/**
 * send_invalid_totp_login_email(user, "TOTP"): skipped for disabled/deleted
 * users, capped at 1 per 24h per (alert_type, to_email) via sent_alert.
 */
async function sendInvalidTotpLoginEmail(
  env: Env,
  user: UserRow,
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
      "An invalid TOTP code was provided but the email and password were correct.\n\n" +
      "This request has been blocked. However, if this was not you, please change your password immediately.\n" +
      `${env.URL}/dashboard/setting#change_password\n`,
  });
}

// --------------------------------------------------------------------------
// POST /api/auth/login
// --------------------------------------------------------------------------

authRoutes.post(
  "/auth/login",
  rateLimit("auth_login", "10/minute"),
  async (c) => {
    const data = await getJsonBody(c);
    if (!data) return badRequest(c, "request body cannot be empty");

    const password = strField(data, "password");
    const device = deviceField(data);

    const emailInput = data.email;
    if (!emailInput || typeof emailInput !== "string") {
      return badRequest(c, "Email or password incorrect");
    }

    const user = await findUserByEmailInput(c.env.DB, emailInput);

    // dummy bcrypt check runs even when no user exists (timing mitigation)
    const passwordOk = await checkPassword(user?.password ?? null, password);
    if (!user || !passwordOk) {
      return badRequest(c, "Email or password incorrect");
    }
    if (user.disabled) return badRequest(c, "Account disabled");
    if (user.delete_on !== null) {
      return badRequest(c, "Account scheduled for deletion");
    }
    if (!user.activated) return jsonError(c, 422, "Account not activated");
    if (user.fido_uuid !== null && !user.enable_otp) {
      return jsonError(c, 403, "Currently we don't support FIDO on mobile yet");
    }

    return c.json(await authPayload(c, user, device), 200);
  },
);

// --------------------------------------------------------------------------
// POST /api/auth/register
// --------------------------------------------------------------------------

authRoutes.post(
  "/auth/register",
  rateLimit("auth_register", "10/minute"),
  async (c) => {
    const data = await getJsonBody(c);
    if (!data) return badRequest(c, "request body cannot be empty");

    const dirtyEmail = strField(data, "email");
    const email = canonicalizeEmail(dirtyEmail);
    const password = strField(data, "password");
    const db = c.env.DB;

    if (
      c.env.DISABLE_REGISTRATION !== undefined &&
      c.env.DISABLE_REGISTRATION !== ""
    ) {
      return badRequest(c, "registration is closed");
    }
    if (
      !(await emailCanBeUsedAsMailbox(db, email)) ||
      (await personalEmailAlreadyUsed(db, email))
    ) {
      return badRequest(c, `cannot use ${email} as personal inbox`);
    }
    // abuser_lookup ban check skipped: table/MAC_KEY absent in this port.
    const passwordLen = [...password].length; // Python len() = code points
    if (!password || passwordLen < 8)
      return badRequest(c, "password too short");
    if (passwordLen > 100) return badRequest(c, "password too long");

    // User.create(email, name=dirty_email, password=...) and its side effects
    const now = new Date();
    const user = await db
      .prepare(
        `INSERT INTO users (email, name, password, alternative_id, trial_end)
         VALUES (?1, ?2, ?3, ?4, ?5) RETURNING *`,
      )
      .bind(
        sanitizeEmail(email),
        dirtyEmail.slice(0, 100),
        await hashPassword(password),
        crypto.randomUUID(),
        toStr(addHours(addDays(now, 7), 1)),
      )
      .first<UserRow>();
    if (!user) throw new Error("users insert returned no row");

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

    // first (newsletter) alias — Alias.create_new with the user's default
    // word suffix scheme: 1 word + 3 digits on FIRST_ALIAS_DOMAIN
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
      await db
        .prepare(
          "UPDATE users SET newsletter_alias_id = ?1, updated_at = ?2 WHERE id = ?3",
        )
        .bind(alias?.id ?? null, nowStr(), user.id)
        .run();
      break;
    }

    // onboarding jobs (presence flag, not part of the typed Env contract)
    const disableOnboarding =
      (c.env as unknown as Record<string, string | undefined>)
        .DISABLE_ONBOARDING !== undefined;
    if (!disableOnboarding) {
      const payload = JSON.stringify({ user_id: user.id });
      const jobs: [string, number][] = [
        ["onboarding-1", 1],
        ["onboarding-2", 2],
        ["onboarding-4", 3],
      ];
      for (const [name, days] of jobs) {
        await db
          .prepare(
            "INSERT INTO job (name, payload, run_at) VALUES (?1, ?2, ?3)",
          )
          .bind(name, payload, toStr(addDays(now, days)))
          .run();
      }
    }

    const code = randomDigits(6);
    await db
      .prepare("INSERT INTO account_activation (user_id, code) VALUES (?1, ?2)")
      .bind(user.id, code)
      .run();

    await sendActivationEmail(c.env, email, code);

    return c.json({ msg: "User needs to confirm their account" }, 200);
  },
);

// --------------------------------------------------------------------------
// POST /api/auth/activate
// --------------------------------------------------------------------------

authRoutes.post(
  "/auth/activate",
  rateLimit("auth_activate", "10/minute"),
  async (c) => {
    const data = await getJsonBody(c);
    if (!data) return badRequest(c, "request body cannot be empty");
    const db = c.env.DB;

    const user = await findUserByEmailInput(db, strField(data, "email"));
    // same message regardless — no account enumeration
    if (!user || user.activated) return badRequest(c, "Wrong email or code");

    const activation = await db
      .prepare("SELECT * FROM account_activation WHERE user_id = ?1")
      .bind(user.id)
      .first<AccountActivationRow>();
    if (!activation) return badRequest(c, "Wrong email or code");

    // strict compare: a JSON number never matches the stored string
    if (activation.code !== data.code) {
      const tries = activation.tries - 1;
      await db
        .prepare(
          "UPDATE account_activation SET tries = ?1, updated_at = ?2 WHERE id = ?3",
        )
        .bind(tries, nowStr(), activation.id)
        .run();
      if (tries === 0) {
        await db
          .prepare("DELETE FROM account_activation WHERE id = ?1")
          .bind(activation.id)
          .run();
        return jsonError(c, 410, "Too many wrong tries");
      }
      return badRequest(c, "Wrong email or code");
    }

    await db
      .prepare("UPDATE users SET activated = 1, updated_at = ?1 WHERE id = ?2")
      .bind(nowStr(), user.id)
      .run();
    await db
      .prepare("DELETE FROM account_activation WHERE id = ?1")
      .bind(activation.id)
      .run();

    return c.json({ msg: "Account is activated, user can login now" }, 200);
  },
);

// --------------------------------------------------------------------------
// POST /api/auth/reactivate
// --------------------------------------------------------------------------

authRoutes.post(
  "/auth/reactivate",
  rateLimit("auth_reactivate", "10/minute"),
  async (c) => {
    const data = await getJsonBody(c);
    if (!data) return badRequest(c, "request body cannot be empty");
    const db = c.env.DB;

    const emailInput = strField(data, "email");
    const user = await findUserByEmailInput(db, emailInput);
    // enumeration-safe message (deliberately differs from activate's)
    if (!user || user.activated) return badRequest(c, "Something went wrong");
    if (!canSendOrReceive(user)) return badRequest(c, "User is disabled");

    await db
      .prepare("DELETE FROM account_activation WHERE user_id = ?1")
      .bind(user.id)
      .run();

    const code = randomDigits(6);
    await db
      .prepare("INSERT INTO account_activation (user_id, code) VALUES (?1, ?2)")
      .bind(user.id, code)
      .run();

    // sent to the *sanitized* input email (register uses the canonical one)
    await sendActivationEmail(c.env, sanitizeEmail(emailInput), code);

    return c.json({ msg: "User needs to confirm their account" }, 200);
  },
);

// --------------------------------------------------------------------------
// POST /api/auth/facebook + /api/auth/google
// Social auth is not configured in this deployment (no client id/secret) →
// the Flask config gate fails before the body is even parsed.
// --------------------------------------------------------------------------

authRoutes.post(
  "/auth/facebook",
  rateLimit("auth_facebook", "10/minute"),
  (c) => badRequest(c, "invalid login mechanism"),
);

authRoutes.post("/auth/google", rateLimit("auth_google", "10/minute"), (c) =>
  badRequest(c, "invalid login mechanism"),
);

// --------------------------------------------------------------------------
// POST /api/auth/forgot_password
// --------------------------------------------------------------------------

authRoutes.post(
  "/auth/forgot_password",
  rateLimit("auth_forgot_password", "2/minute"),
  async (c) => {
    const data = await getJsonBody(c);
    if (!data?.email || typeof data.email !== "string") {
      return badRequest(c, "request body must contain email");
    }
    const db = c.env.DB;

    const user = await findUserByEmailInput(db, data.email);
    if (user) {
      // send_reset_password_email: the code row is created even for
      // disabled users; only the email itself is skipped.
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
    }

    // constant response — no account enumeration
    return c.json({ ok: true }, 200);
  },
);

// --------------------------------------------------------------------------
// POST /api/auth/mfa
// --------------------------------------------------------------------------

authRoutes.post(
  "/auth/mfa",
  rateLimit("auth_mfa", "10/minute"),
  requestLock("mfa_auth"),
  async (c) => {
    const data = await getJsonBody(c);
    if (!data) return badRequest(c, "request body cannot be empty");
    const db = c.env.DB;
    const device = deviceField(data);

    // int(Signer(FLASK_SECRET).unsign(mfa_key)) — any failure → same 400
    let userId: number | null = null;
    if (typeof data.mfa_key === "string") {
      const value = await itsdangerousUnsign(c.env.FLASK_SECRET, data.mfa_key);
      if (value !== null && /^\s*[+-]?\d+\s*$/.test(value)) {
        userId = Number.parseInt(value, 10);
      }
    }
    if (userId === null) return badRequest(c, "Invalid mfa_key");

    const user = await getUserById(db, userId);
    if (!user) return badRequest(c, "Invalid mfa_key");
    if (!user.enable_otp) {
      return badRequest(
        c,
        "This endpoint should only be used by user who enables MFA",
      );
    }

    // pyotp str()s the token, so a JSON number without leading zeros still
    // verifies; the replay compare is `last_otp == mfa_token` on raw values,
    // which in Python never equates str and int.
    const rawToken = data.mfa_token;
    const token =
      typeof rawToken === "string" ? rawToken : String(rawToken ?? "");
    const lastOtp = typeof rawToken === "string" ? user.last_otp : null;
    const valid =
      user.otp_secret !== null &&
      token !== "" &&
      verifyTotp(user.otp_secret, token, lastOtp);
    if (!valid) {
      await sendInvalidTotpLoginEmail(c.env, user);
      return badRequest(c, "Wrong TOTP Token");
    }

    await db
      .prepare("UPDATE users SET last_otp = ?1, updated_at = ?2 WHERE id = ?3")
      .bind(token, nowStr(), user.id)
      .run();

    const apiKey = await getOrCreateApiKey(db, user.id, device);
    await createSession(c, user.id);

    // NB: only three keys — no mfa_enabled/mfa_key here
    return c.json(
      { name: user.name || "", email: user.email, api_key: apiKey.code },
      200,
    );
  },
);
