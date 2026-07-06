/**
 * Integration tests for the server-rendered /auth/* pages
 * (specs/web/01-auth-pages.md, src/web/auth-pages.ts).
 *
 * Rate limits are ACTIVE and key on CF-Connecting-IP for anonymous sessions,
 * so every request defaults to a fresh IP; the rate-limit test hammers one
 * fixed IP. bcrypt is slow in workerd — users are seeded with a precomputed
 * hash and heavy tests get explicit timeouts.
 */

import { env, SELF } from "cloudflare:test";
import { Secret, TOTP } from "otpauth";
import { beforeEach, describe, expect, it } from "vitest";
import { timestampSign, tokenUrlsafe } from "../src/lib/crypto";
import { addDays, addHours, addMinutes, toStr } from "../src/lib/dates";
import { sentEmails } from "../src/lib/mailer";
import type { UserRow } from "../src/lib/rows";
import type { SessionData } from "../src/lib/session";
import { hashRecoveryCode, sanitizeNextUrl } from "../src/web/auth-pages";
import { createApiKey, createUser } from "./fixtures";

const BASE = "https://sl.test";
const PASSWORD = "s3cr3t-Passw0rd";
// bcrypt.hashSync("s3cr3t-Passw0rd", 12) — precomputed to keep tests fast
const PASSWORD_HASH =
  "$2b$12$IJPBbcbPtYQhZZh1EjwW.OXwZT3pPf5GlVvs3lf38O9/ZjjLZ2KZ2";
const OTP_SECRET = "JBSWY3DPEHPK3PXP";

let ipSeq = 0;
const freshIp = () => `10.9.${Math.floor(ipSeq / 250)}.${(ipSeq++ % 250) + 1}`;

interface ReqOpts {
  ip?: string;
  cookie?: string;
}

function get(path: string, opts: ReqOpts = {}): Promise<Response> {
  return SELF.fetch(`${BASE}${path}`, {
    redirect: "manual",
    headers: {
      "CF-Connecting-IP": opts.ip ?? freshIp(),
      ...(opts.cookie ? { Cookie: opts.cookie } : {}),
    },
  });
}

function postForm(
  path: string,
  fields: Record<string, string>,
  opts: ReqOpts = {},
): Promise<Response> {
  return SELF.fetch(`${BASE}${path}`, {
    method: "POST",
    redirect: "manual",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "CF-Connecting-IP": opts.ip ?? freshIp(),
      ...(opts.cookie ? { Cookie: opts.cookie } : {}),
    },
    body: new URLSearchParams(fields).toString(),
  });
}

/** First Set-Cookie value ("name=value") for a cookie name, or null. */
function cookieOf(res: Response, name = "slapp"): string | null {
  for (const sc of res.headers.getSetCookie()) {
    if (sc.startsWith(`${name}=`)) return sc.split(";")[0];
  }
  return null;
}

function sessionTokenOf(cookie: string): string {
  return cookie.split("=")[1];
}

async function kvSession(cookie: string): Promise<SessionData | null> {
  const raw = await env.KV.get(`session:${sessionTokenOf(cookie)}`);
  return raw ? (JSON.parse(raw) as SessionData) : null;
}

/** Browser-like bootstrap: GET a form page, keep its anon cookie + CSRF token. */
async function formSession(
  path: string,
): Promise<{ cookie: string; csrf: string; html: string }> {
  const res = await get(path);
  expect(res.status).toBe(200);
  const cookie = cookieOf(res);
  expect(cookie).toBeTruthy();
  const html = await res.text();
  const m = html.match(/name="csrf_token" type="hidden" value="([^"]+)"/);
  expect(m).toBeTruthy();
  if (!m || !cookie) throw new Error("no csrf/cookie on form page");
  return { cookie, csrf: m[1], html };
}

/** Seed a KV session directly (bypasses HTTP) with a known CSRF secret. */
async function makeSession(
  data: Partial<SessionData> = {},
): Promise<{ cookie: string; token: string; csrf: string }> {
  const token = crypto.randomUUID().replaceAll("-", "");
  const csrfSecret = "c".repeat(40);
  await env.KV.put(
    `session:${token}`,
    JSON.stringify({ csrf: csrfSecret, ...data }),
  );
  const csrf = await timestampSign(
    `${env.FLASK_SECRET}wtf-csrf-token`,
    csrfSecret,
  );
  return { cookie: `slapp=${token}`, token, csrf };
}

function totpNow(): string {
  return new TOTP({
    secret: Secret.fromBase32(OTP_SECRET),
    algorithm: "SHA1",
    digits: 6,
    period: 30,
  }).generate();
}

beforeEach(() => {
  sentEmails.length = 0;
});

// ---------------------------------------------------------------------------

describe("sanitize_next_url port", () => {
  const domains = ["app.sl.example.com"];
  it("mirrors the Flask NextUrlSanitizer table", () => {
    expect(sanitizeNextUrl(null, domains)).toBeNull();
    expect(sanitizeNextUrl("", domains)).toBeNull();
    expect(sanitizeNextUrl("/dashboard/setting", domains)).toBe(
      "/dashboard/setting",
    );
    expect(sanitizeNextUrl("/x?y=1#frag", domains)).toBe("/x?y=1");
    expect(sanitizeNextUrl("//evil.com/x", domains)).toBeNull();
    expect(sanitizeNextUrl("https://evil.com/x", domains)).toBeNull();
    expect(
      sanitizeNextUrl("https://app.sl.example.com/dashboard/", domains),
    ).toBe("https://app.sl.example.com/dashboard/");
    expect(sanitizeNextUrl("\\\\evil.com/x", domains)).toBeNull();
    expect(sanitizeNextUrl("javascript:alert(1)", domains)).toBeNull();
  });
});

// ---------------------------------------------------------------------------

describe("GET|POST /auth/login", () => {
  let user: UserRow;
  beforeEach(async () => {
    user = await createUser(env.DB, { password: PASSWORD_HASH });
  });

  it("GET renders the login form with csrf + field names", async () => {
    const { html } = await formSession("/auth/login");
    expect(html).toContain("Welcome back!");
    expect(html).toMatch(/<title>\s*Login\s*\| SimpleLogin\s*<\/title>/);
    expect(html).toMatch(/<input [^>]*name="email"[^>]*type="email"/);
    expect(html).toMatch(/<input [^>]*name="password"[^>]*type="password"/);
    expect(html).not.toContain("Log in with Proton"); // unconfigured
  });

  it("POST happy path rotates the session, sets user_id + sudo_time, redirects to the dashboard", async () => {
    const { cookie, csrf } = await formSession("/auth/login");
    const res = await postForm(
      "/auth/login",
      { csrf_token: csrf, email: user.email, password: PASSWORD },
      { cookie },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    const newCookie = cookieOf(res);
    expect(newCookie).toBeTruthy();
    expect(newCookie).not.toBe(cookie); // token rotation
    const sess = await kvSession(newCookie ?? "");
    expect(sess?.user_id).toBe(user.id);
    expect(sess?.alternative_id).toBe(user.alternative_id);
    expect(sess?.sudo_time).toBeGreaterThan(0);
    // old anon session was deleted
    expect(await kvSession(cookie)).toBeNull();
  }, 20000);

  it("POST honors a sanitized ?next= and drops a hostile one", async () => {
    const s1 = await formSession("/auth/login");
    const ok = await postForm(
      "/auth/login?next=%2Fdashboard%2Fsetting",
      { csrf_token: s1.csrf, email: user.email, password: PASSWORD },
      { cookie: s1.cookie },
    );
    expect(ok.status).toBe(302);
    expect(ok.headers.get("location")).toBe("/dashboard/setting");

    const s2 = await formSession("/auth/login");
    const bad = await postForm(
      `/auth/login?next=${encodeURIComponent("https://evil.com/x")}`,
      { csrf_token: s2.csrf, email: user.email, password: PASSWORD },
      { cookie: s2.cookie },
    );
    expect(bad.status).toBe(302);
    expect(bad.headers.get("location")).toBe("/dashboard/");
  }, 30000);

  it("POST wrong password re-renders 200 with the exact flash", async () => {
    const { cookie, csrf } = await formSession("/auth/login");
    const res = await postForm(
      "/auth/login",
      { csrf_token: csrf, email: user.email, password: "wrong-password" },
      { cookie },
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('toastr.error("Email or password incorrect");');
    expect(html).toContain("Welcome back!"); // form again
    // password field is cleared
    expect(html).not.toContain("wrong-password");
  }, 20000);

  it("POST without csrf token fails silently with a 200 re-render", async () => {
    const { cookie } = await formSession("/auth/login");
    const res = await postForm(
      "/auth/login",
      { email: user.email, password: PASSWORD },
      { cookie },
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Welcome back!");
    // no flash was queued (base.html's inline JS contains an unrelated
    // literal toastr.error call, so match the message)
    expect(html).not.toContain('toastr.error("Email or password incorrect");');
    const sess = await kvSession(cookie);
    expect(sess?.user_id).toBeUndefined();
  });

  it("POST with empty fields shows wtforms required errors", async () => {
    const { cookie, csrf } = await formSession("/auth/login");
    const res = await postForm(
      "/auth/login",
      { csrf_token: csrf, email: "", password: "" },
      { cookie },
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("This field is required.");
  });

  it("POST for a non-activated user flashes + shows the resend link", async () => {
    const unactivated = await createUser(env.DB, {
      password: PASSWORD_HASH,
      activated: 0,
    });
    const { cookie, csrf } = await formSession("/auth/login");
    const res = await postForm(
      "/auth/login",
      { csrf_token: csrf, email: unactivated.email, password: PASSWORD },
      { cookie },
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(
      "Please check your inbox for the activation email. You can also have this email re-sent",
    );
    expect(html).toContain('href="/auth/resend_activation"');
  }, 20000);

  it("POST for a disabled user flashes the disabled message", async () => {
    const disabled = await createUser(env.DB, {
      password: PASSWORD_HASH,
      disabled: 1,
    });
    const { cookie, csrf } = await formSession("/auth/login");
    const res = await postForm(
      "/auth/login",
      { csrf_token: csrf, email: disabled.email, password: PASSWORD },
      { cookie },
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      "Your account is disabled. Please contact SimpleLogin team to re-enable your account.",
    );
  }, 20000);

  it("POST for a TOTP user redirects to the /auth/mfa interstitial without logging in", async () => {
    const otpUser = await createUser(env.DB, {
      password: PASSWORD_HASH,
      enable_otp: 1,
      otp_secret: OTP_SECRET,
    });
    const { cookie, csrf } = await formSession("/auth/login");
    const res = await postForm(
      "/auth/login",
      { csrf_token: csrf, email: otpUser.email, password: PASSWORD },
      { cookie },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/auth/mfa");
    // no rotation on the interstitial: same anon session carries mfa_user_id
    const sess = await kvSession(cookie);
    expect(sess?.user_id).toBeUndefined();
    expect(sess?.extra?.mfa_user_id).toBe(otpUser.id);
  }, 20000);

  it("GET redirects an already-authenticated user to the dashboard", async () => {
    const { cookie } = await makeSession({ user_id: user.id });
    const res = await get("/auth/login", { cookie });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
  });
});

// ---------------------------------------------------------------------------

describe("GET|POST /auth/register", () => {
  it("GET renders the register form", async () => {
    const { html } = await formSession("/auth/register");
    expect(html).toContain("Create new account");
    expect(html).toMatch(/<input [^>]*name="email"/);
    expect(html).toMatch(/<input [^>]*name="password"/);
  });

  it("POST happy path creates user + mailbox + newsletter alias + activation email, renders waiting page", async () => {
    const email = `web-reg-${Date.now()}@example.com`;
    const { cookie, csrf } = await formSession("/auth/register");
    const res = await postForm(
      "/auth/register",
      { csrf_token: csrf, email, password: "longEnough-Passw0rd" },
      { cookie },
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("An email to validate your email is on its way.");

    const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?1")
      .bind(email)
      .first<UserRow>();
    expect(user).toBeTruthy();
    expect(user?.activated).toBe(0);
    expect(user?.default_mailbox_id).toBeTruthy();
    expect(user?.newsletter_alias_id).toBeTruthy();

    const activation = await env.DB.prepare(
      "SELECT * FROM activation_code WHERE user_id = ?1",
    )
      .bind(user?.id)
      .first<{ code: string }>();
    expect(activation?.code).toMatch(/^[a-z]{30}$/);

    const audit = await env.DB.prepare(
      "SELECT action FROM user_audit_log WHERE user_id = ?1",
    )
      .bind(user?.id)
      .first<{ action: string }>();
    expect(audit?.action).toBe("create_user");

    // Alias.create emits an alias_audit_log row for the newsletter alias
    // (app/models.py L1862: action "create", message "New alias created")
    const aliasAudit = await env.DB.prepare(
      "SELECT alias_id, alias_email, action, message FROM alias_audit_log WHERE user_id = ?1",
    )
      .bind(user?.id)
      .first<{
        alias_id: number;
        alias_email: string;
        action: string;
        message: string;
      }>();
    expect(aliasAudit?.action).toBe("create");
    expect(aliasAudit?.message).toBe("New alias created");
    expect(aliasAudit?.alias_id).toBe(user?.newsletter_alias_id);
    const newsletterAlias = await env.DB.prepare(
      "SELECT email FROM alias WHERE id = ?1",
    )
      .bind(user?.newsletter_alias_id)
      .first<{ email: string }>();
    expect(aliasAudit?.alias_email).toBe(newsletterAlias?.email);

    const mail = sentEmails.find(
      (m) => m.subject === "Just one more step to join SimpleLogin",
    );
    expect(mail?.to).toBe(email);
    expect(mail?.text).toContain(`/auth/activate?code=${activation?.code}`);
  }, 20000);

  it("POST with an already-used email flashes `Email ... already used`", async () => {
    const existing = await createUser(env.DB);
    const { cookie, csrf } = await formSession("/auth/register");
    const res = await postForm(
      "/auth/register",
      {
        csrf_token: csrf,
        email: existing.email,
        password: "longEnough-Passw0rd",
      },
      { cookie },
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(`Email ${existing.email} already used`);
  }, 20000);

  it("POST with an email on a blocklisted mailbox domain (parent-suffix match) flashes the personal-inbox error", async () => {
    // invalid_mailbox_domain is an optional table (absent from the D1
    // migrations) — email_can_be_used_as_mailbox must enforce it when present
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS invalid_mailbox_domain (
         id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL UNIQUE)`,
    ).run();
    await env.DB.prepare(
      "INSERT INTO invalid_mailbox_domain (domain) VALUES (?1)",
    )
      .bind("blocked-inbox.test")
      .run();

    // subdomain of the blocklisted domain: is_invalid_mailbox_domain walks
    // parent suffixes (email_utils.py L793)
    const email = "someone@mail.blocked-inbox.test";
    const { cookie, csrf } = await formSession("/auth/register");
    const res = await postForm(
      "/auth/register",
      { csrf_token: csrf, email, password: "longEnough-Passw0rd" },
      { cookie },
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      'toastr.error("You cannot use this email address as your personal inbox.");',
    );
    const user = await env.DB.prepare("SELECT 1 FROM users WHERE email = ?1")
      .bind(email)
      .first();
    expect(user).toBeNull();
  }, 20000);

  it("POST with a short password shows the wtforms Length message", async () => {
    const { cookie, csrf } = await formSession("/auth/register");
    const res = await postForm(
      "/auth/register",
      { csrf_token: csrf, email: "short@example.com", password: "short" },
      { cookie },
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      "Field must be between 8 and 100 characters long.",
    );
  });

  it("redirects an authenticated user away with a warning flash", async () => {
    const user = await createUser(env.DB);
    const { cookie } = await makeSession({ user_id: user.id });
    const res = await get("/auth/register", { cookie });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    const sess = await kvSession(cookie);
    expect(sess?.flashes?.[0]?.message).toBe("You are already logged in");
  });
});

// ---------------------------------------------------------------------------

describe("GET /auth/activate", () => {
  it("unknown code renders the 400 error page", async () => {
    const res = await get("/auth/activate?code=nope");
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Activation code cannot be found");
  });

  it("expired code renders 400 with the resend link", async () => {
    const user = await createUser(env.DB, { activated: 0 });
    await env.DB.prepare(
      "INSERT INTO activation_code (user_id, code, expired) VALUES (?1, ?2, ?3)",
    )
      .bind(
        user.id,
        "expiredcodeexpiredcodeexpired1",
        toStr(addHours(new Date(), -1)),
      )
      .run();
    const res = await get("/auth/activate?code=expiredcodeexpiredcodeexpired1");
    expect(res.status).toBe(400);
    const html = await res.text();
    expect(html).toContain("Activation code was expired");
    expect(html).toContain('href="/auth/resend_activation"');
  });

  it("valid code activates, logs in, sends the welcome email, redirects to the dashboard", async () => {
    const user = await createUser(env.DB, { activated: 0 });
    await env.DB.prepare(
      "INSERT INTO activation_code (user_id, code, expired) VALUES (?1, ?2, ?3)",
    )
      .bind(
        user.id,
        "validcodevalidcodevalidcode123",
        toStr(addHours(new Date(), 1)),
      )
      .run();
    const res = await get("/auth/activate?code=validcodevalidcodevalidcode123");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");

    const row = await env.DB.prepare(
      "SELECT activated FROM users WHERE id = ?1",
    )
      .bind(user.id)
      .first<{ activated: number }>();
    expect(row?.activated).toBe(1);

    const cookie = cookieOf(res);
    const sess = await kvSession(cookie ?? "");
    expect(sess?.user_id).toBe(user.id);
    expect(sess?.sudo_time).toBeUndefined(); // activation grants no sudo
    expect(sess?.flashes?.[0]?.message).toBe("Your account has been activated");

    const gone = await env.DB.prepare(
      "SELECT 1 FROM activation_code WHERE user_id = ?1",
    )
      .bind(user.id)
      .first();
    expect(gone).toBeNull();

    expect(
      sentEmails.find((m) => m.subject === "Welcome to SimpleLogin"),
    ).toBeTruthy();

    const audit = await env.DB.prepare(
      "SELECT 1 FROM user_audit_log WHERE user_id = ?1 AND action = 'activate_user'",
    )
      .bind(user.id)
      .first();
    expect(audit).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------

describe("GET|POST /auth/resend_activation", () => {
  it("unknown email renders 200 with the enumeration-safe warning", async () => {
    const { cookie, csrf } = await formSession("/auth/resend_activation");
    const res = await postForm(
      "/auth/resend_activation",
      { csrf_token: csrf, email: "nobody-here@example.com" },
      { cookie },
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(
      "If this email is registered, an activation email has been sent.",
    );
    expect(html).toContain("Resend activation email"); // same page again
  });

  it("unactivated user gets a fresh activation email + waiting page", async () => {
    const user = await createUser(env.DB, { activated: 0 });
    const { cookie, csrf } = await formSession("/auth/resend_activation");
    const res = await postForm(
      "/auth/resend_activation",
      { csrf_token: csrf, email: user.email },
      { cookie },
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      "An email to validate your email is on its way.",
    );
    expect(
      sentEmails.find(
        (m) =>
          m.subject === "Just one more step to join SimpleLogin" &&
          m.to === user.email,
      ),
    ).toBeTruthy();
  });

  it("already-activated user is redirected to login", async () => {
    const user = await createUser(env.DB); // activated
    const { cookie, csrf } = await formSession("/auth/resend_activation");
    const res = await postForm(
      "/auth/resend_activation",
      { csrf_token: csrf, email: user.email },
      { cookie },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/auth/login");
    const sess = await kvSession(cookie);
    expect(sess?.flashes?.[0]?.message).toBe(
      "Your account was already activated, please login",
    );
  });
});

// ---------------------------------------------------------------------------

describe("GET|POST /auth/forgot_password", () => {
  it("valid POST always flashes success and creates a reset code for known users", async () => {
    const user = await createUser(env.DB);
    const { cookie, csrf } = await formSession("/auth/forgot_password");
    const res = await postForm(
      "/auth/forgot_password",
      { csrf_token: csrf, email: user.email },
      { cookie },
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      "If your email is correct, you are going to receive an email to reset your password",
    );
    const code = await env.DB.prepare(
      "SELECT code FROM reset_password_code WHERE user_id = ?1",
    )
      .bind(user.id)
      .first<{ code: string }>();
    expect(code).toBeTruthy();
    const mail = sentEmails.find(
      (m) => m.subject === "Reset your password on SimpleLogin",
    );
    expect(mail?.text).toContain(`/auth/reset_password?code=${code?.code}`);
  });

  it("unknown email flashes the same message and creates nothing", async () => {
    const { cookie, csrf } = await formSession("/auth/forgot_password");
    const res = await postForm(
      "/auth/forgot_password",
      { csrf_token: csrf, email: "ghost@example.com" },
      { cookie },
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      "If your email is correct, you are going to receive an email to reset your password",
    );
    expect(sentEmails.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------

describe("GET|POST /auth/reset_password", () => {
  async function makeResetCode(userId: number, expiredIn = 1): Promise<string> {
    const code = tokenUrlsafe(32);
    await env.DB.prepare(
      "INSERT INTO reset_password_code (user_id, code, expired) VALUES (?1, ?2, ?3)",
    )
      .bind(userId, code, toStr(addHours(new Date(), expiredIn)))
      .run();
    return code;
  }

  it("unknown code shows the single-use error (200, not 4xx)", async () => {
    const res = await get("/auth/reset_password?code=unknown");
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      "The reset password link can be used only once. Please request a new link to reset password.",
    );
  });

  it("expired code shows the expired error", async () => {
    const user = await createUser(env.DB, { password: PASSWORD_HASH });
    const code = await makeResetCode(user.id, -1);
    const res = await get(`/auth/reset_password?code=${code}`);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      "The link has been already expired. Please make a new request of the reset password link",
    );
  });

  it("POST reusing the old password is rejected", async () => {
    const user = await createUser(env.DB, { password: PASSWORD_HASH });
    const code = await makeResetCode(user.id);
    const page = await formSession(`/auth/reset_password?code=${code}`);
    const res = await postForm(
      `/auth/reset_password?code=${code}`,
      { csrf_token: page.csrf, password: PASSWORD },
      { cookie: page.cookie },
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("You cannot reuse the same password");
  }, 20000);

  it("POST happy path sets the password, rotates alternative_id, purges codes, logs in", async () => {
    const user = await createUser(env.DB, { password: PASSWORD_HASH });
    const code = await makeResetCode(user.id);
    const page = await formSession(`/auth/reset_password?code=${code}`);
    const res = await postForm(
      `/auth/reset_password?code=${code}`,
      { csrf_token: page.csrf, password: "brand-new-Passw0rd" },
      { cookie: page.cookie },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");

    const row = await env.DB.prepare(
      "SELECT password, alternative_id, activated FROM users WHERE id = ?1",
    )
      .bind(user.id)
      .first<{ password: string; alternative_id: string; activated: number }>();
    expect(row?.password).not.toBe(PASSWORD_HASH);
    expect(row?.alternative_id).not.toBe(user.alternative_id);
    expect(row?.activated).toBe(1);

    const remaining = await env.DB.prepare(
      "SELECT 1 FROM reset_password_code WHERE user_id = ?1",
    )
      .bind(user.id)
      .first();
    expect(remaining).toBeNull();

    const newCookie = cookieOf(res);
    const sess = await kvSession(newCookie ?? "");
    expect(sess?.user_id).toBe(user.id);
    expect(sess?.alternative_id).toBe(row?.alternative_id);
    expect(sess?.flashes?.[0]?.message).toBe("Your new password has been set");

    const audit = await env.DB.prepare(
      "SELECT 1 FROM user_audit_log WHERE user_id = ?1 AND action = 'reset_password'",
    )
      .bind(user.id)
      .first();
    expect(audit).toBeTruthy();
  }, 30000);
});

// ---------------------------------------------------------------------------

describe("GET /auth/change_email", () => {
  async function makeEmailChange(
    userId: number,
    newEmail: string,
    expiredIn = 12,
  ): Promise<string> {
    const code = tokenUrlsafe(32);
    await env.DB.prepare(
      "INSERT INTO email_change (user_id, new_email, code, expired) VALUES (?1, ?2, ?3, ?4)",
    )
      .bind(userId, newEmail, code, toStr(addHours(new Date(), expiredIn)))
      .run();
    return code;
  }

  it("invalid code renders the static failure page", async () => {
    const res = await get("/auth/change_email?code=bogus");
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Incorrect or expired link.");
  });

  it("expired code deletes the row and renders the failure page", async () => {
    const user = await createUser(env.DB);
    const code = await makeEmailChange(
      user.id,
      `new-${user.id}@example.com`,
      -1,
    );
    const res = await get(`/auth/change_email?code=${code}`);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("Incorrect or expired link.");
    const row = await env.DB.prepare(
      "SELECT 1 FROM email_change WHERE code = ?1",
    )
      .bind(code)
      .first();
    expect(row).toBeNull();
  });

  it("valid code updates the email, purges reset codes, redirects to login", async () => {
    const user = await createUser(env.DB);
    const newEmail = `changed-${user.id}@example.com`;
    const code = await makeEmailChange(user.id, newEmail);
    await env.DB.prepare(
      "INSERT INTO reset_password_code (user_id, code, expired) VALUES (?1, ?2, ?3)",
    )
      .bind(user.id, tokenUrlsafe(32), toStr(addHours(new Date(), 1)))
      .run();

    const res = await get(`/auth/change_email?code=${code}`);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/auth/login");

    const row = await env.DB.prepare("SELECT email FROM users WHERE id = ?1")
      .bind(user.id)
      .first<{ email: string }>();
    expect(row?.email).toBe(newEmail);
    const reset = await env.DB.prepare(
      "SELECT 1 FROM reset_password_code WHERE user_id = ?1",
    )
      .bind(user.id)
      .first();
    expect(reset).toBeNull();

    const cookie = cookieOf(res);
    const sess = await kvSession(cookie ?? "");
    expect(sess?.flashes?.[0]?.message).toBe("Your new email has been updated");
  });

  it("is rate limited at 3/hour per IP with the HTML 429 page", async () => {
    const ip = freshIp();
    for (let i = 0; i < 3; i++) {
      const res = await get("/auth/change_email?code=whatever", { ip });
      expect(res.status).toBe(200);
    }
    const blocked = await get("/auth/change_email?code=whatever", { ip });
    expect(blocked.status).toBe(429);
    expect(await blocked.text()).toContain("Whoa, slow down there, pardner!");
  });
});

// ---------------------------------------------------------------------------

describe("GET|POST /auth/mfa", () => {
  let otpUser: UserRow;
  beforeEach(async () => {
    otpUser = await createUser(env.DB, {
      password: PASSWORD_HASH,
      enable_otp: 1,
      otp_secret: OTP_SECRET,
    });
  });

  it("without the interstitial state redirects to login with a warning", async () => {
    const { cookie } = await makeSession({});
    const res = await get("/auth/mfa", { cookie });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/auth/login");
    const sess = await kvSession(cookie);
    expect(sess?.flashes?.[0]?.message).toBe(
      "Unknown error, redirect back to main page",
    );
  });

  it("redirects to login when the user has no OTP enabled", async () => {
    const plain = await createUser(env.DB);
    const { cookie } = await makeSession({ extra: { mfa_user_id: plain.id } });
    const res = await get("/auth/mfa", { cookie });
    expect(res.status).toBe(302);
    const sess = await kvSession(cookie);
    expect(sess?.flashes?.[0]?.message).toBe(
      "Only user with MFA enabled should go to this page",
    );
  });

  it("redirects to login with the MFA warning when mfa_user_id points at a deleted user", async () => {
    // Flask mfa.py L48: `if not (user and user.enable_otp)` — None-safe
    const { cookie } = await makeSession({ extra: { mfa_user_id: 424242 } });
    const res = await get("/auth/mfa", { cookie });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/auth/login");
    const sess = await kvSession(cookie);
    expect(sess?.flashes?.[0]).toEqual({
      category: "warning",
      message: "Only user with MFA enabled should go to this page",
    });
  });

  it("GET renders the token form", async () => {
    const { cookie } = await makeSession({
      extra: { mfa_user_id: otpUser.id },
    });
    const res = await get("/auth/mfa", { cookie });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Two Factor Authentication");
    expect(html).toMatch(/<input [^>]*name="token"/);
    expect(html).toContain("Remember this browser for 30 days");
  });

  it("POST with the current TOTP logs in (no sudo), remembers the browser", async () => {
    const { cookie, csrf } = await makeSession({
      extra: { mfa_user_id: otpUser.id },
    });
    const res = await postForm(
      "/auth/mfa",
      { csrf_token: csrf, token: totpNow(), remember: "y" },
      { cookie },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");

    const newCookie = cookieOf(res);
    expect(newCookie).not.toBe(cookie);
    const sess = await kvSession(newCookie ?? "");
    expect(sess?.user_id).toBe(otpUser.id);
    expect(sess?.sudo_time).toBeUndefined(); // TOTP does NOT grant sudo
    expect(sess?.extra?.mfa_user_id).toBeUndefined();

    const mfaCookie = cookieOf(res, "mfa");
    expect(mfaCookie).toBeTruthy();
    const browser = await env.DB.prepare(
      "SELECT token FROM mfa_browser WHERE user_id = ?1",
    )
      .bind(otpUser.id)
      .first<{ token: string }>();
    expect(mfaCookie).toBe(`mfa=${browser?.token}`);

    const row = await env.DB.prepare("SELECT last_otp FROM users WHERE id = ?1")
      .bind(otpUser.id)
      .first<{ last_otp: string }>();
    expect(row?.last_otp).toBeTruthy();
  });

  it("POST with a wrong token flashes, stays, and sends the alert email", async () => {
    const { cookie, csrf } = await makeSession({
      extra: { mfa_user_id: otpUser.id },
    });
    const res = await postForm(
      "/auth/mfa",
      { csrf_token: csrf, token: "000000" },
      { cookie },
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('toastr.warning("Incorrect token");');
    const alert = sentEmails.find(
      (m) =>
        m.subject ===
        "Unsuccessful attempt to login to your SimpleLogin account",
    );
    expect(alert).toBeTruthy();
    // send_invalid_totp_login_email(user, "TOTP") (mfa.py L105)
    expect(alert?.text).toContain(
      "An invalid TOTP code was provided but the email and password were correct.",
    );
  });

  it("device-cookie fast path logs straight in", async () => {
    const token = "d".repeat(64);
    await env.DB.prepare(
      "INSERT INTO mfa_browser (user_id, token, expires) VALUES (?1, ?2, ?3)",
    )
      .bind(otpUser.id, token, toStr(addDays(new Date(), 30)))
      .run();
    const { cookie } = await makeSession({
      extra: { mfa_user_id: otpUser.id },
    });
    const res = await get("/auth/mfa", { cookie: `${cookie}; mfa=${token}` });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    const sess = await kvSession(cookieOf(res) ?? "");
    expect(sess?.user_id).toBe(otpUser.id);
    // gotcha parity: mfa_user_id survives the fast path
    expect(sess?.extra?.mfa_user_id).toBe(otpUser.id);
  });
});

// ---------------------------------------------------------------------------

describe("GET|POST /auth/recovery", () => {
  const RAW_CODE = "my-recovery-code";
  let otpUser: UserRow;

  async function seedRecoveryCode(userId: number, used = 0): Promise<void> {
    const hashed = await hashRecoveryCode(env.FLASK_SECRET, RAW_CODE);
    await env.DB.prepare(
      "INSERT INTO recovery_code (user_id, code, used) VALUES (?1, ?2, ?3)",
    )
      .bind(userId, hashed, used)
      .run();
  }

  beforeEach(async () => {
    otpUser = await createUser(env.DB, {
      enable_otp: 1,
      otp_secret: OTP_SECRET,
    });
  });

  it("valid unused code logs in and marks the code used", async () => {
    await seedRecoveryCode(otpUser.id);
    const { cookie, csrf } = await makeSession({
      extra: { mfa_user_id: otpUser.id },
    });
    const res = await postForm(
      "/auth/recovery",
      { csrf_token: csrf, code: RAW_CODE },
      { cookie },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/");
    const sess = await kvSession(cookieOf(res) ?? "");
    expect(sess?.user_id).toBe(otpUser.id);
    expect(sess?.sudo_time).toBeUndefined();
    const row = await env.DB.prepare(
      "SELECT used, used_at FROM recovery_code WHERE user_id = ?1",
    )
      .bind(otpUser.id)
      .first<{ used: number; used_at: string | null }>();
    expect(row?.used).toBe(1);
    expect(row?.used_at).toBeTruthy();
  });

  it("used code flashes `Code already used`", async () => {
    await seedRecoveryCode(otpUser.id, 1);
    const { cookie, csrf } = await makeSession({
      extra: { mfa_user_id: otpUser.id },
    });
    const res = await postForm(
      "/auth/recovery",
      { csrf_token: csrf, code: RAW_CODE },
      { cookie },
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('toastr.error("Code already used");');
  });

  it("wrong code flashes `Incorrect code` and sends the alert email", async () => {
    await seedRecoveryCode(otpUser.id);
    const { cookie, csrf } = await makeSession({
      extra: { mfa_user_id: otpUser.id },
    });
    const res = await postForm(
      "/auth/recovery",
      { csrf_token: csrf, code: "not-the-code" },
      { cookie },
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('toastr.error("Incorrect code");');
    const alert = sentEmails.find(
      (m) =>
        m.subject ===
        "Unsuccessful attempt to login to your SimpleLogin account",
    );
    expect(alert).toBeTruthy();
    // send_invalid_totp_login_email(user, "recovery") (recovery.py L76)
    expect(alert?.text).toContain(
      "An invalid recovery code was provided but the email and password were correct.",
    );
  });

  it("renders the 500 page when mfa_user_id points at a deleted user (Flask raises here)", async () => {
    // recovery.py L37 calls user.two_factor_authentication_enabled() on the
    // None user -> unhandled exception, unlike the None-safe /mfa and /fido
    const { cookie } = await makeSession({ extra: { mfa_user_id: 424242 } });
    const res = await get("/auth/recovery", { cookie });
    expect(res.status).toBe(500);
  });
});

// ---------------------------------------------------------------------------

describe("GET /auth/logout", () => {
  it("purges the session, flashes on the fresh one, clears mfa/dark-mode cookies", async () => {
    const user = await createUser(env.DB);
    const { cookie, token } = await makeSession({ user_id: user.id });
    const res = await get("/auth/logout", { cookie });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/auth/login");

    // old KV session gone
    expect(await env.KV.get(`session:${token}`)).toBeNull();

    const newCookie = cookieOf(res);
    expect(newCookie).toBeTruthy();
    expect(newCookie).not.toBe(cookie);
    const setCookies = res.headers.getSetCookie().join("\n");
    expect(setCookies).toContain("mfa=;");
    expect(setCookies).toContain("dark-mode=;");

    // the flash survives onto the login page
    const login = await get("/auth/login", { cookie: newCookie ?? "" });
    expect(await login.text()).toContain(
      'toastr.success("You are logged out");',
    );
  });
});

// ---------------------------------------------------------------------------

describe("GET /auth/api_to_cookie", () => {
  it("missing token flashes + redirects to login", async () => {
    const res = await get("/auth/api_to_cookie");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/auth/login");
    const sess = await kvSession(cookieOf(res) ?? "");
    expect(sess?.flashes?.[0]?.message).toBe("Missing token");
  });

  it("valid token logs in WITHOUT rotating the session and deletes the token", async () => {
    const user = await createUser(env.DB);
    const apiKey = await createApiKey(env.DB, user.id);
    const code = tokenUrlsafe(32);
    await env.DB.prepare(
      "INSERT INTO api_cookie_token (code, user_id, api_key_id) VALUES (?1, ?2, ?3)",
    )
      .bind(code, user.id, apiKey.id)
      .run();

    const { cookie, token } = await makeSession({});
    const res = await get(
      `/auth/api_to_cookie?token=${encodeURIComponent(code)}&next=%2Fdashboard%2Fsetting`,
      { cookie },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/dashboard/setting");
    // gotcha parity: same token, no rotation
    expect(cookieOf(res)).toBeNull();
    const sess = JSON.parse(
      (await env.KV.get(`session:${token}`)) ?? "{}",
    ) as SessionData;
    expect(sess.user_id).toBe(user.id);
    expect(sess.sudo_time).toBeUndefined();

    const gone = await env.DB.prepare(
      "SELECT 1 FROM api_cookie_token WHERE code = ?1",
    )
      .bind(code)
      .first();
    expect(gone).toBeNull();
  });

  it("token older than 5 minutes is rejected with the same flash", async () => {
    const user = await createUser(env.DB);
    const apiKey = await createApiKey(env.DB, user.id);
    const code = tokenUrlsafe(32);
    await env.DB.prepare(
      "INSERT INTO api_cookie_token (code, user_id, api_key_id, created_at) VALUES (?1, ?2, ?3, ?4)",
    )
      .bind(code, user.id, apiKey.id, toStr(addMinutes(new Date(), -6)))
      .run();
    const res = await get(
      `/auth/api_to_cookie?token=${encodeURIComponent(code)}`,
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/auth/login");
    const sess = await kvSession(cookieOf(res) ?? "");
    expect(sess?.flashes?.[0]?.message).toBe("Missing token");
  });
});

// ---------------------------------------------------------------------------

describe("GET|POST /auth/fido (WebAuthn deferred)", () => {
  let fidoUser: UserRow;
  beforeEach(async () => {
    fidoUser = await createUser(env.DB, {
      fido_uuid: crypto.randomUUID(),
    });
    await env.DB.prepare(
      `INSERT INTO fido (credential_id, uuid, public_key, sign_count, name, user_id, transports)
       VALUES (?1, ?2, ?3, 0, 'key1', ?4, ?5)`,
    )
      .bind(
        `cred-${fidoUser.id}`,
        fidoUser.fido_uuid,
        `pk-${fidoUser.id}`,
        fidoUser.id,
        JSON.stringify(["usb", "nfc"]),
      )
      .run();
  });

  it("guards: non-FIDO user is bounced to login with the security-key warning", async () => {
    const plain = await createUser(env.DB);
    const { cookie } = await makeSession({ extra: { mfa_user_id: plain.id } });
    const res = await get("/auth/fido", { cookie });
    expect(res.status).toBe(302);
    const sess = await kvSession(cookie);
    expect(sess?.flashes?.[0]?.message).toBe(
      "Only user with security key linked should go to this page",
    );
  });

  it("guards: deleted user behind mfa_user_id is bounced to login, not a 500", async () => {
    // Flask fido.py L53: `if not (user and user.fido_enabled())` — None-safe
    const { cookie } = await makeSession({ extra: { mfa_user_id: 424242 } });
    const res = await get("/auth/fido", { cookie });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/auth/login");
    const sess = await kvSession(cookie);
    expect(sess?.flashes?.[0]).toEqual({
      category: "warning",
      message: "Only user with security key linked should go to this page",
    });
  });

  it("GET renders the page shell and stores a challenge in the session", async () => {
    const { cookie } = await makeSession({
      extra: { mfa_user_id: fidoUser.id },
    });
    const res = await get("/auth/fido", { cookie });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("security key (WebAuthn)");
    expect(html).toMatch(/<input [^>]*name="sk_assertion"[^>]*type="hidden"/);
    expect(html).toContain(`cred-${fidoUser.id}`);
    const sess = await kvSession(cookie);
    expect(typeof sess?.extra?.fido_challenge).toBe("string");
  });

  it("POST with unparsable assertion redirects to login with the Invalid Payload warning", async () => {
    const { cookie, csrf } = await makeSession({
      extra: { mfa_user_id: fidoUser.id },
    });
    const res = await postForm(
      "/auth/fido",
      { csrf_token: csrf, sk_assertion: "not-json" },
      { cookie },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/auth/login");
    const sess = await kvSession(cookie);
    expect(sess?.flashes?.[0]?.message).toBe(
      "Key verification failed. Error: Invalid Payload",
    );
  });

  it("POST with a JSON assertion fails verification (deferred stub) and re-renders", async () => {
    const { cookie, csrf } = await makeSession({
      extra: { mfa_user_id: fidoUser.id },
    });
    const res = await postForm(
      "/auth/fido",
      { csrf_token: csrf, sk_assertion: '{"id":"x"}' },
      { cookie },
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      'toastr.warning("Key verification failed.");',
    );
    // still anonymous
    const sess = await kvSession(cookie);
    expect(sess?.user_id).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------

describe("GET /auth/social + OAuth config gates", () => {
  it("renders the deprecated social page", async () => {
    const res = await get("/auth/social");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Social login");
    expect(html).toContain("deprecated");
    expect(html).not.toContain("Sign in with GitHub"); // unconfigured
  });

  it.each([
    "/auth/github/login",
    "/auth/github/callback",
    "/auth/google/login",
    "/auth/google/callback",
    "/auth/facebook/login",
    "/auth/facebook/callback",
    "/auth/proton/login",
    "/auth/proton/callback",
    "/auth/oidc/login",
    "/auth/oidc/callback",
  ])("%s redirects to login when the provider is unconfigured", async (path) => {
    const res = await get(path);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/auth/login");
  });
});
