/**
 * Integration tests for the /api/auth/* route group (specs/01-auth.md).
 *
 * Rate limits are ACTIVE (DISABLE_RATE_LIMIT unset) and key on the
 * CF-Connecting-IP header, so every test family uses its own IP; 429 tests
 * hammer one fixed IP. bcrypt costs ~0.5-1s per op in workerd, so users are
 * seeded with a precomputed hash instead of hashing per test.
 */

import { env, SELF } from "cloudflare:test";
import { Secret, TOTP } from "otpauth";
import { beforeEach, describe, expect, it } from "vitest";
import { itsdangerousSign } from "../src/lib/crypto";
import { sentEmails } from "../src/lib/mailer";
import type {
  AccountActivationRow,
  AliasRow,
  ApiKeyRow,
  JobRow,
  ResetPasswordCodeRow,
  UserRow,
} from "../src/lib/rows";
import { createUser } from "./fixtures";

const PASSWORD = "s3cr3t-Passw0rd";
// bcrypt.hashSync("s3cr3t-Passw0rd", 12) — precomputed to keep tests fast
const PASSWORD_HASH =
  "$2b$12$IJPBbcbPtYQhZZh1EjwW.OXwZT3pPf5GlVvs3lf38O9/ZjjLZ2KZ2";

const OTP_SECRET = "JBSWY3DPEHPK3PXP";

const API_KEY_RE = /^[a-z]{60}$/;

function postJson(
  path: string,
  body: unknown,
  ip: string,
  extraHeaders: Record<string, string> = {},
): Promise<Response> {
  return SELF.fetch(`https://sl.test${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "CF-Connecting-IP": ip,
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  });
}

/**
 * Authenticated "slapp" web-session cookie for a user — the flask-login
 * session that makes the limiter key by user id instead of IP.
 */
async function webSessionCookie(user: UserRow): Promise<string> {
  const token = crypto.randomUUID();
  await env.KV.put(
    `session:${token}`,
    JSON.stringify({ user_id: user.id, alternative_id: user.alternative_id }),
  );
  return `slapp=${token}`;
}

function totpNow(secret: string): string {
  return new TOTP({
    secret: Secret.fromBase32(secret),
    algorithm: "SHA1",
    digits: 6,
    period: 30,
  }).generate();
}

/** A 6-digit code that is guaranteed not to be currently valid. */
function wrongTotp(secret: string): string {
  return totpNow(secret) === "000000" ? "111111" : "000000";
}

async function mfaKeyFor(userId: number): Promise<string> {
  return itsdangerousSign(env.FLASK_SECRET, String(userId));
}

/**
 * Fixed-window limits reset on real minute boundaries; if one is imminent,
 * wait it out so a hammer sequence can't be split across two windows.
 */
async function avoidMinuteBoundary(marginSecs = 4): Promise<void> {
  const secs = (Date.now() / 1000) % 60;
  if (secs > 60 - marginSecs) {
    await new Promise((r) => setTimeout(r, (60 - secs) * 1000 + 200));
  }
}

async function activationRow(
  userId: number,
): Promise<AccountActivationRow | null> {
  return env.DB.prepare("SELECT * FROM account_activation WHERE user_id = ?1")
    .bind(userId)
    .first<AccountActivationRow>();
}

beforeEach(() => {
  sentEmails.length = 0;
});

// ---------------------------------------------------------------------------
// /api/auth/login
// ---------------------------------------------------------------------------

describe("POST /api/auth/login", () => {
  it("returns the full auth payload and creates an ApiKey for the device", async () => {
    const user = await createUser(env.DB, { password: PASSWORD_HASH });
    const res = await postJson(
      "/api/auth/login",
      { email: user.email, password: PASSWORD, device: "Test Device" },
      "10.0.1.1",
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({
      name: "",
      email: user.email,
      mfa_enabled: false,
      mfa_key: null,
      api_key: expect.stringMatching(API_KEY_RE),
    });
    // ApiKey persisted with the device name, verbatim
    const key = await env.DB.prepare("SELECT * FROM api_key WHERE user_id = ?1")
      .bind(user.id)
      .first<ApiKeyRow>();
    expect(key?.code).toBe(body.api_key);
    expect(key?.name).toBe("Test Device");
    // web session cookie set (login_user equivalent)
    expect(res.headers.get("Set-Cookie") ?? "").toContain("slapp=");
  });

  it("returns the user's name and reuses an existing ApiKey for the same device", async () => {
    const user = await createUser(env.DB, {
      password: PASSWORD_HASH,
      name: "John Wick",
    });
    const code = "a".repeat(60);
    await env.DB.prepare(
      "INSERT INTO api_key (user_id, code, name) VALUES (?1, ?2, ?3)",
    )
      .bind(user.id, code, "phone")
      .run();

    const res = await postJson(
      "/api/auth/login",
      { email: user.email, password: PASSWORD, device: "phone" },
      "10.0.1.2",
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      name: "John Wick",
      email: user.email,
      mfa_enabled: false,
      mfa_key: null,
      api_key: code,
    });
    const n = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM api_key WHERE user_id = ?1",
    )
      .bind(user.id)
      .first<{ n: number }>();
    expect(n?.n).toBe(1);
  });

  it("finds the user via the canonicalized email", async () => {
    await createUser(env.DB, {
      email: "johndoe@gmail.com",
      password: PASSWORD_HASH,
    });
    const res = await postJson(
      "/api/auth/login",
      { email: "John.Doe+work@gmail.com", password: PASSWORD },
      "10.0.1.3",
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.email).toBe("johndoe@gmail.com");
  });

  it("rejects a wrong password", async () => {
    const user = await createUser(env.DB, { password: PASSWORD_HASH });
    const res = await postJson(
      "/api/auth/login",
      { email: user.email, password: "not-the-password" },
      "10.0.1.4",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Email or password incorrect" });
  });

  it("rejects an unknown email with the same message", async () => {
    const res = await postJson(
      "/api/auth/login",
      { email: "ghost@example.com", password: PASSWORD },
      "10.0.1.5",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Email or password incorrect" });
  });

  it("rejects a missing email without hitting bcrypt", async () => {
    const res = await postJson(
      "/api/auth/login",
      { password: PASSWORD },
      "10.0.1.6",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Email or password incorrect" });
  });

  it("400s on an empty JSON object body", async () => {
    const res = await postJson("/api/auth/login", {}, "10.0.1.7");
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "request body cannot be empty",
    });
  });

  it("400s when the body is not JSON", async () => {
    const res = await SELF.fetch("https://sl.test/api/auth/login", {
      method: "POST",
      headers: { "CF-Connecting-IP": "10.0.1.8" },
      body: "email=a@b.c",
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "request body cannot be empty",
    });
  });

  it('400s with "Bad Request" on malformed JSON', async () => {
    const res = await SELF.fetch("https://sl.test/api/auth/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CF-Connecting-IP": "10.0.1.9",
      },
      body: "{not json",
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Bad Request" });
  });

  it("rejects a disabled account", async () => {
    const user = await createUser(env.DB, {
      password: PASSWORD_HASH,
      disabled: 1,
    });
    const res = await postJson(
      "/api/auth/login",
      { email: user.email, password: PASSWORD },
      "10.0.1.10",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Account disabled" });
  });

  it("rejects an account scheduled for deletion", async () => {
    const user = await createUser(env.DB, {
      password: PASSWORD_HASH,
      delete_on: "2030-01-01 00:00:00+00:00",
    });
    const res = await postJson(
      "/api/auth/login",
      { email: user.email, password: PASSWORD },
      "10.0.1.11",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "Account scheduled for deletion",
    });
  });

  it("422s on a non-activated account", async () => {
    const user = await createUser(env.DB, {
      password: PASSWORD_HASH,
      activated: 0,
    });
    const res = await postJson(
      "/api/auth/login",
      { email: user.email, password: PASSWORD },
      "10.0.1.12",
    );
    expect(res.status).toBe(422);
    expect(await res.json()).toEqual({ error: "Account not activated" });
  });

  it("403s on a FIDO-only account", async () => {
    const user = await createUser(env.DB, {
      password: PASSWORD_HASH,
      fido_uuid: "some-fido-uuid",
    });
    const res = await postJson(
      "/api/auth/login",
      { email: user.email, password: PASSWORD },
      "10.0.1.13",
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({
      error: "Currently we don't support FIDO on mobile yet",
    });
  });

  it("returns a signed mfa_key and no api_key when TOTP is enabled", async () => {
    const user = await createUser(env.DB, {
      password: PASSWORD_HASH,
      enable_otp: 1,
      otp_secret: OTP_SECRET,
    });
    const res = await postJson(
      "/api/auth/login",
      { email: user.email, password: PASSWORD, device: "Test Device" },
      "10.0.1.14",
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      name: "",
      email: user.email,
      mfa_enabled: true,
      mfa_key: await mfaKeyFor(user.id),
      api_key: null,
    });
    // no ApiKey creation, no session login on the MFA branch
    const n = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM api_key WHERE user_id = ?1",
    )
      .bind(user.id)
      .first<{ n: number }>();
    expect(n?.n).toBe(0);
    expect(res.headers.get("Set-Cookie")).toBeNull();
  });

  it("429s after 10 requests per minute from one IP", async () => {
    await avoidMinuteBoundary();
    const ip = "10.0.1.100";
    for (let i = 0; i < 10; i++) {
      const res = await postJson("/api/auth/login", { device: "x" }, ip);
      expect(res.status).toBe(400);
    }
    const res = await postJson("/api/auth/login", { device: "x" }, ip);
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });
});

// ---------------------------------------------------------------------------
// /api/auth/register
// ---------------------------------------------------------------------------

describe("POST /api/auth/register", () => {
  it("creates an unactivated user with mailbox, newsletter alias, jobs and activation code", async () => {
    const res = await postJson(
      "/api/auth/register",
      { email: "newuser@example.com", password: "longenough" },
      "10.0.2.1",
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      msg: "User needs to confirm their account",
    });

    const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?1")
      .bind("newuser@example.com")
      .first<UserRow>();
    expect(user).not.toBeNull();
    expect(user?.activated).toBe(0);
    expect(user?.name).toBe("newuser@example.com");
    expect(user?.password).toMatch(/^\$2b\$12\$/);
    expect(user?.alternative_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(user?.trial_end).not.toBeNull();

    // verified default mailbox wired up
    const mailbox = await env.DB.prepare(
      "SELECT * FROM mailbox WHERE user_id = ?1",
    )
      .bind(user?.id)
      .first<{ id: number; email: string; verified: number }>();
    expect(mailbox?.email).toBe("newuser@example.com");
    expect(mailbox?.verified).toBe(1);
    expect(user?.default_mailbox_id).toBe(mailbox?.id);

    // newsletter alias
    const alias = await env.DB.prepare("SELECT * FROM alias WHERE user_id = ?1")
      .bind(user?.id)
      .first<AliasRow>();
    expect(alias?.email).toMatch(
      /^simplelogin-newsletter\..+@sl\.example\.com$/,
    );
    expect(alias?.note).toBe(
      "This is your first alias. It's used to receive SimpleLogin communications like new features announcements, newsletters.",
    );
    expect(user?.newsletter_alias_id).toBe(alias?.id);

    // onboarding jobs
    const jobs = await env.DB.prepare(
      "SELECT * FROM job WHERE payload = ?1 ORDER BY id",
    )
      .bind(JSON.stringify({ user_id: user?.id }))
      .all<JobRow>();
    expect(jobs.results.map((j) => j.name)).toEqual([
      "onboarding-1",
      "onboarding-2",
      "onboarding-4",
    ]);

    // activation code + email
    const activation = user ? await activationRow(user.id) : null;
    expect(activation?.code).toMatch(/^\d{6}$/);
    expect(activation?.tries).toBe(3);
    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].to).toBe("newuser@example.com");
    expect(sentEmails[0].subject).toBe(
      "Just one more step to join SimpleLogin",
    );
    expect(sentEmails[0].text).toContain(activation?.code);
  });

  it("registers under the canonical email but keeps the dirty email as name", async () => {
    const res = await postJson(
      "/api/auth/register",
      { email: "New.User+tag@GMAIL.com", password: "longenough" },
      "10.0.2.2",
    );
    expect(res.status).toBe(200);
    const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?1")
      .bind("newuser@gmail.com")
      .first<UserRow>();
    expect(user).not.toBeNull();
    expect(user?.name).toBe("New.User+tag@GMAIL.com");
    expect(sentEmails[0].to).toBe("newuser@gmail.com");
  });

  it("rejects an already-used email", async () => {
    const user = await createUser(env.DB);
    const res = await postJson(
      "/api/auth/register",
      { email: user.email, password: "longenough" },
      "10.0.2.3",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: `cannot use ${user.email} as personal inbox`,
    });
  });

  it("rejects an invalid email (no @ canonicalizes to empty string)", async () => {
    const res = await postJson(
      "/api/auth/register",
      { email: "not-an-email", password: "longenough" },
      "10.0.2.4",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "cannot use  as personal inbox",
    });
  });

  it("rejects an email whose domain has no dot", async () => {
    const res = await postJson(
      "/api/auth/register",
      { email: "user@nodot", password: "longenough" },
      "10.0.2.5",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "cannot use user@nodot as personal inbox",
    });
  });

  it("rejects an email on a SimpleLogin alias domain", async () => {
    await env.DB.prepare("INSERT INTO public_domain (domain) VALUES (?1)")
      .bind("sl.example.com")
      .run();
    const res = await postJson(
      "/api/auth/register",
      { email: "someone@sl.example.com", password: "longenough" },
      "10.0.2.6",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "cannot use someone@sl.example.com as personal inbox",
    });
  });

  it("rejects a short or missing password", async () => {
    const short = await postJson(
      "/api/auth/register",
      { email: "pwshort@example.com", password: "seven77" },
      "10.0.2.7",
    );
    expect(short.status).toBe(400);
    expect(await short.json()).toEqual({ error: "password too short" });

    const missing = await postJson(
      "/api/auth/register",
      { email: "pwmissing@example.com" },
      "10.0.2.7",
    );
    expect(missing.status).toBe(400);
    expect(await missing.json()).toEqual({ error: "password too short" });
  });

  it("rejects a password over 100 chars", async () => {
    const res = await postJson(
      "/api/auth/register",
      { email: "pwlong@example.com", password: "x".repeat(101) },
      "10.0.2.8",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "password too long" });
  });

  it("accepts an internationalized (IDN) domain like email_validator", async () => {
    // validate_email("user@bücher.example", allow_smtputf8=False) passes:
    // the domain is IDNA-encoded, only the local part must be ASCII
    const res = await postJson(
      "/api/auth/register",
      { email: "user@bücher.example", password: "longenough" },
      "10.0.2.11",
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      msg: "User needs to confirm their account",
    });
    const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?1")
      .bind("user@bücher.example")
      .first<UserRow>();
    expect(user).not.toBeNull();
    expect(sentEmails[0].to).toBe("user@bücher.example");
  });

  it("caps the address length at 254 chars like email_validator (not 320)", async () => {
    const local = "a".repeat(64);
    const ok = `${local}@${"b".repeat(63)}.${"c".repeat(63)}.${"e".repeat(57)}.com`;
    const tooLong = `${local}@${"b".repeat(63)}.${"c".repeat(63)}.${"e".repeat(58)}.com`;
    expect(ok).toHaveLength(254);
    expect(tooLong).toHaveLength(255);

    // 255 chars → EmailNotValidError("The email address is too long") → 400
    const longRes = await postJson(
      "/api/auth/register",
      { email: tooLong, password: "longenough" },
      "10.0.2.12",
    );
    expect(longRes.status).toBe(400);
    expect(await longRes.json()).toEqual({
      error: `cannot use ${tooLong} as personal inbox`,
    });

    // exactly 254 chars is still valid
    const okRes = await postJson(
      "/api/auth/register",
      { email: ok, password: "longenough" },
      "10.0.2.12",
    );
    expect(okRes.status).toBe(200);
    expect(await okRes.json()).toEqual({
      msg: "User needs to confirm their account",
    });
  });

  it("400s when registration is disabled (presence flag, even '0')", async () => {
    const testEnv = env as unknown as Record<string, unknown>;
    testEnv.DISABLE_REGISTRATION = "0";
    try {
      const res = await postJson(
        "/api/auth/register",
        { email: "closed@example.com", password: "longenough" },
        "10.0.2.9",
      );
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "registration is closed" });
    } finally {
      delete testEnv.DISABLE_REGISTRATION;
    }
  });

  it("400s on an empty body", async () => {
    const res = await postJson("/api/auth/register", {}, "10.0.2.10");
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "request body cannot be empty",
    });
  });

  it("429s after 10 requests per minute from one IP", async () => {
    await avoidMinuteBoundary();
    const ip = "10.0.2.100";
    for (let i = 0; i < 10; i++) {
      const res = await postJson(
        "/api/auth/register",
        { email: `rl${i}@example.com`, password: "x" },
        ip,
      );
      expect(res.status).toBe(400);
    }
    const res = await postJson(
      "/api/auth/register",
      { email: "rl10@example.com", password: "x" },
      ip,
    );
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });
});

// ---------------------------------------------------------------------------
// /api/auth/activate
// ---------------------------------------------------------------------------

describe("POST /api/auth/activate", () => {
  async function unactivatedUser(code = "123456"): Promise<UserRow> {
    const user = await createUser(env.DB, { activated: 0 });
    await env.DB.prepare(
      "INSERT INTO account_activation (user_id, code) VALUES (?1, ?2)",
    )
      .bind(user.id, code)
      .run();
    return user;
  }

  it("activates the account with the right code", async () => {
    const user = await unactivatedUser();
    const res = await postJson(
      "/api/auth/activate",
      { email: user.email, code: "123456" },
      "10.0.3.1",
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      msg: "Account is activated, user can login now",
    });
    const after = await env.DB.prepare("SELECT * FROM users WHERE id = ?1")
      .bind(user.id)
      .first<UserRow>();
    expect(after?.activated).toBe(1);
    expect(await activationRow(user.id)).toBeNull();
  });

  it("decrements tries on a wrong code", async () => {
    const user = await unactivatedUser();
    const res = await postJson(
      "/api/auth/activate",
      { email: user.email, code: "999999" },
      "10.0.3.2",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Wrong email or code" });
    expect((await activationRow(user.id))?.tries).toBe(2);
  });

  it("410s and deletes the code after 3 wrong tries", async () => {
    await avoidMinuteBoundary();
    const user = await unactivatedUser();
    for (let i = 0; i < 2; i++) {
      const res = await postJson(
        "/api/auth/activate",
        { email: user.email, code: "999999" },
        "10.0.3.3",
      );
      expect(res.status).toBe(400);
    }
    const res = await postJson(
      "/api/auth/activate",
      { email: user.email, code: "999999" },
      "10.0.3.3",
    );
    expect(res.status).toBe(410);
    expect(await res.json()).toEqual({ error: "Too many wrong tries" });
    expect(await activationRow(user.id)).toBeNull();
  });

  it("never matches a code sent as a JSON number", async () => {
    const user = await unactivatedUser("123456");
    const res = await postJson(
      "/api/auth/activate",
      { email: user.email, code: 123456 },
      "10.0.3.4",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Wrong email or code" });
    expect((await activationRow(user.id))?.tries).toBe(2);
  });

  it("uses the same message for unknown email, activated user and missing code row", async () => {
    const activated = await createUser(env.DB);
    for (const email of ["ghost@example.com", activated.email]) {
      const res = await postJson(
        "/api/auth/activate",
        { email, code: "123456" },
        "10.0.3.5",
      );
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "Wrong email or code" });
    }
    const noRow = await createUser(env.DB, { activated: 0 });
    const res = await postJson(
      "/api/auth/activate",
      { email: noRow.email, code: "123456" },
      "10.0.3.5",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Wrong email or code" });
  });

  it("400s on an empty body", async () => {
    const res = await postJson("/api/auth/activate", {}, "10.0.3.6");
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "request body cannot be empty",
    });
  });

  it("429s after 10 requests per minute from one IP", async () => {
    await avoidMinuteBoundary();
    const ip = "10.0.3.100";
    for (let i = 0; i < 10; i++) {
      const res = await postJson(
        "/api/auth/activate",
        { email: "ghost@example.com", code: "123456" },
        ip,
      );
      expect(res.status).toBe(400);
    }
    const res = await postJson(
      "/api/auth/activate",
      { email: "ghost@example.com", code: "123456" },
      ip,
    );
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });
});

// ---------------------------------------------------------------------------
// /api/auth/reactivate
// ---------------------------------------------------------------------------

describe("POST /api/auth/reactivate", () => {
  it("replaces the activation code and re-sends the email", async () => {
    const user = await createUser(env.DB, { activated: 0 });
    await env.DB.prepare(
      "INSERT INTO account_activation (user_id, code, tries) VALUES (?1, ?2, ?3)",
    )
      .bind(user.id, "000111", 1)
      .run();

    const res = await postJson(
      "/api/auth/reactivate",
      { email: user.email },
      "10.0.4.1",
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      msg: "User needs to confirm their account",
    });

    const activation = await activationRow(user.id);
    expect(activation?.code).toMatch(/^\d{6}$/);
    expect(activation?.tries).toBe(3);

    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].to).toBe(user.email);
    expect(sentEmails[0].subject).toBe(
      "Just one more step to join SimpleLogin",
    );
    expect(sentEmails[0].text).toContain(activation?.code);
  });

  it("uses the enumeration-safe message for unknown or already-activated accounts", async () => {
    const activated = await createUser(env.DB);
    for (const email of ["ghost@example.com", activated.email]) {
      const res = await postJson("/api/auth/reactivate", { email }, "10.0.4.2");
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "Something went wrong" });
    }
  });

  it("rejects a disabled unactivated user", async () => {
    const user = await createUser(env.DB, { activated: 0, disabled: 1 });
    const res = await postJson(
      "/api/auth/reactivate",
      { email: user.email },
      "10.0.4.3",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "User is disabled" });
  });

  it("400s on an empty body", async () => {
    const res = await postJson("/api/auth/reactivate", {}, "10.0.4.4");
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "request body cannot be empty",
    });
  });

  it("429s after 10 requests per minute from one IP", async () => {
    await avoidMinuteBoundary();
    const ip = "10.0.4.100";
    for (let i = 0; i < 10; i++) {
      const res = await postJson(
        "/api/auth/reactivate",
        { email: "ghost@example.com" },
        ip,
      );
      expect(res.status).toBe(400);
    }
    const res = await postJson(
      "/api/auth/reactivate",
      { email: "ghost@example.com" },
      ip,
    );
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });
});

// ---------------------------------------------------------------------------
// /api/auth/facebook + /api/auth/google (not configured here)
// ---------------------------------------------------------------------------

describe("POST /api/auth/facebook and /api/auth/google", () => {
  it("400s before body parsing when the mechanism is not enabled", async () => {
    for (const path of ["/api/auth/facebook", "/api/auth/google"]) {
      // even with no body at all — the config gate runs first
      const res = await SELF.fetch(`https://sl.test${path}`, {
        method: "POST",
        headers: { "CF-Connecting-IP": "10.0.5.1" },
      });
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "invalid login mechanism" });
    }
  });

  it("429s after 10 requests per minute from one IP", async () => {
    await avoidMinuteBoundary();
    const ip = "10.0.5.100";
    for (let i = 0; i < 10; i++) {
      const res = await postJson("/api/auth/google", { google_token: "x" }, ip);
      expect(res.status).toBe(400);
    }
    const res = await postJson("/api/auth/google", { google_token: "x" }, ip);
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });
});

// ---------------------------------------------------------------------------
// /api/auth/forgot_password
// ---------------------------------------------------------------------------

describe("POST /api/auth/forgot_password", () => {
  it("creates a reset code and sends the email", async () => {
    const user = await createUser(env.DB);
    const res = await postJson(
      "/api/auth/forgot_password",
      { email: user.email },
      "10.0.6.1",
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });

    const code = await env.DB.prepare(
      "SELECT * FROM reset_password_code WHERE user_id = ?1",
    )
      .bind(user.id)
      .first<ResetPasswordCodeRow>();
    expect(code?.code).toHaveLength(43); // token_urlsafe(32)
    expect(code?.expired.localeCompare(code.created_at)).toBe(1); // +1h

    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].to).toBe(user.email);
    expect(sentEmails[0].subject).toBe("Reset your password on SimpleLogin");
    expect(sentEmails[0].text).toContain(
      `https://app.sl.example.com/auth/reset_password?code=${code?.code}`,
    );
  });

  it("returns the same 200 for an unknown email, without side effects", async () => {
    const res = await postJson(
      "/api/auth/forgot_password",
      { email: "ghost@example.com" },
      "10.0.6.2",
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    expect(sentEmails).toHaveLength(0);
  });

  it("creates the code but skips the email for a disabled user", async () => {
    const user = await createUser(env.DB, { disabled: 1 });
    const res = await postJson(
      "/api/auth/forgot_password",
      { email: user.email },
      "10.0.6.3",
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
    const code = await env.DB.prepare(
      "SELECT 1 FROM reset_password_code WHERE user_id = ?1",
    )
      .bind(user.id)
      .first();
    expect(code).not.toBeNull();
    expect(sentEmails).toHaveLength(0);
  });

  it("400s when the body has no email", async () => {
    for (const body of [{}, { email: "" }]) {
      const res = await postJson("/api/auth/forgot_password", body, "10.0.6.4");
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({
        error: "request body must contain email",
      });
    }
  });

  it("429s after 2 requests per minute from one IP", async () => {
    await avoidMinuteBoundary();
    const ip = "10.0.6.100";
    for (let i = 0; i < 2; i++) {
      const res = await postJson(
        "/api/auth/forgot_password",
        { email: "ghost@example.com" },
        ip,
      );
      expect(res.status).toBe(200);
    }
    const res = await postJson(
      "/api/auth/forgot_password",
      { email: "ghost@example.com" },
      ip,
    );
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });

  it("keys the rate limit by user id when an authenticated session cookie is sent", async () => {
    // flask-limiter __key_func (app/extensions.py:14-19): userid:{id} when
    // current_user.is_authenticated, else the client IP — cookie-logged-in
    // users behind a shared IP get their own bucket.
    await avoidMinuteBoundary(10);
    const ip = "10.0.6.101";
    const body = { email: "ghost@example.com" };

    // exhaust the anonymous IP bucket (2/minute)
    for (let i = 0; i < 2; i++) {
      expect(
        (await postJson("/api/auth/forgot_password", body, ip)).status,
      ).toBe(200);
    }
    expect((await postJson("/api/auth/forgot_password", body, ip)).status).toBe(
      429,
    );

    // a cookie-authenticated user on the SAME IP has its own bucket
    const userA = await createUser(env.DB);
    const cookieA = await webSessionCookie(userA);
    for (let i = 0; i < 2; i++) {
      const res = await postJson("/api/auth/forgot_password", body, ip, {
        Cookie: cookieA,
      });
      expect(res.status).toBe(200);
    }
    const exhaustedA = await postJson("/api/auth/forgot_password", body, ip, {
      Cookie: cookieA,
    });
    expect(exhaustedA.status).toBe(429);
    expect(await exhaustedA.json()).toEqual({ error: "Rate limit exceeded" });

    // ...and another user on that IP is isolated from both buckets
    const userB = await createUser(env.DB);
    const cookieB = await webSessionCookie(userB);
    const resB = await postJson("/api/auth/forgot_password", body, ip, {
      Cookie: cookieB,
    });
    expect(resB.status).toBe(200);
  });

  it("still keys by IP when the session cookie belongs to a disabled user", async () => {
    // flask-login's user loader returns None for disabled users, so the
    // limiter falls back to the IP key
    await avoidMinuteBoundary(6);
    const ip = "10.0.6.102";
    const disabled = await createUser(env.DB, { disabled: 1 });
    const cookie = await webSessionCookie(disabled);
    const body = { email: "ghost@example.com" };
    for (let i = 0; i < 2; i++) {
      const res = await postJson("/api/auth/forgot_password", body, ip, {
        Cookie: cookie,
      });
      expect(res.status).toBe(200);
    }
    const res = await postJson("/api/auth/forgot_password", body, ip, {
      Cookie: cookie,
    });
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });
});

// ---------------------------------------------------------------------------
// /api/auth/mfa
// ---------------------------------------------------------------------------

describe("POST /api/auth/mfa", () => {
  async function mfaUser(
    overrides: Record<string, unknown> = {},
  ): Promise<UserRow> {
    return createUser(env.DB, {
      enable_otp: 1,
      otp_secret: OTP_SECRET,
      ...overrides,
    });
  }

  it("exchanges a valid mfa_key + TOTP for an api_key", async () => {
    const user = await mfaUser();
    const token = totpNow(OTP_SECRET);
    const res = await postJson(
      "/api/auth/mfa",
      {
        mfa_key: await mfaKeyFor(user.id),
        mfa_token: token,
        device: "Test Device",
      },
      "10.0.7.1",
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toEqual({
      name: "",
      email: user.email,
      api_key: expect.stringMatching(API_KEY_RE),
    });

    const after = await env.DB.prepare("SELECT * FROM users WHERE id = ?1")
      .bind(user.id)
      .first<UserRow>();
    expect(after?.last_otp).toBe(token);

    const key = await env.DB.prepare("SELECT * FROM api_key WHERE user_id = ?1")
      .bind(user.id)
      .first<ApiKeyRow>();
    expect(key?.code).toBe(body.api_key);
    expect(key?.name).toBe("Test Device");
    expect(res.headers.get("Set-Cookie") ?? "").toContain("slapp=");
  });

  it("reuses an existing ApiKey with a NULL name when no device is sent", async () => {
    const user = await mfaUser();
    const code = "b".repeat(60);
    await env.DB.prepare("INSERT INTO api_key (user_id, code) VALUES (?1, ?2)")
      .bind(user.id, code)
      .run();
    const res = await postJson(
      "/api/auth/mfa",
      { mfa_key: await mfaKeyFor(user.id), mfa_token: totpNow(OTP_SECRET) },
      "10.0.7.2",
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.api_key).toBe(code);
  });

  it("400s on a bad or missing mfa_key", async () => {
    for (const body of [
      { mfa_token: "123456" },
      { mfa_key: "1234.notavalidsignature", mfa_token: "123456" },
      { mfa_key: "no-dot-here", mfa_token: "123456" },
    ]) {
      const res = await postJson("/api/auth/mfa", body, "10.0.7.3");
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "Invalid mfa_key" });
    }
  });

  it("400s on a validly-signed mfa_key for a nonexistent user", async () => {
    const res = await postJson(
      "/api/auth/mfa",
      { mfa_key: await mfaKeyFor(999999), mfa_token: "123456" },
      "10.0.7.4",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Invalid mfa_key" });
  });

  it("400s for a user without TOTP enabled", async () => {
    const user = await createUser(env.DB);
    const res = await postJson(
      "/api/auth/mfa",
      { mfa_key: await mfaKeyFor(user.id), mfa_token: "123456" },
      "10.0.7.5",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "This endpoint should only be used by user who enables MFA",
    });
  });

  it("rejects a wrong TOTP token and sends the alert email once per 24h", async () => {
    const user = await mfaUser();
    const wrong = wrongTotp(OTP_SECRET);
    for (let i = 0; i < 2; i++) {
      const res = await postJson(
        "/api/auth/mfa",
        { mfa_key: await mfaKeyFor(user.id), mfa_token: wrong },
        "10.0.7.6",
      );
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "Wrong TOTP Token" });
    }
    // rate-controlled to 1 alert per 24h per (alert_type, to_email)
    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].to).toBe(user.email);
    expect(sentEmails[0].subject).toBe(
      "Unsuccessful attempt to login to your SimpleLogin account",
    );
    const alerts = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM sent_alert WHERE to_email = ?1 AND alert_type = 'invalid_totp_login'",
    )
      .bind(user.email)
      .first<{ n: number }>();
    expect(alerts?.n).toBe(1);
  });

  it("rejects a replayed token (last_otp guard)", async () => {
    const token = totpNow(OTP_SECRET);
    const user = await mfaUser({ last_otp: token });
    const res = await postJson(
      "/api/auth/mfa",
      { mfa_key: await mfaKeyFor(user.id), mfa_token: token },
      "10.0.7.7",
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "Wrong TOTP Token" });
  });

  it("400s on an empty body", async () => {
    const res = await postJson("/api/auth/mfa", {}, "10.0.7.8");
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: "request body cannot be empty",
    });
  });

  it("429s when the mfa_auth request lock is contended", async () => {
    const ip = "10.0.7.9";
    await env.DB.prepare(
      "INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, 1)",
    )
      .bind(`lock:ip:${ip}:mfa_auth`, Math.floor(Date.now() / 1000))
      .run();
    const res = await postJson(
      "/api/auth/mfa",
      { mfa_key: "x", mfa_token: "123456" },
      ip,
    );
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });

  it("keys the mfa_auth lock by user id for cookie-authenticated callers", async () => {
    // parallel_limiter (app/parallel_limiter.py:55-58): the lock name is
    // cl:{current_user.id}:mfa_auth when a session cookie authenticates the
    // caller, cl:{remote_addr}:mfa_auth otherwise
    const user = await mfaUser();
    const cookie = await webSessionCookie(user);
    await env.DB.prepare(
      "INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, 1)",
    )
      .bind(`lock:user:${user.id}:mfa_auth`, Math.floor(Date.now() / 1000))
      .run();

    // the held user lock blocks the cookie-authenticated request...
    const locked = await postJson(
      "/api/auth/mfa",
      { mfa_key: "x", mfa_token: "123456" },
      "10.0.7.10",
      { Cookie: cookie },
    );
    expect(locked.status).toBe(429);
    expect(await locked.json()).toEqual({ error: "Rate limit exceeded" });

    // ...but not an anonymous one from the same IP (keyed by IP instead)
    const anon = await postJson(
      "/api/auth/mfa",
      { mfa_key: "x", mfa_token: "123456" },
      "10.0.7.10",
    );
    expect(anon.status).toBe(400);
    expect(await anon.json()).toEqual({ error: "Invalid mfa_key" });
  });

  it("429s after 10 requests per minute from one IP", async () => {
    await avoidMinuteBoundary();
    const ip = "10.0.7.100";
    for (let i = 0; i < 10; i++) {
      const res = await postJson(
        "/api/auth/mfa",
        { mfa_key: "bad", mfa_token: "123456" },
        ip,
      );
      expect(res.status).toBe(400);
    }
    const res = await postJson(
      "/api/auth/mfa",
      { mfa_key: "bad", mfa_token: "123456" },
      ip,
    );
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "Rate limit exceeded" });
  });
});
