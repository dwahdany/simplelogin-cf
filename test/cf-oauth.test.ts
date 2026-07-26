/**
 * "Connect your Cloudflare account" OAuth flow: src/lib/cfoauth.ts +
 * src/web/cloudflare-pages.ts.
 *
 * The Cloudflare OAuth endpoints (dash.cloudflare.com) AND the token-proof
 * call (api.cloudflare.com/client/v4/accounts) are faked through the single
 * setCfOauthFetch seam — tests share the SELF isolate, so a module-level
 * seam reaches the worker under test. It is installed in beforeEach and torn
 * down in afterAll because vitest.config.ts runs singleWorker (one module
 * graph for ALL test files: leaving the seam in place would break real fetch
 * for every later file), exactly like test/domain-provision.test.ts.
 *
 * CF_OAUTH_CLIENT_ID/SECRET are secrets, absent from the vitest bindings, so
 * the feature is OFF by default; the tests set them and restore "" after.
 */

import { env, SELF } from "cloudflare:test";
import { Hono } from "hono";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  buildAuthorizeUrl,
  CF_API_ACCOUNTS_URL,
  CF_API_ZONES_URL,
  CF_OAUTH_AUTHORIZE_URL,
  CF_OAUTH_REVOKE_URL,
  CF_OAUTH_TOKEN_URL,
  computeCodeChallenge,
  decryptSecretValue,
  encryptSecretValue,
  FALLBACK_EXPIRES_IN_SECS,
  getGrant,
  getValidAccessToken,
  saveGrant,
  setCfOauthFetch,
} from "../src/lib/cfoauth";
import { addSeconds, toStr } from "../src/lib/dates";
import type { Env } from "../src/lib/env";
import { createSession } from "../src/lib/session";
import { csrfTokenField, generateCsrfToken } from "../src/lib/web/forms";
import { renderTemplate } from "../src/lib/web/templates";
import type { WebEnv } from "../src/lib/web/webauth";
import {
  cfOauthPageStatus,
  DEFAULT_CF_OAUTH_SCOPES,
} from "../src/web/cloudflare-pages";
import { createUser } from "./fixtures";

const BASE = "http://example.com";
const CLIENT_ID = "cf-client-id";
// Deliberately contains characters the RFC 6749 §2.3.1 form-encoding must
// escape before base64 (/, +, space).
const CLIENT_SECRET = "s3cr3t/+ x";
const REDIRECT_URI = "https://app.sl.example.com/dashboard/cloudflare/callback";
const DOMAINS_PAGE = "/dashboard/custom_domain";

// ---------------------------------------------------------------------------
// fake OAuth provider + Cloudflare v4 /accounts
// ---------------------------------------------------------------------------

interface FakeCall {
  method: string;
  url: string;
  form: Record<string, string>;
  auth: string | null;
}

class FakeCfOauth {
  calls: FakeCall[] = [];
  tokenStatus = 200;
  tokenBody: unknown = {
    access_token: "at-1",
    refresh_token: "rt-1",
    expires_in: 3600,
    scope: "account.read zone.read",
    token_type: "bearer",
  };
  accountsStatus = 200;
  accountsBody: unknown = {
    success: true,
    errors: [],
    result: [{ id: "acc-1", name: "you@example.com" }],
  };
  /**
   * The liveness probe is GET /zones (zone.read), NOT /accounts: the live
   * authorize endpoint refuses `account.read` for this deployment's client,
   * so the flow cannot request it and /accounts is best-effort only.
   */
  zonesStatus = 200;
  zonesBody: unknown = { success: true, errors: [], result: [] };
  revokeStatus = 200;

  callsTo(url: string): FakeCall[] {
    return this.calls.filter((c) => c.url.startsWith(url));
  }

  fetch = async (input: string, init?: RequestInit): Promise<Response> => {
    const method = init?.method ?? "GET";
    const headers = new Headers((init?.headers ?? {}) as HeadersInit);
    const raw = typeof init?.body === "string" ? init.body : "";
    const form = Object.fromEntries(new URLSearchParams(raw));
    this.calls.push({
      method,
      url: input,
      form,
      auth: headers.get("authorization"),
    });

    if (input === CF_OAUTH_TOKEN_URL) {
      return Response.json(this.tokenBody, { status: this.tokenStatus });
    }
    if (input === CF_OAUTH_REVOKE_URL) {
      return new Response("", { status: this.revokeStatus });
    }
    if (input.startsWith(CF_API_ACCOUNTS_URL)) {
      return Response.json(this.accountsBody, { status: this.accountsStatus });
    }
    if (input.startsWith(CF_API_ZONES_URL)) {
      return Response.json(this.zonesBody, { status: this.zonesStatus });
    }
    return Response.json({ success: false, errors: [] }, { status: 404 });
  };
}

let fake = new FakeCfOauth();

const envx = env as unknown as Record<string, string | undefined>;
const envt = env as unknown as Env;

beforeEach(() => {
  fake = new FakeCfOauth();
  setCfOauthFetch((input, init) => fake.fetch(input, init));
  envx.CF_OAUTH_CLIENT_ID = CLIENT_ID;
  envx.CF_OAUTH_CLIENT_SECRET = CLIENT_SECRET;
  envx.CF_OAUTH_SCOPES = "";
});

afterEach(() => {
  envx.CF_OAUTH_CLIENT_ID = "";
  envx.CF_OAUTH_CLIENT_SECRET = "";
  envx.CF_OAUTH_SCOPES = "";
  envx.CF_ACCOUNT_ID = "";
});

afterAll(() => {
  setCfOauthFetch(null);
});

// ---------------------------------------------------------------------------
// HTTP + session helpers (as in test/domain-provision.test.ts)
// ---------------------------------------------------------------------------

/**
 * Both state-changing routes are sudo-gated (like /api_key), so sessions are
 * created sudo-fresh by default; `{ sudo: false }` exercises the gate.
 */
async function sessionCookieFor(
  userId: number,
  opts: { sudo?: boolean } = {},
): Promise<string> {
  const helper = new Hono<WebEnv>();
  helper.get("/mk", async (c) => {
    await createSession(
      c,
      userId,
      opts.sudo === false ? {} : { sudo_time: Math.floor(Date.now() / 1000) },
    );
    return c.text("ok");
  });
  const res = await helper.request("/mk", {}, env);
  return (res.headers.get("set-cookie") ?? "").split(";")[0];
}

async function csrfTokenFor(cookie: string): Promise<string> {
  const helper = new Hono<WebEnv>();
  helper.get("/csrf", async (c) => c.text(await generateCsrfToken(c)));
  const res = await helper.request(
    "/csrf",
    { headers: { Cookie: cookie } },
    env,
  );
  return res.text();
}

function get(path: string, cookie: string): Promise<Response> {
  return SELF.fetch(BASE + path, {
    headers: { Cookie: cookie },
    redirect: "manual",
  });
}

function post(
  path: string,
  cookie: string,
  fields: Record<string, string>,
): Promise<Response> {
  return SELF.fetch(BASE + path, {
    method: "POST",
    headers: {
      Cookie: cookie,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(fields),
    redirect: "manual",
  });
}

async function sessionData(cookie: string): Promise<Record<string, unknown>> {
  const token = cookie.split("=")[1];
  const raw = await env.KV.get(`session:${token}`);
  return raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
}

async function pendingAttempt(
  cookie: string,
): Promise<{ state: string; verifier: string; at: number } | undefined> {
  const data = await sessionData(cookie);
  const extra = (data.extra ?? {}) as Record<string, unknown>;
  return extra.cf_oauth as
    | { state: string; verifier: string; at: number }
    | undefined;
}

async function flashes(
  cookie: string,
): Promise<Array<{ category: string; message: string }>> {
  const data = await sessionData(cookie);
  return (data.flashes ?? []) as Array<{ category: string; message: string }>;
}

async function tokenRow(userId: number): Promise<{
  access_token_enc: string;
  refresh_token_enc: string | null;
  expires_at: string | null;
  scopes: string | null;
  cf_account_id: string | null;
  cf_account_name: string | null;
} | null> {
  return env.DB.prepare("SELECT * FROM cf_oauth_token WHERE user_id = ?1")
    .bind(userId)
    .first();
}

/** POST /connect (CSRF + sudo) and return the parsed authorize URL. */
async function startConnect(cookie: string): Promise<URL> {
  const res = await post("/dashboard/cloudflare/connect", cookie, {
    csrf_token: await csrfTokenFor(cookie),
  });
  expect(res.status).toBe(302);
  return new URL(res.headers.get("location") ?? "");
}

// ===========================================================================
// src/lib/cfoauth.ts units
// ===========================================================================

describe("cfoauth: authorize URL", () => {
  it("is the dash.cloudflare.com endpoint with S256 PKCE and space-joined scopes", async () => {
    const verifier = "a".repeat(43);
    const challenge = await computeCodeChallenge(verifier);
    const url = new URL(
      buildAuthorizeUrl({
        clientId: "cid",
        redirectUri: "https://app.example.com/cb",
        scopes: ["account.read", "zone.read"],
        state: "st-1",
        codeChallenge: challenge,
      }),
    );
    expect(`${url.origin}${url.pathname}`).toBe(CF_OAUTH_AUTHORIZE_URL);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe("cid");
    expect(url.searchParams.get("redirect_uri")).toBe(
      "https://app.example.com/cb",
    );
    expect(url.searchParams.get("scope")).toBe("account.read zone.read");
    expect(url.searchParams.get("state")).toBe("st-1");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    // known-answer: base64url(SHA-256("aaa...")) — no padding, url alphabet
    expect(url.searchParams.get("code_challenge")).toBe(challenge);
    expect(challenge).not.toContain("=");
    expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // the verifier itself is NEVER in the authorize URL
    expect(url.search).not.toContain(verifier);
  });
});

describe("cfoauth: AES-GCM at-rest encryption", () => {
  it("round-trips, hides the plaintext, and uses a fresh IV per call", async () => {
    const a = await encryptSecretValue("secret-key", "at-plaintext");
    const b = await encryptSecretValue("secret-key", "at-plaintext");
    expect(a).not.toBe(b); // fresh 12-byte IV each time
    expect(a).not.toContain("at-plaintext");
    // versioned blob: "v1.<b64 iv>.<b64 ct>"
    expect(a).toMatch(/^v1\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$/);
    expect(a.split(".")[1]).toBe(btoa(atob(a.split(".")[1]))); // valid b64
    expect(atob(a.split(".")[1]).length).toBe(12); // 96-bit IV
    expect(await decryptSecretValue("secret-key", a)).toBe("at-plaintext");
    expect(await decryptSecretValue("secret-key", b)).toBe("at-plaintext");
  });

  it("returns null for another key, a tampered tag, or a malformed blob", async () => {
    const blob = await encryptSecretValue("secret-key", "at-plaintext");
    expect(await decryptSecretValue("other-key", blob)).toBeNull();
    const [v, iv, ct] = blob.split(".");
    const flipped = `${v}.${iv}.${btoa(
      atob(ct)
        .split("")
        .map((ch, i) =>
          i === 0 ? String.fromCharCode(ch.charCodeAt(0) ^ 1) : ch,
        )
        .join(""),
    )}`;
    expect(await decryptSecretValue("secret-key", flipped)).toBeNull();
    expect(await decryptSecretValue("secret-key", "not-a-blob")).toBeNull();
    expect(await decryptSecretValue("secret-key", ".x")).toBeNull();
    // an unversioned (pre-v1) blob is refused rather than half-parsed
    expect(await decryptSecretValue("secret-key", `${iv}.${ct}`)).toBeNull();
  });

  it("binds the ciphertext to its AAD: a blob moved to another user fails", async () => {
    const blob = await encryptSecretValue("secret-key", "at-plaintext", "7");
    expect(await decryptSecretValue("secret-key", blob, "7")).toBe(
      "at-plaintext",
    );
    // same key, same blob, different user id => authentication failure
    expect(await decryptSecretValue("secret-key", blob, "8")).toBeNull();
    expect(await decryptSecretValue("secret-key", blob)).toBeNull();
  });

  it("getGrant refuses a row whose ciphertext was moved to another user", async () => {
    const owner = await createUser(env.DB);
    const thief = await createUser(env.DB);
    await saveGrant(envt, owner.id, {
      accessToken: "at-owner",
      refreshToken: "rt-owner",
    });
    const stolen = await tokenRow(owner.id);
    await saveGrant(envt, thief.id, { accessToken: "at-thief" });
    await env.DB.prepare(
      "UPDATE cf_oauth_token SET access_token_enc = ?1 WHERE user_id = ?2",
    )
      .bind(stolen?.access_token_enc ?? "", thief.id)
      .run();

    expect((await getGrant(envt, owner.id))?.accessToken).toBe("at-owner");
    expect((await getGrant(envt, thief.id))?.accessToken).toBeNull();
  });
});

// ===========================================================================
// POST /dashboard/cloudflare/connect
// ===========================================================================

describe("POST /cloudflare/connect", () => {
  it("redirects to the authorize URL, binding state + S256 challenge to the session", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);

    const url = await startConnect(cookie);
    expect(`${url.origin}${url.pathname}`).toBe(CF_OAUTH_AUTHORIZE_URL);
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(url.searchParams.get("scope")).toBe(
      DEFAULT_CF_OAUTH_SCOPES.join(" "),
    );
    // scopes are dot-delimited ids, space-separated in the query
    expect(url.searchParams.get("scope")).toContain("zone-settings.write");
    // offline_access is REQUESTED, not assumed from the client's grant types
    // (fosite only mints a refresh token when it is a granted scope)
    expect(url.searchParams.get("scope")).toContain("offline_access");

    const attempt = await pendingAttempt(cookie);
    expect(attempt).toBeDefined();
    if (!attempt) throw new Error("no attempt");
    // state round-trips; the challenge is S256(verifier), and the verifier
    // itself never leaves the session
    expect(url.searchParams.get("state")).toBe(attempt.state);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBe(
      await computeCodeChallenge(attempt.verifier),
    );
    expect(url.href).not.toContain(attempt.verifier);
    expect(attempt.verifier.length).toBeGreaterThanOrEqual(43);
  });

  it("honours CF_OAUTH_SCOPES (space-separated) over the predicted defaults", async () => {
    envx.CF_OAUTH_SCOPES = "  account.read   dns.write ";
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const url = await startConnect(cookie);
    expect(url.searchParams.get("scope")).toBe("account.read dns.write");
  });

  it("feature gate: without client credentials it flashes and redirects, storing no state", async () => {
    envx.CF_OAUTH_CLIENT_ID = "";
    envx.CF_OAUTH_CLIENT_SECRET = "";
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);

    const res = await post("/dashboard/cloudflare/connect", cookie, {
      csrf_token: await csrfTokenFor(cookie),
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(DOMAINS_PAGE);
    expect(await pendingAttempt(cookie)).toBeUndefined();
    expect((await flashes(cookie))[0]).toMatchObject({ category: "error" });
    expect(fake.calls).toHaveLength(0);
  });

  it("feature gate: half-configured (secret missing) is also off", async () => {
    envx.CF_OAUTH_CLIENT_SECRET = "";
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const res = await post("/dashboard/cloudflare/connect", cookie, {
      csrf_token: await csrfTokenFor(cookie),
    });
    expect(res.headers.get("location")).toBe(DOMAINS_PAGE);
    expect(await pendingAttempt(cookie)).toBeUndefined();
  });

  it("is not a GET: a cross-site top-level navigation cannot start a flow", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const res = await get("/dashboard/cloudflare/connect", cookie);
    expect(res.status).toBe(404); // no GET route at all
    expect(await pendingAttempt(cookie)).toBeUndefined();
  });

  it("rejects a missing/invalid CSRF token, minting no state", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const res = await post("/dashboard/cloudflare/connect", cookie, {});
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(DOMAINS_PAGE);
    expect(await pendingAttempt(cookie)).toBeUndefined();
    expect((await flashes(cookie))[0]).toMatchObject({ category: "error" });
  });

  it("requires fresh sudo, bouncing to enter_sudo with a usable next", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id, { sudo: false });
    const res = await post("/dashboard/cloudflare/connect", cookie, {
      csrf_token: await csrfTokenFor(cookie),
    });
    expect(res.status).toBe(302);
    // POST-only route: `next` must be the PAGE carrying the form, not this
    // endpoint (enter_sudo comes back with a GET)
    expect(res.headers.get("location")).toBe(
      `/dashboard/enter_sudo?next=${encodeURIComponent(DOMAINS_PAGE)}`,
    );
    expect(await pendingAttempt(cookie)).toBeUndefined();
  });

  it("requires login", async () => {
    const res = await SELF.fetch(`${BASE}/dashboard/cloudflare/connect`, {
      method: "POST",
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("/auth/login");
  });
});

// ===========================================================================
// GET /dashboard/cloudflare/callback
// ===========================================================================

describe("GET /cloudflare/callback", () => {
  it("happy path: exchanges the code with PKCE, proves the token, stores an ENCRYPTED grant", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const url = await startConnect(cookie);
    const attempt = await pendingAttempt(cookie);
    if (!attempt) throw new Error("no attempt");

    const res = await get(
      `/dashboard/cloudflare/callback?code=the-code&state=${encodeURIComponent(attempt.state)}`,
      cookie,
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(DOMAINS_PAGE);

    // token request: client_secret_basic with RFC 6749 §2.3.1 form-encoded
    // credentials, form-encoded body, PKCE verifier, matching redirect_uri
    const tok = fake.callsTo(CF_OAUTH_TOKEN_URL);
    expect(tok).toHaveLength(1);
    expect(tok[0].method).toBe("POST");
    expect(tok[0].auth).toBe(`Basic ${btoa("cf-client-id:s3cr3t%2F%2B+x")}`);
    expect(tok[0].form).toEqual({
      grant_type: "authorization_code",
      code: "the-code",
      redirect_uri: url.searchParams.get("redirect_uri") ?? "",
      code_verifier: attempt.verifier,
    });

    // the token was PROVEN against api.cloudflare.com before being stored
    const probe = fake.callsTo(CF_API_ACCOUNTS_URL);
    expect(probe).toHaveLength(1);
    expect(probe[0].method).toBe("GET");
    expect(probe[0].auth).toBe("Bearer at-1");

    const row = await tokenRow(user.id);
    if (!row) throw new Error("no cf_oauth_token row");
    expect(row.cf_account_id).toBe("acc-1");
    expect(row.cf_account_name).toBe("you@example.com");
    expect(row.scopes).toBe("account.read zone.read");
    // ciphertext != plaintext, and it decrypts back
    expect(row.access_token_enc).not.toContain("at-1");
    expect(row.refresh_token_enc).not.toContain("rt-1");
    expect(row.access_token_enc).toMatch(
      /^v1\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$/,
    );
    // AAD-bound to the owning user id
    expect(
      await decryptSecretValue(
        envt.FLASK_SECRET,
        row.access_token_enc,
        String(user.id),
      ),
    ).toBe("at-1");
    expect(
      await decryptSecretValue(
        envt.FLASK_SECRET,
        row.refresh_token_enc ?? "",
        String(user.id),
      ),
    ).toBe("rt-1");
    // expiry derived from expires_in (never hardcoded), ~1h out
    const ttl =
      new Date(`${row.expires_at?.replace(" ", "T")}`).getTime() - Date.now();
    expect(ttl).toBeGreaterThan(3500_000);
    expect(ttl).toBeLessThanOrEqual(3600_000);

    // state is single-use: consumed from the session
    expect(await pendingAttempt(cookie)).toBeUndefined();
    const fl = await flashes(cookie);
    expect(fl[0].category).toBe("success");
    expect(fl[0].message).toContain("you@example.com");
    // no token value ever reaches a flash
    expect(JSON.stringify(fl)).not.toContain("at-1");
    expect(JSON.stringify(fl)).not.toContain("rt-1");
  });

  it("no expires_in => short conservative fallback, not an assumed lifetime", async () => {
    fake.tokenBody = { access_token: "at-noexp", refresh_token: "rt-noexp" };
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await startConnect(cookie);
    const attempt = await pendingAttempt(cookie);
    await get(
      `/dashboard/cloudflare/callback?code=c&state=${encodeURIComponent(attempt?.state ?? "")}`,
      cookie,
    );
    const row = await tokenRow(user.id);
    const ttl =
      new Date(`${row?.expires_at?.replace(" ", "T")}`).getTime() - Date.now();
    expect(ttl).toBeLessThanOrEqual(FALLBACK_EXPIRES_IN_SECS * 1000);
    expect(ttl).toBeGreaterThan((FALLBACK_EXPIRES_IN_SECS - 10) * 1000);
  });

  it("state mismatch: no token request, no row, error flash", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await startConnect(cookie);

    const res = await get(
      "/dashboard/cloudflare/callback?code=the-code&state=forged-state",
      cookie,
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(DOMAINS_PAGE);
    expect(fake.calls).toHaveLength(0);
    expect(await tokenRow(user.id)).toBeNull();
    expect((await flashes(cookie))[0]).toMatchObject({ category: "error" });
    // ...and the genuine in-flight attempt SURVIVES: an unmatched callback
    // (any link an attacker gets the victim to follow) must not be able to
    // cancel the flow the user started in another tab.
    expect(await pendingAttempt(cookie)).toBeDefined();
  });

  it("an unmatched callback cannot cancel the pending attempt, and the real one still completes", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await startConnect(cookie);
    const attempt = await pendingAttempt(cookie);

    // attacker-induced hit: no state at all
    await get("/dashboard/cloudflare/callback?error=access_denied", cookie);
    // the user's real callback still works
    const res = await get(
      `/dashboard/cloudflare/callback?code=the-code&state=${encodeURIComponent(attempt?.state ?? "")}`,
      cookie,
    );
    expect(res.status).toBe(302);
    expect(await tokenRow(user.id)).not.toBeNull();
  });

  it("provider error text is NOT flashed when the state does not match", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await startConnect(cookie);
    await get(
      "/dashboard/cloudflare/callback?error=x&error_description=" +
        encodeURIComponent("Call 555-1234 to restore your account"),
      cookie,
    );
    const msg = (await flashes(cookie))[0].message;
    expect(msg).not.toContain("555-1234");
    expect(msg).toContain("did not match this browser session");
  });

  it("state is single-use: replaying the exact same callback fails the second time", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await startConnect(cookie);
    const attempt = await pendingAttempt(cookie);
    const cb = `/dashboard/cloudflare/callback?code=the-code&state=${encodeURIComponent(attempt?.state ?? "")}`;
    await get(cb, cookie);
    expect(fake.callsTo(CF_OAUTH_TOKEN_URL)).toHaveLength(1);

    await env.DB.prepare("DELETE FROM cf_oauth_token WHERE user_id = ?1")
      .bind(user.id)
      .run();
    const again = await get(cb, cookie);
    expect(again.headers.get("location")).toBe(DOMAINS_PAGE);
    expect(fake.callsTo(CF_OAUTH_TOKEN_URL)).toHaveLength(1); // not redeemed twice
    expect(await tokenRow(user.id)).toBeNull();
  });

  it("provider error response (with the matching state): reported, no exchange, nothing stored", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await startConnect(cookie);
    const attempt = await pendingAttempt(cookie);

    const res = await get(
      "/dashboard/cloudflare/callback?error=access_denied&error_description=User+said+no" +
        `&state=${encodeURIComponent(attempt?.state ?? "")}`,
      cookie,
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(DOMAINS_PAGE);
    expect(fake.calls).toHaveLength(0);
    expect(await tokenRow(user.id)).toBeNull();
    const fl = await flashes(cookie);
    expect(fl[0].category).toBe("error");
    expect(fl[0].message).toContain("User said no");
    // a matched response is still single-use
    expect(await pendingAttempt(cookie)).toBeUndefined();
  });

  it("provider error text is sanitized before it reaches the toastr flash", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await startConnect(cookie);
    const attempt = await pendingAttempt(cookie);
    const nasty = encodeURIComponent('bad");alert(1);//<script>\\');
    await get(
      `/dashboard/cloudflare/callback?error=x&error_description=${nasty}` +
        `&state=${encodeURIComponent(attempt?.state ?? "")}`,
      cookie,
    );
    const msg = (await flashes(cookie))[0].message;
    expect(msg).not.toContain('"');
    expect(msg).not.toContain("<");
    expect(msg).not.toContain("\\");
    expect(msg).toContain("bad");
  });

  it("token endpoint refusal: diagnostic flash, nothing stored", async () => {
    fake.tokenStatus = 400;
    fake.tokenBody = {
      error: "invalid_grant",
      error_description: "code expired",
    };
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await startConnect(cookie);
    const attempt = await pendingAttempt(cookie);

    const res = await get(
      `/dashboard/cloudflare/callback?code=c&state=${encodeURIComponent(attempt?.state ?? "")}`,
      cookie,
    );
    expect(res.headers.get("location")).toBe(DOMAINS_PAGE);
    expect(await tokenRow(user.id)).toBeNull();
    expect(fake.callsTo(CF_API_ACCOUNTS_URL)).toHaveLength(0);
    const fl = await flashes(cookie);
    expect(fl[0].category).toBe("error");
    expect(fl[0].message).toContain("invalid_grant");
  });

  it("token-works check fails: grant NOT stored, token revoked, CF_API_TOKEN named as the fallback", async () => {
    // The liveness probe is GET /zones — a 403 there means the API refused
    // the OAuth token outright (the OPEN RISK), unlike a /accounts 403 which
    // is expected and non-fatal (account.read is not grantable).
    fake.zonesStatus = 403;
    fake.zonesBody = {
      success: false,
      errors: [
        { code: 9109, message: "Unauthorized to access requested resource" },
      ],
      result: null,
    };
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await startConnect(cookie);
    const attempt = await pendingAttempt(cookie);

    const res = await get(
      `/dashboard/cloudflare/callback?code=c&state=${encodeURIComponent(attempt?.state ?? "")}`,
      cookie,
    );
    expect(res.headers.get("location")).toBe(DOMAINS_PAGE);
    // the OPEN RISK is caught: nothing is persisted
    expect(await tokenRow(user.id)).toBeNull();
    // and BOTH unusable tokens are handed back (RFC 7009 §2.1 makes the
    // refresh -> access cascade a SHOULD, so the access token is revoked too)
    const rev = fake.callsTo(CF_OAUTH_REVOKE_URL);
    expect(rev.map((r) => r.form)).toEqual([
      { token: "rt-1", token_type_hint: "refresh_token" },
      { token: "at-1", token_type_hint: "access_token" },
    ]);
    const fl = await flashes(cookie);
    expect(fl[0].category).toBe("error");
    expect(fl[0].message).toContain("Cloudflare API refused it");
    expect(fl[0].message).toContain("CF_API_TOKEN");
    expect(fl[0].message).toContain("NOT saved");
    // best-effort revocation is not asserted as fact
    expect(fl[0].message).toContain("asked Cloudflare to revoke");
  });

  it("no refresh_token in the response: stored, but warned with the cause", async () => {
    fake.tokenBody = {
      access_token: "at-norefresh",
      expires_in: 3600,
      scope: "account.read",
    };
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await startConnect(cookie);
    const attempt = await pendingAttempt(cookie);
    await get(
      `/dashboard/cloudflare/callback?code=c&state=${encodeURIComponent(attempt?.state ?? "")}`,
      cookie,
    );

    const row = await tokenRow(user.id);
    expect(row?.refresh_token_enc).toBeNull();
    const fl = await flashes(cookie);
    expect(fl[0].category).toBe("success");
    expect(fl[1].category).toBe("warning");
    // the operator gets a path from symptom to remedy
    expect(fl[1].message).toContain("offline_access");
    expect(fl[1].message).toContain("CF_OAUTH_SCOPES");
  });

  it("reconnect: the grant being replaced is revoked before it is overwritten", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await saveGrant(envt, user.id, {
      accessToken: "at-old",
      refreshToken: "rt-old",
      expiresAt: toStr(addSeconds(new Date(), 3600)),
    });

    await startConnect(cookie);
    const attempt = await pendingAttempt(cookie);
    await get(
      `/dashboard/cloudflare/callback?code=c&state=${encodeURIComponent(attempt?.state ?? "")}`,
      cookie,
    );

    // the OLD pair (whose ciphertext the upsert destroys) went back first
    expect(fake.callsTo(CF_OAUTH_REVOKE_URL).map((r) => r.form)).toEqual([
      { token: "rt-old", token_type_hint: "refresh_token" },
      { token: "at-old", token_type_hint: "access_token" },
    ]);
    const grant = await getGrant(envt, user.id);
    expect(grant?.accessToken).toBe("at-1");
    expect(grant?.refreshToken).toBe("rt-1");
  });

  it("refuses a grant that cannot see the operator's account (CF_ACCOUNT_ID)", async () => {
    envx.CF_ACCOUNT_ID = "acc-operator";
    try {
      const user = await createUser(env.DB);
      const cookie = await sessionCookieFor(user.id);
      await startConnect(cookie);
      const attempt = await pendingAttempt(cookie);
      const res = await get(
        `/dashboard/cloudflare/callback?code=c&state=${encodeURIComponent(attempt?.state ?? "")}`,
        cookie,
      );
      expect(res.headers.get("location")).toBe(DOMAINS_PAGE);
      // acc-1 != acc-operator: nothing stored, both tokens handed back
      expect(await tokenRow(user.id)).toBeNull();
      expect(fake.callsTo(CF_OAUTH_REVOKE_URL)).toHaveLength(2);
      const fl = await flashes(cookie);
      expect(fl[0].category).toBe("error");
      expect(fl[0].message).toContain("mail worker");
    } finally {
      envx.CF_ACCOUNT_ID = "";
    }
  });

  it("with CF_ACCOUNT_ID set, the pinned account is the one recorded", async () => {
    envx.CF_ACCOUNT_ID = "acc-2";
    fake.accountsBody = {
      success: true,
      errors: [],
      result: [
        { id: "acc-1", name: "Personal" },
        { id: "acc-2", name: "Operator Ltd" },
      ],
    };
    try {
      const user = await createUser(env.DB);
      const cookie = await sessionCookieFor(user.id);
      await startConnect(cookie);
      const attempt = await pendingAttempt(cookie);
      await get(
        `/dashboard/cloudflare/callback?code=c&state=${encodeURIComponent(attempt?.state ?? "")}`,
        cookie,
      );
      const row = await tokenRow(user.id);
      expect(row?.cf_account_id).toBe("acc-2"); // not accounts[0]
      expect(row?.cf_account_name).toBe("Operator Ltd");
    } finally {
      envx.CF_ACCOUNT_ID = "";
    }
  });

  it("callback carries no redirect parameter: a next= is ignored (no open redirect)", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await startConnect(cookie);
    const attempt = await pendingAttempt(cookie);
    const res = await get(
      `/dashboard/cloudflare/callback?code=c&state=${encodeURIComponent(attempt?.state ?? "")}&next=https%3A%2F%2Fevil.example`,
      cookie,
    );
    expect(res.headers.get("location")).toBe(DOMAINS_PAGE);
  });
});

// ===========================================================================
// refresh-on-expiry (getValidAccessToken)
// ===========================================================================

describe("getValidAccessToken", () => {
  it("returns the stored token untouched while it is fresh", async () => {
    const user = await createUser(env.DB);
    await saveGrant(envt, user.id, {
      accessToken: "at-fresh",
      refreshToken: "rt-1",
      expiresAt: toStr(addSeconds(new Date(), 3600)),
    });
    expect(await getValidAccessToken(envt, user.id)).toBe("at-fresh");
    expect(fake.calls).toHaveLength(0);
  });

  it("refreshes inside the 60s skew window and PERSISTS A ROTATED refresh token", async () => {
    fake.tokenBody = {
      access_token: "at-2",
      refresh_token: "rt-rotated",
      expires_in: 1800,
      scope: "account.read dns.write",
    };
    const user = await createUser(env.DB);
    await saveGrant(envt, user.id, {
      accessToken: "at-old",
      refreshToken: "rt-old",
      // still 30s in the FUTURE: inside the skew window, so it must refresh
      expiresAt: toStr(addSeconds(new Date(), 30)),
      scopes: "account.read",
      accountId: "acc-1",
      accountName: "Acme",
    });

    expect(await getValidAccessToken(envt, user.id)).toBe("at-2");

    const tok = fake.callsTo(CF_OAUTH_TOKEN_URL);
    expect(tok).toHaveLength(1);
    expect(tok[0].form).toEqual({
      grant_type: "refresh_token",
      refresh_token: "rt-old",
    });
    expect(tok[0].auth).toBe(`Basic ${btoa("cf-client-id:s3cr3t%2F%2B+x")}`);

    const grant = await getGrant(envt, user.id);
    expect(grant?.accessToken).toBe("at-2");
    expect(grant?.refreshToken).toBe("rt-rotated"); // rotation persisted
    expect(grant?.scopes).toBe("account.read dns.write");
    expect(grant?.accountName).toBe("Acme"); // account metadata preserved
    const row = await tokenRow(user.id);
    expect(row?.access_token_enc).not.toContain("at-2");

    // a second call inside the new lifetime does not hit the endpoint again
    expect(await getValidAccessToken(envt, user.id)).toBe("at-2");
    expect(fake.callsTo(CF_OAUTH_TOKEN_URL)).toHaveLength(1);
  });

  it("keeps the existing refresh token when the response omits one", async () => {
    fake.tokenBody = { access_token: "at-3", expires_in: 900 };
    const user = await createUser(env.DB);
    await saveGrant(envt, user.id, {
      accessToken: "at-old",
      refreshToken: "rt-keep",
      expiresAt: toStr(addSeconds(new Date(), -10)),
    });
    expect(await getValidAccessToken(envt, user.id)).toBe("at-3");
    const grant = await getGrant(envt, user.id);
    expect(grant?.refreshToken).toBe("rt-keep");
  });

  it("invalid_grant deletes the row so refresh cannot loop", async () => {
    fake.tokenStatus = 400;
    fake.tokenBody = { error: "invalid_grant" };
    const user = await createUser(env.DB);
    await saveGrant(envt, user.id, {
      accessToken: "at-old",
      refreshToken: "rt-dead",
      expiresAt: toStr(addSeconds(new Date(), -10)),
    });
    expect(await getValidAccessToken(envt, user.id)).toBeNull();
    expect(await tokenRow(user.id)).toBeNull();
    // second call short-circuits at "no grant": still exactly one attempt
    expect(await getValidAccessToken(envt, user.id)).toBeNull();
    expect(fake.callsTo(CF_OAUTH_TOKEN_URL)).toHaveLength(1);
  });

  it("a transient 500 returns null but keeps the grant (one attempt, no loop)", async () => {
    fake.tokenStatus = 500;
    fake.tokenBody = { error: "server_error" };
    const user = await createUser(env.DB);
    await saveGrant(envt, user.id, {
      accessToken: "at-old",
      refreshToken: "rt-live",
      expiresAt: toStr(addSeconds(new Date(), -10)),
    });
    expect(await getValidAccessToken(envt, user.id)).toBeNull();
    expect(fake.callsTo(CF_OAUTH_TOKEN_URL)).toHaveLength(1);
    expect(await tokenRow(user.id)).not.toBeNull();
  });

  it("expired with no refresh token returns null without calling the endpoint", async () => {
    const user = await createUser(env.DB);
    await saveGrant(envt, user.id, {
      accessToken: "at-old",
      refreshToken: null,
      expiresAt: toStr(addSeconds(new Date(), -10)),
    });
    expect(await getValidAccessToken(envt, user.id)).toBeNull();
    expect(fake.calls).toHaveLength(0);
  });

  it("no grant at all => null", async () => {
    const user = await createUser(env.DB);
    expect(await getValidAccessToken(envt, user.id)).toBeNull();
  });
});

// ===========================================================================
// POST /dashboard/cloudflare/disconnect
// ===========================================================================

describe("POST /cloudflare/disconnect", () => {
  it("revokes both tokens best-effort and deletes the row", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await saveGrant(envt, user.id, {
      accessToken: "at-1",
      refreshToken: "rt-1",
      expiresAt: toStr(addSeconds(new Date(), 3600)),
      accountName: "Acme",
    });

    const res = await post("/dashboard/cloudflare/disconnect", cookie, {
      csrf_token: await csrfTokenFor(cookie),
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(DOMAINS_PAGE);

    const rev = fake.callsTo(CF_OAUTH_REVOKE_URL);
    expect(rev.map((r) => r.form)).toEqual([
      { token: "rt-1", token_type_hint: "refresh_token" },
      { token: "at-1", token_type_hint: "access_token" },
    ]);
    expect(rev[0].auth).toBe(`Basic ${btoa("cf-client-id:s3cr3t%2F%2B+x")}`);
    expect(await tokenRow(user.id)).toBeNull();
    expect((await flashes(cookie))[0]).toMatchObject({ category: "success" });
  });

  it("deletes the row even when revocation fails at Cloudflare", async () => {
    fake.revokeStatus = 500;
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await saveGrant(envt, user.id, {
      accessToken: "at-1",
      refreshToken: "rt-1",
    });
    await post("/dashboard/cloudflare/disconnect", cookie, {
      csrf_token: await csrfTokenFor(cookie),
    });
    expect(await tokenRow(user.id)).toBeNull();
  });

  it("rejects a missing/invalid CSRF token and keeps the grant", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await saveGrant(envt, user.id, {
      accessToken: "at-1",
      refreshToken: "rt-1",
    });

    const res = await post("/dashboard/cloudflare/disconnect", cookie, {});
    expect(res.status).toBe(302);
    expect(await tokenRow(user.id)).not.toBeNull();
    expect(fake.calls).toHaveLength(0);
    expect((await flashes(cookie))[0]).toMatchObject({ category: "error" });
  });

  it("revokes even when the OAuth client credentials are gone (last chance)", async () => {
    // The row — and with it the only copy of the ciphertext — is about to be
    // deleted, so revocation must be ATTEMPTED regardless of configuration.
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    await saveGrant(envt, user.id, {
      accessToken: "at-1",
      refreshToken: "rt-1",
    });
    const csrf = await csrfTokenFor(cookie);
    envx.CF_OAUTH_CLIENT_SECRET = "";

    await post("/dashboard/cloudflare/disconnect", cookie, {
      csrf_token: csrf,
    });
    expect(fake.callsTo(CF_OAUTH_REVOKE_URL)).toHaveLength(2);
    expect(await tokenRow(user.id)).toBeNull();
  });

  it("requires fresh sudo and keeps the grant until it is confirmed", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id, { sudo: false });
    await saveGrant(envt, user.id, {
      accessToken: "at-1",
      refreshToken: "rt-1",
    });
    const res = await post("/dashboard/cloudflare/disconnect", cookie, {
      csrf_token: await csrfTokenFor(cookie),
    });
    expect(res.headers.get("location")).toBe(
      `/dashboard/enter_sudo?next=${encodeURIComponent(DOMAINS_PAGE)}`,
    );
    expect(await tokenRow(user.id)).not.toBeNull();
    expect(fake.calls).toHaveLength(0);
  });

  it("is a no-op with a warning when nothing is connected", async () => {
    const user = await createUser(env.DB);
    const cookie = await sessionCookieFor(user.id);
    const res = await post("/dashboard/cloudflare/disconnect", cookie, {
      csrf_token: await csrfTokenFor(cookie),
    });
    expect(res.status).toBe(302);
    expect(fake.calls).toHaveLength(0);
    expect((await flashes(cookie))[0]).toMatchObject({ category: "warning" });
  });
});

// ===========================================================================
// status helper + the partial the domain page renders it with
// ===========================================================================

describe("cfOauthPageStatus", () => {
  it("reports configured/connected + account name, and never any token", async () => {
    const user = await createUser(env.DB);
    expect(await cfOauthPageStatus(envt, user.id)).toMatchObject({
      configured: true,
      connected: false,
      account_name: null,
      connect_url: "/dashboard/cloudflare/connect",
      disconnect_url: "/dashboard/cloudflare/disconnect",
    });

    await saveGrant(envt, user.id, {
      accessToken: "at-1",
      refreshToken: "rt-1",
      scopes: "account.read dns.write",
      accountId: "acc-1",
      accountName: "Acme",
    });
    const status = await cfOauthPageStatus(envt, user.id);
    expect(status).toMatchObject({
      configured: true,
      connected: true,
      needs_reconnect: false,
      has_refresh_token: true,
      account_name: "Acme",
      account_id: "acc-1",
      scopes: "account.read dns.write",
    });
    expect(JSON.stringify(status)).not.toContain("at-1");
    expect(JSON.stringify(status)).not.toContain("rt-1");
  });

  it("expired with no refresh token is 'connected but unusable', not plain connected", async () => {
    const user = await createUser(env.DB);
    await saveGrant(envt, user.id, {
      accessToken: "at-1",
      refreshToken: null,
      expiresAt: toStr(addSeconds(new Date(), -10)),
    });
    expect(await cfOauthPageStatus(envt, user.id)).toMatchObject({
      connected: true,
      needs_reconnect: true,
      has_refresh_token: false,
    });
    // an expired grant that CAN be renewed is not "needs reconnect"
    await saveGrant(envt, user.id, {
      accessToken: "at-1",
      refreshToken: "rt-1",
      expiresAt: toStr(addSeconds(new Date(), -10)),
    });
    expect(await cfOauthPageStatus(envt, user.id)).toMatchObject({
      connected: true,
      needs_reconnect: false,
    });
  });

  it("is not configured when the operator registered no OAuth client", async () => {
    envx.CF_OAUTH_CLIENT_ID = "";
    const user = await createUser(env.DB);
    await saveGrant(envt, user.id, { accessToken: "at-1" });
    expect(await cfOauthPageStatus(envt, user.id)).toMatchObject({
      configured: false,
      connected: false,
    });
  });
});

describe("_cloudflare_connect.html partial", () => {
  const render = (cf_oauth: unknown) =>
    renderTemplate("dashboard-mailbox/_cloudflare_connect.html", {
      cf_oauth,
      csrf_form: { csrf_token: csrfTokenField("tok") },
    });

  it("renders nothing when the feature is off", () => {
    expect(render(undefined).trim()).toBe("");
    expect(render({ configured: false, connected: true }).trim()).toBe("");
  });

  it("renders the connect form (POST + CSRF), then the disconnect form once connected", async () => {
    const user = await createUser(env.DB);
    const off = render(await cfOauthPageStatus(envt, user.id));
    // connecting is a state-changing POST, never an <a href> (SameSite=Lax)
    expect(off).toContain('action="/dashboard/cloudflare/connect"');
    expect(off).toContain('method="post"');
    expect(off).toContain('name="csrf_token"');
    expect(off).not.toContain("href=");

    await saveGrant(envt, user.id, {
      accessToken: "at-1",
      refreshToken: "rt-1",
      accountId: "acc-1",
      accountName: "Acme",
      scopes: "dns.write",
    });
    const on = render(await cfOauthPageStatus(envt, user.id));
    expect(on).toContain("Acme");
    expect(on).toContain('action="/dashboard/cloudflare/disconnect"');
    expect(on).toContain('name="csrf_token"');
    expect(on).not.toContain("at-1");
    expect(on).not.toContain("rt-1");
  });

  it("says the authorization must be renewed instead of claiming it is in use", async () => {
    const user = await createUser(env.DB);
    await saveGrant(envt, user.id, {
      accessToken: "at-1",
      refreshToken: null,
      accountName: "Acme",
      expiresAt: toStr(addSeconds(new Date(), -10)),
    });
    const html = render(await cfOauthPageStatus(envt, user.id));
    expect(html).toContain("can no longer be renewed");
    expect(html).not.toContain("uses this delegated access");
    // and offers the way out, in place
    expect(html).toContain('action="/dashboard/cloudflare/connect"');
  });
});
