/**
 * ONE-SHOT Cloudflare authorization: src/lib/cfoauth.ts +
 * src/web/cloudflare-pages.ts.
 *
 * The contract under test is "the authorization cannot outlive the run":
 * no offline_access is requested, `prompt=consent` forces a fresh approval
 * every time, the access token is spent inside the callback request and
 * revoked in a `finally`, and NOTHING about it is ever persisted (the
 * cf_oauth_token table is gone — migrations/0005_drop_cf_oauth.sql).
 *
 * Three module-level seams are faked: the dash.cloudflare.com OAuth
 * endpoints (setCfOauthFetch), the api.cloudflare.com v4 API the inline
 * provisioning run then calls (setCfFetch) and the DoH client the run's
 * re-verification uses (setDomainDnsClient). Tests share the SELF isolate, so
 * module-level seams reach the worker under test; they are torn down in
 * afterAll because vitest.config.ts runs singleWorker (one module graph for
 * ALL test files — leaving a seam installed would break every later file).
 *
 * CF_OAUTH_CLIENT_ID/SECRET are secrets, absent from the vitest bindings, so
 * the feature is OFF by default; the tests set them and restore "" after.
 */

import { env, SELF } from "cloudflare:test";
import { Hono } from "hono";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import { setCfFetch } from "../src/lib/cfapi";
import {
  buildAuthorizeUrl,
  CF_OAUTH_AUTHORIZE_URL,
  CF_OAUTH_REVOKE_URL,
  CF_OAUTH_START_PATH,
  CF_OAUTH_TOKEN_URL,
  computeCodeChallenge,
  setCfOauthFetch,
} from "../src/lib/cfoauth";
import type { Env } from "../src/lib/env";
import { createSession } from "../src/lib/session";
import { generateCsrfToken } from "../src/lib/web/forms";
import type { WebEnv } from "../src/lib/web/webauth";
import {
  DEFAULT_CF_OAUTH_SCOPES,
  scopesFor,
} from "../src/web/cloudflare-pages";
import { setDomainDnsClient } from "../src/web/mailbox-domain-pages";
import { createUser } from "./fixtures";

const BASE = "http://example.com";
const CLIENT_ID = "cf-client-id";
// Deliberately contains characters the RFC 6749 §2.3.1 form-encoding must
// escape before base64 (/, +, space).
const CLIENT_SECRET = "s3cr3t/+ x";
const REDIRECT_URI = "https://app.sl.example.com/dashboard/cloudflare/callback";
const DOMAINS_PAGE = "/dashboard/custom_domain";
const CALLBACK = "/dashboard/cloudflare/callback";
/** Distinctive enough that a full-database scan for it means something. */
const ACCESS_TOKEN = "cf-oneshot-access-9f3a";
/** CF_ACCOUNT_ID: a hard prerequisite for the one-shot route (§3.1). */
const ACCOUNT_ID = "acc-operator";
const confirmPath = (domainId: number) =>
  `/dashboard/domains/${domainId}/cf-confirm`;

// ---------------------------------------------------------------------------
// fake dash.cloudflare.com (token + revoke)
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
    access_token: ACCESS_TOKEN,
    expires_in: 3600,
    scope: "zone.read dns.write",
    token_type: "bearer",
  };
  revokeStatus = 200;

  callsTo(url: string): FakeCall[] {
    return this.calls.filter((c) => c.url.startsWith(url));
  }

  fetch = async (input: string, init?: RequestInit): Promise<Response> => {
    const raw = typeof init?.body === "string" ? init.body : "";
    this.calls.push({
      method: init?.method ?? "GET",
      url: input,
      form: Object.fromEntries(new URLSearchParams(raw)),
      auth: new Headers((init?.headers ?? {}) as HeadersInit).get(
        "authorization",
      ),
    });
    if (input === CF_OAUTH_TOKEN_URL) {
      return Response.json(this.tokenBody, { status: this.tokenStatus });
    }
    if (input === CF_OAUTH_REVOKE_URL) {
      return new Response("", { status: this.revokeStatus });
    }
    throw new Error(`unexpected OAuth endpoint call: ${input}`);
  };
}

// ---------------------------------------------------------------------------
// fake api.cloudflare.com (only what one provisioning run touches)
// ---------------------------------------------------------------------------

interface ApiCall {
  method: string;
  path: string;
  auth: string | null;
  body?: unknown;
}

class FakeCfApi {
  calls: ApiCall[] = [];
  zones: Array<{ id: string; name: string }> = [];
  catchAll = new Map<string, unknown>();
  txt = new Map<string, string[]>();

  writes(): ApiCall[] {
    return this.calls.filter((c) => c.method !== "GET");
  }

  fetch = async (input: string, init?: RequestInit): Promise<Response> => {
    const url = new URL(input);
    const method = init?.method ?? "GET";
    const body =
      typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    this.calls.push({
      method,
      path: url.pathname + url.search,
      auth: new Headers((init?.headers ?? {}) as HeadersInit).get(
        "authorization",
      ),
      body,
    });
    const ok = (result: unknown) =>
      Response.json({ success: true, errors: [], result });

    if (method === "GET" && url.pathname === "/client/v4/zones") {
      const name = url.searchParams.get("name");
      return ok(this.zones.filter((z) => z.name === name));
    }
    if (/\/email\/routing\/rules\/catch_all$/.test(url.pathname)) {
      const zoneId = url.pathname.split("/")[4];
      if (method === "PUT") {
        this.catchAll.set(zoneId, body);
        return ok(body);
      }
      return ok(
        this.catchAll.get(zoneId) ?? {
          enabled: false,
          matchers: [{ type: "all" }],
          actions: [{ type: "drop" }],
        },
      );
    }
    if (url.pathname.endsWith("/email/routing")) {
      return ok({ enabled: false, status: "ready" });
    }
    if (url.pathname.endsWith("/email/routing/enable")) {
      return ok({ enabled: true, status: "ready" });
    }
    if (url.pathname.endsWith("/dns_records")) {
      if (method === "POST") {
        const rec = body as { type: string; name: string; content: string };
        if (rec.type === "TXT") {
          this.txt.set(rec.name, [
            ...(this.txt.get(rec.name) ?? []),
            rec.content.replace(/^"|"$/g, ""),
          ]);
        }
        return ok({ id: "rec1", ...rec });
      }
      return ok([]);
    }
    return Response.json(
      { success: false, errors: [{ code: 404, message: "no fake" }] },
      { status: 404 },
    );
  };
}

let fake = new FakeCfOauth();
let api = new FakeCfApi();

const envx = env as unknown as Record<string, string | undefined>;
const envt = env as unknown as Env;

beforeEach(() => {
  fake = new FakeCfOauth();
  api = new FakeCfApi();
  setCfOauthFetch((input, init) => fake.fetch(input, init));
  setCfFetch((input, init) => api.fetch(input, init));
  setDomainDnsClient({
    async getTxtRecords(domain) {
      return api.txt.get(domain) ?? [];
    },
    async getMxDomains() {
      return new Map();
    },
    async getCnameRecord() {
      return null;
    },
  });
  envx.CF_OAUTH_CLIENT_ID = CLIENT_ID;
  envx.CF_OAUTH_CLIENT_SECRET = CLIENT_SECRET;
  envx.CF_OAUTH_SCOPES = "";
  // `oauth` mode requires BOTH: no static CF_API_TOKEN (that credential wins,
  // because it works for every user) and a pinned CF_ACCOUNT_ID (a zone
  // outside the worker's account can never be finished).
  envx.CF_API_TOKEN = "";
  envx.CF_ACCOUNT_ID = ACCOUNT_ID;
});

afterEach(() => {
  envx.CF_OAUTH_CLIENT_ID = "";
  envx.CF_OAUTH_CLIENT_SECRET = "";
  envx.CF_OAUTH_SCOPES = "";
  envx.CF_ACCOUNT_ID = "";
  envx.CF_API_TOKEN = "";
});

afterAll(() => {
  setCfOauthFetch(null);
  setCfFetch(null);
  setDomainDnsClient(null);
});

// ---------------------------------------------------------------------------
// HTTP + session helpers
// ---------------------------------------------------------------------------

/** No sudo: the one-shot flow deliberately has no sudo gate (it attaches no
 *  lasting credential — see the module header of cloudflare-pages.ts). */
async function sessionCookieFor(userId: number): Promise<string> {
  const helper = new Hono<WebEnv>();
  helper.get("/mk", async (c) => {
    await createSession(c, userId, {});
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

async function pendingAttempt(cookie: string): Promise<
  | {
      state: string;
      verifier: string;
      at: number;
      domainId: number;
    }
  | undefined
> {
  const extra = ((await sessionData(cookie)).extra ?? {}) as Record<
    string,
    unknown
  >;
  return extra.cf_oauth as
    | { state: string; verifier: string; at: number; domainId: number }
    | undefined;
}

async function flashes(
  cookie: string,
): Promise<Array<{ category: string; message: string }>> {
  const data = await sessionData(cookie);
  return (data.flashes ?? []) as Array<{ category: string; message: string }>;
}

async function makeDomain(userId: number, domain: string): Promise<number> {
  const row = await env.DB.prepare(
    "INSERT INTO custom_domain (user_id, domain, ownership_txt_token) VALUES (?1, ?2, ?3) RETURNING id",
  )
    .bind(userId, domain, `tok${userId}`)
    .first<{ id: number }>();
  return row?.id as number;
}

/** Every user table in the D1 database (for the "nothing is persisted" scan). */
async function allTables(): Promise<string[]> {
  const rows = await env.DB.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'",
  ).all<{ name: string }>();
  return rows.results.map((r) => r.name);
}

/** Tables whose rows contain `needle` anywhere — the storage regression net. */
async function tablesContaining(needle: string): Promise<string[]> {
  const hits: string[] = [];
  for (const table of await allTables()) {
    const rows = await env.DB.prepare(`SELECT * FROM "${table}"`).all<
      Record<string, unknown>
    >();
    if (rows.results.some((r) => JSON.stringify(r).includes(needle))) {
      hits.push(table);
    }
  }
  return hits;
}

/**
 * Render the confirmation page and take its CSRF token plus the ONE-TIME
 * nonce it minted. /start is unreachable without this: the target domain and
 * the hash of the displayed plan live in the session slot the nonce names.
 */
async function confirmFor(
  cookie: string,
  domainId: number,
): Promise<{ csrf: string; nonce: string }> {
  const res = await get(confirmPath(domainId), cookie);
  const html = await res.text();
  const csrf = html.match(
    /name="csrf_token" type="hidden" value="([^"]+)"/,
  )?.[1];
  const nonce = html.match(/name="cf_nonce" value="([^"]+)"/)?.[1];
  if (!csrf || !nonce) {
    throw new Error(`no confirmation page for ${domainId} (${res.status})`);
  }
  return { csrf, nonce };
}

/** Confirmation page -> POST /cloudflare/start, returning the authorize URL. */
async function startRun(cookie: string, domainId: number): Promise<URL> {
  const { csrf, nonce } = await confirmFor(cookie, domainId);
  const res = await post(CF_OAUTH_START_PATH, cookie, {
    csrf_token: csrf,
    cf_nonce: nonce,
  });
  expect(res.status).toBe(302);
  return new URL(res.headers.get("location") ?? "");
}

/** A user + an owned domain whose zone the fake API knows about. */
async function scenario(prefix: string): Promise<{
  userId: number;
  domainId: number;
  domain: string;
  cookie: string;
  dnsPage: string;
}> {
  const user = await createUser(env.DB);
  const domain = `${prefix}${user.id}.example.org`;
  api.zones.push({ id: `zone-${prefix}${user.id}`, name: domain });
  const domainId = await makeDomain(user.id, domain);
  return {
    userId: user.id,
    domainId,
    domain,
    cookie: await sessionCookieFor(user.id),
    dnsPage: `/dashboard/domains/${domainId}/dns`,
  };
}

// ===========================================================================
// src/lib/cfoauth.ts units
// ===========================================================================

describe("cfoauth: authorize URL", () => {
  it("is the dash.cloudflare.com endpoint with S256 PKCE and prompt=consent", async () => {
    const verifier = "a".repeat(43);
    const challenge = await computeCodeChallenge(verifier);
    const url = new URL(
      buildAuthorizeUrl({
        clientId: "cid",
        redirectUri: "https://app.example.com/cb",
        scopes: ["zone.read", "dns.write"],
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
    expect(url.searchParams.get("scope")).toBe("zone.read dns.write");
    expect(url.searchParams.get("state")).toBe("st-1");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBe(challenge);
    expect(challenge).not.toContain("=");
    expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // the verifier itself is NEVER in the authorize URL
    expect(url.search).not.toContain(verifier);
    // Hydra remembers consent sessions: without this a second run would skip
    // the screen entirely, which is the whole point of the flow.
    expect(url.searchParams.get("prompt")).toBe("consent");
  });
});

describe("cfoauth: scopes", () => {
  it("never asks for offline_access — a refresh token must not exist", () => {
    expect(DEFAULT_CF_OAUTH_SCOPES).not.toContain("offline_access");
    expect(DEFAULT_CF_OAUTH_SCOPES).not.toContain("offline");
    expect(scopesFor(envt)).toEqual(DEFAULT_CF_OAUTH_SCOPES);
  });

  it("strips offline_access/offline from an operator override", () => {
    envx.CF_OAUTH_SCOPES = " zone.read  offline_access dns.write offline ";
    expect(scopesFor(envt)).toEqual(["zone.read", "dns.write"]);
  });
});

// ===========================================================================
// POST /dashboard/cloudflare/start
// ===========================================================================

describe("POST /cloudflare/start", () => {
  it("redirects to the authorize URL, binding state + PKCE + target domain to the session", async () => {
    const s = await scenario("start");
    const url = await startRun(s.cookie, s.domainId);

    expect(`${url.origin}${url.pathname}`).toBe(CF_OAUTH_AUTHORIZE_URL);
    expect(url.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(url.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(url.searchParams.get("prompt")).toBe("consent");
    expect(url.searchParams.get("scope")).toBe(
      DEFAULT_CF_OAUTH_SCOPES.join(" "),
    );
    expect(url.searchParams.get("scope")).toContain("zone-settings.write");
    expect(url.searchParams.get("scope")).not.toContain("offline");

    const attempt = await pendingAttempt(s.cookie);
    expect(attempt).toBeDefined();
    if (!attempt) throw new Error("no attempt");
    expect(attempt.domainId).toBe(s.domainId);
    expect(url.searchParams.get("state")).toBe(attempt.state);
    expect(url.searchParams.get("code_challenge")).toBe(
      await computeCodeChallenge(attempt.verifier),
    );
    // the verifier never leaves the KV session
    expect(url.href).not.toContain(attempt.verifier);
    expect(attempt.verifier.length).toBeGreaterThanOrEqual(43);
  });

  it("rejects a missing/invalid CSRF token, minting no state", async () => {
    const s = await scenario("csrf");
    const { nonce } = await confirmFor(s.cookie, s.domainId);
    const res = await post(CF_OAUTH_START_PATH, s.cookie, {
      cf_nonce: nonce,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(DOMAINS_PAGE);
    expect(await pendingAttempt(s.cookie)).toBeUndefined();
    expect((await flashes(s.cookie))[0]).toMatchObject({ category: "error" });
    expect(fake.calls).toHaveLength(0);
  });

  it("a confirmation is bound to the browser session that rendered it", async () => {
    const owner = await scenario("owned");
    // the owner reads the diff...
    const { nonce } = await confirmFor(owner.cookie, owner.domainId);
    // ...another user replays the nonce from their own session
    const other = await createUser(env.DB);
    const cookie = await sessionCookieFor(other.id);
    const res = await post(CF_OAUTH_START_PATH, cookie, {
      csrf_token: await csrfTokenFor(cookie),
      cf_nonce: nonce,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(DOMAINS_PAGE);
    expect(await pendingAttempt(cookie)).toBeUndefined();
    expect(fake.calls).toHaveLength(0);
    // and they cannot render the diff for that domain either
    const page = await get(confirmPath(owner.domainId), cookie);
    expect(page.status).toBe(302);
    expect(page.headers.get("location")).toBe("/dashboard/");
  });

  it("refuses a missing/garbage confirm nonce: no diff, no run", async () => {
    const s = await scenario("nononce");
    for (const cf_nonce of ["", "not-a-nonce", "x".repeat(43)]) {
      const res = await post(CF_OAUTH_START_PATH, s.cookie, {
        csrf_token: await csrfTokenFor(s.cookie),
        cf_nonce,
      });
      expect(res.headers.get("location")).toBe(DOMAINS_PAGE);
      expect(await pendingAttempt(s.cookie)).toBeUndefined();
      expect(fake.calls).toHaveLength(0);
    }
  });

  it("a confirmation is single-use: the same nonce cannot start two runs", async () => {
    const s = await scenario("once");
    const { csrf, nonce } = await confirmFor(s.cookie, s.domainId);
    const first = await post(CF_OAUTH_START_PATH, s.cookie, {
      csrf_token: csrf,
      cf_nonce: nonce,
    });
    expect(first.headers.get("location")).toContain(CF_OAUTH_AUTHORIZE_URL);
    const attempt = await pendingAttempt(s.cookie);

    const replay = await post(CF_OAUTH_START_PATH, s.cookie, {
      csrf_token: csrf,
      cf_nonce: nonce,
    });
    expect(replay.headers.get("location")).toBe(DOMAINS_PAGE);
    // the in-flight attempt of the first run is untouched
    expect((await pendingAttempt(s.cookie))?.state).toBe(attempt?.state);
  });

  it("feature gate: without client credentials it flashes and stores no state", async () => {
    const s = await scenario("gate");
    const { csrf, nonce } = await confirmFor(s.cookie, s.domainId);
    // the operator removes the OAuth client while the page is open
    envx.CF_OAUTH_CLIENT_ID = "";
    envx.CF_OAUTH_CLIENT_SECRET = "";
    const res = await post(CF_OAUTH_START_PATH, s.cookie, {
      csrf_token: csrf,
      cf_nonce: nonce,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(s.dnsPage);
    expect(await pendingAttempt(s.cookie)).toBeUndefined();
    expect((await flashes(s.cookie))[0]).toMatchObject({ category: "error" });
    expect(fake.calls).toHaveLength(0);
  });

  it("gate: CF_ACCOUNT_ID is a prerequisite — no pinned account, no hand-off", async () => {
    const s = await scenario("unpinned");
    const { csrf, nonce } = await confirmFor(s.cookie, s.domainId);
    envx.CF_ACCOUNT_ID = "";
    const res = await post(CF_OAUTH_START_PATH, s.cookie, {
      csrf_token: csrf,
      cf_nonce: nonce,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(s.dnsPage);
    expect(await pendingAttempt(s.cookie)).toBeUndefined();
    expect(fake.calls).toHaveLength(0);
  });

  it("gate: a domain overlapping the deployment's own is refused before Cloudflare", async () => {
    const user = await createUser(env.DB);
    // EMAIL_DOMAIN is sl.example.com in the test env (vitest.config.ts)
    const domainId = await makeDomain(user.id, "hijack.sl.example.com");
    const cookie = await sessionCookieFor(user.id);
    const res = await get(confirmPath(domainId), cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      `/dashboard/domains/${domainId}/dns`,
    );
    expect((await flashes(cookie))[0].message).toContain("overlaps");
    expect(fake.calls).toHaveLength(0);
  });

  it("is not a GET: a cross-site top-level navigation cannot start a run", async () => {
    const s = await scenario("noget");
    const res = await get(CF_OAUTH_START_PATH, s.cookie);
    expect(res.status).toBe(404); // no GET route at all
    expect(await pendingAttempt(s.cookie)).toBeUndefined();
  });

  it("requires login", async () => {
    const res = await SELF.fetch(BASE + CF_OAUTH_START_PATH, {
      method: "POST",
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("/auth/login");
  });

  it("refuses once the provisioning budget is spent, before touching Cloudflare", async () => {
    const s = await scenario("rl");
    const now = Date.now() / 1000;
    for (const [seconds, limit] of [
      [60, 3],
      [3600, 20],
    ] as const) {
      await env.DB.prepare(
        "INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, ?3)",
      )
        .bind(
          `rlw:web_cf_provision:userid:${s.userId}:${seconds}`,
          Math.floor(now / seconds),
          limit,
        )
        .run();
    }
    const { csrf, nonce } = await confirmFor(s.cookie, s.domainId);
    const res = await post(CF_OAUTH_START_PATH, s.cookie, {
      csrf_token: csrf,
      cf_nonce: nonce,
    });
    expect(res.status).toBe(429);
    expect(await pendingAttempt(s.cookie)).toBeUndefined();
    expect(fake.calls).toHaveLength(0);
    // ...and the refusal did NOT burn the confirmation: once the window
    // rolls over, the same page still works
    await env.DB.prepare("DELETE FROM rate_limit WHERE key LIKE ?1")
      .bind(`rlw:web_cf_provision:userid:${s.userId}:%`)
      .run();
    const retried = await post(CF_OAUTH_START_PATH, s.cookie, {
      csrf_token: csrf,
      cf_nonce: nonce,
    });
    expect(retried.headers.get("location")).toContain(CF_OAUTH_AUTHORIZE_URL);
  });

  it("has a throttle of its own: /start cannot be hammered for free", async () => {
    const s = await scenario("startrl");
    const now = Date.now() / 1000;
    await env.DB.prepare(
      "INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, ?3)",
    )
      .bind(
        `rlw:web_cf_oauth_start:userid:${s.userId}:60`,
        Math.floor(now / 60),
        10,
      )
      .run();
    const { csrf, nonce } = await confirmFor(s.cookie, s.domainId);
    const res = await post(CF_OAUTH_START_PATH, s.cookie, {
      csrf_token: csrf,
      cf_nonce: nonce,
    });
    expect(res.status).toBe(429);
    expect(await pendingAttempt(s.cookie)).toBeUndefined();
  });
});

// ===========================================================================
// GET /dashboard/cloudflare/callback — redeem, RUN, revoke
// ===========================================================================

describe("GET /cloudflare/callback", () => {
  it("happy path: redeems with PKCE, provisions inline, revokes, stores NOTHING", async () => {
    const s = await scenario("happy");
    const url = await startRun(s.cookie, s.domainId);
    const attempt = await pendingAttempt(s.cookie);
    if (!attempt) throw new Error("no attempt");

    const res = await get(
      `${CALLBACK}?code=the-code&state=${encodeURIComponent(attempt.state)}`,
      s.cookie,
    );
    expect(res.status).toBe(302);
    // lands back on the DNS page of the domain the attempt named
    expect(res.headers.get("location")).toBe(s.dnsPage);

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

    // the run really happened, under the one-shot token
    expect(api.writes().length).toBeGreaterThan(0);
    expect([...new Set(api.calls.map((c) => c.auth))]).toEqual([
      `Bearer ${ACCESS_TOKEN}`,
    ]);

    // ...and the token was handed back EXACTLY ONCE, on the success path too
    const rev = fake.callsTo(CF_OAUTH_REVOKE_URL);
    expect(rev).toHaveLength(1);
    expect(rev[0].form).toEqual({
      token: ACCESS_TOKEN,
      token_type_hint: "access_token",
    });
    expect(rev[0].auth).toBe(`Basic ${btoa("cf-client-id:s3cr3t%2F%2B+x")}`);

    // NOTHING was persisted: no grant table exists at all, and no row in any
    // table (nor the KV session) carries the token
    expect(await allTables()).not.toContain("cf_oauth_token");
    expect(await tablesContaining(ACCESS_TOKEN)).toEqual([]);
    expect(JSON.stringify(await sessionData(s.cookie))).not.toContain(
      ACCESS_TOKEN,
    );

    const fl = await flashes(s.cookie);
    expect(fl[0].category).toBe("success");
    expect(JSON.stringify(fl)).not.toContain(ACCESS_TOKEN);
    // the attempt is consumed
    expect(await pendingAttempt(s.cookie)).toBeUndefined();
  });

  it("a FAILING run still revokes the token (finally)", async () => {
    const s = await scenario("failrun");
    // a foreign catch-all: the run refuses at the read-only preflight
    api.catchAll.set(`zone-failrun${s.userId}`, {
      enabled: true,
      matchers: [{ type: "all" }],
      actions: [{ type: "forward", value: ["ops@elsewhere.example"] }],
    });
    await startRun(s.cookie, s.domainId);
    const attempt = await pendingAttempt(s.cookie);

    const res = await get(
      `${CALLBACK}?code=c&state=${encodeURIComponent(attempt?.state ?? "")}`,
      s.cookie,
    );
    expect(res.headers.get("location")).toBe(s.dnsPage);
    // the guard fired BEFORE any write, on the inline path too
    expect(api.writes()).toEqual([]);
    const fl = await flashes(s.cookie);
    expect(fl[0].category).toBe("error");
    expect(fl[0].message).toContain("Refusing to change the catch-all");
    // ...and the authorization was still handed back
    expect(fake.callsTo(CF_OAUTH_REVOKE_URL).map((r) => r.form)).toEqual([
      { token: ACCESS_TOKEN, token_type_hint: "access_token" },
    ]);
    expect(await tablesContaining(ACCESS_TOKEN)).toEqual([]);
  });

  it("an unexpected refresh_token is revoked too, never used and never stored", async () => {
    fake.tokenBody = {
      access_token: ACCESS_TOKEN,
      refresh_token: "rt-unexpected",
      expires_in: 3600,
    };
    const s = await scenario("norefresh");
    await startRun(s.cookie, s.domainId);
    const attempt = await pendingAttempt(s.cookie);
    await get(
      `${CALLBACK}?code=c&state=${encodeURIComponent(attempt?.state ?? "")}`,
      s.cookie,
    );
    // refresh token first (RFC 7009 §2.1 makes the cascade a SHOULD only)
    expect(fake.callsTo(CF_OAUTH_REVOKE_URL).map((r) => r.form)).toEqual([
      { token: "rt-unexpected", token_type_hint: "refresh_token" },
      { token: ACCESS_TOKEN, token_type_hint: "access_token" },
    ]);
    expect(await tablesContaining("rt-unexpected")).toEqual([]);
  });

  it("state mismatch: no token request, in-flight attempt survives", async () => {
    const s = await scenario("mismatch");
    await startRun(s.cookie, s.domainId);

    const res = await get(`${CALLBACK}?code=the-code&state=forged`, s.cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(DOMAINS_PAGE);
    expect(fake.calls).toHaveLength(0);
    expect(api.calls).toEqual([]);
    expect((await flashes(s.cookie))[0]).toMatchObject({ category: "error" });
    // a stray/forged hit must not cancel the flow started in another tab
    expect(await pendingAttempt(s.cookie)).toBeDefined();
  });

  it("provider error text is NOT flashed when the state does not match", async () => {
    const s = await scenario("phish");
    await startRun(s.cookie, s.domainId);
    await get(
      `${CALLBACK}?error=x&error_description=${encodeURIComponent("Call 555-1234 to restore your account")}`,
      s.cookie,
    );
    const msg = (await flashes(s.cookie))[0].message;
    expect(msg).not.toContain("555-1234");
    expect(msg).toContain("did not match this browser session");
  });

  it("state is single-use: replaying the same callback does nothing", async () => {
    const s = await scenario("replay");
    await startRun(s.cookie, s.domainId);
    const attempt = await pendingAttempt(s.cookie);
    const cb = `${CALLBACK}?code=the-code&state=${encodeURIComponent(attempt?.state ?? "")}`;
    await get(cb, s.cookie);
    expect(fake.callsTo(CF_OAUTH_TOKEN_URL)).toHaveLength(1);

    const again = await get(cb, s.cookie);
    expect(again.headers.get("location")).toBe(DOMAINS_PAGE);
    expect(fake.callsTo(CF_OAUTH_TOKEN_URL)).toHaveLength(1); // not redeemed twice
  });

  it("provider error response (matching state): reported, no exchange, no run", async () => {
    const s = await scenario("denied");
    await startRun(s.cookie, s.domainId);
    const attempt = await pendingAttempt(s.cookie);

    const res = await get(
      `${CALLBACK}?error=access_denied&error_description=User+said+no&state=${encodeURIComponent(attempt?.state ?? "")}`,
      s.cookie,
    );
    expect(res.headers.get("location")).toBe(s.dnsPage);
    expect(fake.calls).toHaveLength(0);
    expect(api.calls).toEqual([]);
    const fl = await flashes(s.cookie);
    expect(fl[0].category).toBe("error");
    expect(fl[0].message).toContain("User said no");
    expect(fl[0].message).toContain("Nothing was changed");
    expect(await pendingAttempt(s.cookie)).toBeUndefined();
  });

  it("provider error text is sanitized before it reaches the toastr flash", async () => {
    const s = await scenario("nasty");
    await startRun(s.cookie, s.domainId);
    const attempt = await pendingAttempt(s.cookie);
    const nasty = encodeURIComponent('bad");alert(1);//<script>\\');
    await get(
      `${CALLBACK}?error=x&error_description=${nasty}&state=${encodeURIComponent(attempt?.state ?? "")}`,
      s.cookie,
    );
    const msg = (await flashes(s.cookie))[0].message;
    expect(msg).not.toContain('"');
    expect(msg).not.toContain("<");
    expect(msg).not.toContain("\\");
    expect(msg).toContain("bad");
  });

  it("token endpoint refusal: diagnostic flash, no run, nothing to revoke", async () => {
    fake.tokenStatus = 400;
    fake.tokenBody = {
      error: "invalid_grant",
      error_description: "code expired",
    };
    const s = await scenario("refused");
    await startRun(s.cookie, s.domainId);
    const attempt = await pendingAttempt(s.cookie);

    const res = await get(
      `${CALLBACK}?code=c&state=${encodeURIComponent(attempt?.state ?? "")}`,
      s.cookie,
    );
    expect(res.headers.get("location")).toBe(s.dnsPage);
    expect(api.calls).toEqual([]);
    expect(fake.callsTo(CF_OAUTH_REVOKE_URL)).toHaveLength(0);
    const fl = await flashes(s.cookie);
    expect(fl[0].category).toBe("error");
    expect(fl[0].message).toContain("invalid_grant");
    expect(fl[0].message).toContain("nothing was changed");
  });

  it("the run happens even when revocation fails, and the failure is not fatal", async () => {
    fake.revokeStatus = 500;
    const s = await scenario("revokefail");
    await startRun(s.cookie, s.domainId);
    const attempt = await pendingAttempt(s.cookie);
    const res = await get(
      `${CALLBACK}?code=c&state=${encodeURIComponent(attempt?.state ?? "")}`,
      s.cookie,
    );
    expect(res.status).toBe(302);
    expect((await flashes(s.cookie))[0].category).toBe("success");
    expect(fake.callsTo(CF_OAUTH_REVOKE_URL)).toHaveLength(1);
    // and still nothing stored: the ~1h Hydra ceiling is the only backstop
    expect(await tablesContaining(ACCESS_TOKEN)).toEqual([]);
  });

  it("an attempt older than the TTL is refused without redeeming the code", async () => {
    const s = await scenario("stale");
    await startRun(s.cookie, s.domainId);
    // age the pending attempt past ATTEMPT_TTL_SECS
    const token = s.cookie.split("=")[1];
    const data = JSON.parse((await env.KV.get(`session:${token}`)) ?? "{}");
    const state = data.extra.cf_oauth.state as string;
    data.extra.cf_oauth.at = Math.floor(Date.now() / 1000) - 601;
    await env.KV.put(`session:${token}`, JSON.stringify(data));

    const res = await get(
      `${CALLBACK}?code=c&state=${encodeURIComponent(state)}`,
      s.cookie,
    );
    expect(res.headers.get("location")).toBe(s.dnsPage);
    expect(fake.calls).toHaveLength(0);
    expect((await flashes(s.cookie))[0].message).toContain("expired");
  });

  it("a domain deleted while the user was at Cloudflare: no code redeemed", async () => {
    const s = await scenario("vanished");
    await startRun(s.cookie, s.domainId);
    const attempt = await pendingAttempt(s.cookie);
    await env.DB.prepare("DELETE FROM custom_domain WHERE id = ?1")
      .bind(s.domainId)
      .run();

    const res = await get(
      `${CALLBACK}?code=c&state=${encodeURIComponent(attempt?.state ?? "")}`,
      s.cookie,
    );
    expect(res.headers.get("location")).toBe(DOMAINS_PAGE);
    expect(fake.calls).toHaveLength(0);
    expect(api.calls).toEqual([]);
    expect((await flashes(s.cookie))[0]).toMatchObject({ category: "warning" });
  });

  it("the rate limit is spent in the callback, and refuses before minting a token", async () => {
    const s = await scenario("cbrl");
    await startRun(s.cookie, s.domainId);
    const attempt = await pendingAttempt(s.cookie);
    // budget exhausted between the redirect and the return
    const now = Date.now() / 1000;
    for (const [seconds, limit] of [
      [60, 3],
      [3600, 20],
    ] as const) {
      await env.DB.prepare(
        `INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET window_start = ?2, count = ?3`,
      )
        .bind(
          `rlw:web_cf_provision:userid:${s.userId}:${seconds}`,
          Math.floor(now / seconds),
          limit,
        )
        .run();
    }
    const res = await get(
      `${CALLBACK}?code=c&state=${encodeURIComponent(attempt?.state ?? "")}`,
      s.cookie,
    );
    // a flash + the domain's DNS page, NOT a bare 429: the user has just
    // approved on Cloudflare's consent screen and has to be told that
    // nothing changed and that continuing means approving again
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(s.dnsPage);
    const fl = await flashes(s.cookie);
    expect(fl[0].category).toBe("error");
    expect(fl[0].message).toContain("Nothing was changed");
    // no token was ever minted, so there is nothing to revoke
    expect(fake.calls).toHaveLength(0);
    expect(api.calls).toEqual([]);
  });

  it("two deliveries of the same callback redeem the code at most once", async () => {
    // A double-clicked navigation or a browser prefetch of the redirect
    // target: both requests can read the session before either writes.
    // Redeeming the same authorization code twice is what RFC 6749 §4.1.2
    // says the server SHOULD punish by revoking the tokens it already issued
    // — i.e. it could kill the winner's token mid-run, between the
    // Email-Routing enable and the catch-all PUT.
    const s = await scenario("dup");
    await startRun(s.cookie, s.domainId);
    const attempt = await pendingAttempt(s.cookie);
    const cb = `${CALLBACK}?code=the-code&state=${encodeURIComponent(attempt?.state ?? "")}`;
    await Promise.all([get(cb, s.cookie), get(cb, s.cookie)]);
    // exactly one redemption, one run, one revocation — the KV session alone
    // cannot give this (no compare-and-set), so the callback takes a D1 claim
    expect(fake.callsTo(CF_OAUTH_TOKEN_URL)).toHaveLength(1);
    expect(fake.callsTo(CF_OAUTH_REVOKE_URL)).toHaveLength(1);
    expect(
      api.calls.filter((call) =>
        call.path.startsWith("/client/v4/zones?name="),
      ),
    ).toHaveLength(1);
    expect(await pendingAttempt(s.cookie)).toBeUndefined();
  });

  it("a successful run SPENDS the budget (one deduct per completed run)", async () => {
    const s = await scenario("spend");
    await startRun(s.cookie, s.domainId);
    const attempt = await pendingAttempt(s.cookie);
    await get(
      `${CALLBACK}?code=c&state=${encodeURIComponent(attempt?.state ?? "")}`,
      s.cookie,
    );
    const row = await env.DB.prepare(
      "SELECT count FROM rate_limit WHERE key = ?1",
    )
      .bind(`rlw:web_cf_provision:userid:${s.userId}:60`)
      .first<{ count: number }>();
    expect(row?.count).toBe(1);
  });

  it("callback carries no redirect parameter: a next= is ignored (no open redirect)", async () => {
    const s = await scenario("openredir");
    await startRun(s.cookie, s.domainId);
    const attempt = await pendingAttempt(s.cookie);
    const res = await get(
      `${CALLBACK}?code=c&state=${encodeURIComponent(attempt?.state ?? "")}&next=https%3A%2F%2Fevil.example`,
      s.cookie,
    );
    expect(res.headers.get("location")).toBe(s.dnsPage);
  });

  it("requires login", async () => {
    const res = await SELF.fetch(`${BASE + CALLBACK}?code=c&state=s`, {
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain("/auth/login");
  });
});
