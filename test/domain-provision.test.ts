/**
 * One-click Cloudflare domain provisioning: route 7's cf-provision branch
 * (src/web/mailbox-domain-pages.ts handleCfProvision) + src/lib/cfapi.ts.
 * The Cloudflare API is faked through the setCfFetch seam and the page's
 * DNS checks through setDomainDnsClient — tests share the SELF isolate, so
 * module-level seams reach the worker under test; they are installed in
 * beforeEach and torn down in afterAll because vitest.config.ts runs
 * singleWorker (one module graph for ALL test files — leaving the seams in
 * place would disable the real DoH client for every later file). Created
 * records propagate instantly into the fake DoH view, letting the
 * in-process re-verification flip the ownership/MX/SPF/DMARC flags like the
 * manual check buttons.
 */

import { env, SELF } from "cloudflare:test";
import { Hono } from "hono";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import { setCfFetch } from "../src/lib/cfapi";
import { createSession } from "../src/lib/session";
import type { WebEnv } from "../src/lib/web/webauth";
import { setDomainDnsClient } from "../src/web/mailbox-domain-pages";
import { createUser } from "./fixtures";

const BASE = "http://example.com";
const DMARC_RECORD = "v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s";
const SPF_RECORD = "v=spf1 include:_spf.mx.cloudflare.net ~all";
const ROUTE_MX_HOSTS = [
  "route1.mx.cloudflare.net",
  "route2.mx.cloudflare.net",
  "route3.mx.cloudflare.net",
];

// ---------------------------------------------------------------------------
// fake Cloudflare API (stateful: writes are visible to later reads, so the
// idempotency scenario exercises real check-before-write behavior)
// ---------------------------------------------------------------------------

interface CfCall {
  method: string;
  path: string; // pathname + search
  body?: unknown;
}

interface FakeCatchAll {
  enabled: boolean;
  name?: string;
  matchers?: unknown[];
  actions: Array<{ type: string; value?: string[] }>;
}

class FakeCloudflare {
  calls: CfCall[] = [];
  zones: Array<{ id: string; name: string }> = [];
  routingEnabled = new Set<string>(); // zone ids (apex enable)
  catchAll = new Map<string, FakeCatchAll>(); // by zone id
  dnsRecords: Array<{
    id: string;
    zoneId: string;
    type: string;
    name: string;
    content: string;
  }> = [];
  /** The DoH view the page's checks see (instant "propagation"). */
  txt = new Map<string, string[]>();
  mx = new Map<string, Map<number, string[]>>();
  private nextId = 1;

  writes(): CfCall[] {
    return this.calls.filter((c) => c.method !== "GET");
  }

  /** What Email Routing onboarding does to DNS: MX (per-zone priorities)
   *  plus the SPF TXT record (docs/DOMAINS.md §1.2). */
  private provisionRoutingDns(zoneId: string, name: string): void {
    const mxMap = new Map<number, string[]>();
    let priority = 37; // Cloudflare-assigned, not operator-chosen
    for (const host of ROUTE_MX_HOSTS) {
      this.dnsRecords.push({
        id: `rec${this.nextId++}`,
        zoneId,
        type: "MX",
        name,
        content: host,
      });
      mxMap.set(priority, [`${host}.`]);
      priority += 10;
    }
    this.mx.set(name, mxMap);
    this.dnsRecords.push({
      id: `rec${this.nextId++}`,
      zoneId,
      type: "TXT",
      name,
      content: `"${SPF_RECORD}"`,
    });
    this.txt.set(name, [...(this.txt.get(name) ?? []), SPF_RECORD]);
  }

  fetch = async (input: string, init?: RequestInit): Promise<Response> => {
    const url = new URL(input);
    const method = init?.method ?? "GET";
    const body =
      typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    this.calls.push({ method, path: url.pathname + url.search, body });
    const ok = (result: unknown) =>
      Response.json({ success: true, errors: [], result });

    if (method === "GET" && url.pathname === "/client/v4/zones") {
      const name = url.searchParams.get("name");
      return ok(this.zones.filter((z) => z.name === name));
    }

    let m = /^\/client\/v4\/zones\/([^/]+)\/email\/routing$/.exec(url.pathname);
    if (m && method === "GET") {
      return ok({ enabled: this.routingEnabled.has(m[1]), status: "ready" });
    }

    m = /^\/client\/v4\/zones\/([^/]+)\/email\/routing\/enable$/.exec(
      url.pathname,
    );
    if (m && method === "POST") {
      const zoneId = m[1];
      this.routingEnabled.add(zoneId);
      const zone = this.zones.find((z) => z.id === zoneId);
      if (zone) this.provisionRoutingDns(zoneId, zone.name);
      return ok({ enabled: true, status: "ready" });
    }

    m = /^\/client\/v4\/zones\/([^/]+)\/email\/routing\/dns$/.exec(
      url.pathname,
    );
    if (m && method === "POST") {
      this.provisionRoutingDns(m[1], (body as { name: string }).name);
      return ok({});
    }

    m = /^\/client\/v4\/zones\/([^/]+)\/email\/routing\/rules\/catch_all$/.exec(
      url.pathname,
    );
    if (m && method === "GET") {
      return ok(
        this.catchAll.get(m[1]) ?? {
          enabled: false,
          name: "",
          matchers: [{ type: "all" }],
          actions: [{ type: "drop" }],
        },
      );
    }
    if (m && method === "PUT") {
      this.catchAll.set(m[1], body as FakeCatchAll);
      return ok(body);
    }

    m = /^\/client\/v4\/zones\/([^/]+)\/dns_records$/.exec(url.pathname);
    if (m && method === "GET") {
      const zoneId = m[1];
      const type = url.searchParams.get("type");
      const name = url.searchParams.get("name.exact");
      return ok(
        this.dnsRecords.filter(
          (r) => r.zoneId === zoneId && r.type === type && r.name === name,
        ),
      );
    }
    if (m && method === "POST") {
      const record = body as { type: string; name: string; content: string };
      this.dnsRecords.push({
        id: `rec${this.nextId++}`,
        zoneId: m[1],
        type: record.type,
        name: record.name,
        content: record.content,
      });
      if (record.type === "TXT") {
        const unquoted = record.content.replace(/^"|"$/g, "");
        this.txt.set(record.name, [
          ...(this.txt.get(record.name) ?? []),
          unquoted,
        ]);
      }
      return ok({ id: `rec${this.nextId - 1}`, ...record });
    }

    return Response.json(
      {
        success: false,
        errors: [
          { code: 404, message: `no fake for ${method} ${url.pathname}` },
        ],
        result: null,
      },
      { status: 404 },
    );
  };
}

let fake = new FakeCloudflare();

const envx = env as unknown as Record<string, string | undefined>;

beforeEach(() => {
  fake = new FakeCloudflare();
  // Tests and SELF share this isolate, so the routes see these seams.
  setCfFetch((input, init) => fake.fetch(input, init));
  setDomainDnsClient({
    async getTxtRecords(domain) {
      return fake.txt.get(domain) ?? [];
    },
    async getMxDomains(domain) {
      return fake.mx.get(domain) ?? new Map();
    },
    async getCnameRecord() {
      return null;
    },
  });
  // CF_API_TOKEN is a secret (absent from vitest bindings): feature is off
  // by default; enable it for these tests. "" restores "unset".
  envx.CF_API_TOKEN = "test-cf-token";
  envx.EMAIL_SERVERS_WITH_PRIORITY =
    "10 route1.mx.cloudflare.net.,20 route2.mx.cloudflare.net.,30 route3.mx.cloudflare.net.";
});

afterEach(() => {
  envx.CF_API_TOKEN = "";
  envx.EMAIL_SERVERS_WITH_PRIORITY = "";
  envx.PREMIUM_ALIAS_DOMAINS = "";
});

// singleWorker shares the module graph with every other test file: restore
// the real fetch / DoH clients (both seams accept null for that).
afterAll(() => {
  setCfFetch(null);
  setDomainDnsClient(null);
});

// ---------------------------------------------------------------------------
// HTTP helpers (as in web-mailbox-domain-pages.test.ts)
// ---------------------------------------------------------------------------

async function sessionCookieFor(userId: number): Promise<string> {
  const helper = new Hono<WebEnv>();
  helper.get("/mk", async (c) => {
    await createSession(c, userId, {});
    return c.text("ok");
  });
  const res = await helper.request("/mk", {}, env);
  return (res.headers.get("set-cookie") ?? "").split(";")[0];
}

async function get(path: string, cookie: string): Promise<Response> {
  return SELF.fetch(BASE + path, {
    headers: { Cookie: cookie },
    redirect: "manual",
  });
}

async function getCsrf(path: string, cookie: string): Promise<string> {
  const res = await get(path, cookie);
  const html = await res.text();
  const m = html.match(/name="csrf_token" type="hidden" value="([^"]+)"/);
  if (!m) throw new Error(`no csrf token on ${path} (status ${res.status})`);
  return m[1];
}

async function post(
  path: string,
  cookie: string,
  fields: Record<string, string>,
): Promise<Response> {
  const body = new URLSearchParams(fields);
  return SELF.fetch(BASE + path, {
    method: "POST",
    headers: {
      Cookie: cookie,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
    redirect: "manual",
  });
}

async function getFlashes(
  cookie: string,
): Promise<Array<{ category: string; message: string }>> {
  const token = cookie.split("=")[1];
  const raw = await env.KV.get(`session:${token}`);
  if (!raw) return [];
  return (JSON.parse(raw).flashes ?? []) as Array<{
    category: string;
    message: string;
  }>;
}

async function clearFlashes(cookie: string): Promise<void> {
  const token = cookie.split("=")[1];
  const raw = await env.KV.get(`session:${token}`);
  if (!raw) return;
  const data = JSON.parse(raw);
  data.flashes = [];
  await env.KV.put(`session:${token}`, JSON.stringify(data));
}

async function makeDomain(
  userId: number,
  domain: string,
  token: string,
): Promise<number> {
  const row = await env.DB.prepare(
    "INSERT INTO custom_domain (user_id, domain, ownership_txt_token) VALUES (?1, ?2, ?3) RETURNING id",
  )
    .bind(userId, domain, token)
    .first<{ id: number }>();
  return row?.id as number;
}

interface DomainFlags {
  ownership_verified: number;
  verified: number;
  spf_verified: number;
  dmarc_verified: number;
}

const NO_FLAGS: DomainFlags = {
  ownership_verified: 0,
  verified: 0,
  spf_verified: 0,
  dmarc_verified: 0,
};

const ALL_FLAGS: DomainFlags = {
  ownership_verified: 1,
  verified: 1,
  spf_verified: 1,
  dmarc_verified: 1,
};

async function domainFlags(id: number): Promise<DomainFlags> {
  const row = await env.DB.prepare(
    `SELECT ownership_verified, verified, spf_verified, dmarc_verified
     FROM custom_domain WHERE id = ?1`,
  )
    .bind(id)
    .first<DomainFlags>();
  if (!row) throw new Error(`no custom_domain ${id}`);
  return row;
}

async function provision(id: number, cookie: string): Promise<Response> {
  const csrf = await getCsrf(`/dashboard/domains/${id}/dns`, cookie);
  return post(`/dashboard/domains/${id}/dns`, cookie, {
    "form-name": "cf-provision",
    csrf_token: csrf,
  });
}

// ---------------------------------------------------------------------------

describe("cf-provision: happy paths", () => {
  it("apex: exact API calls (conflict preflight before any write), records planted, all flags set", async () => {
    const user = await createUser(env.DB);
    const domain = `apex${user.id}.example.org`;
    fake.zones.push({ id: "zone-apex", name: domain });
    const id = await makeDomain(user.id, domain, "tokapex");
    const cookie = await sessionCookieFor(user.id);

    // token stored => the button renders on GET
    const page = await get(`/dashboard/domains/${id}/dns`, cookie);
    expect(await page.text()).toContain(
      'name="form-name" value="cf-provision"',
    );

    const res = await provision(id, cookie);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`/dashboard/domains/${id}/dns`);

    // all refusal checks (catch-all, foreign MX) are READS that precede the
    // first write (the routing enable)
    expect(fake.calls.map((c) => [c.method, c.path])).toEqual([
      ["GET", `/client/v4/zones?name=${domain}`],
      ["GET", "/client/v4/zones/zone-apex/email/routing/rules/catch_all"],
      [
        "GET",
        `/client/v4/zones/zone-apex/dns_records?type=MX&name.exact=${domain}`,
      ],
      ["GET", "/client/v4/zones/zone-apex/email/routing"],
      ["POST", "/client/v4/zones/zone-apex/email/routing/enable"],
      ["PUT", "/client/v4/zones/zone-apex/email/routing/rules/catch_all"],
      [
        "GET",
        `/client/v4/zones/zone-apex/dns_records?type=TXT&name.exact=${domain}`,
      ],
      ["POST", "/client/v4/zones/zone-apex/dns_records"],
      [
        "GET",
        `/client/v4/zones/zone-apex/dns_records?type=TXT&name.exact=_dmarc.${domain}`,
      ],
      ["POST", "/client/v4/zones/zone-apex/dns_records"],
    ]);

    // catch-all PUT body: worker action exactly as the dashboard creates it
    const put = fake.calls.find((c) => c.method === "PUT");
    expect(put?.body).toEqual({
      enabled: true,
      name: 'simplelogin: route all mail to worker "simplelogin"',
      matchers: [{ type: "all" }],
      actions: [{ type: "worker", value: ["simplelogin"] }],
    });

    // TXT contents: the EXACT ownership record the page displays, then DMARC
    const txtPosts = fake.calls.filter(
      (c) => c.method === "POST" && c.path.endsWith("/dns_records"),
    );
    expect(txtPosts[0].body).toEqual({
      type: "TXT",
      name: domain,
      content: '"sl-verification=tokapex"',
      ttl: 1,
      comment: "SimpleLogin ownership verification (auto-configure)",
    });
    expect(txtPosts[1].body).toEqual({
      type: "TXT",
      name: `_dmarc.${domain}`,
      content: `"${DMARC_RECORD}"`,
      ttl: 1,
      comment: "SimpleLogin (auto-configure)",
    });

    // in-process re-verification persisted ALL the flags the provisioning
    // steps create records for (ownership, MX, SPF, DMARC)
    expect(await domainFlags(id)).toEqual(ALL_FLAGS);

    const flashes = await getFlashes(cookie);
    expect(flashes).toHaveLength(1);
    expect(flashes[0].category).toBe("success");
    expect(flashes[0].message).toContain("ownership verified");
    expect(flashes[0].message).toContain("MX verified");
    expect(flashes[0].message).toContain("SPF verified");
    expect(flashes[0].message).toContain("DMARC verified");
    // BOTH manual leftovers are listed (docs/DOMAINS.md §1.4 + §1.6)
    expect(flashes[0].message).toContain("Email Sending");
    expect(flashes[0].message).toContain("destination address");
    // no operator Cloudflare internals in user-facing output
    expect(flashes[0].message).not.toContain("zone-apex");
  });

  it("subdomain: routing via POST email/routing/dns {name}, catch-all left alone", async () => {
    const user = await createUser(env.DB);
    const zoneName = `par${user.id}.example.org`;
    const domain = `mail.${zoneName}`;
    fake.zones.push({ id: "zone-par", name: zoneName });
    // the zone catch-all already routes to this worker (per-zone rule)
    fake.catchAll.set("zone-par", {
      enabled: true,
      name: "existing",
      matchers: [{ type: "all" }],
      actions: [{ type: "worker", value: ["simplelogin"] }],
    });
    const id = await makeDomain(user.id, domain, "toksub");
    const cookie = await sessionCookieFor(user.id);

    const res = await provision(id, cookie);
    expect(res.status).toBe(302);

    expect(fake.calls.map((c) => [c.method, c.path])).toEqual([
      ["GET", `/client/v4/zones?name=${domain}`], // exact name: no zone
      ["GET", `/client/v4/zones?name=${zoneName}`], // parent label: found
      ["GET", "/client/v4/zones/zone-par/email/routing/rules/catch_all"],
      [
        "GET",
        `/client/v4/zones/zone-par/dns_records?type=MX&name.exact=${domain}`,
      ],
      ["POST", "/client/v4/zones/zone-par/email/routing/dns"],
      [
        "GET",
        `/client/v4/zones/zone-par/dns_records?type=TXT&name.exact=${domain}`,
      ],
      ["POST", "/client/v4/zones/zone-par/dns_records"],
      [
        "GET",
        `/client/v4/zones/zone-par/dns_records?type=TXT&name.exact=_dmarc.${domain}`,
      ],
      ["POST", "/client/v4/zones/zone-par/dns_records"],
    ]);
    const routingDns = fake.calls.find((c) =>
      c.path.endsWith("/email/routing/dns"),
    );
    expect(routingDns?.body).toEqual({ name: domain });

    expect(await domainFlags(id)).toEqual(ALL_FLAGS);
    const flashes = await getFlashes(cookie);
    expect(flashes[0].category).toBe("success");
    expect(flashes[0].message).toContain(
      "catch-all already routes to worker simplelogin",
    );
    // the enclosing zone's name/id are the operator's business, not the
    // user's (`zone <name> found` used to leak it)
    expect(flashes[0].message).not.toContain(`zone ${zoneName}`);
    expect(flashes[0].message).not.toContain("zone-par");
  });
});

describe("cf-provision: refusals and errors", () => {
  it("refuses when an enabled catch-all points elsewhere — before ANY write", async () => {
    const user = await createUser(env.DB);
    const domain = `busy${user.id}.example.org`;
    fake.zones.push({ id: "zone-busy", name: domain });
    fake.routingEnabled.add("zone-busy");
    fake.catchAll.set("zone-busy", {
      enabled: true,
      name: "ops forward",
      matchers: [{ type: "all" }],
      actions: [{ type: "forward", value: ["ops@elsewhere.example"] }],
    });
    const id = await makeDomain(user.id, domain, "tokbusy");
    const cookie = await sessionCookieFor(user.id);

    const res = await provision(id, cookie);
    expect(res.status).toBe(302);

    // aborted at the read-only preflight: zone lookup + catch-all GET only
    expect(fake.calls.map((c) => [c.method, c.path])).toEqual([
      ["GET", `/client/v4/zones?name=${domain}`],
      ["GET", "/client/v4/zones/zone-busy/email/routing/rules/catch_all"],
    ]);
    expect(fake.writes()).toEqual([]);
    expect(await domainFlags(id)).toEqual(NO_FLAGS);
    const flashes = await getFlashes(cookie);
    expect(flashes).toHaveLength(1);
    expect(flashes[0].category).toBe("error");
    expect(flashes[0].message).toContain("Refusing to change the catch-all");
    expect(flashes[0].message).toContain(domain);
  });

  it("refuses a DISABLED catch-all that still carries a foreign destination (PUT would destroy it)", async () => {
    const user = await createUser(env.DB);
    const domain = `paused${user.id}.example.org`;
    fake.zones.push({ id: "zone-paused", name: domain });
    fake.catchAll.set("zone-paused", {
      enabled: false,
      name: "temporarily off",
      matchers: [{ type: "all" }],
      actions: [{ type: "forward", value: ["ops@company.example"] }],
    });
    const id = await makeDomain(user.id, domain, "tokpause");
    const cookie = await sessionCookieFor(user.id);

    const res = await provision(id, cookie);
    expect(res.status).toBe(302);
    expect(fake.writes()).toEqual([]);
    // the stored forward target survives untouched
    expect(fake.catchAll.get("zone-paused")?.actions).toEqual([
      { type: "forward", value: ["ops@company.example"] },
    ]);
    const flashes = await getFlashes(cookie);
    expect(flashes[0].category).toBe("error");
    expect(flashes[0].message).toContain("Refusing to change the catch-all");
    expect(await domainFlags(id)).toEqual(NO_FLAGS);
  });

  it("refuses an ENABLED drop-only catch-all (deliberate reject-all)", async () => {
    const user = await createUser(env.DB);
    const domain = `dropall${user.id}.example.org`;
    fake.zones.push({ id: "zone-drop", name: domain });
    fake.catchAll.set("zone-drop", {
      enabled: true,
      name: "reject everything",
      matchers: [{ type: "all" }],
      actions: [{ type: "drop" }],
    });
    const id = await makeDomain(user.id, domain, "tokdrop");
    const cookie = await sessionCookieFor(user.id);

    const res = await provision(id, cookie);
    expect(res.status).toBe(302);
    expect(fake.writes()).toEqual([]);
    const flashes = await getFlashes(cookie);
    expect(flashes[0].category).toBe("error");
    expect(flashes[0].message).toContain("Refusing to change the catch-all");
    expect(await domainFlags(id)).toEqual(NO_FLAGS);
  });

  it("refuses to enable Email Routing when the name already has foreign MX records", async () => {
    const user = await createUser(env.DB);
    const domain = `legacy${user.id}.example.org`;
    fake.zones.push({ id: "zone-legacy", name: domain });
    fake.dnsRecords.push({
      id: "mx-foreign",
      zoneId: "zone-legacy",
      type: "MX",
      name: domain,
      content: "mail.protonmail.ch",
    });
    const id = await makeDomain(user.id, domain, "toklegacy");
    const cookie = await sessionCookieFor(user.id);

    const res = await provision(id, cookie);
    expect(res.status).toBe(302);
    // reads only — no enable, no dns writes: the existing mail setup stays
    expect(fake.calls.map((c) => [c.method, c.path])).toEqual([
      ["GET", `/client/v4/zones?name=${domain}`],
      ["GET", "/client/v4/zones/zone-legacy/email/routing/rules/catch_all"],
      [
        "GET",
        `/client/v4/zones/zone-legacy/dns_records?type=MX&name.exact=${domain}`,
      ],
    ]);
    expect(fake.writes()).toEqual([]);
    const flashes = await getFlashes(cookie);
    expect(flashes[0].category).toBe("error");
    expect(flashes[0].message).toContain("Refusing to enable Email Routing");
    expect(flashes[0].message).toContain(domain);
    expect(await domainFlags(id)).toEqual(NO_FLAGS);
  });

  it("flashes a clear error when no zone is found in the account", async () => {
    const user = await createUser(env.DB);
    const domain = `nozone${user.id}.example.org`;
    const id = await makeDomain(user.id, domain, "toknozone");
    const cookie = await sessionCookieFor(user.id);

    const res = await provision(id, cookie);
    expect(res.status).toBe(302);

    // walked the labels, nothing else
    expect(fake.calls.map((c) => [c.method, c.path])).toEqual([
      ["GET", `/client/v4/zones?name=${domain}`],
      ["GET", "/client/v4/zones?name=example.org"],
    ]);
    const flashes = await getFlashes(cookie);
    expect(flashes).toHaveLength(1);
    expect(flashes[0].category).toBe("error");
    expect(flashes[0].message).toContain(domain);
    expect(flashes[0].message).toContain(
      "Add the domain to your Cloudflare account first",
    );
    expect(await domainFlags(id)).toEqual(NO_FLAGS);
  });

  it("caps the zone walk at 5 lookups for a many-label domain", async () => {
    const user = await createUser(env.DB);
    const domain = `a.b.c.d.e.f.g.h.i.deep${user.id}.example.org`;
    const id = await makeDomain(user.id, domain, "tokdeep");
    const cookie = await sessionCookieFor(user.id);

    const res = await provision(id, cookie);
    expect(res.status).toBe(302);
    // exact name + the 4 shortest suffixes only — not one GET per label
    expect(fake.calls.map((c) => c.path)).toEqual([
      `/client/v4/zones?name=${domain}`,
      `/client/v4/zones?name=h.i.deep${user.id}.example.org`,
      `/client/v4/zones?name=i.deep${user.id}.example.org`,
      `/client/v4/zones?name=deep${user.id}.example.org`,
      "/client/v4/zones?name=example.org",
    ]);
    const flashes = await getFlashes(cookie);
    expect(flashes[0].category).toBe("error");
  });

  it("surfaces Cloudflare API errors as a redacted flash that keeps the completed steps", async () => {
    const user = await createUser(env.DB);
    const domain = `apierr${user.id}.example.org`;
    fake.zones.push({ id: "zone-err", name: domain });
    // make the routing enable 403 (e.g. token missing a scope)
    const realFetch = fake.fetch;
    fake.fetch = async (input, init) => {
      if ((init?.method ?? "GET") === "POST" && input.endsWith("/enable")) {
        return Response.json(
          {
            success: false,
            errors: [{ code: 10000, message: "Authentication error" }],
            result: null,
          },
          { status: 403 },
        );
      }
      return realFetch(input, init);
    };
    const id = await makeDomain(user.id, domain, "tokerr");
    const cookie = await sessionCookieFor(user.id);

    const res = await provision(id, cookie);
    expect(res.status).toBe(302);
    const flashes = await getFlashes(cookie);
    expect(flashes).toHaveLength(1);
    expect(flashes[0].category).toBe("error");
    expect(flashes[0].message).toContain("Cloudflare API error");
    // the CF error message survives, the request path (zone id!) does not
    expect(flashes[0].message).toContain("Authentication error");
    expect(flashes[0].message).not.toContain("/zones/");
    expect(flashes[0].message).not.toContain("zone-err");
    // completed steps + retry guidance are reported
    expect(flashes[0].message).toContain("zone found");
    expect(flashes[0].message).toContain("safe to retry");
  });

  it("flashes (not 500s) when the Cloudflare API is unreachable at network level", async () => {
    const user = await createUser(env.DB);
    const domain = `netdown${user.id}.example.org`;
    fake.fetch = async () => {
      throw new TypeError("connection reset");
    };
    const id = await makeDomain(user.id, domain, "toknet");
    const cookie = await sessionCookieFor(user.id);

    const res = await provision(id, cookie);
    expect(res.status).toBe(302); // error flash + redirect, no 500 page
    const flashes = await getFlashes(cookie);
    expect(flashes).toHaveLength(1);
    expect(flashes[0].category).toBe("error");
    expect(flashes[0].message).toContain("Cloudflare API error");
    expect(flashes[0].message).toContain("request failed");
    expect(flashes[0].message).not.toContain("/zones");
    expect(await domainFlags(id)).toEqual(NO_FLAGS);
  });
});

describe("cf-provision: feature gate", () => {
  it("without CF_API_TOKEN the button is absent and the POST branch is inert", async () => {
    envx.CF_API_TOKEN = ""; // "" = unset (vitest convention)
    const user = await createUser(env.DB);
    const domain = `gated${user.id}.example.org`;
    fake.zones.push({ id: "zone-gated", name: domain });
    const id = await makeDomain(user.id, domain, "tokgated");
    const cookie = await sessionCookieFor(user.id);

    const page = await get(`/dashboard/domains/${id}/dns`, cookie);
    const html = await page.text();
    expect(html).not.toContain("cf-provision");
    expect(html).not.toContain("Auto-configure on Cloudflare");

    // POST behaves like an unknown form-name: renders the page, no effects
    const res = await provision(id, cookie);
    expect(res.status).toBe(200);
    expect(fake.calls).toEqual([]);
    expect(await getFlashes(cookie)).toEqual([]);
    expect(await domainFlags(id)).toEqual(NO_FLAGS);
  });

  it("SL subdomains never render nor handle the cf-provision form", async () => {
    const user = await createUser(env.DB);
    const domain = `me${user.id}.subs.example.net`;
    fake.zones.push({ id: "zone-subs", name: "subs.example.net" });
    const row = await env.DB.prepare(
      `INSERT INTO custom_domain
         (user_id, domain, ownership_txt_token, is_sl_subdomain,
          ownership_verified, verified)
       VALUES (?1, ?2, 'toksl', 1, 1, 1) RETURNING id`,
    )
      .bind(user.id, domain)
      .first<{ id: number }>();
    const id = row?.id as number;
    const cookie = await sessionCookieFor(user.id);

    const page = await get(`/dashboard/domains/${id}/dns`, cookie);
    const html = await page.text();
    expect(html).not.toContain('value="cf-provision"');
    expect(html).not.toContain("Auto-configure on Cloudflare");

    const res = await provision(id, cookie);
    expect(res.status).toBe(200); // unknown form-name fallthrough
    expect(fake.calls).toEqual([]);
    expect(await getFlashes(cookie)).toEqual([]);
  });
});

describe("cf-provision: rate limit", () => {
  it("returns 429 without spending any Cloudflare API call once the limit is hit", async () => {
    const user = await createUser(env.DB);
    const domain = `rl${user.id}.example.org`;
    fake.zones.push({ id: "zone-rl", name: domain });
    const id = await makeDomain(user.id, domain, "tokrl");
    const cookie = await sessionCookieFor(user.id);

    // Seed BOTH fixed windows at their limits instead of looping requests
    // (deterministic; immune to a minute-window rollover mid-test).
    const now = Date.now() / 1000;
    for (const [seconds, limit] of [
      [60, 3],
      [3600, 20],
    ] as const) {
      await env.DB.prepare(
        "INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, ?3)",
      )
        .bind(
          `rlw:web_cf_provision:userid:${user.id}:${seconds}`,
          Math.floor(now / seconds),
          limit,
        )
        .run();
    }

    const res = await provision(id, cookie);
    expect(res.status).toBe(429);
    expect(fake.calls).toEqual([]);
    expect(await domainFlags(id)).toEqual(NO_FLAGS);
  });
});

describe("cf-provision: idempotency", () => {
  it("re-clicking performs no writes and reports already-configured steps", async () => {
    const user = await createUser(env.DB);
    const domain = `again${user.id}.example.org`;
    fake.zones.push({ id: "zone-again", name: domain });
    const id = await makeDomain(user.id, domain, "tokagain");
    const cookie = await sessionCookieFor(user.id);

    const first = await provision(id, cookie);
    expect(first.status).toBe(302);
    const writesAfterFirst = fake.writes().length;
    expect(writesAfterFirst).toBeGreaterThan(0);
    expect(await domainFlags(id)).toEqual(ALL_FLAGS);
    await clearFlashes(cookie);

    const second = await provision(id, cookie);
    expect(second.status).toBe(302);
    // check-before-write: no duplicate creates on the re-run
    expect(fake.writes().length).toBe(writesAfterFirst);
    expect(
      fake.dnsRecords.filter(
        (r) =>
          r.type === "TXT" &&
          r.name === domain &&
          r.content.includes("sl-verification"),
      ),
    ).toHaveLength(1);
    const flashes = await getFlashes(cookie);
    expect(flashes).toHaveLength(1);
    expect(flashes[0].category).toBe("success");
    expect(flashes[0].message).toContain("Email Routing already enabled");
    expect(flashes[0].message).toContain("catch-all already routes");
    expect(flashes[0].message).toContain("DMARC record already present");
    expect(flashes[0].message).toContain("ownership already verified");
    expect(flashes[0].message).toContain("MX already verified");
    expect(flashes[0].message).toContain("SPF already verified");
    expect(flashes[0].message).toContain("DMARC already verified");
  });
});

describe("cf-provision: deployment-domain collision guard", () => {
  it("refuses subdomains of EMAIL_DOMAIN without any API call", async () => {
    // EMAIL_DOMAIN is sl.example.com in the test env (vitest.config.ts)
    const user = await createUser(env.DB);
    const domain = "hijack.sl.example.com";
    fake.zones.push({ id: "zone-own", name: "sl.example.com" });
    const id = await makeDomain(user.id, domain, "tokhijack");
    const cookie = await sessionCookieFor(user.id);

    const res = await provision(id, cookie);
    expect(res.status).toBe(302);
    expect(fake.calls).toEqual([]);
    const flashes = await getFlashes(cookie);
    expect(flashes).toHaveLength(1);
    expect(flashes[0].category).toBe("error");
    expect(flashes[0].message).toContain("overlaps");
    expect(flashes[0].message).toContain("sl.example.com");
    expect(await domainFlags(id)).toEqual(NO_FLAGS);
  });

  it("refuses parents of a deployment domain too", async () => {
    const user = await createUser(env.DB);
    const domain = "example.com"; // parent of sl.example.com
    const id = await makeDomain(user.id, domain, "tokparent");
    const cookie = await sessionCookieFor(user.id);

    const res = await provision(id, cookie);
    expect(res.status).toBe(302);
    expect(fake.calls).toEqual([]);
    const flashes = await getFlashes(cookie);
    expect(flashes[0].category).toBe("error");
    expect(flashes[0].message).toContain("overlaps");
  });

  it("refuses SIBLING hostnames whose resolved zone hosts the deployment's domains", async () => {
    // EMAIL_DOMAIN sl.example.com lives inside the operator's example.com
    // zone (the live topology: mail.example.com inside example.com). A
    // sibling name passes the string guard but must be caught at the zone
    // boundary — token zone-scoping cannot help, since the token must be
    // able to edit the very zone hosting EMAIL_DOMAIN.
    const user = await createUser(env.DB);
    const domain = `evil${user.id}.example.com`;
    fake.zones.push({ id: "zone-deploy", name: "example.com" });
    const id = await makeDomain(user.id, domain, "tokevil");
    const cookie = await sessionCookieFor(user.id);

    const res = await provision(id, cookie);
    expect(res.status).toBe(302);
    // findZone ran (string guard passes) — but nothing was written and no
    // routing/TXT call ever happened
    expect(fake.calls.map((c) => [c.method, c.path])).toEqual([
      ["GET", `/client/v4/zones?name=${domain}`],
      ["GET", "/client/v4/zones?name=example.com"],
    ]);
    expect(fake.writes()).toEqual([]);
    const flashes = await getFlashes(cookie);
    expect(flashes).toHaveLength(1);
    expect(flashes[0].category).toBe("error");
    expect(flashes[0].message).toContain(
      "hosts this SimpleLogin deployment's own domains",
    );
    expect(await domainFlags(id)).toEqual(NO_FLAGS);
  });

  it("protects public_domain rows that are not mirrored into ALIAS_DOMAINS", async () => {
    const user = await createUser(env.DB);
    const pub = `pub${user.id}.example.net`;
    await env.DB.prepare("INSERT INTO public_domain (domain) VALUES (?1)")
      .bind(pub)
      .run();
    const domain = `sub.${pub}`;
    const id = await makeDomain(user.id, domain, "tokpub");
    const cookie = await sessionCookieFor(user.id);

    const res = await provision(id, cookie);
    expect(res.status).toBe(302);
    expect(fake.calls).toEqual([]);
    const flashes = await getFlashes(cookie);
    expect(flashes[0].category).toBe("error");
    expect(flashes[0].message).toContain("overlaps");
    expect(flashes[0].message).toContain(pub);
    expect(await domainFlags(id)).toEqual(NO_FLAGS);
  });

  it("protects PREMIUM_ALIAS_DOMAINS entries", async () => {
    envx.PREMIUM_ALIAS_DOMAINS = "prem.example.net";
    const user = await createUser(env.DB);
    const domain = `x${user.id}.prem.example.net`;
    const id = await makeDomain(user.id, domain, "tokprem");
    const cookie = await sessionCookieFor(user.id);

    const res = await provision(id, cookie);
    expect(res.status).toBe(302);
    expect(fake.calls).toEqual([]);
    const flashes = await getFlashes(cookie);
    expect(flashes[0].category).toBe("error");
    expect(flashes[0].message).toContain("overlaps");
    expect(flashes[0].message).toContain("prem.example.net");
  });
});
