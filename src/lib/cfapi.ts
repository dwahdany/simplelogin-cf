/**
 * Minimal typed Cloudflare v4 API client for one-click domain provisioning
 * from the dashboard (src/web/mailbox-domain-pages.ts, "cf-provision" form).
 * The operations mirror scripts/provision-domain.mjs, whose endpoints were
 * verified against developers.cloudflare.com/api on 2026-07-26:
 *
 * - GET  /zones?name=<domain>                                (zone lookup)
 * - GET  /zones/{id}/email/routing                           (settings: enabled/status)
 * - POST /zones/{id}/email/routing/enable          body {}   (apex: enable + lock MX/SPF)
 * - POST /zones/{id}/email/routing/dns             body {name} (subdomain routing records)
 * - GET|PUT /zones/{id}/email/routing/rules/catch_all        (catch-all rule)
 * - GET|POST /zones/{id}/dns_records  (?type=&name.exact=)   (TXT records)
 *
 * The catch-all `worker` action value is under-documented in the API schema
 * ("optional array of string"); dashboard-created rules return
 * {type:"worker", value:["<worker script name>"]}, which is what we send.
 *
 * Every ensure* helper is check-before-write (idempotent, safe to re-run)
 * and NEVER modifies an existing record/rule:
 * - ensureCatchAllToWorker throws the typed CatchAllConflictError instead of
 *   overwriting a catch-all that carries any foreign (non-drop, non-worker)
 *   action — even a DISABLED one (the PUT replaces the whole rule body, so
 *   overwriting would destroy a stored forward target) — or an enabled
 *   drop-only rule (a deliberate reject-all). `catchAllConflict` exposes the
 *   same check read-only so callers can refuse BEFORE any write.
 * - ensureEmailRouting throws the typed ForeignMxError instead of enabling
 *   routing for a name that already has non-Cloudflare MX records (enabling
 *   would hijack/split delivery of mail that currently goes elsewhere — on
 *   the live deployment the apex zone's mail is Protonmail's).
 * Network-level fetch rejections are rethrown as CfApiError with status 0 so
 * callers have a single error type for "the Cloudflare API call failed".
 *
 * The client authenticates with either the operator's static CF_API_TOKEN or
 * a per-user Cloudflare OAuth grant — see CfCredential below.
 */

const API_BASE = "https://api.cloudflare.com/client/v4";

// ---------------------------------------------------------------------------
// fetch test seam (modeled on setMailboxDnsClient in
// src/web/mailbox-domain-pages.ts — tests run in the same isolate as SELF)
// ---------------------------------------------------------------------------

export type CfFetch = (input: string, init?: RequestInit) => Promise<Response>;

const realCfFetch: CfFetch = (input, init) => fetch(input, init);

let cfFetch: CfFetch = realCfFetch;

/** Test seam (tests run in the same isolate as SELF). `null` restores fetch. */
export function setCfFetch(f: CfFetch | null): void {
  cfFetch = f ?? realCfFetch;
}

// ---------------------------------------------------------------------------
// types
// ---------------------------------------------------------------------------

export interface CfZone {
  id: string;
  name: string;
  /**
   * Owning account, as returned by GET /zones. Optional because callers must
   * not depend on it (an older/partial response, or a fake in tests, may omit
   * it) — the account check in handleCfProvision fails OPEN when it is
   * absent, rather than blocking every provisioning run on a response shape.
   */
  account?: { id?: string; name?: string };
}

export interface CfEmailRoutingSettings {
  enabled?: boolean;
  status?: string;
}

export interface CfEmailRoutingAction {
  type: string;
  value?: string[];
}

export interface CfCatchAllRule {
  enabled?: boolean;
  name?: string;
  matchers?: Array<{ type: string }>;
  actions?: CfEmailRoutingAction[];
}

export interface CfDnsRecord {
  id?: string;
  type: string;
  name: string;
  content: string;
  ttl?: number;
  comment?: string;
}

interface CfEnvelope<T> {
  success: boolean;
  result: T;
  errors?: Array<{ code?: number; message?: string }>;
}

export class CfApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly errors: Array<{ code?: number; message?: string }> = [],
  ) {
    super(message);
  }
}

/**
 * Typed refusal: the zone's catch-all rule routes (or is configured to
 * route) mail somewhere other than our worker. Overwriting it would silently
 * reroute the zone's other mail flows — or, for a disabled rule, destroy its
 * stored destination (the PUT replaces the whole rule body) — so callers
 * must surface this to the operator instead of writing.
 */
export class CatchAllConflictError extends Error {
  constructor(
    readonly zoneName: string,
    readonly actions: CfEmailRoutingAction[],
  ) {
    super(
      `catch-all rule on zone ${zoneName} points elsewhere: ` +
        JSON.stringify(actions),
    );
  }
}

/**
 * Typed refusal: the target name already has MX records that are NOT
 * Cloudflare Email Routing's. Enabling routing there would add Cloudflare's
 * MX next to (apex: instead of) the existing ones, hijacking or splitting
 * delivery of mail that currently goes elsewhere.
 */
export class ForeignMxError extends Error {
  constructor(
    readonly domain: string,
    readonly records: CfDnsRecord[],
  ) {
    super(
      `${domain} already has non-Cloudflare MX records: ` +
        records.map((r) => r.content).join(", "),
    );
  }
}

// ---------------------------------------------------------------------------
// client
// ---------------------------------------------------------------------------

/**
 * A bearer token, resolved lazily before EVERY request. Used for the per-user
 * Cloudflare OAuth grant (src/lib/cfoauth.ts `getValidAccessToken`), whose
 * access token is short-lived: one provisioning run makes up to ~9 calls and
 * the token can hit its refresh window between two of them, so the credential
 * must be re-resolved per request rather than captured once.
 *
 * The provider may throw. A CfApiError is propagated unchanged (callers can
 * use its status, e.g. 401, to say "reconnect your Cloudflare account");
 * anything else is wrapped as CfApiError with status 0, so callers still have
 * exactly one error type for "the Cloudflare API call failed".
 */
export type CfTokenProvider = () => string | Promise<string>;

/** Static token string (operator CF_API_TOKEN) or a per-request provider. */
export type CfCredential = string | CfTokenProvider;

export class CfClient {
  /**
   * @param credential a token string (unchanged legacy form) or a
   * CfTokenProvider resolved before every request.
   */
  constructor(private readonly credential: CfCredential) {}

  /** The bearer token for the next request (see CfTokenProvider). */
  private async resolveToken(method: string, path: string): Promise<string> {
    if (typeof this.credential === "string") return this.credential;
    try {
      return await this.credential();
    } catch (e) {
      if (e instanceof CfApiError) throw e;
      throw new CfApiError(
        `${method} ${path}: no usable Cloudflare credential: ${e instanceof Error ? e.message : String(e)}`,
        0,
      );
    }
  }

  /** Cloudflare v4 envelope fetch: returns `result` or throws CfApiError. */
  private async request<T>(
    path: string,
    opts: { method?: string; body?: unknown } = {},
  ): Promise<T> {
    const { method = "GET", body } = opts;
    const token = await this.resolveToken(method, path);
    let res: Response;
    try {
      res = await cfFetch(`${API_BASE}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          ...(body !== undefined ? { "content-type": "application/json" } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (e) {
      // fetch rejections (connection reset, DNS failure, subrequest limit)
      // become CfApiError too, so callers flash instead of 500ing.
      throw new CfApiError(
        `${method} ${path} network error: ${e instanceof Error ? e.message : String(e)}`,
        0,
      );
    }
    let data: CfEnvelope<T> | null = null;
    try {
      data = (await res.json()) as CfEnvelope<T>;
    } catch {
      /* non-JSON body — fall through */
    }
    if (!data || typeof data !== "object") {
      throw new CfApiError(
        `${method} ${path} -> HTTP ${res.status} (non-JSON response)`,
        res.status,
      );
    }
    if (!data.success) {
      const errs =
        (data.errors ?? []).map((e) => `[${e.code}] ${e.message}`).join("; ") ||
        `HTTP ${res.status}`;
      throw new CfApiError(
        `${method} ${path} failed: ${errs}`,
        res.status,
        data.errors ?? [],
      );
    }
    return data.result;
  }

  /**
   * Find the enclosing zone for `domain` by exact name, then walking up
   * parent labels: sl.example.com -> "sl.example.com", then "example.com".
   * The walk is capped at 5 lookups (the exact name plus the 4 shortest
   * suffixes — zone apexes are registrable domains, rarely deeper than 4
   * labels) so a many-label domain cannot burn ~1 GET /zones per label of
   * the operator's API quota.
   */
  async findZone(domain: string): Promise<CfZone | null> {
    const labels = domain.split(".");
    const starts: number[] = [];
    for (let i = 0; i <= labels.length - 2; i++) starts.push(i);
    const capped = starts.length > 5 ? [0, ...starts.slice(-4)] : starts;
    for (const i of capped) {
      const candidate = labels.slice(i).join(".");
      const zones = await this.request<CfZone[] | null>(
        `/zones?name=${encodeURIComponent(candidate)}`,
      );
      const zone = (zones ?? []).find((z) => z.name === candidate);
      if (zone) return zone;
    }
    return null;
  }

  getEmailRoutingSettings(
    zoneId: string,
  ): Promise<CfEmailRoutingSettings | null> {
    return this.request(`/zones/${zoneId}/email/routing`);
  }

  /** Apex only: enables Email Routing, creating + locking the MX/SPF set. */
  enableEmailRouting(zoneId: string): Promise<CfEmailRoutingSettings | null> {
    return this.request(`/zones/${zoneId}/email/routing/enable`, {
      method: "POST",
      body: {},
    });
  }

  /** Subdomain: registers `name`'s Email Routing DNS (MX/SPF) records. */
  addEmailRoutingDns(zoneId: string, name: string): Promise<unknown> {
    return this.request(`/zones/${zoneId}/email/routing/dns`, {
      method: "POST",
      body: { name },
    });
  }

  getCatchAll(zoneId: string): Promise<CfCatchAllRule | null> {
    return this.request(`/zones/${zoneId}/email/routing/rules/catch_all`);
  }

  putCatchAllToWorker(
    zoneId: string,
    worker: string,
  ): Promise<CfCatchAllRule | null> {
    return this.request(`/zones/${zoneId}/email/routing/rules/catch_all`, {
      method: "PUT",
      body: {
        enabled: true,
        name: `simplelogin: route all mail to worker "${worker}"`,
        matchers: [{ type: "all" }],
        actions: [{ type: "worker", value: [worker] }],
      },
    });
  }

  listDnsRecords(
    zoneId: string,
    query: { type: string; name: string },
  ): Promise<CfDnsRecord[] | null> {
    const qs = `type=${encodeURIComponent(query.type)}&name.exact=${encodeURIComponent(query.name)}`;
    return this.request(`/zones/${zoneId}/dns_records?${qs}`);
  }

  createDnsRecord(
    zoneId: string,
    record: CfDnsRecord,
  ): Promise<CfDnsRecord | null> {
    return this.request(`/zones/${zoneId}/dns_records`, {
      method: "POST",
      body: record,
    });
  }
}

// ---------------------------------------------------------------------------
// idempotent provisioning steps (check-before-write, mirroring the script)
// ---------------------------------------------------------------------------

export type EnsureOutcome = "created" | "already";

const CF_ROUTING_MX_RE = /\.mx\.cloudflare\.net$/i;

/**
 * Enable Email Routing for `domain`. Apex (domain === zone.name): the
 * zone-level enable endpoint. Subdomain: the routing-DNS endpoint with the
 * subdomain name; idempotency check is the route*.mx.cloudflare.net MX
 * records already existing at the subdomain (same as the script).
 * REFUSES (typed ForeignMxError, before any write) when the name already
 * has non-Cloudflare MX records: the apex enable replaces/locks the MX set
 * and a subdomain write would add Cloudflare MX next to the foreign ones,
 * splitting delivery — mail that currently goes elsewhere must never be
 * silently rerouted.
 */
export async function ensureEmailRouting(
  client: CfClient,
  zone: CfZone,
  domain: string,
): Promise<EnsureOutcome> {
  const mx =
    (await client.listDnsRecords(zone.id, { type: "MX", name: domain })) ?? [];
  const foreign = mx.filter((r) => !CF_ROUTING_MX_RE.test(r.content ?? ""));
  if (foreign.length > 0) throw new ForeignMxError(domain, foreign);
  if (zone.name === domain) {
    const settings = await client.getEmailRoutingSettings(zone.id);
    if (settings?.enabled) return "already";
    await client.enableEmailRouting(zone.id);
    return "created";
  }
  const routed = mx.filter((r) => CF_ROUTING_MX_RE.test(r.content ?? ""));
  if (routed.length >= 3) return "already";
  await client.addEmailRoutingDns(zone.id, domain);
  return "created";
}

/**
 * Read-only conflict check for pointing the catch-all at `worker`. Returns
 * the rule's actions when the rule must NOT be overwritten, null when a PUT
 * is safe. Conflicts, regardless of `enabled` (the PUT replaces the whole
 * rule body, so overwriting a disabled rule destroys its stored target):
 * - any foreign action (non-drop, not the worker action for `worker`);
 * - an ENABLED drop-only rule (a deliberate reject-all: mail the zone owner
 *   rejects must not silently start flowing into the worker). A DISABLED
 *   drop-only rule is Cloudflare's default state and safe to replace.
 */
export function catchAllConflict(
  rule: CfCatchAllRule | null,
  worker: string,
): CfEmailRoutingAction[] | null {
  if (!rule) return null;
  const actions = rule.actions ?? [];
  const foreign = actions.filter(
    (a) =>
      a.type !== "drop" &&
      !(a.type === "worker" && (a.value ?? []).includes(worker)),
  );
  if (foreign.length > 0) return actions;
  const live = actions.filter((a) => a.type !== "drop");
  if (rule.enabled && live.length === 0 && actions.length > 0) return actions;
  return null;
}

/**
 * Point the zone catch-all rule at `worker`. Writes ONLY when the current
 * rule is absent, disabled drop-only/actionless, or already ours-but-
 * disabled; "already" when it is enabled and routes to this worker; throws
 * CatchAllConflictError per `catchAllConflict` above. Callers that already
 * fetched the rule (e.g. for a pre-write conflict check) can pass it as
 * `prefetched` to skip the extra GET.
 */
export async function ensureCatchAllToWorker(
  client: CfClient,
  zone: CfZone,
  worker: string,
  prefetched?: CfCatchAllRule | null,
): Promise<EnsureOutcome> {
  const rule =
    prefetched !== undefined ? prefetched : await client.getCatchAll(zone.id);
  const conflict = catchAllConflict(rule, worker);
  if (conflict) throw new CatchAllConflictError(zone.name, conflict);
  const ours = (rule?.actions ?? []).find(
    (a) => a.type === "worker" && (a.value ?? []).includes(worker),
  );
  if (rule?.enabled && ours) return "already";
  await client.putCatchAllToWorker(zone.id, worker);
  return "created";
}

/** TXT content comes back as quoted character-strings (possibly chunked). */
function normalizeTxtContent(data: string): string {
  const chunks = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
  return chunks.length ? chunks.join("") : data;
}

/**
 * Create the TXT record `name` -> `content` (unquoted; quoted on write per
 * RFC 1035) unless it already exists. With `skipIfAnyAtName`, ANY existing
 * TXT at `name` counts as "already" (used for _dmarc, where an existing
 * record — e.g. from Email Sending onboarding — must be left alone);
 * without it, only a record with this exact content does (used for the
 * ownership TXT, which coexists with SPF etc. at the domain root). Existing
 * records are never modified.
 */
export async function ensureTxtRecord(
  client: CfClient,
  zoneId: string,
  name: string,
  content: string,
  opts: { skipIfAnyAtName?: boolean; comment?: string } = {},
): Promise<EnsureOutcome> {
  const existing =
    (await client.listDnsRecords(zoneId, { type: "TXT", name })) ?? [];
  if (opts.skipIfAnyAtName && existing.length > 0) return "already";
  if (existing.some((r) => normalizeTxtContent(r.content) === content)) {
    return "already";
  }
  await client.createDnsRecord(zoneId, {
    type: "TXT",
    name,
    content: `"${content}"`,
    ttl: 1, // 1 = automatic
    ...(opts.comment !== undefined ? { comment: opts.comment } : {}),
  });
  return "created";
}
