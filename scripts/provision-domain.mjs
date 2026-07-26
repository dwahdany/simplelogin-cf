#!/usr/bin/env node
/**
 * Provision a Cloudflare zone/domain for this SimpleLogin deployment:
 * Email Routing + catch-all-to-worker + (optional) DMARC record, plus a
 * read-only Email Sending onboarding check. App-side steps (public_domain
 * row, ALIAS_DOMAINS, redeploy) are printed as a checklist — see
 * docs/DOMAINS.md for the full runbook.
 *
 * Usage:  CLOUDFLARE_API_TOKEN=... node scripts/provision-domain.mjs \
 *             --zone mail.example.com [--worker simplelogin] [--dmarc]
 *
 * Requires Node 22+ (global fetch, util.parseArgs). No dependencies.
 * Idempotent: every step checks current state before writing and skips
 * cleanly on re-runs; it REFUSES to overwrite a live catch-all rule that
 * points somewhere else (see step 3).
 *
 * All endpoints verified against developers.cloudflare.com/api on 2026-07-26:
 * - GET  /zones?name=<domain>                                (zone lookup)
 * - GET  /zones/{id}/email/routing                           (settings: enabled/status)
 * - POST /zones/{id}/email/routing/enable          body {}   (apex: enable + lock MX/SPF)
 * - POST /zones/{id}/email/routing/dns             body {name} (subdomain routing records)
 * - GET|PUT /zones/{id}/email/routing/rules/catch_all        (catch-all rule)
 * - GET|POST /zones/{id}/dns_records  (?type=&name.exact=)   (DMARC TXT)
 * - GET  /zones/{id}/email/sending/subdomains                (Email Sending, read-only)
 *
 * Known API gaps (manual dashboard steps, printed at the end):
 * - Email Sending onboarding for a zone APEX has no public write API as of
 *   2026-07-26 — the docs only describe the dashboard flow (Compute > Email
 *   Service > Email Sending > Onboard Domain). A subdomains write endpoint
 *   exists (POST /zones/{id}/email/sending/subdomains) but its `name`
 *   semantics are under-documented, so this script only READS sending state
 *   and never writes it. Onboarding is REQUIRED for FORWARD_MODE=rewrite.
 * - The catch-all `worker` action value is under-documented in the API
 *   schema ("optional array of string"); dashboard-created rules return
 *   {type:"worker", value:["<worker script name>"]}, which is what we send.
 */

import { parseArgs } from "node:util";

const API = "https://api.cloudflare.com/client/v4";
// Same record the dashboard instructs custom-domain owners to publish
// (src/web/mailbox-domain-pages.ts DMARC_RECORD).
const DMARC_RECORD = "v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s";

const HELP = `provision-domain.mjs — Cloudflare-side setup for a SimpleLogin email domain

Usage:
  CLOUDFLARE_API_TOKEN=... node scripts/provision-domain.mjs --zone <domain> [options]

Arguments:
  --zone <domain>    The email domain to provision. May be a zone apex
                     (example.com) or a subdomain of an existing zone
                     (sl.example.com) — the enclosing zone is auto-detected.
  --worker <name>    Worker script that receives the mail (default: simplelogin).
  --dmarc            Also create the _dmarc TXT record
                     ("${DMARC_RECORD}").
  --help             This text.

Token:
  CLOUDFLARE_API_TOKEN must be a SCOPED API token
  (dash.cloudflare.com/profile/api-tokens) with at least:
    Zone > Zone            : Read
    Zone > DNS             : Edit
    Zone > Email Routing Rules : Edit
  NOTE: the OAuth token wrangler stores from "wrangler login" CANNOT write
  DNS records or email settings — it will 403 here. Create a dedicated
  scoped token instead.

What it does (idempotent, safe to re-run):
  1. Look up the zone id.
  2. Enable Email Routing (apex: POST .../email/routing/enable; subdomain:
     POST .../email/routing/dns with the subdomain name). This creates and
     locks the MX + SPF records.
  3. Point the zone catch-all rule at the worker (skips if already set;
     refuses to overwrite a live catch-all that goes somewhere else).
  4. (--dmarc) Create the _dmarc TXT record if absent.
  5. Check Email Sending onboarding (read-only) and print the remaining
     manual dashboard + app-side steps.

Examples:
  CLOUDFLARE_API_TOKEN=xxx node scripts/provision-domain.mjs --zone sl.example.com --dmarc
  CLOUDFLARE_API_TOKEN=xxx node scripts/provision-domain.mjs --zone example.com --worker simplelogin
`;

class ApiError extends Error {
  constructor(message, status, errors) {
    super(message);
    this.status = status;
    this.errors = errors;
  }
}

const TOKEN = process.env.CLOUDFLARE_API_TOKEN;

/** Cloudflare v4 envelope fetch: returns `result` or throws ApiError. */
async function cf(path, { method = "GET", body } = {}) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${TOKEN}`,
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* non-JSON body — fall through */
  }
  if (!data || typeof data !== "object")
    throw new ApiError(
      `${method} ${path} -> HTTP ${res.status} (non-JSON response)`,
      res.status,
      [],
    );
  if (!data.success) {
    const errs =
      (data.errors ?? [])
        .map((e) => `[${e.code}] ${e.message}`)
        .join("; ") || `HTTP ${res.status}`;
    throw new ApiError(`${method} ${path} failed: ${errs}`, res.status, data.errors ?? []);
  }
  return data.result;
}

const log = (msg) => console.log(msg);
const step = (msg) => console.log(`\n==> ${msg}`);
const die = (msg) => {
  console.error(`ERROR: ${msg}`);
  process.exit(1);
};

/**
 * Find the enclosing zone for `domain` by stripping leading labels:
 * sl.example.com -> try "sl.example.com", then "example.com".
 */
async function findZone(domain) {
  const labels = domain.split(".");
  for (let i = 0; i <= labels.length - 2; i++) {
    const candidate = labels.slice(i).join(".");
    const zones = await cf(`/zones?name=${encodeURIComponent(candidate)}`);
    const zone = (zones ?? []).find((z) => z.name === candidate);
    if (zone) return zone;
  }
  return null;
}

async function main() {
  const { values: args } = parseArgs({
    options: {
      zone: { type: "string" },
      worker: { type: "string", default: "simplelogin" },
      dmarc: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
  });
  if (args.help) {
    console.log(HELP);
    return;
  }
  if (!args.zone) die("--zone <domain> is required (see --help)");
  if (!TOKEN)
    die(
      "CLOUDFLARE_API_TOKEN is not set. Create a SCOPED token (Zone:Read, " +
        "DNS:Edit, Email Routing Rules:Edit) at " +
        "dash.cloudflare.com/profile/api-tokens — wrangler's OAuth token " +
        "cannot write DNS or email settings.",
    );

  const emailDomain = args.zone.toLowerCase().replace(/\.$/, "");
  const worker = args.worker;
  if (!emailDomain.includes("."))
    die(`"${emailDomain}" does not look like a domain`);
  // Manual follow-ups collected along the way, printed as a checklist.
  const manual = [];
  const failures = [];

  // -- 1. Zone lookup --------------------------------------------------------
  step(`Looking up zone for ${emailDomain}`);
  let zone;
  try {
    zone = await findZone(emailDomain);
  } catch (e) {
    die(
      `${e.message}\nHint: a 403 here usually means the token lacks Zone:Read ` +
        "or is wrangler's OAuth token (which cannot be used for this script).",
    );
  }
  if (!zone)
    die(
      `No zone in this account contains "${emailDomain}". Add the domain as ` +
        "a zone in the Cloudflare dashboard first (Account Home > Add a domain).",
    );
  const isSubdomain = zone.name !== emailDomain;
  log(
    `    zone: ${zone.name} (${zone.id})${isSubdomain ? ` — ${emailDomain} is a subdomain of it` : ""}`,
  );

  // -- 2. Email Routing ------------------------------------------------------
  step("Enabling Email Routing");
  try {
    const settings = await cf(`/zones/${zone.id}/email/routing`);
    if (!isSubdomain) {
      if (settings?.enabled) {
        log(`    already enabled (status: ${settings.status ?? "unknown"}) — skipping`);
      } else {
        const r = await cf(`/zones/${zone.id}/email/routing/enable`, {
          method: "POST",
          body: {},
        });
        log(`    enabled (status: ${r?.status ?? "unknown"}) — MX + SPF records created and locked`);
      }
    } else {
      // Subdomain: the zone-level enable endpoint only covers the apex. The
      // routing-DNS endpoint takes a `name` and creates the subdomain's
      // MX/SPF set. Idempotency check: the route*.mx.cloudflare.net MX
      // records already existing at the subdomain.
      const mx = await cf(
        `/zones/${zone.id}/dns_records?type=MX&name.exact=${encodeURIComponent(emailDomain)}`,
      );
      const routed = (mx ?? []).filter((r) => /\.mx\.cloudflare\.net$/i.test(r.content ?? ""));
      if (routed.length >= 3) {
        log(`    ${emailDomain} already has the Cloudflare routing MX set — skipping`);
      } else {
        try {
          await cf(`/zones/${zone.id}/email/routing/dns`, {
            method: "POST",
            body: { name: emailDomain },
          });
          log(`    routing DNS records created for ${emailDomain}`);
        } catch (e) {
          failures.push(`Email Routing on subdomain ${emailDomain}: ${e.message}`);
          manual.push(
            `Enable Email Routing for the subdomain in the dashboard: zone ${zone.name} > ` +
              `Compute > Email Service > Email Routing > Onboard Domain > select ${emailDomain}.`,
          );
        }
      }
    }
  } catch (e) {
    failures.push(`Email Routing: ${e.message}`);
  }

  // -- 3. Catch-all rule -> worker ------------------------------------------
  // NOTE: the catch-all is per-ZONE and applies to every routing-enabled
  // domain in it (apex + subdomains) that has no more-specific rule.
  step(`Pointing the zone catch-all rule at worker "${worker}"`);
  try {
    const rule = await cf(`/zones/${zone.id}/email/routing/rules/catch_all`);
    const actions = rule?.actions ?? [];
    const ours = actions.find(
      (a) => a.type === "worker" && (a.value ?? []).includes(worker),
    );
    const live = actions.filter((a) => a.type !== "drop");
    if (rule?.enabled && ours) {
      log("    catch-all already routes to the worker — skipping");
    } else if (rule?.enabled && live.length > 0) {
      // Overwriting would silently reroute the zone's other mail flows.
      failures.push(
        `Catch-all rule is live but points elsewhere: ${JSON.stringify(actions)}. ` +
          "Refusing to overwrite — review it in the dashboard (Email Routing > " +
          "Routing rules) and re-run, or edit it there.",
      );
    } else {
      const updated = await cf(`/zones/${zone.id}/email/routing/rules/catch_all`, {
        method: "PUT",
        body: {
          enabled: true,
          name: `simplelogin: route all mail to worker "${worker}"`,
          matchers: [{ type: "all" }],
          actions: [{ type: "worker", value: [worker] }],
        },
      });
      log(`    catch-all set (enabled: ${updated?.enabled ?? true})`);
    }
  } catch (e) {
    failures.push(`Catch-all rule: ${e.message}`);
  }

  // -- 4. DMARC --------------------------------------------------------------
  if (args.dmarc) {
    const dmarcName = `_dmarc.${emailDomain}`;
    step(`Creating DMARC record ${dmarcName}`);
    try {
      const existing = await cf(
        `/zones/${zone.id}/dns_records?type=TXT&name.exact=${encodeURIComponent(dmarcName)}`,
      );
      if ((existing ?? []).length > 0) {
        log(`    TXT already exists — skipping. Current: ${existing[0].content}`);
      } else {
        // TXT content must be quoted character-strings (RFC 1035).
        await cf(`/zones/${zone.id}/dns_records`, {
          method: "POST",
          body: {
            type: "TXT",
            name: dmarcName,
            content: `"${DMARC_RECORD}"`,
            ttl: 1, // 1 = automatic
            comment: "SimpleLogin (scripts/provision-domain.mjs)",
          },
        });
        log(`    created: ${DMARC_RECORD}`);
      }
    } catch (e) {
      failures.push(`DMARC record: ${e.message}`);
    }
  }

  // -- 5. Email Sending (read-only check) ------------------------------------
  step("Checking Email Sending onboarding (read-only)");
  let sendingOnboarded = false;
  try {
    const subs = await cf(`/zones/${zone.id}/email/sending/subdomains`);
    const names = (Array.isArray(subs) ? subs : [])
      .map((s) => s?.name ?? s?.domain ?? s?.subdomain ?? s?.hostname)
      .filter((n) => typeof n === "string")
      .map((n) => (n.endsWith(zone.name) ? n : `${n}.${zone.name}`));
    sendingOnboarded = names.includes(emailDomain);
    if (sendingOnboarded) {
      log(`    ${emailDomain} is onboarded for Email Sending`);
    } else {
      log(
        `    ${emailDomain} is NOT onboarded for Email Sending` +
          (names.length ? ` (onboarded: ${names.join(", ")})` : ""),
      );
    }
  } catch (e) {
    log(`    could not check (${e.message}) — verify in the dashboard`);
  }
  if (!sendingOnboarded) {
    manual.push(
      "Onboard the domain for Email Sending (dashboard-only, no public API " +
        "as of 2026-07-26): Compute > Email Service > Email Sending > Onboard " +
        `Domain > select ${emailDomain}. REQUIRED for FORWARD_MODE=rewrite ` +
        "(Cloudflare DKIM-signs outbound mail so strict-DMARC receivers " +
        "accept it); without it either forwards get junked/rejected or you " +
        "must set FORWARD_MODE=passthrough.",
    );
  }

  // -- Summary ----------------------------------------------------------------
  manual.push(
    "Verify DESTINATION addresses: Cloudflare only delivers " +
      "message.forward()/send_email to verified destination addresses of the " +
      "account (Email Routing > Destination addresses) — add every user " +
      "mailbox this deployment forwards to.",
    "App side (see cloudflare/docs/DOMAINS.md): PUBLIC domain — seed a " +
      "public_domain row (scripts/seed-public-domain.sql), add the domain to " +
      "ALIAS_DOMAINS in wrangler.jsonc and redeploy. CUSTOM domain — the " +
      "owner completes verification in the SimpleLogin dashboard (ownership " +
      "TXT + MX checks).",
    "Optional (worker-side DKIM fallback): publish the DKIM_PRIVATE_KEY " +
      `public key as TXT at dkim._domainkey.${emailDomain} — only relevant ` +
      "when the domain is in ALIAS_DOMAINS and Email Sending is not signing.",
  );
  step("Manual steps remaining");
  manual.forEach((m, i) => log(`    ${i + 1}. ${m}`));

  if (failures.length > 0) {
    console.error("\nFAILED steps:");
    for (const f of failures) console.error(`  - ${f}`);
    process.exit(1);
  }
  log(`\nDone. Cloudflare-side provisioning for ${emailDomain} is complete.`);
}

main().catch((e) => die(e.stack ?? String(e)));
