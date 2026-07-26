/**
 * ONE-SHOT Cloudflare authorization for "Auto-configure on Cloudflare"
 * (self-managed OAuth, GA 2026-06-03). Mounted at /dashboard in
 * src/index.ts. No Flask counterpart — this is Cloudflare-platform-specific.
 *
 * THE POINT OF THIS MODULE: never hold a credential that can change someone
 * else's domain. There is no "connect your account", no grant table, no
 * refresh token and no disconnect button, because there is nothing to
 * disconnect. A run is: the user reads the exact record diff on the
 * confirmation page (src/web/mailbox-domain-pages.ts, rendered from the same
 * plan the writes use) -> POSTs here -> approves at Cloudflare -> we redeem
 * the code, spend the access token INSIDE this one request, and hand it back
 * to the revocation endpoint in a `finally`. Nothing is written to D1.
 *
 * Routes: POST /cloudflare/start, GET /cloudflare/callback
 *
 * SECURITY MODEL
 * - Starting a run is a POST carrying the page's CSRF token, never a GET: it
 *   mints session state and bounces the user to Cloudflare. The session
 *   cookie is SameSite=Lax, so a plain <a href> would let any cross-site
 *   top-level navigation start one, clobber another tab's pending attempt, or
 *   burn the limiter.
 * - THE RUN IS BOUND TO THE DIFF THE USER READ. /start takes no domain id
 *   from the client: it takes the ONE-TIME confirm nonce minted by the
 *   confirmation page (src/web/mailbox-domain-pages.ts) and reads the target
 *   domain — plus a hash of the plan as displayed — out of the session slot
 *   that nonce names. So the id cannot be swapped for another owned domain,
 *   a stale/replayed submit cannot start a second run, and /start is
 *   unreachable without a rendered diff (a same-origin script holding the
 *   session-wide CSRF token could otherwise have sent a victim to
 *   Cloudflare's consent screen without ever showing them the review page).
 * - The gates the DNS page applies are re-applied here (mode, SL subdomain,
 *   deployment-domain collision) so a run that can only ever be refused never
 *   asks anyone for an authorization.
 * - NO SUDO GATE (deliberate change from the stored-grant design, which had
 *   one): this endpoint no longer attaches any lasting credential to the
 *   account. It only produces a redirect to Cloudflare, where the user has to
 *   approve on Cloudflare's own consent screen before anything can happen —
 *   and the writes that follow are exactly the ones the equivalent
 *   CF_API_TOKEN button has always performed without sudo.
 * - The `state` is generated per attempt and stored ONLY in that browser's KV
 *   web session (never in a global or shared KV key), so a state minted for
 *   one session cannot validate a callback delivered in another. It is
 *   compared in constant time and consumed as soon as it MATCHES, so
 *   replaying the same callback URL a second time fails — while a callback
 *   that does not match consumes nothing, so a stray/forged request cannot
 *   cancel a genuine in-flight attempt. Because KV has no compare-and-set,
 *   the single-use property is enforced by an atomic D1 claim
 *   (claimCallbackOnce): two CONCURRENT deliveries of the same callback would
 *   otherwise both redeem the same authorization code.
 * - The TARGET DOMAIN travels in that same session slot, not in the callback
 *   query string: Cloudflare echoes back only `code`/`state`, and a domain id
 *   taken from the URL would let a crafted callback point a freshly minted
 *   token at a different row. It is re-checked for ownership on return.
 * - Nothing the provider put in the query string is acted on or shown before
 *   the state check: an `error`/`error_description` from an unmatched
 *   callback is dropped, never flashed (attacker-authored text inside a
 *   first-party error toast is a phishing primitive even when it cannot be
 *   XSS).
 * - The PKCE verifier lives in the same session slot and never leaves the
 *   server: only its S256 challenge goes to Cloudflare.
 * - `redirect_uri` is derived from the URL var, never from the request's
 *   Host header, and every redirect target is a hardcoded internal path —
 *   this flow reads no `next`/`return_to` parameter at all, so the callback
 *   cannot be turned into an open redirect.
 * - Tokens are never rendered, flashed, logged or persisted; only sanitized
 *   provider diagnostics reach the UI.
 * - TWO TABS: the session holds exactly one pending attempt. Starting a
 *   second run overwrites the first tab's state/verifier/domain, so the older
 *   tab's callback fails the state check and asks the user to start again —
 *   a deliberate trade (single-use, no unbounded per-session state).
 * - The rate limit is the provisioning one (`web_cf_provision`), checked
 *   before the redirect so the user is told early, and checked AND SPENT in
 *   the callback before the code is redeemed — a run that never reaches
 *   Cloudflare costs nothing, and a token is only ever minted when there is
 *   budget to spend it. /start additionally spends a much cheaper budget of
 *   its own (`web_cf_oauth_start`), because it is a KV write plus a redirect
 *   that no other limiter would ever count.
 */

import type { Context } from "hono";
import { Hono } from "hono";
import {
  buildAuthorizeUrl,
  CF_OAUTH_CALLBACK_PATH,
  CfOauthError,
  cfOauthConfigured,
  computeCodeChallenge,
  constantTimeEqual,
  exchangeCode,
  generateCodeVerifier,
  generateState,
  revokeOneShotToken,
} from "../lib/cfoauth";
import type { Env } from "../lib/env";
import { getSession, saveSession } from "../lib/session";
import { validateCsrfToken } from "../lib/web/forms";
import { webLimiter } from "../lib/web/limiter";
import {
  buildCurrentUser,
  flash,
  renderErrorPage,
  safeDiagnostic,
} from "../lib/web/render";
import { urlFor } from "../lib/web/urls";
import { requireWebLogin, type WebEnv } from "../lib/web/webauth";
import {
  CF_PROVISION_LIMITS,
  cfProvisionDnsPath,
  loadOwnedCustomDomain,
  runCfProvision,
  takeCfConfirmation,
} from "./mailbox-domain-pages";

export const webCloudflarePagesRoutes = new Hono<WebEnv>();

/** Session slot holding the single pending authorization attempt. */
const SESSION_KEY = "cf_oauth";

/** A pending attempt older than this is refused (kills stale/parked tabs). */
const ATTEMPT_TTL_SECS = 600;

/**
 * Throttle for the hand-off itself: /start only CHECKS the provisioning
 * budget (a run that never reaches Cloudflare must not cost one), so without
 * this the endpoint has no budget of its own — each POST is a D1 read plus a
 * KV session write plus a redirect to dash.cloudflare.com. Deliberately loose
 * compared to `web_cf_provision` (3/minute): a user re-reading the diff and
 * clicking through must never hit it.
 */
const CF_OAUTH_START_LIMITS = "10/minute;60/hour";

/**
 * Product scope ids requested when the CF_OAUTH_SCOPES var is unset.
 *
 * These were empirically probed against the live authorize endpoint on
 * 2026-07-26 for this deployment's client: all of them are ACCEPTED, while
 * `account.read` — the one scope Cloudflare documents — is REFUSED ("The
 * OAuth 2.0 Client is not allowed to request scope 'account.read'"), and
 * Hydra fails the WHOLE authorization request if any single scope is
 * disallowed. Re-enumerate the ids with ANY Cloudflare API token:
 *
 *   curl -H "Authorization: Bearer $CF_API_TOKEN" \
 *        https://api.cloudflare.com/client/v4/oauth/scopes
 *
 * (`result[]` objects — use the `id` field. Ids are dot-delimited; the
 * colon-delimited API-token permission spelling is rejected.)
 *
 * Why these: the Accepted-Permissions badges of the endpoints src/lib/cfapi.ts
 * calls map to
 *   GET      /zones                                     -> Zone Read
 *   GET|POST /zones/{id}/email/routing[/enable|/dns]    -> ZONE SETTINGS read/write
 *                                                          (NOT Email Routing Rules)
 *   GET|PUT  /zones/{id}/email/routing/rules/catch_all  -> Email Routing Rules read/write
 *   GET|POST /zones/{id}/dns_records                    -> DNS read/write
 * Dropping the zone-settings scopes makes the routing-enable step 403 at run
 * time (docs/DOMAINS.md §3.3).
 *
 * `offline_access` is deliberately ABSENT and is stripped from any operator
 * override (scopesFor): it is what would make Cloudflare mint a refresh
 * token, i.e. an authorization that outlives the run. Without it the token
 * cannot be renewed by anyone and dies on its own within Hydra's ~1 h
 * ceiling even if our explicit revocation fails.
 */
export const DEFAULT_CF_OAUTH_SCOPES = [
  "zone.read",
  "zone-settings.read",
  "zone-settings.write",
  "email-routing-rule.read",
  "email-routing-rule.write",
  "dns.read",
  "dns.write",
];

/** Scopes that would turn a one-shot authorization into a renewable one. */
const RENEWAL_SCOPES = new Set(["offline_access", "offline"]);

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

export function scopesFor(env: Env): string[] {
  const raw = (env.CF_OAUTH_SCOPES ?? "").trim();
  const requested = raw ? raw.split(/\s+/) : DEFAULT_CF_OAUTH_SCOPES;
  // An operator override must not be able to reintroduce a refresh token:
  // strip rather than refuse, so a stale CF_OAUTH_SCOPES value degrades to a
  // working one-shot run instead of breaking the feature.
  const scopes = requested.filter((s) => !RENEWAL_SCOPES.has(s));
  if (scopes.length !== requested.length) {
    console.error(
      "cf-oauth: CF_OAUTH_SCOPES contained offline_access/offline — dropped. " +
        "This flow must never obtain a refresh token; remove it from the var.",
    );
  }
  return scopes;
}

/**
 * The registered redirect URL. Built from the URL var, NEVER from the
 * request Host header — a Host-derived redirect_uri is both an open-redirect
 * primitive and a way to get the authorization code delivered elsewhere.
 */
export function cfOauthRedirectUri(env: Env): string {
  return `${(env.URL ?? "").replace(/\/+$/, "")}${CF_OAUTH_CALLBACK_PATH}`;
}

/**
 * Fallback landing page: used only when we do not (or must not) know which
 * domain the attempt was for. Hardcoded internal endpoint — this flow accepts
 * no caller-supplied return target, so it cannot be used as an open redirect.
 */
const backToDomains = () => urlFor("dashboard.custom_domain");

interface PendingAttempt {
  state: string;
  verifier: string;
  /** unix seconds, for the TTL check */
  at: number;
  /** the custom_domain row this run will configure (never from the URL) */
  domainId: number;
}

/**
 * Window of the single-use CALLBACK CLAIM below. Only has to outlive a
 * pending attempt (ATTEMPT_TTL_SECS), after which the TTL check refuses the
 * callback anyway. Rows are named in the `rlw:<name>:<subject>:<seconds>`
 * shape the maintenance job already knows how to expire
 * (src/jobs/maintenance.ts rateLimitRowExpiry), so they clean themselves up.
 */
const CALLBACK_CLAIM_WINDOW_SECS = 900;

/**
 * ATOMICALLY claim the right to redeem this callback, exactly once.
 *
 * The session slot alone cannot do this: KV has no compare-and-set, so two
 * deliveries of the same callback URL (a double-clicked navigation, a browser
 * prefetch or retry of the redirect target) can both read the pending attempt
 * before either writes it back, and both would then redeem the SAME
 * authorization code. RFC 6749 §4.1.2 says the authorization server SHOULD
 * revoke every token issued from a reused code — so the loser's redemption
 * can kill the winner's token MID-RUN, i.e. after ensureEmailRouting has
 * created and LOCKED the zone's MX set and before the catch-all lands: the
 * "Cloudflare MX with nothing behind them" state the whole preflight ordering
 * exists to prevent.
 *
 * D1 is the only strongly consistent store here, and the port already uses
 * the `rate_limit` table as its general-purpose mutex (requestLock in
 * src/lib/ratelimit.ts, same INSERT ... ON CONFLICT ... RETURNING idiom):
 * SQLite serializes the insert, so exactly one caller gets a row back.
 * Deliberately NOT gated on DISABLE_RATE_LIMIT — this is a correctness lock,
 * not a budget. The state is hashed rather than stored: it is a per-attempt
 * secret, and this row outlives the request.
 */
async function claimCallbackOnce(
  c: Context<WebEnv>,
  state: string,
): Promise<boolean> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(state),
  );
  const hash = [...new Uint8Array(digest)]
    .slice(0, 16)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const row = await c.env.DB.prepare(
    `INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, 1)
     ON CONFLICT(key) DO NOTHING RETURNING key`,
  )
    .bind(
      `rlw:cf_oauth_callback:${hash}:${CALLBACK_CLAIM_WINDOW_SECS}`,
      Math.floor(Date.now() / 1000 / CALLBACK_CLAIM_WINDOW_SECS),
    )
    .first();
  return row !== null;
}

function readAttempt(
  extra: Record<string, unknown> | undefined,
): PendingAttempt | null {
  const raw = extra?.[SESSION_KEY] as Partial<PendingAttempt> | undefined;
  if (
    !raw ||
    typeof raw.state !== "string" ||
    typeof raw.verifier !== "string" ||
    typeof raw.at !== "number" ||
    typeof raw.domainId !== "number"
  ) {
    return null;
  }
  return {
    state: raw.state,
    verifier: raw.verifier,
    at: raw.at,
    domainId: raw.domainId,
  };
}

// ===========================================================================
// POST /cloudflare/start — mint state+PKCE, hand off to Cloudflare
// ===========================================================================

webCloudflarePagesRoutes.post(
  "/cloudflare/start",
  requireWebLogin,
  async (c) => {
    const env = c.env;
    const user = c.get("webUser");

    let body: Record<string, string | File> = {};
    try {
      body = await c.req.parseBody();
    } catch {
      /* unparsable body => missing CSRF token, handled below */
    }
    const csrf = typeof body.csrf_token === "string" ? body.csrf_token : null;
    if ((await validateCsrfToken(c, csrf)) !== null) {
      // Flask re-renders the owning page carrying the form error; this route
      // has no page of its own, so the equivalent is flash + redirect back.
      await flash(c, "Invalid request, please try again", "error");
      return c.redirect(backToDomains(), 302);
    }

    // Cheap throttle of its own (see CF_OAUTH_START_LIMITS): the endpoint
    // must not be free to hammer just because the expensive budget below is
    // only checked here.
    const startLimiter = await webLimiter(
      c,
      "web_cf_oauth_start",
      CF_OAUTH_START_LIMITS,
    );
    if (startLimiter.exceeded) {
      return renderErrorPage(c, 429, await buildCurrentUser(c, user));
    }
    await startLimiter.deduct();

    // Same budget the run itself spends: checked (not counted) BEFORE the
    // confirmation is consumed, so being out of budget costs the user only a
    // wait, not a re-read of the diff.
    const limiter = await webLimiter(
      c,
      "web_cf_provision",
      CF_PROVISION_LIMITS,
    );
    if (limiter.exceeded) {
      return renderErrorPage(c, 429, await buildCurrentUser(c, user));
    }

    // THE TARGET COMES FROM THE CONFIRMATION PAGE, NOT FROM THIS FORM. The
    // nonce is one-time and session-bound; the domain id and the hash of the
    // diff that was displayed travel with it. A submit with no (or a stale,
    // or someone else's) nonce cannot start a run.
    //
    // takeCfConfirmation also re-applies every refusal the DNS page makes —
    // the mode gate (which covers "no OAuth client registered" and
    // "CF_ACCOUNT_ID not pinned"), the SL-subdomain gate, the
    // deployment-domain collision — and checks that the plan is still the one
    // that was displayed, so a hopeless or changed run never reaches
    // Cloudflare's consent screen.
    const nonce = typeof body.cf_nonce === "string" ? body.cf_nonce : null;
    const taken = await takeCfConfirmation(c, nonce, "oauth");
    if ("refusal" in taken) return taken.refusal;
    const cd = taken.cd;

    const state = generateState();
    const verifier = generateCodeVerifier();
    const challenge = await computeCodeChallenge(verifier);

    // Session-BOUND (not global) and single-slot: the callback consumes it.
    // Written onto a FRESH read of the session, never the middleware's
    // snapshot — that snapshot still carries the confirm slot consumeCfConfirm
    // just deleted, and saving it would resurrect the one-time nonce.
    const session = (await getSession(c)) ?? {};
    session.extra = {
      ...session.extra,
      [SESSION_KEY]: {
        state,
        verifier,
        at: Math.floor(Date.now() / 1000),
        domainId: cd.id,
      } satisfies PendingAttempt,
    };
    await saveSession(c, session);

    return c.redirect(
      buildAuthorizeUrl({
        clientId: env.CF_OAUTH_CLIENT_ID ?? "",
        redirectUri: cfOauthRedirectUri(env),
        scopes: scopesFor(env),
        state,
        codeChallenge: challenge,
      }),
      302,
    );
  },
);

// ===========================================================================
// GET /cloudflare/callback — validate state, redeem the code, RUN, revoke
// ===========================================================================

webCloudflarePagesRoutes.get(
  "/cloudflare/callback",
  requireWebLogin,
  async (c) => {
    const env = c.env;
    const user = c.get("webUser");
    const url = new URL(c.req.url);

    const session = c.get("webSession");
    const attempt = readAttempt(session.extra);
    /**
     * Consume the pending attempt. Called ONLY once the returned state has
     * matched, which gives both properties: single-use (a replayed callback
     * URL, or a second tab racing this one, finds nothing to validate
     * against) AND un-cancellable (a stray or attacker-induced request with
     * no state, or the wrong one, leaves a genuine in-flight attempt alone).
     *
     * SINGLE USE IS ENFORCED BY D1 (claimCallbackOnce), not by this KV write:
     * concurrent duplicates can both read the session before either writes,
     * and the loser must never reach the token endpoint. This function runs
     * only for the caller that already won that claim; it re-reads the
     * session from KV so the delete lands on the current copy rather than on
     * the snapshot taken at the top of the request.
     */
    const consumeAttempt = async (): Promise<boolean> => {
      const fresh = (await getSession(c)) ?? {};
      const slot = readAttempt(fresh.extra);
      if (!attempt) return false;
      if (!slot || !constantTimeEqual(slot.state, attempt.state)) {
        // Already gone (a sequential replay of a callback whose run finished)
        // — nothing to consume, and the claim above has decided anyway.
        return true;
      }
      if (fresh.extra) delete fresh.extra[SESSION_KEY];
      // Keep the request's snapshot in step: anything that saves it later
      // (nothing does today) must not resurrect the attempt.
      if (session.extra) delete session.extra[SESSION_KEY];
      await saveSession(c, fresh);
      return true;
    };

    if (!cfOauthConfigured(env)) {
      await flash(
        c,
        "Cloudflare OAuth is not configured on this instance",
        "error",
      );
      return c.redirect(backToDomains(), 302);
    }

    // 1. State FIRST: must exist in THIS session, match in constant time.
    //    Nothing the provider sent — including `error_description` — is read
    //    or shown before this passes. RFC 6749 §4.1.2.1 requires `state` on
    //    error redirects too, so the genuine "user clicked Cancel" response
    //    still reaches the error branch below; an unmatched callback gets
    //    this fixed, first-party text and nothing else.
    const returnedState = url.searchParams.get("state") ?? "";
    if (
      !attempt ||
      !returnedState ||
      !constantTimeEqual(attempt.state, returnedState) ||
      // The state matched: this response belongs to a real attempt of ours,
      // so claim it NOW — before anything else is read or done — and burn the
      // session slot, whatever the outcome below. A duplicate delivery that
      // loses the claim lands here too and is told the same thing as an
      // unmatched callback: nothing happened, start again.
      !(await claimCallbackOnce(c, returnedState)) ||
      !(await consumeAttempt())
    ) {
      await flash(
        c,
        "The Cloudflare authorization could not be verified (the response " +
          "did not match this browser session). Nothing was changed — " +
          "please start again",
        "error",
      );
      return c.redirect(backToDomains(), 302);
    }
    const back = () => c.redirect(cfProvisionDnsPath(attempt.domainId), 302);

    if (Math.floor(Date.now() / 1000) - attempt.at > ATTEMPT_TTL_SECS) {
      await flash(
        c,
        "The Cloudflare authorization request expired before it came back. " +
          "Nothing was changed — please start again",
        "error",
      );
      return back();
    }

    // 2. Provider-side error response (RFC 6749 §4.1.2.1) — reachable only
    //    with a matching state, i.e. only for a flow this browser started,
    //    so "you clicked Cancel" reads as itself.
    const providerError = url.searchParams.get("error");
    if (providerError) {
      const detail = safeDiagnostic(
        url.searchParams.get("error_description") ?? providerError,
      );
      await flash(
        c,
        `Cloudflare did not authorize the change${detail ? `: ${detail}` : ""}. ` +
          "Nothing was changed",
        "error",
      );
      return back();
    }

    // 3. A success response must carry a code.
    const code = url.searchParams.get("code") ?? "";
    if (!code) {
      await flash(
        c,
        "Cloudflare did not return an authorization code. Nothing was " +
          "changed — please start again",
        "error",
      );
      return back();
    }

    // 4. The target domain comes from the SESSION, never from the callback
    //    URL, and is re-checked for ownership: the row may have been deleted
    //    (or the session moved to another user) while the user was away.
    const cd = await loadOwnedCustomDomain(env.DB, user.id, attempt.domainId);
    if (!cd) {
      await flash(
        c,
        "That domain is no longer available on your account, so nothing was " +
          "changed",
        "warning",
      );
      return c.redirect(backToDomains(), 302);
    }

    // 5. Rate limit BEFORE redeeming the code: the same per-user budget the
    //    static-token path spends (each run costs ~10 authenticated
    //    Cloudflare API calls). Refusing here means no token is ever minted,
    //    so there is nothing to revoke.
    const limiter = await webLimiter(
      c,
      "web_cf_provision",
      CF_PROVISION_LIMITS,
    );
    if (limiter.exceeded) {
      // A flash + redirect, not a bare 429 page: the user has just approved
      // on Cloudflare's consent screen and needs to be told that nothing was
      // changed and that continuing means approving again (the state and the
      // verifier are gone). Every other refusal in this handler reads that
      // way too.
      await flash(
        c,
        "You have started this too many times in the last minute, so it was " +
          "not run. Nothing was changed — wait a moment and start again",
        "error",
      );
      return back();
    }
    await limiter.deduct();

    // 6. Redeem the code with the PKCE verifier (which never left the KV
    //    session).
    let token: Awaited<ReturnType<typeof exchangeCode>>;
    try {
      token = await exchangeCode({
        clientId: env.CF_OAUTH_CLIENT_ID ?? "",
        clientSecret: env.CF_OAUTH_CLIENT_SECRET ?? "",
        code,
        redirectUri: cfOauthRedirectUri(env),
        codeVerifier: attempt.verifier,
      });
    } catch (e) {
      if (!(e instanceof CfOauthError)) throw e;
      // Full detail (which may quote request parameters) is for the
      // operator's logs only.
      console.error(`cf-oauth: code exchange failed: ${e.message}`);
      const detail = safeDiagnostic(e.code ?? `HTTP ${e.status}`);
      await flash(
        c,
        `Cloudflare refused to issue an access token (${detail}), so nothing ` +
          "was changed. Please try again, and ask the operator to check the " +
          "OAuth client's secret and redirect URL if it keeps failing",
        "error",
      );
      return back();
    }
    // Diagnostics only, and the ONLY thing ever logged about a token: what
    // Cloudflare actually GRANTED (which may differ from what was asked for)
    // and how long it would have lived. The token value itself is never
    // logged, flashed or stored. This is what makes a scope trap
    // (docs/DOMAINS.md §3.3) readable in Workers Logs.
    console.log(
      `cf-oauth: token issued (type=${token.tokenType ?? "?"}, ` +
        `expires_in=${token.expiresIn ?? "?"}, scope=${token.scope ?? "?"})`,
    );

    // 7. SPEND IT HERE AND NOWHERE ELSE. The token goes straight into the one
    //    provisioning run the user just confirmed — the same function, the
    //    same guards and the same flashes as the static-token path — and the
    //    `finally` hands it back to Cloudflare whether that run succeeded,
    //    refused, or threw. It is never written to D1, never logged, and
    //    never reachable by a later request.
    try {
      return await runCfProvision(c, cd, {
        source: "oauth",
        token: token.accessToken,
      });
    } finally {
      await revokeOneShotToken(env, token);
    }
  },
);
