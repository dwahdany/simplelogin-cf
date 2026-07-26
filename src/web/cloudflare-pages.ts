/**
 * "Connect your Cloudflare account" OAuth flow (self-managed OAuth, GA
 * 2026-06-03). Mounted at /dashboard in src/index.ts.
 *
 * No Flask counterpart — this is Cloudflare-platform-specific: it replaces
 * the static CF_API_TOKEN secret with a per-user delegated grant that the
 * operator can revoke from the Cloudflare dashboard.
 *
 * Endpoints (verified against
 * developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/,
 * "Last updated Jun 3, 2026", and by live probe of the OIDC discovery
 * document on 2026-07-26) live on dash.cloudflare.com, NOT api.cloudflare.com:
 *   authorize https://dash.cloudflare.com/oauth2/auth
 *   token     https://dash.cloudflare.com/oauth2/token
 *   revoke    https://dash.cloudflare.com/oauth2/revoke
 * The API calls the grant then authorizes still go to api.cloudflare.com/client/v4.
 *
 * Routes: POST /cloudflare/connect, GET /cloudflare/callback,
 *         POST /cloudflare/disconnect
 *
 * SECURITY MODEL
 * - Starting a connection is a POST carrying the page's CSRF token, never a
 *   GET: it mints session state and spends a rate-limit budget. The session
 *   cookie is SameSite=Lax, so a plain <a href> would let any cross-site
 *   top-level navigation start (and, for a user who already consented at
 *   Cloudflare, silently COMPLETE) a connection, clobber another tab's
 *   pending attempt, or burn the limiter.
 * - The `state` is generated per connect attempt and stored ONLY in that
 *   browser's KV web session (never in a global or shared KV key), so a
 *   state minted for one session cannot validate a callback delivered in
 *   another. It is compared in constant time and consumed (deleted from the
 *   session) as soon as it MATCHES, so replaying the same callback URL a
 *   second time fails — while a callback that does not match consumes
 *   nothing, so a stray/forged request cannot cancel a genuine in-flight
 *   attempt.
 * - Nothing the provider put in the query string is acted on or shown before
 *   the state check: an `error`/`error_description` from an unmatched
 *   callback is dropped, never flashed (attacker-authored text inside a
 *   first-party error toast is a phishing primitive even when it cannot be
 *   XSS).
 * - The PKCE verifier lives in the same session slot and never leaves the
 *   server: only its S256 challenge goes to Cloudflare.
 * - `redirect_uri` is derived from the URL var, never from the request's
 *   Host header, and the post-flow redirect target is a hardcoded internal
 *   path — this flow reads no `next`/`return_to` parameter at all, so the
 *   callback cannot be turned into an open redirect.
 * - Tokens are never rendered, flashed or logged: only the account name and
 *   sanitized provider diagnostics reach the UI, and only ciphertext reaches
 *   D1 (src/lib/cfoauth.ts, AES-GCM).
 * - TWO TABS: the session holds exactly one pending attempt. Starting a
 *   second connect overwrites the first tab's state/verifier, so the older
 *   tab's callback fails the state check and asks the user to start again —
 *   a deliberate trade (single-use, no unbounded per-session state). Only
 *   the user's own POST can do this now (see the CSRF note above).
 * - REVOCATION is attempted on every path that drops a token: disconnect,
 *   a failed post-issue probe, RECONNECT (the grant being replaced is
 *   revoked first — otherwise its ciphertext is overwritten and it can never
 *   be revoked by anyone but the account owner), and account deletion
 *   (src/jobs/handlers/delete-account.ts).
 */

import type { Context } from "hono";
import { Hono } from "hono";
import {
  buildAuthorizeUrl,
  CfOauthError,
  computeCodeChallenge,
  constantTimeEqual,
  deleteGrant,
  exchangeCode,
  generateCodeVerifier,
  generateState,
  getGrant,
  getGrantMeta,
  probeAccountsWithToken,
  probeApiWithToken,
  revokeGrantTokens,
  saveGrant,
} from "../lib/cfoauth";
import { toDate } from "../lib/dates";
import type { Env } from "../lib/env";
import { saveSession } from "../lib/session";
import { validateCsrfToken } from "../lib/web/forms";
import { webLimiter } from "../lib/web/limiter";
import { buildCurrentUser, flash, renderErrorPage } from "../lib/web/render";
import { urlFor } from "../lib/web/urls";
import {
  makeRequireWebSudo,
  requireWebLogin,
  type WebEnv,
} from "../lib/web/webauth";

export const webCloudflarePagesRoutes = new Hono<WebEnv>();

/** App-root-relative paths of this flow (also what the operator registers). */
export const CF_OAUTH_CONNECT_PATH = "/dashboard/cloudflare/connect";
export const CF_OAUTH_CALLBACK_PATH = "/dashboard/cloudflare/callback";
export const CF_OAUTH_DISCONNECT_PATH = "/dashboard/cloudflare/disconnect";

/** Session slot holding the single pending authorization attempt. */
const SESSION_KEY = "cf_oauth";

/** A pending attempt older than this is refused (kills stale/parked tabs). */
const ATTEMPT_TTL_SECS = 600;

/**
 * Product scope ids requested when the CF_OAUTH_SCOPES var is unset.
 *
 * WARNING — only `account.read` is officially documented by Cloudflare (as
 * an example, alongside `workers-platform.read`); the others are PREDICTED
 * from Cloudflare's permission-group labels and are UNVERIFIED. Enumerate
 * the real ids with ANY Cloudflare API token:
 *
 *   curl -H "Authorization: Bearer $CF_API_TOKEN" \
 *        https://api.cloudflare.com/client/v4/oauth/scopes
 *
 * (`result[]` objects — use the `id` field. Ids are dot-delimited; the
 * colon-delimited API-token permission spelling is rejected.) Then set the
 * verified space-separated list as the CF_OAUTH_SCOPES var; the OAuth
 * client's scope picker in the Cloudflare dashboard must offer at least the
 * same set.
 *
 * Why these: the Accepted-Permissions badges of the endpoints src/lib/cfapi.ts
 * calls map to
 *   GET      /zones                                     -> Zone Read
 *   GET|POST /zones/{id}/email/routing[/enable|/dns]    -> ZONE SETTINGS read/write
 *                                                          (NOT Email Routing Rules)
 *   GET|PUT  /zones/{id}/email/routing/rules/catch_all  -> Email Routing Rules read/write
 *   GET|POST /zones/{id}/dns_records                    -> DNS read/write
 * plus account.read for the GET /accounts probe in the callback. Dropping
 * the zone-settings scopes makes the routing-enable step 403 at run time.
 *
 * `offline_access` IS requested (it is a protocol scope, present in the
 * discovery document's `scopes_supported`). Cloudflare's authorization
 * server is Ory Hydra/fosite, which mints a refresh token only when
 * `offline`/`offline_access` is among the GRANTED scopes — listing
 * `refresh_token` in the client's grant_types is necessary but NOT
 * sufficient. Without it the grant dies at the first access-token expiry
 * (~1 h) and cannot be renewed; the callback additionally warns when a token
 * response comes back with no refresh token, naming this scope.
 */
export const DEFAULT_CF_OAUTH_SCOPES = [
  "offline_access",
  // NB: `account.read` is deliberately NOT requested. It is the one product
  // scope Cloudflare documents, but the live authorize endpoint rejected it
  // for this deployment's client ("The OAuth 2.0 Client is not allowed to
  // request scope 'account.read'"), and Hydra fails the WHOLE authorization
  // request if any single scope is disallowed — so including it broke every
  // connect attempt. The account-identity probe therefore runs on
  // GET /zones (zone.read) and treats /accounts as best-effort; the zone's
  // own `account` field still gives us the id for CF_ACCOUNT_ID pinning.
  "zone.read",
  "zone-settings.read",
  "zone-settings.write",
  "email-routing-rule.read",
  "email-routing-rule.write",
  "dns.read",
  "dns.write",
];

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** Both client credentials present ("" counts as unset, like CF_API_TOKEN). */
export function cfOauthConfigured(env: Env): boolean {
  return (
    (env.CF_OAUTH_CLIENT_ID ?? "") !== "" &&
    (env.CF_OAUTH_CLIENT_SECRET ?? "") !== ""
  );
}

function scopesFor(env: Env): string[] {
  const raw = (env.CF_OAUTH_SCOPES ?? "").trim();
  return raw ? raw.split(/\s+/) : DEFAULT_CF_OAUTH_SCOPES;
}

/**
 * The Cloudflare account that hosts CF_WORKER_NAME, or null when the
 * operator did not pin one. Email Routing can only send a zone's mail to a
 * Worker in the SAME account, so a grant/zone outside this account can never
 * complete a provisioning run (src/lib/env.ts CF_ACCOUNT_ID).
 */
export function operatorAccountId(env: Env): string | null {
  return (env.CF_ACCOUNT_ID ?? "").trim() || null;
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
 * Where every branch of this flow lands. Hardcoded internal endpoint: the
 * flow accepts no caller-supplied return target, so it cannot be used as an
 * open redirect.
 */
const backToDomains = () => urlFor("dashboard.custom_domain");

/**
 * Flash text renders inside `toastr.<category>("...")` in a <script> block
 * (base.html), where the template's HTML escaping is not JS-string escaping,
 * and provider diagnostics here are attacker-reachable (anyone can send a
 * victim to the callback with a crafted `error_description`). So: printable
 * ASCII only, quotes/backslashes/angle brackets dropped, hard length cap.
 */
function safeDiagnostic(s: string | null | undefined, max = 160): string {
  if (!s) return "";
  return s
    .replace(/[^\x20-\x7e]+/g, " ")
    .replace(/["'`\\<>]/g, "")
    .slice(0, max)
    .trim();
}

interface PendingAttempt {
  state: string;
  verifier: string;
  /** unix seconds, for the TTL check */
  at: number;
}

function readAttempt(
  extra: Record<string, unknown> | undefined,
): PendingAttempt | null {
  const raw = extra?.[SESSION_KEY] as Partial<PendingAttempt> | undefined;
  if (
    !raw ||
    typeof raw.state !== "string" ||
    typeof raw.verifier !== "string" ||
    typeof raw.at !== "number"
  ) {
    return null;
  }
  return { state: raw.state, verifier: raw.verifier, at: raw.at };
}

// ---------------------------------------------------------------------------
// status helper for the domain pages
// ---------------------------------------------------------------------------

/**
 * Connected status + account name for rendering (see
 * templates/dashboard-mailbox/_cloudflare_connect.html). Reads only the
 * non-secret columns: no token is decrypted here, let alone rendered.
 */
export interface CfOauthPageStatus {
  /** the operator registered an OAuth client (id AND secret set) */
  configured: boolean;
  /** this user has a stored grant */
  connected: boolean;
  /**
   * The grant row exists but can no longer produce an access token: the
   * recorded expiry has passed and there is no refresh token to renew it
   * with (Cloudflare issues one only when `offline_access` was granted).
   * Provisioning REFUSES in this state, so the page must not claim the
   * delegated access is in use — it renders "reconnect" instead. Computed
   * from non-secret columns only: nothing is decrypted here.
   */
  needs_reconnect: boolean;
  account_name: string | null;
  account_id: string | null;
  scopes: string | null;
  connected_at: string | null;
  expires_at: string | null;
  has_refresh_token: boolean;
  connect_url: string;
  disconnect_url: string;
}

export async function cfOauthPageStatus(
  env: Env,
  userId: number,
): Promise<CfOauthPageStatus> {
  const configured = cfOauthConfigured(env);
  const meta = configured ? await getGrantMeta(env, userId) : null;
  const expired =
    meta?.expiresAt != null && toDate(meta.expiresAt).getTime() <= Date.now();
  return {
    configured,
    connected: meta !== null,
    needs_reconnect: meta !== null && expired && !meta.hasRefreshToken,
    account_name: meta?.accountName ?? null,
    account_id: meta?.accountId ?? null,
    scopes: meta?.scopes ?? null,
    connected_at: meta?.updatedAt ?? meta?.createdAt ?? null,
    expires_at: meta?.expiresAt ?? null,
    has_refresh_token: meta?.hasRefreshToken ?? false,
    connect_url: CF_OAUTH_CONNECT_PATH,
    disconnect_url: CF_OAUTH_DISCONNECT_PATH,
  };
}

// ===========================================================================
// POST /cloudflare/connect — start the Authorization Code + PKCE(S256) flow
// ===========================================================================

/**
 * Attaching (or detaching) a delegated DNS/mail-write authorization is at
 * least as sensitive as minting an API key, which this codebase gates behind
 * sudo (settings-pages.ts /api_key, /mfa_setup, /fido_setup,
 * /delete_account). Both routes are POST-only, so `next` cannot be their own
 * path — enter_sudo comes back with a GET; it is the domains page that
 * carries the form.
 */
const requireCfSudo = makeRequireWebSudo(urlFor("dashboard.custom_domain"));

/** Shared by both state-changing routes: reject without a valid CSRF token. */
async function csrfRejected(c: Context<WebEnv>): Promise<Response | null> {
  let body: Record<string, string | File> = {};
  try {
    body = await c.req.parseBody();
  } catch {
    /* unparsable body => missing CSRF token, handled below */
  }
  const csrf = typeof body.csrf_token === "string" ? body.csrf_token : null;
  if ((await validateCsrfToken(c, csrf)) === null) return null;
  // Flask re-renders the owning page carrying the form error; these routes
  // have no page of their own, so the equivalent is flash + redirect back.
  await flash(c, "Invalid request, please try again", "error");
  return c.redirect(backToDomains(), 302);
}

webCloudflarePagesRoutes.post(
  "/cloudflare/connect",
  requireWebLogin,
  requireCfSudo,
  async (c) => {
    const env = c.env;
    const bad = await csrfRejected(c);
    if (bad) return bad;
    if (!cfOauthConfigured(env)) {
      await flash(
        c,
        "Connecting a Cloudflare account is not available on this instance: " +
          "the operator has not registered an OAuth client " +
          "(CF_OAUTH_CLIENT_ID / CF_OAUTH_CLIENT_SECRET)",
        "error",
      );
      return c.redirect(backToDomains(), 302);
    }

    // Each attempt writes a KV session entry and bounces the user to
    // Cloudflare: cheap, but not free. Same webLimiter idiom as
    // web_cf_provision in mailbox-domain-pages.ts.
    const limiter = await webLimiter(c, "web_cf_oauth", "10/minute;60/hour");
    if (limiter.exceeded) {
      return renderErrorPage(
        c,
        429,
        await buildCurrentUser(c, c.get("webUser")),
      );
    }
    await limiter.deduct();

    const state = generateState();
    const verifier = generateCodeVerifier();
    const challenge = await computeCodeChallenge(verifier);

    // Session-BOUND (not global) and single-slot: the callback consumes it.
    const session = c.get("webSession");
    session.extra = {
      ...session.extra,
      [SESSION_KEY]: {
        state,
        verifier,
        at: Math.floor(Date.now() / 1000),
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
// GET /cloudflare/callback — validate state, redeem the code, prove the token
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
     */
    const consumeAttempt = async (): Promise<void> => {
      if (session.extra && SESSION_KEY in session.extra) {
        delete session.extra[SESSION_KEY];
        await saveSession(c, session);
      }
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
      !constantTimeEqual(attempt.state, returnedState)
    ) {
      await flash(
        c,
        "The Cloudflare connection could not be verified (the response did " +
          "not match this browser session). Please start again",
        "error",
      );
      return c.redirect(backToDomains(), 302);
    }
    // The state matched: this response belongs to a real attempt of ours, so
    // burn it now, whatever the outcome below.
    await consumeAttempt();

    if (Math.floor(Date.now() / 1000) - attempt.at > ATTEMPT_TTL_SECS) {
      await flash(
        c,
        "The Cloudflare connection request expired. Please start again",
        "error",
      );
      return c.redirect(backToDomains(), 302);
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
        `Cloudflare did not authorize the connection${detail ? `: ${detail}` : ""}`,
        "error",
      );
      return c.redirect(backToDomains(), 302);
    }

    // 3. A success response must carry a code.
    const code = url.searchParams.get("code") ?? "";
    if (!code) {
      await flash(
        c,
        "Cloudflare did not return an authorization code. Please start again",
        "error",
      );
      return c.redirect(backToDomains(), 302);
    }

    // 4. Redeem the code with the PKCE verifier (which never left the KV
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
        `Cloudflare refused to issue an access token (${detail}). Nothing ` +
          "was stored — please try again, and ask the operator to check the " +
          "OAuth client's secret and redirect URL if it keeps failing",
        "error",
      );
      return c.redirect(backToDomains(), 302);
    }

    // 5. PROVE the token works against api.cloudflare.com. This is the one
    //    materially unverified assumption of the feature (no public example
    //    shows a dash.cloudflare.com token accepted as a v4 API bearer
    //    token), so a grant that has not been seen to work is never stored.
    // Best-effort by contract (revokeGrantTokens never throws), so every
    // wording below says "asked Cloudflare to revoke", not "revoked".
    const probe = await probeApiWithToken(token.accessToken);
    if (!probe.ok) {
      console.error(
        `cf-oauth: token issued but GET /zones failed: ${probe.status} ${probe.detail}`,
      );
      // Do not sit on a token we cannot use.
      await revokeGrantTokens(env, token);
      await flash(
        c,
        "Cloudflare issued the OAuth token, but the Cloudflare API refused " +
          `it (${safeDiagnostic(probe.detail) || `HTTP ${probe.status}`}). ` +
          "The connection was NOT saved and we asked Cloudflare to revoke " +
          "the token. Domain auto-configuration keeps using the operator's " +
          "CF_API_TOKEN as before. Most likely the OAuth client is missing " +
          "the scopes this instance needs (zone / zone-settings / " +
          "email-routing-rule / dns) — see CF_OAUTH_SCOPES",
        "error",
      );
      return c.redirect(backToDomains(), 302);
    }

    // Account identity is BEST EFFORT: `account.read` is not grantable to
    // this client (see probeApiWithToken), so /accounts usually 403s. When
    // it does, the panel shows the account as unnamed and the connect-time
    // pin below is skipped — CF_ACCOUNT_ID is still enforced per zone during
    // provisioning, where the zone object carries its own account id.
    const accountsProbe = await probeAccountsWithToken(token.accessToken);
    const reachable = accountsProbe.ok ? accountsProbe.accounts : [];
    if (!accountsProbe.ok) {
      console.log(
        `cf-oauth: account listing unavailable (${accountsProbe.status} ${accountsProbe.detail}) — expected without account.read`,
      );
    }

    // 6. ACCOUNT PIN. Cloudflare Email Routing can only route a zone's mail
    //    to a Worker in the SAME account, and the catch-all this instance
    //    writes targets CF_WORKER_NAME by bare name. A grant that cannot
    //    reach the account hosting that worker is therefore unusable: it
    //    would enable Email Routing (writing MX) and only THEN fail on the
    //    catch-all, leaving the zone accepting mail nobody handles. Refuse
    //    at connect time instead. Skipped when the operator pinned no
    //    account (src/lib/env.ts CF_ACCOUNT_ID).
    //    Only enforceable when the account listing was actually readable.
    const pinned = operatorAccountId(env);
    if (
      pinned &&
      reachable.length > 0 &&
      !reachable.some((a) => a.id === pinned)
    ) {
      console.error(
        `cf-oauth: grant for user ${user.id} cannot see the operator account ${pinned}`,
      );
      await revokeGrantTokens(env, token);
      await flash(
        c,
        "That Cloudflare account cannot be used here: it is not the " +
          "Cloudflare account that hosts this instance's mail worker, and " +
          "Cloudflare Email Routing can only deliver a zone's mail to a " +
          "worker in the same account. The connection was NOT saved and we " +
          "asked Cloudflare to revoke the token. Connect the account that " +
          "holds the zone you want to use for mail, or ask the operator",
        "error",
      );
      return c.redirect(backToDomains(), 302);
    }

    // Prefer the pinned account over "whatever came back first" — the panel
    // then names the account that will actually be written to.
    const account =
      (pinned ? reachable.find((a) => a.id === pinned) : null) ??
      reachable[0] ??
      null;

    // 7. RECONNECT: revoke whatever this row held before overwriting it.
    //    saveGrant is an upsert, so without this the previous access +
    //    refresh tokens stay live at Cloudflare with their ciphertext gone —
    //    unrevokable by anyone but the account owner. Best-effort, never
    //    blocking: the user asked to (re)connect.
    const previous = await getGrant(env, user.id);
    if (previous && (previous.accessToken || previous.refreshToken)) {
      await revokeGrantTokens(env, {
        accessToken: previous.accessToken ?? "",
        refreshToken: previous.refreshToken,
      });
    }

    // 8. Store the grant (both tokens encrypted at rest by saveGrant).
    await saveGrant(env, user.id, {
      accessToken: token.accessToken,
      refreshToken: token.refreshToken,
      expiresAt: token.expiresAt,
      scopes: token.scope,
      accountId: account?.id ?? null,
      accountName: account?.name ?? null,
    });

    const shown =
      safeDiagnostic(account?.name) || safeDiagnostic(account?.id) || "unnamed";
    const many =
      reachable.length > 1
        ? ` (this grant can reach ${reachable.length} Cloudflare ` +
          "accounts — provisioning will use whichever one holds the zone of " +
          "the domain being configured)"
        : "";
    await flash(
      c,
      `Cloudflare account "${shown}" connected${many}. Domain ` +
        "auto-configuration will now use this delegated access, which you " +
        "can revoke here or in the Cloudflare dashboard at any time",
      "success",
    );
    // 9. NO REFRESH TOKEN: the grant dies at the first access-token expiry
    //    and there is no way to renew it. Cloudflare's authorization server
    //    (Ory Hydra/fosite) only mints one when `offline_access` is among the
    //    GRANTED scopes — so this means the scope was not requested, or the
    //    registered client does not offer it. Name the cause here; the
    //    symptom otherwise appears an hour later as "the authorization
    //    expired" with nothing pointing at the fix.
    if (!token.refreshToken) {
      console.error(
        "cf-oauth: token response contained NO refresh_token — the grant " +
          "cannot be renewed. Add offline_access to CF_OAUTH_SCOPES and " +
          "ensure the OAuth client's grant types include refresh_token.",
      );
      await flash(
        c,
        "Cloudflare did not issue a refresh token, so this connection will " +
          "stop working when its access token expires and you will have to " +
          "connect again. Ask the operator to include offline_access in the " +
          "requested scopes (CF_OAUTH_SCOPES) and refresh_token in the " +
          "OAuth client's grant types",
        "warning",
      );
    }
    return c.redirect(backToDomains(), 302);
  },
);

// ===========================================================================
// POST /cloudflare/disconnect — revoke at Cloudflare, drop the row
// ===========================================================================

webCloudflarePagesRoutes.post(
  "/cloudflare/disconnect",
  requireWebLogin,
  requireCfSudo,
  async (c) => {
    const env = c.env;
    const user = c.get("webUser");

    const bad = await csrfRejected(c);
    if (bad) return bad;

    const grant = await getGrant(env, user.id);
    if (!grant) {
      await flash(c, "No Cloudflare account is connected", "warning");
      return c.redirect(backToDomains(), 302);
    }

    // Best effort, but ALWAYS attempted and always for BOTH tokens: this is
    // the last moment anyone can revoke them (the row — and with it the
    // ciphertext — is deleted immediately after), so skipping it because the
    // client credentials look unset would strand a live authorization
    // forever. Failure must NOT block the local delete: the user asked to
    // disconnect. revokeToken never throws.
    await revokeGrantTokens(env, grant);

    await deleteGrant(env, user.id);
    await flash(
      c,
      "Cloudflare account disconnected. If you want to be certain it is " +
        "gone, review it in the Cloudflare dashboard as well " +
        "(Manage Account > Authorized apps)",
      "success",
    );
    return c.redirect(backToDomains(), 302);
  },
);
