/**
 * Cloudflare **self-managed OAuth** client (GA 2026-06-03) for a ONE-SHOT,
 * never-stored authorization, backing the "Auto-configure on Cloudflare"
 * hand-off in src/web/cloudflare-pages.ts. No Flask counterpart.
 *
 * THE MODEL, in one sentence: the user is sent to Cloudflare, the code that
 * comes back is redeemed, the resulting access token is spent INSIDE that one
 * request to provision exactly one domain, and it is handed back to
 * Cloudflare's revocation endpoint in a `finally` block. Nothing about the
 * authorization is ever written to D1 — there is no grant table, no
 * ciphertext, no "connected account" state to leak, expire or forget to
 * revoke. The operator of this instance can never act on a user's Cloudflare
 * account outside of a run the user just clicked through.
 *
 * ONE HOLE IN "every path revokes", stated rather than papered over: if the
 * token request itself fails at the NETWORK level, Cloudflare may have minted
 * a token whose value never reached us, so there is nothing to hand back.
 * Everything we can see is revoked — `tokenRequest` parses `access_token`
 * BEFORE it inspects `error`/status, so a token returned alongside an error
 * is revoked before the throw — and the ~1 h Hydra ceiling below is the
 * backstop for the rest.
 *
 * NO REFRESH TOKEN, DELIBERATELY. `offline_access` is NOT requested (and
 * scopesFor() strips it even if an operator puts it in CF_OAUTH_SCOPES).
 * Cloudflare's authorization server is Ory Hydra, which mints a refresh token
 * only when `offline`/`offline_access` is among the GRANTED scopes — so
 * omitting it means the issued authorization is capped by Hydra's access-token
 * lifetime (~1 h) and CANNOT be renewed by anyone, including us. That ceiling
 * is the backstop if revocation ever fails; the normal case is that the token
 * dies seconds after it was issued. If Cloudflare ever returns a refresh token
 * anyway, `CfTokenResponse.refreshToken` carries it purely so the caller can
 * revoke that too rather than strand it.
 *
 * ENDPOINTS. Verified against
 * developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/
 * and by a live probe of the OIDC discovery document on 2026-07-26: the
 * OAuth endpoints live on **dash.cloudflare.com**, NOT api.cloudflare.com
 * (which is where the resulting token is then *used*). RFC 8414's
 * /.well-known/oauth-authorization-server does not exist on that host — the
 * discovery document is the OIDC one, /.well-known/openid-configuration.
 * That probe also confirmed: authorization_code + refresh_token grants,
 * response_type=code, client_secret_basic / client_secret_post / none, and
 * PKCE code_challenge_methods. Only the Authorization Code flow is supported
 * for third-party clients.
 *
 * PKCE IS ALWAYS USED (S256), even though we are a confidential client with
 * a secret: defense in depth against a leaked/replayed authorization code
 * (an attacker who steals the code from the redirect still cannot redeem it
 * without the verifier, which never leaves the KV session).
 *
 * WHAT THE CONSENT SCREEN CANNOT DO (probed 2026-07-26, stated honestly in
 * the UI rather than papered over): it shows the account and the scope list
 * and nothing else. There is no zone picker, and the discovery document
 * advertises no `authorization_details_types_supported`, so RFC 9396 rich
 * authorization requests are not available either. For the lifetime of the
 * run the token is therefore account-wide — which is exactly why it is
 * one-shot and revoked immediately.
 */

import type { Env } from "./env";

// ---------------------------------------------------------------------------
// endpoints (see the module docstring — dash.cloudflare.com, not api.*)
// ---------------------------------------------------------------------------

export const CF_OAUTH_AUTHORIZE_URL = "https://dash.cloudflare.com/oauth2/auth";
export const CF_OAUTH_TOKEN_URL = "https://dash.cloudflare.com/oauth2/token";
export const CF_OAUTH_REVOKE_URL = "https://dash.cloudflare.com/oauth2/revoke";
/**
 * REFERENCE ONLY — nothing in this codebase fetches a discovery document (a
 * runtime dependency on it would add a failure mode for zero benefit: the
 * three endpoints above are constants). Kept because it is how the endpoint
 * list above was verified, and how to re-verify it:
 *   curl -s https://dash.cloudflare.com/.well-known/openid-configuration
 * RFC 8414's /.well-known/oauth-authorization-server path does NOT exist on
 * that host (it returns the dashboard SPA's HTML). The userinfo and JWKS
 * endpoints it advertises are unused: this flow never asks for an id_token.
 */
export const CF_OIDC_DISCOVERY_URL =
  "https://dash.cloudflare.com/.well-known/openid-configuration";

/**
 * App-root-relative paths of the flow. `CF_OAUTH_CALLBACK_PATH` is what the
 * operator registers as the OAuth client's redirect URL (docs/DOMAINS.md
 * §3.2) — changing it invalidates the registration. They live here, not in a
 * web module, so both src/web/cloudflare-pages.ts (which serves them) and
 * src/web/mailbox-domain-pages.ts (whose confirmation page posts to the
 * first) can reference them without importing each other.
 */
export const CF_OAUTH_START_PATH = "/dashboard/cloudflare/start";
export const CF_OAUTH_CALLBACK_PATH = "/dashboard/cloudflare/callback";

/** Both client credentials present ("" counts as unset, like CF_API_TOKEN). */
export function cfOauthConfigured(env: Env): boolean {
  return (
    (env.CF_OAUTH_CLIENT_ID ?? "") !== "" &&
    (env.CF_OAUTH_CLIENT_SECRET ?? "") !== ""
  );
}

// ---------------------------------------------------------------------------
// fetch test seam (modeled exactly on setCfFetch in src/lib/cfapi.ts —
// tests run in the same isolate as SELF, so a module-level seam reaches the
// worker under test)
// ---------------------------------------------------------------------------

export type CfOauthFetch = (
  input: string,
  init?: RequestInit,
) => Promise<Response>;

const realCfOauthFetch: CfOauthFetch = (input, init) => fetch(input, init);

let cfOauthFetch: CfOauthFetch = realCfOauthFetch;

/** Test seam (tests run in the same isolate as SELF). `null` restores fetch. */
export function setCfOauthFetch(f: CfOauthFetch | null): void {
  cfOauthFetch = f ?? realCfOauthFetch;
}

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

/**
 * A token/revoke endpoint failure. `code` is the RFC 6749 §5.2 `error`
 * member when the provider sent one. NOTE: `message` may embed provider text
 * — it is for logs only. Callers that surface anything to a user MUST
 * sanitize (src/web/cloudflare-pages.ts safeDiagnostic).
 */
export class CfOauthError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string | null = null,
    readonly description: string | null = null,
  ) {
    super(message);
  }
}

// ---------------------------------------------------------------------------
// small encoding helpers
// ---------------------------------------------------------------------------

const enc = new TextEncoder();

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64url(bytes: Uint8Array): string {
  return b64(bytes)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/**
 * application/x-www-form-urlencoded encoding of one component, per RFC 6749
 * §2.3.1 (the client id/secret must be form-encoded BEFORE base64 for HTTP
 * Basic). encodeURIComponent leaves !'()*-._~ alone and encodes space as
 * %20, whereas the urlencoded serializer keeps only alphanumerics and
 * *-._ and writes space as "+". `*` is percent-encoded here too — strictly
 * more escaping than required, which decodes identically on the server, so
 * it can only ever be safe.
 */
function formUrlEncode(s: string): string {
  return encodeURIComponent(s)
    .replace(
      /[!'()*~]/g,
      (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`,
    )
    .replaceAll("%20", "+");
}

/** RFC 6749 §2.3.1 client_secret_basic credentials. */
function basicAuth(clientId: string, clientSecret: string): string {
  return btoa(`${formUrlEncode(clientId)}:${formUrlEncode(clientSecret)}`);
}

// ---------------------------------------------------------------------------
// PKCE + state
// ---------------------------------------------------------------------------

/** RFC 7636 code_verifier: 32 random bytes base64url = 43 chars (43..128 ok). */
export function generateCodeVerifier(): string {
  return b64url(randomBytes(32));
}

/** RFC 7636 S256 challenge: base64url(SHA-256(ASCII(verifier))). */
export async function computeCodeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(verifier));
  return b64url(new Uint8Array(digest));
}

/** Opaque, unguessable CSRF state for the authorization request. */
export function generateState(): string {
  return b64url(randomBytes(32));
}

/**
 * Length-independent, content-constant-time string compare for the state
 * check. (Lengths are fixed here, but the primitive must not leak position
 * of the first differing byte.)
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const x = enc.encode(a);
  const y = enc.encode(b);
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

// ---------------------------------------------------------------------------
// authorize URL
// ---------------------------------------------------------------------------

export interface AuthorizeParams {
  clientId: string;
  /** Must byte-match one of the client's registered redirect URLs. */
  redirectUri: string;
  /** Product scope ids, space-joined into the `scope` parameter. */
  scopes: string[];
  state: string;
  /** S256 challenge from computeCodeChallenge (never the raw verifier). */
  codeChallenge: string;
}

/**
 * Build the authorization-request URL. Two invariants, both load-bearing for
 * the one-shot model:
 *
 * - `code_challenge_method` is ALWAYS S256 — plain is never emitted, and
 *   there is no non-PKCE path.
 * - `prompt=consent` is ALWAYS sent (OIDC Core §3.1.2.1). Hydra remembers a
 *   previous consent for the same client+subject+scopes and would otherwise
 *   skip the screen entirely on the second run, so a single earlier click
 *   would silently authorize every later run — exactly the "long-lived
 *   delegation" this design exists to avoid. With it, every run costs the
 *   user one deliberate approval.
 *
 * The caller decides the scope list (DEFAULT_CF_OAUTH_SCOPES in
 * src/web/cloudflare-pages.ts, overridable with CF_OAUTH_SCOPES). It must NOT
 * contain `offline_access`/`offline` — see the module docstring; scopesFor()
 * strips them before they ever reach here.
 */
export function buildAuthorizeUrl(p: AuthorizeParams): string {
  const q = new URLSearchParams({
    response_type: "code",
    client_id: p.clientId,
    redirect_uri: p.redirectUri,
    scope: p.scopes.join(" "),
    state: p.state,
    code_challenge: p.codeChallenge,
    code_challenge_method: "S256",
    prompt: "consent",
  });
  return `${CF_OAUTH_AUTHORIZE_URL}?${q.toString()}`;
}

// ---------------------------------------------------------------------------
// token endpoint
// ---------------------------------------------------------------------------

export interface CfTokenResponse {
  accessToken: string;
  /**
   * Normally null: no `offline_access` is requested, so Hydra mints none.
   * Carried ONLY so the caller can revoke an unexpected one instead of
   * stranding a renewable authorization it never asked for. It is never
   * stored and never used to refresh.
   */
  refreshToken: string | null;
  /** space-separated scopes as GRANTED (may differ from what we asked for). */
  scope: string | null;
  tokenType: string | null;
  /** provider `expires_in` when present — diagnostics/logging only. */
  expiresIn: number | null;
}

interface RawTokenBody {
  access_token?: unknown;
  refresh_token?: unknown;
  expires_in?: unknown;
  scope?: unknown;
  token_type?: unknown;
  error?: unknown;
  error_description?: unknown;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v !== "" ? v : null;
}

async function tokenRequest(
  clientId: string,
  clientSecret: string,
  form: Record<string, string>,
): Promise<CfTokenResponse> {
  const body = new URLSearchParams(form);
  let res: Response;
  try {
    res = await cfOauthFetch(CF_OAUTH_TOKEN_URL, {
      method: "POST",
      headers: {
        // client_secret_basic (RFC 6749 §2.3.1). The credentials are NEVER
        // put in the body as well — sending both is a spec violation some
        // providers reject outright.
        authorization: `Basic ${basicAuth(clientId, clientSecret)}`,
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body: body.toString(),
    });
  } catch (e) {
    // Network-level rejection: status 0, no provider error code.
    throw new CfOauthError(
      `token request network error: ${e instanceof Error ? e.message : String(e)}`,
      0,
    );
  }

  let data: RawTokenBody | null = null;
  try {
    data = (await res.json()) as RawTokenBody;
  } catch {
    /* non-JSON body */
  }
  if (!data || typeof data !== "object") {
    throw new CfOauthError(
      `token endpoint returned HTTP ${res.status} with a non-JSON body`,
      res.status,
    );
  }
  // Tokens are parsed BEFORE the error branch on purpose: a response can
  // carry both an `error` member (or an odd status) and a usable token, and
  // throwing without looking would strand an authorization we can no longer
  // revoke — we would never have learned its value. See the docstring above
  // for the one hole that remains (a network-level failure).
  const accessToken = str(data.access_token);
  const refreshToken = str(data.refresh_token);
  const errCode = str(data.error);
  if (errCode || !res.ok) {
    if (accessToken || refreshToken) {
      console.error(
        "cf-oauth: the token endpoint returned an error alongside a token — " +
          "revoking it before failing",
      );
      // Best effort, never throws (revokeToken's contract).
      if (refreshToken) {
        await revokeToken({
          clientId,
          clientSecret,
          token: refreshToken,
          tokenTypeHint: "refresh_token",
        });
      }
      if (accessToken) {
        await revokeToken({
          clientId,
          clientSecret,
          token: accessToken,
          tokenTypeHint: "access_token",
        });
      }
    }
    throw new CfOauthError(
      `token endpoint refused the request: HTTP ${res.status} ${errCode ?? ""} ${str(data.error_description) ?? ""}`.trim(),
      res.status,
      errCode,
      str(data.error_description),
    );
  }
  if (!accessToken) {
    throw new CfOauthError(
      "token endpoint returned no access_token",
      res.status,
    );
  }

  const rawExpires =
    typeof data.expires_in === "number"
      ? data.expires_in
      : typeof data.expires_in === "string"
        ? Number(data.expires_in)
        : Number.NaN;

  return {
    accessToken,
    refreshToken,
    scope: str(data.scope),
    tokenType: str(data.token_type),
    expiresIn:
      Number.isFinite(rawExpires) && rawExpires > 0
        ? Math.floor(rawExpires)
        : null,
  };
}

/** Authorization-code redemption, with the PKCE verifier. */
export function exchangeCode(args: {
  clientId: string;
  clientSecret: string;
  code: string;
  redirectUri: string;
  codeVerifier: string;
}): Promise<CfTokenResponse> {
  return tokenRequest(args.clientId, args.clientSecret, {
    grant_type: "authorization_code",
    code: args.code,
    redirect_uri: args.redirectUri,
    code_verifier: args.codeVerifier,
  });
}

/**
 * RFC 7009 revocation, best effort: never throws, returns whether the
 * provider acknowledged. Module-private — every caller outside this file
 * goes through `revokeOneShotToken`, which revokes BOTH tokens in the right
 * order and logs failures.
 */
async function revokeToken(args: {
  clientId: string;
  clientSecret: string;
  token: string;
  tokenTypeHint?: "access_token" | "refresh_token";
}): Promise<boolean> {
  const form: Record<string, string> = { token: args.token };
  if (args.tokenTypeHint) form.token_type_hint = args.tokenTypeHint;
  try {
    const res = await cfOauthFetch(CF_OAUTH_REVOKE_URL, {
      method: "POST",
      headers: {
        authorization: `Basic ${basicAuth(args.clientId, args.clientSecret)}`,
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body: new URLSearchParams(form).toString(),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * End the one-shot authorization: hand every token the response contained
 * back to Cloudflare. Called from the `finally` of the provisioning run
 * (src/web/cloudflare-pages.ts), so it runs on success, on refusal, and on an
 * unexpected throw alike.
 *
 * BOTH tokens, when a refresh token unexpectedly appeared: RFC 7009 §2.1
 * makes the cascade from a refresh token to its outstanding access tokens a
 * SHOULD, not a MUST, so revoking only one can leave the other alive. The
 * refresh token goes first — it is the one that could outlive the request.
 *
 * Never throws (revokeToken is best-effort by contract) and deliberately NOT
 * gated on the client credentials looking present: if they really are gone
 * the request just fails, whereas skipping it strands an authorization
 * nobody can revoke. Failure is not silent — it is logged, and the ~1 h Hydra
 * ceiling is the backstop, because without `offline_access` the token cannot
 * be renewed by anyone.
 */
export async function revokeOneShotToken(
  env: Env,
  tokens: { accessToken?: string | null; refreshToken?: string | null },
): Promise<void> {
  const clientId = env.CF_OAUTH_CLIENT_ID ?? "";
  const clientSecret = env.CF_OAUTH_CLIENT_SECRET ?? "";
  if (tokens.refreshToken) {
    console.error(
      "cf-oauth: token response carried a refresh_token although " +
        "offline_access was never requested — revoking it immediately",
    );
    const ok = await revokeToken({
      clientId,
      clientSecret,
      token: tokens.refreshToken,
      tokenTypeHint: "refresh_token",
    });
    if (!ok) console.error("cf-oauth: refresh-token revocation was refused");
  }
  if (tokens.accessToken) {
    const ok = await revokeToken({
      clientId,
      clientSecret,
      token: tokens.accessToken,
      tokenTypeHint: "access_token",
    });
    if (!ok) {
      console.error(
        "cf-oauth: access-token revocation was refused — the authorization " +
          "now expires on its own (no refresh token was ever issued)",
      );
    }
  }
}
