/**
 * Cloudflare **self-managed OAuth** client (GA 2026-06-03) + encrypted grant
 * storage, backing the "Connect your Cloudflare account" flow in
 * src/web/cloudflare-pages.ts. No Flask counterpart.
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
 * TOKEN LIFETIME IS NEVER HARDCODED: expiry is derived from the token
 * response's `expires_in`. If the provider omits it, we fall back to a
 * deliberately SHORT window (FALLBACK_EXPIRES_IN_SECS) so we refresh early
 * and often rather than assuming a long-lived token that may already be
 * dead.
 *
 * AT-REST ENCRYPTION: access/refresh tokens are AES-GCM encrypted with a key
 * derived from FLASK_SECRET (SHA-256 over the secret plus a domain-
 * separation string, so this key can never collide with the itsdangerous
 * signing use of the same secret). Stored as
 * "<version>.<base64 iv>.<base64 ct>" with a fresh random 12-byte IV per
 * encryption, so a D1 dump alone does not yield usable Cloudflare
 * credentials. The version prefix tells a FLASK_SECRET rotation apart from a
 * format change, and the user id is passed as GCM `additionalData`, so a
 * ciphertext relocated to another user_id by a D1-write-capable attacker
 * fails the authentication tag instead of decrypting. Rotating FLASK_SECRET
 * invalidates every stored grant (users must reconnect) — by design.
 *
 * OPEN RISK (documented, handled at runtime): no public worked example shows
 * a dash.cloudflare.com OAuth access token being accepted as a bearer token
 * by api.cloudflare.com/client/v4. `probeAccountsWithToken` exists precisely
 * so the callback can PROVE this at connect time and degrade gracefully
 * (the static CF_API_TOKEN stays the fallback) instead of storing a grant
 * that silently 403s later.
 */

import { addSeconds, nowStr, toDate, toStr } from "./dates";
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
/** Where the granted token is actually spent (src/lib/cfapi.ts API_BASE). */
export const CF_API_ZONES_URL = "https://api.cloudflare.com/client/v4/zones";
export const CF_API_ACCOUNTS_URL =
  "https://api.cloudflare.com/client/v4/accounts";

/**
 * Refresh this many seconds BEFORE the recorded expiry: covers clock skew
 * between us and Cloudflare plus the round-trip of the request the token is
 * about to be used for.
 */
export const REFRESH_SKEW_SECS = 60;

/**
 * Conservative fallback when a token response omits `expires_in`. Five
 * minutes, chosen to be far shorter than any plausible real lifetime: the
 * cost of being wrong is one extra refresh round-trip, whereas guessing too
 * long means every API call fails with an expired token until the row is
 * touched. NEVER replace this with an assumed real Cloudflare lifetime.
 */
export const FALLBACK_EXPIRES_IN_SECS = 300;

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

  /**
   * True when retrying with the SAME grant can never succeed: the user
   * revoked us in the Cloudflare dashboard, or the refresh token rotated
   * away / expired. The stored row is then dead weight and is deleted, which
   * is also what stops a refresh loop (see getValidAccessToken).
   */
  get grantIsDead(): boolean {
    return this.code === "invalid_grant";
  }
}

// ---------------------------------------------------------------------------
// small encoding helpers
// ---------------------------------------------------------------------------

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function unb64(s: string): Uint8Array | null {
  try {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
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
 * Build the authorization-request URL. `code_challenge_method` is ALWAYS
 * S256 — plain is never emitted, and there is no non-PKCE path.
 *
 * The caller decides the scope list (DEFAULT_CF_OAUTH_SCOPES in
 * src/web/cloudflare-pages.ts, overridable with CF_OAUTH_SCOPES). It MUST
 * include `offline_access`: the discovery document identifies Cloudflare's
 * authorization server as Ory Hydra/fosite, whose `canIssueRefreshToken`
 * mints a refresh token only when `offline`/`offline_access` is among the
 * GRANTED scopes of the request — having `refresh_token` in the client's
 * grant_types is necessary but not sufficient. Without it the grant silently
 * dies at the first access-token expiry.
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
  });
  return `${CF_OAUTH_AUTHORIZE_URL}?${q.toString()}`;
}

// ---------------------------------------------------------------------------
// token endpoint
// ---------------------------------------------------------------------------

export interface CfTokenResponse {
  accessToken: string;
  /** null when the provider did not return one (do not clobber a stored one). */
  refreshToken: string | null;
  /** canonical "YYYY-MM-DD HH:MM:SS+00:00", derived from expires_in. */
  expiresAt: string;
  /** seconds actually used (response value, or FALLBACK_EXPIRES_IN_SECS). */
  expiresIn: number;
  /** space-separated scopes as GRANTED (may differ from what we asked for). */
  scope: string | null;
  tokenType: string | null;
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
    // Network-level rejection: status 0, no provider error code, so it is
    // NOT treated as a dead grant (transient — the row survives).
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
  const errCode = str(data.error);
  if (errCode || !res.ok) {
    throw new CfOauthError(
      `token endpoint refused the request: HTTP ${res.status} ${errCode ?? ""} ${str(data.error_description) ?? ""}`.trim(),
      res.status,
      errCode,
      str(data.error_description),
    );
  }
  const accessToken = str(data.access_token);
  if (!accessToken) {
    throw new CfOauthError(
      "token endpoint returned no access_token",
      res.status,
    );
  }

  // Lifetime is ALWAYS derived, never assumed (see FALLBACK_EXPIRES_IN_SECS).
  const rawExpires =
    typeof data.expires_in === "number"
      ? data.expires_in
      : typeof data.expires_in === "string"
        ? Number(data.expires_in)
        : Number.NaN;
  const expiresIn =
    Number.isFinite(rawExpires) && rawExpires > 0
      ? Math.floor(rawExpires)
      : FALLBACK_EXPIRES_IN_SECS;

  return {
    accessToken,
    refreshToken: str(data.refresh_token),
    expiresAt: toStr(addSeconds(new Date(), expiresIn)),
    expiresIn,
    scope: str(data.scope),
    tokenType: str(data.token_type),
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
 * Refresh-token grant. The response's refresh_token MAY be a NEW one
 * (rotation): callers must persist whatever comes back — see
 * getValidAccessToken.
 */
export function refreshAccessToken(args: {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
}): Promise<CfTokenResponse> {
  return tokenRequest(args.clientId, args.clientSecret, {
    grant_type: "refresh_token",
    refresh_token: args.refreshToken,
  });
}

/**
 * RFC 7009 revocation, best effort: never throws, returns whether the
 * provider acknowledged. Called on disconnect so the grant dies at
 * Cloudflare too, not just in our D1.
 */
export async function revokeToken(args: {
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
 * Hand a grant's tokens back to Cloudflare. BOTH of them: RFC 7009 §2.1
 * makes the cascade from a refresh token to its outstanding access tokens a
 * SHOULD, not a MUST, so revoking only the refresh token can leave a
 * fully-scoped access token alive until it expires.
 *
 * Never throws (revokeToken is best-effort by contract), so EVERY path that
 * drops a grant calls it unconditionally: disconnect, a failed post-issue
 * probe, reconnect-over-an-existing-row (src/web/cloudflare-pages.ts) and
 * account deletion (src/jobs/handlers/delete-account.ts). It is deliberately
 * NOT gated on the client credentials looking present: if they really are
 * gone the request just fails, whereas skipping it strands an authorization
 * that nobody can revoke once the ciphertext is deleted.
 */
export async function revokeGrantTokens(
  env: Env,
  tokens: { accessToken?: string | null; refreshToken?: string | null },
): Promise<void> {
  const clientId = env.CF_OAUTH_CLIENT_ID ?? "";
  const clientSecret = env.CF_OAUTH_CLIENT_SECRET ?? "";
  if (tokens.refreshToken) {
    await revokeToken({
      clientId,
      clientSecret,
      token: tokens.refreshToken,
      tokenTypeHint: "refresh_token",
    });
  }
  if (tokens.accessToken) {
    await revokeToken({
      clientId,
      clientSecret,
      token: tokens.accessToken,
      tokenTypeHint: "access_token",
    });
  }
}

// ---------------------------------------------------------------------------
// "does this token actually work against api.cloudflare.com?" probe
// ---------------------------------------------------------------------------

export interface CfAccountRef {
  id: string;
  name: string;
}

export type AccountProbe =
  | { ok: true; accounts: CfAccountRef[] }
  | { ok: false; status: number; detail: string };

/** Cloudflare v4 response envelope (same shape as src/lib/cfapi.ts). */
interface CfEnvelope {
  success?: boolean;
  result?: unknown;
  errors?: Array<{ code?: number; message?: string }>;
}

/**
 * PROVE the dash.cloudflare.com-issued token is accepted by
 * api.cloudflare.com — the one materially unverified assumption of this
 * whole feature — using GET /zones, which `zone.read` covers.
 *
 * Why not /accounts: `account.read` is the only product scope Cloudflare
 * documents, but the live authorize endpoint REFUSES it for this
 * deployment's OAuth client ("The OAuth 2.0 Client is not allowed to request
 * scope 'account.read'"), and Hydra rejects the entire authorization request
 * if any one scope is disallowed — so the flow cannot ask for it. Account
 * identity is recovered best-effort by `probeAccountsWithToken` below, and
 * authoritatively from a zone's own `account` field at provisioning time.
 * Never throws.
 */
export async function probeApiWithToken(
  accessToken: string,
): Promise<{ ok: true } | { ok: false; status: number; detail: string }> {
  try {
    const res = await cfOauthFetch(`${CF_API_ZONES_URL}?per_page=1`, {
      method: "GET",
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/json",
      },
    });
    let data: CfEnvelope | null = null;
    try {
      data = (await res.json()) as CfEnvelope;
    } catch {
      /* non-JSON */
    }
    if (res.ok && data?.success === true) return { ok: true };
    const detail =
      (data?.errors ?? [])
        .map((e) => `[${e.code}] ${e.message}`)
        .filter(Boolean)
        .join("; ") || `HTTP ${res.status}`;
    return { ok: false, status: res.status, detail };
  } catch (e) {
    return {
      ok: false,
      status: 0,
      detail: `network error: ${e instanceof Error ? e.message : String(e)}`,
    };
  }
}

/**
 * GET /client/v4/accounts with the OAuth access token — BEST EFFORT ONLY:
 * it needs `account.read`, which this client is not allowed to request (see
 * probeApiWithToken). A failure here is not fatal; it only means the UI
 * cannot name the account and CF_ACCOUNT_ID pinning has nothing to check at
 * connect time (it still applies per-zone during provisioning, where the
 * zone object carries its own account id). Never throws.
 */
export async function probeAccountsWithToken(
  accessToken: string,
): Promise<AccountProbe> {
  let res: Response;
  try {
    // per_page: the default page is small, and the caller may be looking for
    // ONE specific account id (CF_ACCOUNT_ID) in this list — a pinned account
    // that fell off page 1 would be refused as "not reachable".
    res = await cfOauthFetch(`${CF_API_ACCOUNTS_URL}?per_page=50`, {
      method: "GET",
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/json",
      },
    });
  } catch (e) {
    return {
      ok: false,
      status: 0,
      detail: `network error: ${e instanceof Error ? e.message : String(e)}`,
    };
  }
  let data: CfEnvelope | null = null;
  try {
    data = (await res.json()) as CfEnvelope;
  } catch {
    /* non-JSON */
  }
  if (!data || typeof data !== "object") {
    return {
      ok: false,
      status: res.status,
      detail: `HTTP ${res.status} (non-JSON response)`,
    };
  }
  if (!res.ok || data.success !== true) {
    const detail =
      (data.errors ?? [])
        .map((e) => `[${e.code}] ${e.message}`)
        .filter(Boolean)
        .join("; ") || `HTTP ${res.status}`;
    return { ok: false, status: res.status, detail };
  }
  const accounts = (Array.isArray(data.result) ? data.result : [])
    .map((r) => r as { id?: unknown; name?: unknown })
    .filter((r) => typeof r.id === "string")
    .map((r) => ({ id: r.id as string, name: (str(r.name) ?? "") as string }));
  return { ok: true, accounts };
}

// ---------------------------------------------------------------------------
// AES-GCM at-rest encryption
// ---------------------------------------------------------------------------

/**
 * Domain separation: FLASK_SECRET also keys itsdangerous signing (alias
 * suffixes, CSRF, mfa). Hashing it together with this constant guarantees
 * the AES key is unrelated to any signing key derived from the same secret.
 */
const KEY_DOMAIN = "simplelogin/cf-oauth/aes-gcm/v1";

const keyCache = new Map<string, Promise<CryptoKey>>();

function aesKey(flaskSecret: string): Promise<CryptoKey> {
  let k = keyCache.get(flaskSecret);
  if (!k) {
    k = (async () => {
      const digest = await crypto.subtle.digest(
        "SHA-256",
        enc.encode(`${flaskSecret}${KEY_DOMAIN}`),
      );
      return crypto.subtle.importKey(
        "raw",
        digest,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"],
      );
    })();
    keyCache.set(flaskSecret, k);
  }
  return k;
}

/**
 * Ciphertext format version. It is INSIDE the stored blob so that a decrypt
 * failure can be attributed: an unknown/absent prefix is a format change, a
 * well-formed "v1" blob that will not decrypt is a rotated FLASK_SECRET (or
 * a row moved between users — see the AAD below).
 */
const BLOB_VERSION = "v1";

/**
 * Encrypt a token for storage. Format:
 * "v1.<base64 iv>.<base64 ciphertext>" with a FRESH random 96-bit IV per
 * call (never reused — GCM IV reuse under the same key is catastrophic). The
 * GCM tag is appended to the ciphertext by WebCrypto, so tampering is
 * detected on decrypt.
 *
 * `aad` is authenticated but not encrypted: callers pass the owning user id,
 * which BINDS the ciphertext to that row. An attacker with D1 write access
 * who copies another user's ciphertext into their own row then gets a tag
 * failure (null) instead of a usable Cloudflare token.
 */
export async function encryptSecretValue(
  flaskSecret: string,
  plaintext: string,
  aad = "",
): Promise<string> {
  const key = await aesKey(flaskSecret);
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: enc.encode(aad) },
    key,
    enc.encode(plaintext),
  );
  return `${BLOB_VERSION}.${b64(iv)}.${b64(new Uint8Array(ct))}`;
}

/**
 * Decrypt a stored token. Returns null (never throws) on a malformed blob, a
 * version this build does not know, a failed authentication tag (tampered,
 * or the row was moved to another user id — see `aad`), or a FLASK_SECRET
 * that has been rotated since the grant was written. Callers treat all of
 * those as "not connected".
 */
export async function decryptSecretValue(
  flaskSecret: string,
  blob: string,
  aad = "",
): Promise<string | null> {
  const parts = blob.split(".");
  if (parts.length !== 3 || parts[0] !== BLOB_VERSION) return null;
  const iv = unb64(parts[1]);
  const ct = unb64(parts[2]);
  if (!iv || !ct || iv.length !== 12 || ct.length === 0) return null;
  try {
    const key = await aesKey(flaskSecret);
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: enc.encode(aad) },
      key,
      ct,
    );
    return dec.decode(pt);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// D1 storage (migrations/0004_cf_oauth.sql, table cf_oauth_token)
// ---------------------------------------------------------------------------

/** Raw row shape; *_enc columns hold ciphertext, never plaintext. */
interface CfOauthTokenRow {
  id: number;
  created_at: string;
  updated_at: string | null;
  user_id: number;
  access_token_enc: string;
  refresh_token_enc: string | null;
  expires_at: string | null;
  scopes: string | null;
  cf_account_id: string | null;
  cf_account_name: string | null;
}

/** Non-secret grant metadata — safe to render. */
export interface CfGrantMeta {
  createdAt: string;
  updatedAt: string | null;
  expiresAt: string | null;
  scopes: string | null;
  accountId: string | null;
  accountName: string | null;
  /**
   * Whether a refresh token is stored. Read from `refresh_token_enc IS NOT
   * NULL` — no decryption, no secret — so the UI can say "connected but the
   * authorization can no longer be renewed" instead of claiming a dead grant
   * is in use (Cloudflare only issues one when `offline_access` was granted).
   */
  hasRefreshToken: boolean;
}

/** A grant with its tokens DECRYPTED. Never log or render these fields. */
export interface CfOauthGrant extends CfGrantMeta {
  userId: number;
  /** null when the ciphertext could not be decrypted (FLASK_SECRET rotated). */
  accessToken: string | null;
  refreshToken: string | null;
}

export interface SaveGrantInput {
  accessToken: string;
  refreshToken?: string | null;
  expiresAt?: string | null;
  scopes?: string | null;
  accountId?: string | null;
  accountName?: string | null;
}

/**
 * Insert-or-replace the (unique) row for `userId`, encrypting both tokens
 * with the user id as GCM additional data (see encryptSecretValue).
 */
export async function saveGrant(
  env: Env,
  userId: number,
  g: SaveGrantInput,
): Promise<void> {
  const aad = String(userId);
  const accessEnc = await encryptSecretValue(
    env.FLASK_SECRET,
    g.accessToken,
    aad,
  );
  const refreshEnc = g.refreshToken
    ? await encryptSecretValue(env.FLASK_SECRET, g.refreshToken, aad)
    : null;
  await env.DB.prepare(
    `INSERT INTO cf_oauth_token
       (user_id, access_token_enc, refresh_token_enc, expires_at, scopes,
        cf_account_id, cf_account_name, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
     ON CONFLICT(user_id) DO UPDATE SET
       access_token_enc = excluded.access_token_enc,
       refresh_token_enc = excluded.refresh_token_enc,
       expires_at = excluded.expires_at,
       scopes = excluded.scopes,
       cf_account_id = excluded.cf_account_id,
       cf_account_name = excluded.cf_account_name,
       updated_at = excluded.updated_at`,
  )
    .bind(
      userId,
      accessEnc,
      refreshEnc,
      g.expiresAt ?? null,
      g.scopes ?? null,
      g.accountId ?? null,
      g.accountName ?? null,
      nowStr(),
    )
    .run();
}

/** The grant with tokens decrypted, or null when the user has none. */
export async function getGrant(
  env: Env,
  userId: number,
): Promise<CfOauthGrant | null> {
  const row = await env.DB.prepare(
    "SELECT * FROM cf_oauth_token WHERE user_id = ?1",
  )
    .bind(userId)
    .first<CfOauthTokenRow>();
  if (!row) return null;
  const aad = String(row.user_id);
  return {
    userId: row.user_id,
    accessToken: await decryptSecretValue(
      env.FLASK_SECRET,
      row.access_token_enc,
      aad,
    ),
    refreshToken: row.refresh_token_enc
      ? await decryptSecretValue(env.FLASK_SECRET, row.refresh_token_enc, aad)
      : null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    expiresAt: row.expires_at,
    scopes: row.scopes,
    accountId: row.cf_account_id,
    accountName: row.cf_account_name,
    hasRefreshToken: row.refresh_token_enc !== null,
  };
}

/** Non-secret columns only — for status rendering (no decryption at all). */
export async function getGrantMeta(
  env: Env,
  userId: number,
): Promise<CfGrantMeta | null> {
  const row = await env.DB.prepare(
    `SELECT created_at, updated_at, expires_at, scopes, cf_account_id,
            cf_account_name,
            (refresh_token_enc IS NOT NULL) AS has_refresh
       FROM cf_oauth_token WHERE user_id = ?1`,
  )
    .bind(userId)
    .first<
      Omit<
        CfOauthTokenRow,
        "id" | "user_id" | "access_token_enc" | "refresh_token_enc"
      > & { has_refresh: number }
    >();
  if (!row) return null;
  return {
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    expiresAt: row.expires_at,
    scopes: row.scopes,
    accountId: row.cf_account_id,
    accountName: row.cf_account_name,
    hasRefreshToken: row.has_refresh === 1,
  };
}

export async function deleteGrant(env: Env, userId: number): Promise<void> {
  await env.DB.prepare("DELETE FROM cf_oauth_token WHERE user_id = ?1")
    .bind(userId)
    .run();
}

/** A usable access token plus when it goes stale (unix ms, null = unknown). */
export interface CfResolvedToken {
  token: string;
  expiresAtMs: number | null;
}

/**
 * The one entry point provisioning code should use: a currently-valid access
 * token for `userId`, or null.
 *
 * Refreshes transparently when `now >= expires_at - REFRESH_SKEW_SECS`, and
 * persists WHATEVER the provider returns — Cloudflare may ROTATE the refresh
 * token, in which case the old one is invalid the moment the new one is
 * issued, so the new one must be written or the grant is lost on the next
 * refresh. When no new refresh token comes back, the existing one is kept.
 *
 * NO LOOPS: exactly one refresh attempt per call, and a permanently dead
 * grant (RFC 6749 invalid_grant — user revoked us, or the refresh token
 * expired) DELETES the row, so the next call short-circuits at "no grant"
 * instead of hammering the token endpoint. Transient failures (network,
 * 5xx, client misconfiguration) leave the row alone and just return null,
 * so a fixed CF_OAUTH_CLIENT_SECRET resurrects the grant without a
 * reconnect.
 *
 * Returns null when: no row, ciphertext undecryptable, expired with no
 * refresh token, or the refresh failed.
 *
 * `resolveAccessToken` additionally reports the token's expiry so a caller
 * making many API calls in one run can hold it in memory and come back only
 * when it is actually about to go stale, instead of paying a D1 read plus
 * two AES-GCM decrypts per call (src/web/mailbox-domain-pages.ts
 * cfProvisionCredential).
 */
export async function getValidAccessToken(
  env: Env,
  userId: number,
): Promise<string | null> {
  return (await resolveAccessToken(env, userId))?.token ?? null;
}

export async function resolveAccessToken(
  env: Env,
  userId: number,
): Promise<CfResolvedToken | null> {
  const grant = await getGrant(env, userId);
  if (!grant) return null;
  if (!grant.accessToken) {
    // FLASK_SECRET rotated (or the row was corrupted): the tokens are
    // unrecoverable, so the grant is dead — drop it and make the user
    // reconnect rather than retrying forever.
    console.error(
      `cf-oauth: undecryptable grant for user ${userId} (FLASK_SECRET rotated?) — dropping`,
    );
    await deleteGrant(env, userId);
    return null;
  }

  const now = Date.now();
  const expiresAtMs =
    grant.expiresAt === null ? null : toDate(grant.expiresAt).getTime();
  const stillFresh =
    expiresAtMs === null || now < expiresAtMs - REFRESH_SKEW_SECS * 1000;
  if (stillFresh) return { token: grant.accessToken, expiresAtMs };

  if (!grant.refreshToken) return null;
  const clientId = env.CF_OAUTH_CLIENT_ID ?? "";
  const clientSecret = env.CF_OAUTH_CLIENT_SECRET ?? "";
  if (!clientId || !clientSecret) return null;

  try {
    const tok = await refreshAccessToken({
      clientId,
      clientSecret,
      refreshToken: grant.refreshToken,
    });
    await saveGrant(env, userId, {
      accessToken: tok.accessToken,
      // rotation-safe: keep the old refresh token only if none came back
      refreshToken: tok.refreshToken ?? grant.refreshToken,
      expiresAt: tok.expiresAt,
      scopes: tok.scope ?? grant.scopes,
      accountId: grant.accountId,
      accountName: grant.accountName,
    });
    return {
      token: tok.accessToken,
      expiresAtMs: toDate(tok.expiresAt).getTime(),
    };
  } catch (e) {
    if (!(e instanceof CfOauthError)) throw e;
    console.error(`cf-oauth: refresh failed for user ${userId}: ${e.message}`);
    if (e.grantIsDead) await deleteGrant(env, userId);
    return null;
  }
}
