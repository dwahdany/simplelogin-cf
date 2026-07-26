/**
 * Per-request render pipeline for the web dashboard: flash storage, the
 * context-processor globals (specs/web/00-web-infra.md §5.2), the request
 * shim, the current_user view-model (§6.9), and HTML error pages (§4).
 *
 * current_user keeps METHOD form (`current_user.is_premium()`) so templates
 * stay byte-identical to the Flask ones — the values are precomputed per
 * request and exposed as zero-arg closures.
 */

import type { Context } from "hono";
import { humanize } from "../dates";
import type { Env } from "../env";
import {
  getPremiumInputs,
  inTrial,
  isPremium,
  lifetimeOrActiveSubscription,
} from "../models";
import type { UserRow } from "../rows";
import { getSession, type SessionData, saveSession } from "../session";
import { renderTemplate } from "./templates";
import { urlFor } from "./urls";

export type FlashCategory = "success" | "error" | "warning" | "info";

/** Queue a flash message (survives redirects via the KV session). */
export async function flash<E extends { Bindings: Env }>(
  c: Context<E>,
  message: string,
  category: FlashCategory,
): Promise<void> {
  const session = (await getSession(c)) ?? {};
  session.flashes = [...(session.flashes ?? []), { category, message }];
  await saveSession(c, session);
}

/**
 * Sanitize third-party diagnostic text (an OAuth provider's
 * `error_description`, a Cloudflare API error body) before it is put in a
 * flash. Flash text renders inside `toastr.<category>("...")` in a <script>
 * block (base.html), where the template's HTML escaping is NOT JS-string
 * escaping — a message ending in a backslash would escape the closing quote.
 * So: printable ASCII only, quotes/backslashes/angle brackets dropped, hard
 * length cap. Every flash that interpolates provider text must go through
 * this (src/web/cloudflare-pages.ts, runCfProvision).
 */
export function safeDiagnostic(
  s: string | null | undefined,
  max = 160,
): string {
  if (!s) return "";
  return s
    .replace(/[^\x20-\x7e]+/g, " ")
    .replace(/["'`\\<>]/g, "")
    .slice(0, max)
    .trim();
}

/** Anonymous current_user — error pages and auth pages render through base.html. */
const ANONYMOUS_USER = {
  is_authenticated: false,
  is_admin: false,
  can_use_phone: false,
  profile_picture_id: null as number | null,
  name: "",
  email: "",
  trial_end: null as string | null,
  should_show_upgrade_button: () => false,
  in_trial: () => false,
  is_premium: () => false,
  subdomain_is_available: () => false,
  should_show_app_page: () => false,
  profile_picture_url: () =>
    urlFor("static", { filename: "default-avatar.png" }),
  get_name_initial: () => "",
};

export type CurrentUserCtx = typeof ANONYMOUS_USER & { id?: number };

/** Build the base-layout view-model for a logged-in user (async DB lookups precomputed). */
export async function buildCurrentUser<E extends { Bindings: Env }>(
  c: Context<E>,
  user: UserRow,
): Promise<CurrentUserCtx> {
  const inputs = await getPremiumInputs(c.env.DB, user.id);
  const now = new Date();
  const premium = isPremium(inputs, now);
  const trial = inTrial(user, now);
  const upgradable = !lifetimeOrActiveSubscription(inputs, now);

  const subdomainRow = await c.env.DB.prepare(
    "SELECT COUNT(*) AS n FROM public_domain WHERE can_use_subdomain = 1",
  ).first<{ n: number }>();
  const appRow = await c.env.DB.prepare(
    `SELECT (SELECT COUNT(*) FROM client_user WHERE user_id = ?1)
          + (SELECT COUNT(*) FROM client WHERE user_id = ?1) AS n`,
  )
    .first<{ n: number }>()
    .catch(() => ({ n: 0 }));

  const initials = (user.name ?? "")
    .split(" ")
    .filter(Boolean)
    .map((w) => w[0].toUpperCase())
    .join("");

  return {
    ...ANONYMOUS_USER,
    id: user.id,
    is_authenticated: true,
    is_admin: !!user.is_admin,
    can_use_phone: !!(user as unknown as { can_use_phone?: number })
      .can_use_phone,
    profile_picture_id: user.profile_picture_id,
    name: user.name ?? "",
    email: user.email,
    trial_end: user.trial_end,
    should_show_upgrade_button: () => upgradable,
    in_trial: () => trial,
    is_premium: () => premium,
    subdomain_is_available: () => (subdomainRow?.n ?? 0) > 0,
    should_show_app_page: () => (appRow?.n ?? 0) > 0,
    get_name_initial: () => initials || "",
  };
}

export interface WebRenderOptions {
  status?: number;
  /** precomputed current_user view-model; anonymous when omitted */
  currentUser?: CurrentUserCtx;
  headers?: Record<string, string>;
}

/**
 * Render a page template with the full base-layout context. Drains pending
 * flash messages (they render as toastr calls in base.html).
 */
export async function webRender<E extends { Bindings: Env }>(
  c: Context<E>,
  template: string,
  pageCtx: Record<string, unknown> = {},
  opts: WebRenderOptions = {},
): Promise<Response> {
  const env = c.env as Env & Record<string, string | undefined>;
  const url = new URL(c.req.url);
  const now = new Date();

  // Drain flashes (they must survive redirects but render exactly once).
  const session: SessionData | null = await getSession(c);
  let flashes: Array<[string, string]> = [];
  if (session?.flashes?.length) {
    flashes = session.flashes.map((f) => [f.category, f.message]);
    session.flashes = [];
    await saveSession(c, session);
  }

  const context: Record<string, unknown> = {
    // context-processor globals (§5.2)
    YEAR: now.getUTCFullYear(),
    NOW: { timestamp: now.getTime() / 1000, year: now.getUTCFullYear() },
    URL: env.URL,
    SENTRY_DSN: env.SENTRY_FRONT_END_DSN ?? null,
    VERSION: env.VERSION ?? "dev",
    FIRST_ALIAS_DOMAIN: env.FIRST_ALIAS_DOMAIN ?? env.EMAIL_DOMAIN,
    PLAUSIBLE_HOST: env.PLAUSIBLE_HOST ?? null,
    PLAUSIBLE_DOMAIN: env.PLAUSIBLE_DOMAIN ?? null,
    GITHUB_CLIENT_ID: env.GITHUB_CLIENT_ID ?? null,
    GOOGLE_CLIENT_ID: env.GOOGLE_CLIENT_ID ?? null,
    FACEBOOK_CLIENT_ID: env.FACEBOOK_CLIENT_ID ?? null,
    LANDING_PAGE_URL: env.LANDING_PAGE_URL ?? "https://simplelogin.io",
    STATUS_PAGE_URL: env.STATUS_PAGE_URL ?? "https://status.simplelogin.io",
    SUPPORT_EMAIL: env.SUPPORT_EMAIL ?? "",
    PGP_SIGNER: env.PGP_SIGNER ?? null,
    CANONICAL_URL: `${env.URL}${url.pathname}`,
    PAGE_LIMIT: 20,
    ZENDESK_ENABLED: env.ZENDESK_ENABLED !== undefined,
    MAX_NB_EMAIL_FREE_PLAN: env.MAX_NB_EMAIL_FREE_PLAN ?? "5",
    HEADER_ALLOW_API_COOKIES: "X-Sl-Allowcookies",
    // request shim (§7.8)
    request: {
      path: url.pathname,
      url: c.req.url,
      full_path: `${url.pathname}?${url.search.slice(1)}`,
      args: {
        get: (k: string, d: unknown = null) => url.searchParams.get(k) ?? d,
      },
      cookies: {
        get: (k: string) => {
          const m = (c.req.header("Cookie") ?? "").match(
            new RegExp(`(?:^|;\\s*)${k}=([^;]*)`),
          );
          return m ? decodeURIComponent(m[1]) : undefined;
        },
      },
    },
    url_for: (endpoint: string, params?: Record<string, unknown>) =>
      urlFor(endpoint, params),
    get_flashed_messages: () => flashes,
    humanize,
    current_user: opts.currentUser ?? ANONYMOUS_USER,
    ...pageCtx,
  };

  const html = renderTemplate(template, context);
  return c.html(html, (opts.status ?? 200) as 200, opts.headers);
}

/** HTML error pages (error/<status>.html), used by the app-level handlers. */
export async function renderErrorPage<E extends { Bindings: Env }>(
  c: Context<E>,
  status: 400 | 403 | 404 | 405 | 429 | 500,
  currentUser?: CurrentUserCtx,
): Promise<Response> {
  return webRender(c, `error/${status}.html`, {}, { status, currentUser });
}
