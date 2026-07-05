/**
 * Web-session auth plumbing (specs/web/00-web-infra.md §8):
 * - user loader: KV session -> users row, anonymous when disabled /
 *   pending-deletion / alternative_id rotated away;
 * - requireWebLogin: the Flask 401-funnel — flash "You need to login to see
 *   this page" (error) + 302 /auth/login?next=<full_path>;
 * - requireWebSudo: 120 s web sudo gap, _preserved_flashes dance, redirect
 *   to /dashboard/enter_sudo?next=<path>;
 * - loginUserWeb: session-token rotation on login.
 */

import type { Context, MiddlewareHandler } from "hono";
import { userIsActive } from "../auth";
import type { Env } from "../env";
import type { UserRow } from "../rows";
import {
  getSession,
  rotateSession,
  type SessionData,
  saveSession,
} from "../session";
import { flash } from "./render";
import { urlFor } from "./urls";

const SUDO_GAP_SECS = 120;

export type WebVars = {
  webUser: UserRow;
  webSession: SessionData;
};
export type WebEnv = { Bindings: Env; Variables: WebVars };

/** Flask request.full_path: path + "?" + query — keeps a bare trailing "?". */
export function fullPath(c: Context): string {
  const url = new URL(c.req.url);
  return `${url.pathname}?${url.search.slice(1)}`;
}

/**
 * Resolve the logged-in user from the KV session, or null. Mirrors the
 * flask-login user loader: anonymous when the user is disabled, scheduled
 * for deletion, or the session's alternative_id no longer matches (password
 * reset logged this session out everywhere).
 */
export async function loadWebUser(
  c: Context<WebEnv>,
): Promise<{ user: UserRow | null; session: SessionData | null }> {
  const session = await getSession(c);
  if (session?.user_id == null) return { user: null, session };
  const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?1")
    .bind(session.user_id)
    .first<UserRow>();
  if (!user || user.disabled || !userIsActive(user))
    return { user: null, session };
  if (
    session.alternative_id &&
    user.alternative_id &&
    session.alternative_id !== user.alternative_id
  ) {
    return { user: null, session };
  }
  return { user, session };
}

/** The @login_required equivalent (401 funnel from simplelogin_app.py:310+). */
export const requireWebLogin: MiddlewareHandler<WebEnv> = async (c, next) => {
  const { user, session } = await loadWebUser(c);
  if (!user) {
    await flash(c, "You need to login to see this page", "error");
    return c.redirect(urlFor("auth.login", { next: fullPath(c) }), 302);
  }
  c.set("webUser", user);
  c.set("webSession", session ?? {});
  await next();
};

/**
 * The @sudo_required equivalent — must run AFTER requireWebLogin. On a stale
 * sudo, pending flashes are stashed in extra._preserved_flashes and restored
 * by the next sudo-fresh request (enter_sudo re-render keeps them alive).
 */
export const requireWebSudo: MiddlewareHandler<WebEnv> = async (c, next) => {
  const session = c.get("webSession");
  const now = Date.now() / 1000;
  const sudoFresh =
    session.sudo_time !== undefined && now - session.sudo_time <= SUDO_GAP_SECS;
  if (!sudoFresh) {
    if (session.flashes?.length) {
      session.extra = {
        ...session.extra,
        _preserved_flashes: session.flashes,
      };
      session.flashes = [];
      await saveSession(c, session);
    }
    const url = new URL(c.req.url);
    return c.redirect(
      urlFor("dashboard.enter_sudo", { next: url.pathname }),
      302,
    );
  }
  const preserved = session.extra?._preserved_flashes as
    | SessionData["flashes"]
    | undefined;
  if (preserved?.length) {
    session.flashes = [...preserved, ...(session.flashes ?? [])];
    delete session.extra?._preserved_flashes;
    await saveSession(c, session);
  }
  await next();
};

/**
 * login_user(): rotate the session token, keep pre-login session data
 * (flashes survive login, Flask keeps the dict), bind the user.
 */
export async function loginUserWeb(
  c: Context<WebEnv>,
  user: UserRow,
  existing?: SessionData | null,
): Promise<void> {
  const base = existing ?? (await getSession(c)) ?? {};
  await rotateSession(c, {
    ...base,
    user_id: user.id,
    alternative_id: user.alternative_id ?? undefined,
  });
}
