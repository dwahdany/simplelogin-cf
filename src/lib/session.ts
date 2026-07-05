import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { Env } from "./env";

/**
 * KV-backed web session, replacing Flask's client-side signed "slapp" cookie.
 * The cookie value is an opaque token; clients never introspect it.
 */

export const SESSION_COOKIE = "slapp";
const SESSION_TTL_SECS = 7 * 24 * 3600; // Flask REMEMBER_COOKIE_DURATION = 7 days

export interface SessionData {
  /** absent = anonymous session (pre-login flash messages / CSRF) */
  user_id?: number;
  /** unix seconds when sudo mode was entered from the web dashboard */
  sudo_time?: number;
  /** pending flash messages, consumed on next page render */
  flashes?: Array<{ category: string; message: string }>;
  /** per-session CSRF secret (flask-wtf session["csrf_token"] equivalent) */
  csrf?: string;
  /** interstitial state (MFA-in-progress user id, next URL, ...) */
  extra?: Record<string, unknown>;
}

function randomToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

export async function createSession<E extends { Bindings: Env }>(
  c: Context<E>,
  userId: number,
  data: Omit<SessionData, "user_id"> = {},
): Promise<void> {
  const token = randomToken();
  const full: SessionData = { ...data, user_id: userId };
  await c.env.KV.put(`session:${token}`, JSON.stringify(full), {
    expirationTtl: SESSION_TTL_SECS,
  });
  setCookie(c, SESSION_COOKIE, token, {
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    maxAge: SESSION_TTL_SECS,
  });
}

/**
 * Persist changes to the CURRENT session (same token). When no session
 * cookie exists yet, an anonymous session is created — Flask equivalent:
 * writing to `session` from a pre-login view (flashes, CSRF secret, MFA
 * interstitial state).
 */
export async function saveSession<E extends { Bindings: Env }>(
  c: Context<E>,
  data: SessionData,
): Promise<void> {
  let token = getCookie(c, SESSION_COOKIE);
  if (!token) {
    token = randomToken();
    setCookie(c, SESSION_COOKIE, token, {
      path: "/",
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      maxAge: SESSION_TTL_SECS,
    });
  }
  await c.env.KV.put(`session:${token}`, JSON.stringify(data), {
    expirationTtl: SESSION_TTL_SECS,
  });
}

export async function getSession<E extends { Bindings: Env }>(
  c: Context<E>,
): Promise<SessionData | null> {
  const token = getCookie(c, SESSION_COOKIE);
  if (!token) return null;
  const raw = await c.env.KV.get(`session:${token}`);
  return raw ? (JSON.parse(raw) as SessionData) : null;
}

export async function destroySession<E extends { Bindings: Env }>(
  c: Context<E>,
): Promise<void> {
  const token = getCookie(c, SESSION_COOKIE);
  if (token) await c.env.KV.delete(`session:${token}`);
  deleteCookie(c, SESSION_COOKIE, { path: "/" });
}
