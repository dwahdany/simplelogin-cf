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
  user_id: number;
  /** unix seconds when sudo mode was entered from the web dashboard */
  sudo_time?: number;
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
): Promise<void> {
  const token = randomToken();
  const data: SessionData = { user_id: userId };
  await c.env.KV.put(`session:${token}`, JSON.stringify(data), {
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
