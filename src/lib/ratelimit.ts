import type { Context, MiddlewareHandler } from "hono";
import type { AppEnv } from "./auth";
import { rateLimited } from "./errors";
import { getSession } from "./session";

/**
 * Fixed-window rate limiting on D1 (single-writer => atomic upserts),
 * replacing flask-limiter, plus a 5s mutex replacing parallel_limiter.lock.
 *
 * flask-limiter semantics preserved:
 * - default key: user id for cookie-session requests, client IP otherwise;
 *   routes that passed key_func=g.user.id use keyByUser.
 * - 429 responses use the /api error handler body {"error": "Rate limit exceeded"}.
 * - DISABLE_RATE_LIMIT env var (presence-based) disables the flask-limiter
 *   windows only — parallel_limiter locks stay active, like in Flask.
 */

export interface Window {
  limit: number;
  seconds: number;
}

/** Parse "100/day;50/hour;5/minute" into windows. */
export function parseLimits(spec: string): Window[] {
  const UNIT: Record<string, number> = {
    second: 1,
    minute: 60,
    hour: 3600,
    day: 86400,
  };
  return spec.split(";").map((part) => {
    const [n, unit] = part.trim().split("/");
    return { limit: Number(n), seconds: UNIT[unit.trim()] };
  });
}

async function hitWindow(
  db: D1Database,
  key: string,
  win: Window,
  now: number,
): Promise<number> {
  const windowStart = Math.floor(now / win.seconds);
  const row = await db
    .prepare(
      `INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, 1)
       ON CONFLICT(key) DO UPDATE SET
         count = CASE WHEN window_start = ?2 THEN count + 1 ELSE 1 END,
         window_start = ?2
       RETURNING count`,
    )
    .bind(`${key}:${win.seconds}`, windowStart)
    .first<{ count: number }>();
  return row?.count ?? 1;
}

export function clientIp(headers: Headers): string {
  return headers.get("CF-Connecting-IP") ?? "unknown";
}

/**
 * flask-limiter/parallel_limiter key semantics: keyed by the flask-login
 * SESSION user whenever the request carries a valid slapp cookie — even when
 * an Authentication header is also present (flask-login loads the session on
 * every request, independent of the API-key auth path) — else client IP.
 */
async function flaskLoginSubject(c: Context<AppEnv>): Promise<string> {
  const authSession = c.get("session");
  if (authSession?.user_id != null) return `user:${authSession.user_id}`;
  const cookieSession = await getSession(c);
  if (cookieSession?.user_id != null) return `user:${cookieSession.user_id}`;
  return `ip:${clientIp(c.req.raw.headers)}`;
}

/**
 * Rate-limit middleware. Must run AFTER requireApiAuth when keyBy="user".
 * keyBy="default" mirrors flask-limiter's key func: session user id when
 * cookie-authenticated, client IP otherwise (API-key traffic!).
 */
export function rateLimit(
  name: string,
  spec: string,
  keyBy: "user" | "default" | "ip" = "default",
): MiddlewareHandler<AppEnv> {
  const windows = parseLimits(spec);
  return async (c, next) => {
    if (c.env.DISABLE_RATE_LIMIT) return next();
    let subject: string;
    if (keyBy === "user") {
      subject = `user:${c.get("user").id}`;
    } else if (keyBy === "default") {
      subject = await flaskLoginSubject(c);
    } else {
      subject = `ip:${clientIp(c.req.raw.headers)}`;
    }
    const now = Date.now() / 1000;
    for (const win of windows) {
      const count = await hitWindow(
        c.env.DB,
        `rl:${name}:${subject}`,
        win,
        now,
      );
      if (count > win.limit) return rateLimited(c);
    }
    return next();
  };
}

/**
 * parallel_limiter.lock() port: 5s NX mutex held for the request duration.
 * Contention => 429 {"error": "Rate limit exceeded"}.
 * Keyed like flask-limiter (session user else IP — parallel_limiter uses
 * flask-login's current_user, NOT g.user, so API-key traffic locks per IP).
 * NOT disabled by DISABLE_RATE_LIMIT (parallel_limiter has no such filter).
 */
export function requestLock(name: string): MiddlewareHandler<AppEnv> {
  const TTL = 5;
  return async (c, next) => {
    const subject = await flaskLoginSubject(c);
    const key = `lock:${subject}:${name}`;
    const now = Math.floor(Date.now() / 1000);
    const acquired = await c.env.DB.prepare(
      `INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, 1)
       ON CONFLICT(key) DO UPDATE SET window_start = ?2
         WHERE rate_limit.window_start <= ?2 - ${TTL}
       RETURNING key`,
    )
      .bind(key, now)
      .first();
    if (!acquired) return rateLimited(c);
    try {
      await next();
    } finally {
      await c.env.DB.prepare("DELETE FROM rate_limit WHERE key = ?1")
        .bind(key)
        .run();
    }
  };
}
