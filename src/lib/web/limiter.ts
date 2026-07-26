/**
 * Web rate limiting — flask-limiter deduct_when semantics over the D1
 * rate_limit table (key: session user if logged in, else client IP).
 * Hoisted from src/web/auth-pages.ts so all web page modules share it.
 */

import type { Context } from "hono";
import type { Env } from "../env";
import { clientIp, parseLimits } from "../ratelimit";
import { getSession } from "../session";

export interface WebLimiter {
  exceeded: boolean;
  deduct: () => Promise<void>;
}

/**
 * Check the fixed windows WITHOUT counting; `deduct()` increments (call it
 * unconditionally right after the check for Flask routes without
 * deduct_when, or only on the flagged branches otherwise).
 */
export async function webLimiter<E extends { Bindings: Env }>(
  c: Context<E>,
  name: string,
  spec: string,
): Promise<WebLimiter> {
  if (c.env.DISABLE_RATE_LIMIT !== undefined) {
    return { exceeded: false, deduct: async () => {} };
  }
  const session = await getSession(c);
  const subject =
    session?.user_id != null
      ? `userid:${session.user_id}`
      : `ip:${clientIp(c.req.raw.headers)}`;
  const windows = parseLimits(spec);
  const now = Date.now() / 1000;
  let exceeded = false;
  for (const win of windows) {
    const key = `rlw:${name}:${subject}:${win.seconds}`;
    const row = await c.env.DB.prepare(
      "SELECT count, window_start FROM rate_limit WHERE key = ?1",
    )
      .bind(key)
      .first<{ count: number; window_start: number }>();
    if (
      row &&
      row.window_start === Math.floor(now / win.seconds) &&
      row.count >= win.limit
    ) {
      exceeded = true;
      break;
    }
  }
  return {
    exceeded,
    deduct: async () => {
      const at = Date.now() / 1000;
      for (const win of windows) {
        const key = `rlw:${name}:${subject}:${win.seconds}`;
        const windowStart = Math.floor(at / win.seconds);
        await c.env.DB.prepare(
          `INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, 1)
           ON CONFLICT(key) DO UPDATE SET
             count = CASE WHEN window_start = ?2 THEN count + 1 ELSE 1 END,
             window_start = ?2`,
        )
          .bind(key, windowStart)
          .run();
      }
    },
  };
}
