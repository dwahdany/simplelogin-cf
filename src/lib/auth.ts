import type { Context, MiddlewareHandler } from "hono";
import { addMinutes, nowStr, toDate } from "./dates";
import type { Env } from "./env";
import { jsonError } from "./errors";
import type { ApiKeyRow, UserRow } from "./rows";
import { getSession, type SessionData } from "./session";

/**
 * Port of app/api/base.py authorize_request / require_api_auth /
 * require_api_sudo.
 *
 * - API key is passed in the `Authentication` header (raw code, no Bearer).
 * - Cookie fallback needs BOTH an authenticated session cookie AND the
 *   `X-Sl-Allowcookies` header. (Flask 500s on session-without-header due to
 *   a bug; we return 401 "Wrong api key" instead — no working client hits it.)
 * - Every API-key request updates api_key.last_used/times before the route.
 * - Sudo mode lasts 5 minutes (api_key.sudo_mode_at or session sudo_time).
 */

export type Vars = {
  user: UserRow;
  apiKey: ApiKeyRow | null;
  session: SessionData | null;
};
export type AppEnv = { Bindings: Env; Variables: Vars };

const SUDO_MODE_MINUTES_VALID = 5;
export const HEADER_ALLOW_API_COOKIES = "X-Sl-Allowcookies";

/** User.is_active(): true if delete_on is NULL, else delete_on < now. */
export function userIsActive(user: UserRow): boolean {
  if (user.delete_on === null) return true;
  return toDate(user.delete_on).getTime() < Date.now();
}

async function authorizeRequest(
  c: Context<AppEnv>,
): Promise<Response | undefined> {
  const apiCode = c.req.header("Authentication");
  let apiKey: ApiKeyRow | null = null;
  let user: UserRow | null = null;
  let session: SessionData | null = null;

  if (apiCode !== undefined) {
    apiKey = await c.env.DB.prepare("SELECT * FROM api_key WHERE code = ?1")
      .bind(apiCode)
      .first<ApiKeyRow>();
  }

  if (!apiKey) {
    session = await getSession(c);
    if (session && c.req.header(HEADER_ALLOW_API_COOKIES)) {
      user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?1")
        .bind(session.user_id)
        .first<UserRow>();
    }
    if (!user) return jsonError(c, 401, "Wrong api key");
  } else {
    // stats update happens before any other check, like the Flask app
    await c.env.DB.prepare(
      "UPDATE api_key SET last_used = ?1, times = times + 1, updated_at = ?1 WHERE id = ?2",
    )
      .bind(nowStr(), apiKey.id)
      .run();
    user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?1")
      .bind(apiKey.user_id)
      .first<UserRow>();
    if (!user) return jsonError(c, 401, "Wrong api key");
  }

  if (user.disabled) return jsonError(c, 403, "Disabled account");
  if (!userIsActive(user)) return jsonError(c, 401, "Account does not exist");

  c.set("user", user);
  c.set("apiKey", apiKey);
  c.set("session", session);
  return undefined;
}

export const requireApiAuth: MiddlewareHandler<AppEnv> = async (c, next) => {
  const err = await authorizeRequest(c);
  if (err) return err;
  await next();
};

function sudoModeIsActive(apiKey: ApiKeyRow): boolean {
  if (!apiKey.sudo_mode_at) return false;
  const validFrom = addMinutes(new Date(), -SUDO_MODE_MINUTES_VALID);
  return toDate(apiKey.sudo_mode_at).getTime() >= validFrom.getTime();
}

function sessionSudoIsActive(session: SessionData | null): boolean {
  if (!session?.sudo_time) return false;
  return Date.now() / 1000 - session.sudo_time <= SUDO_MODE_MINUTES_VALID * 60;
}

export const requireApiSudo: MiddlewareHandler<AppEnv> = async (c, next) => {
  const err = await authorizeRequest(c);
  if (err) return err;
  const apiKey = c.get("apiKey");
  if (
    apiKey ? !sudoModeIsActive(apiKey) : !sessionSudoIsActive(c.get("session"))
  ) {
    return jsonError(c, 440, "Need sudo");
  }
  await next();
};
