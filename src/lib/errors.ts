import type { Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";

/** `{"error": msg}` with an arbitrary status — the API's standard error shape. */
export function jsonError(c: Context, status: number, msg: string): Response {
  return c.json({ error: msg }, status as ContentfulStatusCode);
}

export const badRequest = (c: Context, msg: string) => jsonError(c, 400, msg);
export const forbidden = (c: Context, msg = "Forbidden") => jsonError(c, 403, msg);
export const notFound = (c: Context, msg: string) => jsonError(c, 404, msg);
export const rateLimited = (c: Context) => jsonError(c, 429, "Rate limit exceeded");
