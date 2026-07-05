/**
 * Server-side rendering for the web dashboard: precompiled Nunjucks
 * templates (see scripts/build-templates.mjs) rendered with the slim
 * runtime — no eval / new Function, as Workers require.
 *
 * The Environment is a module-level singleton; per-request state (user,
 * flashes, csrf token, request path...) is passed via the render context.
 */

// @ts-expect-error UMD bundle without type declarations; runtime-only build.
import nunjucks from "nunjucks/browser/nunjucks-slim.js";
import { precompiled } from "../../generated/templates";
import { humanize } from "../dates";

/** Loader protocol object serving precompiled template functions. */
const precompiledLoader = {
  getSource(name: string) {
    const tmpl = precompiled[name];
    if (!tmpl) return null;
    return { src: { type: "code", obj: tmpl }, path: name, noCache: false };
  },
};

const env: any = new (nunjucks as any).Environment(precompiledLoader, {
  autoescape: true,
});

// Filters/tests mirrored from simplelogin_app.py's jinja_env additions.
env.addFilter("dt", (value: string | Date | null) =>
  value == null
    ? ""
    : humanize(typeof value === "string" ? value : value.toISOString()),
);
env.addFilter("enumerate", (iterable: unknown[]) =>
  (iterable ?? []).map((item, i) => [i, item] as const),
);
env.addTest("none", (v: unknown) => v === null || v === undefined);
// Jinja `tojson` — Nunjucks calls it `dump`; register an alias.
env.addFilter("tojson", (v: unknown) => {
  return markSafe(
    JSON.stringify(v)
      .replaceAll("<", "\\u003c")
      .replaceAll(">", "\\u003e")
      .replaceAll("&", "\\u0026"),
  );
});

/** Duck-type of nunjucks' SafeString (the real class, so autoescape skips it). */
export interface SafeStringLike {
  val: string;
  length: number;
  toString(): string;
}

/** Mark pre-escaped HTML as safe for autoescaping (nunjucks SafeString). */
export function markSafe(html: string): SafeStringLike {
  return new (nunjucks as any).runtime.SafeString(html) as SafeStringLike;
}

/** Render a template by its path relative to cloudflare/templates/. */
export function renderTemplate(
  name: string,
  context: Record<string, unknown>,
): string {
  return env.render(name, context) as string;
}
