import { Hono } from "hono";
import { cors } from "hono/cors";
import { handleEmail } from "./email";
import type { AppEnv } from "./lib/auth";
import { renderErrorPage } from "./lib/web/render";
import { aliasCreationRoutes } from "./routes/alias-creation";
import { aliasRoutes } from "./routes/aliases";
import { authRoutes } from "./routes/auth";
import { mailboxDomainRoutes } from "./routes/mailboxes";
import { userRoutes } from "./routes/user";
import { webAliasPagesRoutes } from "./web/alias-pages";
import { webAuthPagesRoutes } from "./web/auth-pages";
import { webBillingPagesRoutes } from "./web/billing-pages";
import { webInfraRoutes } from "./web/infra";
import { webMailboxDomainPagesRoutes } from "./web/mailbox-domain-pages";
import { webSettingsPagesRoutes } from "./web/settings-pages";

const app = new Hono<AppEnv>();

// Flask sets strict_slashes=False app-wide: /dashboard/ == /dashboard.
// Normalize by re-dispatching the stripped path (one level of recursion).
app.use("*", async (c, next) => {
  const url = new URL(c.req.url);
  if (url.pathname.length > 1 && url.pathname.endsWith("/")) {
    const stripped = url.pathname.replace(/\/+$/, "");
    // Skip when the stripped path is itself a mount root that only exists
    // with the slash (none today) — plain re-dispatch:
    url.pathname = stripped;
    let ctx: unknown;
    try {
      ctx = c.executionCtx;
    } catch {
      ctx = undefined;
    }
    return app.fetch(
      new Request(url.toString(), c.req.raw),
      c.env,
      ctx as Parameters<typeof app.fetch>[2],
    );
  }
  await next();
});

// flask-cors equivalent: wildcard origin on /api/*, no credentials,
// preflight reflects requested headers (covers `Authentication`).
app.use("/api/*", cors());

app.onError(async (err, c) => {
  // Flask's error handlers branch on the path: /api/* gets JSON, the web
  // gets HTML error pages (specs/web/00-web-infra.md §4).
  const isApi = new URL(c.req.url).pathname.startsWith("/api/");
  if (err instanceof SyntaxError) {
    if (isApi) return c.json({ error: "Bad Request" }, 400);
    return renderErrorPage(c, 400);
  }
  console.error(err);
  if (isApi) return c.json({ error: "Internal error" }, 500);
  return renderErrorPage(c, 500);
});

app.notFound(async (c) => {
  const isApi = new URL(c.req.url).pathname.startsWith("/api/");
  if (isApi) return c.json({ error: "No such endpoint" }, 404);
  return renderErrorPage(c, 404);
});

app.get("/api/health", (c) => c.json({ status: "ok" }));

app.route("/api", authRoutes);
app.route("/api", aliasRoutes);
app.route("/api", aliasCreationRoutes);
app.route("/api", mailboxDomainRoutes);
app.route("/api", userRoutes);

// Web dashboard (server-rendered)
app.route("/", webInfraRoutes);
app.route("/auth", webAuthPagesRoutes);
app.route("/dashboard", webAliasPagesRoutes);
app.route("/dashboard", webMailboxDomainPagesRoutes);
app.route("/dashboard", webSettingsPagesRoutes);
app.route("/dashboard", webBillingPagesRoutes);

export default {
  fetch: app.fetch,
  email: handleEmail,
};
