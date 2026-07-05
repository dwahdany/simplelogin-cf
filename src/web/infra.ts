/**
 * App-level web routes (specs/web/00-web-infra.md §3): index redirect,
 * health/monitor endpoints, /dnt, OIDC metadata, internal helpers, and the
 * consciously-deferred Paddle webhooks.
 */

import { Hono } from "hono";
import { getSession, saveSession } from "../lib/session";
import { flash } from "../lib/web/render";
import { urlFor } from "../lib/web/urls";
import { loadWebUser, type WebEnv } from "../lib/web/webauth";

export const webInfraRoutes = new Hono<WebEnv>();

// GET+POST / -> dashboard when logged in, else login (simplelogin_app.py set_index_page)
webInfraRoutes.on(["GET", "POST"], "/", async (c) => {
  const { user } = await loadWebUser(c);
  return c.redirect(
    user ? urlFor("dashboard.index") : urlFor("auth.login"),
    302,
  );
});

webInfraRoutes.get("/health", (c) => c.text("success"));
webInfraRoutes.get("/git", (c) => c.text("dev"));
webInfraRoutes.get("/version", (c) => c.text("dev"));
webInfraRoutes.get("/live", (c) => c.text("live"));
webInfraRoutes.get("/exception", () => {
  throw new Error("to make sure sentry works");
});

webInfraRoutes.get("/favicon.ico", (c) =>
  c.redirect("/static/favicon.ico", 302),
);

// Raw HTML fragment, byte-identical semantics to Flask's /dnt response.
webInfraRoutes.get("/dnt", (c) =>
  c.html(`<script src="/static/local-storage-polyfill.js"></script>

<script>
store.set('analytics-ignore', 't');
alert("Analytics disabled");
window.location.href = "/";
</script>`),
);

// Static OIDC discovery metadata (the provider itself is out of scope).
webInfraRoutes.get("/.well-known/openid-configuration", (c) => {
  c.header("Access-Control-Allow-Origin", "*");
  return c.json({
    issuer: c.env.URL,
    authorization_endpoint: `${c.env.URL}/oauth2/authorize`,
    token_endpoint: `${c.env.URL}/oauth2/token`,
    userinfo_endpoint: `${c.env.URL}/oauth2/userinfo`,
    jwks_uri: `${c.env.URL}/jwks`,
    response_types_supported: [
      "code",
      "token",
      "id_token",
      "id_token token",
      "id_token code",
    ],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
  });
});

// OIDC provider signing key — deferred with the oauth blueprint.
webInfraRoutes.get("/jwks", (c) => c.notFound());

// GET with side effects, works even for anonymous sessions (Flask parity).
webInfraRoutes.get("/internal/exit-sudo-mode", async (c) => {
  const session = (await getSession(c)) ?? {};
  session.sudo_time = 0;
  await saveSession(c, session);
  await flash(c, "Exited sudo mode", "info");
  return c.redirect(urlFor("dashboard.index"), 302);
});

webInfraRoutes.get("/internal/integrations/proton", async (c) => {
  await flash(
    c,
    "You can now connect your Proton and your SimpleLogin account",
    "success",
  );
  const { user } = await loadWebUser(c);
  return c.redirect(
    user
      ? urlFor("dashboard.setting", { _anchor: "connect-with-proton" })
      : urlFor("auth.login"),
    302,
  );
});

// Paddle webhooks — BLOCKER B5, consciously not ported.
webInfraRoutes.on(["GET", "POST"], "/paddle", (c) =>
  c.text("Paddle webhook not supported in this deployment", 501),
);
webInfraRoutes.on(["GET", "POST"], "/paddle_coupon", (c) =>
  c.text("Paddle webhook not supported in this deployment", 501),
);
