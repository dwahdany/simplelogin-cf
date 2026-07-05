import { Hono } from "hono";
import { cors } from "hono/cors";
import { handleEmail } from "./email";
import type { AppEnv } from "./lib/auth";
import { aliasCreationRoutes } from "./routes/alias-creation";
import { aliasRoutes } from "./routes/aliases";
import { authRoutes } from "./routes/auth";
import { mailboxDomainRoutes } from "./routes/mailboxes";
import { userRoutes } from "./routes/user";

const app = new Hono<AppEnv>();

// flask-cors equivalent: wildcard origin on /api/*, no credentials,
// preflight reflects requested headers (covers `Authentication`).
app.use("/api/*", cors());

app.onError((err, c) => {
  // Flask's /api error handlers: malformed JSON -> 400 "Bad Request",
  // anything else -> 500 "Internal error".
  if (err instanceof SyntaxError) {
    return c.json({ error: "Bad Request" }, 400);
  }
  console.error(err);
  return c.json({ error: "Internal error" }, 500);
});

app.get("/api/health", (c) => c.json({ status: "ok" }));

app.route("/api", authRoutes);
app.route("/api", aliasRoutes);
app.route("/api", aliasCreationRoutes);
app.route("/api", mailboxDomainRoutes);
app.route("/api", userRoutes);

export default {
  fetch: app.fetch,
  email: handleEmail,
};
