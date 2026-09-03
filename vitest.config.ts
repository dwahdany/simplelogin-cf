import path from "node:path";
import {
  cloudflareTest,
  readD1Migrations,
} from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(__dirname, "migrations"));

  return {
    plugins: [
      cloudflareTest({
        singleWorker: true,
        wrangler: { configPath: "./wrangler.example.jsonc" },
        miniflare: {
          bindings: {
            TEST_MIGRATIONS: migrations,
            FLASK_SECRET: "test-flask-secret",
            // Tests are written against these fixture values; wrangler.jsonc
            // carries the real deployment vars and must not leak into tests.
            EMAIL_DOMAIN: "sl.example.com",
            ALIAS_DOMAINS: "sl.example.com",
            PREMIUM_ALIAS_DOMAINS: "",
            URL: "https://app.sl.example.com",
            MAX_NB_EMAIL_FREE_PLAN: "3",
            // Tests assert the Flask-parity rebuild path.
            FORWARD_MODE: "rewrite",
            // Deployment-only vars in wrangler.jsonc that must stay unset in
            // tests (fixtures assume open registration / Flask MX defaults).
            // Miniflare can't delete a wrangler var, so "" is the documented
            // "unset" spelling for these two (see src/lib/env.ts).
            DISABLE_REGISTRATION: "",
            EMAIL_SERVERS_WITH_PRIORITY: "",
          },
        },
      }),
    ],
    test: {
      setupFiles: ["./test/apply-migrations.ts"],
    },
  };
});
