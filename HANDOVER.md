# Handover: SimpleLogin → Cloudflare Workers rewrite

**Goal:** Rebuild SimpleLogin as a Cloudflare-native serverless app (Workers +
D1 + KV + Email Routing) with a **field/status-code-exact compatible API** so
existing client apps (mobile apps, browser extensions) keep working unchanged.

**Branch:** `cloudflare-rewrite` (off `master`). Everything lives under
`cloudflare/`. As of commit `34f42417` the port is functionally complete:
API + email worker + server-rendered web dashboard, 672 tests green in real
workerd, tsc + Biome clean.

---

## 1. The compatibility contract: `cloudflare/specs/`

Extracted from the Flask source by parallel readers; the **source of truth**.
`00`–`08` cover the API/data model/email pipeline/config; `specs/web/00`–`05`
cover the web dashboard blueprints. When ambiguous, read the original Flask
code (paths cited inside each spec).

Key API gotchas (clients depend on these): `Authentication` header (raw key);
cookie fallback needs `X-Sl-Allowcookies`; HTTP 440 sudo with 5-min TTL;
per-request api_key.last_used/times writes; arrow 0.16 date format
`YYYY-MM-DD HH:MM:SS+00:00`; exact error strings (400 "Unknown error",
404 "No such alias", 405 "Method not allowed"...); 201 for mailbox/alias/
api_key creation; PAGE_LIMIT 20; presence-based list filters; itsdangerous
1.1-compatible signing (signed_suffix TimestampSigner max_age 600s, mfa_key
Signer) — byte-verified against Python vectors in test/crypto.test.ts.

Deliberate deviations (safe for working clients): Flask 500-bug paths return
clean 4xx; signed-cookie session → opaque KV session (cookie still "slapp");
Redis limits/locks → D1 `rate_limit` table with flask-limiter/parallel_limiter
KEY SEMANTICS preserved (session user else IP; locks not disabled by
DISABLE_RATE_LIMIT); SMTP → SEND_EMAIL binding via src/lib/mailer.ts;
ts_vector search → LIKE approximation (documented in serializer.ts).

## 2. Architecture / state (all committed)

- **API** (`src/routes/`): all 52 Flask routes, field-exact. Adversarially
  verified: 5 finder agents diffed implementation vs Flask views, findings
  re-verified by skeptics, 26 confirmed mismatches fixed with regression
  tests (commit `34f42417`).
- **Email worker** (`src/email.ts`): alias resolution (exact → catch-all/
  rules → directory), reverse-alias contact creation, EmailLog +
  last_email_log_id, forward/reply paths, VERP.
- **Web dashboard** (`src/web/` + `templates/` + `src/lib/web/`): ~73
  server-rendered routes ported from the Flask blueprints; nunjucks templates
  precompiled at build time (`scripts/build-templates.mjs` → `src/generated/`,
  gitignored — `npm test`'s pretest hook builds them; run it before a bare
  `npx tsc`/`vitest`). KV sessions with CSRF/flashes; static assets via the
  ASSETS binding (`scripts/build-assets.mjs` → `public/`).
  Deferred shells (config-gated, routes present): FIDO assertion verification,
  PGP key import (needs an OpenPGP port), Paddle checkout/webhooks, Zendesk
  (needs ZENDESK_HOST), OAuth token exchanges (need provider credentials).
- **Core lib** (`src/lib/`): auth middleware (440 sudo honors either api_key
  sudo_mode_at OR browser-session sudo_time), D1 rate limiting, KV sessions,
  arrow-exact dates/humanize, itsdangerous/bcrypt/TOTP crypto, models
  (subscription-precedence premium logic), serializers, mailer seam.
  405-vs-404 Werkzeug parity implemented in `src/index.ts` notFound.
- **Schema**: `migrations/0001_init.sql` (50 tables) + `0002_rate_limit.sql`.

## 3. Working on this codebase

Node is NOT on PATH: `nix-shell -p nodejs_22 --run '...'` from `cloudflare/`.
`npm test` (672 tests, workerd via vitest-pool-workers 0.18/vitest 4 —
config uses the `cloudflareTest()` vite plugin), `npx tsc --noEmit`,
`npx @biomejs/biome check --write .`. Python one-offs: `uv run --with ...`.
Git commits non-sandboxed. Rust tooling preferred (Biome, uv/ruff).

File ownership pattern used by agent fan-outs: route/page agents own only
their module + test file; shared lib/index.ts belong to the lead. Test
fixtures in `test/fixtures.ts`; web tests seed KV sessions directly.

## 4. Remaining / nice-to-have

- Completeness audit of all 52 routes re-run (first attempt returned empty) —
  check result, fix anything it surfaces.
- Deploy runbook is in README.md: `wrangler d1 create` + migrations,
  KV namespace, `wrangler secret put FLASK_SECRET`, Email Routing → worker,
  DNS/MX; wrangler.jsonc has `REPLACE_WITH_*` placeholder ids.
- Follow-up refactors flagged by agents: extract duplicated helpers
  (email validation, suffix signing, alias delete) from route modules into
  src/lib; deterministic-time test seams for humanize/premium boundaries;
  port openpgp.js for PGP import; WebAuthn ceremony support.
- Not ported (out of scope, documented): Flask-Admin panel, Paddle webhooks,
  Proton OAuth partner flows, phone reservations UI, batch import S3 jobs.

## 5. Original Flask reference points

API views `app/api/views/*.py`; base auth `app/api/base.py`; serializers
`app/api/serializer.py`; models `app/models.py`; email `email_handler.py`;
web blueprints `app/dashboard/`, `app/auth/`; templates `templates/`.
