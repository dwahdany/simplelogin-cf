# Handover: SimpleLogin → Cloudflare Workers rewrite

**Goal:** Rebuild SimpleLogin as a Cloudflare-native serverless app (Workers +
D1 + KV + Email Routing) with a **byte/field-exact compatible API** so existing
client apps (mobile apps, browser extensions) keep working unchanged.

**Branch:** `cloudflare-rewrite` (off `master`). Everything lives under
`cloudflare/`. Commits so far: scaffold → specs → core lib foundations →
(uncommitted at handover time: crypto + models/serializer layers, Biome).

---

## 1. The compatibility contract: `cloudflare/specs/`

Nine spec files were extracted from the Flask source by parallel readers; they
are the **source of truth** for the rewrite. Implement from the specs; when
ambiguous, read the original Flask code (paths cited inside each spec).

- `00-routes-inventory.md` — all 52 routes, auth semantics, CORS, rate limits.
- `01-auth.md` … `05-user-settings.md` — per-route request/response/error
  schemas, exact strings and status codes.
- `06-data-model.md` — full schema; its §24 SQL block **is**
  `migrations/0001_init.sql`.
- `07-email-handling.md` — forwarding/reply pipeline for the email worker.
- `08-config.md` — config constants and their quirks.

Highest-value gotchas (clients depend on these):
- Auth header is literally **`Authentication`** (raw API key, no Bearer).
  Cookie fallback needs session cookie **and** `X-Sl-Allowcookies` header.
- Sudo failure = **HTTP 440** `{"error": "Need sudo"}`, 5-min TTL
  (`api_key.sudo_mode_at`). Entered via `PATCH /api/sudo`.
- Every API-key request **writes** `api_key.last_used/times` before the route.
- Dates: `YYYY-MM-DD HH:MM:SS+00:00` (arrow 0.16 default, no `T`/`Z`);
  `*_timestamp` = unix seconds; notifications use arrow `humanize()` strings.
- Error bodies are exact strings clients may match on (e.g. GET missing alias
  → **400** `{"error": "Unknown error"}`, not 404; contacts endpoint → 404
  `{"error": "No such alias"}`).
- 201 for: mailbox create, alias create (v2/v3/random), api_key create.
- `GET /api/export/aliases` returns CSV (the only non-JSON success).
- PAGE_LIMIT = 20 everywhere; `/api/v2/aliases` has **no** `has_more` field,
  but `/api/notifications` returns `more` (fetches PAGE_LIMIT+1).
- Alias-list filters `pinned/disabled/enabled` are **presence-based** query
  params (`?pinned=false` still filters); precedence pinned>disabled>enabled.
- `signed_suffix` = itsdangerous 1.1 TimestampSigner, secret
  `FLASK_SECRET + "custom_alias"`, max_age 600s — parse on the RIGHTMOST two
  dots. `mfa_key` = itsdangerous Signer over the user id, no expiry.

**Deliberate deviations** (documented, safe for working clients):
- Flask paths that 500 due to real bugs (session-cookie-without-header,
  missing body fields hitting `None`) return clean 4xxs here instead.
- Flask signed-cookie session → opaque KV session (cookie still named `slapp`).
- Redis rate limiting / locks → D1 `rate_limit` table (atomic single-writer
  upserts); flask-limiter key semantics preserved (IP-keyed for API-key
  traffic except `/aliases*` which key by user id).

## 2. Current state of `cloudflare/`

**Toolchain:** TypeScript + Hono 4 on Workers; vitest 4 +
`@cloudflare/vitest-pool-workers` 0.18 (tests run in real workerd; note the
new vite-plugin config API `cloudflareTest()` in `vitest.config.ts`; D1
migrations auto-applied via `test/apply-migrations.ts`). Biome (Rust) is
installed with `biome.json` written but **no format/lint pass has been run
yet** — user wants Rust/Astral-style tooling wherever possible (`uv` for any
ad-hoc Python, Biome for lint/format).

**Node is not on PATH** — prefix all npm/npx with
`nix-shell -p nodejs_22 --run '...'` from `cloudflare/`. Commands:
`npm test`, `npx tsc --noEmit`, `npx @biomejs/biome check --write .`.
Git commits must be run non-sandboxed. Test secret `FLASK_SECRET` is provided
via miniflare bindings in `vitest.config.ts`.

**Done and committed (52f0c552):**
- `migrations/0001_init.sql` (50 tables) + `0002_rate_limit.sql`.
- `src/lib/`: `auth.ts` (requireApiAuth/requireApiSudo per base.py),
  `ratelimit.ts` (fixed-window + 5s request mutex), `session.ts` (KV),
  `dates.ts` (arrow-exact format + humanize — thresholds verified against
  real arrow 0.16 via `uv run`), `errors.ts`, `rows.ts` (D1 row typings),
  `env.ts` (bindings contract). `src/index.ts` mounts CORS, error handlers
  (SyntaxError→400 "Bad Request", other→500 "Internal error"), health route,
  and five **stub** route modules in `src/routes/`.
- Smoke tests green at commit time (worker + D1 + KV in workerd).

**Done by subagents, UNCOMMITTED and NOT yet verified by the lead:**
- `src/lib/crypto.ts` + `src/lib/words.ts` + `test/crypto.test.ts` —
  bcrypt(NFKC, cost 12), TOTP (±2 steps, last_otp replay), itsdangerous
  Signer/TimestampSigner reimplementations with hardcoded Python-generated
  cross-vectors (via `uv run --with itsdangerous==1.1.0 ...`), randomString/
  tokenUrlsafe/randomWords, canonicalize/sanitizeEmail.
- `src/lib/models.ts`, `src/lib/serializer.ts`, `test/fixtures.ts`,
  `test/models.test.ts`, `test/serializer.test.ts` — premium/subscription
  precedence, alias limits, `getAliasInfosWithPaginationV3`, alias/contact
  serializers, shared test fixtures (`createUser/createAlias/...`).
- Both agents reported success, but **the first action for whoever picks this
  up is: run `npx tsc --noEmit && npm test` and fix anything red, run the
  Biome pass, then commit.** (A verification run was interrupted at handover.)

## 3. Contracts the next agents must honor

- Route modules own ONLY their file in `src/routes/` + their test file;
  shared lib files are the lead's/lib-agents' — extend, don't fork.
- Exports available to routes: `requireApiAuth`, `requireApiSudo`, `AppEnv`,
  vars `user`/`apiKey`/`session`; `rateLimit(name, spec, keyBy)`,
  `requestLock(name)`; `jsonError/badRequest/...`; `nowStr/toStr/toEpoch/
  humanize`; row types from `rows.ts`; crypto + models + serializer exports
  (see file headers). Test fixtures in `test/fixtures.ts`.
- `wrangler.jsonc`: D1 (`DB`), KV (`KV`), `send_email` (`SEND_EMAIL`), vars;
  D1/KV ids are `REPLACE_WITH_*` placeholders — real deploy needs
  `wrangler d1 create` / `kv namespace create` + `wrangler secret put
  FLASK_SECRET`, plus Email Routing wired to the email worker.

## 4. Remaining work (task list mirrors this)

1. **Route groups** (task #4) — five parallel agents, one per stub module,
   implementing from specs with field-exact tests:
   `auth.ts` (spec 01: login/register/activate/reactivate/forgot_password/mfa
   — MFA needs crypto.itsdangerous mfa_key), `aliases.ts` (spec 02: list
   v1/v2, get/update/delete/toggle, activities, contacts, contact toggle/
   delete), `alias-creation.ts` (spec 03: v4/v5 options, v2/v3 custom, random
   — signed suffixes + `requestLock("alias_creation")` + ALIAS_LIMIT),
   `mailboxes.ts` (spec 04: mailbox CRUD + v2 list, custom domains + trash),
   `user.ts` (spec 05: user_info GET/PATCH, api_key POST (sudo), sudo PATCH,
   settings + domains v1/v2, notifications, exports CSV/JSON, user DELETE
   (sudo), cookie_token, stats, logout; apple/phone/proton-unlink minimal per
   spec). Emails (activation etc.): use `SEND_EMAIL` binding when bound, else
   log — keep an injectable seam for tests.
2. **Email worker** (task #5) — `src/email.ts` per spec 07: alias resolution
   (exact → custom-domain catch-all/rules → directory), contact get-or-create
   with new-format reverse aliases, EmailLog + `alias.last_email_log_id`,
   forward via `message.forward()` to verified mailboxes, reply path via
   reverse-alias detection + sender verification, disabled-alias handling,
   VERP-style bounce address fidelity where CF allows. Export as
   `export default { fetch: app.fetch, email: handleEmail }` (lead owns
   `src/index.ts` — coordinate that one-line change).
3. **Adversarial verification** (task #6) — workflow: per route group, an
   agent diffs implementation against the ORIGINAL Flask views (not the
   specs) and reports schema mismatches with CONFIRMED/PLAUSIBLE verdicts;
   fix confirmed ones; completeness check: every route in
   `00-routes-inventory.md` §5 exists with matching methods/status codes.
4. **Finish** (task #7) — full green suite, Biome clean, README (deploy steps
   incl. D1/KV/Email Routing/DNS), commit per milestone.

## 5. Original Flask reference points

- API views: `app/api/views/*.py`; auth plumbing `app/api/base.py`;
  serializers `app/api/serializer.py`; models `app/models.py` (4198 lines);
  email pipeline `email_handler.py` (2497 lines); config `app/config.py`.
