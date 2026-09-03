# Architecture notes: SimpleLogin on Cloudflare Workers

**Goal:** run SimpleLogin as a Cloudflare-native serverless app (Workers + D1
+ KV + Email Routing/Sending) with a **field/status-code-exact compatible
API**, so unmodified SimpleLogin clients (mobile apps, browser extensions)
work against it.

This is the engineering companion to the README: what the port consists of,
which upstream behaviours it reproduces exactly, and — most importantly —
where it deliberately diverges because the platform forces it to. Read §0
before touching `src/email.ts`.

**Status:** functionally complete and running in production by its author.
964 tests green in real workerd; `tsc` and Biome clean. All three layers
(API, email worker, web dashboard) have been through an adversarial
line-by-line diff against the upstream Flask source, followed by a fix
program adding the operational half: a cron-driven D1 job runner (alias
batch import, mailbox/domain/account deletion, onboarding and user-report
emails), DSN/bounce detection under the no-VERP model, transient-send retry,
proxied unsubscribe, PGP, Email-Routing-aware custom-domain verification, and
domain provisioning tooling (see §4a).

> Deployment specifics (URLs, resource ids, account) are intentionally not in
> this repo — see the README for setup and `wrangler.example.jsonc` for the
> configuration surface.

## 0. Platform constraints that shape the design

Cloudflare's platform imposes two constraints that shape the whole email path:
1. The `send_email` binding **requires the SMTP envelope sender to equal the
   `From` header address** — so `sendRawEmail`/`mailer.ts` send with the
   From-address as the envelope, NOT a VERP bounce address. VERP generation is
   retained only to parse any legacy VERP-addressed inbound mail. Practical
   consequence: **downstream bounces come back to the alias / reverse-alias as
   ordinary inbound mail, not to `sl.*` VERP addresses**, so the VERP-inbound
   bounce phases are largely unreachable in this deployment (documented in code).
2. `message.forward()` can only add `X-*` headers, so it cannot rewrite From/
   To/Cc. Full Flask-parity forwarding therefore rebuilds the MIME message and
   sends via the binding — which only passes strict-receiver DMARC once the
   domain is onboarded onto **Email Sending** (Cloudflare then DKIM-signs).

`FORWARD_MODE` var selects the strategy:
- `rewrite` (current) — Flask-parity: From = reverse alias, To/Cc mapped, body
  optionally rewritten; requires Email Sending onboarding.
- `passthrough` — `message.forward()` as-is (original sender in From, Reply
  goes to the sender); the free-tier fallback.

## 1. The compatibility contract: `specs/`

Extracted from the Flask source by parallel readers; the **source of truth**.
`specs/00`–`08` cover the API/data model/email pipeline/config; `specs/web/00`–
`05` cover the web dashboard blueprints. When ambiguous, read the original Flask
code (paths cited inside each spec).

Key API gotchas (clients depend on these): `Authentication` header (raw key,
not `Authorization`); cookie fallback needs `X-Sl-Allowcookies`; HTTP **440**
sudo with 5-min TTL; per-request `api_key.last_used/times` writes; arrow 0.16
date format `YYYY-MM-DD HH:MM:SS+00:00` (no `T`/`Z`); relative `humanize()`
strings on notifications; exact error strings (400 "Unknown error", 404 "No
such alias", 405 "Method not allowed"…); 201 for mailbox/alias/api_key
creation; PAGE_LIMIT 20; presence-based list filters; itsdangerous 1.1-
compatible signing (signed_suffix TimestampSigner max_age 600s, mfa_key Signer)
— byte-verified against Python vectors in `test/crypto.test.ts`.

Deliberate deviations (safe for working clients, all documented in code):
Flask 500-bug paths return clean 4xx; signed-cookie session → opaque KV
session (cookie still `slapp`); Redis limits/locks → D1 `rate_limit` table
(flask-limiter/parallel_limiter KEY SEMANTICS preserved — session user else IP);
SMTP → `SEND_EMAIL` binding; envelope-sender alignment (see §0); worker-side or
Cloudflare DKIM instead of Postfix; `ts_vector` search → LIKE approximation.

## 2. Architecture / state (all committed)

- **API** (`src/routes/`): all 52 Flask routes, field-exact. Adversarially
  verified twice — the initial 5-dimension diff (26 fixes) and the completeness
  audit (all 52 routes 1:1 on path/method/auth/status).
- **Email worker** (`src/email.ts`): alias resolution (exact → custom-domain
  catch-all/auto-create rules → directory), reverse-alias contact creation,
  forward + reply phases with full header rewriting, MIME-aware body rewrite for
  `replace_reverse_alias`, EmailLog bookkeeping, rate-limited alert/notification
  emails, defensive bounce side-effects, VERP parsing. Verified by the
  email-worker adversarial diff (forward/reply/special + branch inventory).
- **Web dashboard** (`src/web/` + `templates/` + `src/lib/web/`): ~73
  server-rendered routes ported from the Flask blueprints; nunjucks templates
  precompiled at build time (`scripts/build-templates.mjs` → `src/generated/`,
  gitignored — `npm test`'s pretest hook builds them; run it before a bare
  `npx tsc`/`vitest`). KV sessions with CSRF/flashes; static assets via the
  `ASSETS` binding (`scripts/build-assets.mjs` → `public/`). Verified by the
  5-module adversarial diff (28 fixes) + web route completeness audit.
- **Crypto/compat** (`src/lib/`): bcrypt (NFKC, cost 12), TOTP (±2 window,
  replay guard), itsdangerous Signer/TimestampSigner, arrow-exact
  dates/humanize, DKIM signer (`src/lib/dkim.ts`, RFC 6376, dkimpy-cross-checked).
- **Core lib** (`src/lib/`): auth middleware (440 sudo honors api_key
  sudo_mode_at OR browser-session sudo_time), D1 rate limiting + 5s request
  lock, KV sessions, models (subscription-precedence premium logic),
  serializers, mailer seam. Werkzeug 405-vs-404 parity in `src/index.ts`.
- **Schema**: `migrations/0001_init.sql` (50 tables) + `0002_rate_limit.sql` +
  `0003_web_tables.sql` + `0004_cf_oauth.sql` (table `cf_oauth_token`) +
  `0005_drop_cf_oauth.sql`, which **drops that table again**: Cloudflare
  authorizations are one-shot now and nothing is stored (§4a). Run
  `npx wrangler d1 migrations apply simplelogin --remote` before the next
  deploy.

## 3. Working on this codebase

- Node is NOT on PATH: prefix commands with `nix-shell -p nodejs_22 --run '...'`
  from the repo root, or use any Node 22 (`nvm use 22`).
- `npm test` (964 tests, workerd via `@cloudflare/vitest-pool-workers` 0.18 /
  vitest 4 — config uses the `cloudflareTest()` vite plugin; `pretest` builds
  templates). `npx tsc --noEmit`. `npx @biomejs/biome check --write .`.
- Test-time env vars are pinned in `vitest.config.ts` (fixtures assert
  `sl.example.com`); the real deploy vars live in `wrangler.jsonc` and must not
  leak into tests. `FORWARD_MODE=rewrite` in tests.
- Python one-offs: `uv run --with ...`. Rust tooling preferred (Biome, uv/ruff).
- Git commits/pushes non-sandboxed.
- The fixed-window rate-limit "hammer" tests are timing-sensitive and can flake
  once under heavy machine load — rerun once before treating red as real.
- Agent fan-out convention: route/page agents own only their module + test
  file; shared `src/lib/**` and `src/index.ts` belong to the lead.

## 4. Remaining / nice-to-have (nothing blocking)

- **Config-gated shells** (routes exist, feature stubbed): FIDO/WebAuthn
  assertion verification, Paddle checkout/webhooks, Zendesk support tickets
  (needs `ZENDESK_HOST`), OAuth provider token exchanges (need provider
  creds), hCaptcha (needs secret).
- **Skipped as unreachable** (documented in code, not bugs): OOO-over-VERP
  re-delivery and cross-recipient dedup — depend on VERP-addressed inbound /
  multi-RCPT transactions that don't occur under the envelope model (§0).
- **PGP scope**: forward-path mailbox PGP only; reply-phase *contact* PGP and
  the contact-detail PGP form are not implemented (documented in src/lib/pgp.ts).
- **Refactors flagged by agents:** extract duplicated helpers (email
  validation, suffix signing, alias delete — now also exported from
  `src/jobs/handlers/delete-mailbox.ts`) from route/web modules into
  `src/lib`; deterministic-time seams for humanize/premium boundary tests.
- **Not ported (out of scope, documented):** Flask-Admin panel, SpamAssassin/
  rspamd scoring, RefusedEmail→S3 quarantine, Proton OAuth partner flows,
  phone reservations UI, HIBP cron.

## 4a. Added by the 2026-07-26 fix program

- **Job runner** (`src/jobs/`): cron-driven port of job_runner.py — claim /
  retry-after-30min / error-after-5-attempts parity. Handlers: batch-import
  (full import_from_csv port — CSV from hosted SimpleLogin imports as-is,
  custom-domain rows only), delete-mailbox / delete-domain / delete-account,
  onboarding-1/2/4, send-user-report (zip attachment), retry-email.
  Maintenance (03:17 UTC): trash purge past `delete_on`, rate_limit /
  notification / old-job trims.
- **Email worker hardening** (`src/email.ts`): DSN/bounce detection without
  VERP (multipart/report → email_log bounce bookkeeping + user alert);
  transient send failures now stash the built message in KV and retry via
  `retry-email` jobs with backoff (5m/30m/2h/12h/24h) instead of hard SMTP
  rejects; per-minute flood limit accepts-and-drops with a blocked EmailLog
  (deviation: no tempfail on this platform); `X-SimpleLogin-Loop-Count` loop
  guard; noreply/no-reply spelling unified; notification-send failures no
  longer fail the reply; outbound test-capture gated to test env.
- **FWD-5 unsubscribe** (`src/lib/unsubscribe.ts`): byte-compatible
  UnsubscribeEncoder port (itsdangerous+SHA3-224 vectors); mailto-only
  List-Unsubscribe now proxied through a signed
  `/dashboard/unsubscribe/encoded/<payload>` link; the encoded decoder route
  is real (disable alias / block contact / newsletter unsub).
- **PGP** (`src/lib/pgp.ts`, openpgp.js): mailbox key import validates and
  stores; forward path builds RFC 3156 multipart/encrypted per
  prepare_pgp_message; falls back to plaintext with the Flask banner on
  encryption failure.
- **Custom domains on Email Routing**: MX verification is host-set based
  (`route1/2/3.mx.cloudflare.net` from `EMAIL_SERVERS_WITH_PRIORITY`,
  priorities ignored — CF assigns them per zone); SPF check expects
  `include:_spf.mx.cloudflare.net`; DKIM verifies on the primary record
  (custom-domain DKIM comes from Email Sending onboarding). DNS page carries
  Cloudflare-specific instructions.
- **Tooling**: `scripts/provision-domain.mjs` (zone → Email Routing → 
  catch-all-to-worker → DMARC via API; prints manual steps for Email Sending
  onboarding, which has no public write API), `scripts/backup-d1.sh`,
  `scripts/seed-public-domain.sql`, `docs/DOMAINS.md` (full add-a-domain
  runbook), `test/cors.test.ts` (browser-extension CORS contract).
  The provisioning script also has a one-click dashboard port ("Auto-
  configure on Cloudflare" on the custom-domain DNS page) —
  `src/lib/cfapi.ts` + `runCfProvision` in
  `src/web/mailbox-domain-pages.ts`; guards, rate limit and token-scoping
  requirements in `docs/DOMAINS.md` §3. **Rewritten 2026-07-26 to a ONE-SHOT
  authorization that is never stored** (the maintainer's requirement: no
  long-lived tokens that can change other people's domains). Three routes,
  picked by `cfProvisionMode()`, all going through the one guarded run — and
  **both credentialed routes show the confirmation page first**: the button
  POSTs and redirects (PRG) to `GET /dashboard/domains/<id>/cf-confirm`, which
  renders the exact record diff (from `cfProvisionPlan`, the same object the
  run writes from) and mints a ONE-TIME nonce carrying the target domain id
  and a hash of the displayed plan. Every hand-off resolves the domain from
  that nonce — no endpoint takes a `custom_domain_id` from the client, a
  confirmation is single-use, and a plan that changed since it was shown sends
  the user back to a fresh diff (`takeCfConfirmation`).
  - the operator-wide `CF_API_TOKEN` secret — the headless credential, and the
    one that WINS when both are configured (a delegated authorization only
    works for someone who can sign in to the operator's account, so offering
    it on top of `CF_API_TOKEN` would hide the credential that works). The
    confirmed POST (`form-name=cf-provision-confirmed`) runs it.
  - **one-shot user authorization**, offered only when there is no
    `CF_API_TOKEN` *and* `CF_ACCOUNT_ID` is pinned (unpinned, a delegated run
    could enable+lock Cloudflare MX on a zone whose catch-all PUT must then
    fail): confirmation page → `POST /dashboard/cloudflare/start` (CSRF +
    nonce; re-runs the mode/SL-subdomain/collision gates) → Cloudflare
    authorize with `prompt=consent` and NO `offline_access` → `GET
    /dashboard/cloudflare/callback` takes an atomic D1 claim on the state
    (KV has no CAS, so two concurrent deliveries of the same callback would
    otherwise both redeem the code), redeems it,
    runs the provisioning inline and revokes the token in a `finally`.
    Nothing reaches D1; `0005_drop_cf_oauth.sql` removed the grant table and
    with it saveGrant/refresh/AES-GCM/connect/disconnect.
    `src/lib/cfoauth.ts` + `src/web/cloudflare-pages.ts` (mounted at
    `/dashboard` in `src/index.ts`). Secrets: `CF_OAUTH_CLIENT_ID`,
    `CF_OAUTH_CLIENT_SECRET`, `CF_ACCOUNT_ID` (the account hosting this
    worker — cross-account zones cannot be provisioned, so the USER must
    authorize with that account; the confirmation page says so) and the
    optional `CF_OAUTH_SCOPES` override (`offline_access` is stripped).
    Not registered on the live deployment yet; walkthrough in
    `docs/DOMAINS.md` §3.1–§3.5.
  - **manual**: the copy-pasteable record table plus a deep link to
    Cloudflare's own Email Routing onboarding wizard, rendered in ALL modes,
    so there is always a route needing no credentials. Why not Domain
    Connect: `docs/DOMAINS.md` §3.5.
- **Test-env note**: wrangler vars merge into the vitest miniflare env; for
  presence-based flags `""` now means "unset" (`DISABLE_REGISTRATION`,
  `EMAIL_SERVERS_WITH_PRIORITY` are pinned to `""` in vitest.config.ts).

## 5. Redeploy / rotate runbook

With Node 22 on PATH, from the repo root:
- Deploy: `npm run deploy` (predeploy builds templates + assets).
- Migrations: `npx wrangler d1 migrations apply simplelogin --remote`.
- Secrets: `npx wrangler secret put FLASK_SECRET` / `DKIM_PRIVATE_KEY`.
- New domain: follow `docs/DOMAINS.md`. Short version: zone into the account,
  `CLOUDFLARE_API_TOKEN=... node scripts/provision-domain.mjs --zone <domain>
  --dmarc` (Email Routing + catch-all + DMARC), onboard Email Sending in the
  dashboard (no public write API), then for a shared domain seed
  `public_domain` (scripts/seed-public-domain.sql) + extend `ALIAS_DOMAINS`;
  for a user custom domain just verify in the dashboard (MX check accepts the
  route*.mx.cloudflare.net set). NOTE: wrangler's OAuth token cannot write
  DNS or email settings — use a scoped API token.
- Backups: `scripts/backup-d1.sh` (dated `wrangler d1 export`); KV `file:*`
  blobs (batch-import uploads) are outside D1 backups.
- Full setup notes also in `README.md`.

## 6. Original Flask reference points

API views `app/api/views/*.py`; base auth `app/api/base.py`; serializers
`app/api/serializer.py`; models `app/models.py`; email pipeline
`email_handler.py` + `app/email_utils.py` + `app/contact_utils.py`; web
blueprints `app/dashboard/views/`, `app/auth/views/`; Jinja templates
`templates/`; config `app/config.py`.
