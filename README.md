# SimpleLogin on Cloudflare Workers

A serverless rewrite of the SimpleLogin API and email-forwarding pipeline for
the Cloudflare stack — Workers + D1 + KV + Email Routing — with a
**field-exact compatible API** so existing SimpleLogin clients (mobile apps,
browser extensions) keep working against it unchanged.

The compatibility contract lives in [`specs/`](specs/) — nine documents
extracted route-by-route from the original Flask code, covering all 52 API
routes, the data model, the email pipeline, and config quirks. The
implementation is tested field-exactly against them (exact status codes,
exact error strings, arrow-compatible date formats).

## Layout

| Path | What |
|---|---|
| `src/index.ts` | Worker entry: Hono app (`fetch`) + Email Routing handler (`email`) |
| `src/routes/` | The five API route groups (auth, aliases, alias-creation, mailboxes, user) |
| `src/email.ts` | Email Routing worker: forward + reply pipeline (spec 07) |
| `src/lib/` | Shared layer: auth middleware, crypto (bcrypt/TOTP/itsdangerous), models (premium/limits), serializers, D1 rate limiting, KV sessions, arrow-compatible dates, mailer |
| `migrations/` | D1 schema (50 tables + rate_limit) |
| `specs/` | The extracted compatibility contract |
| `test/` | Integration tests running in real workerd via `@cloudflare/vitest-pool-workers` |

## Development

Requires Node 22+.

```sh
npm ci
npm test                    # vitest, runs in workerd with real D1/KV
npx tsc --noEmit            # typecheck
npx @biomejs/biome check .  # lint + format
```

## Deploying

1. **Create the D1 database** and apply migrations:

   ```sh
   npx wrangler d1 create simplelogin
   # put the returned database_id into wrangler.jsonc (d1_databases[0].database_id)
   npx wrangler d1 migrations apply simplelogin --remote
   ```

2. **Create the KV namespace** (sessions, profile pictures):

   ```sh
   npx wrangler kv namespace create KV
   # put the returned id into wrangler.jsonc (kv_namespaces[0].id)
   ```

3. **Set the signing secret** (bcrypt-independent; signs alias suffixes, MFA
   keys — compatible with an existing Flask deployment if you reuse its
   `FLASK_SECRET`):

   ```sh
   npx wrangler secret put FLASK_SECRET
   ```

4. **Configure vars** in `wrangler.jsonc`: `EMAIL_DOMAIN` (your alias
   domain), `ALIAS_DOMAINS` (comma-separated), `PREMIUM_ALIAS_DOMAINS`,
   `URL` (app base URL used in emails), `MAX_NB_EMAIL_FREE_PLAN`. Optional
   presence-based flags (setting them at all — even to `"0"` — turns them
   on, matching the Flask config): `DISABLE_REGISTRATION`,
   `DISABLE_RATE_LIMIT`, `DISABLE_ALIAS_SUFFIX`; plus `ALIAS_LIMIT`
   (flask-limiter spec, default `100/day;50/hour;5/minute`).

5. **Wire up Email Routing** on your alias domain in the Cloudflare
   dashboard (this also provisions the MX + SPF DNS records):
   - Enable Email Routing for the zone of `EMAIL_DOMAIN`.
   - Add a catch-all rule → *Send to a Worker* → this worker.
   - Add and verify **destination addresses** for every mailbox users
     forward to — Cloudflare only delivers `message.forward()` /
     `send_email` to verified destinations (see Limitations).

6. **Deploy**:

   ```sh
   npx wrangler deploy
   ```

## Deliberate deviations from the Flask original

Documented in `HANDOVER.md` §1 and inline in the route files; the headline
items:

- Flask code paths that 500 through real bugs (e.g. session cookie without
  `X-Sl-Allowcookies`, `None` hitting `.get()`) return clean 4xx errors here.
  No working client depends on those 500s.
- Sessions are opaque KV-backed tokens (cookie still named `slapp`) instead
  of Flask's signed cookies.
- Redis rate limiting and locks are replaced by a D1 `rate_limit` table with
  flask-limiter-compatible key semantics.
- Writes to tables that only exist in the full Flask schema (audit logs,
  daily metrics, partner event queues) are skipped.
- No MX/DNS validation of mailbox domains (Workers have no raw DNS), no
  SpamAssassin/DMARC/SPF scoring and no PGP in the email pipeline.
- Profile pictures are stored in KV instead of S3.

## Platform limitations to know about

- **Forwarding only reaches verified destination addresses.** Cloudflare
  Email Routing refuses `message.forward()` / outbound `EmailMessage` sends
  to addresses that are not verified destinations of the account. A public
  multi-user deployment therefore needs each user mailbox verified through
  Cloudflare's flow (the API's own mailbox-verification email is separate).
- The reply path (alias → external contact) sends through the `send_email`
  binding and is subject to the same verified-destination restriction.
- There is no tempfail (4xx SMTP) equivalent in Email Workers — transient
  Flask errors map to permanent rejects.
- No background job runner is deployed: rows in the `job` table (account
  deletion, mailbox deletion transfers) are written faithfully but need a
  consumer (e.g. a scheduled Worker) — not implemented yet.
