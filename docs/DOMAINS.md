# Adding an email domain — runbook

How to add a new email domain to this deployment. Two distinct paths:

| | Public (shared) alias domain | User custom domain |
|---|---|---|
| Who uses it | all users pick alias suffixes on it | one user, their own domain |
| App-side state | `public_domain` D1 row + `ALIAS_DOMAINS` var | `custom_domain` row via dashboard |
| Who does what | operator does everything | operator: Cloudflare side; user: dashboard verification |

Both paths share the same Cloudflare-side plumbing (section 1). Related
tooling: [`scripts/provision-domain.mjs`](../scripts/provision-domain.mjs),
[`scripts/seed-public-domain.sql`](../scripts/seed-public-domain.sql),
[`scripts/backup-d1.sh`](../scripts/backup-d1.sh).

## 1. Cloudflare-side prerequisites (every domain)

Mail only reaches the worker if ALL of these hold:

1. **The domain's zone is in the operator's Cloudflare account.** Email
   Routing accepts mail only for zones it manages, and a catch-all rule can
   only target a Worker in the *same* account — so even user custom domains
   must have their zone here (Account Home > Add a domain, then the user
   points their registrar's nameservers at Cloudflare).
2. **Email Routing enabled** on the domain (auto-creates + locks the MX
   records `route1/2/3.mx.cloudflare.net` and the SPF record). Subdomains
   (like the live `mail.example.com` under the `example.com` zone) are
   onboarded individually — the apex's mail setup is untouched.
3. **A catch-all Email Routing rule of type "send to a Worker"** pointed at
   worker `simplelogin`. The catch-all is per-zone and covers every
   routing-enabled (sub)domain in it without a more specific rule.
4. **Email Sending onboarding** for the domain — **required for
   `FORWARD_MODE=rewrite`** (section 4). Dashboard-only as of 2026-07:
   Compute > Email Service > Email Sending > Onboard Domain. This
   auto-creates the `cf-bounce` MX/SPF/DKIM records and a `_dmarc` record,
   and makes Cloudflare DKIM-sign outbound `send_email` traffic for the
   domain.
5. **DMARC record** at `_dmarc.<domain>`:
   `v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s` (Email Sending
   onboarding may already have created one; keep whichever is stricter).
6. **Verified destination addresses.** Cloudflare only delivers
   `message.forward()` / `send_email` to destination addresses verified in
   the account (Email Routing > Destination addresses). Every user mailbox
   this deployment forwards to must be verified there — this is on top of
   SimpleLogin's own mailbox-verification email.

Steps 1–3 (+ 5 with `--dmarc`) are automated by the provisioning script;
step 4 is checked read-only and printed as a manual step:

```sh
cd cloudflare
CLOUDFLARE_API_TOKEN=... node scripts/provision-domain.mjs --zone new-domain.example --dmarc
```

The token must be a **scoped API token** (Zone:Read, DNS:Edit, Email Routing
Rules:Edit) — wrangler's OAuth token from `wrangler login` cannot write DNS
records or email settings. See `--help`.

Zone limit: up to 30 domains per zone across Email Routing + Email Sending,
apex included.

## 2. Public (shared) alias domain

Operator-only. In order:

1. **Cloudflare side** — run `provision-domain.mjs` as above; complete the
   Email Sending onboarding it prints (required before flipping any traffic
   under `FORWARD_MODE=rewrite`).
2. **Seed the `public_domain` row** — edit the domain (and flags: premium
   only? hidden? subdomains?) in `scripts/seed-public-domain.sql`, then:

   ```sh
   npx wrangler d1 execute simplelogin --remote --file scripts/seed-public-domain.sql
   ```

   This is what makes the domain a *valid alias domain* (suffix lists,
   dashboard, and the reply path's `isValidAliasAddressDomain` check).
3. **Add the domain to `ALIAS_DOMAINS`** (comma-separated) in
   `wrangler.jsonc` `vars`. Also:
   - `EMAIL_DOMAIN` — only if the new domain becomes the *default* domain
     (transactional mail From, default suffix, `include:` target of custom
     domains' SPF guidance).
   - `PREMIUM_ALIAS_DOMAINS` — if it should count as premium.
   `ALIAS_DOMAINS` additionally gates worker-side DKIM signing
   (`src/lib/dkim.ts`) and hostname handling in the email worker.
4. **Redeploy** — vars ship with the worker:

   ```sh
   nvm use 22   # or: nix-shell -p nodejs_22 --run '...'
   npm run deploy
   ```

5. **(Optional) worker-side DKIM fallback** — publish the
   `DKIM_PRIVATE_KEY` public key as TXT at `dkim._domainkey.<domain>`. Only
   relevant where Email Sending is not signing; also serves as the CNAME
   target for custom domains' DKIM records (see below).
6. **Verify end-to-end** before announcing: create an alias on the new
   domain, mail it from an external account (Gmail), confirm delivery and —
   under `rewrite` — check "Show original": `SPF: PASS`, `DKIM: PASS` with
   `d=<new domain>`, `DMARC: PASS`. Then reply through the reverse alias and
   confirm the contact receives it from the alias address.

Rollback / retirement: set `hidden = 1` on the `public_domain` row (existing
aliases keep working, no new suffixes) — do not delete the row while aliases
exist on it, and keep it in `ALIAS_DOMAINS`.

## 3. User custom domain

### User's point of view (SimpleLogin dashboard)

Dashboard > Domains > add the domain, then the DNS page
(`/dashboard/domains/<id>/dns`) walks through the records — values in
parentheses are what this deployment expects:

1. **Ownership TXT** at the domain root: `sl-verification=<token>`.
2. **MX** — `route1/2/3.mx.cloudflare.net` (the check compares against the
   `EMAIL_SERVERS_WITH_PRIORITY` var; Cloudflare assigns per-zone priorities
   and the check accepts the standard hosts regardless of arrangement).
   Ownership + MX verified ⇒ the domain flips to **verified** and aliases on
   it start working.
3. **SPF TXT** — `v=spf1 include:_spf.mx.cloudflare.net ~all` (deviation
   from upstream SimpleLogin, which says `include:<EMAIL_DOMAIN>`: replies
   sent for the domain leave Cloudflare's infrastructure).
4. **DKIM CNAMEs** — `dkim._domainkey`, `dkim02._domainkey`,
   `dkim03._domainkey` → the same label on `EMAIL_DOMAIN` (only the primary
   is required for the "verified" badge).
5. **DMARC TXT** — `v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s`.

SPF/DKIM/DMARC are optional for receiving but affect deliverability of mail
*sent from* the domain.

Note: if the domain's zone lives in the operator's Cloudflare account
(required — see below), Email Routing already created/locked the MX records
and Email Sending the DMARC record, so the user typically only adds the
ownership TXT and the DKIM CNAMEs.

### Operator's point of view

A custom domain needs **no app-side config** — no `ALIAS_DOMAINS` entry, no
`public_domain` row, no redeploy. The `custom_domain` row is created and
verified entirely through the dashboard. What the operator must do is make
the mail *arrive*, which is exactly section 1:

```sh
CLOUDFLARE_API_TOKEN=... node scripts/provision-domain.mjs --zone users-domain.example
```

i.e. zone in the account, Email Routing enabled, the catch-all already
pointing at `simplelogin` (per-zone — a new zone needs its own), and — for
`FORWARD_MODE=rewrite` — Email Sending onboarding for the user's domain too,
otherwise forwards for aliases on it fail DMARC at strict receivers.

## 4. FORWARD_MODE: passthrough vs rewrite

Set in `wrangler.jsonc` (`FORWARD_MODE`), pinned to `rewrite` in tests. See
`HANDOVER.md` §0 for the platform constraints behind this.

| | `rewrite` (current, Flask parity) | `passthrough` (free-tier fallback) |
|---|---|---|
| Mechanism | rebuild MIME, send via `SEND_EMAIL` binding | `message.forward()` + `X-SimpleLogin-*` headers |
| From header | reverse alias (contact identity preserved) | original sender, unmodified |
| Reply from mailbox | goes through the reverse alias (sender never sees the real address) | goes **directly to the original sender**, exposing the real mailbox |
| Body reverse-alias rewriting | yes (`replace_reverse_alias`) | impossible |
| Email Sending onboarding | **required per domain** — Cloudflare DKIM-signs, DMARC passes | not needed for forwards |
| Plan | Workers Paid (Email Sending) | free tier OK |

The mode is global, but the *onboarding requirement is per domain*: under
`rewrite`, every alias domain and every verified custom domain must be
onboarded onto Email Sending, or forwards for that domain get junked or
rejected by strict receivers (Gmail, Yahoo, corporate MX).

## 5. Troubleshooting

Reject codes are emitted by `src/email.ts` via `message.setReject(...)` and
appear in the sender's bounce and in Workers Logs (observability is enabled).

- **`550 SL E520 Unverified custom domain`** — the alias resolves to a
  `custom_domain` row with `verified = 0`. The owner must finish dashboard
  verification (ownership TXT + MX check on the DNS page). Applies to both
  inbound forwards and replies.
- **`550 SL E503`** (on replying through a reverse alias) — the alias's
  domain is *neither* in `public_domain` *nor* a verified custom domain.
  For a new public domain that means the seed step was skipped: run
  `scripts/seed-public-domain.sql` (section 2.2). No redeploy needed for
  this specific check — it reads D1.
- **Forwards land in spam / bounce with a DMARC failure** (under
  `FORWARD_MODE=rewrite`) — the *alias domain* (the From domain of the
  rebuilt message = the reverse alias's domain) is not onboarded onto Email
  Sending, so nothing DKIM-signs it. Onboard the domain (section 1.4) or
  temporarily set `FORWARD_MODE=passthrough`. Check Gmail's "Show original":
  `dkim=pass header.d=<alias domain>` is what you want.
- **Mail to the new domain bounces without ever hitting the worker**
  (no Workers Logs entry) — Email Routing isn't enabled on that (sub)domain,
  or the zone catch-all rule is missing/disabled/pointing elsewhere. Re-run
  `provision-domain.mjs` — it reports the current catch-all if it refuses to
  overwrite it.
- **Forward accepted by the worker but never delivered, log shows
  `cannot forward to <mailbox>`** — the mailbox is not a verified
  *destination address* in Cloudflare Email Routing (section 1.6). Verify it
  in the dashboard; SimpleLogin's own verification email is not enough.
- **`421 SL E404 Unexpected error - Retry later`** — transient worker error
  (D1 hiccup, unexpected exception); the sender's MTA will retry. Investigate
  in Workers Logs if it persists.
- **`provision-domain.mjs` fails with 403/Authentication error** — the token
  is missing scopes or is wrangler's OAuth token, which cannot write DNS or
  email settings. Create a scoped API token (see `--help`).
- **Onboarding a subdomain fails with a limit error** — zones cap at 30
  Email Routing/Sending domains combined, apex included.

## 6. Operations note

Before any domain surgery (retiring a domain, editing `public_domain` rows,
migrating aliases), snapshot the database:

```sh
./scripts/backup-d1.sh   # -> backups/simplelogin-YYYY-MM-DD.sql
```

KV `file:` blobs (batch-import uploads, profile pictures) are outside D1
backups — see the notes inside the script.
