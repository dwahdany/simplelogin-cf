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

The token must be a **scoped API token** (Zone:Read, **Zone Settings:Edit**,
DNS:Edit, Email Routing Rules:Edit) — wrangler's OAuth token from
`wrangler login` cannot write DNS records or email settings. Zone Settings is
the non-obvious one: enabling Email Routing is gated on it, not on Email
Routing Rules (§3.3). See `--help`.

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

### One-click provisioning from the dashboard (optional)

The DNS page (`/dashboard/domains/<id>/dns`) can grow an **"Auto-configure on
Cloudflare"** button — a server-side port of `provision-domain.mjs`
(`src/lib/cfapi.ts` + the cf-provision branch in
`src/web/mailbox-domain-pages.ts`). One click runs zone lookup → Email
Routing → catch-all-to-worker → ownership TXT + DMARC, then re-runs the
page's ownership/MX/SPF/DMARC checks in-process. `CF_WORKER_NAME` overrides
the catch-all target worker (default `simplelogin`).

#### 3.1 Two credential paths

The button appears when **either** credential exists, and provisioning always
prefers the first:

| | **A. User's Cloudflare account (OAuth)** | **B. Operator's static token** |
|---|---|---|
| Config | `CF_OAUTH_CLIENT_ID` + `CF_OAUTH_CLIENT_SECRET` | `CF_API_TOKEN` |
| Whose account | the account *the user connects themselves* | the operator's |
| Per user | yes (one grant per user, D1 `cf_oauth_token`) | no, instance-wide |
| Revocation | user: Disconnect button; account owner: Cloudflare dashboard > Manage Account > Authorized apps | operator rotates the secret |
| Storage | AES-GCM ciphertext in D1, key derived from `FLASK_SECRET` | wrangler secret |
| Lifetime | short-lived access token, auto-refreshed (refresh token) | until revoked |

Both paths run **the same code** (`handleCfProvision`): identical guards,
identical rate limit, identical refusals. The only difference is the bearer
token on the outgoing calls — the OAuth token is resolved once per run and
re-resolved as soon as it enters the 60 s refresh window, so an access token
that ages out mid-run is refreshed transparently (it never falls back to
`CF_API_TOKEN` mid-run: that would finish writing under an authorization the
user never granted).

A grant that exists but yields no token right now (expired with no refresh
token, or revoked at Cloudflare) is a **refusal, not a downgrade**: the run
stops with "please connect your Cloudflare account again" rather than
quietly continuing under the operator's account-wide token. The connect panel
says the same thing before the click (`needs_reconnect`).

With neither credential the feature is off: the button is hidden and the POST
`form-name` is ignored (falls through to a plain page render). `""` counts as
unset everywhere, and a half-configured OAuth client (id without secret) is
off.

**Cross-account provisioning does NOT work — by design of the platform.**
Cloudflare Email Routing can only deliver a zone's mail to a Worker in the
**same account**, and the catch-all this code writes names `CF_WORKER_NAME`
with no account qualifier. So whichever path is used, the domain's zone must
live in the Cloudflare account that hosts this worker. Path A's value is
therefore *delegation*, not multi-tenancy: the user authorizes their own
(operator-hosted) account with a revocable, per-user grant instead of the
operator holding one token that can edit every zone.

Pin that account so the code can enforce it:

```sh
npx wrangler secret put CF_ACCOUNT_ID   # or add it to wrangler.jsonc `vars`
```

With `CF_ACCOUNT_ID` set, (a) the OAuth callback refuses (and revokes) a
grant that cannot see that account, and (b) provisioning refuses a zone whose
`account.id` differs — **before** the Email-Routing enable, which would
otherwise write and lock the zone's MX records and only then fail on the
catch-all, leaving the zone advertising Cloudflare MX with nothing behind
them (inbound mail rejected). Unset, both checks are skipped and that failure
mode is on the operator to avoid.

#### 3.2 Registering the OAuth client (path A, operator, one-off)

Cloudflare self-managed OAuth went GA 2026-06-03
([docs](https://developers.cloudflare.com/fundamentals/oauth/)). Requires the
role **Super Administrator**, **Administrator** or **OAuth Client Write**.

1. Cloudflare dashboard > **Manage Account > OAuth clients > Create client**.
2. Fields:
   - **Client name**: anything, e.g. `SimpleLogin (self-hosted)`.
   - **Response types**: `code` (Authorization Code is the only flow
     supported for third-party clients).
   - **Grant types**: `authorization_code` **and** `refresh_token` (without
     the latter the grant dies at the first access-token expiry and every
     user has to reconnect).
   - **Token endpoint auth method**: `client_secret_basic` — this is a
     server-side Worker, i.e. a confidential client. (PKCE S256 is sent
     anyway.)
   - **Redirect URL**: `<URL var>/dashboard/cloudflare/callback`, e.g.
     `https://simplelogin.example.workers.dev/dashboard/cloudflare/callback`.
     It is derived from the `URL` var, never from the request Host header, so
     it must match that var exactly.
   - **Scopes**: see §3.3 — including `offline_access`.
3. Store the credentials:

   ```sh
   npx wrangler secret put CF_OAUTH_CLIENT_ID
   npx wrangler secret put CF_OAUTH_CLIENT_SECRET
   npx wrangler secret put CF_ACCOUNT_ID      # §3.1, account hosting the worker
   ```

   Optional: `CF_OAUTH_SCOPES` (space-separated) overrides the requested
   scope list without a code change. It is read from the environment like
   any other var, so it only exists at runtime if you either add it to
   `wrangler.jsonc` `vars` **or** push it with
   `npx wrangler secret put CF_OAUTH_SCOPES` — setting it anywhere else is a
   silent no-op and the built-in defaults are used.

Endpoints used (all on `dash.cloudflare.com`, **not** `api.cloudflare.com`):
`/oauth2/auth`, `/oauth2/token`, `/oauth2/revoke`, discovery at
`https://dash.cloudflare.com/.well-known/openid-configuration`. The API calls
the grant then authorizes still go to `api.cloudflare.com/client/v4`; the
callback proves that end-to-end with a `GET /client/v4/accounts` probe before
storing anything, and refuses to store a grant the API will not accept.

#### 3.3 Scopes — the caveat and the zone-settings trap

Default requested scopes (`DEFAULT_CF_OAUTH_SCOPES` in
`src/web/cloudflare-pages.ts`):

```
offline_access account.read zone.read zone-settings.read zone-settings.write
email-routing-rule.read email-routing-rule.write dns.read dns.write
```

**Only `account.read` is officially documented** (`offline_access` is a
protocol scope and appears in the discovery document's `scopes_supported`).
The rest are derived from Cloudflare's permission-group labels and are
**unverified**. Enumerate the real ids before registering the client — the
endpoint takes *any* API token:

```sh
curl -s https://api.cloudflare.com/client/v4/oauth/scopes \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" | jq '.result[] | {id, name}'
```

Use the `id` field verbatim (ids are dot-delimited; colon-delimited forms are
rejected).

**`offline_access` is requested explicitly and must be ticked in the client's
scope picker.** Cloudflare's authorization server is Ory Hydra/fosite
(visible in the discovery document), which mints a refresh token only when
`offline`/`offline_access` is among the **granted** scopes — listing
`refresh_token` in the client's grant types is necessary but *not*
sufficient. Without it every grant dies ~1 h after connecting and cannot be
renewed. The callback detects this at connect time: it stores the grant and
flashes a warning naming `offline_access` and `CF_OAUTH_SCOPES` (and logs
it), and the connect panel then shows "this authorization can no longer be
renewed" once the access token has expired.

**The trap:** the Accepted-Permissions badge on each endpoint does not follow
the product names.

| Call the provisioner makes | Permission actually required |
|---|---|
| `GET /zones?name=` | **Zone** Read |
| `GET/POST /zones/{id}/email/routing`, `.../enable`, `.../dns` | **Zone Settings** read/write (*not* Email Routing Rules) |
| `GET/PUT /zones/{id}/email/routing/rules/catch_all` | **Email Routing Rules** read/write |
| `GET/POST /zones/{id}/dns_records` | **DNS** read/write |

An OAuth client registered without the zone-settings scopes therefore
authorizes fine, passes the callback probe, and then **403s exactly at the
Email-Routing-enable step**. The dashboard says so: a 401/403 under an OAuth
grant flashes "the authorization is missing a permission or has expired",
names the zone-settings scopes and tells the user to reconnect (a 401/403
under `CF_API_TOKEN` keeps the generic "Cloudflare API error" wording — the
user cannot fix the operator's token).

The same mapping applies to the static token of path B: scope it
Zone:Read, **Zone Settings:Edit**, DNS:Edit, Email Routing Rules:Edit.

#### 3.4 Security model

Under path B the button plants the ownership TXT with the *operator's* token,
i.e. clicking it "proves" ownership of any name that token can edit, for
whichever user added the domain. Path A narrows this to the user's own
account, but every guard below applies to both paths:

- `CF_API_TOKEN` MUST be a scoped API token (see §3.3) and should
  additionally be **zone-scoped to only the zones intended for user custom
  domains** wherever possible.
- The server refuses domains that overlap the deployment's own mail
  domains (`EMAIL_DOMAIN`, `FIRST_ALIAS_DOMAIN`, `ALIAS_DOMAINS`,
  `PREMIUM_ALIAS_DOMAINS`, every `public_domain` row) **and** any domain
  whose resolved zone hosts one of them (sibling hostnames like
  `foo.example.com` next to `mail.example.com`) — token zone-scoping
  cannot cover that case, because the token must be able to edit the very
  zone hosting `EMAIL_DOMAIN`.
- Non-destructive: it refuses (never overwrites) a catch-all rule with a
  foreign destination — even a disabled one — and refuses to enable Email
  Routing on a name that already carries non-Cloudflare MX records.
- **Nothing is written until every read-only check has passed**, and an
  authorization failure during those checks is never mistaken for "this zone
  has no Email Routing yet": a 401/403 on the catch-all preflight aborts
  before the Email-Routing enable rather than falling through into it (that
  ordering is what keeps a wrong `email-routing-rule.*` scope from leaving a
  zone with Cloudflare MX and no rule behind them). Same for the
  `CF_ACCOUNT_ID` check of §3.1.
- Rate-limited per user (3/minute; 20/hour) — each click spends up to ~10
  authenticated calls of the Cloudflare API quota (the *user's* quota under
  path A, the operator's under path B).
- Flashes never contain tokens, zone names or zone ids; full errors go to
  Workers Logs via `console.error`.
- Connect and Disconnect are **POSTs with the page's CSRF token, behind web
  sudo** (like `/api_key`): the session cookie is `SameSite=Lax`, so a
  cross-site top-level navigation would otherwise be able to start — and for
  an already-consented user silently finish — a connection.
- Tokens are AES-GCM encrypted at rest with a key derived from
  `FLASK_SECRET`, versioned (`v1.<iv>.<ct>`) and bound to the owning
  `user_id` as GCM additional data, so a row copied to another user fails to
  decrypt. Rotating `FLASK_SECRET` invalidates every grant (users reconnect).
- Every path that drops a grant asks Cloudflare to revoke **both** tokens
  first — Disconnect, a failed post-issue probe, reconnecting over an
  existing grant, and account deletion (the `cf_oauth_token` cascade in
  `handleDeleteAccount` would otherwise strand a live refresh token).
- What it does NOT do (reported in the flash as the remaining manual
  steps): Email Sending onboarding (§1.4, dashboard-only) and
  destination-address verification (§1.6).

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
  email settings. Create a scoped API token (see `--help` and §3.3).
- **"Auto-configure on Cloudflare" fails right after "zone found", with
  "the authorization is missing a permission"** — under a connected
  Cloudflare account this is almost always the zone-settings trap (§3.3):
  the OAuth client was registered without `zone-settings.read` /
  `zone-settings.write`, so enabling Email Routing is refused. Fix the
  client's scopes in Manage Account > OAuth clients, then have the user
  Disconnect and Connect again — existing grants keep the scopes they were
  issued with. If the wording is the generic "Cloudflare API error" instead,
  the run used the operator's `CF_API_TOKEN`: add Zone Settings:Edit there.
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
