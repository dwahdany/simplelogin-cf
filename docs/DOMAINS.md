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

The DNS page (`/dashboard/domains/<id>/dns`) carries an **"Auto-configure on
Cloudflare"** card — a server-side port of `provision-domain.mjs`
(`src/lib/cfapi.ts` + `runCfProvision` in `src/web/mailbox-domain-pages.ts`).
One run does zone lookup → Email Routing → catch-all-to-worker → ownership TXT
+ DMARC, then re-runs the page's ownership/MX/SPF/DMARC checks in-process.
`CF_WORKER_NAME` overrides the catch-all target worker (default
`simplelogin`).

#### 3.1 Three routes, one of which always exists

|  | **A. One-shot user authorization** | **B. Operator's static token** | **C. Manual** |
|---|---|---|---|
| Config | `CF_OAUTH_CLIENT_ID` + `CF_OAUTH_CLIENT_SECRET` + `CF_ACCOUNT_ID`, and **no** `CF_API_TOKEN` | `CF_API_TOKEN` | nothing |
| Whose account | the account the user approves, per run | the operator's | the user's own browser session |
| Stored | **nothing at all** | wrangler secret | — |
| Lifetime | the single request it was minted for (revoked in a `finally`; Hydra's ~1 h ceiling is the backstop) | until rotated | — |
| Renewable | **no** — `offline_access` is never requested, so there is no refresh token | n/a | n/a |

`cfProvisionMode()` picks **B when `CF_API_TOKEN` is set**, else A when an
OAuth client is registered *and* `CF_ACCOUNT_ID` is pinned, else "none" — and
**C is rendered in all three cases**, so a user always has a route that
requires no credentials from anyone.

Two prerequisites decide whether A is offered at all, both for the same
reason (the same-account constraint below):

- **`CF_ACCOUNT_ID` must be pinned.** The delegated token belongs to whatever
  account the user signs in with, so `findZone` normally *succeeds* on a zone
  that can never be finished; without a pinned account the per-zone guard has
  nothing to compare against and the run would enable (and LOCK) Cloudflare MX
  on that zone before failing on the catch-all. Unpinned, A is withdrawn and
  the mode falls back to B/none (with a `console.error` naming the var).
- **`CF_API_TOKEN` wins when both exist.** A delegated authorization only ever
  works for a user who can sign in to the operator's account, while the
  operator's own token works for every user. Letting A supersede B would send
  every user of a multi-user instance to a consent screen that cannot help
  them, and hide the credential that can. An operator who wants A simply does
  not set `CF_API_TOKEN`.

**Both credentialed routes show the confirmation page first.** The click never
runs anything:

1. The DNS-page button POSTs (CSRF) and **redirects** (POST/Redirect/GET) to
   `GET /dashboard/domains/<id>/cf-confirm`, which lists the exact diff: the
   `sl-verification` TXT (name + value), the `_dmarc` TXT (name + value), the
   MX/SPF set Cloudflare will create **and lock** when Email Routing is
   enabled, and the zone-wide catch-all pointed at `CF_WORKER_NAME`. Those
   values come from `cfProvisionPlan()` — the same object the run writes from,
   so the preview cannot drift from the writes. Under A the page also says
   plainly that the account signed in with must be the one hosting this
   instance's mail worker, that Cloudflare's consent screen has no zone picker
   (the authorization is account-wide for the duration of the run), that it is
   not stored, that it cannot be renewed, and that it is revoked when the run
   ends.
2. Rendering that page mints a **one-time confirm nonce** into the KV session
   together with the target domain id and a **hash of the plan as displayed**.
   Everything downstream reads the domain out of that slot: no endpoint takes a
   `custom_domain_id` from the client any more, the nonce is single-use, and a
   plan that changed since it was rendered sends the user back to a fresh diff
   instead of writing records they never saw (`takeCfConfirmation`).
3. Under **B**, the page's button posts `form-name=cf-provision-confirmed` back
   to the DNS page, which spends the rate limit and runs immediately with the
   operator's token.
   Under **A**, it POSTs (CSRF + nonce) to `/dashboard/cloudflare/start`, which
   re-applies every gate, mints `state` + PKCE verifier + the target
   `custom_domain` id into the KV session and redirects to the authorize
   endpoint **with `prompt=consent`** (Hydra remembers consent sessions —
   without it a second run would silently skip the screen, which would recreate
   the standing delegation this design exists to avoid).
4. `/dashboard/cloudflare/callback` validates the state and takes an atomic D1
   claim on it before anything else, so two concurrent deliveries of the same
   callback cannot both redeem the code, redeems the code with
   the PKCE verifier, and **runs the provisioning inline with that access
   token**, then revokes it in a `finally` — success, refusal or exception
   alike. The token is never written to D1 and never leaves the request.

There is **no "connect your Cloudflare account"**, no grant table, no refresh
token and no Disconnect button: `migrations/0005_drop_cf_oauth.sql` drops the
`cf_oauth_token` table that the previous design used.

Both A and B call **the same function** (`runCfProvision`) with an
already-resolved token: identical guards, identical rate limit, identical
refusals. The only thing `source` changes is the wording of a 401/403 flash
(the user can re-authorize; they cannot fix the operator's token) and the
"no zone found" flash.

**Cross-account provisioning does NOT work — by design of the platform.**
Cloudflare Email Routing can only deliver a zone's mail to a Worker in the
**same account**, and the catch-all this code writes names `CF_WORKER_NAME`
with no account qualifier. So whichever route is used, the domain's zone must
live in the Cloudflare account that hosts this worker — under A that means the
**user has to authorize with that account**, which the confirmation page says
outright and the "no zone found" flash repeats (it must never advise adding
the domain to some other account). Route A's value is therefore *delegation
without custody*: the operator never holds a credential for anyone's account,
not even briefly at rest.

Pin that account — for route A it is a hard prerequisite, for B a safety net:

```sh
npx wrangler secret put CF_ACCOUNT_ID   # or add it to wrangler.jsonc `vars`
```

With `CF_ACCOUNT_ID` set, provisioning refuses a zone whose `account.id`
differs — **before** the Email-Routing enable, which would otherwise write and
lock the zone's MX records and only then fail on the catch-all, leaving the
zone advertising Cloudflare MX with nothing behind them (inbound mail
rejected). Unset, the check is skipped for route B (the operator's token can
only see the operator's zones anyway) and route A is not offered at all.
(There is no connect-time account check: there is no connect step, and
Cloudflare's consent screen cannot be constrained to one account or zone
anyway.)

#### 3.2 Registering the OAuth client (route A, operator, one-off)

Cloudflare self-managed OAuth went GA 2026-06-03
([docs](https://developers.cloudflare.com/fundamentals/oauth/)). Requires the
role **Super Administrator**, **Administrator** or **OAuth Client Write**.

1. Cloudflare dashboard > **Manage Account > OAuth clients > Create client**.
2. Fields:
   - **Client name**: anything, e.g. `SimpleLogin (self-hosted)`. The user
     sees this on the consent screen.
   - **Response types**: `code` (Authorization Code is the only flow
     supported for third-party clients).
   - **Grant types**: `authorization_code` **only**. Do *not* add
     `refresh_token`: this flow must never be able to obtain one (see §3.3).
   - **Token endpoint auth method**: `client_secret_basic` — this is a
     server-side Worker, i.e. a confidential client. (PKCE S256 is sent
     anyway.)
   - **Redirect URL**: `<URL var>/dashboard/cloudflare/callback`, e.g.
     `https://simplelogin.example.workers.dev/dashboard/cloudflare/callback`.
     It is derived from the `URL` var, never from the request Host header, so
     it must match that var exactly.
   - **Scopes**: see §3.3 — and **not** `offline_access`.
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
   silent no-op and the built-in defaults are used. `offline_access` /
   `offline` are stripped from it at runtime and logged, so a stale value
   cannot resurrect refresh tokens.

Endpoints used (all on `dash.cloudflare.com`, **not** `api.cloudflare.com`):
`/oauth2/auth`, `/oauth2/token`, `/oauth2/revoke`, discovery at
`https://dash.cloudflare.com/.well-known/openid-configuration`. The API calls
the token then authorizes go to `api.cloudflare.com/client/v4`; the very first
of them (`GET /zones`) is what proves end-to-end that a dash-issued token is
accepted there, and any 401/403 surfaces as the scope-trap flash of §3.3.

#### 3.3 Scopes — the caveat, the zone-settings trap, and no `offline_access`

Default requested scopes (`DEFAULT_CF_OAUTH_SCOPES` in
`src/web/cloudflare-pages.ts`):

```
zone.read zone-settings.read zone-settings.write
email-routing-rule.read email-routing-rule.write dns.read dns.write
```

All seven were **probed against the live authorize endpoint on 2026-07-26 and
accepted**. `account.read` — the only scope Cloudflare documents — is
**refused** for this deployment's client ("The OAuth 2.0 Client is not allowed
to request scope 'account.read'"), and Hydra fails the *whole* authorization
request if any single scope is disallowed, so it must not be requested.
Re-enumerate the ids with any API token:

```sh
curl -s https://api.cloudflare.com/client/v4/oauth/scopes \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" | jq '.result[] | {id, name}'
```

Use the `id` field verbatim (ids are dot-delimited; colon-delimited forms are
rejected).

**`offline_access` is deliberately NOT requested — do not "fix" this.**
Cloudflare's authorization server is Ory Hydra (visible in the discovery
document), which mints a refresh token only when `offline`/`offline_access` is
among the **granted** scopes. Omitting it is exactly what makes the
authorization one-shot: it cannot be renewed by us, by the operator, or by
anyone who steals the worker's secrets, and it dies on its own inside Hydra's
~1 h access-token ceiling even if the explicit revoke call fails. The client's
grant types should not include `refresh_token` either; if a refresh token ever
comes back anyway, `revokeOneShotToken` hands it straight back and logs it.

**The trap:** the Accepted-Permissions badge on each endpoint does not follow
the product names.

| Call the provisioner makes | Permission actually required |
|---|---|
| `GET /zones?name=` | **Zone** Read |
| `GET/POST /zones/{id}/email/routing`, `.../enable`, `.../dns` | **Zone Settings** read/write (*not* Email Routing Rules) |
| `GET/PUT /zones/{id}/email/routing/rules/catch_all` | **Email Routing Rules** read/write |
| `GET/POST /zones/{id}/dns_records` | **DNS** read/write |

An OAuth client registered without the zone-settings scopes therefore
authorizes fine and then **403s exactly at the Email-Routing-enable step**.
The dashboard says so: a 401/403 under a delegated authorization flashes "the
authorization you just approved is missing a permission", names the
zone-settings scopes and tells the user to run it again (a 401/403 under
`CF_API_TOKEN` keeps the generic "Cloudflare API error" wording — the user
cannot fix the operator's token).

The same mapping applies to the static token of route B: scope it
Zone:Read, **Zone Settings:Edit**, DNS:Edit, Email Routing Rules:Edit.

#### 3.4 Security model

Under route B the button plants the ownership TXT with the *operator's* token,
i.e. clicking it "proves" ownership of any name that token can edit, for
whichever user added the domain. Route A narrows this to the account the user
just approved, but every guard below applies to both:

- `CF_API_TOKEN` MUST be a scoped API token (see §3.3) and should
  additionally be **zone-scoped to only the zones intended for user custom
  domains** wherever possible.
- The server refuses domains that overlap the deployment's own mail
  domains (`EMAIL_DOMAIN`, `FIRST_ALIAS_DOMAIN`, `ALIAS_DOMAINS`,
  `PREMIUM_ALIAS_DOMAINS`, every `public_domain` row) **and** any domain
  whose resolved zone hosts one of them (sibling hostnames like
  `foo.example.com` next to `mail.example.com`) — token zone-scoping
  cannot cover that case, because the token must be able to edit the very
  zone hosting `EMAIL_DOMAIN`. The string-level half of that guard also runs
  *before* the hand-off to Cloudflare, so a hopeless run never asks anyone
  for an authorization.
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
- Rate-limited per user (3/minute; 20/hour) — each run spends up to ~10
  authenticated calls of the Cloudflare API quota (the *user's* quota under
  route A, the operator's under route B). The budget is *checked* on the way
  to the confirmation page and at the hand-off, and *spent* by whichever
  endpoint runs (the confirmed POST under B; the callback, just before the
  code is redeemed, under A): reading the diff is free, an abandoned run costs
  nothing, and a token is only ever minted when there is budget to spend it.
  `/dashboard/cloudflare/start` additionally spends its own much looser budget
  (`web_cf_oauth_start`, 10/minute; 60/hour) so the endpoint is not free to
  hammer for the KV write and redirect it performs.
- Flashes never contain tokens, zone names or zone ids; full errors go to
  Workers Logs via `console.error`.
- Every state-changing step is a **POST with the page's CSRF token**: the
  session cookie is `SameSite=Lax`, so a cross-site top-level navigation
  would otherwise be able to start a run. There is no sudo gate any more —
  it protected against a hijacked session *attaching a lasting credential*,
  and no lasting credential exists; the run itself still needs the user to
  approve on Cloudflare's own screen (route A) after reading the diff.
- **The run is bound to the diff, not to a form field.** The CSRF token is
  session-wide and form-agnostic, so on its own it would let same-origin
  script (or a stale form) start a run for any owned domain without the
  review page ever rendering. The confirmation page therefore mints a
  one-time nonce carrying the domain id and the plan hash; `/start` and the
  confirmed POST resolve the target from it, consume it, and re-run the mode
  / SL-subdomain / collision gates before the hand-off.
- The `state` is per-attempt, session-bound, constant-time compared and
  consumed only on a match. Single use is enforced by an **atomic D1 claim**
  (the `rate_limit`-table mutex idiom `requestLock` already uses), because KV
  has no compare-and-set and two CONCURRENT deliveries of the same callback
  (double-clicked navigation, browser prefetch) would otherwise both redeem
  the same code — RFC 6749 §4.1.2 lets the authorization server revoke every
  token issued from a reused code, which could kill the winner's token
  mid-run, between the Email-Routing enable and the catch-all PUT. The PKCE
  verifier never leaves the KV session, and the **target domain travels in the
  session, not in the callback URL** — otherwise a crafted callback could
  point a freshly minted token at a different row. Ownership is re-checked on
  return.
- Nothing from the provider's query string is read or shown before the state
  check, and what is shown is sanitized (flashes render inside a
  `toastr.<category>("…")` JS string) — the same sanitizer covers Cloudflare
  API error text quoted in a run's failure flash.
- What it does NOT do (reported in the flash as the remaining manual
  steps): Email Sending onboarding (§1.4, dashboard-only) and
  destination-address verification (§1.6).

#### 3.5 Roads not taken (researched 2026-07-26 — please don't re-investigate)

- **Domain Connect: not usable here.** Cloudflare *is* a Domain Connect DNS
  provider, sync-only: `dig TXT _domainconnect.example.com` returns
  `api.cloudflare.com/client/v4/dns/domainconnect`, and its
  `/v2/{domain}/settings` advertises `urlSyncUX
  https://dash.cloudflare.com/domainconnect` with **no** `urlAsyncUX`. The
  blocker is the template model: a Domain Connect *service provider template*
  must be **manually onboarded per DNS provider** (Cloudflare:
  domain-connect@cloudflare.com, ~8 h update SLA, `APEXCNAME` rejected), the
  protocol references templates by pre-registered id, and **arbitrary records
  cannot be passed at redirect time**. Publishing to the public Templates
  repo is not sufficient, and zero of the 997 public templates point MX at
  Cloudflare Email Routing. So a self-hosted instance cannot use it.
- **Dashboard deep links cannot prefill DNS records.** Verified by an
  exhaustive grep of the documented dash-routes list: every entry is a bare
  path such as `/?to=/:account/:zone/dns/records`. No record-value
  parameters exist.
- **What we use instead**, in the manual panel: Cloudflare's own **Email
  Routing "Onboard Domain" wizard**,
  `https://dash.cloudflare.com/?to=/:account/email-service/routing`. It is
  the closest native review-and-approve UX — it shows the records it will add
  and writes them itself, inside the user's own dashboard session — but it
  covers only the MX/SPF side: the catch-all-to-worker rule and our
  `sl-verification` / `_dmarc` TXT records still have to be added by hand
  (the panel lists them, copy-pasteable).
- **RFC 9396 rich authorization requests** are not offered by Cloudflare's
  authorization server (no `authorization_details_types_supported` in the
  discovery document), and the consent screen has no zone picker — so a
  "this zone only" authorization is not expressible. That is stated on the
  confirmation page rather than glossed over, and is the reason the
  authorization is one-shot.

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
  "the authorization you just approved is missing a permission"** — this is
  almost always the zone-settings trap (§3.3): the OAuth client was
  registered without `zone-settings.read` / `zone-settings.write`, so
  enabling Email Routing is refused. Fix the client's scopes in Manage
  Account > OAuth clients, then have the user click the button again — every
  run mints a fresh authorization, so the new scopes apply immediately (there
  is nothing to disconnect). If the wording is the generic "Cloudflare API
  error" instead, the run used the operator's `CF_API_TOKEN`: add Zone
  Settings:Edit there.
- **"No zone for X was found in the Cloudflare account you authorized"** —
  the user approved with the wrong Cloudflare account. Cross-account
  provisioning cannot work (§3.1), so the fix is to sign in to the account
  that hosts this instance's mail worker and run it again — *not* to add the
  domain to whichever account was authorized.
- **The button shows a page instead of running** — expected: both credentialed
  routes render the record diff first and only run on the second click (§3.1).
  If that page's button comes back with "That confirmation is no longer
  valid", the one-time nonce was already used (double submit) or the page sat
  open for more than 15 minutes — reload it.
- **The Cloudflare consent screen does not appear on a repeat run** — it
  must: the authorize URL always carries `prompt=consent` (§3.1). If a run
  ever completes without it, something is stripping that parameter and the
  one-shot property is broken — treat it as a bug, not a convenience.
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
