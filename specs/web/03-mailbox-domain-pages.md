# Web Spec 03 — Mailbox / Domain / Directory pages (`/dashboard/*`, server-rendered)

Source files:
- `app/dashboard/base.py` (blueprint `dashboard`, url_prefix **`/dashboard`**)
- `app/dashboard/views/`: `mailbox.py`, `mailbox_detail.py`, `custom_domain.py`, `domain_detail.py`, `subdomain.py`, `directory.py`, `batch_import.py`, `refused_email.py`
- Shared helpers: `app/mailbox_utils.py`, `app/user_settings.py` (`set_default_mailbox`), `app/custom_domain_utils.py`, `app/custom_domain_validation.py`, `app/dns_utils.py`, `app/regex_utils.py`, `app/pgp_utils.py`, `app/dashboard/views/enter_sudo.py` (`sudo_required`), `app/parallel_limiter.py`
- Templates: `templates/dashboard/mailbox.html`, `mailbox_detail.html`, `mailbox_validation.html`, `custom_domain.html`, `domain_detail/{base,dns,info,trash,auto-create}.html`, `subdomain.html`, `directory.html`, `batch_import.html`, `refused_email.html`

Where behavior duplicates the API port, this spec references **API spec 04** (`cloudflare/specs/04-mailbox-domain.md`): `sanitize_email` (§10), `check_email_for_mailbox` + `EmailCannotBeUsedReason` strings (§11), `create_mailbox` (§4), `delete_mailbox` + delete-mailbox job (§5), `request_mailbox_email_change` / `cancel_email_change` / `verify_mailbox_code` (§6), `set_custom_domain_mailboxes` (§9), serializer helpers `nb_alias()` (§3). Session/CSRF/flash/rate-limit/sudo plumbing is **Web spec 01** (`cloudflare/specs/web/01-auth-pages.md`, "Shared plumbing").

All paths below are prefixed **`/dashboard`**. `strict_slashes=False` app-wide.

---

## Route inventory (14 routes)

| # | Path | Methods | Auth | Rate limit | Endpoint name (`url_for`) |
|---|------|---------|------|-----------|---------------------------|
| 1 | `/dashboard/mailbox` | GET, POST | `@login_required` + parallel lock (POST) | none | `dashboard.mailbox_route` |
| 2 | `/dashboard/mailbox_verify` | GET | `@login_required` | none | `dashboard.mailbox_verify` — GET has **DB side effects** |
| 3 | `/dashboard/mailbox/<int:mailbox_id>/` | GET, POST | `@login_required` + **`@sudo_required`** | `20/minute` POST-only | `dashboard.mailbox_detail_route` |
| 4 | `/dashboard/mailbox/<int:mailbox_id>/cancel_email_change` | GET, POST | `@login_required` | none | `dashboard.cancel_mailbox_change_route` — GET has side effects, **no CSRF** |
| 5 | `/dashboard/mailbox/confirm_change` | GET | `@login_required` | `3/minute` | `dashboard.mailbox_confirm_email_change_route` — GET has side effects |
| 6 | `/dashboard/custom_domain` | GET, POST | `@login_required` + parallel lock (POST) | none | `dashboard.custom_domain` |
| 7 | `/dashboard/domains/<int:custom_domain_id>/dns` | GET, POST | `@login_required` | none | `dashboard.domain_detail_dns` — GET can write DB (token gen); POST does **DNS lookups** (BLOCKER) |
| 8 | `/dashboard/domains/<int:custom_domain_id>/info` | GET, POST | `@login_required` | none | `dashboard.domain_detail` |
| 9 | `/dashboard/domains/<int:custom_domain_id>/trash` | GET, POST | `@login_required` | none | `dashboard.domain_detail_trash` |
| 10 | `/dashboard/domains/<int:custom_domain_id>/auto-create` | GET, POST | `@login_required` | none | `dashboard.domain_detail_auto_create` — delete branch has **no CSRF** |
| 11 | `/dashboard/subdomain` | GET, POST | `@login_required` + parallel lock (POST) | none | `dashboard.subdomain_route` |
| 12 | `/dashboard/directory` | GET, POST | `@login_required` + parallel lock (POST) | none | `dashboard.directory` |
| 13 | `/dashboard/batch_import` | GET, POST | `@login_required` + **`@sudo_required`** | `10/minute` POST-only | `dashboard.batch_import_route` — S3 (BLOCKER) |
| 14 | `/dashboard/refused_email` | GET, POST | `@login_required` | none | `dashboard.refused_email_route` — POST behaves exactly like GET, no CSRF |

Rate-limit key: `userid:{id}` (all these routes are session-authenticated); disabled by `DISABLE_RATE_LIMIT`; 429 renders `templates/error/429.html` (HTML). Port: `cloudflare/src/lib/ratelimit.ts`.

### Shared patterns in this group

- **`form-name` dispatch**: every multi-form page POSTs `<input type="hidden" name="form-name" value="...">` and the view dispatches on `request.form.get("form-name")`. An unknown/missing `form-name` on POST falls through to the GET render (200, no flash).
- **CSRF**: no global CSRFProtect. CSRF is checked only where the view either calls `csrf_form.validate()` (`CSRFValidationForm` = bare FlaskForm) or validates a specific FlaskForm. Branches that skip both are CSRF-exempt (marked below). CSRF failure pattern in this group: `flash("Invalid request", "warning")` + `redirect(request.url)` (or `url_for` equivalent) — unlike the auth pages, failures here are visible.
- **`@sudo_required`** (routes 3, 13): if `session["sudo_time"]` absent or older than **120 s** → move `session["_flashes"]` to `session["_preserved_flashes"]` and `redirect(url_for("dashboard.enter_sudo", next=request.path))`. On a sudo-fresh request, any `_preserved_flashes` are appended back into `_flashes`. Consequence: after "create mailbox" (route 1) redirects to route 3, a stale-sudo user goes through `/dashboard/enter_sudo` and still sees the success flash afterwards.
- **`parallel_limiter.lock(only_when=POST)`** (routes 1, 6, 11, 12): Redis `SET NX EX 5` lock on key `cl:{user_id}:{view_fn_name}`; if already held → HTTP **429** (`werkzeug.exceptions.TooManyRequests`). No-op when Redis is not configured. **BLOCKER (Redis)** — stance: no-op it in the port (the Flask behavior when `lock_redis` is None), optionally add a best-effort KV lock later. Do not build a Redis dependency.
- **`emit_user_audit_log`**: nearly every mutation writes a `user_audit_log` row. **D1 gap: `user_audit_log` has no table in `cloudflare/migrations/0001_init.sql`** (already flagged in Web spec 01) — a migration is required, or the port must consistently skip audit logging (pick one stance for the whole port).
- All tables touched by this group exist in D1 except `user_audit_log`: `mailbox`, `mailbox_activation`, `authorized_address`, `custom_domain`, `domain_mailbox`, `auto_create_rule`, `auto_create_rule__mailbox`, `domain_deleted_alias`, `deleted_subdomain`, `deleted_directory`, `directory`, `directory_mailbox`, `public_domain` (SLDomain), `batch_import`, `file`, `job`, `email_log`, `refused_email`, `users`, `alias`, `alias_mailbox`.

---

## Route 1: `GET|POST /dashboard/mailbox` (`dashboard.mailbox_route`)

Forms:

`NewMailboxForm(FlaskForm)`:
| field | type | validators | error strings |
|---|---|---|---|
| `email` | `EmailField` (html5, "email") | DataRequired, Email | `This field is required.` / `Invalid email address.` |

`DeleteMailboxForm(FlaskForm)`:
| field | type | validators | error strings |
|---|---|---|---|
| `mailbox_id` | IntegerField | DataRequired | `This field is required.` (also fails on 0); non-integer input → `Not a valid integer value` |
| `transfer_mailbox_id` | IntegerField | (none) | empty/non-integer input still produces `Not a valid integer value` (wtforms 2.3.3 coercion error) → form invalid |

Plus `csrf_form = CSRFValidationForm()` (used by the set-default form).

GET: query `mailbox WHERE user_id = :uid ORDER BY created_at DESC` (all, unpaginated). Render `dashboard/mailbox.html` with context `{mailboxes, new_mailbox_form, delete_mailbox_form, csrf_form}`.

POST branches by `form-name`:

**`delete`** (validates `delete_mailbox_form` → CSRF + fields):
1. Invalid form → flash `Invalid request` (warning) → `redirect(request.url)`.
2. `Mailbox.get(mailbox_id)` — **by PK only, before ownership check**: if the row exists (even another user's) and `is_admin_disabled()` (`flags & 1`) → flash `You cannot modify that mailbox. Please contact support.` (error) → redirect `dashboard.mailbox_route`.
3. `mailbox_utils.delete_mailbox(user, mailbox_id, transfer_mailbox_id)` — exact semantics + error strings in API spec 04 §5. Error strings (flashed with category **warning**): `Invalid mailbox`, `Cannot delete your default mailbox`, `You must transfer the aliases to a mailbox you own`, `You can not transfer the aliases to the mailbox you want to delete`, `Your new mailbox is not verified`. `transfer_mailbox_id <= 0` (the UI sends `-1` for "Delete my aliases") means no transfer (`null` in job payload).
4. Success: inserts `job` row `(name='delete-mailbox', payload={"mailbox_id", "transfer_mailbox_id", "send_mail": true}, run_at=now)` — actual deletion is async (job runner). Flash (success, note the **missing space** after the period — faithful f-string concat bug):
   `Mailbox {mailbox.email} scheduled for deletion.You will receive a confirmation email when the deletion is finished`
   → redirect `dashboard.mailbox_route`.

**`set-default`** (validates `csrf_form` only; `mailbox_id` read raw from `request.form`):
1. CSRF invalid → `Invalid request` (warning) → `redirect(request.url)`.
2. Same pre-ownership admin-disabled check as above → `You cannot modify that mailbox. Please contact support.` (error) → redirect.
3. `user_settings.set_default_mailbox(user, mailbox_id)`; raises `CannotSetMailbox` with msg flashed as **warning**: `Invalid mailbox` (not found / other user) or `This is mailbox is not verified` (sic — typo is in the source). If already default: no-op success.
4. Success: `users.default_mailbox_id = mailbox.id` + audit log `UpdateMailbox`. Flash `Mailbox {mailbox.email} is set as Default Mailbox` (success) → redirect `dashboard.mailbox_route`.

**`create`** (validates `new_mailbox_form` → CSRF + email field):
1. Invalid → `Invalid request` (warning) → `redirect(request.url)`. (Field-level errors are never shown because of this redirect — the form's `render_field_errors` is effectively dead on this page.)
2. `mailbox_email = email.lower().strip().replace(" ", "")`, then `mailbox_utils.create_mailbox(user, mailbox_email)` — full flow in API spec 04 §4: premium-only (`Only available for paid plans`), `check_email_for_mailbox` (§11: `Invalid email`, `Email already used`, `Invalid email: {reason.value}`), insert `mailbox` (verified=false), audit log, insert `mailbox_activation` (code = `token_urlsafe(16)`, tries=0), send email to the new mailbox address with subject `Please confirm your mailbox {mailbox.email}` (templates `transactional/verify-mailbox.{txt.jinja2,html}`, link = `{URL}/dashboard/mailbox_verify?mailbox_id={id}&code={code}`). Errors flashed as **warning** → redirect `dashboard.mailbox_route`.
3. Success: flash `You are going to receive an email to confirm {mailbox.email}.` (success) → redirect **`dashboard.mailbox_detail_route`** (`mailbox_id=<new id>`) — which is sudo-gated (see shared patterns).

## Route 2: `GET /dashboard/mailbox_verify` (`dashboard.mailbox_verify`)

Query args: `mailbox_id`, `code`.

1. No `mailbox_id` → flash `You followed an invalid link` (error) → redirect `dashboard.mailbox_route`.
2. With `code`: `verify_mailbox_code(current_user, mailbox_id, code)` (API spec 04 §6): checks ownership, latest `mailbox_activation` row, `tries >= 3` clears codes, 15-minute expiry, wrong code increments `tries`. On error flash `Cannot verify mailbox: {e.msg}` (error) → redirect `dashboard.mailbox_route`. Possible `{e.msg}`: `Invalid mailbox`, `Invalid code`, `Invalid activation code. Please request another code.`, `Invalid activation code`.
3. Success (also the already-verified idempotent case): DB writes `mailbox.verified=true` (+ email swap if `new_email` pending), audit log, delete all `mailbox_activation` rows for the mailbox. Render **`dashboard/mailbox_validation.html`** (no flash) — page body: `Mailbox <b>{{ mailbox.email }}</b> verified, you can now start creating alias with it` + button `Go To Home Page` → `url_for("dashboard.index")`.
4. **No `code` (legacy link)**: calls `verify_with_signed_secret(mailbox_id)` — **this code path is broken in current Flask**: the function's `request: str` parameter shadows `flask.request` and `request.args` on a str raises `AttributeError` → HTTP 500. Port stance: treat code-less links as invalid — flash `Invalid link. Please delete and re-add your mailbox` (error) → redirect `dashboard.mailbox_route` (the intended behavior per the dead code), do NOT reimplement the itsdangerous `TimestampSigner(MAILBOX_SECRET)` path.

## Route 3: `GET|POST /dashboard/mailbox/<int:mailbox_id>/` (`dashboard.mailbox_detail_route`)

`@login_required` + `@sudo_required` + `limiter.limit("20/minute", methods=["POST"])` (GET is unlimited).

Guards (both methods, in order):
1. Not found or `mailbox.user_id != current_user.id` → flash `You cannot see this page` (warning) → redirect `dashboard.index`.
2. `mailbox.is_admin_disabled()` → flash `You cannot modify that mailbox. Please contact support.` (error) → redirect `dashboard.mailbox_route`.

Form `ChangeEmailForm(FlaskForm)`:
| field | type | validators | error strings |
|---|---|---|---|
| `email` | StringField "email" | DataRequired, Email | `This field is required.` / `Invalid email address.` |

`pending_email = mailbox.new_email` (or None).

POST: **first** `csrf_form.validate()` for ALL branches → on failure flash `Invalid request` (warning) → `redirect(request.url)`. Then dispatch on `form-name`:

**`update-email`** (additionally requires `change_email_form.validate_on_submit()`; if the email field is invalid the condition is false and control **falls through to the GET render** with field errors shown — no flash):
- `mailbox_utils.request_mailbox_email_change(user, mailbox, email)` (API spec 04 §6): sanitize; `Same email` if unchanged; `check_email_for_mailbox` (§11); sets `mailbox.new_email`, audit log; unique-violation on `new_email` → `Email already in use`; inserts `mailbox_activation`; sends email **to the NEW address** with subject `Confirm mailbox change on SimpleLogin` (templates `transactional/verify-mailbox-change.{txt.jinja2,html}`, link `{URL}/dashboard/mailbox/confirm_change?mailbox_id={id}&code={code}`).
- Success flash: `You are going to receive an email to confirm {mailbox.email}.` (success) — note it names the **old** email even though the mail goes to the new one (faithful).
- `MailboxError` → flash `{e.msg}` (**error** here, unlike route 1's warning).
- Both cases → redirect `dashboard.mailbox_detail_route(mailbox_id)`.

**`force-spf`**:
- If config `ENFORCE_SPF` unset → flash `SPF enforcement globally not enabled` (error) → redirect `dashboard.index`.
- `mailbox.force_spf = (request.form.get("spf-status") == "on")` + audit log + commit.
- Flash (success) — faithful **operator-precedence bug**: the message is `SPF enforcement was enabled` when `spf-status` is present, else `disabled successfully` (the string `"SPF enforcement was "` is only prepended in the enabled branch).
- Redirect `dashboard.mailbox_detail_route(mailbox_id)`.

**`add-authorized-address`**:
- `address = sanitize_email(request.form.get("email"))`; `validate_email(address, check_deliverability=False, allow_smtputf8=False)`.
- Invalid → flash `invalid {address}` (error). Duplicate (`authorized_address` row for this mailbox+email) → flash `{address} already added` (error). Else insert `authorized_address (user_id, mailbox_id, email)` + audit log → flash `{address} added as authorized address` (success).
- Always redirect `dashboard.mailbox_detail_route(mailbox_id)`.

**`delete-authorized-address`** (`authorized-address-id` form field):
- Not found or belongs to a different mailbox → flash `Unknown error. Refresh the page` (warning). Else delete row + audit log → flash `{address} has been deleted` (success). Redirect same page.

**`pgp`** with `action=save` — **BLOCKER (PGP/GPG)**, see Blockers §:
- Not premium → flash `Only premium plan can add PGP Key` (warning) → redirect same page.
- `mailbox.is_proton()` → flash `Enabling PGP for a Proton Mail mailbox is redundant and does not add any security benefit` (**info**) → redirect same page. (`is_proton()` = email domain in `PROTON_EMAIL_DOMAINS` [`proton.me, protonmail.com, protonmail.ch, proton.ch, pm.me`] **or a live MX lookup** of the email domain hitting `PROTON_MX_SERVERS` [`mail.protonmail.ch.`, `mailsec.protonmail.ch.`] — DNS BLOCKER; port stance: static domain-list check + DoH MX check.)
- Load key from form field `pgp`; `load_public_key_and_check` imports into GPG and does a test encryption, returns fingerprint. Failure → flash `Cannot add the public key, please verify it` (error) and **falls through to render** (no redirect; nothing committed). Success → set `mailbox.pgp_public_key`, `mailbox.pgp_finger_print`, audit log, commit → flash `Your PGP public key is saved successfully` (success) → redirect same page.

**`pgp`** with `action=remove` (allowed for free users):
- `pgp_public_key = NULL, pgp_finger_print = NULL, disable_pgp = false` + audit? (no audit before clearing? — it emits `UpdateMailbox` audit with the old fingerprint) + commit → flash `Your PGP public key is removed successfully` (success) → redirect same page.
- `pgp` with any other/missing `action` → falls through to render (no-op).

**`toggle-pgp`**:
- `pgp-enabled == "on"`: if `is_proton()` → `disable_pgp = true` + flash the Proton redundancy message above (info); else `disable_pgp = false` + audit → flash `PGP is enabled on {mailbox.email}` (info).
- Else: `disable_pgp = true` + audit → flash `PGP is disabled on {mailbox.email}` (info).
- Commit → redirect same page.

**`generic-subject`**:
- `action=save`: `mailbox.generic_subject = request.form.get("generic-subject")` (no server-side length check; DB column is VARCHAR(78), template input has `maxlength=78`) + audit + commit → flash `Generic subject is enabled` (success) → redirect same page.
- `action=remove`: NULL + audit + commit → flash `Generic subject is disabled` (success) → redirect same page.

GET render: `dashboard/mailbox_detail.html` with `**locals()` = `{mailbox_id, mailbox, change_email_form, csrf_form, pending_email, spf_available}` where `spf_available = ENFORCE_SPF` (config presence-bool).

## Route 4: `GET|POST /dashboard/mailbox/<int:mailbox_id>/cancel_email_change` (`dashboard.cancel_mailbox_change_route`)

No CSRF, no sudo; GET has side effects (linked as a plain `<a>` from mailbox_detail).
- `cancel_email_change(mailbox_id, user)`: not found / other user's → `MailboxError("Invalid mailbox")` → flash `{e.msg}` (warning) → redirect `dashboard.index`.
- Success: `mailbox.new_email = NULL` + delete all `mailbox_activation` rows (commits) → flash `Your mailbox change is cancelled` (success) → redirect `dashboard.mailbox_detail_route(mailbox_id)`.

## Route 5: `GET /dashboard/mailbox/confirm_change` (`dashboard.mailbox_confirm_email_change_route`)

`limiter.limit("3/minute")`. Query args `mailbox_id`, `code`.

- With `code`: `verify_mailbox_code(current_user, mailbox_id, code)` (performs the email swap: `email = new_email`, `new_email = NULL`, `verified = true`, audit, clears activation codes). Success → flash `Successfully changed mailbox email` (success) → redirect `dashboard.mailbox_detail_route(mailbox.id)`. `MailboxError` → flash `Cannot verify mailbox: {e.msg}` (error) → redirect `dashboard.mailbox_route`.
- Without `code` (legacy signed link): `TimestampSigner(MAILBOX_SECRET).unsign(mailbox_id, max_age=900)` (`MAILBOX_SECRET = FLASK_SECRET + "mailbox"`) then `perform_mailbox_email_change(mailbox_id)`:
  - `EmailAlreadyUsed` → flash `{new_email} is already used` (error) → redirect `dashboard.mailbox_detail_route(mailbox_id)`.
  - `InvalidId` (no mailbox or no pending change) → flash `Invalid link` (error) → redirect `dashboard.index`.
  - Success → flash `The {mailbox.email} is updated` (success) **and then also** flash `Successfully changed mailbox email` (success) — double flash, faithful — → redirect `dashboard.mailbox_detail_route(mailbox_id)`.
  - Any exception (bad/expired signature, non-int) → flash `Invalid link` (error) → redirect `dashboard.index`.
  - Port stance: only the `code` path matters going forward (all emails link with `code` since the `MailboxActivation` refactor); implement the legacy path as flash `Invalid link` (error) → redirect `dashboard.index`.

## Route 6: `GET|POST /dashboard/custom_domain` (`dashboard.custom_domain`)

Form `NewCustomDomainForm(FlaskForm)`:
| field | type | validators | error strings |
|---|---|---|---|
| `domain` | StringField "domain" | DataRequired, Length(max=128) | `This field is required.` / `Field cannot be longer than 128 characters.` |

GET: `custom_domains = custom_domain WHERE user_id=:uid AND is_sl_subdomain=0 AND pending_deletion=0` (unpaginated, insertion order). Render `dashboard/custom_domain.html` with `{custom_domains, new_custom_domain_form, EMAIL_SERVERS_WITH_PRIORITY}` (the last one is passed but unused by the template).

POST `form-name=create`:
1. Not premium → flash `Only premium plan can add custom domain` (warning) → redirect `dashboard.custom_domain`. (Checked BEFORE form validation.)
2. Form invalid → **falls through to render** with field errors (no flash, 200).
3. `create_custom_domain(user, domain)`:
   - sanitize: lowercase, strip, strip leading `http://` / `https://`.
   - `can_domain_be_used` failures → `CreateCustomDomainResult(message, message_category="error")`, flashed then **falls through to render** (`res.redirect` is never set by this code path). Exact messages:
     - `This is not a valid domain` (RFC-1035 label check: ≤255 chars, labels match `^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$`, trailing dot stripped)
     - `A custom domain cannot be a built-in domain.` (domain exists in `public_domain`)
     - `{domain} already used` (any user's `custom_domain` row)
     - `You cannot add a domain that you are currently using for your personal email. Please change your personal email to your real email`
     - `{domain} already used in a SimpleLogin mailbox` (any VERIFIED mailbox `... LIKE '%@{domain}'`)
   - Success: insert `custom_domain (domain, user_id)`; `CustomDomain.create` generates `ownership_txt_token = random_string(30)` and raises `SubdomainInTrashError` only for subdomains; **ownership inheritance**: if the new domain ends with `.{existing domain}` of the same user and that parent has `ownership_verified` → new domain gets `ownership_verified = true`. Audit log `CreateCustomDomain`. Flash `New domain {res.instance.domain} is created` (success) → redirect **`dashboard.domain_detail_dns(custom_domain_id=res.instance.id)`**.

## Route 7: `GET|POST /dashboard/domains/<int:custom_domain_id>/dns` (`dashboard.domain_detail_dns`)

Guard: not found or other user's → flash `You cannot see this page` (warning) → redirect `dashboard.index`.

**GET side effect**: if `NOT ownership_verified AND ownership_txt_token IS NULL` → generate `ownership_txt_token = random_string(30)` + commit (also done lazily inside `get_ownership_verification_record`).

Defaults for render: `mx_ok = spf_ok = dkim_ok = dmarc_ok = ownership_ok = True`, all `*_errors = []`.

POST: `csrf_form.validate()` first → `Invalid request` (warning) + `redirect(request.url)`. Then by `form-name` — each branch performs live DNS queries (**BLOCKER: DNS**, see below). Success branches redirect; **failure branches do NOT redirect** — they set `*_ok = False`, `*_errors`, flash, and fall through to render (flash appears on the same response):

| form-name | success flash (success) + redirect | failure flash + state |
|---|---|---|
| `check-ownership` | `Domain ownership is verified. Please proceed to the other records setup` → redirect `dashboard.domain_detail_dns` with `_anchor="dns-setup"` (i.e. `#dns-setup`) | `We can't find the needed TXT record` (**error**); `ownership_errors` = all TXT records found on the domain |
| `check-mx` | `Your domain can start receiving emails. You can now use it to create alias` → redirect same page | `The MX record is not correctly set` (**warning**); `mx_errors` = list of `"{prio} {mx_domain}"` strings found |
| `check-spf` | `SPF is setup correctly` → redirect same page | `SPF: {EMAIL_DOMAIN} is not included in your SPF record.` (**warning**); `spf_errors` = TXT records found minus the ownership-verification records |
| `check-dkim` | `DKIM is setup correctly.` → redirect same page | `DKIM: the CNAME record is not correctly set` (**warning**); `dkim_errors` = **dict** `{queried_hostname: found_cname_or_"empty"}` |
| `check-dmarc` | `DMARC is setup correctly` → redirect same page | `DMARC: The TXT record is not correctly set` (**warning**); `dmarc_errors` = TXT records found at `_dmarc.{domain}` |

DNS-check semantics (`CustomDomainValidation` + `dns_utils.NetworkDNSClient(NAMESERVERS)`, default nameserver `1.1.1.1`) — the port must reproduce these over **DNS-over-HTTPS**:

- **Expected records** (also passed to the template):
  - `ownership_records = ExpectedValidationRecords{recommended, allowed}`: values `"{prefix}-verification={ownership_txt_token}"` for prefixes `[partner_prefix?, "sl"]` (partner prefix only when `custom_domain.partner_id` is in config `PARTNER_CUSTOM_DOMAIN_VALIDATION_PREFIXES`; `recommended` = first).
  - `expected_mx_records`: dict `{priority: ExpectedValidationRecords}` from config `EMAIL_SERVERS_WITH_PRIORITY` (e.g. `[(10, "mx1.simplelogin.co."), (20, "mx2.simplelogin.co.")]`; targets carry a **trailing dot**); if partner domain configured (`PARTNER_DNS_CUSTOM_DOMAINS[partner_id]`), partner `mx1./mx2.{partner_domain}.` entries take priority 10/20 and the defaults are appended to the `allowed` lists.
  - `spf_record` (string) = `v=spf1 include:{EMAIL_DOMAIN or partner domain} ~all`.
  - `dkim_records`: dict `{"dkim._domainkey" | "dkim02._domainkey" | "dkim03._domainkey": ExpectedValidationRecords}` with values `{key}._domainkey.{EMAIL_DOMAIN}` (partner domain first in `allowed` when present). **No trailing dot** (the template appends `.` for display).
  - `dmarc_record` = constant `v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s`.
- **check-ownership**: TXT lookup on the domain; success iff any `allowed` string is **exactly equal** to one of the TXT strings. On success set `custom_domain.ownership_verified = true` + audit `VerifyCustomDomain` + commit.
- **check-mx**: MX lookup → `{priority: [target-with-trailing-dot,...]}`. `is_mx_equivalent`: the number of distinct found priorities must equal the number of expected priorities, and walking found priorities in ascending order, every found target at position *i* must be in the `allowed` set of the *i*-th expected record (absolute priority numbers are ignored). Success → `custom_domain.verified = true` + audit + commit. Failure does NOT clear `verified` (a previously-verified domain keeps the flag; the template shows a special warning in that state).
- **check-spf**: TXT lookup; parse records starting with `v=spf1`; collect every `include:` value; success iff intersection with expected SPF domains non-empty → `spf_verified = true` + audit + commit. **Failure sets `spf_verified = false` + commit** (un-verifies), errors are TXT records with the ownership-verification records filtered out.
- **check-dkim**: for each of the 3 prefixes, CNAME lookup of `{prefix}.{domain}` (trailing dot stripped from the answer); a record is correct iff the CNAME is in `allowed`. Legacy grace: if the domain is already `dkim_verified` and at least `dkim._domainkey` is correct, keep `dkim_verified = true` and just report the other missing records; otherwise `dkim_verified = (no invalid records)` + audit-if-now-verified + commit.
- **check-dmarc**: TXT lookup on `_dmarc.{domain}`; success iff the exact `DMARC_RECORD` string is among them → `dmarc_verified = true` + audit + commit; **failure sets `dmarc_verified = false` + commit**.

Render `dashboard/domain_detail/dns.html` with `**locals()` (includes `custom_domain`, `csrf_form`, all `*_ok`/`*_errors`) plus the expected-record kwargs above and `EMAIL_SERVERS_WITH_PRIORITY`.

## Route 8: `GET|POST /dashboard/domains/<int:custom_domain_id>/info` (`dashboard.domain_detail`)

Guard: same `You cannot see this page` (warning) → `dashboard.index`. `mailboxes = current_user.mailboxes()` (**verified only**) filtered to exclude admin-disabled.

POST: `csrf_form.validate()` first → `Invalid request` (warning) + `redirect(request.url)`. Branches:

**`switch-catch-all`**: `catch_all = NOT catch_all` + audit + commit. Flash `The catch-all has been enabled for {domain}` (success) or `The catch-all has been disabled for {domain}` (**warning**). Redirect `dashboard.domain_detail`.

**`set-name`**: if `action == "save"`: `name = request.form.get("alias-name").replace("\n", "")` + audit + commit → flash `Default alias name for Domain {domain} has been set` (success). Else (any other/missing action): `name = NULL` → flash `Default alias name for Domain {domain} has been removed` (**info**). Redirect same page. (Gotcha: a POST missing `alias-name` entirely raises `AttributeError` → 500 in Flask; the template always sends it.)

**`switch-random-prefix-generation`**: toggle + audit + commit. Flash `Random prefix generation has been enabled for {domain}` (success) / `Random prefix generation has been disabled for {domain}` (**warning**). Redirect same page.

**`update`** (`mailbox_ids` multi-value): `set_custom_domain_mailboxes` (same helper as API spec 04 §9): failure reasons flashed as **warning** with exact `.value` strings: `Something went wrong, please retry` (unknown/unverified/foreign or admin-disabled mailbox), `You must select at least 1 mailbox`, `You can only set up to 20 mailboxes per domain`. Success: replace all `domain_mailbox` rows + audit + commit → flash `{domain} mailboxes has been updated` (success). Redirect same page.

**`delete`**: `delete_custom_domain(domain)` → set `pending_deletion = true` + insert `job (name='delete-domain', payload={"custom_domain_id"}, run_at=now)` (async deletion). Flash (success, same missing-space bug): `{name} scheduled for deletion.You will receive a confirmation email when the deletion is finished`. Redirect `dashboard.subdomain_route` if `is_sl_subdomain` else `dashboard.custom_domain`.

GET: `nb_alias = COUNT(alias WHERE custom_domain_id=:id)` (raw count — **includes trashed aliases**, unlike the model's `nb_alias()`). Render `dashboard/domain_detail/info.html` with `**locals()` = `{custom_domain_id, csrf_form, custom_domain, mailboxes, nb_alias}`.

## Route 9: `GET|POST /dashboard/domains/<int:custom_domain_id>/trash` (`dashboard.domain_detail_trash`)

Guard: `You cannot see this page` (warning) → `dashboard.index`. POST: CSRF first (`Invalid request` warning + redirect `request.url`).

- **`empty-all`**: `DELETE FROM domain_deleted_alias WHERE domain_id=:id` → flash `All deleted aliases can now be re-created` (success) → redirect `dashboard.domain_detail_trash`.
- **`remove-single`** (`deleted-alias-id`): not found or wrong domain → flash `Unknown error, refresh the page` (warning) → redirect. Else delete row → flash `{deleted_alias.email} can now be re-created` (success) → redirect same page.

GET: `domain_deleted_aliases = domain_deleted_alias WHERE domain_id=:id` (all). Render `dashboard/domain_detail/trash.html` with `{domain_deleted_aliases, custom_domain, csrf_form}`.

## Route 10: `GET|POST /dashboard/domains/<int:custom_domain_id>/auto-create` (`dashboard.domain_detail_auto_create`)

Forms:

`AutoCreateRuleForm(FlaskForm)`:
| field | type | validators | error strings |
|---|---|---|---|
| `regex` | StringField "regex" | DataRequired, Length(max=128) | `This field is required.` / `Field cannot be longer than 128 characters.` |
| `display_name` | StringField "display name" | Optional, Length(max=128) | `Field cannot be longer than 128 characters.` |
| `order` | IntegerField "order" | DataRequired, NumberRange(min=0, max=100) | `This field is required.` (also for 0 — DataRequired rejects falsy!) / `Number must be between 0 and 100.` / `Not a valid integer value` |

`AutoCreateTestForm(FlaskForm)`: `local` — StringField "local part", DataRequired + Length(max=128).

Guard (after form construction): `You cannot see this page` (warning) → `dashboard.index`. `mailboxes` = verified, non-admin-disabled (as route 8). Test defaults: `auto_create_test_local = ""`, `auto_create_test_result = ""`, `auto_create_test_passed = False`.

POST branches:

**`create-auto-create-rule`** (CSRF via form validation; invalid form → fall through to render with field errors):
1. Duplicate `order` among `custom_domain.auto_create_rules` → flash `Another rule with the same order already exists` (error) → **falls through to render** (no redirect).
2. Each `mailbox_ids` entry must exist, belong to user, be verified → else flash `Something went wrong, please retry` (warning) → redirect same page. Admin-disabled → flash `Cannot assign admin-disabled mailbox. Please contact support.` (error) → redirect.
3. Empty selection → flash `You must select at least 1 mailbox` (warning) → redirect.
4. `re.compile(regex)` failure → flash `Invalid regex {regex}` (error) → redirect. (Port: validate with `new RegExp(...)`; note Python-only syntax like `(?P<name>)` will diverge — acceptable.)
5. `display_name`: `\r`/`\n` → space, strip; empty → NULL.
6. Insert `auto_create_rule (custom_domain_id, order, regex, display_name)` + one `auto_create_rule__mailbox` per mailbox; commit. Flash `New auto create rule has been created` (success) → redirect same page.

**`delete-auto-create-rule`** (`rule-id`) — **NO CSRF validation** (template renders no token, view validates nothing — faithful CSRF hole; port stance: keep behavior, or add CSRF and note the divergence):
- Not found / wrong domain → flash `Something wrong, please retry` (error) → redirect. Else delete rule (cascades rule-mailboxes) → flash `Rule #{rule_order} has been deleted` (success) → redirect same page. (Non-int `rule-id` → `int()` ValueError → 500, faithful.)

**`test-auto-create-rule`** (CSRF via `auto_create_test_form`):
- Iterate `custom_domain.auto_create_rules` **sorted by `order` ascending**; first rule whose regex **full-matches** the local part wins (`regex_match` uses `re2.fullmatch`, falling back to `re.fullmatch`). Result strings: `{local}@{domain} passes rule #{rule.order}` (`auto_create_test_passed=True`, green alert) or `{local}@{domain} doesn't pass any rule` (yellow alert). Renders the template directly (200) — no redirect. Invalid form → falls to the final render.

GET/fallthrough render: `dashboard/domain_detail/auto-create.html` with `**locals()` = `{custom_domain_id, custom_domain, mailboxes, new_auto_create_rule_form, auto_create_test_form, auto_create_test_local, auto_create_test_result, auto_create_test_passed}`.

## Route 11: `GET|POST /dashboard/subdomain` (`dashboard.subdomain_route`)

Availability gate (both methods): `User.subdomain_is_available()` = `COUNT(public_domain WHERE can_use_subdomain=1) > 0`; if false → flash `Unknown error, redirect to the home page` (error) → redirect `dashboard.index`. (Config-gate: hide the "Subdomains" nav entry when no SLDomain has `can_use_subdomain`.)

Form `NewSubdomainForm(FlaskForm)`: `domain` — StringField, DataRequired + Length(max=64); `subdomain` — StringField, DataRequired + Length(max=64). (Field errors are never displayed — failures flash + redirect.)

Data: `sl_domains = public_domain WHERE can_use_subdomain=1`; `subdomains = custom_domain WHERE user_id=:uid AND is_sl_subdomain=1` (**no `pending_deletion` filter** — a just-deleted subdomain still shows until the job runs; faithful).

POST `form-name=create`, checks in order:
1. Form invalid → flash `Invalid new subdomain` (warning) → redirect `dashboard.subdomain_route`.
2. Not premium → flash `Only premium plan can add subdomain` (warning) → redirect `request.url`.
3. `current_user.subdomain_quota <= 0` → flash `You can't create more than 5 subdomains` (error) → redirect. (`subdomain_quota` = `min(users._subdomain_quota, 5 - COUNT(custom_domain WHERE user_id AND is_sl_subdomain=1))`; `MAX_NB_SUBDOMAIN = 5`; `_subdomain_quota` is **permanently decremented** on each create, so deletions never restore quota.)
4. `subdomain`/`domain` lowercased + stripped. `len(subdomain) < 3` → flash `Subdomain must have at least 3 characters` (error) → redirect.
5. Not fullmatch `[0-9a-z-]{1,}` → flash `Subdomain can only contain lowercase letters, numbers and dashes (-)` (error) → redirect.
6. Ends with `-` → flash `Subdomain can't end with dash (-)` (error) → redirect.
7. `domain` not among `sl_domains` (tamper check) → flash `Unknown error, refresh the page` (error) → redirect.
8. `full_domain = f"{subdomain}.{domain}"`. Already a `custom_domain` row → flash `{full_domain} already used` (error) → **falls through to render**. A verified mailbox `...@{full_domain}` exists → flash `{full_domain} already used in a SimpleLogin mailbox` (error) → **falls through to render**.
9. `CustomDomain.create(is_sl_subdomain=true, catch_all=true, domain=full_domain, user_id, verified=true, dkim_verified=false, spf_verified=true, dmarc_verified=false, ownership_verified=true)` — the model's `create` also generates `ownership_txt_token`, decrements `users._subdomain_quota`, and raises `SubdomainInTrashError` if `deleted_subdomain` has the domain → flash `{full_domain} has been used before and cannot be reused` (error) → falls through to render. Success: audit log `CreateCustomDomain` (`Create subdomain ...`), flash `New subdomain {domain} is created` (success) → redirect **`dashboard.domain_detail`** (info page, not DNS).

GET render: `dashboard/subdomain.html` with `{sl_domains, errors: {} (always empty), subdomains, new_subdomain_form}`.

## Route 12: `GET|POST /dashboard/directory` (`dashboard.directory`)

Forms:
- `NewDirForm`: `name` — StringField, DataRequired + Length(min=3) + `Regexp(r"^[a-zA-Z0-9][a-zA-Z0-9-_]+$")`. Errors: `This field is required.` / `Field must be at least 3 characters long.` / `Invalid input.`
- `ToggleDirForm`: `directory_id` — IntegerField DataRequired; `directory_enabled` — BooleanField (no validators).
- `UpdateDirForm`: `directory_id` — IntegerField DataRequired; `mailbox_ids` — SelectMultipleField DataRequired, `validate_choice=False` (choices populated with the user's mailbox ids as strings but not enforced).
- `DeleteDirForm`: `directory_id` — IntegerField DataRequired.

Data: `dirs = directory WHERE user_id ORDER BY created_at DESC`; `mailboxes` = verified, non-admin-disabled.

POST branches (each validates its own FlaskForm → CSRF included; invalid → flash `Invalid request` (warning) → redirect `dashboard.directory`):

**`delete`**: `Directory.get(directory_id)` → missing: flash `Unknown error. Refresh the page` (warning); wrong owner: flash `You cannot delete this directory` (warning). Success: audit `DeleteDirectory`, then `Directory.delete` — **synchronous**: every `alias WHERE directory_id` is deleted via `alias_delete.delete_alias(..., reason=DirectoryDeleted)` (trash or hard-delete per user setting), a `deleted_directory (name)` row is inserted (blocks reuse), the directory row is deleted, commit. Flash `Directory {name} has been deleted` (success) → redirect.

**`toggle-directory`**: missing or wrong owner → flash `Unknown error. Refresh the page` (warning) → redirect. `directory_enabled` truthy → `disabled = false`, flash `On-the-fly is enabled for {name}` (success); else `disabled = true`, flash `On-the-fly is disabled for {name}` (**warning**). Audit `UpdateDirectory` + commit → redirect.

**`update`**: missing/wrong owner → `Unknown error. Refresh the page` (warning). Every `mailbox_ids` entry must exist, belong to user, be verified → else flash `Something went wrong, please retry` (warning) → redirect. Empty → flash `You must select at least 1 mailbox` (warning) → redirect. Replace all `directory_mailbox` rows, audit, commit → flash `Directory {name} has been updated` (success) → redirect. (Note: unlike `create`, this branch does NOT reject admin-disabled mailboxes — faithful.)

**`create`**:
1. Not premium → flash `Only premium plan can add directory` (warning) → redirect.
2. `directory_quota <= 0` → flash `You cannot have more than 50 directories` (warning) → redirect. (`directory_quota = min(users._directory_quota, 50 - COUNT(directory WHERE user_id))`; `MAX_NB_DIRECTORY = 50`; `_directory_quota` permanently decremented on create.)
3. Form invalid → falls through to render with field errors (no flash).
4. `new_dir_name = name.lower().strip()`. Exists (any user, `directory.name` unique) → flash `{new_dir_name} already used` (warning) → redirect.
5. Reserved names `reply, ra, bounces, bounce, transactional` + config `BOUNCE_PREFIX_FOR_REPLY_PHASE` (default `bounce_reply`) → flash `this directory name is reserved, please choose another name` (warning) → redirect.
6. `Directory.create(name, user_id)` — raises `DirectoryInTrashError` if `deleted_directory` has the name → flash `{new_dir_name} has been used before and cannot be reused` (error) → redirect. On success also decrements `users._directory_quota` and emits audit `CreateDirectory` (message duplicates the name: `New directory {name} ({name})` — faithful), commit.
7. Optional `mailbox_ids` (raw `request.form.getlist`): per-mailbox checks — invalid/foreign/unverified → flash `Something went wrong, please retry` (warning) → redirect (directory already created!); admin-disabled → flash `Cannot assign admin-disabled mailbox. Please contact support.` (error) → redirect (same caveat). Valid → insert `directory_mailbox` rows + commit. (No selection → directory falls back to default mailbox at read time via the model property.)
8. Flash `Directory {new_dir.name} is created` (success) → redirect `dashboard.directory`.

GET render: `dashboard/directory.html` with `{dirs, toggle_dir_form, update_dir_form, delete_dir_form, new_dir_form, mailboxes, EMAIL_DOMAIN, ALIAS_DOMAINS}`.

## Route 13: `GET|POST /dashboard/batch_import` (`dashboard.batch_import_route`)

`@login_required` + `@sudo_required` + `limiter.limit("10/minute", methods=["POST"])`.

Both methods, in order:
1. `current_user.verified_custom_domains()` empty (`custom_domain WHERE user_id AND ownership_verified=1`) → flash `Alias batch import is only available for custom domains` (warning) — **no redirect**, page still renders/processes.
2. `current_user.disable_import` → flash `you cannot use the import feature, please contact SimpleLogin team` (error) → redirect `dashboard.index`.

`batch_imports = batch_import WHERE user_id=:uid AND processed=0`.

POST:
1. `csrf_form.validate()` → `Invalid request` (warning) + `redirect(request.url)`.
2. `len(batch_imports) > 10` → flash `You have too many imports already. Please wait until some get cleaned up` (error) → **render** the page (200, not a redirect).
3. `request.files["alias-file"]` (missing key → werkzeug 400). `file_path = random_string(20) + ".csv"`; insert `file (user_id, path)`; **S3 upload** `s3.upload_from_bytesio(file_path, alias_file)` — **BLOCKER (S3)**, stance below; insert `batch_import (user_id, file_id)`; insert `job (name='batch-import', payload={"batch_import_id"}, run_at=now)`; commit. Processing is done by the job runner (out of scope here; the importer only creates aliases for the user's verified domains).
4. Flash `The file has been uploaded successfully and the import will start shortly` (success) → redirect `dashboard.batch_import_route`.

GET render: `dashboard/batch_import.html` with `{batch_imports, csrf_form}`. `batch_import.nb_alias()` = `COUNT(alias WHERE batch_import_id=:id)`.

## Route 14: `GET|POST /dashboard/refused_email` (`dashboard.refused_email_route`)

POST is accepted but there is no POST handling — identical to GET, no CSRF (faithful; port may register GET only and note the divergence, or accept POST as GET).

- `highlight_id = request.args.get("highlight_id")`, parsed as int; parse failure → `None`.
- `email_logs = email_log WHERE user_id=:uid AND refused_email_id IS NOT NULL ORDER BY id DESC` (all, unpaginated).
- If the highlighted log is found at index > 0, move it to the front (`if highlight_index:` — index 0 is falsy so already-first stays put).
- Render `dashboard/refused_email.html` with `**locals()` = `{highlight_id, email_logs, highlight_index}` (+ stray loop vars).
- Template calls `refused_email.get_url()` → **S3 presigned URL** (3600 s) for `path` (or `full_report_path` when `path` is NULL) — **BLOCKER (S3)**.

---

## Templates — porting notes

Layout chain: all pages extend `default.html` → `base.html` (except `mailbox_validation.html`, which extends `base.html` directly). `base.html` does `{% from "_formhelpers.html" import render_field, render_field_errors %}` at top level, so **`render_field_errors` is available in every child template without an explicit import** — the Nunjucks build must inject this macro globally. `render_field_errors(field)`: if `field.errors` render `<ul class="errors"><li class="text-danger">{{ error }}</li>...</ul>`.

Shared constructs across the group:
- Filter **`dt`** = `arrow.get(value).humanize()` (e.g. "3 days ago") — used on every `created_at`/`delete_at`. The registered `enumerate` filter is unused here.
- `{{ <form>.csrf_token }}` hidden inputs; `<input type="hidden" name="form-name" ...>` dispatch.
- Flash rendering: toastr via base layout (Web spec 01 "Flash messages") — categories used here: success, error, warning, info.
- `current_user` attributes: `is_premium()`, `email`, `default_mailbox_id`, `default_mailbox.email`, `include_sender_in_reverse_alias`, `subdomain_quota`, `directory_quota`.
- Context-processor globals consumed: `URL` (custom_domain.html), `PGP_SIGNER` (mailbox_detail.html), `FIRST_ALIAS_DOMAIN` + `ALIAS_DOMAINS` passed explicitly (directory.html).
- JS libs the pages depend on (already in static bundle): jQuery, bootbox (confirm/prompt dialogs for delete flows), multiple-select (`$('.mailbox-select').multipleSelect()`), parsley (client-side validation), Vue 2 with `[[ ]]` delimiters (subdomain.html only), `drag-drop-into-text.js` (mailbox_detail PGP textarea), clipboard tooltips (`.clipboard` + `data-clipboard-text`, dns.html).

Per template:

| Template | Title block | Notes |
|---|---|---|
| `dashboard/mailbox.html` | `Mailboxes` | `active_page = "mailbox"`. Loops mailboxes: `mailbox.is_admin_disabled()`, `verified`, `pgp_enabled()` (= `pgp_finger_print AND NOT disable_pgp`), `nb_alias()`, `created_at\|dt`; "Default Mailbox" badge when `id == current_user.default_mailbox_id`. Free-plan banner `This feature is only available in premium plan.`. "How to use" collapse auto-shown when `mailboxes\|length == 1`. Delete form has a hidden `<select name="transfer_mailbox_id">` with `-1` = "Delete my aliases" + all other verified mailboxes; bootbox prompt drives it. url_for: `dashboard.mailbox_detail_route` |
| `dashboard/mailbox_detail.html` | `Mailbox {{ mailbox.email }}` | `active_page = "mailbox"`. Uses `pending_email` (readonly email input + link to `dashboard.cancel_mailbox_change_route`), `mailbox.is_proton()` (**DNS at render time** — see Blockers), `mailbox.pgp_finger_print/pgp_public_key/disable_pgp/generic_subject/force_spf`, `mailbox.authorized_addresses` (relationship → `authorized_address WHERE mailbox_id`), `spf_available`, `PGP_SIGNER` (`All forwarded emails will be signed with <b>{{ PGP_SIGNER }}</b>.` shown only when set), premium gating (PGP textarea+Save disabled for free users + banner `This feature is only available in premium plan.`), `current_user.include_sender_in_reverse_alias` info box, hardcoded link `/dashboard/setting#sender-in-ra` |
| `dashboard/mailbox_validation.html` | `Mailbox Validation` | extends `base.html` (bare page). url_for: `dashboard.index` |
| `dashboard/custom_domain.html` | `Custom Domains` | `active_page = "custom_domain"`. Per domain: `ownership_verified`/`verified` state machine → badge `Domain ready`, button `Ownership verified. Setup the DNS` (→ `dashboard.domain_detail_dns` `_anchor='dns-setup'`), or `Verify domain ownership` (→ `_anchor='ownership-form'`); `nb_alias()`, `created_at\|dt`. Free banner links `{{ URL }}/dashboard/pricing`. url_for: `dashboard.domain_detail`, `dashboard.domain_detail_dns` |
| `dashboard/domain_detail/base.html` | — | Sidebar layout; `active_page` = `subdomain` if `custom_domain.is_sl_subdomain` else `custom_domain`. **DNS tab hidden for subdomains** (`is_sl_subdomain`). Tabs → `dashboard.domain_detail`, `dashboard.domain_detail_dns`, `dashboard.domain_detail_trash`, `dashboard.domain_detail_auto_create`; `domain_detail_page` set-variable selects the active tab (`info`/`dns`/`trash`/`auto_create`) |
| `dashboard/domain_detail/dns.html` | `{{ custom_domain.domain }} DNS` | Ownership section hidden once `ownership_verified`; rest of page wrapped in `disabled-content` until then (+ alert `A domain ownership must be verified first.`). Per check: expected records with copy-to-clipboard, Verify / `Re-verify` button, error box `Your DNS is not correctly set. The ... record we obtain is:` + `(Empty)` when no errors list; `dkim_errors` iterated with `.items()` (dict!); extra warnings when a previously verified record now fails (e.g. `Without the MX record set up correctly, you can miss emails sent to your aliases. Please update the MX record ASAP.`). Uses `ownership_records.recommended`, `expected_mx_records[prio].recommended`, `dkim_records`, `spf_record`, `dmarc_record` |
| `dashboard/domain_detail/info.html` | `{{ custom_domain.domain }} Info` | catch-all switch auto-submits; mailboxes multi-select shows `custom_domain.mailboxes` **property** (falls back to `[user.default_mailbox]` when no `domain_mailbox` rows — D1 port must replicate); name form; random-prefix switch; delete section with different copy for subdomains (`Because a deleted subdomain can't be recycled...your subdomain quota will still be {{ current_user.subdomain_quota }}`) and bootbox confirm; `nb_alias` from context |
| `dashboard/domain_detail/trash.html` | `{{ custom_domain.domain }} deleted aliases` | `Empty Trash` button only when `domain_deleted_aliases\|length > 0`, else text `There's no deleted alias recorded for this domain.`; per row `deleted_alias.email`, `created_at\|dt` |
| `dashboard/domain_detail/auto-create.html` | `{{ custom_domain.domain }} Auto Create Rules` | Warning `Rules are ineffective when catch-all is enabled.` + whole page `disabled-content` when `catch_all`. Iterates `custom_domain.auto_create_rules` (sorted by order; property) with `rule.mailboxes` relationship; delete form (no CSRF); new-rule form with `render_field_errors`; debug/test form; result alert green/yellow by `auto_create_test_passed` |
| `dashboard/subdomain.html` | `Subdomains` | `active_page = "subdomain"`. Free banner → `url_for("dashboard.pricing")`. New-subdomain card `disabled-content` when `current_user.subdomain_quota <= 0`; Vue app previews `[[subdomain]].[[domain]]`; quota text `Currently you can create up to <b>{{ current_user.subdomain_quota }}</b> subdomains.`; inline script reads `{{ sl_domains[0].domain }}` (safe: route guarantees non-empty) |
| `dashboard/directory.html` | `Directory` | `active_page = "directory"`. Free banner `This feature is only available in premium plan.`; `FIRST_ALIAS_DOMAIN` in how-to examples; `ALIAS_DOMAINS` list; per dir: toggle switch (auto-submit), `dir.nb_alias()`, `dir.mailboxes` property (default-mailbox fallback), update multi-select, delete via bootbox; new-dir card `disabled-content` when `directory_quota <= 0`; quota copy `You can create up to {{ current_user.directory_quota }} directories.`; `current_user.default_mailbox.email` in info box |
| `dashboard/batch_import.html` | `Alias Batch Import` | `active_page = "setting"` (!). Download link `url_for('static', filename='batch_import_template.csv')` — port must serve `/static/batch_import_template.csv`. File input `name="alias-file"` accept=.csv, multipart form with `csrf_form.csrf_token`. Table of imports: `created_at\|dt`, `nb_alias()`, `Processed ✅`/`Pending` |
| `dashboard/refused_email.html` | `Quarantine` | `active_page = "setting"`. Per email_log: `refused_email` (`created_at\|dt`, `deleted`, `delete_at\|dt`, `get_url()` — S3), `contact` → `alias` chain (`email_log.is_reply` flips From/To display), `bounced` badge `Bounce` vs `Quarantine`, highlight class when `email_log.id == highlight_id`, link `url_for("dashboard.index", highlight_alias_id=alias.id)` labelled `Disable Alias` |

Out-of-group `url_for` targets referenced (map in the port's route table): `dashboard.index` (+ `highlight_alias_id` query arg), `dashboard.pricing`, `dashboard.enter_sudo` (+ `next`), `static` (filename arg). The shared header/footer (`default.html`) additionally references the full nav including out-of-scope blueprints (`phone.*`, `developer.*`, `discover.*`) — covered by the web-infra/layout spec, not here.

---

## BLOCKERS (external dependencies) and porting stances

1. **DNS resolution** (`dns_utils.NetworkDNSClient` over `NAMESERVERS`, default `1.1.1.1`, via dnspython UDP/TCP):
   - Used by route 7 (all 5 checks: TXT / MX / TXT-SPF / CNAME×3 / TXT-DMARC), by `Mailbox.is_proton()` (MX lookup — runs during mailbox_detail **render** and in the pgp/toggle-pgp branches), and by `email_can_be_used_as_mailbox_with_reason` (MX + A lookups during mailbox create/change, see API spec 04 §11).
   - **Stance: implement a `DoHClient` (DNS-over-HTTPS, `https://cloudflare-dns.com/dns-query` with `accept: application/dns-json`) mirroring the `DNSClient` interface** (`get_txt_record` → join TXT character-strings, strip quotes; `get_mx_domains` → `{prio: [target-with-trailing-dot]}`; `get_cname_record` → strip trailing dot; `get_a_record`). Any lookup error must behave as "no records" (Flask swallows all exceptions), never a 5xx. `is_proton()`'s MX half may be gated behind the same client; the static `PROTON_EMAIL_DOMAINS` suffix check must always run.
2. **PGP / GPG** (`load_public_key_and_check` — imports the key into a gnupg keyring or rust pgp and test-encrypts; returns fingerprint):
   - **Stance: bundle `openpgp.js`** (bundled npm dep, CSP-safe) to `readKey` → fingerprint (uppercase hex, matching gnupg format) + a dummy `encrypt` to validate usability; on any error behave exactly like `PGPException` → flash `Cannot add the public key, please verify it` (error). If deferring: hide the PGP card and reject `form-name=pgp` with the same error flash — do NOT store unvalidated keys, `pgp_finger_print` drives email-worker encryption (spec 07).
3. **S3** (`s3.upload_from_bytesio` for batch-import CSVs; `File.get_url`/`RefusedEmail.get_url` presigned URLs for downloads):
   - **Stance: R2 bucket binding** (or KV for the small CSVs) keyed by the existing `file.path` / `refused_email.path|full_report_path` values. "Presigned URL" becomes an authenticated worker route (e.g. `GET /dashboard/files/<path>` checking `user_id`) — Flask's 3600 s expiry becomes moot. The email worker (spec 07) already stores refused emails; reuse its storage layer. `LOCAL_FILE_UPLOAD` config path is irrelevant to the port.
4. **Redis** (`parallel_limiter.lock` on routes 1/6/11/12): **stance: no-op** (Flask behavior without Redis); document the lost double-submit protection; D1's serialized writes make the race benign.
5. **Job runner** (rows in `job`: `delete-mailbox`, `delete-domain`, `batch-import`): the web views only enqueue. **Stance: insert identical `job` rows in D1**; execution belongs to the port's cron/queue worker (see API spec 04 §5 for `delete-mailbox` semantics; `delete-domain` hard-deletes the domain + aliases and inserts `deleted_subdomain` for subdomains; `batch-import` parses the CSV and creates aliases). Until that worker exists, deletions stay pending — acceptable, matches Flask with a stopped job runner.
6. **itsdangerous `TimestampSigner(MAILBOX_SECRET)` legacy links** (routes 2 & 5, code-less variants): **stance: do not port**; return the "Invalid link" flashes documented above (route 2's legacy path is already a 500 in Flask).
7. **`user_audit_log`** — missing D1 table (shared with Web spec 01's list); add migration or adopt a port-wide "skip audit log" stance.
8. **re2 regex semantics** (`regex_match` for auto-create rules): Flask compiles user regexes with Python `re` (creation-time check) and evaluates with `re2` (fallback `re`), full-match. **Stance: JS `new RegExp` + full-match anchoring (`^(?:...)$`)** for both validation and the test endpoint; divergence on Python-only syntax is acceptable and should just fail validation with the same `Invalid regex {regex}` flash.
