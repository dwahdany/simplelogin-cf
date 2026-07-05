# Web Spec 04 — Settings + security pages

Server-rendered pages of the `dashboard` blueprint (`url_prefix="/dashboard"`) covering user
settings, account/security settings, sudo mode, API keys, TOTP/FIDO 2FA management, account
deletion, notifications and one-click unsubscribe confirmation pages.

Source files (authoritative):
- `app/dashboard/views/setting.py` (big settings page)
- `app/dashboard/views/account_setting.py` (+ `resend_email_change`, `cancel_email_change`, `unlink_proton_account`)
- `app/dashboard/views/api_key.py`
- `app/dashboard/views/enter_sudo.py` (also defines the `sudo_required` decorator)
- `app/dashboard/views/mfa_setup.py`, `mfa_cancel.py`
- `app/dashboard/views/fido_setup.py`, `fido_manage.py`
- `app/dashboard/views/delete_account.py`
- `app/dashboard/views/notification.py`
- `app/dashboard/views/unsubscribe.py`
- `app/internal/exit_sudo.py` (related: `/internal/exit-sudo-mode`)
- Helpers: `app/user_settings.py`, `app/utils.py` (`CSRFValidationForm`, `sanitize_next_url`,
  `random_string`), `app/image_validation.py`, `app/jobs/export_user_data_job.py`,
  `app/handler/unsubscribe_encoder.py`, `app/handler/unsubscribe_handler.py`,
  `app/contact_utils.py` (`contact_toggle_block`), `app/alias_utils.py` (`change_alias_status`),
  `app/proton/proton_unlink.py`
- Templates (`templates/dashboard/`): `setting.html`, `account_setting.html`, `api_key.html`,
  `new_api_key.html`, `enter_sudo.html`, `mfa_setup.html`, `mfa_cancel.html`, `fido_setup.html`,
  `fido_manage.html`, `recovery_code.html`, `delete_account.html`, `notification.html`,
  `notifications.html`, `unsubscribe.html`, `block_contact.html`

Existing API-port correspondences (do NOT re-describe / reuse):
- Settings values + validation (`alias_generator`, `notification`, `random_alias_default_domain`,
  `random_alias_suffix`, `sender_format`, `available_domains_for_random_alias()`,
  `default_random_alias_domain()`, `set_default_alias_domain`) → **API spec 05 §4**
  (`cloudflare/specs/05-user-settings.md`, `PATCH /api/setting`) — the web POST branches below are
  the form-encoded equivalents of the same column writes.
- API key create semantics (`ApiKey.create` → `code = random_string(60)`, fallback uuid4 on
  collision) → API spec 05 §1 (`POST /api/api_key`).
- Unlink proton account → API spec 05 (`DELETE /api/setting/unlink_proton_account`) — same
  `perform_proton_account_unlink` helper.
- Notifications list/read → API spec 05 §5 (`GET /api/notifications`) — web version has its own
  ordering/pagination, documented below.
- Password check (bcrypt, NFKC), TOTP mechanics → API spec 01 + `cloudflare/src/lib/crypto.ts`
  (`verifyPassword`, `verifyTotp` — **but see §8 gotcha: setup uses `valid_window=0`, not 2**).
- Change-email / reset-password emails → web spec 01 (auth pages) routes `/auth/change_email`,
  `/auth/reset_password` consume the codes created here.
- Data-export / delete-account jobs → job table exists in D1 (`cloudflare/migrations/0001_init.sql`
  `job`); the job **runner** is out of scope for the Workers port (external cron), only row
  creation is ported.
- Session / flash / CSRF / `@login_required` / error pages / `dt` filter / `render_field_errors`
  → web spec 02 §0 (shared web infrastructure). This spec only documents deltas.

`app.url_map.strict_slashes = False` — every path also matches with a trailing slash.

---

## Route inventory (18 routes)

| # | Methods | Path (full) | Endpoint (`url_for`) | Auth | Rate limit |
|---|---------|-------------|----------------------|------|-----------|
| 1 | GET, POST | `/dashboard/setting` | `dashboard.setting` | `@login_required` | `5/minute` POST only |
| 2 | GET, POST | `/dashboard/account_setting` | `dashboard.account_setting` | `@login_required` + `@sudo_required` | `5/minute` POST only |
| 3 | GET, POST | `/dashboard/resend_email_change` | `dashboard.resend_email_change` | `@login_required` + `@sudo_required` | `5/hour` (all methods incl. GET) |
| 4 | GET, POST | `/dashboard/cancel_email_change` | `dashboard.cancel_email_change` | `@login_required` + `@sudo_required` | none |
| 5 | POST | `/dashboard/unlink_proton_account` | `dashboard.unlink_proton_account` | `@login_required` + `@sudo_required` | none |
| 6 | GET, POST | `/dashboard/api_key` | `dashboard.api_key` | `@login_required` + `@sudo_required` | `100/hour` (all methods) |
| 7 | GET, POST | `/dashboard/enter_sudo` | `dashboard.enter_sudo` | `@login_required` | `3/minute` (all methods incl. GET!) |
| 8 | GET, POST | `/dashboard/mfa_setup` | `dashboard.mfa_setup` | `@login_required` + `@sudo_required` | none |
| 9 | GET, POST | `/dashboard/mfa_cancel` | `dashboard.mfa_cancel` | `@login_required` + `@sudo_required` | none |
| 10 | GET, POST | `/dashboard/fido_setup` | `dashboard.fido_setup` | `@login_required` + `@sudo_required` | none — **BLOCKER: WebAuthn** |
| 11 | GET, POST | `/dashboard/fido_manage` | `dashboard.fido_manage` | `@login_required` + `@sudo_required` | none — **BLOCKER: WebAuthn** |
| 12 | GET, POST | `/dashboard/delete_account` | `dashboard.delete_account` | `@login_required` + `@sudo_required` | none |
| 13 | GET, POST | `/dashboard/notification/<notification_id>` | `dashboard.notification_route` | `@login_required` | none |
| 14 | GET, POST | `/dashboard/notifications` | `dashboard.notifications_route` | `@login_required` | none |
| 15 | GET, POST | `/dashboard/unsubscribe/<int:alias_id>` | `dashboard.unsubscribe` | `@login_required` | none |
| 16 | GET, POST | `/dashboard/block_contact/<int:contact_id>` | `dashboard.block_contact` | `@login_required` | none |
| 17 | GET | `/dashboard/unsubscribe/encoded/<encoded_request>` | `dashboard.encoded_unsubscribe` | `@login_required` | none |
| 18 | GET | `/internal/exit-sudo-mode` | `internal.exit_sudo_mode` | none (!) | none |

`<int:...>` converters 404 on non-integers **before** the handler. Route 13 has **no** int
converter — see §13 gotcha.

---

## 0. `@sudo_required` — exact decorator mechanics (`enter_sudo.py`)

```python
_SUDO_GAP = 120           # seconds (2 minutes) — NOT the API's 5 minutes
```

Wrapper logic, executed AFTER `@login_required` (decorator order: `@login_required` then
`@sudo_required`, so anonymous users hit the 401→login redirect first):

1. If `"sudo_time" not in session` **or** `time() - int(session["sudo_time"]) > 120`:
   - if `session["_flashes"]` is non-empty → move the whole list to
     `session["_preserved_flashes"]` (so queued flash messages are NOT consumed/rendered by the
     sudo page but survive until the destination page renders after sudo succeeds);
   - `return redirect(url_for("dashboard.enter_sudo", next=request.path))`
     → `302 /dashboard/enter_sudo?next=<path only, no query string>`.
     **Gotcha:** `request.path`, not `full_path` — query strings are dropped on the sudo detour.
2. Else (sudo fresh): if `session["_preserved_flashes"]` exists, append its entries onto
   `session["_flashes"]` and delete it; then run the view.

`session["sudo_time"]` (int unix seconds) writers:
- `dashboard.enter_sudo` POST success (this spec §7),
- `after_login()` on password login (web spec 01 shared plumbing),
- `/auth/fido` verify success (web spec 01) — **not** TOTP/recovery login,
- `/internal/exit-sudo-mode` sets it to `0` (route 18): flash `Exited sudo mode` (info) +
  redirect `dashboard.index`. No auth decorator — anonymous access just writes `sudo_time=0` into
  an anonymous session and redirects (which then 401→login).

Port: `sudo_time` and the preserved-flash list are `SessionData` keys in KV
(`cloudflare/src/lib/session.ts`); the flash-preservation dance must be replicated because
several POST handlers in *other* groups flash *before* redirecting to a sudo-protected page.

---

## 1. `GET|POST /dashboard/setting` (`dashboard.setting`)

`@login_required`, `@limiter.limit("5/minute", methods=["POST"])` (GET unlimited).

Forms:
- `SettingForm(FlaskForm)`: `name = StringField("Name")` (no validators),
  `profile_picture = FileField("Profile Picture")` (no validators) — used only by
  `update-profile`.
- `PromoCodeForm(FlaskForm)`: `code = StringField("Name", validators=[DataRequired()])` — passed
  to the template as `promo_form` but **no form in `setting.html` uses it** (dead context, keep
  for fidelity or drop).
- `CSRFValidationForm` — empty form, CSRF only; used by all other branches.

### POST dispatch

All POST branches first run:
```python
if not csrf_form.validate():
    flash("Invalid request", "warning")
    return redirect(url_for("dashboard.setting"))
```
Then dispatch on hidden field `form-name`. Every branch below (unless noted) ends with
`redirect(url_for("dashboard.setting"))` (302). Two branches (`change-blocked-behaviour`,
`alias-delete-action`) **fall through to the GET render (200)** after flashing — port must
reproduce the missing redirect (flash shows on the rendered page instead of after a redirect;
a browser refresh re-posts).

| `form-name` | Input fields | Effect (users table unless noted) | Flash (category) |
|---|---|---|---|
| `update-profile` | `name` (text), `profile_picture` (file) | If `form.name.data != user.name` → `users.name = form.name.data`, commit. If a file uploaded: magic-number sniff via `detect_image_format` (PNG `89 50 4E 47 0D 0A 1A 0A`, JPG `FF D8 FF E0`, WEBP `52 49 46 46`; anything else = Unknown) → if Unknown flash `This image format is not supported` (error) + redirect. Else: if `users.profile_picture_id` set and that `file` row belongs to user → `s3.delete(old.path)`; create `file` row (`path = random_string(30)` lowercase a–z, `user_id`), `s3.upload_from_bytesio(path, bytes)`, `users.profile_picture_id = file.id`, commit. **BLOCKER: S3** (see Blockers). | `Your profile has been updated` (success) — only if something changed; if nothing changed and form valid, **falls through to re-render (200), no flash** |
| `notification-preference` | `notification` checkbox (`on` when checked, absent otherwise) | `users.notification = (choose == "on")`, commit | `Your notification preference has been updated` (success) |
| `change-alias-generator` | `alias-generator-scheme` (select: 1=word, 2=uuid) | `int()` cast — **non-numeric value → uncaught ValueError → 500** (bug-compatible). If value ∈ {1,2}: `users.alias_generator = scheme`, commit. If a valid int but not in enum: no write. | `Your preference has been updated` (success) — flashed **even when the enum check failed and nothing was written** |
| `change-random-alias-default-domain` | `random-alias-default-domain` (select; `""` = Not Selected) | `user_settings.set_default_alias_domain(user, domain)` — exact same helper as API spec 05 §4 `random_alias_default_domain`: empty → both `default_alias_public_domain_id` and `default_alias_custom_domain_id` = NULL; SLDomain hidden → error `Domain does not exist`; SLDomain premium_only and user not premium → error `You cannot use this domain`; unknown / not-owned / unverified custom domain → error `Domain does not exist or it hasn't been verified`. On `CannotSetAlias` → flash the exception msg (error) + redirect. Else commit. | `Your preference has been updated` (success) |
| `random-alias-suffix` | `random-alias-suffix-generator` (select: 0=word, 1=random_string) | `int()` wrapped in try/except → non-numeric flashes `Invalid value` (error) + redirect. If ∈ {0,1}: `users.random_alias_suffix = scheme`, commit. | `Your preference has been updated` (success) — flashed even if enum check failed |
| `change-sender-format` | `sender-format` (select: 0=AT, 2=A, 5=NAME_ONLY, 6=AT_ONLY, 7=NO_NAME) | `int()` cast — **non-numeric → 500**. If valid enum: `users.sender_format = value`, `users.sender_format_updated_at = now()`, commit + flash. If valid int not in enum: no write, **no flash**, still redirect. | `Your sender format preference has been updated` (success) |
| `replace-ra` | `replace-ra` checkbox | `users.replace_reverse_alias = (choose == "on")`, commit | `Your preference has been updated` (success) |
| `enable_data_breach_check` | `enable_data_breach_check` checkbox | **Premium gate first**: `not user.is_premium()` → flash `Only premium plan can enable data breach monitoring` (warning) + redirect, no write. Else `users.enable_data_breach_check = (choose == "on")`, commit | on: `Data breach monitoring is enabled` (success); off: `Data breach monitoring is disabled` (info) |
| `sender-in-ra` | `enable` checkbox | `users.include_sender_in_reverse_alias = (choose == "on")`, commit | `Your preference has been updated` (success) |
| `expand-alias-info` | `enable` checkbox | `users.expand_alias_info = (choose == "on")`, commit | `Your preference has been updated` (success) |
| `ignore-loop-email` | `enable` checkbox | `users.ignore_loop_email = (choose == "on")`, commit — **the form for this branch is commented out in `setting.html`**; branch is dead but reachable by hand-crafted POST | `Your preference has been updated` (success) |
| `one-click-unsubscribe` | `unsubscribe-behaviour` (select, **enum NAMES** as values: `PreserveOriginal`, `DisableAlias`, `BlockContact`) | matched by name → `users.unsub_behaviour` = 2 / 0 / 1 respectively, commit. Unknown value → flash `There was an error. Please try again` (warning) + redirect, no write. | `Your preference has been updated` (success) |
| `include_website_in_one_click_alias` | `enable` checkbox | `users.include_website_in_one_click_alias = (choose == "on")`, commit | `Your preference has been updated` (success) |
| `change-blocked-behaviour` | `blocked-behaviour` (select, **string of enum VALUE**: `"0"`=return_2xx, `"1"`=return_5xx) | string-compared to `str(enum.value)` → `users.block_behaviour` = matching value, commit. Unknown → flash `There was an error. Please try again` (warning) + redirect. **Success: NO redirect — falls through to render (200).** | `Your preference has been updated` (success) |
| `sender-header` | `enable` checkbox | `users.include_header_email_header = (choose == "on")`, commit | `Your preference has been updated` (success) |
| `alias-delete-action` | `alias-delete-action` (select, `"0"`=MoveToTrash, `"1"`=DeleteImmediately) | string-compare like above → `users.alias_delete_action`, commit. Unknown → `There was an error. Please try again` (warning) + redirect. **Success: NO redirect — falls through to render (200).** | `Your preference has been updated` (success) |
| *(anything else)* | — | no-op; falls through to GET render (200), no flash | — |

### GET render — `dashboard/setting.html` context

```python
render_template("dashboard/setting.html",
    csrf_form=CSRFValidationForm(),
    form=SettingForm(),
    PlanEnum=PlanEnum,                        # monthly=2, yearly=3
    SenderFormatEnum=SenderFormatEnum,        # AT=0, A=2, NAME_ONLY=5, AT_ONLY=6, NO_NAME=7
    BlockBehaviourEnum=BlockBehaviourEnum,    # return_2xx=0, return_5xx=1
    promo_form=PromoCodeForm(),               # unused by template
    pending_email=<EmailChange.get_by(user_id).new_email or None>,   # unused by setting.html (used by account_setting)
    AliasGeneratorEnum=AliasGeneratorEnum,    # word=1, uuid=2
    UnsubscribeBehaviourEnum=UnsubscribeBehaviourEnum,  # DisableAlias=0, BlockContact=1, PreserveOriginal=2
    UserAliasDeleteAction=UserAliasDeleteAction,        # MoveToTrash=0, DeleteImmediately=1
    manual_sub=ManualSubscription.get_by(user_id),
    partner_sub=<active PartnerSubscription or None>,
    partner_name=<partner.name or None>,      # via get_partner_subscription_and_name()
    apple_sub=AppleSubscription.get_by(user_id),
    paddle_sub=current_user.get_paddle_subscription(),   # active-only (14-day grace)
    coinbase_sub=CoinbaseSubscription.get_by(user_id),
    FIRST_ALIAS_DOMAIN=config.FIRST_ALIAS_DOMAIN,
    ALIAS_RAND_SUFFIX_LENGTH=config.ALIAS_RANDOM_SUFFIX_LENGTH,   # default 5
    connect_with_proton=config.CONNECT_WITH_PROTON,     # bool: env var presence
    can_unlink_proton_account=(user.flags & 2) == 0,    # FLAG_CREATED_FROM_PARTNER
)
```
`get_partner_subscription_and_name(user_id)`: `PartnerSubscription.find_by_user_id` (join via
`partner_user`); returns `(sub, partner.name)` only if sub exists and
`is_active()` (lifetime or `end_at > now`).

Page title: `Settings`. `active_page = "setting"`.

Template notes (`setting.html`, extends `default.html`):
- "Current Plan" card branches: `current_user.lifetime` → text `You have lifetime access to the Premium plan.`;
  else `lifetime_or_active_subscription()` → shows whichever of paddle
  (`{{ paddle_sub.plan_name() }} plan subscribed via Paddle.` — `Monthly`/`Yearly`, plus
  `(Cancelled)` prefix if `paddle_sub.cancelled`, link `dashboard.billing` "Manage Subscription ➡"),
  manual (`Manual plan which expires {{ manual_sub.end_at | dt }} ({{ manual_sub.end_at.format("YYYY-MM-DD") }}).`
  + if `manual_sub.is_giveaway` an Upgrade link to `dashboard.pricing`), apple
  (`Premium plan subscribed via Apple which expires {{ apple_sub.expires_date | dt }} ...` + alert about
  cancelling on Apple first, link `dashboard.pricing`), coinbase
  (`Yearly plan subscribed with cryptocurrency which expires on {{ coinbase_sub.end_at.format("YYYY-MM-DD") }}.`),
  partner (`Premium lifetime subscription managed by {{ partner_name }}.` or
  `Premium subscription managed by {{ partner_name }}.`); `elif current_user.in_trial()` →
  `Your Premium trial expires {{ current_user.trial_end | dt }}.`; else `You are on the Free plan.`
- Data-breach card shows an upsell alert (`This feature is only available on Premium plan.` + link
  `dashboard.pricing`) when `not current_user.is_premium()`; the checkbox is still rendered (server
  rejects with the warning flash).
- `current_user` attributes read: `lifetime`, `lifetime_or_active_subscription()`, `in_trial()`,
  `trial_end`, `is_premium()`, `notification`, `name`, `profile_picture_id`,
  `profile_picture_url()` (**S3 presigned URL** — BLOCKER; falls back to
  `url_for("static", filename="default-avatar.png")` when no picture), `alias_generator`,
  `available_domains_for_random_alias()`, `default_alias_custom_domain_id`,
  `default_alias_public_domain_id`, `default_random_alias_domain()`, `random_alias_suffix`,
  `enable_data_breach_check`, `sender_format`, `replace_reverse_alias`,
  `include_sender_in_reverse_alias` (checkbox checked when value is **None or truthy**),
  `expand_alias_info`, `include_website_in_one_click_alias`, `unsub_behaviour.value`,
  `block_behaviour.value`, `alias_delete_action.value`, `include_header_email_header`.
- `url_for` targets: `dashboard.billing`, `dashboard.pricing`, `dashboard.refused_email_route`
  (button `See quarantine & bounce emails`), `dashboard.alias_trash` (`See alias trash`),
  `dashboard.batch_import_route` (`Batch Import`), `dashboard.alias_export_route`
  (`Export Aliases`).
- Filters: `dt` (arrow humanize), `.format("YYYY-MM-DD")` on Arrow objects (port: format dates).
- Each sub-form posts to `action="#<anchor>"` (same URL + fragment) with its own
  `{{ csrf_form.csrf_token }}` / `{{ form.csrf_token }}`.
- Inline script highlights the card whose id matches `location.hash` (class `highlighted`).

---

## 2. `GET|POST /dashboard/account_setting` (`dashboard.account_setting`)

`@login_required` + `@sudo_required`, `5/minute` POST only.

Forms: `ChangeEmailForm` (imported from `mailbox_detail.py`):
| field | type | validators | error strings |
|---|---|---|---|
| `email` | StringField "email" | DataRequired, Email | `This field is required.` / `Invalid email address.` |

plus `CSRFValidationForm`.

`pending_email = EmailChange.get_by(user_id=current_user.id).new_email` (or None).

### POST branches (after CSRF check → on failure flash `Invalid request` (warning) + redirect **`dashboard.setting`** — note: not account_setting):

**`form-name == "update-email"`** (only if `change_email_form.validate()`; on validation failure
falls through to re-render with field errors):
1. `new_email = canonicalize_email(form.email.data)` (gmail dot/plus-stripping etc. — API spec 01).
2. Only proceeds if `new_email != current_user.email` **and** `pending_email is None` — otherwise
   **silent fall-through to re-render, no flash** (gotcha: submitting the same email or while a
   change is pending does nothing visible).
3. `personal_email_already_used(new_email)` (users.email exists) **or** `Alias.get_by(email=new_email)`
   → flash `Email {new_email} already used` (error), re-render.
4. `not email_can_be_used_as_mailbox(new_email)` (MX/disposable/banned-domain chain — API spec 01)
   → flash `You cannot use this email address as your personal inbox.` (error), re-render.
5. Another user's `EmailChange` with same `new_email`: if that row `is_expired()`
   (`expired < now`) → delete it + commit and continue; else flash
   `You cannot use this email address as your personal inbox.` (error) (same string as 4), re-render.
6. Valid: `EmailChange.create(user_id, code=random_string(60), new_email)` (row default
   `expired = now + 12h`), commit; send email **to the NEW address**, subject
   `Confirm email update on SimpleLogin`, templates `transactional/change-email.{txt,html}`, link
   `{URL}/auth/change_email?code={code}` (silently skipped if `user.can_send_or_receive()` is
   false); flash `A confirmation email is on the way, please check your inbox` (success);
   redirect `dashboard.account_setting`.

**`form-name == "change-password"`**:
- flash `You are going to receive an email containing instructions to change your password`
  (success) — **flashed before/regardless of the email actually sending**;
- `ResetPasswordCode.create(user_id, code=secrets.token_urlsafe(32))` + commit (row default
  expiry 1 h); email to user, subject `Reset your password on SimpleLogin`, templates
  `transactional/reset-password.{txt,html}`, link `{URL}/auth/reset_password?code={code}`
  (skipped when `can_send_or_receive()` false);
- redirect `dashboard.account_setting`.

**`form-name == "send-full-user-report"`**:
- `ExportUserDataJob(user).store_job_in_db()`: if a `job` row with `name='send-user-report'`,
  `payload->user_id == user.id`, `taken=false`, `state=ready` already exists → returns None →
  flash `An export of your data is currently in progress` (error); else creates
  `Job(name="send-user-report", payload={"user_id": id}, run_at=now)` + commit → flash
  `You will receive your SimpleLogin data via email shortly` (success).
- **No redirect** — falls through to re-render (200).

### GET render — `dashboard/account_setting.html` context

```python
csrf_form, PlanEnum, SenderFormatEnum, BlockBehaviourEnum, change_email_form,
pending_email, AliasGeneratorEnum, UnsubscribeBehaviourEnum,
partner_sub, partner_name,                       # same helper as §1
FIRST_ALIAS_DOMAIN, ALIAS_RAND_SUFFIX_LENGTH,
connect_with_proton=config.CONNECT_WITH_PROTON,
proton_linked_account,   # PartnerUser.partner_email for the proton partner, or None
                         # (None too when ProtonPartnerNotSetUp is raised)
can_unlink_proton_account=(user.flags & 2) == 0,
```
(Only `change_email_form`, `csrf_form`, `pending_email`, `connect_with_proton`,
`can_unlink_proton_account`, `proton_linked_account` are actually used by the template; the enums
are dead context.)

Page title: `Settings`. `active_page = "setting"`.

Template notes (`account_setting.html`):
- Email field rendered with `value=current_user.email` and `readonly` when `pending_email != None`.
- When `pending_email`: shows `Pending email change: {{ pending_email }}` (red) + two mini-forms
  POSTing to `dashboard.resend_email_change` (`Resend confirmation email`) and
  `dashboard.cancel_email_change` (`Cancel email change`), each carrying
  `{{ change_email_form.csrf_token }}` only.
- TOTP card: `current_user.enable_otp` false → link `Setup TOTP` → `dashboard.mfa_setup`; true →
  `Disable TOTP` → `dashboard.mfa_cancel`.
- WebAuthn card: `current_user.fido_uuid is none` → `Setup WebAuthn` → `dashboard.fido_setup`;
  else `Manage WebAuthn` → `dashboard.fido_manage`.
- Proton card shown only when `connect_with_proton and can_unlink_proton_account`:
  linked (`proton_linked_account != None`) → text `Your account is currently linked to the Proton
  account <b>{{ proton_linked_account }}</b>` + POST form to `dashboard.unlink_proton_account`
  (button `Unlink account`, bootbox confirm `All your aliases will be removed from Proton Pass.
  Are you sure?`); not linked → link `Connect with Proton` →
  `url_for("auth.proton_login", action="link")` (out-of-scope blueprint — map it).
- Data-export card → POST `send-full-user-report` (button `Request your data`).
- Account deletion card → link `Delete account` → `dashboard.delete_account`.
- Other `url_for`s: `dashboard.mailbox_route` ("Mailboxes page" link),
  `url_for('static', filename='images/proton.svg')`.
- `current_user` attrs: `email`, `enable_otp`, `fido_uuid`.

## 3. `GET|POST /dashboard/resend_email_change`

`@limiter.limit("5/hour")` (counts every hit), `@login_required` + `@sudo_required`.
No template — pure action endpoint (works via GET too! GET with side effects).
- CSRF (`CSRFValidationForm`) invalid → flash `Invalid request. Please try again` (warning) +
  redirect `dashboard.setting`. **Gotcha: a GET always fails CSRF** (no token in query), so GET is
  effectively a redirect-to-setting — but it still counts against the 5/hour limit.
- `EmailChange` exists → `email_change.expired = now + 12h`, commit; resend the same
  confirmation email (subject `Confirm email update on SimpleLogin` to the pending address);
  flash `A confirmation email is on the way, please check your inbox` (success) → redirect
  `dashboard.account_setting`.
- else flash `You have no pending email change. Redirect back to Setting page` (warning) →
  redirect `dashboard.account_setting`.

## 4. `GET|POST /dashboard/cancel_email_change`

`@login_required` + `@sudo_required`, no limiter.
- CSRF invalid → flash `Invalid request. Please try again` (warning) + redirect `dashboard.setting`.
- `EmailChange` exists → delete row, commit; flash `Your email change is cancelled` (success) →
  redirect `dashboard.account_setting`.
- else flash `You have no pending email change. Redirect back to Setting page` (warning) →
  redirect `dashboard.account_setting`.

## 5. `POST /dashboard/unlink_proton_account`

`@login_required` + `@sudo_required`. POST only.
- CSRF invalid → flash `Invalid request` (warning) + redirect `dashboard.setting`.
- `perform_proton_account_unlink(current_user)`:
  - `can_unlink_proton_account` false (user created from partner, `flags & 2`) → returns None →
    flash `Account cannot be unlinked` (warning).
  - else deletes the `partner_user` row, emits user audit log (`action=unlink_account`) +
    partner event; returns the external user id → flash
    `Your Proton account has been unlinked` (success).
  - **Known 500**: if the user was never linked (`partner_user` is None) the helper dereferences
    `partner_user.external_user_id` → AttributeError → 500 (same bug listed in API spec 05).
- redirect `dashboard.account_setting` in both flash cases.

---

## 6. `GET|POST /dashboard/api_key` (`dashboard.api_key`)

`@login_required` + `@sudo_required`, `@limiter.limit("100/hour")` (all methods).

Form `NewApiKeyForm(FlaskForm)`: `name = StringField("Name", validators=[DataRequired()])` →
error `This field is required.` (but see gotcha below — never displayed). Plus `CSRFValidationForm`.

GET: `api_keys = ApiKey WHERE user_id ORDER BY created_at DESC` (all). Render
`dashboard/api_key.html` with `api_keys`, `new_api_key_form`, `csrf_form`. Title `API Key`,
`active_page = "api_key"`.

POST (CSRF invalid → flash `Invalid request` (warning) + `redirect(request.url)`):
- `form-name == "delete"` with `api-key-id`:
  - unknown id → flash `Unknown error. Refresh the page` (warning) → redirect `dashboard.api_key`;
  - other user's key → flash `You cannot delete this api key` (warning) → redirect;
  - else delete row + commit → flash `API Key {name} has been deleted` (success) (name may be the
    literal `None` if the key has no name — Python interpolation) → redirect `dashboard.api_key`.
- `form-name == "create"`:
  - if form valid: `clean_up_unused_or_old_api_keys(user_id)` — if user has >
    `MAX_API_KEYS` (default 30) keys, delete never-used keys oldest-first, then oldest-`last_used`
    keys, until count ≤ 30; then `ApiKey.create(name=form.name.data, user_id)` (code =
    `random_string(60)` lowercase a–z; uuid4 on collision) + commit; flash
    `New API Key {name} has been created` (success); **return
    `render_template("dashboard/new_api_key.html", api_key=new_api_key)` (200, no redirect)** —
    the only place the secret `code` is ever shown.
  - if form invalid (empty name): **no flash, no error display** — falls to
    `redirect(url_for("dashboard.api_key"))` (gotcha: the DataRequired error string is lost).
- `form-name == "delete-all"`: `DELETE FROM api_key WHERE user_id = ?` + commit; flash
  `All API Keys have been deleted` (success); redirect `dashboard.api_key`.

Template notes (`api_key.html`): per-key card shows `{{ api_key.name or "N/A" }}`; subtitle
`Created {{ api_key.created_at | dt }}. Used {{ api_key.times }} times. Was last used
{{ api_key.last_used | dt }}.` when `last_used` else `Never used`; the key value input is always
the literal `**********` (code never rendered on the list page). Per-key hidden form
(`form-name=delete`, `api-key-id`) with bootbox confirm `If this API Key is currently in use, you
might need to login again on the corresponding device, please confirm.` (buttons `Yes, delete it`
/ `Cancel`). `Delete All` form shown only when `api_keys|length > 0`, bootbox confirm `This will
delete all API Keys, they will all stop working, are you sure?` (buttons `Delete All` / `Cancel`).
Create form: placeholder `Chrome`, helper text `Name of the api key, e.g. where it will be used.`,
button `Create`.

`new_api_key.html`: heading `New API Key {{ api_key.name }} is created`, warning alert
`For security reasons, API Key is only visible when it is created.`, input masked `**********`
with eye-toggle exposing `data-secret="{{ api_key.code }}"`, and a clipboard button copying
`{{ api_key.code }}`.

---

## 7. `GET|POST /dashboard/enter_sudo` (`dashboard.enter_sudo`)

`@limiter.limit("3/minute")` — **applies to GET too**: three sudo-protected page loads that each
redirect here can exhaust it → 429 page.  `@login_required`. NOT `@sudo_required` (obviously).

Form `LoginForm(FlaskForm)`: `password = PasswordField("Password", validators=[DataRequired()])`
→ error `This field is required.` (rendered via `render_field_errors`).

POST (`validate_on_submit()`):
- `current_user.check_password(password)` (bcrypt, NFKC — reuse `verifyPassword`):
  - success: `session["sudo_time"] = int(time())`; if `session["_preserved_flashes"]` exists,
    append onto `session["_flashes"]` (restores flashes preserved by `sudo_required`);
    `next_url = sanitize_next_url(request.args.get("next"))` (web spec 01 §sanitize) → redirect
    `next_url` if present else `dashboard.index`.
  - failure: flash `Incorrect password` (warning); fall through to re-render (200).

GET render — `dashboard/enter_sudo.html` context:
```python
password_check_form=form,
next=request.args.get("next"),           # RAW, unsanitized — only embedded in url_for links
connect_with_proton=<CONNECT_WITH_PROTON and user's PartnerUser.partner_id == proton partner id>,
connect_with_oidc=<OIDC_CLIENT_ID is not None and SocialAuth(user_id, social="oidc") exists>,
connect_with_oidc_icon=config.CONNECT_WITH_OIDC_ICON,
```
- **Config gating**: the Proton button shows only for proton-linked users when
  `CONNECT_WITH_PROTON` env is present; the SSO button only for users with an `oidc` SocialAuth
  row when `OIDC_CLIENT_ID` is set. **D1 gap: `social_auth` table missing** (already flagged in
  web spec 01) — gate to false until it exists.
- Template: title `SUDO MODE`, heading `Entering Sudo Mode`, copy `The next page contains
  security related setting.` / `Please enter your account password so that we can ensure it's
  you.`, submit button `Submit`. Proton block: `Alternatively you can use your Proton credentials
  to ensure it's you.` + button `Authenticate with Proton` →
  `url_for('auth.proton_login', next=next)`. OIDC block: `Alternatively you can use your SSO
  credentials to ensure it's you.` + button `Authenticate with SSO` (icon class
  `fa {{ connect_with_oidc_icon }}`) → `url_for('auth.oidc_login', next=next)`. (Both
  out-of-scope auth endpoints; BLOCKER-gated in web spec 01.)
- `active_page = "setting"`.

---

## 8. `GET|POST /dashboard/mfa_setup` (`dashboard.mfa_setup`)

`@login_required` + `@sudo_required`.

Guard (GET and POST): `current_user.enable_otp` already true → flash
`you have already enabled MFA` (warning, lowercase y) → redirect `dashboard.index`.

Form `OtpTokenForm(FlaskForm)`: `token = StringField("Token", validators=[DataRequired()])` →
`This field is required.`

**GET side effect**: if `users.otp_secret` is NULL → `otp_secret = pyotp.random_base32()`
(32-char base32 A–Z2–7) + **commit**.

POST (`validate_on_submit()`):
- `token = form.token.data.replace(" ", "")` (all spaces stripped).
- `pyotp.TOTP(otp_secret).verify(token)` — **`valid_window=0`** (exact current 30 s step only;
  the port's `verifyTotp` defaults to ±2 — must pass window 0 here) **and**
  `current_user.last_otp != token` (replay guard):
  - success: `users.enable_otp = True`, `users.last_otp = token`,
    `regenerate_user_alternative_id(user)` → `users.alternative_id = uuid4()` **and updates the
    current session's stored user reference so the current browser stays logged in** (port: update
    the KV session's `alternative_id`/user pointer; all other sessions become invalid), commit;
    flash `MFA has been activated` (success); `RecoveryCode.generate(user)` → deletes ALL existing
    `recovery_code` rows, inserts 8 codes (raw = `random_string(8)` lowercase a–z; stored as
    base64url(HMAC-SHA3-224(`RECOVERY_CODE_HMAC_SECRET`, raw)) without padding — **SHA3 not in
    WebCrypto**, see Blockers), commit; **return
    `render_template("dashboard/recovery_code.html", recovery_codes=<raw codes>)` (200)**.
  - failure: flash `Incorrect token` (warning); fall through to re-render.

Render — `dashboard/mfa_setup.html` context: `otp_token_form`, `otp_uri` =
`otpauth://totp/SimpleLogin:{email}?secret={otp_secret}&issuer=SimpleLogin` (pyotp
provisioning_uri; email URL-quoted). Title `MFA Setup`, `active_page = "setting"`. Template shows
a QR canvas (local `qrious` lib via `url_for('static',
filename='node_modules/qrious/dist/qrious.min.js')`), the copy `You will need to use a 2FA
application like Proton Pass or Aegis on your phone or PC and scan the following QR Code:`,
manual-entry input showing `{{ current_user.otp_secret }}`, helper `Please enter the 6-digit
number displayed in your authenticator app.`, button `Submit`.

`recovery_code.html` (shared with fido_setup): title `Recovery Codes`, heading `Recovery codes`,
warning `If you had recovery codes before, they have been invalidated. Store these codes in a
safe place. You won't be able to retrieve them again!`, `<li>` per raw code.

## 9. `GET|POST /dashboard/mfa_cancel` (`dashboard.mfa_cancel`)

`@login_required` + `@sudo_required`.

Guard: `not current_user.enable_otp` → flash `you don't have MFA enabled` (warning) → redirect
`dashboard.index`.

POST (CSRF invalid → flash `Invalid request` (warning) + `redirect(request.url)`):
- `users.enable_otp = False`, `users.otp_secret = NULL`, regenerate `alternative_id`
  (+ keep current session valid, as §8), commit;
- if `not user.two_factor_authentication_enabled()` (i.e. no FIDO either) →
  `DELETE FROM recovery_code WHERE user_id` (RecoveryCode.empty);
- flash `TOTP is now disabled` (**warning**, not success); redirect `dashboard.index`.

GET: render `dashboard/mfa_cancel.html` with `csrf_form`. Title `Cancel MFA`, heading
`Two Factor Authentication`, copy `Disabling TOTP reduces the security of your account, please
make sure to re-activate it later or use WebAuthn (FIDO).`, button `Disable TOTP`.

---

## 10. `GET|POST /dashboard/fido_setup` — **BLOCKER: WebAuthn**

`@login_required` + `@sudo_required`.

Form `FidoTokenForm(FlaskForm)`: `key_name = StringField(DataRequired)`,
`sk_assertion = HiddenField(DataRequired)`.

Flask flow (document only — recommend config-gating, see Blockers):
- GET: builds `webauthn.WebAuthnMakeCredentialOptions(challenge=token_urlsafe(32), rp_name=
  "SimpleLogin", RP_ID=hostname(URL), user_id=fido_uuid (existing users.fido_uuid or fresh
  uuid4), username=email, display_name=name or email, attestation="none",
  user_verification="discouraged")`; deletes the `webauthn.loc` extension; appends each existing
  Fido credential to `excludeCredentials` (`type: "public-key"`, `id: credential_id`,
  `transports: ["usb","nfc","ble","internal"]`); stores **`session["fido_uuid"]`** and
  **`session["fido_challenge"]`** (challenge with `=` padding stripped); renders
  `dashboard/fido_setup.html` with `fido_token_form` and
  `credential_create_options=<registration dict>` (injected via `|tojson|safe` into JS which
  calls `navigator.credentials.create`).
- POST: parses `sk_assertion` JSON (invalid → flash `Key registration failed. Error: Invalid
  Payload` (warning) → redirect `dashboard.index`); verifies with
  `webauthn.WebAuthnRegistrationResponse(RP_ID, URL, assertion, session["fido_challenge"],
  trusted_attestation_cert_required=False, none_attestation_permitted=True)` — verify failure →
  flash `Key registration failed.` (warning) → redirect `dashboard.index`. Success: set
  `users.fido_uuid = session["fido_uuid"]` if NULL; `Fido.create(credential_id, uuid,
  public_key, sign_count, name=key_name, user_id, credential_type=assertion["type"],
  authenticator_attachment, transports (list or NULL), aaguid=<parsed from attestation
  authData bytes 37..53 when AT flag set, else NULL>)`; regenerate `alternative_id`; commit;
  flash `Security key has been activated` (success); generate recovery codes and render
  `dashboard/recovery_code.html` (same as §8).
- Session keys consumed: `fido_uuid`, `fido_challenge` (KeyError → 500 if POSTed without a prior
  GET).
- Template: title `Security Key Setup`, heading `Register Your Security Key`, key-name
  placeholder `Name of your key (Required)`, button `Register Key`, client toastr errors
  `Key name cannot be empty.` / `An error occurred when we trying to register your key.`; loads
  `static/assets/js/vendors/base64.js` and `/static/assets/js/vendors/webauthn.js?v={{ VERSION }}`
  (jinja global `VERSION`).

## 11. `GET|POST /dashboard/fido_manage` — **BLOCKER: WebAuthn (soft — deletion itself is plain DB)**

`@login_required` + `@sudo_required`.

Guard: `not current_user.fido_enabled()` (`fido_uuid IS NULL`) → flash
`You haven't registered a security key` (warning) → redirect `dashboard.index`.

Form `FidoManageForm(FlaskForm)`: `credential_id = HiddenField(DataRequired)`.

POST (`validate_on_submit()`):
- `Fido.get_by(uuid=user.fido_uuid, credential_id=...)` not found → flash
  `Unknown error, redirect back to manage page` (warning) → redirect `dashboard.fido_manage`.
- else delete `fido` row, regenerate `alternative_id` (keep current session), commit; flash
  `Key {name} successfully unlinked` (success);
- if no `fido` rows remain for that uuid: `users.fido_uuid = NULL`, commit; if
  `not two_factor_authentication_enabled()` → delete all `recovery_code` rows; redirect
  `dashboard.index`. Otherwise redirect `dashboard.fido_manage`.

GET: render `dashboard/fido_manage.html` with `fido_manage_form`,
`keys=Fido.filter_by(uuid=user.fido_uuid)` (unordered query). Title `Manage Security Key`.
Table columns ID / Name / Device / Linked At (`{{ key.created_at | dt }}`) / Operation; each row
has an `Unlink` button that fills the hidden form and submits; device cell resolved client-side
from `url_for('static', filename='aaguid.json')` by `data-aaguid="{{ key.aaguid or '' }}"`
(fallback text `Unknown`); last row links `dashboard.fido_setup` (`Link a New Key` / button
`Link`). Copy: `Unlink all keys will also disable WebAuthn 2FA.`

---

## 12. `GET|POST /dashboard/delete_account`

`@login_required` + `@sudo_required`.

Form `DeleteDirForm(FlaskForm)` — empty (CSRF only).

POST, only when `form-name == "delete-account"` (any other POST → GET render):
- form invalid (CSRF) → flash `Invalid request` (warning) + **re-render** `delete_account.html`
  (200, not redirect).
- active Paddle sub (`get_paddle_subscription()` non-None and `not sub.cancelled`) → flash
  `Please cancel your current subscription first` (warning) → redirect `dashboard.setting`.
- else: `emit_user_audit_log(action=UserAuditLogAction.UserMarkedForDeletion
  ("user_marked_for_deletion"), message=f"User {id} ({email}) marked for deletion via webapp")`
  (**D1 gap: `user_audit_log` table missing** — same gap as web spec 01);
  `Job.create(name="delete-account", payload={"user_id": id}, run_at=now, commit=True)`;
  flash `Your account deletion has been scheduled. You'll receive an email when the deletion is
  finished` (info); redirect `dashboard.setting`.

GET: render `dashboard/delete_account.html` with `delete_form`. Title `Delete account`, heading
`Account Deletion`, warning alert `Once an account is deleted, it can't be restored. All its
records (aliases, domains, settings, etc.) are immediately deleted.`, button `Delete account`
with bootbox confirm `All your data including your aliases will be deleted, other people might
not be able to reach you after,  please confirm.` (note double space — exact string; buttons
`Yes, delete my account` / `Cancel`).

---

## 13. `GET|POST /dashboard/notification/<notification_id>` (`dashboard.notification_route`)

`@login_required`. **No int converter** — `notification_id` is a string;
`Notification.get("abc")` raises on Postgres → **500 for non-numeric ids** (bug-compatible; D1
port will silently return no row — acceptable divergence, or replicate 404).

- not found → flash `Incorrect link. Redirect you to the home page` (warning) → redirect
  `dashboard.index`.
- `notification.user_id != current_user.id` → flash `You don't have access to this page. Redirect
  you to the home page` (warning) → redirect `dashboard.index`.
- **GET side effect**: if `not notification.read` → `read = True` + commit (also runs on POST).
- POST (**no CSRF check at all** — gotcha): `title = notification.title or
  notification.message[:20]`; delete row + commit; flash `{title} has been deleted` (success);
  redirect `dashboard.index`.
- GET: render `dashboard/notification.html` with `notification`. Title
  `{{ notification.title }}`, `active_page = "dashboard"`; body renders
  `{{ notification.message | safe }}` (**raw HTML — message is server-generated**), delete button
  with JS `confirm('This operation is irreversible, please confirm')`.

## 14. `GET|POST /dashboard/notifications` (`dashboard.notifications_route`)

`@login_required`. POST allowed but behaves identically to GET (no POST handling).

- `page = int(request.args.get("page"))` defaulting to 0; ValueError swallowed → 0. Negative
  pages accepted (SQL OFFSET negative → Postgres error → 500; port: clamp or replicate).
- Query: `notification WHERE user_id ORDER BY read ASC, created_at DESC LIMIT PAGE_LIMIT+1
  OFFSET page*PAGE_LIMIT` (`PAGE_LIMIT=20`; unread first). `last_page = len(rows) <= PAGE_LIMIT`
  — **the 21st row is NOT trimmed before rendering** (gotcha: a full page renders 21 cards; port
  bug-compatible or trim consciously).
- Render `dashboard/notifications.html` with `notifications`, `page`, `last_page`. Title
  `Notifications`, `active_page = "dashboard"`. Card per notification:
  `{{ notification.title | safe or "" }}`, `{{ notification.message | safe }}` (clamped box),
  link `More ➡` → `url_for('dashboard.notification_route', notification_id=notification.id)`,
  `{{ notification.created_at | dt }}`. Pagination block only when `page > 0 or not last_page`:
  `Previous` → `?page={{ page-1 }}` (class `disabled` when `page == 0`), `Next` →
  `?page={{ page+1 }}` (`disabled` when `last_page`).

---

## 15. `GET|POST /dashboard/unsubscribe/<int:alias_id>` (`dashboard.unsubscribe`)

`@login_required`. RFC 8058 one-click unsubscribe landing.

- Alias not found → flash `Incorrect link. Redirect you to the home page` (warning) → redirect
  `dashboard.index`.
- `alias.user_id != current_user.id` → flash `You don't have access to this page. Redirect you to
  the home page` (warning) → redirect `dashboard.index`.
- POST: **CSRF exemption** — the check is skipped when header
  `List-Unsubscribe-Post: One-Click` is present (RFC 8058 automated POST); otherwise CSRF invalid
  → flash `Invalid request` (warning) + `redirect(request.url)`. Then:
  `change_alias_status(alias, enabled=False, message="Set enabled=False from unsubscribe
  request")` → `alias.enabled = false`, alias audit log (`ChangeAliasStatus`,
  `Set alias status to False. Set enabled=False from unsubscribe request`) + partner event
  dispatch (correspondence: same helper as API spec 02 alias toggle); commit; flash
  `Alias {alias.email} has been blocked` (success); redirect
  `url_for("dashboard.index", highlight_alias_id=alias.id)`.
- GET: render `dashboard/unsubscribe.html` with `alias=alias.email` (string!), `csrf_form`.
  Title `Deactivate an alias`, heading `Deactivate alias`, copy `You are about to deactivate the
  alias` + mailto link, `After this, you will stop receiving all emails sent to this alias,
  please confirm. You will always be able to re-activate it untill you will decide to delete
  it.` (sic — "untill"), button `Confirm`.

## 16. `GET|POST /dashboard/block_contact/<int:contact_id>` (`dashboard.block_contact`)

`@login_required`.
- Contact not found / not owned → same two warning flashes + redirect `dashboard.index` as §15.
- POST (CSRF invalid → `Invalid request` warning + `redirect(request.url)` — **no One-Click
  exemption here**): if `contact.block_forward is False` → `contact_toggle_block(contact)`
  (`contact.block_forward = true` + alias audit log `UpdateContact` + commit) and flash
  `Emails sent from {contact.website_email} are now blocked` (success); if already blocked → no
  write, **no flash**. Redirect `url_for("dashboard.alias_contact_manager",
  alias_id=contact.alias_id, highlight_contact_id=contact.id)`.
- GET: render `dashboard/block_contact.html` with `contact`, `csrf_form`. Title `Block a sender`,
  heading `Block sender`, copy `You are about to block the sender <b>{{ contact.website_email
  }}</b> from sending emails to <b>{{ contact.alias.email }}</b>`, button `Confirm`.

## 17. `GET /dashboard/unsubscribe/encoded/<encoded_request>` (`dashboard.encoded_unsubscribe`)

`@login_required`. **GET with side effects** (disables alias / blocks contact / unsubscribes
newsletter / forwards original unsubscribe).

`UnsubscribeHandler().handle_unsubscribe_from_request(current_user, encoded_request)`:
- Decode: payload format `un.<base64url(json [action, data])>.<sig>` where sig =
  `itsdangerous.Signer(UNSUBSCRIBE_SECRET, digest_method=hashlib.sha3_224)` — **SHA3-224 HMAC
  with itsdangerous SHA3 key-derivation; NOT WebCrypto-supported** (Blockers). Bad
  signature/format → None.
- Actions (enum values in payload): `1` UnsubscribeNewsletter (data=user_id; must equal current
  user; sets `users.notification = false` + commit; sends email to user, subject
  `You have been unsubscribed from SimpleLogin newsletter`), `2` DisableAlias (data=alias_id;
  ownership checked; `change_alias_status(enabled=False, message="Set enabled=False via
  unsubscribe header")` + commit; emails each alias mailbox, subject `Alias {alias.email} has
  been disabled successfully`), `3` DisableContact (data=contact_id; ownership checked; toggle
  block if unblocked + commit; emails each alias mailbox, subject `Emails from
  {contact.website_email} to {alias.email} are now blocked`), `4` OriginalUnsubscribeMailto
  (data=[0, alias_id, recipient, subject]; ownership checked; **re-sends the original
  unsubscribe email from the alias to the original list address via SMTP**).
- View responses:
  - handler returned None → flash `Invalid unsubscribe request` (error) → redirect `dashboard.index`.
  - DisableAlias → flash `Alias {alias.email} has been blocked` (success) → redirect
    `dashboard.index?highlight_alias_id={alias.id}`.
  - DisableContact → flash `Emails sent from {contact.website_email} are now blocked` (success)
    → redirect `dashboard.alias_contact_manager?alias_id=...&highlight_contact_id=...`.
  - UnsubscribeNewsletter → flash `You've unsubscribed from the newsletter` (success) → redirect
    `dashboard.index`.
  - OriginalUnsubscribeMailto → flash `The original unsubscribe request has been forwarded`
    (success) → redirect `dashboard.index`.
- **Gotcha / upstream bug**: `UnsubscribeEncoder.encode_url` generates
  `{URL}/dashboard/unsubscribe/encoded?data={payload}` (query param) but the route expects the
  payload as a **path segment** — generated web links for actions 1/4 actually 404 in Flask
  today (only exercised when `UNSUBSCRIBER` env is unset). Port the route as-is; do not "fix" the
  encoder without noting the divergence.

---

## Template porting summary (constructs needing attention)

All templates `{% extends "default.html" %}` (authenticated layout: navbar, toastr flash drain,
`current_user` in navbar — web infra). Blocks used: `title`, `head`, `default_content`, `script`.

| Template | Filters | Macros | Notable |
|---|---|---|---|
| `setting.html` | `dt`, Arrow `.format("YYYY-MM-DD")`, enum `.name.capitalize()` / `.name.upper()` in option labels (`Based on Random Word`, `Based on UUID`) | `render_field_errors` | enum classes passed as context; `available_domains_for_random_alias()` loop `(is_public, domain)`; option label `Random combination of {{ ALIAS_RAND_SUFFIX_LENGTH }} letter and digits`; anchor-highlight script; `url_for` → billing, pricing, refused_email_route, alias_trash, batch_import_route, alias_export_route |
| `account_setting.html` | — | `render_field_errors` | readonly email when pending; bootbox unlink confirm; `url_for` → mailbox_route, mfa_setup, mfa_cancel, fido_setup, fido_manage, unlink_proton_account, resend_email_change, cancel_email_change, delete_account, **auth.proton_login(action="link")**, static proton.svg |
| `api_key.html` | `dt`, `length` | `render_field_errors` | two bootbox confirms; masked key value |
| `new_api_key.html` | — | — | secret in `data-secret` + clipboard.js button |
| `enter_sudo.html` | — | `render_field_errors` | raw `next` into `url_for('auth.proton_login', next=next)` / `url_for('auth.oidc_login', next=next)`; malformed nesting of the oidc `{% endif %}` (inside the div) — harmless, keep output-equivalent |
| `mfa_setup.html` | — | `render_field_errors` | inline QRious QR of `{{ otp_uri }}`; displays `current_user.otp_secret` |
| `mfa_cancel.html` | — | — | plain confirm form |
| `fido_setup.html` | `tojson`, `safe` | `render_field_errors` | `credential_create_options|tojson|safe` into JS; `VERSION` jinja global; navigator.credentials |
| `fido_manage.html` | `dt` | — | aaguid.json client fetch; inline-JS submits hidden form |
| `recovery_code.html` | — | — | loop over raw codes |
| `delete_account.html` | — | — | bootbox confirm |
| `notification.html` | `safe` | — | `message | safe` (trusted HTML); JS confirm |
| `notifications.html` | `dt`, `safe` | — | pagination links via `url_for(..., page=page±1)` |
| `unsubscribe.html` / `block_contact.html` | — | — | plain confirm forms |

`request.*` usage in views: `request.form.get("form-name")` dispatch everywhere,
`request.url` (redirect target after CSRF failure in §6/§9/§15/§16), `request.args.get("next")`
(§7), `request.args.get("page")` (§14), `request.path` (sudo redirect), header
`List-Unsubscribe-Post` (§15). `csrf_token` rendered by `{{ <form>.csrf_token }}` in every POST
form except `notification.html`'s delete form (none — CSRF-unprotected POST, see §13).

Session keys this group reads/writes: `sudo_time`, `_flashes`, `_preserved_flashes`,
`fido_uuid`, `fido_challenge`, plus flask-login `_user_id` rewrite inside
`regenerate_user_alternative_id` (§8/§9/§10/§11).

---

## BLOCKERS / external dependencies

| # | Feature | Flask behavior | Porting stance |
|---|---|---|---|
| B1 | **S3 profile picture** (§1 `update-profile`, `profile_picture_url()`) | uploads bytes to S3/local under `File.path`, deletes the old object, presigned GET url (1 h) for display | **Gate**: treat like absent config — skip the file branch (name-only updates still work), never render the `<img>` (only shown when `profile_picture_id` set, which stays NULL). Later: R2 binding drop-in. |
| B2 | **WebAuthn registration/verify** (§10, and §8/§9/§11 recovery interplay) | python `webauthn` lib verifies attestation, CBOR/AAGUID parsing | **Gate behind a config flag (e.g. `FIDO_ENABLED`)**: hide the WebAuthn card in `account_setting.html` and have `/fido_setup` flash + redirect to `dashboard.index` when off. `/fido_manage` (list/unlink, pure DB) can ship as-is since it's unreachable without `fido_uuid`. Defer real attestation verify (or use `@simplewebauthn/server` workers-compat later). |
| B3 | **Proton link/unlink + OIDC sudo buttons** (§2/§5/§7) | Proton OAuth partner flow; `SocialAuth`/`PartnerUser` lookups; `CONNECT_WITH_PROTON` env-presence gate, `OIDC_CLIENT_ID` gate | **Config-gate exactly like Flask**: with both unset, the Proton card and sudo alternative buttons disappear and `unlink_proton_account` flashes `Account cannot be unlinked`. `social_auth` table missing in D1 (needed only when OIDC enabled). |
| B4 | **Paddle / Coinbase / Apple / Manual / Partner subscription display** (§1 Current Plan, §12 guard) | read-only rows + `get_paddle_subscription()` grace-period logic | Not really external: pure DB reads; tables exist in D1. Port the display logic; Paddle management links point at `dashboard.billing`/`dashboard.pricing` (other group). |
| B5 | **Transactional email sends** (§2 change-email + reset-password, §17 handler emails) | SMTP via `send_email`, subjects quoted above, silently skipped when `can_send_or_receive()` false | Use existing `cloudflare/src/lib/mailer.ts`; content templates need porting (out of this group's scope — shared transactional set). |
| B6 | **Background jobs** (§2 `send-user-report`, §12 `delete-account`) | inserts `job` rows consumed by the external job-runner; export builds a zip and emails it, delete purges the account | Port ONLY the row insert + duplicate-check (`send-user-report` dedupe on `taken=false AND state=ready`); job execution stays on the Python runner or a future Worker cron. |
| B7 | **SHA3-224** (§8 recovery-code HMAC, §17 unsubscribe signature) | `hmac(RECOVERY_CODE_HMAC_SECRET, code, sha3_224)`; `itsdangerous.Signer(UNSUBSCRIBE_SECRET, digest_method=sha3_224)` | WebCrypto has no SHA3. Recommend: bundle a tiny pure-JS sha3 (e.g. `js-sha3`) — needed anyway for recovery-code login parity (web spec 01 route 9); alternatively defer §17 (`encoded_unsubscribe` → always flash `Invalid unsubscribe request`) which matches current behavior for web links given the encoder-URL bug. |
| B8 | **pyotp** (§8) | TOTP SHA1/30 s/6-digit, `valid_window=0` at setup | Already ported (`verifyTotp` in `cloudflare/src/lib/crypto.ts`) — call with window **0** here, and generate secrets as 32-char base32. Not a blocker. |
| B9 | **`user_audit_log` writes** (§5 unlink, §12 delete, §15/§16/§17 alias audit log) | insert-only audit rows | D1 migration needed (`user_audit_log`, `alias_audit_log` — same gap flagged by web specs 01/02). Until then: skip writes behind a helper no-op. |

Known 500-paths to keep or consciously fix: non-numeric `notification_id` (§13); negative
`?page=` (§14); non-numeric `alias-generator-scheme`/`sender-format` (§1); POST `/fido_setup`
without session challenge (§10); `unlink_proton_account` when never linked (§5).
