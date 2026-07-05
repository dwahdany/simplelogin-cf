# Web Spec 01 — Auth pages (`/auth/*`, server-rendered)

Source files:
- `app/auth/base.py` (blueprint, url_prefix `/auth`)
- `app/auth/views/`: `login.py`, `register.py`, `activate.py`, `resend_activation.py`, `forgot_password.py`, `reset_password.py`, `change_email.py`, `mfa.py`, `recovery.py`, `logout.py`, `api_to_cookie.py`, `login_utils.py`, `social.py`, `fido.py`, `google.py`, `facebook.py`, `github.py`, `proton.py`, `oidc.py`
- `templates/auth/*.html`, plus shared bases `templates/base.html`, `templates/single.html`, `templates/error.html`, `templates/_formhelpers.html`
- `simplelogin_app.py` (session config, error handlers, jinja globals, `slref` capture, `/` index)
- `app/session.py` (Redis server-side session), `app/extensions.py` (limiter + login_manager)

Where behavior duplicates the API port, this spec references **API spec 01** (`cloudflare/specs/01-auth.md`) instead of restating it (bcrypt check, dummy-hash timing mitigation, email sanitize/canonicalize, TOTP verify, `send_reset_password_email`, mailbox-usable checks).

All routes below are prefixed **`/auth`**. `strict_slashes=False` app-wide (trailing slash also matches).

---

## Route inventory (23 routes)

| # | Path | Methods | Auth | Rate limit | Notes |
|---|------|---------|------|-----------|-------|
| 1 | `/auth/login` | GET, POST | anonymous (redirects if logged in) | `10/minute`, deducted **only** when `g.deduct_limit` set (wrong email/password) | endpoint `auth.login` |
| 2 | `/auth/register` | GET, POST | anonymous (redirects if logged in) | none | `auth.register` |
| 3 | `/auth/activate` | GET, POST | anonymous (400 page if logged in) | `10/minute`, deducted only when code not found | **GET has side effects** (activates + logs in) |
| 4 | `/auth/resend_activation` | GET, POST | none | `10/hour` — deducted on **every** request incl. GET | `auth.resend_activation` |
| 5 | `/auth/forgot_password` | GET, POST | none | `10/hour`, deducted on every **valid form POST** | `auth.forgot_password` |
| 6 | `/auth/reset_password` | GET, POST | none | `10/minute`, deducted only when code invalid/not found | `auth.reset_password` |
| 7 | `/auth/change_email` | GET, POST | none | `3/hour` — deducted on **every** request incl. GET | **GET has side effects** (changes user email) |
| 8 | `/auth/mfa` | GET, POST | MFA interstitial (`session["mfa_user_id"]`) | `10/minute`, deducted on wrong token or invalid `mfa` device cookie | `auth.mfa` |
| 9 | `/auth/recovery` | GET, POST | MFA interstitial | `10/minute`, deducted on wrong/used code | endpoint is **`auth.recovery_route`** (function name) |
| 10 | `/auth/logout` | GET | any | none | GET with side effects (logout + cookie deletion) |
| 11 | `/auth/api_to_cookie` | GET | none (token in query) | none | GET logs user in |
| 12 | `/auth/fido` | GET, POST | MFA interstitial | `10/minute`, deducted on failed verify or invalid `mfa` cookie | **BLOCKER: WebAuthn** |
| 13 | `/auth/social` | GET, POST | anonymous (redirects if logged in) | none | deprecated social-login chooser page |
| 14 | `/auth/github/login` | GET | none | none | **BLOCKER: OAuth** — no config gate (see gotcha) |
| 15 | `/auth/github/callback` | GET | none | none | BLOCKER: OAuth |
| 16 | `/auth/google/login` | GET | none | none | gate: `google_enabled()` |
| 17 | `/auth/google/callback` | GET | none | none | BLOCKER: OAuth + S3 |
| 18 | `/auth/facebook/login` | GET | none | none | gate: `facebook_enabled()` |
| 19 | `/auth/facebook/callback` | GET | none | none | BLOCKER: OAuth + S3 |
| 20 | `/auth/proton/login` | GET | none | none | gate: `PROTON_CLIENT_ID and PROTON_CLIENT_SECRET` |
| 21 | `/auth/proton/callback` | GET | none | none | BLOCKER: Proton partner flow |
| 22 | `/auth/oidc/login` | GET | none | none | gate: `OIDC_CLIENT_ID and OIDC_CLIENT_SECRET` |
| 23 | `/auth/oidc/callback` | GET | none | none | BLOCKER: OIDC |

Related app-level route (not in the blueprint, but part of the auth UX): `GET|POST /` → if `current_user.is_authenticated` redirect `dashboard.index`, else redirect `auth.login`.

App-level **401 handler** (non-`/api` paths): `flash("You need to login to see this page", "error")` + `redirect(url_for("auth.login", next=request.full_path))`. This is how every `@login_required` page funnels into `/auth/login?next=...` (note `full_path` keeps the query string and a trailing `?` if none).

---

## Shared plumbing (must exist before any route works)

### Session (Flask → KV port)
- Flask: server-side session in Redis, cookie **`slapp`** contains an itsdangerous-signed session id (`Signer(FLASK_SECRET, salt="session", key_derivation="hmac")`). `session.permanent = True` on every request; lifetime **7 days**; unauthenticated sessions get a **300 s** Redis TTL (kept only for the CSRF token). Cookie: HttpOnly, SameSite=Lax, Secure iff `URL` starts with https.
- Port correspondence: `cloudflare/src/lib/session.ts` already implements an opaque-token KV session with the same cookie name/TTL. The web port must **extend `SessionData`** with the keys used here: `mfa_user_id` (int), `sudo_time` (int), `slref` (string), `csrf` (string), flash queue, and the OAuth keys (`oauth_state`, `oauth_next`, `oauth_scheme`, `oauth_mode`, `oauth_action`, `google_next_url`, `facebook_next_url`, `oauth_redirect_next`, `fido_challenge`).
- **Session regeneration**: every successful login path executes `session.session_id = str(uuid.uuid4())` *before* `login_user(user)` (session-fixation defense; the old Redis key is abandoned, not deleted). Port: mint a **new KV token + Set-Cookie** on login, carrying over surviving keys. Exception: `api_to_cookie` does **not** rotate (gotcha, replicate or fix consciously).
- `login_user(user)` is always called **without `remember=`** (remember=False). Persistence comes solely from the permanent session (7 d). Flask-Login stores `_user_id = user.alternative_id` (uuid string, NOT the integer id) and, with `session_protection = "strong"`, an `_id` fingerprint (sha512 of remote-addr + user-agent); a fingerprint mismatch silently empties the session. Port stance: store `user_id` (int) in KV; fingerprint binding optional (document if dropped).
- `logout_session()` = flask-login `logout_user()` + delete the Redis key + assign fresh session id.
- User loader: `User.get_by(alternative_id=...)`; returns None (→ anonymous) if `user.disabled` or `not user.is_active()` (`delete_on` set and in the future). The port's session middleware must re-check `disabled`/`delete_on` on every request — a password-reset regenerates `alternative_id` to force logout of other browsers (see Route 6), so KV sessions must also store/compare `alternative_id` **or** be individually revocable.

### CSRF (flask-wtf FlaskForm)
- Every wtforms POST validates a `csrf_token` hidden field (rendered by `{{ form.csrf_token }}`); token = `URLSafeTimedSerializer(FLASK_SECRET, salt="wtf-csrf-token")` over a random value kept in `session["csrf_token"]`; time limit **3600 s**.
- On CSRF failure `validate_on_submit()` returns False and the page **re-renders with 200**; the error string (`"The CSRF token is missing."` / `"The CSRF token has expired."` / `"The CSRF token is invalid."`) lands in `form.csrf_token.errors`, which **no auth template renders** → silent failure, user just sees the form again. Gotcha: because anonymous Redis sessions expire after 300 s, a login form left open >5 min fails CSRF silently on submit.
- GET-only routes (`logout`, `api_to_cookie`, all OAuth login/callback) have **no CSRF protection at all**.

### Flash messages
`flash(message, category)` appends to `session["_flashes"]`; `base.html` drains them via `get_flashed_messages(with_categories=true)` and emits `<script>toastr.{{category}}("{{ message }}")</script>` per message. Categories used by this group: `success`, `error`, `warning`, `info` (must map 1:1 to toastr methods). Messages must survive the redirect (store in session/KV, drain on next render).

### Rate limiting
Same engine as API spec 01 (flask-limiter; port: `cloudflare/src/lib/ratelimit.ts` D1 windows). Key: `userid:{id}` when session-authenticated else `ip:{remote_addr}`. Disabled by `DISABLE_RATE_LIMIT`. Non-API 429 → render `templates/error/429.html`, status 429 (HTML, not JSON). The `deduct_when=lambda r: hasattr(g, "deduct_limit") and g.deduct_limit` pattern means the counter increments **only on requests that set the flag** (marked per-route below); routes without `deduct_when` (`resend_activation`, `change_email`) count every hit including GETs.

### `sanitize_next_url(url)` (`app/utils.py` `NextUrlSanitizer`)
1. falsy → None. 2. replace every `\` with `/`. 3. `urlparse`; if a hostname is present it must be in `ALLOWED_REDIRECT_DOMAINS` (default: `[hostname of URL]`) → return the (backslash-replaced) full URL, else None. 4. no hostname: accept only `path` starting with `/` but not `//`, returning `path` + (`?query` if any). Everything else → None.

### `sanitize_scheme(scheme)` — proton only
None if falsy or `http`/`https`; must match `^[a-z.]+$` else None.

### `after_login(user, next_url, login_from_proton=False)` (`login_utils.py`)
The single post-credential dispatcher — **replicate exactly**:
1. Unless `login_from_proton`: if `user.fido_enabled()` (i.e. `fido_uuid IS NOT NULL`) → `session["mfa_user_id"] = user.id`; redirect `auth.fido` (`?next=<next_url>` iff next_url). Else if `user.enable_otp` → same but redirect `auth.mfa`. (FIDO wins when both are enabled.)
2. Otherwise: rotate session id, `login_user(user)`, `session["sudo_time"] = int(unix_now)`, redirect `next_url` or `url_for("dashboard.index")`.
- Gotcha: **`sudo_time` is granted by password login and by FIDO completion, but NOT by TOTP (`mfa`) or recovery-code completion** — those paths call `login_user` themselves without setting `sudo_time`.

### Referral capture (`get_referral()`)
- App-level `before_request`: if `?slref=<code>` present on **any** URL → `session["slref"] = code`.
- `get_referral()`: look up `Referral` by `code` from cookie **`slref`** first, then from `session["slref"]`. Returns the Referral row or None. Used only by register → `users.referral_id`.
- (The `slref` cookie itself is set by the separate landing-page site; the webapp only reads it.)

### MFA interstitial state
- Session key: `MFA_USER_ID = "mfa_user_id"` — written by `after_login`, read by `/auth/mfa`, `/auth/recovery`, `/auth/fido`; deleted on successful TOTP/recovery/FIDO verify (NOT deleted on device-cookie fast-path — gotcha).
- Device cookie **`mfa`**: 64-char lowercase-a–z token referencing `mfa_browser` row (`user_id`, `token` unique, `expires` = now+30 d). Set only when "remember" checked: `secure=URL.startswith("https")`, `httponly=True`, `samesite="Lax"`, `expires=browser.expires`.
- **D1 gap**: `mfa_browser` has **no table** in `cloudflare/migrations/0001_init.sql` — a migration is required (also missing and needed by this group: `social_auth`, `daily_metric`, `abuser_lookup`, `user_audit_log`).

---

## Route 1: `GET|POST /auth/login` (`auth.login`)

Rate limit `10/minute`, deducted only on the wrong-credentials branch.

Form `LoginForm(FlaskForm)`:
| field | type | validators | error string |
|---|---|---|---|
| `email` | StringField "Email" | DataRequired | `This field is required.` |
| `password` | StringField "Password" | DataRequired | `This field is required.` |

Common: `next_url = sanitize_next_url(request.args.get("next"))`. The form posts to the same URL (no `action`), so `?next=` survives the POST.

GET (or failed validation):
- If `current_user.is_authenticated`: redirect `next_url` if present else `dashboard.index` (no flash).
- Render `auth/login.html` with context: `form`, `next_url`, `show_resend_activation` (bool, set only by the not-activated branch below), `connect_with_proton=CONNECT_WITH_PROTON` (env-presence bool), `connect_with_oidc=(OIDC_CLIENT_ID is not None)`, `connect_with_oidc_icon=CONNECT_WITH_OIDC_ICON`.

POST (`validate_on_submit()` true), in order:
1. `email = sanitize_email(form.email.data)`; `canonical_email = canonicalize_email(email)`; `user = User.get_by(email=email) or User.get_by(email=canonical_email)` (identical to API spec 01 Route 1).
2. `not user or not user.check_password(password)` → dummy bcrypt check when no user (same fixed hash as API spec 01); set deduct flag; **clear `form.password.data` (password input re-renders empty)**; flash `Email or password incorrect` (error); re-render (200).
3. `user.disabled` → flash `Your account is disabled. Please contact SimpleLogin team to re-enable your account.` (error); re-render.
4. `user.delete_on is not None` → flash `Your account is scheduled to be deleted on {user.delete_on}` (error) — `{user.delete_on}` is the Arrow repr, e.g. `2026-07-05T10:00:00+00:00`; re-render.
5. `not user.activated` → `show_resend_activation = True`; flash `Please check your inbox for the activation email. You can also have this email re-sent` (error); re-render (template shows a "You haven't received the activation email? Resend" link to `auth.resend_activation`).
6. Success → `return after_login(user, next_url)` (may redirect to `auth.fido`/`auth.mfa` interstitial instead of logging in — see shared plumbing).

DB: reads `users` by email (×2); no writes (login itself writes only the session).

---

## Route 2: `GET|POST /auth/register` (`auth.register`)

No rate limit.

Form `RegisterForm(FlaskForm)`:
| field | type | validators | error strings |
|---|---|---|---|
| `email` | StringField "Email" | DataRequired | `This field is required.` |
| `password` | StringField "Password" | DataRequired, Length(min=8, max=100) | `This field is required.` / `Field must be between 8 and 100 characters long.` |

Pre-checks (GET and POST):
1. `current_user.is_authenticated` → flash `You are already logged in` (warning); redirect `dashboard.index`.
2. `config.DISABLE_REGISTRATION` → flash `Registration is closed` (error); redirect `auth.login`.

`next_url = request.args.get("next")` — **raw, NOT sanitized** (only embedded in template links and the activation link, never redirected to directly).

POST branches, in order:
1. **hCaptcha** (only if `HCAPTCHA_SECRET` set): POST `https://hcaptcha.com/siteverify` with `{secret, response: request.form["h-captcha-response"]}`. On failure: flash `Wrong Captcha` (error) and re-render `auth/register.html` with context **only** `form`, `next_url`, `HCAPTCHA_SITEKEY` — gotcha: `connect_with_proton`/`connect_with_oidc` are omitted → falsy → the Proton/SSO buttons vanish on this re-render. **BLOCKER** (external HTTP): config-gate exactly like Flask — skip verification when `HCAPTCHA_SECRET` unset; `fetch` to hcaptcha works on Workers if enabled.
2. `email = canonicalize_email(form.email.data)` — the account is created under the **canonical** email; `name` is set to the raw input.
3. `not email_can_be_used_as_mailbox(email)` (same helper chain as API spec 01 Route 2 step 4, incl. MX lookup) → flash `You cannot use this email address as your personal inbox.` (error); re-render.
4. `check_if_abuser_email(email)` (HMAC-SHA256(`MAC_KEY`) lookup in `abuser_lookup` — see API spec 01 Route 2 step 5) → flash `The email address provided is banned from registration.` (error); re-render.
5. `personal_email_already_used(canonical) or personal_email_already_used(sanitize_email(raw))` → flash `Email {email} already used` (error, canonical email interpolated); re-render.
6. Create: `User.create(email=canonical, name=<raw form email>, password=..., referral=get_referral())` + commit — full side-effect set identical to API spec 01 Route 2 step 8 (mailbox, newsletter alias, audit log, onboarding jobs), **plus `referral_id`** from the `slref` cookie/session.
7. `send_activation_email(user, next_url)` (see below) inside try/except; then RegisterEvent + `DailyMetric.get_or_create_today_metric().nb_new_web_non_proton_user += 1` + commit. On **exception**: flash `Invalid email, are you sure the email is correct?` (error); redirect `auth.register` — gotcha: **the user row already exists** at this point.
8. Success → render `auth/register_waiting_activation.html` (200, no redirect).

GET render context: `form`, `next_url`, `HCAPTCHA_SITEKEY`, `connect_with_proton`, `connect_with_oidc=(config.OIDC_CLIENT_ID is not None)`, `connect_with_oidc_icon`.

### `send_activation_email(user, next_url)` (module-level in `register.py`, shared with Route 4)
1. Delete **all** existing `activation_code` rows for the user.
2. `ActivationCode.create(user_id, code=random_string(30))` — 30 lowercase a–z chars; `expired` defaults to now+1 h; commit.
3. Link `f"{URL}/auth/activate?code={code}"`, plus `"&next=" + encode_url(next_url)` if next_url (`encode_url` = `urllib.parse.quote(url, safe="")`).
4. `email_utils.send_activation_email(user, link)`: skipped if `!user.can_send_or_receive()`; to `user.email`, subject **`Just one more step to join SimpleLogin`**, templates `transactional/activation.txt|.html` (context: `user`, `activation_link`, `email=user.email`).

Note: this is the **web** activation flow (`activation_code` table, 30-char link code, 1 h expiry) — distinct from the API's `account_activation` 6-digit flow (API spec 01). Both tables exist in D1.

---

## Route 3: `GET|POST /auth/activate` (`auth.activate`)

Rate limit `10/minute`, deducted only when the code is not found. POST is accepted but behaves identically (code comes from `request.args`; there is no form).

Logic, in order:
1. `current_user.is_authenticated` → render `auth/activate.html` with `error="You are already logged in"`, **status 400**.
2. `code = request.args.get("code")`; lookup `activation_code` by `code`. Not found → deduct flag; render `auth/activate.html` with `error="Activation code cannot be found"`, **400**.
3. `is_expired()` (`expired < now`) → render with `error="Activation code was expired"`, `show_resend_activation=True`, **400**.
4. Success (**GET side effects**): `user.activated = True`; `user_audit_log` row (action `ActivateUser`, message `User has been activated: {user.email}`); rotate session id; `login_user(user)`; delete the activation-code row; commit; flash `Your account has been activated` (success); `send_welcome_email(user)` (subject **`Welcome to SimpleLogin`**, to the user's communication email — newsletter alias if set — skipped when unsubscribed); redirect **`dashboard.index`**.
- Gotcha: the `&next=` embedded in the activation link is **ignored** — activation always lands on the dashboard. Also note activation logs the user in **without** any MFA interstitial and without setting `sudo_time`.

---

## Route 4: `GET|POST /auth/resend_activation` (`auth.resend_activation`)

Rate limit `10/hour`, **every request deducts** (no `deduct_when`), keyed by IP.

Form `ResendActivationForm(FlaskForm)`: `email` StringField "Email", DataRequired (`This field is required.`).

POST branches:
1. User lookup by sanitized-then-canonical email (as login). Not found → flash `If this email is registered, an activation email has been sent.` (warning); **render** `auth/resend_activation.html` (no redirect; enumeration-safe).
2. `user.activated` → flash `Your account was already activated, please login` (success); redirect `auth.login`. (Gotcha: this branch *does* reveal that the address has an activated account.)
3. Else: flash `An activation email has been sent to you. Please check your inbox/spam folder.` (warning); `send_activation_email(user, request.args.get("next"))` (raw `next`, embedded in the link); render `auth/register_waiting_activation.html`.

GET: render `auth/resend_activation.html` with `form`.

---

## Route 5: `GET|POST /auth/forgot_password` (`auth.forgot_password`)

Rate limit `10/hour`, deducted on every **valid form submit** (flag set unconditionally inside the branch, before the user lookup).

Form `ForgotPasswordForm(FlaskForm)`: `email` StringField "Email", DataRequired.

POST (valid): flash `If your email is correct, you are going to receive an email to reset your password` (success) — **always, before/regardless of lookup**; then lookup (sanitized, canonical) and, if found, `send_reset_password_email(user)` — the exact same helper as API spec 01 Route 7: insert `reset_password_code` (`secrets.token_urlsafe(32)` ≈ 43 chars, `expired`=now+1 h), email subject **`Reset your password on SimpleLogin`**, link `{URL}/auth/reset_password?code={code}` (skipped when `user.disabled`/`delete_on`). Then falls through to re-render the same page (no redirect).

GET / invalid: render `auth/forgot_password.html` with `form` (template also displays optional `error` var, never set by this view).

---

## Route 6: `GET|POST /auth/reset_password` (`auth.reset_password`)

Rate limit `10/minute`, deducted only when code missing/unknown.

Form `ResetPasswordForm(FlaskForm)`: `password` StringField "Password", DataRequired + Length(min=8, max=100) (`This field is required.` / `Field must be between 8 and 100 characters long.`).

Logic, in order (code from `request.args.get("code")`, both GET and POST):
1. No matching `reset_password_code` row → deduct flag; render `auth/reset_password.html` with `form` and `error="The reset password link can be used only once. Please request a new link to reset password."` (200 — note: unlike activate, **no 4xx status**).
2. `is_expired()` → render with `error="The link has been already expired. Please make a new request of the reset password link"` (200). (Row is NOT deleted.)
3. POST valid: `user.check_password(new_password)` (reuse of old password) → render with `error="You cannot reuse the same password"` (200).
4. Success: `user.set_password(new_password)` (bcrypt, API spec 01); flash `Your new password has been set` (success); `user.activated = True` (reset link doubles as activation); `user_audit_log` row (action `ResetPassword`, message `User has reset their password`); **delete ALL** `reset_password_code` rows of the user; `regenerate_user_alternative_id(user, update_session=False)` → new `users.alternative_id` uuid, which **invalidates every other logged-in browser** (user_loader misses) — port: revoke other KV sessions or store+compare alternative_id; audit-log row action `UpdateProfile`, message `Regenerated alternative id`. Commit. Then `return after_login(user, url_for("dashboard.index"))` — deliberately **not** `login_user` directly, so FIDO/TOTP users get the MFA interstitial; next_url is hardcoded to the dashboard path.
5. GET with valid code: render `auth/reset_password.html` with `form` only (no `error`).

---

## Route 7: `GET|POST /auth/change_email` (`auth.change_email`)

Rate limit `3/hour`, every request deducts. (The confirmation email is produced by `dashboard.setting`; link format `{URL}/auth/change_email?code={email_change.code}`.)

Logic (code from `request.args.get("code")`):
1. No `email_change` row for `code` → render `auth/change_email.html` (200) — static "Incorrect or expired link." page.
2. `is_expired()` (`expired` = creation+12 h) → **delete the row**, commit, render the same page.
3. Valid (**GET side effect**): `user.email = email_change.new_email`; delete the `email_change` row; **delete all `reset_password_code` rows** of the user; commit; flash `Your new email has been updated` (success); redirect **`auth.login`** — deliberately does not log in, so MFA still applies.

---

## Route 8: `GET|POST /auth/mfa` (`auth.mfa`)

Rate limit `10/minute`, deducted on invalid device cookie or wrong token.

Form `OtpTokenForm(FlaskForm)`:
| field | type | validators | notes |
|---|---|---|---|
| `token` | StringField "Token" | DataRequired (`This field is required.`) | |
| `remember` | BooleanField "attr", default False | — | `description="Remember this browser for 30 days"` (rendered as the checkbox label) |

Guards (GET and POST):
1. `session.get("mfa_user_id")` missing → flash `Unknown error, redirect back to main page` (warning); redirect `auth.login`.
2. `user = User.get(user_id)`; `not (user and user.enable_otp)` → flash `Only user with MFA enabled should go to this page` (warning); redirect `auth.login`.

`next_url = sanitize_next_url(request.args.get("next"))`.

Device-cookie fast path (before form handling): if cookie `mfa` present → look up `mfa_browser` by token; if found, not expired, and `browser.user_id == user.id`: rotate session id, `login_user(user)`, flash `Welcome back!` (success), redirect `next_url or dashboard.index` (gotcha: `mfa_user_id` stays in session; `sudo_time` NOT set). Otherwise (cookie invalid) set deduct flag and continue.

POST valid:
1. `token = form.token.data.replace(" ", "")`; verify `pyotp.TOTP(user.otp_secret).verify(token, valid_window=2)` **and** `user.last_otp != token` (exact semantics in API spec 01 "TOTP verification").
2. Success: `del session["mfa_user_id"]`; `user.last_otp = token`; commit; rotate session id; `login_user(user)`; flash `Welcome back!` (success); response = redirect `next_url or dashboard.index`; if `remember` checked: `MfaBrowser.create_new(user)` (64-char token, expires now+30 d) + commit + set cookie `mfa` (attributes in shared plumbing). **`sudo_time` is NOT set.**
3. Failure: flash `Incorrect token` (warning); deduct flag; **clear `form.token.data`**; `send_invalid_totp_login_email(user, "TOTP")` — subject **`Unsuccessful attempt to login to your SimpleLogin account`**, rate-controlled max 1/24 h via `sent_alert` (API spec 01); re-render.

GET/failed render: `auth/mfa.html` with `otp_token_form`, `enable_fido=user.fido_enabled()` (shows "Verify by your security key" link to `auth.fido`), `next_url` (used in the `auth.recovery_route` link).

---

## Route 9: `GET|POST /auth/recovery` (endpoint **`auth.recovery_route`**)

Rate limit `10/minute`, deducted on used/incorrect code.

Form `RecoveryForm(FlaskForm)`: `code` StringField "Code", DataRequired.

Guards: same as mfa but the second check is `user.two_factor_authentication_enabled()` (`enable_otp or fido_enabled()`); same two warning flashes (`Unknown error, redirect back to main page` / `Only user with MFA enabled should go to this page`). Gotcha: no `user` None-check before calling the method → a stale `mfa_user_id` pointing at a deleted user raises → web 500 page.

`next_url = sanitize_next_url(request.args.get("next"))`.

POST valid: `recovery_code = RecoveryCode.find_by_user_code(user, code)` — code is HMAC-SHA3-224(`RECOVERY_CODE_HMAC_SECRET`, raw code), base64url-no-padding, matched against `recovery_code.code` for the user.
- Found & `used` → deduct flag; flash `Code already used` (error); re-render.
- Found & unused: `del session["mfa_user_id"]`; rotate session id; `login_user(user)`; flash `Welcome back!` (success); mark `used=True`, `used_at=now`; commit; redirect `next_url or dashboard.index`. (**No `sudo_time`, no `mfa` cookie option.**)
- Not found → deduct flag; flash `Incorrect code` (error); `send_invalid_totp_login_email(user, "recovery")`; re-render.

Render: `auth/recovery.html` with `recovery_form`.

---

## Route 10: `GET /auth/logout` (`auth.logout`)

GET with side effects (CSRF-less logout — replicate as-is):
1. `logout_session()` (logout + purge server session).
2. flash `You are logged out` (success) — gotcha: flash written **after** purge into the fresh session, so it does survive and shows on the login page.
3. Redirect `auth.login`; delete cookies `slapp` (SESSION_COOKIE_NAME), `mfa`, `dark-mode`.

---

## Route 11: `GET /auth/api_to_cookie` (`auth.api_to_cookie`)

Turns an API token into a web session (used by extension/mobile deep-links). Query: `token`, optional `next`.
1. No `token` arg → flash `Missing token` (error); redirect `auth.login`.
2. Lookup `api_cookie_token` by `code=token` — **scoped to `user_id=current_user.id` when already logged in**, unscoped otherwise.
3. Not found **or** `created_at < now - 5 minutes` → flash `Missing token` (error, same string); redirect `auth.login`.
4. Valid: delete the token row (single-use, commit); `login_user(token.user)` — gotcha: **no session-id rotation, no MFA interstitial, no sudo_time**; redirect `sanitize_next_url(request.args.get("next"))` or `dashboard.index`.

Token creation lives in the API (`POST /api/user/cookie_token`, `secrets.token_urlsafe(32)`).

---

## Route 12: `GET|POST /auth/fido` (`auth.fido`) — BLOCKER (WebAuthn)

Rate limit `10/minute` (deduct on failed verification / invalid device cookie). Guards identical to mfa but check `user.fido_enabled()`; second warning string differs: `Only user with security key linked should go to this page` (warning).

Form `FidoTokenForm(FlaskForm)`: `sk_assertion` HiddenField, DataRequired; `remember` BooleanField (same description as mfa).

Flask behavior (summary): device-cookie fast path identical to mfa; GET generates `secrets.token_urlsafe(32)` challenge → `session["fido_challenge"]` (rstrip `=`), builds `webauthn_assertion_options` from all `fido` rows of `user.fido_uuid` (injecting stored `transports` per credential, dropping the field when absent) and renders `auth/fido.html` (context: `fido_token_form`, `webauthn_assertion_options`, `enable_otp=user.enable_otp`, `auto_activate` (False after a failed POST), `next_url`). POST parses `sk_assertion` JSON (invalid → flash `Key verification failed. Error: Invalid Payload` (warning) + redirect `auth.login`), verifies via the legacy `webauthn` 0.4-style lib against `RP_ID` (= hostname of `URL`) and origin `URL`, `uv_required=False`; on failure flash `Key verification failed.` (warning) + deduct + re-render with `auto_activate=False`; on success: update `fido.sign_count` (gotcha: written to `user.fido_sign_count` legacy column), `del session["mfa_user_id"]`, `session["sudo_time"]=now` (**FIDO grants sudo**), rotate, `login_user`, flash `Welcome back!` (success), optional `mfa` cookie exactly like mfa, redirect `next_url or dashboard.index`. Also `session.pop("challenge", None)` before generating a new challenge.
- **Porting stance**: implement the route + guards + template; do WebAuthn assertion verification with WebCrypto (`@simplewebauthn/server` works on Workers) or — minimum viable — keep the route but flash `Key verification failed.` and rely on TOTP/recovery. Do not silently drop the route: users with `fido_uuid` set are funneled here by `after_login` and would be locked out; recovery-code login must work.

---

## Route 13: `GET|POST /auth/social` (`auth.social`)

If authenticated → redirect `dashboard.index`. Else render `auth/social.html` (no form; the page reads globals `GITHUB_CLIENT_ID` / `GOOGLE_CLIENT_ID` / `FACEBOOK_CLIENT_ID` from the app-wide context processor and shows one button per configured provider, plus a deprecation warning). Not linked from login/register anymore. Gotcha: template references `next_url` which is **never in context** here → undefined → empty `?next=` args.

---

## Routes 14–23: social/OIDC OAuth — existence, gates, BLOCKER stances

All are GET, no rate limit, no CSRF. Common pieces: `session["oauth_state"]` CSRF state; "user clicked cancel" check `if "error" in request.args` → flash + `redirect("/")`; on success every callback ensures a `social_auth` row `(user_id, social=<name>)` (unique `uq_social_auth`) then `after_login(user, next_url)`.

| Provider | Login gate (redirect `auth.login` when unmet) | next handling | cancel flash (warning) | key error flashes (error) |
|---|---|---|---|---|
| google | `google_enabled()` = `GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET` (login AND callback) | `session["google_next_url"]` | `please use another sign in method then` (lowercase p) | `Sorry you cannot sign up via Google, please use email/password sign-up instead` → redirect `auth.register` |
| facebook | `facebook_enabled()` (login AND callback) | `session["facebook_next_url"]` | `Please use another sign in method then` | `In order to use SimpleLogin, you need to give us a valid email` (warning) → `auth.register`; `Sorry you cannot sign up via Facebook, please use email/password sign-up instead` → `auth.register` |
| github | **NONE — no config gate at all** (gotcha: with unset `GITHUB_CLIENT_ID` the redirect to GitHub is built with `client_id=None`; the port should 302 to `auth.login` when unconfigured and document the divergence) | `?next=` URL-encoded into redirect_uri | `Please use another sign in method then` | `Cannot get a valid email from Github, please another way to login/sign up` → `auth.login`; `Sorry you cannot sign up via Github, please use email/password sign-up instead` → `auth.register` |
| proton | `PROTON_CLIENT_ID and PROTON_CLIENT_SECRET`; also `?action=` must be `link`/`login`/absent, `link` requires auth; bad `?scheme=` → flash `Bad OAuth request` (error) → `auth.login` | `session["oauth_next"]`, plus `oauth_scheme`/`oauth_mode` (apikey mode returns `scheme:///login?apikey=...` deep link) | `Please use another sign in method then` | `Invalid state, please retry`; `There was an error in the login process` |
| oidc | `OIDC_CLIENT_ID and OIDC_CLIENT_SECRET` (login AND callback); callback also requires `session["oauth_state"]` else flash `Invalid state, please retry` (error) → `auth.login` | `session["oauth_redirect_next"]` | `Please use another sign in method then` | `Cannot get user data from OIDC, please use another way to login/sign up`; `Cannot get a valid email from OIDC, please another way to login/sign up`; `Sorry you cannot sign up via the OIDC provider. Please sign-up first with your email.` → `auth.register` |

Behavior notes (for eventual full ports): google/facebook **never create users** (existing-email login only; unknown email → the "cannot sign up via X" flash); both set the user's profile picture via **S3 upload** when missing (extra BLOCKER); github picks the primary+verified email from `/user/emails`; google/facebook `session.pop("_flashes", None)` at login start (clears pending flashes); oidc **creates** users (`activated=True`, name from `OIDC_NAME_FIELD`, welcome email) unless `DISABLE_REGISTRATION` (flash above); proton delegates to `ProtonCallbackHandler` (partner link/login, `DailyMetric` etc.) and calls `after_login(..., login_from_proton=True)` which **bypasses MFA**.

**BLOCKER stance for all five**: implement only the routes + config gates (unconfigured → 302 `auth.login`, matching Flask, incl. treating github as unconfigured-gated) and hide the buttons exactly as the templates/config do (`connect_with_proton`, `connect_with_oidc`, `GITHUB/GOOGLE/FACEBOOK_CLIENT_ID` globals). Defer the actual token exchanges; if a provider is configured but the flow is unimplemented, return the web 500 page rather than a broken half-flow.

---

## Templates — porting notes

All extend `single.html` → `base.html` except `activate.html` (extends `error.html` → `base.html`). `base.html` line 1: `{% from "_formhelpers.html" import render_field, render_field_errors %}` — imported names are available to all child templates (Nunjucks port: make `render_field_errors` a global macro/helper). `render_field_errors(field)`: if `field.errors` → `<ul class="errors">` of `<li class="text-danger">{{ error }}</li>`.

Base-chain requirements (shared with all web groups, listed once):
- Globals from context processor: `YEAR`, `NOW` (arrow; `NOW.timestamp` used in a Black-Friday banner — expired epoch `1701475201`, safe to drop), `URL`, `SENTRY_DSN`, `VERSION`, `FIRST_ALIAS_DOMAIN`, `PLAUSIBLE_HOST`, `PLAUSIBLE_DOMAIN`, `GITHUB_CLIENT_ID`, `GOOGLE_CLIENT_ID`, `FACEBOOK_CLIENT_ID`, `LANDING_PAGE_URL`, `STATUS_PAGE_URL`, `SUPPORT_EMAIL`, `PGP_SIGNER`, `CANONICAL_URL` (= `URL + request.path`), `PAGE_LIMIT`, `ZENDESK_ENABLED`, `MAX_NB_EMAIL_FREE_PLAN`, `HEADER_ALLOW_API_COOKIES`.
- `current_user.is_authenticated`, `current_user.should_show_upgrade_button()` (base banner; anonymous user must short-circuit).
- `request.cookies.get('dark-mode')` (sets `data-theme="dark"` on `<html>`), `get_flashed_messages(with_categories=true)`, `url_for('static', filename=...)` (many), blocks `title` / `head` / `announcement` / `content` / `script`.
- Page `<title>` = `{% block title %} | SimpleLogin`.

Per-template specifics (auth group):

| Template | title block | context consumed | url_for endpoints referenced | other constructs |
|---|---|---|---|---|
| `auth/login.html` | `Login` | `form`, `next_url`, `show_resend_activation`, `connect_with_proton`, `connect_with_oidc`, `connect_with_oidc_icon` | `auth.resend_activation`, `auth.forgot_password`, `auth.register`, `auth.proton_login` (`next=next_url`), `auth.oidc_login` (`next=next_url`) | `form.csrf_token`, `form.email(class=..., type="email", autofocus="true")`, `form.password(... type="password")`, `render_field_errors` |
| `auth/register.html` | `Register` | `form`, `next_url`, `HCAPTCHA_SITEKEY`, `connect_with_proton`, `connect_with_oidc`, `connect_with_oidc_icon` | `auth.proton_login`, `auth.oidc_login`, `auth.login` | hCaptcha `<div class="h-captcha" data-sitekey>` + external script `https://hcaptcha.com/1/api.js` (only when `HCAPTCHA_SITEKEY`); email placeholder `username@proton.me` |
| `auth/register_waiting_activation.html` | `Activation Email Sent` | — | — | `{% block script %}` calls `plausible('Complete registration')` |
| `auth/activate.html` | (none — error layout) | `error`, `show_resend_activation` | `auth.resend_activation` | fills `error_name`/`error_description` blocks of `error.html`; `error.html` has a "Home Page" button linking `/` |
| `auth/resend_activation.html` | `Resend activation email` | `form` | `auth.register` | `form.csrf_token`, `form.email` |
| `auth/forgot_password.html` | `Forgot Password` | `form` (+ optional `error`, unused) | `auth.login` | |
| `auth/reset_password.html` | `Reset password` | `form`, optional `error` | — | `error` shown as `text-danger` div |
| `auth/change_email.html` | `Change Email` | — | `dashboard.setting` | static failure page (success path never renders it) |
| `auth/mfa.html` | `MFA` | `otp_token_form`, `enable_fido`, `next_url` | `auth.fido`, `auth.recovery_route` (`next=next_url`) | checkbox rendered with `otp_token_form.remember(... id="remember")` + label from `.description`; stray hidden input `name="form-name" value="create"` (ignored by view) |
| `auth/recovery.html` | `Recovery Code` | `recovery_form` | — | |
| `auth/fido.html` | `Verify Your Security Key` | `fido_token_form`, `webauthn_assertion_options`, `enable_otp`, `auto_activate`, `next_url` | `auth.mfa`, `auth.recovery_route` (`next=next_url`), `static` (base64.js, webauthn.js) | `{{ webauthn_assertion_options|tojson|safe }}` inside JS (**`tojson` filter needed in Nunjucks env**); `{% block head %}` extra scripts; auto-submit script when `auto_activate` |
| `auth/social.html` | `Social Login` | globals `GITHUB_CLIENT_ID`/`GOOGLE_CLIENT_ID`/`FACEBOOK_CLIENT_ID`; `next_url` (undefined — renders empty) | `auth.github_login`, `auth.google_login`, `auth.facebook_login`, `auth.register`, `auth.login` | |

No `dt`/`enumerate` filters and no htmx/AJAX sub-endpoints in this group; every POST is a full-page form submit. Out-of-scope endpoints referenced by this group's pages: `dashboard.index` (`/dashboard/`), `dashboard.setting` (`/dashboard/setting`), plus the error pages `error/400|403|404|405|429|500.html`.

---

## Gotchas checklist (quick review for the implementer)

1. GET routes with side effects: `/auth/activate` (activates + logs in), `/auth/change_email` (changes email), `/auth/logout`, `/auth/api_to_cookie` (logs in). No CSRF on any of them.
2. `?next=` is sanitized in login/mfa/recovery/fido/api_to_cookie/github/google/facebook/proton/oidc, but **raw** in register/resend_activation (link-embedding only). Activation ignores `next` entirely.
3. Session id rotation before every `login_user` **except** `api_to_cookie`.
4. `sudo_time` set by password login (`after_login`) and FIDO only — not by TOTP/recovery/activate/api_to_cookie.
5. `mfa_user_id` survives the device-cookie fast path (not deleted).
6. Failed login clears the password field; failed TOTP clears the token field.
7. hCaptcha-failure re-render drops the Proton/SSO buttons (missing context vars).
8. Register creates the user **before** sending the activation email; email failure leaves an inactive user row and flashes `Invalid email, are you sure the email is correct?`.
9. `resend_activation` deducts rate limit on GET; `change_email` allows only 3 requests/hour including the render before the real click-through.
10. Flash `error` category → `toastr.error`; the base template comment mentions "danger" but no auth view uses it.
11. wtforms messages are exact: `This field is required.` / `Field must be between 8 and 100 characters long.`; CSRF errors are swallowed (form re-renders silently).
12. `delete_on` flash interpolates the raw Arrow timestamp.
13. `auth.recovery_route` endpoint name ≠ path (`/auth/recovery`).
14. 401 anywhere on the web app → flash `You need to login to see this page` (error) + redirect `auth.login?next=<full_path>`.
15. D1 migration needed: `mfa_browser`, `social_auth`, `daily_metric`, `abuser_lookup`, `user_audit_log` are absent from `0001_init.sql`.

---

## BLOCKER summary

| Feature | Flask behavior | Stance for the port |
|---|---|---|
| hCaptcha (`register`) | POST to `hcaptcha.com/siteverify` when `HCAPTCHA_SECRET` set | Config-gate like Flask (skip when unset); plain `fetch` if enabled |
| WebAuthn (`/auth/fido`, `after_login` FIDO branch) | python-webauthn 0.4 assertion verify, `RP_ID`=URL hostname | Port route+guards; verify via WebCrypto/`@simplewebauthn/server`, or stub verification-failure while keeping TOTP/recovery escape hatches |
| Google/Facebook OAuth | requests-oauthlib flows, login-only (no signup), S3 profile-picture upload | Config-gate (redirect `auth.login` when unconfigured, hide buttons); defer flows; S3 upload → defer (R2 later) |
| GitHub OAuth | **No config gate** in Flask | Add the gate (documented divergence); defer flow |
| Proton OAuth (`CONNECT_WITH_PROTON`) | Partner login/link via `ProtonCallbackHandler`, apikey deep-link mode, bypasses MFA | Config-gate (`PROTON_CLIENT_ID`/`SECRET`, button on `CONNECT_WITH_PROTON`); defer flow |
| Generic OIDC | Discovery via `OIDC_WELL_KNOWN_URL`, creates users | Config-gate (`OIDC_CLIENT_ID`/`SECRET`, button on `OIDC_CLIENT_ID is not None`); defer flow |
| Redis sessions / flask-login | Server-side session, `slapp` signed-id cookie, strong session protection | Replace with KV (`lib/session.ts`), extend SessionData per this spec; alternative_id revocation semantics required |
| Redis rate-limit storage | flask-limiter | Reuse D1 `rate_limit` table (`lib/ratelimit.ts`) with the `deduct_when` flag semantics |
| SMTP sends (activation/welcome/reset/invalid-TOTP emails) | Postfix via `send_email` | Reuse the port's mailer (`lib/mailer.ts`), subjects verbatim |
| MX-lookup in `email_can_be_used_as_mailbox` | live DNS | Same stance as API port (DNS-over-HTTPS / `SKIP_MX_LOOKUP_ON_CHECK`) |
| NewRelic Login/RegisterEvent, Plausible, Sentry | Observability only | Drop / no-op |
