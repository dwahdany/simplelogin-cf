# Spec 01 — Authentication API

Source files:
- `app/api/views/auth.py`
- `app/api/views/auth_mfa.py`

Supporting code referenced (behavior inlined below):
- `app/pw_models.py` (bcrypt password hashing)
- `app/models.py` (`User`, `ApiKey`, `AccountActivation`, `ResetPasswordCode`, `SocialAuth`, `ModelMixin`)
- `app/utils.py` (`sanitize_email`, `canonicalize_email`, `random_string`)
- `app/email_utils.py` (mailbox-email validation, alert emails)
- `app/dashboard/views/account_setting.py` (`send_reset_password_email`)
- `app/api/base.py` (blueprint + auth decorators)
- `app/extensions.py` (rate limiter key function)
- `app/parallel_limiter.py` (Redis concurrency lock)
- `simplelogin_app.py` (`setup_error_page`, CORS, session cookie)

All routes live on the blueprint `api_bp = Blueprint(name="api", import_name=__name__, url_prefix="/api")`, so the full path prefix is **`/api`**. There are **no version variants** (no v2/v3/v4/v5) for any auth route.

**None of the routes in this spec require authentication** (no `require_api_auth` / `require_api_sudo`). They are the routes that *produce* API keys.

There is **no `/auth/logout` endpoint** and **no explicit API-key-creation endpoint** in these files (API keys are created implicitly by login/MFA, see `auth_payload` below; the sudo/api_key endpoints live in `app/api/views/sudo.py` — separate spec).

---

## Global behaviors that apply to every route here

### Response envelope
- Success and error bodies are built with Flask `jsonify(...)` → `Content-Type: application/json`.
- Every error is of the shape `{"error": "<message>"}`. Every non-error is exactly the dict shown per-route.
- CORS is enabled app-wide for `/api/*` with `origins: "*"` (`CORS(app, resources={r"/api/*": {"origins": "*"}})`).

### Rate limiting (`@limiter.limit`)
- flask-limiter, storage = Redis (`MEM_STORE_URI` config). Disabled entirely when config `DISABLE_RATE_LIMIT` is set.
- Key function (`app/extensions.py`):
  - session-authenticated user → `userid:{user.id}`
  - otherwise → `ip:{remote_addr}` (for these unauthenticated routes this is the normal case).
- When a limit is hit, the app-level 429 handler returns (for any path starting with `/api/`):
  - **429** `{"error": "Rate limit exceeded"}`

### App-level error handlers (`setup_error_page` in `simplelogin_app.py`) — apply to `/api/*` paths
- 400 (e.g. malformed JSON body → Flask `request.get_json()` raises BadRequest): `{"error": "Bad Request"}`, 400
- 401: `{"error": "Unauthorized"}`, 401
- 403: `{"error": "Forbidden"}`, 403
- 404: `{"error": "No such endpoint"}`, 404
- 405: `{"error": "Method not allowed"}`, 405
- 429: `{"error": "Rate limit exceeded"}`, 429
- Any uncaught exception: **500** `{"error": "Internal error"}`

### Body parsing
Every route starts with `data = request.get_json()`:
- No body, non-JSON `Content-Type`, or JSON `null` → `data` is falsy → **400** `{"error": "request body cannot be empty"}`.
- **Gotcha:** an empty JSON object `{}` is also falsy in Python → same **400** `"request body cannot be empty"`.
- Syntactically invalid JSON with `Content-Type: application/json` → Flask raises BadRequest → app handler → **400** `{"error": "Bad Request"}`.

### Helper: `sanitize_email(email_address, not_lower=False)` (`app/utils.py`)
```python
if email_address:
    email_address = email_address.strip().replace(" ", "").replace("\n", " ")
    if not not_lower:
        email_address = email_address.lower()
return email_address.replace("‏", "")
```
- Strips leading/trailing whitespace, removes ALL spaces, then replaces `\n` with a space (note the order: a newline therefore becomes a *remaining* space), lowercases, removes U+200F (RTL mark).
- **Gotcha:** if `email_address` is `None`/empty-falsy, the final `.replace` is still executed → `None.replace(...)` raises `AttributeError` → **500** `{"error": "Internal error"}`. This means routes that call `sanitize_email(data.get("email"))` without a guard (register / activate / reactivate) return **500**, not 400, when `email` is missing.

### Helper: `canonicalize_email(email_address)` (`app/utils.py`)
- First `sanitize_email(...)` (same None crash applies).
- Split on `@`; if not exactly 2 parts → returns `""` (empty string).
- If domain is one of `googlemail.com`, `gmail.com`, `protonmail.com`, `proton.me`, `pm.me`: strip everything from the first `+` in the local part, remove all `.` from the local part, then `f"{first}@{domain}".lower().strip()`.
- Any other domain → returns the sanitized email unchanged.

### Password hashing — `PasswordOracle` (`app/pw_models.py`), mixed into `User`
- Column: `password` — `sa.String(128)`, nullable.
- `set_password(password)`:
  1. `password = unicodedata.normalize("NFKC", password)`
  2. `salt = bcrypt.gensalt()` (bcrypt lib default → **cost 12**, `$2b$` prefix)
  3. `self.password = bcrypt.hashpw(password.encode(), salt).decode()` — stored as the full bcrypt string, e.g. `$2b$12$...`
- `check_password(password)`:
  1. `if not self.password: return False` (users created via social login have no password)
  2. NFKC-normalize the candidate, then `bcrypt.checkpw(candidate.encode(), self.password.encode())`
- Library pin: `bcrypt ~= 3.2.0`.
- **Gotcha:** `check_password(None)` (client omitted `password`) crashes in `unicodedata.normalize` → **500** `{"error": "Internal error"}` (both for existing users and for the dummy-hash timing path).

### API key generation — `ApiKey.create` (`app/models.py`)
```python
@classmethod
def create(cls, user_id, name=None, **kwargs):
    code = random_string(60)
    if cls.get_by(code=code):
        code = str(uuid.uuid4())
    return super().create(user_id=user_id, name=name, code=code, **kwargs)
```
- `random_string(length=60)` = 60 characters chosen with `secrets.choice` from `string.ascii_lowercase` **only lowercase a–z, no digits** (the `include_digits` flag is not passed).
- On the (astronomically unlikely) collision, falls back to `str(uuid.uuid4())` (36 chars with dashes).
- Table `api_key`: `id`, `created_at` (arrow/UTC), `updated_at`, `user_id` (FK users.id, cascade), `code` (String(128), unique, not null), `name` (String(128), nullable), `last_used` (ArrowType, default None), `times` (Integer, default 0, not null), `sudo_mode_at` (ArrowType, default None). Index `ix_api_key_user_id` on `user_id`.

### Device name handling / `auth_payload(user, device)` (`app/api/views/auth.py`)
Shared by `/auth/login`, `/auth/facebook`, `/auth/google`:
```python
ret = {"name": user.name or "", "email": user.email, "mfa_enabled": user.enable_otp}
```
- If `user.enable_otp` (TOTP enabled):
  - `ret["mfa_key"] = Signer(FLASK_SECRET).sign(str(user.id))` (see MFA key format below)
  - `ret["api_key"] = None`
  - No ApiKey is created, no session login.
- Else:
  - `api_key = ApiKey.get_by(user_id=user.id, name=device)` — **device names are looked up verbatim**: `device` comes straight from the JSON body, no trimming/validation; `None` is a valid name (lookup with `name=None`). Same `(user_id, device)` pair **reuses the existing key** (no uniqueness constraint on (user_id, name); `get_by` returns the first match).
  - If none exists: `ApiKey.create(user.id, device)` + `Session.commit()`.
  - `ret["mfa_key"] = None`, `ret["api_key"] = api_key.code`
  - `login_user(user)` — Flask-Login **also sets the web session cookie** (name `slapp`, permanent, 7-day lifetime, SameSite=Lax, Secure iff URL is https) on the JSON response.
- Note `name` falls back to `""` (empty string), never null; `mfa_enabled` is a boolean.

### MFA key format (itsdangerous `Signer`, pin `itsdangerous ~= 1.1.0`)
- `s = Signer(FLASK_SECRET)`; `mfa_key = s.sign(str(user.id))`.
- itsdangerous 1.1.0 defaults: `sep="."`, `salt="itsdangerous.Signer"`, digest = **SHA1**, key derivation = **"django-concat"**:
  - `derived_key = SHA1(b"itsdangerous.Signer" + b"signer" + FLASK_SECRET)` (digest bytes)
  - `signature = base64url_no_padding(HMAC_SHA1(derived_key, value))`
  - signed value = `value + "." + signature`, e.g. `"1234.AbCdEf..."`.
- `s.sign()` returns **bytes**; it serializes to a JSON string only because the stack uses **simplejson** (installed; Flask 1.1 + itsdangerous json fall back to it), which decodes bytes as UTF-8. The client sees a plain string `"<user_id>.<sig>"`.
- Verification (`/auth/mfa`): `int(s.unsign(mfa_key))` — rsplit on the last `.`, constant-time compare of the recomputed signature; any exception (bad sig, missing `.`, non-integer payload, `None`) → 400 `"Invalid mfa_key"`.
- **No expiry**: the Signer is not a TimestampSigner — an mfa_key is valid forever (until FLASK_SECRET rotates).

### TOTP verification (pin `pyotp ~= 2.4.0`)
Used only by `/auth/mfa`:
```python
totp = pyotp.TOTP(user.otp_secret)
if not totp.verify(mfa_token, valid_window=2) or user.last_otp == mfa_token:
```
- `user.otp_secret`: `sa.String(16)` — a base32 secret (pyotp decodes with `casefold=True`).
- pyotp TOTP defaults: **30-second interval, 6 digits, HMAC-SHA1**, counter = `floor(unix_time / 30)` (pyotp 2.4 uses `datetime.datetime.now()` + `time.mktime`, i.e. server local time — servers run UTC).
- `valid_window=2` → codes for time-steps **−2 … +2** relative to now are accepted (i.e. **±60 seconds of drift**, 5 candidate codes).
- Comparison is `strings_equal(str(otp), str(generated))`: both sides NFKC-normalized, `hmac.compare_digest`. Generated code is zero-padded to 6 digits. **Gotcha:** a client sending `mfa_token` as a JSON number loses leading zeros (`012345` → `"12345"`) and fails; string tokens work.
- **Replay protection**: `user.last_otp` (`sa.String(12)`) stores the last accepted token; submitting the same token again is rejected even if still within the window. On success `user.last_otp = mfa_token; Session.commit()`.
- On failure (either wrong token OR replay): `send_invalid_totp_login_email(user, "TOTP")` — sends "Unsuccessful attempt to login to your SimpleLogin account" to `user.email`, rate-controlled to **max 1 per 24h** per (alert_type=`invalid_totp_login`, to_email) via the `sent_alert` table; skipped if `user.disabled` or `user.delete_on` set.

### Account activation code format/expiry — `AccountActivation` (`app/models.py`)
- Table `account_activation`: `id`, `created_at`, `updated_at`, `user_id` (FK users.id cascade, **unique** — one active code per user), `code` `sa.String(10)` not null, `tries` Integer default **3** not null, CHECK constraint `tries >= 0` (named `account_activation_tries_positive`).
- Code generation (identical in register & reactivate):
  `code = "".join([str(secrets.choice(string.digits)) for _ in range(6)])` — **6 decimal digits, leading zeros possible, stored/compared as a string**.
- **No expiry**: there is no expiration column or check; the code lives until used, replaced by `/auth/reactivate`, or exhausted (3 wrong tries).

---

## Route 1: `POST /api/auth/login`

```python
@api_bp.route("/auth/login", methods=["POST"])
@limiter.limit("10/minute")
def auth_login():
```

Auth: none.

Request JSON body:
| field | required | type | notes |
|---|---|---|---|
| `email` | yes (missing → 400 below) | string | sanitized + canonicalized |
| `password` | effectively yes | string | `None` → 500 (see gotcha) |
| `device` | optional | string/null | name of ApiKey to reuse/create |

Logic, in order:
1. `data` falsy → **400** `{"error": "request body cannot be empty"}`
2. `email` falsy → sends NewRelic `LoginEvent(failed, api)` → **400** `{"error": "Email or password incorrect"}`
3. `email = sanitize_email(email)`; `canonical_email = canonicalize_email(email)`
4. `user = User.get_by(email=email) or User.get_by(email=canonical_email)` (exact match on `users.email`, sanitized first then canonical)
5. `not user or not user.check_password(password)`:
   - If no user, a **dummy bcrypt check is still executed** against the fixed hash `"$2b$12$ZWqpL73h4rGNfLkJohAFAu0isqSw/bX9p/tzpbWRz/To5FAftaW8u"` (timing-attack mitigation — replicate the constant-time behavior).
   - → **400** `{"error": "Email or password incorrect"}` (+ NewRelic LoginEvent failed)
6. `user.disabled` → **400** `{"error": "Account disabled"}`
7. `user.delete_on is not None` → **400** `{"error": "Account scheduled for deletion"}`
8. `not user.activated` → **422** `{"error": "Account not activated"}`
9. `user.fido_enabled()` (i.e. `fido_uuid is not None`) **and** `not user.enable_otp` → **403** `{"error": "Currently we don't support FIDO on mobile yet"}` (users with both FIDO and TOTP may continue via TOTP)
10. Success → **200** `jsonify(**auth_payload(user, device))`:

Success body (TOTP disabled):
```json
{"name": "<user.name or ''>", "email": "<user.email>", "mfa_enabled": false, "mfa_key": null, "api_key": "<60 lowercase letters>"}
```
Success body (TOTP enabled):
```json
{"name": "<user.name or ''>", "email": "<user.email>", "mfa_enabled": true, "mfa_key": "<id>.<base64url sig>", "api_key": null}
```

Side effects: possible `ApiKey` insert; Flask session cookie (`slapp`) set via `login_user` when TOTP disabled; NewRelic custom event `LoginEvent` on every branch (`success`/`failed`/`disabled_login`/`not_activated`/`scheduled_to_be_deleted`, source `api`).

---

## Route 2: `POST /api/auth/register`

```python
@api_bp.route("/auth/register", methods=["POST"])
@limiter.limit("10/minute")
def auth_register():
```

Auth: none.

Request JSON body:
| field | required | type |
|---|---|---|
| `email` | yes (missing → **500**, see sanitize gotcha) | string |
| `password` | yes | string |

Logic, in order:
1. `data` falsy → **400** `{"error": "request body cannot be empty"}`
2. `dirty_email = data.get("email")`; `email = canonicalize_email(dirty_email)` — **the account is created under the canonical email** (gmail dots/plus stripped), but `name` is set to the raw `dirty_email`.
3. Config `DISABLE_REGISTRATION` (env presence flag) → **400** `{"error": "registration is closed"}` (+ NewRelic RegisterEvent failed)
4. `not email_can_be_used_as_mailbox(email) or personal_email_already_used(email)` → **400** `{"error": f"cannot use {email} as personal inbox"}` (email interpolated into the message; + RegisterEvent invalid_email). Helper behavior:
   - `email_can_be_used_as_mailbox`: `validate_email(email, check_deliverability=False, allow_smtputf8=False)` (python `email_validator` lib) → invalid syntax fails; then domain checks: rejected if domain is an `SLDomain` row, a **verified** `CustomDomain` row, in `invalid_mailbox_domain` table (including any parent domain suffix match), has **no MX records** (live DNS lookup, skipped if config `SKIP_MX_LOOKUP_ON_CHECK`), MX host is an invalid mailbox domain, or MX A-record IP is in `forbidden_mx_ip`; also rejected if the email belongs to a disabled user or a disabled user's mailbox.
   - `personal_email_already_used`: `User.get_by(email=email)` exists.
5. `check_if_abuser_email(email)` — HMAC-SHA256(`MAC_KEY`, lowercased address) hex digest looked up in `abuser_lookup.hashed_address` → if found: **400** `{"error": f"cannot use {email} as it was previously banned"}`
6. `not password or len(password) < 8` → **400** `{"error": "password too short"}`
7. `len(password) > 100` → **400** `{"error": "password too long"}`
8. `User.create(email=email, name=dirty_email, password=password)` — side effects (all in one transaction, committed at step 9):
   - `users` row: email re-sanitized, `name = dirty_email[:100]`, bcrypt password (see hashing above), `activated` defaults to **False**, `alternative_id = str(uuid.uuid4())`, `trial_end` default (+7 days).
   - `mailbox` row: `email=user.email`, `verified=True`; `user.default_mailbox_id = mb.id`.
   - `user_audit_log` row: action `CreateUser`, message `f"Created user {email}"`.
   - First alias created: prefix `simplelogin-newsletter` + random suffix on the default alias domain, note "This is your first alias. It's used to receive SimpleLogin communications like new features announcements, newsletters."; `user.newsletter_alias_id` set.
   - Unless config `DISABLE_ONBOARDING`: 3 `job` rows (`onboarding_1`/`onboarding_2`/`onboarding_4` JobType values) scheduled at now+1/2/3 days.
9. `AccountActivation.create(user_id=user.id, code=<6 digits>)`; `Session.commit()`.
10. Email sent to the **canonical** email: subject `"Just one more step to join SimpleLogin"`, templates `transactional/code-activation.txt.jinja2` / `transactional/code-activation.html` with `code`.
11. **200** `{"msg": "User needs to confirm their account"}` (+ RegisterEvent success)

---

## Route 3: `POST /api/auth/activate`

```python
@api_bp.route("/auth/activate", methods=["POST"])
@limiter.limit("10/minute")
def auth_activate():
```

Auth: none.

Request JSON body:
| field | required | type |
|---|---|---|
| `email` | yes (missing → **500**, sanitize gotcha) | string |
| `code` | yes | string — compared with `!=` against the stored 6-digit string; **a JSON number never matches** (int != str in Python) |

Logic, in order:
1. `data` falsy → **400** `{"error": "request body cannot be empty"}`
2. `user = User.get_by(email=sanitize_email(email)) or User.get_by(email=canonicalize_email(email))`
3. `not user or user.activated` → **400** `{"error": "Wrong email or code"}` (deliberately same message to avoid account enumeration)
4. No `AccountActivation` row for the user → **400** `{"error": "Wrong email or code"}`
5. `account_activation.code != code`:
   - `tries -= 1`; commit.
   - If `tries == 0`: delete the AccountActivation row, commit → **410** `{"error": "Too many wrong tries"}`
   - Else → **400** `{"error": "Wrong email or code"}`
6. Match: `user.activated = True`; `user_audit_log` row (action `ActivateUser`, message `f"User has been activated: {user.email}"`); delete AccountActivation; commit.
7. **200** `{"msg": "Account is activated, user can login now"}`

Note: after activation the user still has to call `/auth/login`; no api_key is returned here.

---

## Route 4: `POST /api/auth/reactivate`

```python
@api_bp.route("/auth/reactivate", methods=["POST"])
@limiter.limit("10/minute")
def auth_reactivate():
```

Auth: none.

Request JSON body: `email` (required; missing → **500** sanitize gotcha).

Logic, in order:
1. `data` falsy → **400** `{"error": "request body cannot be empty"}`
2. Lookup as in activate (sanitized then canonical).
3. `not user or user.activated` → **400** `{"error": "Something went wrong"}` (enumeration-safe message — **different string** from activate's)
4. `not user.can_send_or_receive()` (i.e. `user.disabled` or `user.delete_on is not None`) → **400** `{"error": "User is disabled"}`
5. Existing `AccountActivation` row deleted (+ commit) if present.
6. New 6-digit code created (`AccountActivation.create`, tries resets to 3), commit.
7. Same activation email as register, sent to the **sanitized** (not canonical) input email: subject `"Just one more step to join SimpleLogin"`.
8. **200** `{"msg": "User needs to confirm their account"}`

---

## Route 5: `POST /api/auth/facebook`

```python
@api_bp.route("/auth/facebook", methods=["POST"])
@limiter.limit("10/minute")
def auth_facebook():
```

Auth: none. Gated on config: `facebook_enabled()` = `FACEBOOK_CLIENT_ID and FACEBOOK_CLIENT_SECRET` — if not enabled → **400** `{"error": "invalid login mechanism"}` (checked BEFORE body parsing).

Request JSON body: `facebook_token` (Facebook access token), `device` (optional).

Logic:
1. (config gate above)
2. `data` falsy → **400** `{"error": "request body cannot be empty"}`
3. Facebook Graph API: `graph.get_object("me", fields="email,name")` using the token; `email = sanitize_email(user_info.get("email"))`. (Graph errors → uncaught → **500** `{"error": "Internal error"}`.)
4. `user = User.get_by(email=email)` (no canonicalization here).
5. If no user:
   - `DISABLE_REGISTRATION` → **400** `{"error": "registration is closed"}`
   - `not email_can_be_used_as_mailbox(email) or personal_email_already_used(email)` → **400** `{"error": f"cannot use {email} as personal inbox"}`
   - `User.create(email=email, name=user_info["name"], activated=True)` (no password; all User.create side effects as in register), commit, welcome email sent.
6. Ensure `social_auth` row `(user_id, social="facebook")` exists (create + commit if missing).
7. **200** `jsonify(**auth_payload(user, device))` — same body/side effects as login success.

---

## Route 6: `POST /api/auth/google`

```python
@api_bp.route("/auth/google", methods=["POST"])
@limiter.limit("10/minute")
def auth_google():
```

Auth: none. Gated on `google_enabled()` = `GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET` → **400** `{"error": "invalid login mechanism"}`.

Request JSON body: `google_token` (Google OAuth2 access token), `device` (optional).

Logic (mirrors facebook):
1. (config gate) 2. empty body → **400** `"request body cannot be empty"`
3. Google `oauth2/v2` `userinfo().get()` with the token; `email = sanitize_email(user_info.get("email"))`.
4. `user = User.get_by(email=email)`; if missing: `DISABLE_REGISTRATION` → **400** `"registration is closed"`; mailbox/personal check → **400** `f"cannot use {email} as personal inbox"`; else `User.create(email=email, name="", activated=True)` (note: **name is empty string**, unlike facebook), commit, welcome email.
5. Ensure `social_auth` row `(user_id, social="google")`.
6. **200** `jsonify(**auth_payload(user, device))`.

---

## Route 7: `POST /api/auth/forgot_password`

```python
@api_bp.route("/auth/forgot_password", methods=["POST"])
@limiter.limit("2/minute")
def forgot_password():
```

Auth: none. **Rate limit is 2/minute** (stricter than the others).

Request JSON body: `email` (required).

Logic:
1. `not data or not data.get("email")` → **400** `{"error": "request body must contain email"}` (note: different message from other routes; this route DOES guard against missing email).
2. Lookup by sanitized then canonical email.
3. If user found: `send_reset_password_email(user)` (`app/dashboard/views/account_setting.py`):
   - `ResetPasswordCode.create(user_id=user.id, code=secrets.token_urlsafe(32))` + commit. Table `reset_password_code`: `code` String(128) unique (token_urlsafe(32) → 43-char base64url string), `expired` ArrowType default **now + 1 hour** (`_expiration_1h`), `user_id` FK. Expiry is enforced by the web reset page, not here.
   - Email via `email_utils.send_reset_password_email` (skipped if `user.disabled`/`delete_on`): subject `"Reset your password on SimpleLogin"`, link `f"{URL}/auth/reset_password?code={code}"`.
4. **Always** (user found or not) → **200** `{"ok": true}` (via `jsonify(ok=True)`, default status 200; no enumeration possible).

---

## Route 8: `POST /api/auth/mfa`

```python
@api_bp.route("/auth/mfa", methods=["POST"])
@limiter.limit("10/minute")
@parallel_limiter.lock(name="mfa_auth")
def auth_mfa():
```

Auth: none (the `mfa_key` acts as the credential).

Concurrency lock (`app/parallel_limiter.py`): Redis `SET cl:{request.remote_addr}:mfa_auth <uuid[:10]> EX 5 NX` (keyed by remote IP because `current_user` is anonymous here); if the key already exists → `werkzeug.exceptions.TooManyRequests` → app 429 handler → **429** `{"error": "Rate limit exceeded"}`. Lock released after the request (only if it still holds its own value). No-op if the lock Redis is not configured.

Request JSON body:
| field | required | type |
|---|---|---|
| `mfa_token` | yes | string — the 6-digit TOTP code (send as string to preserve leading zeros) |
| `mfa_key` | yes | string — value returned by `/auth/login` (`"<user_id>.<sig>"`) |
| `device` | optional | string/null — ApiKey name, verbatim (same semantics as login) |

Logic, in order:
1. `data` falsy → **400** `{"error": "request body cannot be empty"}`
2. `user_id = int(Signer(FLASK_SECRET).unsign(mfa_key))`; any exception → **400** `{"error": "Invalid mfa_key"}`
3. `User.get(user_id)` missing → **400** `{"error": "Invalid mfa_key"}`
4. `not user.enable_otp` → **400** `{"error": "This endpoint should only be used by user who enables MFA"}`
5. `not pyotp.TOTP(user.otp_secret).verify(mfa_token, valid_window=2) or user.last_otp == mfa_token` → send invalid-TOTP alert email (max 1/24h, see TOTP section) → **400** `{"error": "Wrong TOTP Token"}`
6. Success: `user.last_otp = mfa_token; Session.commit()` (replay guard).
7. ApiKey lookup/create by `(user_id, name=device)` exactly as in `auth_payload`.
8. `login_user(user)` — sets the `slapp` session cookie.
9. **200**:
```json
{"name": "<user.name or ''>", "email": "<user.email>", "api_key": "<code>"}
```
Note: **no `mfa_enabled` / `mfa_key` fields** in this response (unlike login).

Note: no checks for `disabled` / `delete_on` / `activated` here — a valid, never-expiring `mfa_key` bypasses those login checks.

---

## Implementation notes for Cloudflare

### DB tables/columns touched
- `users`: read by `email` (twice per lookup: sanitized, canonical), by `id`; written: `activated`, `last_otp`, and on create: `email`, `name`, `password`, `alternative_id`, `default_mailbox_id`, `newsletter_alias_id`, `activated`, `trial_end`, flags/defaults. Relevant read columns: `password` (bcrypt string), `disabled` (bool), `delete_on` (timestamptz nullable), `activated` (bool), `enable_otp` (bool), `otp_secret` (varchar16 base32), `last_otp` (varchar12), `fido_uuid` (nullable → `fido_enabled()`), `name`, `email`.
- `api_key`: read by `(user_id, name)` and by `code`; insert `(user_id, name, code, times=0)`.
- `account_activation`: read by `user_id` (unique); insert `(user_id, code, tries=3)`; update `tries`; delete by id.
- `reset_password_code`: insert `(user_id, code, expired=now()+1h)`.
- `social_auth`: read/insert `(user_id, social)` with unique constraint `uq_social_auth`.
- `mailbox`, `alias`, `job`, `user_audit_log`, `sent_alert`, `abuser_lookup`, `sl_domain`, `custom_domain`, `invalid_mailbox_domain`, `forbidden_mx_ip`: touched via helpers as described above.
- All `ModelMixin` tables carry `id` (serial), `created_at` (ArrowType, default `arrow.utcnow`), `updated_at` (ArrowType, onupdate). ArrowType is stored as PostgreSQL `timestamp with time zone`. None of the auth responses serialize datetimes, so no arrow string format matters for these routes — but DB writes must store timezone-aware UTC timestamps.

### Python-specific behaviors to replicate exactly
1. **bcrypt** `$2b$`, cost 12, NFKC normalization of the password *before* hashing/checking. Existing hashes must keep verifying.
2. **itsdangerous 1.1.0 Signer** for `mfa_key`: key = `SHA1("itsdangerous.Signer" + "signer" + FLASK_SECRET)`, HMAC-SHA1, base64url without padding, `.` separator. Keys issued by the Python backend must verify on Workers and vice versa. No expiry.
3. **pyotp TOTP**: RFC 6238, SHA1, 30s, 6 digits, window ±2 steps, base32 secret with casefold, constant-time compare of NFKC-normalized strings; plus the `last_otp` replay rejection.
4. **API key format**: 60 lowercase a–z letters (collision fallback uuid4). Clients may not care, but keep length/charset for safety.
5. **Activation code**: 6-digit string (leading zeros allowed), 3 tries, no expiry, one per user; exact string comparison.
6. **Error strings are load-bearing** — copy verbatim, including `f"cannot use {email} as personal inbox"` with the email interpolated, and the enumeration-safe messages (`"Wrong email or code"`, `"Something went wrong"`, `"Email or password incorrect"`).
7. **Status-code oddities**: 422 for unactivated login; 410 for activation-tries exhausted; 403 for FIDO-only accounts; 429 body `{"error": "Rate limit exceeded"}`; uncaught exceptions → 500 `{"error": "Internal error"}`.
8. **Quirky 4xx/5xx mapping**: `{}` body → 400 `"request body cannot be empty"`; malformed JSON → 400 `"Bad Request"`; missing `email` on register/activate/reactivate → **500** `"Internal error"` (from `None.replace`); missing `password` on login → **500** `"Internal error"` (from NFKC-normalizing `None`). Decide consciously whether to bug-for-bug replicate the 500s (recommended for strict compatibility) — clients cannot have been relying on anything else.
9. **Session cookie side channel**: successful login (non-TOTP), google/facebook and MFA responses also `login_user()` → set the `slapp` Flask session cookie (7-day permanent, SameSite=Lax). The web app and extension rely on this for cookie-based API auth (`X-Sl-Allowcookies` header path in `app/api/base.py`). A Workers port needs a compatible session mechanism or must accept that only header auth works.
10. **JSON `null` vs absent**: login success always includes all five keys (`name`, `email`, `mfa_enabled`, `mfa_key`, `api_key`) with explicit `null`s; `/auth/mfa` success has only three keys.
11. Rate-limit keys are `ip:<addr>` (or `userid:<id>` if a session cookie authenticates the caller), limits `10/minute` everywhere except `forgot_password` `2/minute`; plus the 5-second Redis NX lock per IP on `/auth/mfa`.
12. NewRelic `LoginEvent`/`RegisterEvent` custom events are observability-only (no client-visible effect).
13. Config flags consulted: `DISABLE_REGISTRATION`, `DISABLE_ONBOARDING`, `DISABLE_RATE_LIMIT`, `SKIP_MX_LOOKUP_ON_CHECK`, `FLASK_SECRET`, `URL`, `MEM_STORE_URI`, `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET`, `FACEBOOK_CLIENT_ID`/`FACEBOOK_CLIENT_SECRET`, `MAC_KEY` (abuser HMAC), `MAX_ALERT_24H` (default alert cap; invalid-TOTP alert overrides to 1).
