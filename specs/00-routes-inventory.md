# 00 — Canonical API Routes Inventory

Source of truth: `app/api/` in the SimpleLogin Flask app (repo root `/Users/dariush/git/personal/simplelogin`).
This document inventories **all 52 `@api_bp.route` decorators** (some cover multiple HTTP methods) and specifies, exactly, how the blueprint is registered, how authentication works, and CORS behavior. Per-route request/response schemas are in the per-file specs (01+); this file is the master list.

---

## 1. Blueprint registration and URL prefix

Defined in `app/api/base.py`:

```python
api_bp = Blueprint(name="api", import_name=__name__, url_prefix="/api")
```

Registered in `simplelogin_app.py` (`register_blueprints`, line 215) with **no additional prefix**:

```python
app.register_blueprint(api_bp)
```

Therefore **every route below is served under the `/api` prefix**. E.g. `@api_bp.route("/aliases")` → `GET /api/aliases`.

`app/api/__init__.py` contains no logic — it only imports the view modules so their decorators run (module import order: `alias_options, new_custom_alias, custom_domain, new_random_alias, user_info, auth, auth_mfa, alias, apple, mailbox, notification, setting, export, phone, sudo, user`).

There is also a global `@app.before_request` (referral `?slref=` capture into session) and `@app.after_request` (request logging only, no header mutation) in `simplelogin_app.py` — neither changes API responses.

---

## 2. Authentication — `app/api/base.py` (read in full)

### 2.1 `authorize_request()` — the core auth function

Exact logic (verbatim behavior):

1. Read the raw API key from the request header **`Authentication`** (NOT `Authorization`, no `Bearer` prefix — the header value IS the key):
   ```python
   api_code = request.headers.get("Authentication")
   api_key = ApiKey.get_by(code=api_code)
   ```
2. **If no ApiKey row matches:**
   - If the request carries a valid Flask-Login **session cookie** (`current_user.is_authenticated`) **and** the request has the header **`X-Sl-Allowcookies`** (constant `constants.HEADER_ALLOW_API_COOKIES = "X-Sl-Allowcookies"`; any non-empty value works, only presence/truthiness is checked): `g.user = current_user` (cookie-based auth path, used by the web dashboard's own JS).
   - If the session cookie is **not** authenticated: return
     - **401** `{"error": "Wrong api key"}`
   - **GOTCHA (faithful-bug):** if session-authenticated but the `X-Sl-Allowcookies` header is missing, `g.user` is never assigned, and the next line `g.user.disabled` raises `AttributeError` → Flask returns a generic **500**. This is a real (buggy) behavior in the code path.
3. **If ApiKey matches:** update stats and commit **before** any other check:
   ```python
   api_key.last_used = arrow.now()
   api_key.times += 1
   Session.commit()
   g.user = api_key.user
   ```
4. `if g.user.disabled:` → **403** `{"error": "Disabled account"}`
5. `if not g.user.is_active():` → **401** `{"error": "Account does not exist"}`
   - `User.is_active()` (`app/models.py:865`): returns `True` if `delete_on is None`, else returns `delete_on < arrow.now()`. i.e. a user **scheduled for future deletion is inactive**; oddly, a user whose `delete_on` has already passed reads as active. Copy this comparison exactly.
6. On success: `g.api_key = api_key` (this is **`None` for the cookie-auth path**) and returns `None`.

### 2.2 `require_api_auth`

Decorator that calls `authorize_request()`; if it returned an error tuple, return it as the response; otherwise run the view. Sets `g.user` (User) and `g.api_key` (ApiKey or None).

### 2.3 `require_api_sudo` and sudo-mode TTL

```python
SUDO_MODE_MINUTES_VALID = 5
```

- First runs `authorize_request()` (same errors as above).
- API-key sudo check: `check_sudo_mode_is_active(api_key)` → `api_key.sudo_mode_at and api_key.sudo_mode_at >= arrow.now().shift(minutes=-5)`. So sudo is valid for **5 minutes** after `sudo_mode_at` (column on the `api_key` table).
- Cookie-session sudo fallback: `check_session_sudo_mode_is_active()` → `session["sudo_time"]` exists and `(time() - int(sudo_time)) <= 5 * 60` (unix-seconds stored in the signed session cookie, set by the web dashboard's sudo page).
- If neither: return **440** `{"error": "Need sudo"}` — **440 is a non-standard HTTP status code**; clients depend on it.

Sudo is entered via `PATCH /api/sudo` (see table): body `{"password": "..."}`; wrong/missing password → **403** `{"error": "Invalid password"}`; success sets `g.api_key.sudo_mode_at = arrow.now()` and returns **200** `{"ok": true}`.
**GOTCHA:** `enter_sudo` unconditionally does `g.api_key.sudo_mode_at = ...` — if authenticated via cookie (`g.api_key is None`) this raises `AttributeError` → 500.

Only two routes use `require_api_sudo`: `POST /api/api_key` and `DELETE /api/user`.

### 2.4 Auth summary for the Workers implementation

| Mechanism | How |
|---|---|
| Primary | header `Authentication: <api_key.code>` — plain opaque code, looked up in `api_key` table |
| Fallback | Flask session cookie + header `X-Sl-Allowcookies: <anything truthy>` |
| Side effect on every keyed request | `api_key.last_used = now`, `api_key.times += 1`, committed |
| Sudo TTL | 5 minutes (`api_key.sudo_mode_at` or session `sudo_time`) |
| Errors | 401 `{"error": "Wrong api key"}` · 403 `{"error": "Disabled account"}` · 401 `{"error": "Account does not exist"}` · 440 `{"error": "Need sudo"}` |

---

## 3. CORS

Configured globally in `simplelogin_app.py:476` using flask-cors:

```python
# enable CORS on /api endpoints
CORS(app, resources={r"/api/*": {"origins": "*"}})
```

Flask-cors defaults with this config, applied to every `/api/*` path:

- `Access-Control-Allow-Origin: *` on all responses.
- Automatic `OPTIONS` preflight handling for every `/api/*` route (flask-cors intercepts preflights): allows all standard methods of the route (`GET, HEAD, POST, OPTIONS, PUT, PATCH, DELETE`), reflects `Access-Control-Request-Headers` (default `allow_headers="*"`), no credentials support (`supports_credentials=False`, so no `Access-Control-Allow-Credentials` header), `Access-Control-Max-Age` not set by default.
- Browser extensions rely on this: the `Authentication` header must be accepted in preflight (covered by reflecting requested headers).

Note: two OAuth endpoints outside `/api` also use `@cross_origin()` (`/oauth/token`, `/oauth/userinfo`) — out of scope here.

---

## 4. Rate limiting infrastructure (applies per route below)

- flask-limiter (`app/extensions.py`), default key function: `userid:{current_user.id}` if Flask-Login-authenticated else `ip:{remote_addr}`. **API-key requests are NOT Flask-Login sessions**, so unless a route passes an explicit `key_func` (only `/aliases` and `/v2/aliases` use `key_func=lambda: g.user.id`), API-key traffic is rate-limited **by client IP**.
- Globally disabled when config `DISABLE_RATE_LIMIT` is set (`@limiter.request_filter`).
- Exceeding a limit → flask-limiter default **429** HTML/text response.
- `ALIAS_LIMIT = os.environ.get("ALIAS_LIMIT") or "100/day;50/hour;5/minute"` (`app/config.py:473`).
- `parallel_limiter.lock(name=...)` (`app/parallel_limiter.py`): Redis `SET NX` lock `cl:{current_user.id or remote_addr}:{name}` with 5-second TTL held for the duration of the request; if already locked → `werkzeug.exceptions.TooManyRequests` (**429**). No-op if the lock Redis isn't configured. Used on alias creation ("alias_creation") and MFA ("mfa_auth").

---

## 5. Route table (all 52 decorators, paths shown without the `/api` prefix)

Auth column: **auth** = `@require_api_auth`, **sudo** = `@require_api_sudo`, **none** = no auth decorator.

| # | File (`app/api/views/`) | Route (verbatim decorator path) | Methods | Auth | Rate limit / lock | Purpose |
|---|---|---|---|---|---|---|
| 1 | `alias_options.py:13` | `/v4/alias/options` | GET | auth | — | Alias-creation options: `can_create`, `prefix_suggestion`, optional `recommendation` (from `?hostname`); `suffixes` as list of `[suffix, signed_suffix]` pairs |
| 2 | `alias_options.py:77` | `/v5/alias/options` | GET | auth | — | Same as v4 but `suffixes` is a list of objects `{suffix, signed_suffix, is_custom, is_premium}` |
| 3 | `alias.py:38` | `/aliases` | GET, POST | auth | `10/minute`, key `g.user.id` | Paginated alias list (`?page_id` required int else 400); POST variant accepts JSON body `{"query": ...}` filter |
| 4 | `alias.py:81` | `/v2/aliases` | GET, POST | auth | `50/minute`, key `g.user.id` | Paginated alias list v2 (adds mailbox(es), support_pgp, latest_activity); query filters `pinned`/`disabled`/`enabled`; POST body `{"query"}` |
| 5 | `alias.py:152` | `/aliases/<int:alias_id>` | DELETE | auth | — | Delete (or move to trash) an alias |
| 6 | `alias.py:175` | `/aliases/<int:alias_id>/toggle` | POST | auth | `100/hour` | Enable/disable alias; returns `{"enabled": bool}` |
| 7 | `alias.py:206` | `/aliases/<int:alias_id>/activities` | GET | auth | `30/minute` | Paginated alias activities (`?page_id`) |
| 8 | `alias.py:263` | `/aliases/<int:alias_id>` | PUT, PATCH | auth | — | Update alias: `note`, `name`, `mailbox_id`, `mailbox_ids`, `disable_pgp`, `pinned` |
| 9 | `alias.py:354` | `/aliases/<int:alias_id>` | GET | auth | — | Get one alias (v2 serialization) |
| 10 | `alias.py:377` | `/aliases/<int:alias_id>/contacts` | GET | auth | — | Paginated contacts of an alias (`?page_id`) |
| 11 | `alias.py:413` | `/aliases/<int:alias_id>/contacts` | POST | auth | — | Create a contact (reverse alias) for the alias from `{"contact": ...}` |
| 12 | `alias.py:447` | `/contacts/<int:contact_id>` | DELETE | auth | — | Delete a contact; `{"deleted": true}` |
| 13 | `alias.py:474` | `/contacts/<int:contact_id>/toggle` | POST | auth | — | Block/unblock a contact; returns `{"block_forward": bool}` |
| 14 | `apple.py:33` | `/apple/process_payment` | POST | auth | — | Verify Apple in-app-purchase `receipt_data` (+`is_macapp`), create/extend `AppleSubscription` |
| 15 | `apple.py:65` | `/apple/update_notification` | POST | **none** | — | Apple server-to-server "Subscription Status URL" webhook; updates AppleSubscription from notification payload |
| 16 | `auth.py:35` | `/auth/login` | POST | none | `10/minute` | Email+password login; returns `{name, mfa_enabled, mfa_key, api_key}` (api_key null when MFA on); body `email, password, device` |
| 17 | `auth.py:100` | `/auth/register` | POST | none | `10/minute` | Sign up with `email, password`; sends activation-code email |
| 18 | `auth.py:163` | `/auth/activate` | POST | none | `10/minute` | Confirm account with `email, code`; 3 wrong attempts re-issues code |
| 19 | `auth.py:220` | `/auth/reactivate` | POST | none | `10/minute` | Request a new activation code for `email` |
| 20 | `auth.py:267` | `/auth/facebook` | POST | none | `10/minute` | Login/register with `facebook_token` (+`device`); 400 `{"error":"invalid login mechanism"}` unless `facebook_enabled()` |
| 21 | `auth.py:323` | `/auth/google` | POST | none | `10/minute` | Login/register with `google_token` (+`device`); gated by `google_enabled()` |
| 22 | `auth.py:403` | `/auth/forgot_password` | POST | none | `2/minute` | Send reset-password email for `email` (sanitized + canonicalized lookup) |
| 23 | `auth_mfa.py:16` | `/auth/mfa` | POST | none | `10/minute` + lock `mfa_auth` | Exchange `mfa_token` + TOTP `mfa_code` (+`device`) for `{name, api_key, email}` |
| 24 | `custom_domain.py:29` | `/custom_domains` | GET | auth | — | List user's custom domains (`{"custom_domains": [...]}`) |
| 25 | `custom_domain.py:40` | `/custom_domains/<int:custom_domain_id>/trash` | GET | auth | — | Deleted aliases of a custom domain: `{"aliases": [{alias, deletion_timestamp}]}`; 403 `{"error":"Forbidden"}` if not owner |
| 26 | `custom_domain.py:63` | `/custom_domains/<int:custom_domain_id>` | PATCH | auth | `100/hour` | Update domain: `catch_all`, `random_prefix_generation`, `name`, `mailbox_ids` |
| 27 | `export.py:9` | `/export/data` | GET | auth | — | Export JSON `{email, name, aliases:[{email,enabled}], apps:[{name,home_url}], custom_domains:[str]}` |
| 28 | `export.py:40` | `/export/aliases` | GET | auth | — | Export aliases as downloadable CSV attachment (not JSON) |
| 29 | `mailbox.py:26` | `/mailboxes` | POST | auth | `20/hour` | Create mailbox from `email` (sanitized); sends verification email; **201** with mailbox dict; errors 400 `{"error": <MailboxError.msg>}` |
| 30 | `mailbox.py:55` | `/mailboxes/<int:mailbox_id>` | DELETE | auth | `100/hour` | Delete mailbox; optional body `transfer_aliases_to` (mailbox id) |
| 31 | `mailbox.py:99` | `/mailboxes/<int:mailbox_id>` | PUT | auth | `100/hour` | Update mailbox: `default`, `email`, `cancel_email_change` |
| 32 | `mailbox.py:165` | `/mailboxes` | GET | auth | — | List **verified** mailboxes only |
| 33 | `mailbox.py:181` | `/v2/mailboxes` | GET | auth | — | List ALL mailboxes including unverified |
| 34 | `new_custom_alias.py:29` | `/v2/alias/custom/new` | POST | auth | `ALIAS_LIMIT` (`100/day;50/hour;5/minute`) + lock `alias_creation` | Create custom alias from `alias_prefix` + **`signed_suffix`** (+`mailbox_ids`, `note`, `name`, `?hostname`); **201** |
| 35 | `new_custom_alias.py:135` | `/v3/alias/custom/new` | POST | auth | `ALIAS_LIMIT` + lock `alias_creation` | Same as v2 but suffix handling via v3 contract (`alias_prefix`, `signed_suffix`, `mailbox_ids` required) |
| 36 | `new_random_alias.py:21` | `/alias/random/new` | POST | auth | `ALIAS_LIMIT` + lock `alias_creation` | Create random alias; `?mode=word|uuid`, `?hostname`, body `note`; **201** |
| 37 | `notification.py:11` | `/notifications` | GET | auth | — | Paginated notifications (`?page`, starts at 0): `{more, notifications:[{id,message,title,read,created_at}]}` |
| 38 | `notification.py:63` | `/notifications/<int:notification_id>/read` | POST | auth | — | Mark notification as read |
| 39 | `phone.py:12` | `/phone/reservations/<int:reservation_id>` | GET, POST | auth | — | SMS messages received during a phone-number reservation; 400 `{"error":"Invalid reservation"}` |
| 40 | `setting.py:34` | `/setting` | GET | auth | — | Get user settings (`setting_to_dict(user)`) |
| 41 | `setting.py:45` | `/setting` | PATCH | auth | — | Update settings: `notification`, `alias_generator` (`word|uuid`), `sender_format`, `random_alias_suffix`, `random_alias_default_domain` |
| 42 | `setting.py:112` | `/setting/domains` | GET | auth | — | Domains usable for random alias, as JSON array of `[is_sl_domain, domain]` pairs |
| 43 | `setting.py:127` | `/v2/setting/domains` | GET | auth | — | Same list as objects `{"domain": str, "is_custom": bool}` (note: `is_custom = not is_sl`) |
| 44 | `setting.py:143` | `/setting/unlink_proton_account` | DELETE | auth | — | Unlink linked Proton account; `{"ok": true}` |
| 45 | `sudo.py:9` | `/sudo` | PATCH | auth | `5/minute` | Enter sudo mode: body `{"password"}`; sets `api_key.sudo_mode_at = now`; 403 `{"error":"Invalid password"}` on failure; `{"ok": true}` |
| 46 | `user_info.py:52` | `/user_info` | GET | auth | — | User info: `name, is_premium, email, in_trial, max_alias_free, is_connected_with_proton, can_create_reverse_alias`, profile picture URL |
| 47 | `user_info.py:72` | `/user_info` | PATCH | auth | — | Update `name` and/or `profile_picture` (base64; `null` removes it; unknown image format → 400 `{"error":"Unsupported image format"}`; uploads to S3) |
| 48 | `user_info.py:111` | `/api_key` | POST | **sudo** | — | Create new API key from `{"device"}`; cleans up unused/old keys first; **201** `{"api_key": code}` |
| 49 | `user_info.py:133` | `/logout` | GET | auth | — | Log user out of the **web session** (removes cookie) |
| 50 | `user_info.py:149` | `/stats` | GET | auth | — | Aggregate stats (`nb_alias`, `nb_forward`, `nb_reply`, `nb_block`) |
| 51 | `user.py:12` | `/user` | DELETE | **sudo** | — | Schedule account deletion: audit log + `Job(name=JobType.DELETE_ACCOUNT)`; `{"ok": true}` |
| 52 | `user.py:35` | `/user/cookie_token` | GET | auth | `5/minute` | Create one-time `ApiToCookieToken` to exchange API key for a cookie session: `{"token": code}`; **401** `{"ok": false}` if authenticated via cookie (no `g.api_key`) |

Routes with GET methods where the decorator has no `methods=` argument default to **GET (+ implicit HEAD/OPTIONS)** per Flask: rows 1, 2, 7, 10, 37, 40, 42, 43, 46, 50.

Unauthenticated routes (no decorator): rows 15–23 (`/apple/update_notification` and everything under `/auth/*`). All of them except `/apple/update_notification` carry `@limiter.limit`.

---

## 6. Implementation notes for Cloudflare

**DB tables touched by the auth layer alone:** `api_key` (columns `code`, `user_id`, `last_used` (ArrowType timestamp), `times` (int), `sudo_mode_at` (ArrowType)), `users` (`disabled`, `delete_on`).

**Tables touched across routes (inventory-level):** `users`, `api_key`, `alias`, `alias_used_on`, `email_log`/activity, `contact`, `mailbox`, `custom_domain`, `domain_deleted_alias`, `deleted_alias`, `sl_domain`, `notification`, `apple_subscription`, `phone_reservation`/`phone_message`, `file` (+S3), `job`, `user_audit_log`, `api_to_cookie_token`, `activation_code`/`account_activation`, `reset_password_code`, `proton_partner` link tables.

**Gotchas the Workers implementation must reproduce:**

1. Auth header is literally **`Authentication`** (not `Authorization`). Cookie fallback requires the **`X-Sl-Allowcookies`** header.
2. `require_api_sudo` failure returns HTTP **440** (non-standard). Do not "fix" this to 403.
3. Session-authenticated request **without** `X-Sl-Allowcookies` on an API route → 500 (AttributeError on unset `g.user`), not 401. Decide consciously whether to replicate; clients today never hit the happy path there.
4. `is_active()` uses `delete_on < now` (past-deletion users read as *active*); users with a **future** `delete_on` get 401 `{"error": "Account does not exist"}`.
5. Every API-key-authenticated request performs a **write** (`last_used`, `times += 1`) — relevant for D1/read-replica design.
6. Rate limiting default key is **IP** for API-key traffic (flask-limiter only sees Flask-Login sessions); only `/aliases` & `/v2/aliases` are keyed by user id.
7. `ALIAS_LIMIT` env override: default `"100/day;50/hour;5/minute"` applied to all three alias-creation routes, plus a 5-second Redis mutex (`cl:{user_or_ip}:alias_creation`) returning 429 when contended.
8. CORS is wildcard (`*`) on `/api/*` with no credentials; preflights are auto-answered by flask-cors.
9. `PATCH /api/sudo` only works with API-key auth (`g.api_key.sudo_mode_at` write; cookie auth → 500).
10. `GET /api/export/aliases` returns a **CSV file attachment**, not JSON — the only non-JSON success response in the API.
11. `/aliases` and `/v2/aliases` accept **POST purely to pass a JSON `query` filter body**; POST does not create anything.
12. Success bodies for mailbox create, alias create (v2/v3/random) and api_key create use status **201**; everything else 200 unless stated.
13. Timestamps in responses come from ArrowType columns; e.g. `deletion_timestamp`/`creation_timestamp` are integer unix timestamps (`.timestamp`), while `creation_date` strings use arrow's default `str()` format `YYYY-MM-DD HH:mm:ssZZ` (e.g. `2026-07-05 12:34:56+00:00`). Verify per-route specs for each field.
