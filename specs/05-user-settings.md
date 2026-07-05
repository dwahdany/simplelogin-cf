# Spec 05 — User info, settings, sudo, notifications, export, phone, Apple IAP

Source files:
- `app/api/views/user_info.py`
- `app/api/views/user.py`
- `app/api/views/sudo.py`
- `app/api/views/setting.py`
- `app/api/views/notification.py`
- `app/api/views/export.py`
- `app/api/views/phone.py`
- `app/api/views/apple.py`
- Auth plumbing: `app/api/base.py`

All routes live on the blueprint `api_bp = Blueprint(name="api", import_name=__name__, url_prefix="/api")`, so every path below is served under the **`/api`** prefix (e.g. `GET /api/user_info`).

---

## 0. Authentication plumbing (`app/api/base.py`) — applies to every route below

### `authorize_request()` (used by both decorators)

Executed before the route body:

1. Read header **`Authentication`** (NOT `Authorization`). `api_code = request.headers.get("Authentication")`.
2. Look up `ApiKey.get_by(code=api_code)` (table `api_key`, column `code`).
3. **If no matching API key**:
   - If the request carries a valid, authenticated web session (flask-login `current_user.is_authenticated`) **and** the header **`X-Sl-Allowcookies`** (`constants.HEADER_ALLOW_API_COOKIES = "X-Sl-Allowcookies"`) is present with any truthy value → `g.user = current_user` (cookie-based fallback used by the web dashboard).
   - If NOT authenticated via session → `401` `{"error": "Wrong api key"}`.
   - **Gotcha (must replicate or fix deliberately):** if the user IS session-authenticated but the `X-Sl-Allowcookies` header is missing, `g.user` is never set, and the following `g.user.disabled` access raises `AttributeError` → Flask returns a generic **HTTP 500**. There is no clean error for this branch.
4. **If API key matched**: update stats — `api_key.last_used = arrow.now()`, `api_key.times += 1`, `Session.commit()` (a DB write on *every* authenticated request), then `g.user = api_key.user`.
5. `if g.user.disabled:` → `403` `{"error": "Disabled account"}`.
6. `if not g.user.is_active():` → `401` `{"error": "Account does not exist"}`. (`User.is_active()` = `delete_on is None or delete_on < now()` — note: returns True again *after* the scheduled delete time passes.)
7. `g.api_key = api_key` (may be `None` when cookie fallback was used).

### `@require_api_auth`
Runs `authorize_request()`; on error returns its error response, otherwise calls the view.

### `@require_api_sudo`
Runs `authorize_request()` first (same errors as above). Then requires sudo mode via either:
- `g.api_key.sudo_mode_at >= now() - 5 minutes` (`SUDO_MODE_MINUTES_VALID = 5`), **or**
- Web-session sudo: `session["sudo_time"]` exists and `time() - int(sudo_time) <= 5*60`.

If neither → **status `440`** (non-standard HTTP code!) with body `{"error": "Need sudo"}`.

### Rate limiter (`app/extensions.py`)
Flask-Limiter 1.5 with key function: `f"userid:{current_user.id}"` if flask-login authenticated else `f"ip:{remote_address}"`. **Gotcha:** API-key requests are NOT flask-login-authenticated, so API traffic is rate-limited by *IP*, not user. All rate limiting disabled when env `DISABLE_RATE_LIMIT` is set (`config.DISABLE_RATE_LIMIT`).

---

## 1. `app/api/views/user_info.py`

### Shared helper: `user_to_dict(user)` — the user_info response shape

```python
ret = {
    "name": user.name or "",
    "is_premium": user.is_premium(),
    "email": user.email,
    "in_trial": user.in_trial(),
    "trial_end_timestamp": user.trial_end.timestamp if user.trial_end else None,
    "max_alias_free_plan": user.max_alias_for_free_account(),
    "connected_proton_address": None,
    "can_create_reverse_alias": user.can_create_contacts(),
}
if config.CONNECT_WITH_PROTON:            # env flag "CONNECT_WITH_PROTON" present
    ret["connected_proton_address"] = get_connected_proton_address(user)
if user.profile_picture_id:
    ret["profile_picture_url"] = user.profile_picture.get_url()
else:
    ret["profile_picture_url"] = None
```

Field semantics (exact logic, from `app/models.py` User):

- **`name`**: string, `""` if user.name is NULL.
- **`is_premium`** (bool): `User.is_premium(include_partner_subscription=True)` =
  - `lifetime_or_active_subscription()` → True if `user.lifetime` flag, OR `get_active_subscription()` is not None. `get_active_subscription()` checks in order: active Paddle `Subscription` → `AppleSubscription` where `is_valid()` → `ManualSubscription` where `is_active()` → `CoinbaseSubscription` where `is_active()` → (if include_partner) active `PartnerSubscription`.
  - OR `user.trial_end and arrow.now() < user.trial_end`.
- **`in_trial`** (bool): False if `lifetime_or_active_subscription()`; else True iff `trial_end and now() < trial_end`. So a user can never be both `in_trial=True` and have a subscription; and `is_premium` is True whenever `in_trial` is True.
- **`trial_end_timestamp`**: `user.trial_end.timestamp` — arrow **0.16** property → **integer Unix seconds** (not float, not milliseconds); `null` when `trial_end` is NULL. Note trial_end may be in the past and still emit a timestamp here.
- **`max_alias_free_plan`** (int): if `user.flags & FLAG_FREE_OLD_ALIAS_LIMIT (1<<2)` set → `config.MAX_NB_EMAIL_OLD_FREE_PLAN` (env, default 15); else `config.MAX_NB_EMAIL_FREE_PLAN` (env, default 5).
- **`connected_proton_address`**: `null` unless `config.CONNECT_WITH_PROTON`; then `PartnerUser.get_by(user_id, partner_id=<proton partner id>).partner_email` or `null`. (Proton partner row looked up by `Partner.name == "Proton"` — see `app/proton/proton_partner.py`.)
- **`can_create_reverse_alias`** (bool): `can_create_contacts()` = True if premium; else True if `user.flags & FLAG_FREE_DISABLE_CREATE_CONTACTS (1<<0) == 0`; else `not config.DISABLE_CREATE_CONTACTS_FOR_FREE_USERS`.
- **`profile_picture_url`**: `File.get_url()` → `s3.get_url(file.path, expires_in=3600)`. If `config.LOCAL_FILE_UPLOAD`: `config.URL + "/static/upload/" + path`; else an S3 presigned GET URL valid 3600 s. `null` if no picture.

### `GET /api/user_info`
```python
@api_bp.route("/user_info")
@require_api_auth
```
- No params. Returns `200` with `user_to_dict(g.user)` (shape above).

### `PATCH /api/user_info`
```python
@api_bp.route("/user_info", methods=["PATCH"])
@require_api_auth
```
Body (JSON, all optional; missing body treated as `{}`):
- `profile_picture`: base64 string of image bytes, or `null` to remove the picture. Key presence checked with `"profile_picture" in data`, so:
  1. If key present and user currently has a picture: unset `user.profile_picture_id`, delete the old `File` row and its S3 object (always, even before validating the new one).
  2. If value is not null: decode with `base64.decodebytes` (accepts newlines/whitespace), validate magic number via `detect_image_format`:
     - PNG: bytes `89 50 4E 47 0D 0A 1A 0A`
     - JPG: bytes `FF D8 FF E0` (**only JFIF**; EXIF JPEGs starting `FF D8 FF E1` are rejected!)
     - WEBP: bytes `52 49 46 46` ("RIFF" — any RIFF file passes)
     - otherwise → `400` `{"error": "Unsupported image format"}` (note: old picture was already deleted at this point).
  3. On success: create `File(user_id, path=random_string(30))` — path is 30 random **lowercase ascii letters** — upload bytes to S3 under that key, set `user.profile_picture_id`.
- `name`: set verbatim (`user.name = data["name"]`), including `null` or empty string — no validation, no length check (DB column limit applies).

Response: `200` with `user_to_dict(user)` (same shape as GET). Errors: only the `400 Unsupported image format` above (invalid base64 raises → 500).

### `POST /api/api_key`
```python
@api_bp.route("/api_key", methods=["POST"])
@require_api_sudo
```
- Body required: `{}`/absent body → `400` `{"error": "request body cannot be empty"}` (note: `request.get_json()` with no/invalid JSON body → falsy → this error; in old Flask versions a non-JSON content type raises 400 by itself).
- `device`: optional string, stored as `ApiKey.name`.
- Side effects: `clean_up_unused_or_old_api_keys(user_id)` — if user has more than `config.MAX_API_KEYS` (env, default **30**) keys, deletes oldest *unused* keys (`last_used IS NULL`, oldest `created_at` first), then oldest *used* keys (oldest `last_used` first), until count ≤ 30. Then create `ApiKey` with `code = random_string(60)` (60 random lowercase letters; on collision fallback `str(uuid4())`).
- Response: **`201`** `{"api_key": "<code>"}`.

### `GET /api/logout`
```python
@api_bp.route("/logout", methods=["GET"])
@require_api_auth
```
- Logs out the *web session* (flask-login logout + purges server-side session store) and deletes the session cookie **`slapp`** (`config.SESSION_COOKIE_NAME = "slapp"`) via `Set-Cookie` expiry.
- Response: `200` `{"msg": "User is logged out"}`.

### `GET /api/stats`
```python
@api_bp.route("/stats")
@require_api_auth
```
- Response `200`, dataclass `Stats` serialized (`app/dashboard/views/index.py:get_stats`):
```json
{"nb_alias": int, "nb_forward": int, "nb_reply": int, "nb_block": int}
```
- Exact queries:
  - `nb_alias`: `count(alias where user_id = :u and delete_on is null)`
  - `nb_forward`: `count(email_log where user_id=:u and is_reply=false and blocked=false and bounced=false)`
  - `nb_reply`: `count(email_log where user_id=:u and is_reply=true and blocked=false and bounced=false)`
  - `nb_block`: `count(email_log where user_id=:u and is_reply=false and blocked=true and bounced=false)`

---

## 2. `app/api/views/user.py`

### `DELETE /api/user`
```python
@api_bp.route("/user", methods=["DELETE"])
@require_api_sudo
```
- No input.
- Side effects:
  - `emit_user_audit_log` → insert into `user_audit_log` (user_id, user_email, action=`"user_marked_for_deletion"`, message=`f"Marked user {id} ({email}) for deletion from API"`).
  - Insert `Job` row: `name="delete-account"` (`JobType.DELETE_ACCOUNT.value`), `payload={"user_id": <id>}`, `run_at=now()`, committed. Actual deletion is async via the job runner.
- Response: `200` `{"ok": true}`.

### `GET /api/user/cookie_token`
```python
@api_bp.route("/user/cookie_token", methods=["GET"])
@require_api_auth
@limiter.limit("5/minute")
```
- Requires a *real* API key: if auth happened via the cookie fallback (`g.api_key is None`) → `401` `{"ok": false}` (note: this error body has no `error` field).
- Creates `ApiToCookieToken` row (table `api_cookie_token`): `code = secrets.token_urlsafe(32)` (43-char URL-safe base64), `user_id`, `api_key_id`, committed.
- Response: `200` `{"token": "<code>"}`.
- **Consumption flow** (context; implemented in `app/auth/views/api_to_cookie.py`, `GET /auth/api_to_cookie?token=<code>&next=<url>`): token must exist and `created_at >= now() - 5 minutes`; it is single-use (row deleted), then the user is logged in via cookie and redirected to `next` (sanitized) or the dashboard. A cron job purges tokens older than 1 hour.

---

## 3. `app/api/views/sudo.py`

### `PATCH /api/sudo`
```python
@api_bp.route("/sudo", methods=["PATCH"])
@limiter.limit("5/minute")
@require_api_auth
```
- Body JSON: `password` (required).
  - Key missing → `403` `{"error": "Invalid password"}`.
  - `user.check_password(password)` fails → `403` `{"error": "Invalid password"}`. `check_password` = NFKC-normalize the input, then `bcrypt.checkpw` against `users.password`; returns False when the user has no password set (e.g. Proton-only accounts).
- Success: `g.api_key.sudo_mode_at = arrow.now()`, commit. **Gotcha:** if authenticated via cookie fallback, `g.api_key` is `None` → AttributeError → 500. Sudo via API only works with an API key.
- Response: `200` `{"ok": true}`. Sudo then valid for 5 minutes (see §0).

---

## 4. `app/api/views/setting.py`

### Shared helper: `setting_to_dict(user)` — the settings response shape

```python
{
    "notification": user.notification,                        # bool
    "alias_generator": "word" if user.alias_generator == 1 else "uuid",
    "random_alias_default_domain": user.default_random_alias_domain(),  # str
    "sender_format": SenderFormatEnum.get_name(user.sender_format) or "AT",
    "random_alias_suffix": AliasSuffixEnum.get_name(user.random_alias_suffix),
}
```

Enums (`app/models.py`) — names are the API strings, values are the DB ints:
- `AliasGeneratorEnum`: `word = 1`, `uuid = 2`. Any DB value other than 1 serializes as `"uuid"`.
- `SenderFormatEnum`: `AT = 0`, `A = 2`, `NAME_ONLY = 5`, `AT_ONLY = 6`, `NO_NAME = 7`. If the stored int has no enum name, GET returns `"AT"` (fallback in comment: "return the default sender format (AT) in case user uses a non-supported sender format").
- `AliasSuffixEnum`: `word = 0`, `random_string = 1`. No fallback → unknown value would serialize `null`.

`default_random_alias_domain()`:
- If `user.default_alias_custom_domain_id` set: load that CustomDomain; if missing/unverified/not owned → return `config.FIRST_ALIAS_DOMAIN` (env `FIRST_ALIAS_DOMAIN` or `EMAIL_DOMAIN`); else its `domain`.
- Else if `user.default_alias_public_domain_id` set: load SLDomain; if missing → `FIRST_ALIAS_DOMAIN`; if `premium_only` and user not premium → **side effect**: resets both default-domain columns to NULL and commits, returns `FIRST_ALIAS_DOMAIN`; else its `domain`.
- Else `FIRST_ALIAS_DOMAIN`.

### `GET /api/setting`
```python
@api_bp.route("/setting")
@require_api_auth
```
- Response `200`: `setting_to_dict(user)` (shape above).

### `PATCH /api/setting`
```python
@api_bp.route("/setting", methods=["PATCH"])
@require_api_auth
```
Body JSON, every field optional (missing body → `{}`); fields processed in this order:
- `notification`: assigned verbatim to `user.notification` (bool expected; no validation).
- `alias_generator`: must be `"word"` or `"uuid"` else `400` `{"error": "Invalid alias_generator"}`. Stores 1 / 2.
- `sender_format`: must be one of the enum **names** `"AT" | "A" | "NAME_ONLY" | "AT_ONLY" | "NO_NAME"` else `400` `{"error": "Invalid sender_format"}`. Stores the int and sets `user.sender_format_updated_at = arrow.now()`.
- `random_alias_suffix`: must be `"word"` or `"random_string"` else `400` `{"error": "Invalid random_alias_suffix"}`. Stores 0 / 1.
- `random_alias_default_domain` (string domain):
  1. Try `SLDomain.get_by(domain=...)`. If found: if `premium_only` and `not user.is_premium()` → `400` `{"error": "You cannot use this domain"}`; else set `user.default_alias_public_domain_id = sl_domain.id` and `user.default_alias_custom_domain_id = None`.
  2. Else try `CustomDomain.get_by(domain=...)`; not found → `400` `{"error": "invalid domain"}` (lowercase!). Found but `custom_domain.user_id != user.id or not custom_domain.verified` → same `400` `{"error": "invalid domain"}`. Else set `user.default_alias_custom_domain_id = custom_domain.id`, `user.default_alias_public_domain_id = None`.
- Note: error returns happen mid-processing, so earlier fields in the same request are assigned on the ORM object but **not committed** (function returns before `Session.commit()`; SimpleLogin wraps requests so uncommitted changes roll back).
- Response `200`: `setting_to_dict(user)`.

### `GET /api/setting/domains` (v1)
```python
@api_bp.route("/setting/domains")
@require_api_auth
```
- Response `200`: JSON **array of 2-element arrays** `[[is_sl: bool, domain: string], ...]` (Python tuples serialize as arrays), e.g. `[[true, "simplelogin.io"], [false, "my-domain.com"]]`.
- Source `user.available_domains_for_random_alias()`:
  - SL domains first: `get_sl_domains()` = `SLDomain` where `hidden = false` AND (`id = user.default_alias_public_domain_id` [premium_only allowed only if premium] OR (`partner_id IS NULL` AND (`premium_only = false` unless user premium))), ordered by `SLDomain.order` — marked `is_sl = true`.
  - Then custom domains: `verified_custom_domains()` = `CustomDomain` where `user_id = :u AND ownership_verified = true`, ordered by `domain` ASC — marked `is_sl = false`. (**Note the asymmetry**: listing filters on `ownership_verified`, but PATCH validation checks `verified`.)

### `GET /api/v2/setting/domains`
```python
@api_bp.route("/v2/setting/domains")
@require_api_auth
```
- Same source list; response `200`: array of objects `[{"domain": string, "is_custom": bool}, ...]` where `is_custom = not is_sl`.

### `DELETE /api/setting/unlink_proton_account`
```python
@api_bp.route("/setting/unlink_proton_account", methods=["DELETE"])
@require_api_auth
```
- Calls `perform_proton_account_unlink(user)`:
  - Returns `None` (falsy) if `user.flags & FLAG_CREATED_FROM_PARTNER (1<<1)` is set (account created *by* Proton cannot be unlinked) → route returns `400` `{"error": "The account cannot be unlinked"}`.
  - Otherwise looks up the PartnerUser row for the Proton partner; if present: writes `user_audit_log` (action `"unlink_account"`), dispatches a `UserUnlinked` sync event, deletes the `partner_user` row, commits; returns `partner_user.external_user_id` (truthy string). **Gotcha:** if the user was never linked (`partner_user is None`) the helper hits `partner_user.external_user_id` on `None` → AttributeError → **500** (not a clean 400).
- Success: `200` `{"ok": true}`.

---

## 5. `app/api/views/notification.py`

### `GET /api/notifications`
```python
@api_bp.route("/notifications", methods=["GET"])
@require_api_auth
```
- Query param `page` (int, 0-based, **required**): parsed with `int(request.args.get("page"))`; missing or non-int → `400` `{"error": "page must be provided in request query"}`.
- Query: `notification where user_id = :u ORDER BY read ASC, created_at DESC LIMIT 21 OFFSET page*20` — i.e. **unread first**, newest first within each group. `PAGE_LIMIT = 20` (`app/config.py`, hardcoded); one extra row is fetched to compute `more`.
- Response `200`:
```json
{
  "more": bool,
  "notifications": [
    {"id": int, "message": str, "title": str|null, "read": bool, "created_at": "5 minutes ago"},
    ...
  ]
}
```
- `created_at` is **arrow's `humanize()`** output in English, relative to now — e.g. `"just now"`, `"5 minutes ago"`, `"an hour ago"`, `"2 days ago"`, `"a month ago"` (arrow 0.16 default locale "en"). NOT a timestamp. `message` may contain HTML (rendered from templates).

### `POST /api/notifications/<int:notification_id>/read`
```python
@api_bp.route("/notifications/<int:notification_id>/read", methods=["POST"])
@require_api_auth
```
- Path param `notification_id` (int). No body.
- Not found OR belongs to another user → `403` `{"error": "Forbidden"}` (same response for both; no 404).
- Success: sets `read = true`, commits; `200` `{"done": true}`.

---

## 6. `app/api/views/export.py`

### `GET /api/export/data`
```python
@api_bp.route("/export/data", methods=["GET"])
@require_api_auth
```
- Response `200`:
```json
{
  "email": str,
  "name": str|null,
  "aliases": [{"email": str, "enabled": bool}, ...],
  "apps": [{"name": str, "home_url": str|null}, ...],
  "custom_domains": [str, ...]
}
```
- `aliases` includes ALL aliases (`Alias.filter_by(user_id=...)` — **no `delete_on` filter**, unlike the CSV export); `custom_domains` are bare domain strings (verified or not); `apps` are the user's OAuth `Client` rows. Insertion order in the response dict is `email, name, aliases, apps, custom_domains`; arrays are in default (unordered) query order.
- Note `name` here is raw (`null` possible), unlike `/user_info` which coerces to `""`.

### `GET /api/export/aliases`
```python
@api_bp.route("/export/aliases", methods=["GET"])
@require_api_auth
```
- Returns a **CSV file**, not JSON. `alias_export_csv(user)` (`app/alias_utils.py`):
  - Header row exactly: `alias,note,enabled,mailboxes`
  - One row per alias where `user_id = :u AND delete_on IS NULL`: `[alias.email, alias.note, alias.enabled, mailboxes]`.
    - `note`: raw text (empty string when NULL; csv-quoted if it contains commas/newlines).
    - `enabled`: Python `str(bool)` → literal **`True`** / **`False`** (capitalized!).
    - `mailboxes`: space-joined mailbox emails, with the alias's **primary mailbox first**. Source list is `alias.mailboxes` property = `[alias.mailbox] + alias._mailboxes` (m2m via `alias_mailbox`), filtered to `verified=true`, sorted by email ASC; the export then moves `alias.mailbox` to index 0 (`list.index` + pop/insert). **Gotcha:** if the primary mailbox is unverified it's filtered out and `.index()` raises ValueError → 500.
  - Written with Python `csv.writer` defaults: `\r\n` line terminator, `"` quoting only when needed.
- Response headers: `Content-Disposition: attachment; filename=aliases.csv`, `Content-type: text/csv`. Status `200`.

---

## 7. `app/api/views/phone.py`

### `GET|POST /api/phone/reservations/<int:reservation_id>`
```python
@api_bp.route("/phone/reservations/<int:reservation_id>", methods=["GET", "POST"])
@require_api_auth
```
- Both methods behave identically (POST does nothing extra).
- `PhoneReservation.get(reservation_id)`; missing or `reservation.user_id != user.id` → `400` `{"error": "Invalid reservation"}`.
- Query: `phone_message where number_id = :reservation.number_id AND created_at > reservation.start AND created_at < reservation.end` (strict inequalities; no ordering specified).
- Response `200`:
```json
{
  "ended": bool,               // reservation.end < arrow.now()
  "messages": [
    {"id": int, "from_number": str, "body": str|null, "created_at": "5 minutes ago"},
    ...
  ]
}
```
- `created_at` is arrow `humanize()` (same relative-English format as notifications).
- Tables: `phone_reservation` (number_id, user_id, start, end), `phone_message` (number_id, from_number, body), `phone_number`.

---

## 8. `app/api/views/apple.py`

Product-id constants:
```python
_MONTHLY_PRODUCT_ID = "io.simplelogin.ios_app.subscription.premium.monthly"
_YEARLY_PRODUCT_ID = "io.simplelogin.ios_app.subscription.premium.yearly"
_MACAPP_MONTHLY_PRODUCT_ID = "io.simplelogin.macapp.subscription.premium.monthly"
_MACAPP_YEARLY_PRODUCT_ID = "io.simplelogin.macapp.subscription.premium.yearly"
_MACAPP_MONTHLY_PRODUCT_ID_NEW = "me.proton.simplelogin.macos.premium.monthly"
_MACAPP_YEARLY_PRODUCT_ID_NEW = "me.proton.simplelogin.macos.premium.yearly"
_SANDBOX_URL = "https://sandbox.itunes.apple.com/verifyReceipt"
_PROD_URL = "https://buy.itunes.apple.com/verifyReceipt"
```

### `POST /api/apple/process_payment`
```python
@api_bp.route("/apple/process_payment", methods=["POST"])
@require_api_auth
```
- Body JSON: `receipt_data` (string, App Store receipt), `is_macapp` (optional; only `true` exactly counts: `"is_macapp" in data and data["is_macapp"] is True`).
- Chooses shared secret: `config.MACAPP_APPLE_API_SECRET` if is_macapp else `config.APPLE_API_SECRET`.
- Runs `verify_receipt(receipt_data, user, password)` (summary below). On success also calls `execute_subscription_webhook(user)` (dispatches a `UserPlanChanged` sync event with `plan_end_time` = subscription-end Unix timestamp, excludes partner subs; commits).
- Success → `200` `{"ok": true}`. Any failure → `400` `{"error": "Processing failed"}`.

**`verify_receipt` flow (summary):** POST `{"receipt-data": <receipt_data>, "password": <secret>}` to the production verifyReceipt URL; on network error or 5xx → fail. If the response is exactly `{"status": 21007}` retry against the sandbox URL. Fail unless `data["status"] == 0`. Take `data["latest_receipt_info"]` (fail if empty); pick the transaction with the max `int(expires_date_ms)`; derive `expires_date = arrow.get(int(expires_date_ms)/1000)` and `plan` = `PlanEnum.monthly (2)` if `product_id` is one of the three monthly ids else `PlanEnum.yearly (3)`. Then upsert `apple_subscription`: if the user already has a row, update `receipt_data`, `expires_date`, `original_transaction_id`, `product_id`, `plan`; else, if another account already owns this `original_transaction_id` → fail (prevents receipt reuse across accounts); else create the row. Fires the subscription webhook and commits. Returns the AppleSubscription or None.

### `POST /api/apple/update_notification` — **NO auth decorator** (public webhook for Apple)
```python
@api_bp.route("/apple/update_notification", methods=["POST"])
```
- Body: Apple App Store server notification (v1 style). Uses `unified_receipt.latest_receipt_info` (NOT `latest_expired_receipt_info`).
- Auth-by-secret: if `config.APPLE_WEBHOOK_SECRET_CHECK_ENABLED` (env-flag presence) and (`data` missing, or `data["password"]` missing, or `data["password"]` not in (`APPLE_API_SECRET`, `MACAPP_APPLE_API_SECRET`)) → `401` `{"error": "Unauthorized"}`.
- If `data.unified_receipt.latest_receipt_info` missing/empty → `400` `{"error": "Empty Response"}`.
- Groups transactions by `original_transaction_id`, keeping the one with the largest `expires_date_ms` per group. **Gotcha:** the comparison is `transaction["expires_date_ms"] > latest[...]["expires_date_ms"]` — a **string comparison** (values are strings), which is only correct while all values have equal digit length.
- Then iterates `latest_transactions.items()` but **returns inside the first iteration** either way (processes only one original_transaction_id):
  - Looks up `AppleSubscription.get_by(original_transaction_id=...)`. If found: update `receipt_data = data["unified_receipt"]["latest_receipt"]`, `expires_date = arrow.get(int(expires_date_ms)/1000)`, `plan` (monthly/yearly per product-id lists), `product_id`; commit; fire subscription webhook; → `200` `{"ok": true}`.
  - If not found → `400` `{"error": "Processing failed"}`.
- **Gotcha:** if `latest_transactions` ends up empty the function falls through and returns `None` → Flask 500. Also note there is no `200` fallback after the loop.

---

## Route inventory (20 routes)

| # | Method(s) | Path (under /api) | Auth |
|---|-----------|-------------------|------|
| 1 | GET | /user_info | require_api_auth |
| 2 | PATCH | /user_info | require_api_auth |
| 3 | POST | /api_key | require_api_sudo |
| 4 | GET | /logout | require_api_auth |
| 5 | GET | /stats | require_api_auth |
| 6 | DELETE | /user | require_api_sudo |
| 7 | GET | /user/cookie_token | require_api_auth + `5/minute` |
| 8 | PATCH | /sudo | require_api_auth + `5/minute` |
| 9 | GET | /setting | require_api_auth |
| 10 | PATCH | /setting | require_api_auth |
| 11 | GET | /setting/domains | require_api_auth |
| 12 | GET | /v2/setting/domains | require_api_auth |
| 13 | DELETE | /setting/unlink_proton_account | require_api_auth |
| 14 | GET | /notifications | require_api_auth |
| 15 | POST | /notifications/&lt;int:notification_id&gt;/read | require_api_auth |
| 16 | GET | /export/data | require_api_auth |
| 17 | GET | /export/aliases | require_api_auth |
| 18 | GET, POST | /phone/reservations/&lt;int:reservation_id&gt; | require_api_auth |
| 19 | POST | /apple/process_payment | require_api_auth |
| 20 | POST | /apple/update_notification | none (secret in body) |

---

## Implementation notes for Cloudflare

### DB tables/columns touched
- **users**: `name, email, disabled, delete_on, lifetime, trial_end, flags (bitmask: 1=FREE_DISABLE_CREATE_CONTACTS, 2=CREATED_FROM_PARTNER, 4=FREE_OLD_ALIAS_LIMIT, 8=CREATED_ALIAS_FROM_PARTNER), profile_picture_id, notification, alias_generator, sender_format, sender_format_updated_at, random_alias_suffix, default_alias_public_domain_id, default_alias_custom_domain_id, password (bcrypt, NFKC-normalized input)`
- **api_key**: `code (unique), name, user_id, last_used, times, sudo_mode_at, created_at` — read+written on every API-key request.
- **api_cookie_token**: `code (unique), user_id, api_key_id, created_at`.
- **file**: `path (unique), user_id` + S3/R2 object storage (`get_url` presigned 3600 s, upload, delete).
- **partner_user** (`user_id, partner_id, partner_email, external_user_id`), **partner** (Proton lookup by name).
- **subscription** (Paddle), **apple_subscription** (`user_id, receipt_data, expires_date, original_transaction_id (unique-ish per account), product_id, plan`), **manual_subscription**, **coinbase_subscription**, **partner_subscription** — all consulted by `is_premium()`.
- **sl_domain**: `domain, premium_only, hidden, order, partner_id`.
- **custom_domain**: `domain (unique), user_id, verified, ownership_verified`.
- **notification**: `user_id, message, title, read, created_at`.
- **alias**: `email, note, enabled, user_id, delete_on, mailbox_id` + **alias_mailbox** m2m + **mailbox** (`email, verified`).
- **client**: `name, home_url, user_id`.
- **email_log**: `user_id, is_reply, blocked, bounced` (stats counts).
- **job**: `name, payload (json), run_at` — account deletion is queued, not synchronous.
- **user_audit_log**: `user_id, user_email, action, message`.
- **phone_reservation**, **phone_message**, **phone_number**.
- **sync_event** (via EventDispatcher for UserUnlinked / UserPlanChanged protobuf events).

### Python-specific behaviors to replicate
- **arrow 0.16** is pinned. `arrow_obj.timestamp` is a **property returning an int** (Unix seconds) — used for `trial_end_timestamp` and the subscription webhook. Do not emit floats or ms.
- `humanize()` strings ("just now", "x minutes ago", "an hour ago", "2 days ago", …) are arrow's English humanize — clients display them verbatim; replicate with an equivalent relative-time formatter (thresholds: seconds<45→"just now"/"seconds ago", singular forms "a minute/an hour/a day/a month/a year ago").
- All timestamps stored via `ArrowType` are timezone-aware UTC (`arrow.utcnow` default for `created_at`).
- Header names: auth is **`Authentication`**; cookie-fallback opt-in is **`X-Sl-Allowcookies`**; session cookie name **`slapp`**.
- Non-standard **HTTP 440** for "Need sudo".
- Flask `jsonify` on a Python tuple list (v1 `/setting/domains`) yields nested JSON arrays.
- CSV booleans serialize as `True`/`False` (capitalized), csv lines end `\r\n`.
- `base64.decodebytes` tolerates embedded newlines; strict base64 decoders may need a lenient mode.
- bcrypt password check with **NFKC** unicode normalization of the input first.
- Error-body inconsistencies are load-bearing: `{"ok": false}` (cookie_token 401) vs `{"error": ...}` elsewhere; `"invalid domain"` lowercase vs `"Invalid alias_generator"` capitalized; notifications 403 uses `"Forbidden"` for both missing and not-owned.
- Config flags consulted: `CONNECT_WITH_PROTON` (presence flag), `MAX_NB_EMAIL_FREE_PLAN` (default 5), `MAX_NB_EMAIL_OLD_FREE_PLAN` (default 15), `DISABLE_CREATE_CONTACTS_FOR_FREE_USERS`, `LOCAL_FILE_UPLOAD`, `URL`, `FIRST_ALIAS_DOMAIN`, `MAX_API_KEYS` (default 30), `PAGE_LIMIT` (=20), `SESSION_COOKIE_NAME` (="slapp"), `DISABLE_RATE_LIMIT` (presence flag), `APPLE_API_SECRET`, `MACAPP_APPLE_API_SECRET`, `APPLE_WEBHOOK_SECRET_CHECK_ENABLED` (presence flag).
- Rate limits: `5/minute` on `PATCH /sudo` and `GET /user/cookie_token`; key is `ip:<addr>` for API-key traffic (no flask-login user), `userid:<id>` for cookie traffic.
- Known 500-paths (bug-compatible or fix consciously): cookie session without `X-Sl-Allowcookies` header; `PATCH /sudo` via cookie auth (`g.api_key is None`); unlink_proton_account when never linked; CSV export when an alias's primary mailbox is unverified; apple update_notification falling through the loop; invalid base64 in `profile_picture`.
