# Spec 04 — Mailbox & Custom Domain API

Source files:
- `app/api/views/mailbox.py` (5 routes)
- `app/api/views/custom_domain.py` (3 routes)

Shared helpers referenced (behavior documented inline below):
- `app/api/base.py` (`require_api_auth`, `authorize_request`)
- `app/mailbox_utils.py` (`create_mailbox`, `delete_mailbox`, `request_mailbox_email_change`, `cancel_email_change`, `check_email_for_mailbox`, `generate_activation_code`, `send_verification_email`, `send_change_email`, `verify_mailbox_code`, `count_mailbox_aliases`, `MailboxError`)
- `app/email_utils.py` (`mailbox_already_used`, `email_can_be_used_as_mailbox_with_reason`, `check_domain_for_mailbox`, `is_invalid_mailbox_domain`, `EmailCannotBeUsedReason`)
- `app/email_validation.py` (`is_valid_email`)
- `app/utils.py` (`sanitize_email`)
- `app/custom_domain_utils.py` (`set_custom_domain_mailboxes`, `count_custom_domain_aliases`)
- `job_runner.py` (`delete_mailbox_job` — async mailbox deletion)

All routes live on the Flask blueprint `api_bp = Blueprint(name="api", import_name=__name__, url_prefix="/api")`, so the externally visible paths are **prefixed with `/api`** (e.g. `POST /api/mailboxes`).

---

## 1. Authentication — `@require_api_auth` (app/api/base.py)

Every route in both files uses `@require_api_auth`. None use `@require_api_sudo`.

`authorize_request()` logic, in order:

1. Read header `Authentication` (NOT `Authorization`). Look up `ApiKey.get_by(code=<header value>)`.
2. If no ApiKey found:
   - If the request carries a valid Flask-Login session cookie (`current_user.is_authenticated`) **and** the request has header `X-Sl-Allowcookies` (constant `HEADER_ALLOW_API_COOKIES = "X-Sl-Allowcookies"`, any non-empty value): use the cookie user (`g.user = current_user`).
   - If not session-authenticated: return **401** `{"error": "Wrong api key"}`.
   - Edge case (faithful reproduction): if session-authenticated but the `X-Sl-Allowcookies` header is missing, `g.user` is never set and the following `g.user.disabled` access raises `AttributeError` → Flask returns a **500**. Do not silently turn this into a 401.
3. If ApiKey found: update stats — `api_key.last_used = arrow.now()`, `api_key.times += 1`, commit. Set `g.user = api_key.user`.
4. If `g.user.disabled` (boolean column on `users`): return **403** `{"error": "Disabled account"}`.
5. If not `g.user.is_active()` (`user.delete_on is None or user.delete_on < now`; i.e. inactive when `delete_on` is set and in the future): return **401** `{"error": "Account does not exist"}`.
6. `g.api_key = api_key` (may be `None` for cookie auth) and proceed.

## 2. Rate limiting (app/extensions.py)

`limiter = Limiter(key_func=__key_func)` where the key is:
- `f"userid:{current_user.id}"` if Flask-Login session-authenticated,
- else `f"ip:{remote_address}"`.

IMPORTANT: for pure API-key requests there is no Flask-Login session, so the limiter key is the **client IP**, not the user. Rate limiting is disabled entirely when config `DISABLE_RATE_LIMIT` is true. Limits are declared per-route below. When a limit is exceeded Flask-Limiter returns HTTP 429.

## 3. Serializers

### `mailbox_to_dict(mailbox)` (app/api/views/mailbox.py)

```python
{
    "id": mailbox.id,                                        # int
    "email": mailbox.email,                                  # str
    "verified": mailbox.verified,                            # bool
    "default": mailbox.user.default_mailbox_id == mailbox.id,# bool
    "creation_timestamp": mailbox.created_at.timestamp,      # int (unix seconds, arrow 0.16 property)
    "nb_alias": mailbox.nb_alias(),                          # int
}
```

`mailbox.nb_alias()` → `count_mailbox_aliases(mailbox)`: size of the union of
- `alias_id` from `alias_mailbox` rows with `mailbox_id = mailbox.id` where the alias is **not trashed** (`alias.delete_on is not None` means trashed), plus
- `Alias.id` where `alias.mailbox_id = mailbox.id AND alias.delete_on IS NULL`.

### `custom_domain_to_dict(custom_domain)` (app/api/views/custom_domain.py)

```python
{
    "id": custom_domain.id,                                   # int
    "domain_name": custom_domain.domain,                      # str
    "is_verified": custom_domain.verified,                    # bool (MX verified)
    "nb_alias": custom_domain.nb_alias(),                     # int
    "creation_date": custom_domain.created_at.format(),       # str, arrow default format (see §12)
    "creation_timestamp": custom_domain.created_at.timestamp, # int (unix seconds)
    "catch_all": custom_domain.catch_all,                     # bool
    "name": custom_domain.name,                               # str | null
    "random_prefix_generation": custom_domain.random_prefix_generation,  # bool
    "mailboxes": [ {"id": mb.id, "email": mb.email} for mb in custom_domain.mailboxes ],
}
```

- `custom_domain.nb_alias()` → `Alias.filter_by(custom_domain_id=cd.id, delete_on=None).count()` (trashed aliases excluded).
- `custom_domain.mailboxes` property: mailboxes linked via `domain_mailbox` join table; **if there are no `domain_mailbox` rows, it returns `[user.default_mailbox]`** (the user's default mailbox), so the `mailboxes` array is never empty.

---

## 4. `POST /api/mailboxes` — create mailbox

```python
@api_bp.route("/mailboxes", methods=["POST"])
@limiter.limit("20/hour")
@require_api_auth
def create_mailbox():
```

Request JSON body:
- `email` (str, required).

Flow:
1. `email = request.get_json().get("email")` — if the body is not JSON, Flask's `get_json()` raises (415/400 HTML error). If `email` missing/empty/falsy → **400** `{"error": "Invalid email"}`.
2. `mailbox_email = sanitize_email(email)` (see §10).
3. `mailbox_utils.create_mailbox(user, mailbox_email)` with defaults `verified=False, send_email=True, use_digit_codes=False, send_link=True`:
   - Re-runs `sanitize_email`.
   - If `not user.is_premium()` (no lifetime deal, no active subscription, not in trial) → raise `OnlyPaidError` → **400** `{"error": "Only available for paid plans"}`.
   - `check_email_for_mailbox(email, user)` (see §11) — raises `MailboxError` → **400** `{"error": "<msg>"}` with one of the exact strings listed in §11.
   - `Mailbox.create(email=email, user_id=user.id, verified=False, commit=True)` — INSERT into `mailbox`. (Note: DB has unique constraint `uq_mailbox_user (user_id, email)`.)
   - `emit_user_audit_log(action=CreateMailbox, message=f"Create mailbox {id} ({email}). Verified=False", commit=True)` — INSERT into user audit log table.
   - `generate_activation_code(new_mailbox, use_digit_code=False)`:
     - Deletes ALL existing `mailbox_activation` rows for this mailbox.
     - Code = `secrets.token_urlsafe(16)` (22-char URL-safe base64 string). (The 6-digit code path and `MAILBOX_VERIFICATION_OVERRIDE_CODE` config are only used when `use_digit_codes=True`, which the API never does — that's the dashboard/Proton path.)
     - INSERT `mailbox_activation` row `(mailbox_id, code, tries=0)`.
   - `send_verification_email(user, mailbox, activation, send_link=True)`:
     - To: the new mailbox address.
     - Subject: `f"Please confirm your mailbox {mailbox.email}"`.
     - Templates: `transactional/verify-mailbox.txt.jinja2` / `.html` with `code` and `link`.
     - Link: `config.URL + "/dashboard/mailbox_verify" + f"?mailbox_id={mailbox.id}&code={activation.code}"`.
     - If SMTP rejects the recipient (`SMTPRecipientsRefused`), this is **NOT caught** in this route → 500. (Contrast with PUT below.)
4. Success: **201** with `mailbox_to_dict(new_mailbox)` at the TOP LEVEL (not wrapped): `{"id":…, "email":…, "verified": false, "default":…, "creation_timestamp":…, "nb_alias": 0}`.

Verification itself does NOT happen through this API surface — the user clicks the dashboard link (`GET /dashboard/mailbox_verify?mailbox_id=…&code=…`). `verify_mailbox_code` semantics (needed if you re-implement the dashboard flow): only the most recent activation row is checked; max 3 tries (`MAX_ACTIVATION_TRIES = 3`, exceeding clears codes and errors `"Invalid activation code. Please request another code."`); codes older than 15 minutes are invalid (cleared, same message); wrong code increments `tries` and errors `"Invalid activation code"`; success sets `mailbox.verified = True` (or applies pending `new_email` change), emits audit log, and deletes all activation rows.

Errors summary (all JSON `{"error": <msg>}`):
| Status | Message |
|---|---|
| 400 | `Invalid email` (missing/empty body field, or invalid syntax via `check_email_for_mailbox`) |
| 400 | `Only available for paid plans` |
| 400 | `Email already used` |
| 400 | `Invalid email: <EmailCannotBeUsedReason.value>` (see §11 for the 8 exact strings) |
| 429 | rate limit (20/hour per key, see §2) |

## 5. `DELETE /api/mailboxes/<int:mailbox_id>` — delete mailbox

```python
@api_bp.route("/mailboxes/<int:mailbox_id>", methods=["DELETE"])
@limiter.limit("100/hour")
@require_api_auth
def delete_mailbox(mailbox_id):
```

Request JSON body (optional; `request.get_json() or {}` — a missing/empty body is fine, but a non-JSON content type with a body still errors via Flask):
- `transfer_aliases_to` (optional, int): id of the mailbox to move this mailbox's aliases to. If omitted, `-1`, `0`, `null`, or any falsy value → aliases are deleted along with the mailbox.

Flow:
1. `Mailbox.get(mailbox_id)`; if not found or `mailbox.user_id != user.id` → **403** `{"error": "Forbidden"}`.
2. If `mailbox.is_admin_disabled()` (`mailbox.flags & 1`) → **400** `{"error": "This mailbox has been disabled and cannot be deleted. Please contact support."}`.
3. Parse transfer target: `transfer_mailbox_id = data.get("transfer_aliases_to")`; if truthy AND `int(value) >= 0` → use `int(value)`, else `None`. Note: a non-numeric string raises `ValueError` → 500. `0` (int) is falsy → treated as `None`; `"0"` (string) is truthy and `>= 0` → transfer target id 0 → lookup fails → error below.
4. `mailbox_utils.delete_mailbox(user, mailbox_id, transfer_mailbox_id)` — raises `MailboxError` → **400** `{"error": "<msg>"}`:
   - not found / other user's mailbox → `Invalid mailbox` (unreachable via this route in practice; route already checked)
   - `mailbox.id == user.default_mailbox_id` → `Cannot delete your default mailbox`
   - transfer mailbox not found or owned by another user → `You must transfer the aliases to a mailbox you own`
   - transfer mailbox == mailbox being deleted → `You can not transfer the aliases to the mailbox you want to delete`
   - transfer mailbox not verified → `Your new mailbox is not verified`
5. On success the helper does **NOT delete anything synchronously**. It creates a `job` row: `Job.create(name="delete-mailbox", payload={"mailbox_id": <id>, "transfer_mailbox_id": <id or null>, "send_mail": true}, run_at=arrow.now(), commit=True)`. The mailbox continues to exist (and appears in GET /v2/mailboxes) until the job runner processes it.
6. Response: **200** `{"deleted": true}`.

Async job semantics (`job_runner.py::delete_mailbox_job`) — must be reproduced for behavioral parity:
- If `transfer_mailbox_id` set and that mailbox still exists: for every alias attached to the deleted mailbox — if `alias.mailbox_id == mailbox.id` (primary), set `alias.mailbox_id = transfer_mailbox.id` and remove the transfer mailbox from `alias_mailbox` secondary links if present (avoid dup); else (mailbox is only a secondary link) remove the secondary link and add the transfer mailbox as secondary if not already present.
- Emits user audit log `DeleteMailbox` with message `f"Delete mailbox {mailbox.id} ({mailbox.email})"`.
- `Mailbox.delete(mailbox_id)` (custom classmethod): for each remaining alias with `alias.mailbox_id == mailbox_id`: if the alias has >1 mailboxes, promote the first secondary mailbox to primary; else delete the alias immediately (if user setting `alias_delete_action == DeleteImmediately`) or set `alias.mailbox_id = user.default_mailbox_id` and move the alias to trash. Then delete the mailbox row.
- Sends a notification email to `user.email` (if `send_mail` and user can send/receive): subject `f"Your mailbox {mailbox_email} has been deleted"`; body mentions transfer target if any.

## 6. `PUT /api/mailboxes/<int:mailbox_id>` — update mailbox

```python
@api_bp.route("/mailboxes/<int:mailbox_id>", methods=["PUT"])
@require_api_auth
@limiter.limit("100/hour")
def update_mailbox(mailbox_id):
```

Request JSON body (`request.get_json() or {}`), all fields optional; presence is tested with `in`:
- `default` (bool): if present AND truthy → set this mailbox as the user's default. If the mailbox is unverified → **400** `{"error": "Unverified mailbox cannot be used as default mailbox"}`. Sets `user.default_mailbox_id = mailbox.id`. If present but falsy → silently ignored (still returns 200).
- `email` (str): request a mailbox email change (always processed if the key is present, even if `default` was also given).
- `cancel_email_change` (bool): if present AND truthy → cancel pending email change.

Flow:
1. Ownership check: not found or other user's → **403** `{"error": "Forbidden"}`.
2. `mailbox.is_admin_disabled()` → **400** `{"error": "This mailbox has been disabled. Please contact support."}`.
3. `email` handling: `new_email = sanitize_email(data.get("email"))`, then `mailbox_utils.request_mailbox_email_change(user, mailbox, new_email)` (defaults: `email_ownership_verified=False, send_email=True, use_digit_codes=False`):
   - `sanitize_email` again; if `new_email == mailbox.email` → `MailboxError("Same email")` → **400** `{"error": "Same email"}`.
   - `check_email_for_mailbox(new_email, user)` — same errors as creation (§11): `Invalid email`, `Email already used`, `Invalid email: <reason>` → **400**. NOTE: there is **no premium check** for email change.
   - Sets `mailbox.new_email = new_email`, emits audit log `UpdateMailbox` (message `f"Updated mailbox {mailbox.id} email ({new_email}) pre-verified(False"` — yes, the closing paren is missing in the source), then `Session.commit()`. `mailbox.new_email` has a DB **unique constraint across all users**; `IntegrityError` → rollback → **400** `{"error": "Email already in use"}`.
   - `generate_activation_code(mailbox, use_digit_code=False)` — clears old codes, creates `secrets.token_urlsafe(16)` code.
   - `send_change_email(user, mailbox, activation)`:
     - To: `mailbox.new_email`.
     - Subject: `"Confirm mailbox change on SimpleLogin"`.
     - Templates `transactional/verify-mailbox-change.txt.jinja2` / `.html`.
     - Link: `f"{config.URL}/dashboard/mailbox/confirm_change?mailbox_id={mailbox.id}&code={activation.code}"`.
   - If `send_email` raises `SMTPRecipientsRefused` → **400** `{"error": f"Incorrect mailbox, please recheck {new_email}"}` (new_email interpolated).
   - On success the route redundantly sets `mailbox.new_email = new_email` again and marks changed.
4. `cancel_email_change` truthy → `mailbox_utils.cancel_email_change(mailbox.id, user)`: sets `mailbox.new_email = None` and deletes all `mailbox_activation` rows for the mailbox (commits). (Its `MailboxError("Invalid mailbox")` branches are unreachable here since ownership was already verified.)
5. If anything changed → `Session.commit()`.
6. Response: **200** `{"updated": true}` — returned even when no recognized field was present in the body.

## 7. `GET /api/mailboxes` — list verified mailboxes

```python
@api_bp.route("/mailboxes", methods=["GET"])
@require_api_auth
def get_mailboxes():
```

No rate limit decorator, no query params, no pagination.

Returns only **verified** mailboxes: `user.mailboxes()` = `Mailbox.filter_by(user_id=user.id, verified=True)` (no explicit ordering — default DB order).

Response **200**:
```json
{"mailboxes": [ <mailbox_to_dict>, ... ]}
```

## 8. `GET /api/v2/mailboxes` — list ALL mailboxes

```python
@api_bp.route("/v2/mailboxes", methods=["GET"])
@require_api_auth
def get_mailboxes_v2():
```

No rate limit decorator, no query params, no pagination.

Returns ALL mailboxes of the user **including unverified**: `Mailbox.filter_by(user_id=user.id)` (no explicit ordering).

Response **200** — exactly the same shape as v1:
```json
{"mailboxes": [ <mailbox_to_dict>, ... ]}
```

The v2 dict is identical to v1 (`id`, `email`, `verified`, `default`, `creation_timestamp`, `nb_alias`); the only difference is the filter.

## 9. Custom domain routes

### 9.1 `GET /api/custom_domains`

```python
@api_bp.route("/custom_domains", methods=["GET"])
@require_api_auth
def get_custom_domains():
```

No rate limit, no params, no pagination. Query: `CustomDomain.filter_by(user_id=user.id, is_sl_subdomain=False).all()` — **SimpleLogin subdomains are excluded**; unverified and `pending_deletion` domains are included.

Response **200** (implicit status from `jsonify`):
```json
{"custom_domains": [ <custom_domain_to_dict>, ... ]}
```

### 9.2 `GET /api/custom_domains/<int:custom_domain_id>/trash`

```python
@api_bp.route("/custom_domains/<int:custom_domain_id>/trash", methods=["GET"])
@require_api_auth
def get_custom_domain_trash(custom_domain_id: int):
```

No rate limit, no pagination.

1. Not found or other user's domain → **403** `{"error": "Forbidden"}`. (No `is_sl_subdomain` filter here — subdomain trash is reachable by id.)
2. `DomainDeletedAlias.filter_by(domain_id=custom_domain.id).all()`.

Response **200**:
```json
{"aliases": [ {"alias": "<dda.email>", "deletion_timestamp": <dda.created_at.timestamp int>}, ... ]}
```

### 9.3 `PATCH /api/custom_domains/<int:custom_domain_id>`

```python
@api_bp.route("/custom_domains/<int:custom_domain_id>", methods=["PATCH"])
@require_api_auth
@limiter.limit("100/hour")
def update_custom_domain(custom_domain_id):
```

Request JSON body — required to be non-empty: if `request.get_json()` is falsy → **400** `{"error": "request body cannot be empty"}`. All fields optional (presence tested with `in`):
- `catch_all` (bool): assigned as-is, **no type validation** (any JSON value is written to the boolean column).
- `random_prefix_generation` (bool): assigned as-is, no type validation.
- `name` (str | null): assigned as-is, no validation/length check (DB column is String(128)).
- `mailbox_ids` (array of int): `[int(m_id) for m_id in data.get("mailbox_ids")]` — non-iterable → TypeError → 500; non-numeric element → ValueError → 500.

Flow:
1. Not found or other user's domain → **403** `{"error": "Forbidden"}`. (No `is_sl_subdomain` filter — a subdomain can be PATCHed via this endpoint.)
2. `mailbox_ids` present → `set_custom_domain_mailboxes(user.id, custom_domain, mailbox_ids)` (app/custom_domain_utils.py):
   - Empty list → failure (reason `NoMailboxes`).
   - More than `_MAX_MAILBOXES_PER_DOMAIN = 20` ids → failure (reason `TooManyMailboxes`).
   - Loads mailboxes with `id IN (ids) AND user_id = user.id AND verified = TRUE`; if the count doesn't match `len(mailbox_ids)` (i.e., any id is unknown, foreign, unverified, or duplicated in the list) → failure (reason `InvalidMailbox`).
   - Any selected mailbox `is_admin_disabled()` → failure (reason `InvalidMailbox`).
   - On any failure the route logs and returns **400** `{"error": "Forbidden"}` — note: message "Forbidden" but status **400**, not 403. The reason enum is never exposed to the client.
   - Success: DELETE all `domain_mailbox` rows for the domain, flush, INSERT one row per mailbox, emit user audit log `UpdateCustomDomain` (`f"Updated custom domain {id} mailboxes (domain={domain}) (mailboxes={comma-joined ids})"`), commit.
3. If anything changed → `Session.commit()`.
4. Re-fetches the domain and returns **200**:
```json
{"custom_domain": <custom_domain_to_dict>}
```
Returned even if no recognized field was present (no-op PATCH with e.g. `{"foo": 1}` → 200 with current state).

---

## 10. `sanitize_email(email_address, not_lower=False)` (app/utils.py)

```python
if email_address:
    email_address = email_address.strip().replace(" ", "").replace("\n", " ")
    if not not_lower:
        email_address = email_address.lower()
return email_address.replace("‏", "")
```

- Strips leading/trailing whitespace, removes ALL spaces, replaces newlines with a space (note: since `replace(" ", "")` runs first, embedded `\n` becomes `" "` and survives — order matters), lowercases, removes U+200F (RTL mark).
- Falsy input (empty string) is returned after `.replace("‏", "")`; `None` would crash on the final `.replace` (routes guard against `None` before calling, except PUT mailbox `email: null` which would 500).

## 11. Mailbox email validation — `check_email_for_mailbox(email, user)`

Order matters (first failure wins):

1. **`is_valid_email(email)`** (app/email_validation.py): `validate_email(email_address, check_deliverability=False, allow_smtputf8=False)` from the `email_validator` PyPI package (`~= 2.2.0`). Syntax-only validation: RFC-style local part; **non-ASCII local parts rejected** (`allow_smtputf8=False`); domain must be a resolvable-looking FQDN — must contain a dot, valid labels, no trailing/leading hyphens; IDN domains accepted (IDNA-normalized); no MX/DNS lookup. Failure → `MailboxError("Invalid email")` → 400 `{"error": "Invalid email"}`.
2. **`mailbox_already_used(email, user)`** (app/email_utils.py): `True` only if THIS user already has a `mailbox` row with this exact email (`Mailbox.get_by(email=email, user_id=user.id)`). A different (non-disabled) user having the same mailbox email does NOT block. (The `email == user.email` branch returns False and is effectively dead code.) Failure → `MailboxError("Email already used")`.
3. **`email_can_be_used_as_mailbox_with_reason(email)`** (app/email_utils.py) — returns an `EmailCannotBeUsedReason` or `None`. If non-None → `MailboxError(f"Invalid email: {reason.value}")`. Steps:
   1. `validate_email(...)` again to extract the (IDNA-normalized) domain; invalid → reason `InvalidEmailAddress`.
   2. Empty domain → reason `InvalidEmailDomain`.
   3. `check_domain_for_mailbox(domain)`:
      - No domain or no `"."` in it → `InvalidEmailDomain`.
      - `SLDomain.get_by(domain=domain)` exists (SimpleLogin alias domain, table `public_domain`) → `IsSimpleLoginDomain`.
      - `CustomDomain.get_by(domain=domain, verified=True)` exists (ANY user's verified custom domain) → `IsCustomDomain`.
      - `is_invalid_mailbox_domain(domain)`: the domain or ANY parent suffix (checks `parts[i:]` joined for i in 0..len-2, i.e. `mail.foo.com` checks `mail.foo.com`, `foo.com`) exists in table `invalid_mailbox_domain` → `InvalidMailboxDomain`.
      - DNS MX lookup (`get_mx_domain_list`): if config `SKIP_MX_LOOKUP_ON_CHECK` is false and no MX records → `NoMxRecordFound`.
      - For each MX host: if MX host is itself an invalid mailbox domain (suffix check) → `InvalidMailboxDomain`; resolve its A record and if any resolved IP is in table `forbidden_mx_ip` → `ForbiddenMxRecordFound`.
   4. `User.get_by(email=email)` exists AND that user is `disabled` → `EmailOfDisabledUser`.
   5. Any user owning a `mailbox` row with this email who is `disabled` → `MailboxOfDisabledUser`.

Exact `EmailCannotBeUsedReason.value` strings (client-visible as `"Invalid email: <value>"`):

| Reason | value |
|---|---|
| InvalidEmailAddress | `This email address is not valid` |
| InvalidEmailDomain | `This email domain is not valid` |
| IsSimpleLoginDomain | `This email is a SimpleLogin domain` |
| IsCustomDomain | `This email address belongs to a custom domain that has already been registered` |
| InvalidMailboxDomain | `We don't allow mailboxes using this domain` |
| NoMxRecordFound | `We couldn't get any MX records configured for this domain` |
| ForbiddenMxRecordFound | `We don't allow mailbox domains that point to these MX records` |
| EmailOfDisabledUser | `This email address is not allowed` |
| MailboxOfDisabledUser | `This email address is not allowed` |

## 12. Date/time formats (arrow `~= 0.16.0`)

- `created_at` columns are `ArrowType` (UTC, `default=arrow.utcnow`).
- `.timestamp` is a **property returning an int** (unix seconds, truncated) in arrow 0.16 — used for `creation_timestamp` (mailbox, custom domain) and `deletion_timestamp` (domain trash).
- `.format()` with no args uses arrow's default format string `"YYYY-MM-DD HH:mm:ssZZ"`, producing e.g. `"2021-03-10 21:36:08+00:00"` (space separator, seconds precision, `+00:00` offset with colon, no microseconds, no `T`, no `Z`). Used for custom domain `creation_date` only.

---

## 13. Implementation notes for Cloudflare

DB tables/columns touched:
- `mailbox`: `id`, `user_id`, `email` (String(256), unique per user via `uq_mailbox_user(user_id,email)`), `verified` (bool, default false), `new_email` (String(256), **globally unique**), `flags` (bigint bitmask; bit 0 = `FLAG_ADMIN_DISABLED`), `created_at`. Reads of `disabled`, `pgp_*` not used by these routes.
- `mailbox_activation`: `mailbox_id`, `code` (String(32)), `tries` (int default 0), `created_at`. Cleared (all rows per mailbox) before each new code and on cancel/verify.
- `custom_domain`: `id`, `user_id`, `domain` (String(128), unique), `name` (String(128), nullable), `verified`, `catch_all`, `random_prefix_generation`, `is_sl_subdomain`, `pending_deletion`, `created_at`.
- `domain_mailbox`: `domain_id`, `mailbox_id` (unique pair). PATCH mailbox_ids does full delete-then-insert.
- `domain_deleted_alias`: `email`, `domain_id`, `created_at` (read-only here).
- `alias`, `alias_mailbox`: read for `nb_alias` counts (exclude `delete_on IS NOT NULL`); written by the async delete-mailbox job.
- `job`: INSERT `name="delete-mailbox"`, JSON `payload={"mailbox_id", "transfer_mailbox_id", "send_mail"}`, `run_at=now`.
- `api_key`: `last_used`, `times` updated on every authenticated request.
- `users`: `default_mailbox_id` written by PUT default; `disabled`, `delete_on`, premium/subscription fields read.
- `public_domain` (SLDomain), `invalid_mailbox_domain`, `forbidden_mx_ip`: read during mailbox email validation.
- User audit log table: rows written on create mailbox, email-change request, domain mailboxes update, and by the delete job.

Python/Flask-specific behaviors to reproduce:
- Route int converters (`<int:mailbox_id>`): non-integer path segment → 404 (Flask default HTML 404, not JSON).
- `request.get_json()` (POST /mailboxes, PATCH custom_domain) raises for wrong content type → Flask default 415/400 error page; DELETE/PUT mailbox use `request.get_json() or {}` but still require the body, if present, to be JSON with `Content-Type: application/json`.
- Truthiness semantics: `transfer_aliases_to: 0` → treated as "delete aliases"; `"default": false` and `"cancel_email_change": false` are no-ops; presence checks use `in` on the parsed JSON object.
- Success bodies: POST /mailboxes returns the mailbox object at top level with **201**; DELETE returns `{"deleted": true}` 200; PUT returns `{"updated": true}` 200; PATCH custom_domain returns `{"custom_domain": {...}}` 200; list endpoints wrap in `mailboxes` / `custom_domains` / `aliases` keys with 200.
- Mailbox deletion is **asynchronous** (job queue). API returns `{"deleted": true}` while the row still exists; a subsequent GET /v2/mailboxes may still show it. On Workers, replicate via Queues/Durable Object alarm/cron, preserving the alias-transfer semantics of §5.
- MX/A-record DNS lookups during mailbox creation/email change: on Workers use DNS-over-HTTPS (e.g. 1.1.1.1 resolver). Config flag `SKIP_MX_LOOKUP_ON_CHECK` (default False) skips only the "no MX records" failure, not the invalid-domain/forbidden-IP checks on any records found.
- Emails sent: mailbox verification (subject `Please confirm your mailbox {email}`, link `{URL}/dashboard/mailbox_verify?mailbox_id={id}&code={code}`), mailbox change confirmation (subject `Confirm mailbox change on SimpleLogin`, link `{URL}/dashboard/mailbox/confirm_change?mailbox_id={id}&code={code}`), and post-deletion notification from the job. `config.URL` is the site base URL.
- Rate limits are keyed by IP for API-key clients (no session), and disabled by `DISABLE_RATE_LIMIT`.
- Activation codes for the API path are `secrets.token_urlsafe(16)` — 22 chars, alphabet `A-Za-z0-9_-`.
