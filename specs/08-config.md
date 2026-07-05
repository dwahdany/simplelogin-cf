# 08 — Configuration & Constants

Source files:
- `/app/config.py` — all runtime config, loaded from environment variables (optionally via a dotenv file pointed to by `CONFIG`).
- `/app/constants.py` — small set of hard-coded constants + `JobType` enum.

This spec documents every config value / constant referenced by the **API layer** (`app/api/**`) and the **email handler** (`email_handler.py` + `app/handler/*`, `app/email_utils.py`, `app/email/rate_limit.py`), plus the helper modules they pull in (`app/models.py`, `app/alias_suffix.py`, `app/alias_utils.py`, `app/alias_delete.py`, `app/mailbox_utils.py`, `app/extensions.py`, `app/rate_limiter.py`).

---

## 0. How config values are parsed (critical semantics)

1. **Plain env string**: `os.environ["X"]` (required, crashes at boot if missing) or `os.environ.get("X", default)`.
2. **Presence-based booleans**: many flags use `"X" in os.environ` — the flag is **true if the env var exists at all**, even if set to `"false"`, `"0"` or `""`. Affected flags (subset relevant here): `DISABLE_REGISTRATION`, `DISABLE_ALIAS_SUFFIX`, `NOT_SEND_EMAIL`, `ENFORCE_SPF`, `POSTFIX_SUBMISSION_TLS`, `DISABLE_ONBOARDING`, `ENABLE_SPAM_ASSASSIN`, `ALIAS_AUTOMATIC_DISABLE`, `RSPAMD_SIGN_DKIM`, `ZENDESK_ENABLED`, `DMARC_CHECK_ENABLED`, `ENABLE_ALL_REVERSE_ALIAS_REPLACEMENT`, `DISABLE_RATE_LIMIT`, `STORE_TRANSACTIONAL_EMAILS`, `MAINTENANCE_MODE`, `EVENT_WEBHOOK_SKIP_VERIFY_SSL`, `EVENT_WEBHOOK_DISABLE`, `CONNECT_WITH_PROTON`, `PROTON_VALIDATE_CERTS`, `PROTON_PREVENT_CHANGE_LINKED_ACCOUNT`, `APPLE_WEBHOOK_SECRET_CHECK_ENABLED`, `LOAD_PGP_EMAIL_HANDLER`, `LOCAL_FILE_UPLOAD`, `COLOR_LOG`, `USE_RUST_PGP`, `DROP_PGP_KEY_ATTACHMENTS_ON_REPLY`, `ENFORCE_OAUTH_CLIENT_APPROVED`, `SKIP_MX_LOOKUP_ON_CHECK` (hardcoded `False`, tests only).
3. **Python-literal env values**: `sl_getenv(var, default_factory)` runs `ast.literal_eval()` on the raw value. So list-valued vars must be written as Python/JSON list literals, e.g. `ALIAS_DOMAINS='["domain1.com", "domain2.com"]'`.
4. **CSV env values**: `get_env_csv(var, default)` → split on `,`, strip whitespace, drop empties.
5. **Rate-limit tuples**: `getRateLimitFromConfig(var, default)` parses `hits,seconds:hits,seconds` → `list[(hits, seconds)]`, e.g. `"10,900:50,3600"` → `[(10, 900), (50, 3600)]`.
6. **key=value dicts**: `get_env_dict(var)` parses `key1=value1;key2=value2`.
7. **Hex byte keys**: `read_hex_data(key, default)` → `bytes.fromhex(value)` if set else the default bytes.

---

## 1. Domains

| Name | Default | Type |
|---|---|---|
| `EMAIL_DOMAIN` | **required**, lower-cased (`os.environ["EMAIL_DOMAIN"].lower()`) | str |
| `OTHER_ALIAS_DOMAINS` | `[]` (literal-eval list; each entry `.lower().strip()`) | list[str] |
| `ALIAS_DOMAINS` | if env `ALIAS_DOMAINS` set: literal-eval list; else `OTHER_ALIAS_DOMAINS + [EMAIL_DOMAIN]`; each entry `.lower().strip()` | list[str] |
| `PREMIUM_ALIAS_DOMAINS` | `[]` (literal-eval list, lower/stripped) | list[str] |
| `FIRST_ALIAS_DOMAIN` | `os.environ.get("FIRST_ALIAS_DOMAIN") or EMAIL_DOMAIN` | str |

Where used / what they do:

- **`EMAIL_DOMAIN`**:
  - Email handler: reply (reverse) aliases must end with `EMAIL_DOMAIN` (`email_handler.py:1048`: `if not reply_email.endswith(config.EMAIL_DOMAIN)` → the reply-phase mail is refused); DKIM signature added for `EMAIL_DOMAIN` (`add_dkim_signature(msg, config.EMAIL_DOMAIN)`); reverse-alias generation in `app/email_utils.py` (`generate_reply_email` builds `ra+...@{EMAIL_DOMAIN}` / prefix variants, lines ~1348–1383); default sender domain for VERP addresses (`generate_verp_email(..., sender_domain or config.EMAIL_DOMAIN)`).
  - Default for `BOUNCE_SUFFIX` (`f"+@{EMAIL_DOMAIN}"`), `TRANSACTIONAL_BOUNCE_SUFFIX`, `NOREPLY` (`f'"SimpleLogin (noreply)" <noreply@{EMAIL_DOMAIN}>'`).
- **`ALIAS_DOMAINS`**: used by `can_create_directory_for_address()` (`app/email_utils.py:606-615`): a directory alias (`dir/xxx@domain`) may only be auto-created if the address ends with `@` + one of `ALIAS_DOMAINS`. This is invoked from the email-handler auto-create path (`app/alias_utils.py::try_auto_create`). NOTE: **API alias-domain offerings do NOT come from this config** — they come from the `public_domain` (SLDomain) DB table via `user.get_sl_domains()` / `user.available_alias_domains()`.
- **`PREMIUM_ALIAS_DOMAINS`**: documented as "domains only premium users can use"; at runtime the premium check is done through the SLDomain table (`premium_only` column), not this config. Only referenced in doc-strings of `email_can_be_used_as_mailbox` (the actual check is `SLDomain.get_by(domain=domain)` — any row in the SLDomain table blocks mailbox use).
- **`FIRST_ALIAS_DOMAIN`**:
  - `User.default_random_alias_domain()` (`app/models.py:1104-1139`) — fallback domain used by `POST /api/alias/random/new` when the user has no valid default custom/public domain (also returned when the stored default fails sanity checks).
  - `Alias.create_new(user, prefix)` (`app/models.py:1884-1900`) — builds `f"{prefix}.{suffix}@{config.FIRST_ALIAS_DOMAIN}"` (used by first-alias creation on signup and OAuth flows).
  - `Alias.create_new_random(... alias_domain: str = config.FIRST_ALIAS_DOMAIN)` (models.py:1570) — default arg for random alias creation.

---

## 2. Limits & pagination

| Name | Default | Type |
|---|---|---|
| `MAX_NB_EMAIL_FREE_PLAN` | `int(os.environ["MAX_NB_EMAIL_FREE_PLAN"])`, falls back to `5` (with a printed warning) if unset/unparseable | int |
| `MAX_NB_EMAIL_OLD_FREE_PLAN` | `15` | int |
| `MAX_NB_DIRECTORY` | `50` (hard-coded, not env-configurable) | int |
| `MAX_NB_SUBDOMAIN` | `5` (hard-coded) | int |
| `PAGE_LIMIT` | `20` (hard-coded) | int |
| `MAX_API_KEYS` | `30` (`MAX_API_KEYS` env) | int |
| `MAX_ALERT_24H` | `4` (hard-coded) | int |
| `MAX_ACTIVITY_DURING_MINUTE_PER_ALIAS` | `10` (hard-coded) | int |
| `MAX_ACTIVITY_DURING_MINUTE_PER_MAILBOX` | `15` (hard-coded) | int |
| `MAX_BOUNCES_1D` | `12` (`MAX_BOUNCES_1D` env) | int |
| `MAX_BOUNCES_1W` | `10` (`MAX_BOUNCES_1W` env) | int |
| `MAX_EMAIL_FORWARD_RECIPIENTS` | `30` (`MAX_EMAIL_FORWARD_RECIPIENTS` env) | int |
| `SMTP_SIZE_LIMIT` | `41943040` (40 MiB) | int |
| `ALIAS_RANDOM_SUFFIX_LENGTH` | `5` — env var is named **`ALIAS_RAND_SUFFIX_LENGTH`** (different from the Python name!) | int |
| `ALIAS_TRASH_DAYS` | `30` | int |
| `AUDIT_LOG_MAX_DAYS` | `30` | int |
| `KEEP_OLD_DATA_DAYS` | `30` (hard-coded) | int |
| `HIBP_MAX_ALIAS_CHECK` | `10_000` (hard-coded) | int |

Where used:

- **`MAX_NB_EMAIL_FREE_PLAN` / `MAX_NB_EMAIL_OLD_FREE_PLAN`**: `User.max_alias_for_free_account()` (`app/models.py:957-964`) returns `MAX_NB_EMAIL_OLD_FREE_PLAN` if the user has flag `FLAG_FREE_OLD_ALIAS_LIMIT = 1 << 2` set on `users.flags`, else `MAX_NB_EMAIL_FREE_PLAN`. `User.can_create_new_alias()` / `can_create_num_aliases(n)` enforce it for free (non-premium, non-lifetime) users — **also enforced during free trial** for alias creation checks in API routes.
  - API error message (exact, `POST /api/alias/custom/new` v1/v2/v3 in `new_custom_alias.py:50-56,158-166` and `POST /api/alias/random/new` in `new_random_alias.py:36-43`, status **400**):
    `"You have reached the limitation of a free account with the maximum of {MAX_NB_EMAIL_FREE_PLAN} aliases, please upgrade your plan to create more aliases"`
    — note the message **always interpolates `MAX_NB_EMAIL_FREE_PLAN`** (the new-plan number), even for users on the old 15-alias limit.
  - `GET /api/user_info` returns `"max_alias_free_plan": user.max_alias_for_free_account()`.
  - Also templated into upgrade emails (`app/email_utils.py:110`, `render()` context var `MAX_NB_EMAIL_FREE_PLAN`).
- **`PAGE_LIMIT` (20)**: all API pagination.
  - `GET /api/aliases` (v1, `serializer.get_alias_infos_with_pagination`): `q.limit(PAGE_LIMIT).offset(page_id * PAGE_LIMIT)`.
  - `GET /api/v2/aliases` (`get_alias_infos_with_pagination_v3`): default kwargs `page_limit=PAGE_LIMIT, page_size=PAGE_LIMIT` (the query fetches `page_limit` rows at `offset page_id * page_size`). Exactly 20 items per page; there is no `has_more` field — clients detect the last page by receiving `< 20` items.
  - `GET /api/aliases/:alias_id/contacts` (`serializer.py:302-303`): `.limit(PAGE_LIMIT).offset(page_id * PAGE_LIMIT)`.
  - `GET /api/notifications` (`notification.py:38-43`): fetches `PAGE_LIMIT + 1` rows at `offset page * PAGE_LIMIT`; response `"more": len(notifications) > PAGE_LIMIT`, returns first `PAGE_LIMIT` entries.
  - `GET /api/aliases/:alias_id/logs` (v1 uses `get_alias_log`, same `PAGE_LIMIT` constant).
- **`MAX_NB_DIRECTORY`**: `User.directory_quota` property (`app/models.py:661-664`): `min(_directory_quota, MAX_NB_DIRECTORY - count(directories))`. `MAX_NB_SUBDOMAIN` analogous for SL subdomains (models.py:667-672). (Dashboard-only enforcement; no dedicated API route, but quota indirectly affects directory-based alias auto-creation limits.) There is **no `MAX_ALIAS_PER_DIRECTORY` constant** in the codebase.
- **`MAX_API_KEYS`**: caps ApiKey creation in the dashboard (`app/dashboard/views/api_key.py`, `total_keys <= config.MAX_API_KEYS`). API `auth/login` and `auth/mfa` create keys via `ApiKey.create(user.id, device)` (one per device name — reused if a key with the same `name` exists) and do **not** check this cap.
- **`MAX_ALERT_24H`**: `send_email_with_rate_control(..., max_nb_alert=config.MAX_ALERT_24H, nb_day=1)` (`app/email_utils.py:415-435`): counts rows in `sent_alert` with same `alert_type` + `to_email` newer than `nb_day` days; skips sending if `>= max_nb_alert`. Used by every ALERT_* email in the email handler.
- **`MAX_ACTIVITY_DURING_MINUTE_PER_ALIAS` / `_PER_MAILBOX`** (`app/email/rate_limit.py`): forward/reply is dropped when the number of `email_log` rows joined via `contact` for that alias (resp. mailbox) created within the last minute exceeds 10 (resp. 15). Strictly `>` comparison.
- **`MAX_BOUNCES_1D` / `MAX_BOUNCES_1W`**: `should_disable(alias)` in `app/email_utils.py:1394-1430` — when `ALIAS_AUTOMATIC_DISABLE` is on, an alias is auto-disabled after >12 bounces in 1 day or >10 in 1 week (also user-level: >(2×12) in a day across aliases, >(2.5×10) per week — see code).
- **`MAX_EMAIL_FORWARD_RECIPIENTS`**: `email_handler.py:937` — `check_recipient_limit(msg, config.MAX_EMAIL_FORWARD_RECIPIENTS)`; incoming forward with more than 30 recipients (To+Cc) is rejected.
- **`SMTP_SIZE_LIMIT`**: `email_handler.py:2474` — aiosmtpd `data_size_limit` (40 MiB max inbound message).
- **`ALIAS_RANDOM_SUFFIX_LENGTH`**: `User.get_random_alias_suffix()` (`app/models.py:1260-1274`): if `user.random_alias_suffix == AliasSuffixEnum.random_string.value` → `random_string(ALIAS_RANDOM_SUFFIX_LENGTH, include_digits=True)` (5 chars, lowercase letters + digits); else 1 random word + up to 3 digits (`random_words(1, 3)`); for custom domains, 1 random word without digits.
- **`ALIAS_TRASH_DAYS`**: `app/alias_delete.py:123` — trashed alias `delete_on = now + 30 days` (used by `DELETE /api/aliases/:id` trash semantics and cron purge).

---

## 3. Rate limits

### 3.1 flask-limiter (`app/extensions.py`)

- Key function: `userid:{current_user.id}` when a web session is authenticated, else `ip:{remote_addr}`. For API-key-only requests there is no flask-login user, so limits are **per IP** — except routes that override `key_func` (see below).
- `DISABLE_RATE_LIMIT` (presence flag, default off): registered as a `@limiter.request_filter` — when true all flask-limiter limits are skipped.
- When exceeded, flask-limiter aborts with **429** (default body, not a JSON API error).

`@limiter.limit` values on API routes:

| Route(s) | Limit |
|---|---|
| `POST /api/auth/login`, `/api/auth/register`, `/api/auth/activate`, `/api/auth/reactivate`, `/api/auth/facebook`, `/api/auth/google`, `POST /api/auth/mfa` | `"10/minute"` |
| `POST /api/auth/forgot_password` | `"2/minute"` |
| `POST /api/alias/custom/new`, `POST /api/v2/alias/custom/new`, `POST /api/v3/alias/custom/new`, `POST /api/alias/random/new` | `ALIAS_LIMIT` = env `ALIAS_LIMIT` or default **`"100/day;50/hour;5/minute"`** (all three windows enforced) |
| `GET /api/aliases`, `GET /api/v2/aliases` | `"10/minute", key_func=lambda: g.user.id` (per user id) |
| `POST /api/v2/aliases` (search) | included in the same decorator as above |
| `GET /api/v5/alias/options` (and v4) | `"50/minute", key_func=lambda: g.user.id` |
| `DELETE /api/aliases/:alias_id` | `"100/hour"` |
| `POST /api/aliases/:alias_id/toggle` | `"30/minute"` |
| `POST /api/mailboxes` | `"20/hour"` |
| `DELETE /api/mailboxes/:mailbox_id`, `PUT /api/mailboxes/:mailbox_id` | `"100/hour"` |
| `DELETE /api/custom_domains/:custom_domain_id/trash` | `"100/hour"` |
| `PATCH /api/sudo` | `"5/minute"` |
| `DELETE /api/user` (delete account) | `"5/minute"` |

(`ALIAS_LIMIT` uses flask-limiter multi-limit syntax with `;` separators. The dashboard custom-alias POST uses the same value.)

### 3.2 Redis bucket limits (`app/rate_limiter.py::check_bucket_limit`)

Independent of flask-limiter; uses Redis (`MEM_STORE_URI`, default `None` → **no-op when Redis is not configured**). Buckets are `bl:{lock_name}:{bucket_id}` where `bucket_id = now - (now % bucket_seconds)` (fixed windows, not sliding). On exceed raises HTTP **429 TooManyRequests** ("Rate limit exceeded"). Config values parsed with `getRateLimitFromConfig` (format `hits,seconds:hits,seconds`):

| Name | Default | Applied in |
|---|---|---|
| `ALIAS_CREATE_RATE_LIMIT_FREE` | `"10,900:50,3600"` → `[(10,900),(50,3600)]` | `Alias.create` (`models.py:1795-1803`) for free/trial users; key `alias_create_{seconds}:{user_id}` |
| `ALIAS_CREATE_RATE_LIMIT_PAID` | `"50,900:200,3600"` | same, for premium non-trial users |
| `ALIAS_RESTORE_ONE_RATE_LIMIT` | `"100,86400:200,604800"` | `restore_alias` (`alias_delete.py:177`), key `alias_restore_all_{seconds}:{user_id}` |
| `ALIAS_RESTORE_ALL_RATE_LIMIT` | `"5,3600:20,604800"` | `restore_all_alias` (`alias_delete.py:194`), same key prefix |

Note: `Alias.create` is called by every alias-creating API route **and** by the email handler's on-the-fly (catch-all/directory) alias creation, so the create bucket limit applies to both.

- `MEM_STORE_URI` (default `None`): Redis URI used for these buckets and for `parallel_limiter` locks (e.g. `@parallel_limiter.lock(name="mfa_auth")` on `POST /api/auth/mfa`).
- `DISABLE_RATE_LIMIT` does **not** disable the Redis bucket limits (only flask-limiter); the buckets are disabled in tests via `set_rate_limit_enabled(False)`.

---

## 4. Flags consulted by the API layer

| Name | Default | Used in |
|---|---|---|
| `DISABLE_REGISTRATION` | off (presence flag) | `POST /api/auth/register` (`auth.py:120`) → **400** `{"error": "registration is closed"}`; same check+body in `POST /api/auth/facebook` (`auth.py:304`) and `POST /api/auth/google` (`auth.py:361`) when the social account has no existing user; also web register & OIDC. |
| `DISABLE_ALIAS_SUFFIX` | off (presence flag) | `app/alias_suffix.py`: when set, SL-domain suffixes have no `.random_word` part — `get_alias_suffixes()` produces suffix `"@domain"` instead of `".{random}@domain"` (lines 149, 178), and `verify_prefix_suffix()` accepts an empty domain-prefix for SL domains (lines 74-89). Affects `GET /api/v5/alias/options`, `GET /api/v4/alias/options` and validation in `POST /api/v2|v3/alias/custom/new`. |
| `CONNECT_WITH_PROTON` | off (presence flag) | `user_to_dict` in `GET /api/user_info` / `PATCH /api/user_info` (`user_info.py:41`): when on, `"connected_proton_address"` is populated via `get_connected_proton_address(user)`, else stays `None`. |
| `APPLE_WEBHOOK_SECRET_CHECK_ENABLED` | off (presence flag) | `POST /api/apple/update_notification` (`apple.py:242-249`): when on, payload `password` must equal `APPLE_API_SECRET` or `MACAPP_APPLE_API_SECRET`, else **401** `{"error": "Unauthorized"}`. |
| `DISABLE_CREATE_CONTACTS_FOR_FREE_USERS` | `False` (note: `os.environ.get(..., False)` — any non-empty string is truthy) | `User.can_create_contacts()` (`models.py:1276-1281`): premium users always can; free users can only if this flag is falsy. Surfaced in `GET /api/user_info` as `"can_create_reverse_alias"` and enforced by `POST /api/aliases/:alias_id/contacts` (403 `{"error": "Please upgrade to create a reverse-alias"}`). |
| `DISABLE_RATE_LIMIT` | off | see §3.1. |
| `MAILBOX_VERIFICATION_OVERRIDE_CODE` | `None` | `app/mailbox_utils.py:288-289`: if set, mailbox activation codes are forced to this value (testing backdoor). Affects `POST /api/mailboxes` verification flow. |

---

## 5. Secrets & signing

| Name | Default / derivation | Used for |
|---|---|---|
| `FLASK_SECRET` | **required**, must be non-empty (`RuntimeError` otherwise) | Flask session cookie signing; **`mfa_key` signing** in the API: `auth_payload()` (`auth.py:385-386`) does `itsdangerous.Signer(FLASK_SECRET).sign(str(user.id))` and returns it as `mfa_key` (bytes → serialized as string, format `"{user_id}.{base64_sig}"`); `POST /api/auth/mfa` (`auth_mfa.py:43-46`) does `int(s.unsign(mfa_key))`, any failure → **400** `{"error": "Invalid mfa_key"}`. itsdangerous `Signer` defaults: HMAC-SHA1, salt `"itsdangerous.Signer"`, separator `"."`, key derivation `django-concat` (`key = sha1(salt + b"signer" + secret)`... precisely: digest of `salt + "signer" + secret_key`). No timestamp/expiry on mfa_key. |
| `SESSION_COOKIE_NAME` | `"slapp"` (hard-coded) | Name of the Flask session cookie. `GET /api/logout` (`user_info.py:144`) does `response.delete_cookie(SESSION_COOKIE_NAME)`. Cookie-based API auth (see §8) rides on this session. |
| `MAILBOX_SECRET` | `FLASK_SECRET + "mailbox"` | `itsdangerous.TimestampSigner(MAILBOX_SECRET)` signs mailbox-verification links (dashboard `mailbox.py:157`, `mailbox_detail.py:291`). The API mailbox flow (`mailbox_utils`) uses DB activation codes instead, but the email link embeds this signature. |
| `CUSTOM_ALIAS_SECRET` | `FLASK_SECRET + "custom_alias"` | `app/alias_suffix.py:11`: `signer = itsdangerous.TimestampSigner(CUSTOM_ALIAS_SECRET)`. `get_alias_suffixes()` signs every suffix (`signed_suffix` returned by `GET /api/v4|v5/alias/options`); `check_suffix_signature()` unsigns with **`max_age=600` seconds** — `POST /api/alias/custom/new` (v1/v2) rejects expired/invalid signatures with 412/400 (`"validation of the signed suffix has failed"` / signed-suffix error). v3 (`POST /api/v3/alias/custom/new`) takes an unsigned `alias_suffix` and validates via `verify_prefix_suffix()` instead. TimestampSigner format: `value.timestamp_b64.sig_b64` (HMAC-SHA1, salt `"itsdangerous.Signer"`, epoch-seconds timestamp, URL-safe base64 without padding). |
| `UNSUBSCRIBE_SECRET` | `FLASK_SECRET + "unsub"` | `app/handler/unsubscribe_encoder.py:103-105`: `itsdangerous.Signer(UNSUBSCRIBE_SECRET, digest_method=hashlib.sha3_224)` signs unsubscribe payloads embedded in email subjects/links (email handler unsubscribe flow, `UNSUB_PREFIX = "un"`). |
| `VERP_EMAIL_SECRET` | env or `FLASK_SECRET + "pleasegenerateagoodrandomtoken"`; boot fails if final value < 32 chars | HMAC-SHA3-224 (`VERP_HMAC_ALGO = hashlib.sha3_224`, truncated to first 8 bytes) over a JSON payload `[verp_type, object_id, minutes_since_2022-01-01]`; address format `"{VERP_PREFIX}.{b32(payload)}.{b32(sig)}@{domain}"`, lower-cased, base32 padding stripped (`email_utils.py:1658-1685`). Verified on inbound bounces (`get_verp_info_from_email`, rejects if sig mismatch or timestamp beyond `VERP_MESSAGE_LIFETIME`). |
| `VERP_PREFIX` | `"sl"` | see above; also `app/alias_utils.py:60` — aliases starting with `"{VERP_PREFIX}."` (`sl.`) cannot be created (`check_alias_prefix` bans it). |
| `VERP_MESSAGE_LIFETIME` | `5 * 86400` (5 days, hard-coded) | VERP timestamp validity window. |
| `ALIAS_TRANSFER_TOKEN_SECRET` | env or `FLASK_SECRET + "aliastransfertoken"` | alias-transfer token hashing (dashboard alias transfer; `GET/POST /api/aliases/:id/transfer` not present — dashboard only). |
| `PARTNER_API_TOKEN_SECRET` | env or `FLASK_SECRET + "partnerapitoken"` | partner API token hashing (internal /partner endpoints). |
| `RECOVERY_CODE_HMAC_SECRET` | env or `FLASK_SECRET + "generatearandomtoken"`; must be ≥ 16 chars (boot error) | HMAC of MFA recovery codes stored in DB. |
| `MASTER_ENC_KEY` / `MAC_KEY` / `ABUSER_HKDF_SALT` | `bytes.fromhex(env)` or `(FLASK_SECRET + "enckey"/"mackey"/"absalt").encode()` | abuser-data encryption (admin/abuse tooling). |

**Bounce/VERP address building blocks (email handler):**

| Name | Default |
|---|---|
| `BOUNCE_PREFIX` | `"bounce+"` |
| `BOUNCE_SUFFIX` | `f"+@{EMAIL_DOMAIN}"` |
| `BOUNCE_PREFIX_FOR_REPLY_PHASE` | `"bounce_reply"` (no trailing `+`) |
| `TRANSACTIONAL_BOUNCE_PREFIX` | `"transactional+"` |
| `TRANSACTIONAL_BOUNCE_SUFFIX` | `f"+@{EMAIL_DOMAIN}"` |

Used in `app/alias_utils.py:209-216` (alias addresses may not look like VERP addresses: reject `startswith(BOUNCE_PREFIX) and endswith(BOUNCE_SUFFIX)`, reject `startswith(f"{BOUNCE_PREFIX_FOR_REPLY_PHASE}+") and "+@" in address`) — this validation runs for **API alias creation** (custom + custom-domain aliases) and email-handler auto-creation. Forward-phase envelope senders are `bounce+{email_log.id}+@{EMAIL_DOMAIN}` etc.

---

## 6. URLs

| Name | Default | Used in |
|---|---|---|
| `URL` | **required** (e.g. `https://app.simplelogin.io`) | Base URL for every link generated in emails and API payloads: mailbox confirmation links (`mailbox_utils.py:314,342`: `{URL}/dashboard/mailbox/confirm_change?mailbox_id=..&code=..`), email-handler alert links (`{URL}/dashboard/mailbox/{id}/`, `{URL}/dashboard/unsubscribe/{alias_id}`, `{URL}/dashboard/alias_contact_manager/{alias_id}?highlight_contact_id={contact_id}`, `{URL}/dashboard/refused_email?highlight_id={email_log_id}`, `{URL}/dashboard/mailbox/{alias.mailbox_id}/#authorized-address`), unsubscribe-encoder links (`{URL}/dashboard/unsubscribe/encoded?data=...`), account-activation & reset-password emails sent by `POST /api/auth/register` / `forgot_password`. Also `RP_ID = urlparse(URL).hostname` (WebAuthn) and default for `ALLOWED_REDIRECT_DOMAINS`. |
| `LANDING_PAGE_URL` | `"https://simplelogin.io"` | Template var in transactional emails (`email_utils.py:112`, `models.py:3366`), referral links `{LANDING_PAGE_URL}?slref={code}` (models.py:3183). Not returned by any API route directly. |
| `STATUS_PAGE_URL` | `"https://status.simplelogin.io"` | web templates only. |
| `PARTNER_SUPPORT_URL` | `None` | partner-specific support link in templates. |

---

## 7. Email-handler-specific config (complete list referenced from `email_handler.py` / `app/handler/*`)

| Name | Default | Behavior |
|---|---|---|
| `NOT_SEND_EMAIL` | off | test mode: `sl_sendmail` logs instead of sending. |
| `POSTFIX_SERVERS` | CSV, default `["240.0.0.1"]` | SMTP relay hosts for outbound mail (`email_utils.py:1549`). `POSTFIX_BACKUP_SERVERS` default `[]`. |
| `POSTFIX_PORT` | `587` if `POSTFIX_SUBMISSION_TLS` set, else `25` | outbound SMTP port. `POSTFIX_TIMEOUT` = 3s, `POSTFIX_CONNECT_TIMEOUT` = 1.0s. |
| `ENFORCE_SPF` | off | reply phase: if on and mailbox has `force_spf`, sender IP is SPF-checked against the mailbox domain (`email_handler.py:1122`); failure sends `ALERT_SPF` email with `{URL}/dashboard/mailbox/{id}/#spf` link and refuses send. |
| `ENABLE_SPAM_ASSASSIN` + `SPAMASSASSIN_HOST` | off / `None` | forward phase (`email_handler.py:800-830`) and reply phase (1144-1167) run SpamAssassin scoring. |
| `MAX_SPAM_SCORE` | `5.5` (float) | forward phase spam threshold (user-level `max_spam_score` column overrides). |
| `MAX_REPLY_PHASE_SPAM_SCORE` | `5` (float) | reply phase threshold. |
| `MIN_RSPAMD_SCORE_FOR_FAILED_DMARC` | `None` (float if set) | quarantine emails failing DMARC only above this rspamd score (`app/handler/dmarc.py`). |
| `DMARC_CHECK_ENABLED` | off | enables DMARC handling in the handler. |
| `ALIAS_AUTOMATIC_DISABLE` | off | enables `should_disable()` auto-disabling of bouncing aliases. |
| `ENABLE_ALL_REVERSE_ALIAS_REPLACEMENT` | off; if on, `MAX_NB_REVERSE_ALIAS_REPLACEMENT` env becomes **required** (int) | reply phase: replace all reverse-aliases occurring in the message body, limited to that many contacts (`email_handler.py:1219-1225`). |
| `DROP_PGP_KEY_ATTACHMENTS_ON_REPLY` | off | reply phase strips `application/pgp-keys` attachments (`email_handler.py:1205`). |
| `PGP_SENDER_PRIVATE_KEY_PATH` → `PGP_SENDER_PRIVATE_KEY` | `None` | if set, outgoing PGP-encrypted forwards are signed (`email_handler.py:424`); `PGP_SIGNER` is the signer address. |
| `UNSUBSCRIBER` / `OLD_UNSUBSCRIBER` | `None` / `None` | if `rcpt_tos == [UNSUBSCRIBER]` or `== [OLD_UNSUBSCRIBER]`, the message is handled as an email-based unsubscribe request (`email_handler.py:2122-2123`). `USERS_WITH_HTTP_UNSUBSCRIBE` (CSV of int user ids, default `[]`) selects users whose outbound emails get HTTP unsubscribe headers instead of mailto. |
| `POSTMASTER` | `None` | mail addressed solely to `POSTMASTER` is accepted/logged specially (`email_handler.py:2201,2212`). |
| `NOREPLY` | `f'"SimpleLogin (noreply)" <noreply@{EMAIL_DOMAIN}>'` | `NOREPLY_EMAIL`/`PARTNER_NOREPLY_EMAIL` = bare addresses (parseaddr). `NOREPLIES` (literal-eval list, default `{NOREPLY_EMAIL, PARTNER_NOREPLY_EMAIL}` as list) — mail to these addresses gets an `ALERT_TO_NOREPLY` warning to the user and is dropped (`email_handler.py:2029, 2262`). |
| `LOAD_PGP_EMAIL_HANDLER` | off | load PGP keys at handler startup (`email_handler.py:2481`). |
| `EMAIL_SERVERS_WITH_PRIORITY` | **required** literal-eval, e.g. `[(10, "mx1.domain.com.")]` | expected MX records; used by custom-domain MX verification (API `GET /api/custom_domains/:id/trash`? no — dashboard DNS checks) and templates. |
| `NAMESERVERS` | `["1.1.1.1"]` (CSV env `NAMESERVERS`) | DNS resolver for MX/SPF/DKIM lookups. |
| `PROTON_MX_SERVERS` | `["mail.protonmail.ch.", "mailsec.protonmail.ch."]`; `PROTON_EMAIL_DOMAINS` = `["proton.me","protonmail.com","protonmail.ch","proton.ch","pm.me"]` | proton-mailbox detection. |
| `DKIM_SELECTOR` | `b"dkim"` (hard-coded) | DKIM `s=` selector. `DKIM_PRIVATE_KEY` loaded from `DKIM_PRIVATE_KEY_PATH` if set; `RSPAMD_SIGN_DKIM` (off) delegates signing to Rspamd. DKIM signs headers `From,To,Subject` (see `email_utils.add_dkim_signature`). |
| `ALIAS_TRASH_DAYS` / `KEEP_OLD_DATA_DAYS` | 30 / 30 | trash purge & old-data cleanup (cron). |
| `TEMP_DIR`, `SAVE_UNSENT_DIR`, `STORE_TRANSACTIONAL_EMAILS` | `None`/`None`/off | debugging/persistence of raw messages. |
| `SENTRY_DSN` etc. | `None` | observability only. |

**Alert-type constants** (hard-coded strings in config.py, used as `sent_alert.alert_type` values for `send_email_with_rate_control` — max `MAX_ALERT_24H`=4 per type/recipient/24h):
`reverse_alias_unknown_mailbox`, `dmarc_failed_reply_phase`, `bounce`, `bounce-when-reply`, `spam`, `cycle`, `non_reverse_alias_reply_phase`, `from_address_is_reverse_alias`, `to_noreply`, `spf`, `invalid_totp_login`, `mailbox_is_alias`, `custom_domain_mx_record_issue`, `alert_directory_disabled_alias_creation`, `alert_complaint_reply_phase`, `alert_complaint_forward_phase`, `alert_complaint_transactional_phase`, `alert_quarantine_dmarc`, `alert_dual_sub_with_partner`, `alert_multiple_subscription`.

---

## 8. Apple / misc API-specific config

| Name | Default | Used in |
|---|---|---|
| `APPLE_API_SECRET` | `None` | `POST /api/apple/process_payment` (`apple.py:53-55`): receipt-verification password for the iOS app (`is_macapp` false/absent). |
| `MACAPP_APPLE_API_SECRET` | `None` | same route when body has `"is_macapp": true`. |
| `APPLE_WEBHOOK_SECRET_CHECK_ENABLED` | off | see §4. |
| `PADDLE_*` | vendor/product ids `-1` when unset | Paddle webhooks (web layer, not `/api`). |
| `PROMO_CODE` | `"SIMPLEISBETTER"` (hard-coded) | dashboard coupon flow only. |
| `MAX_NB_EMAIL_OLD_FREE_PLAN` | 15 | see §2. |
| `HIBP_*` | see config.py (`HIBP_SCAN_INTERVAL_DAYS`=7, `HIBP_API_KEYS`=[], `HIBP_RPM`=100, `HIBP_MAX_ALIAS_CHECK`=10000) | cron breach scanning; surfaced to API only via `Alias.hibp_breaches` in alias serialization. |
| `SUPPORT_EMAIL` | **required** | From address of transactional emails (activation, reset password, alerts). `SUPPORT_NAME` default `"Son from SimpleLogin"`. |
| `ADMIN_EMAIL`, `MONITORING_EMAIL` | `None` | internal notifications. |

### constants.py (`app/constants.py`)

| Name | Value | Used in |
|---|---|---|
| `HEADER_ALLOW_API_COOKIES` | `"X-Sl-Allowcookies"` | `app/api/base.py::authorize_request` — **API auth**: primary auth is header `Authentication: <api_key_code>` (looked up in `api_key.code`; on hit, `api_key.last_used = now()`, `api_key.times += 1`, commit). If no valid API key **and** there is an authenticated Flask session (`slapp` cookie) **and** the request carries this header (any value), the session user is used. Otherwise **401** `{"error": "Wrong api key"}`. After auth: `g.user.disabled` → **403** `{"error": "Disabled account"}`; `not g.user.is_active()` → **401** `{"error": "Account does not exist"}`. `require_api_sudo` additionally requires `api_key.sudo_mode_at >= now - 5 minutes` (`SUDO_MODE_MINUTES_VALID = 5`, set via `PATCH /api/sudo`) or session `sudo_time` within 5 min, else **440** `{"error": "Need sudo"}` (non-standard status 440). |
| `DMARC_RECORD` | `"v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s"` | expected DMARC record for custom-domain DNS verification. |
| `HKDF_INFO_TEMPLATE` | `"enc_key.ab.sl.proton.me:%s"`; `AEAD_AAD_DATA` = `"data.ab.sl.proton.me"` | abuser-data crypto. |
| `JobType` enum | `onboarding-1`, `onboarding-2`, `onboarding-4`, `batch-import`, `delete-account`, `delete-mailbox`, `delete-domain`, `send-user-report`, `proton-welcome-1`, `send-alias-creation-events`, `send-event-to-webhook`, `sync-subscription`, `abuser-mark` | `DELETE /api/user` enqueues `Job(name=JobType.DELETE_ACCOUNT.value)`; mailbox deletion enqueues `delete-mailbox`; onboarding jobs scheduled on register. Values are stored in the `job.name` DB column — exact strings matter. |

---

## 9. Implementation notes for Cloudflare

**DB tables/columns touched by the config-related behaviors above:**
- `users`: `flags` (bit `1<<2` = FLAG_FREE_OLD_ALIAS_LIMIT selects 15-alias legacy limit), `lifetime`, `trial_end`, `default_alias_custom_domain_id`, `default_alias_public_domain_id`, `random_alias_suffix`, `max_spam_score`, `disabled`, `_directory_quota`, `_subdomain_quota`.
- `api_key`: `code` (auth token), `last_used` (arrow/timestamptz), `times`, `sudo_mode_at`, `name` (device), `user_id`.
- `public_domain` (SLDomain): `domain`, `premium_only`, `hidden`, `partner_id`, `order` — **this table, not `ALIAS_DOMAINS` config, drives which SL domains API users see**.
- `alias`: `email`, `delete_on` (trash timestamp = now + `ALIAS_TRASH_DAYS`), `custom_domain_id`, `flags`.
- `deleted_alias`, `domain_deleted_alias`: global/domain trash checked in `Alias.create`.
- `sent_alert`: `alert_type`, `to_email`, `created_at` — alert rate control (`MAX_ALERT_24H` per 24h window).
- `email_log` + `contact`: per-minute activity rate limiting for forward/reply.
- `notification`, `job` (`name` = JobType string), `mailbox` (`verified`, activation codes in `mailbox_activation`), `directory`, `custom_domain`.

**Python-specific behaviors to replicate exactly:**
1. **itsdangerous signatures** (mfa_key, signed_suffix, unsubscribe): HMAC over `base64url(value)` with key = `SHA1(salt + b"signer" + secret_key)` ("django-concat" derivation), salt `"itsdangerous.Signer"`, separator `"."`, sig base64url without padding. `TimestampSigner` appends `.` + base64url(big-endian epoch seconds) before signing. Digest is **SHA1** except the unsubscribe signer which passes `digest_method=hashlib.sha3_224`. `check_suffix_signature` enforces `max_age=600`s.
2. **VERP addresses**: HMAC-**SHA3-224** truncated to 8 bytes, payload = compact JSON `[type,int,minutes_since_2022-01-01T00:00]`, base32 (RFC 4648, upper) with `=` padding stripped and final address `.lower()`; decoding re-adds padding `(8 - len%8) % 8`.
3. **Rate-limit strings**: flask-limiter grammar (`"10/minute"`, `"100/day;50/hour;5/minute"`). Default in-memory storage per process; key is `ip:{ip}` for API-key requests except aliases/options routes which key on `g.user.id`. Exceeding returns HTTP 429.
4. **Redis fixed-window buckets** for alias create/restore: window id = `unix_time - (unix_time % bucket_seconds)`; key `bl:{name}:{bucket_id}`; INCR with TTL = bucket_seconds; raise 429 above max hits. **Fail-open** when Redis is unavailable/not configured.
5. **Datetime formats**: models use `arrow`; API serializers emit either `alias.created_at.timestamp` (int epoch) or `str(arrow)`/`.format()` per-route — see the alias/contact specs. `ApiKey.last_used = arrow.now()` is stored as timestamptz; arrow default string format is `YYYY-MM-DD HH:mm:ssZZ` (e.g. `2023-05-01 14:03:22+00:00`) when `str()` is used.
6. **`literal_eval` config parsing** means Workers env vars for list-typed settings must be JSON-ish Python literals; presence-based flags must be modeled as "defined vs undefined", not truthiness.
7. `FLASK_SECRET` is the root of nearly every derived secret (`+ "mailbox"`, `+ "custom_alias"`, `+ "unsub"`, `+ "pleasegenerateagoodrandomtoken"`, `+ "aliastransfertoken"`, `+ "partnerapitoken"`, `+ "generatearandomtoken"`, `+ "enckey"/"mackey"/"absalt"`). Rotating it invalidates signed suffixes, mfa_keys, unsubscribe links, VERP addresses (if `VERP_EMAIL_SECRET` unset) and recovery-code HMACs simultaneously.
8. Status **440** (non-standard) for sudo expiry must be returned verbatim; clients depend on it.
9. `ALIAS_RANDOM_SUFFIX_LENGTH` env var is spelled `ALIAS_RAND_SUFFIX_LENGTH`. `MAX_ALIAS_PER_DIRECTORY` does not exist; the directory cap is `MAX_NB_DIRECTORY = 50` (count of directories, not aliases per directory).
10. The free-plan-limit error message interpolates `MAX_NB_EMAIL_FREE_PLAN` even when the user's actual cap is `MAX_NB_EMAIL_OLD_FREE_PLAN` (15).
