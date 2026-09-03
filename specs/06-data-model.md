# 06 — Data Model Spec (SimpleLogin → Cloudflare D1)

Source of truth: `app/models.py` (4198 lines),
`app/pw_models.py` (User password columns),
`app/utils.py` (random string helpers),
`app/email_utils.py` (reverse-alias generation).

This document lists the complete schema for every table needed by the REST API and the
email-forwarding pipeline, followed by a full SQLite (Cloudflare D1) DDL translation.

---

## 0. Base model columns (`ModelMixin`, models.py L66-156)

Every table below (except `admin_audit_log`, which is not needed here) inherits:

| column | PG type | nullable | default | notes |
|---|---|---|---|---|
| `id` | `INTEGER` | NO | autoincrement | primary key |
| `created_at` | `ArrowType` (= `TIMESTAMP WITHOUT TIME ZONE`) | NO | **client-side** `arrow.utcnow` | NO server default in Postgres — the app always supplies it |
| `updated_at` | `ArrowType` | YES | `None`, `onupdate=arrow.utcnow` | **client-side** onupdate: SQLAlchemy sets it on every UPDATE; the DB does not |

### Datetime storage (`ArrowType`)

- `sqlalchemy_utils.ArrowType` has `impl = sa.types.DateTime` (no `timezone=True`), so in Postgres
  every ArrowType column is `timestamp without time zone` holding a **naive UTC** datetime
  (ArrowType converts to UTC on bind, and `arrow.get(naive)` assumes UTC on read).
- arrow version is pinned to **0.16.0** (`pyproject.toml`: `arrow ~= 0.16.0`), which means:
  - `arrow_obj.timestamp` is a **property returning int epoch seconds** (not a method).
    All API fields named `*_timestamp` (e.g. `creation_timestamp`, `trial_end_timestamp`,
    `last_email_sent_timestamp`) are this int.
  - `arrow_obj.format()` (no args) returns the default format `YYYY-MM-DD HH:mm:ssZZ`,
    e.g. `"2020-04-06 17:57:38+00:00"`. All API fields named `*_date`
    (`creation_date`, `last_email_sent_date`) are exactly this string.
  - `notification.created_at.humanize()` is used by the notification API ("2 hours ago").

**D1 decision: store all ArrowType columns as `TEXT` in exactly the format
`YYYY-MM-DD HH:MM:SS+00:00` (ISO-8601-ish, UTC, second precision — identical to arrow's
default `.format()` output).** Rationale:

- API `*_date` fields can be returned verbatim from the column.
- API `*_timestamp` fields = `Math.floor(Date.parse(value.replace(' ', 'T')) / 1000)`.
- The format is lexicographically sortable and comparable (constant `+00:00` suffix),
  so `WHERE created_at > ?` / `ORDER BY created_at` keep working.
- Precision loss vs Postgres (microseconds) only matters for ordering rows created in the
  same second — always add `id` as tiebreaker in `ORDER BY` (the Python code already
  paginates with `id` tiebreakers in the hot paths).
- Generate with `strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'` (SQL) or in the Worker.

`subscription.next_bill_date` is a plain `sa.Date` (**date, not timestamp**) → store as
`TEXT 'YYYY-MM-DD'`. Paddle grace-period comparison is done at date granularity.

Booleans → `INTEGER` 0/1. `sa.JSON` → `TEXT` containing JSON. `BigInteger` → `INTEGER`
(SQLite ints are 64-bit). `LargeBinary` → `BLOB`. Postgres `TSVECTOR` / trigram-GIN
indexes have no SQLite equivalent — drop them (see notes per table).

---

## 1. Enums (all `EnumE` subclasses, models.py L203-298)

Values are exact — clients and DB rows depend on them.

| Enum | members |
|---|---|
| `PlanEnum` | `monthly = 2`, `yearly = 3`. **Stored by NAME** (`'monthly'`/`'yearly'`) in `subscription.plan` and `apple_subscription.plan` because they use `sa.Enum(PlanEnum)` (native PG enum on names). |
| `SenderFormatEnum` | `AT = 0` ("John Wick - john at wick.com"), `A = 2` ("John Wick - john(a)wick.com"), `NAME_ONLY = 5`, `AT_ONLY = 6`, `NO_NAME = 7`. Note: 1, 3, 4 are unused/legacy. Stored as plain INTEGER in `users.sender_format`. |
| `AliasGeneratorEnum` | `word = 1`, `uuid = 2` (users.alias_generator, plain INTEGER) |
| `AliasSuffixEnum` | `word = 0`, `random_string = 1` (users.random_alias_suffix, plain INTEGER) |
| `BlockBehaviourEnum` | `return_2xx = 0`, `return_5xx = 1`. **Stored by NAME** (`'return_2xx'`/`'return_5xx'`) in `users.block_behaviour` (native PG enum), server default `'return_2xx'`. |
| `UnsubscribeBehaviourEnum` | `DisableAlias = 0`, `BlockContact = 1`, `PreserveOriginal = 2`. Stored as INTEGER via `IntEnumType` in `users.unsub_behaviour`. |
| `AliasDeleteReason` | `Unspecified = 0`, `UserHasBeenDeleted = 1`, `ManualAction = 2`, `DirectoryDeleted = 3`, `MailboxDeleted = 4`, `CustomDomainDeleted = 5` (INTEGER via IntEnumType) |
| `UserAliasDeleteAction` | `MoveToTrash = 0`, `DeleteImmediately = 1` (INTEGER) |
| `JobState` | `ready = 0`, `taken = 1`, `done = 2`, `error = 3` (INTEGER in job.state) |
| `JobPriority` | `Low = 1`, `Default = 50`, `High = 100` (INTEGER in job.priority) |
| `Phase` | `unknown = 0`, `forward = 1`, `reply = 2` |
| `VerpType` | `bounce_forward = 0`, `bounce_reply = 1`, `transactional = 2` |

`IntEnumType` (L300) is a TypeDecorator over `sa.Integer`: binds `enum.value`, reads back
`Enum(value)` — plain integers in the DB.

---

## 2. `users` (class `User`, L407-1291; password column from `PasswordOracle`)

Bit flags (class constants):
- `FLAG_FREE_DISABLE_CREATE_CONTACTS = 1` (1 << 0)
- `FLAG_CREATED_FROM_PARTNER = 2` (1 << 1)
- `FLAG_FREE_OLD_ALIAS_LIMIT = 4` (1 << 2)
- `FLAG_CREATED_ALIAS_FROM_PARTNER = 8` (1 << 3)

"default" = Python/ORM-side default (applied by app code); "server default" = DDL default.
When they differ, rows written through the ORM get the Python default — **replicate the
Python default in the Worker code**, keep the server default only for DDL fidelity.

| column | PG type | nullable | default (python) | server default | unique/index | FK |
|---|---|---|---|---|---|---|
| id / created_at / updated_at | (base) | | | | | |
| `password` | VARCHAR(128) | YES | — | — | | (bcrypt hash; password is NFKC-normalized before bcrypt — pw_models.py) |
| `email` | VARCHAR(256) | NO | — | — | UNIQUE | |
| `name` | VARCHAR(128) | YES | — | — | | |
| `is_admin` | BOOLEAN | NO | False | — | | |
| `alias_generator` | INTEGER | NO | 1 (`AliasGeneratorEnum.word`) | `'1'` | | |
| `notification` | BOOLEAN | NO | True | `'1'` | | |
| `activated` | BOOLEAN | NO | False | — | | |
| `disabled` | BOOLEAN | NO | False | `'0'` | | |
| `profile_picture_id` | INTEGER | YES | — | — | ix_users_profile_picture_id | file.id |
| `otp_secret` | VARCHAR(16) | YES | — | — | | (TOTP secret, base32) |
| `enable_otp` | BOOLEAN | NO | False | `'0'` | | |
| `last_otp` | VARCHAR(12) | YES | `False` (quirk; effectively NULL/'false') | — | | (stores last accepted TOTP code to prevent reuse) |
| `fido_uuid` | VARCHAR | YES | — | — | UNIQUE | (referenced by fido.uuid FK) |
| `default_alias_custom_domain_id` | INTEGER | YES | None | — | ix_users_default_alias_custom_domain_id | custom_domain.id ON DELETE SET NULL |
| `default_alias_public_domain_id` | INTEGER | YES | None | — | | public_domain.id ON DELETE SET NULL |
| `lifetime` | BOOLEAN | NO | False | `'0'` | | |
| `paid_lifetime` | BOOLEAN | NO | False | `'0'` | | |
| `lifetime_coupon_id` | INTEGER | YES | None | — | | lifetime_coupon.id ON DELETE SET NULL |
| `trial_end` | ArrowType | YES | `arrow.now().shift(days=7, hours=1)` | — | part of ix_users_activated_trial_end_lifetime | |
| `default_mailbox_id` | INTEGER | YES | None | — | ix_users_default_mailbox_id | mailbox.id (no ondelete) |
| `sender_format` | INTEGER | NO | 0 (`SenderFormatEnum.AT`) | `'0'` | | |
| `sender_format_updated_at` | ArrowType | YES | None | — | | |
| `replace_reverse_alias` | BOOLEAN | NO | False | `'0'` | | |
| `referral_id` | INTEGER | YES | None | — | index | referral.id ON DELETE SET NULL |
| `intro_shown` | BOOLEAN | NO | False | `'0'` | | |
| `max_spam_score` | INTEGER | YES | — | — | | |
| `newsletter_alias_id` | INTEGER | YES | None | — | index | alias.id ON DELETE SET NULL |
| `include_sender_in_reverse_alias` | BOOLEAN | NO | **True** | `'0'` (differs!) | | |
| `random_alias_suffix` | INTEGER | NO | **0** (`AliasSuffixEnum.word`) | `'1'` (random_string — differs!) | | |
| `expand_alias_info` | BOOLEAN | NO | False | `'0'` | | |
| `ignore_loop_email` | BOOLEAN | NO | False | `'0'` | | |
| `alternative_id` | VARCHAR(128) | YES | — (set to `str(uuid4())` in `User.create`) | — | UNIQUE | |
| `disable_automatic_alias_note` | BOOLEAN | NO | False | `'0'` | | |
| `one_click_unsubscribe_block_sender` | BOOLEAN | NO | False | `'0'` | | |
| `include_website_in_one_click_alias` | BOOLEAN | NO | **True** | `'0'` (differs!) | | |
| `directory_quota` | INTEGER | NO | 50 | `'50'` | | (attr `_directory_quota`) |
| `subdomain_quota` | INTEGER | NO | 5 | `'5'` | | (attr `_subdomain_quota`) |
| `disable_import` | BOOLEAN | NO | False | `'0'` | | |
| `can_use_phone` | BOOLEAN | NO | False | `'0'` | | |
| `phone_quota` | INTEGER | YES | — | — | | |
| `block_behaviour` | PG ENUM `blockbehaviourenum` | NO | — | `'return_2xx'` | | **stored as name string** |
| `include_header_email_header` | BOOLEAN | NO | True | `'1'` | | |
| `enable_data_breach_check` | BOOLEAN | NO | False | `'0'` | | |
| `flags` | BIGINT | NO | **1** (`FLAG_FREE_DISABLE_CREATE_CONTACTS`) | `'0'` (differs!) | | |
| `unsub_behaviour` | INTEGER (IntEnumType) | NO | **2** (`PreserveOriginal`) | `'0'` (`DisableAlias` — differs!) | | |
| `delete_on` | ArrowType | YES | None | ix_users_delete_on | | |
| `alias_delete_action` | INTEGER (IntEnumType) | NO | 0 (`MoveToTrash`) | `'0'` | | |

Composite index: `ix_users_activated_trial_end_lifetime (activated, trial_end, lifetime)`.
Postgres-only: `idx_users_email_trgm` GIN trigram index on email (drop in D1; used for admin search only).

### 2.1 User creation side effects (`User.create`, L691-767)
1. `email = sanitize_email(email)` (strip, remove spaces, lowercase, strip `‏`), `name` truncated to 100 chars.
2. Creates a verified `Mailbox(user_id, email=user.email, verified=True)` and sets `default_mailbox_id`.
3. `alternative_id = str(uuid.uuid4())` if not given.
4. Emits user audit log `CreateUser`.
5. If `from_partner`: sets `FLAG_CREATED_FROM_PARTNER`, `notification=False`, `trial_end=None`, enqueues `SEND_PROTON_WELCOME_1` job, returns (no newsletter alias, no onboarding).
6. Otherwise creates first alias with prefix `simplelogin-newsletter`, note "This is your first alias. It's used to receive SimpleLogin communications like new features announcements, newsletters.", sets `newsletter_alias_id`, and (unless `config.DISABLE_ONBOARDING`) schedules `ONBOARDING_1/2/4` jobs at +1/+2/+3 days.

### 2.2 Plan/premium logic (exact)

Grace constants: `PADDLE_SUBSCRIPTION_GRACE_DAYS = 14`, `_PARTNER_SUBSCRIPTION_GRACE_DAYS = 14`, `_APPLE_GRACE_PERIOD_DAYS = 16`.

- `get_paddle_subscription()` (L1037): `Subscription.get_by(user_id)`; active iff
  `sub.next_bill_date >= (now - 14 days).date()` (a **date** comparison). Else None.
  Note: `cancelled` does NOT matter — a cancelled sub is active until next_bill_date + 14d.
- `AppleSubscription.is_valid()`: `expires_date > now - 16 days`.
- `ManualSubscription.is_active()`: `end_at > now`.
- `CoinbaseSubscription.is_active()`: `end_at > now`.
- `PartnerSubscription.is_active()`: `lifetime OR end_at > now - 14 days`.
  `PartnerSubscription.find_by_user_id(user_id)` joins `partner_subscription.partner_user_id = partner_user.id AND partner_user.user_id = :user_id`.
- `get_active_subscription(include_partner_subscription=True)` (L790): checked **in order**
  Paddle → Apple → Manual → Coinbase → Partner (if included); first active wins.
- `get_active_subscription_end()`: Paddle → `arrow.get(next_bill_date)`; Apple → `expires_date`; Manual/Coinbase → `end_at`; Partner → **None**.
- `lifetime_or_active_subscription()`: `self.lifetime OR get_active_subscription() is not None`.
- `in_trial()` (L870): `NOT lifetime_or_active_subscription() AND trial_end is not None AND now < trial_end`.
- `is_premium(include_partner_subscription=True)` (L886): `lifetime_or_active_subscription(...) OR (trial_end AND now < trial_end)`.
- `is_paid()` (L854): active sub exists AND NOT (it is a ManualSubscription with `is_giveaway`).
- `is_active()` (L865): `delete_on is None OR delete_on < now` (yes — a *future* delete_on makes user inactive... note: `delete_on < arrow.now()` returns True when the scheduled time has passed; i.e. user with pending future deletion is **inactive**? No: if delete_on is in the future, `delete_on < now` is False → is_active() False. Copy this literally.)
- `can_send_or_receive()` (L990): False if `disabled` or `delete_on is not None`.

### 2.3 Alias limits

- `max_alias_for_free_account()` (L957): if `flags & FLAG_FREE_OLD_ALIAS_LIMIT` →
  `config.MAX_NB_EMAIL_OLD_FREE_PLAN` (default **15**), else `config.MAX_NB_EMAIL_FREE_PLAN`
  (env `MAX_NB_EMAIL_FREE_PLAN`, default **5**).
- `can_create_new_alias()` = `can_create_num_aliases(1)` (L973): False if not `is_active()`
  or `disabled`; True if `lifetime_or_active_subscription()`; otherwise
  `count(alias WHERE user_id=? AND delete_on IS NULL) + n <= max_alias_for_free_account()`.
  Note: trash-deleted aliases (delete_on set) do NOT count; the free limit applies **even during trial**.
- `Alias.create` rate limit (L1790-1804): if `user.is_premium() and not user.in_trial()` use
  `config.ALIAS_CREATE_RATE_LIMIT_PAID` = `[(50, 900), (200, 3600)]` else
  `ALIAS_CREATE_RATE_LIMIT_FREE` = `[(10, 900), (50, 3600)]` — list of (hits, window-seconds)
  buckets keyed `alias_create_{window}:{user_id}` (Redis in Python; use DO/KV counter in CF).
- Quota properties: `directory_quota = min(_directory_quota, 50 - count(directory WHERE user_id))`;
  `subdomain_quota = min(_subdomain_quota, 5 - count(custom_domain WHERE user_id AND is_sl_subdomain))`.
  Constants: `MAX_NB_DIRECTORY = 50`, `MAX_NB_SUBDOMAIN = 5` (config.py L142-143).
  Creating a Directory / SL-subdomain **decrements the stored quota column** by 1.
- `can_create_contacts()` (L1276): premium → True; `flags & FLAG_FREE_DISABLE_CREATE_CONTACTS == 0` → True; else `not config.DISABLE_CREATE_CONTACTS_FOR_FREE_USERS`.
- `get_random_alias_suffix(custom_domain=None)` (L1260): if `random_alias_suffix == 1`
  → `random_string(config.ALIAS_RANDOM_SUFFIX_LENGTH /*default 5*/, include_digits=True)`;
  else `random_words(1, 3)` (one dictionary word + 3 digits) or `random_words(1)` for a custom domain.
- `random_string(length=10, include_digits=False)`: lowercase ascii letters (+ digits if requested), `secrets.choice`.
- `random_words(words=2, numbers=0)`: words joined by `_`, followed by `numbers` random digits.

---

## 3. `alias` (class `Alias`, L1601-1955)

`FLAG_PARTNER_CREATED = 1` (1 << 0).

| column | PG type | nullable | default | server default | unique/index | FK |
|---|---|---|---|---|---|---|
| `user_id` | INTEGER | NO | — | — | index | users.id CASCADE |
| `email` | VARCHAR(128) | NO | — | — | UNIQUE | |
| `name` | VARCHAR(128) | YES | None | — | | (display name used when sending from alias) |
| `enabled` | BOOLEAN | NO | True | — | | |
| `flags` | BIGINT | NO | 0 | `'0'` | index | |
| `custom_domain_id` | INTEGER | YES | — | — | index | custom_domain.id CASCADE |
| `automatic_creation` | BOOLEAN | NO | False | `'0'` | | |
| `directory_id` | INTEGER | YES | — | — | index | directory.id CASCADE |
| `note` | TEXT | YES | None | — | (PG trgm+tsvector idx, drop) | |
| `mailbox_id` | INTEGER | NO | — | — | index | mailbox.id CASCADE |
| `disable_pgp` | BOOLEAN | NO | False | `'0'` | | |
| `cannot_be_disabled` | BOOLEAN | NO | False | `'0'` | | |
| `disable_email_spoofing_check` | BOOLEAN | NO | False | `'0'` | | |
| `batch_import_id` | INTEGER | YES | None | — | | batch_import.id SET NULL |
| `original_owner_id` | INTEGER | YES | — | — | ix_alias_original_owner_id | users.id SET NULL |
| `pinned` | BOOLEAN | NO | False | `'0'` | | |
| `transfer_token` | VARCHAR(64) | YES | None | — | UNIQUE | |
| `transfer_token_expiration` | ArrowType | YES | `arrow.utcnow` | — | | |
| `hibp_last_check` | ArrowType | YES | None | — | index | |
| `ts_vector` | TSVECTOR | — | generated `to_tsvector('english', note)` | — | GIN idx | **Postgres-only; DROP in D1** |
| `last_email_log_id` | INTEGER | YES | None | — | | (no FK; denormalized) |
| `delete_on` | ArrowType | YES | None | NULL | ix_alias_delete_on | (set = alias in trash) |
| `delete_reason` | INTEGER (IntEnumType AliasDeleteReason) | YES | None | NULL | | |

Behavior to preserve:
- `mailboxes` property: `[alias.mailbox (owner mailbox)] + alias_mailbox rows (excluding the owner)`, keep only `verified` mailboxes, **sorted by mailbox email**.
- `Alias.create` (L1790): sanitizes email; raises `AliasInTrashError` if email in `deleted_alias` **or** `domain_deleted_alias`; auto-detects custom domain from the alias domain part (`Alias.get_custom_domain`: only if the domain is NOT an SLDomain); raises `AliasDomainForbidden` if the custom domain belongs to another user; sets `FLAG_PARTNER_CREATED` if the custom domain has `partner_id`; increments `daily_metric.nb_alias`; sets user flag `FLAG_CREATED_ALIAS_FROM_PARTNER` when applicable; emits alias audit log `CreateAlias` "New alias created".
- `Alias.create_new(user, prefix, ...)` (L1880): `prefix.lower().strip().replace(" ", "")`, then up to 1000 tries of `f"{prefix}.{suffix}@{config.FIRST_ALIAS_DOMAIN}"` until `available_sl_email` (not in alias.email, contact.reply_email, deleted_alias.email).
- `Alias.create_new_random` (L1906): uses default custom/public domain if set (public premium-only domains only for premium users), scheme word → `random_words(2, 3)@domain`, uuid → uuid4 string.
- `EmailLog.create` updates `alias.last_email_log_id` (raw SQL UPDATE).
- `Alias.delete` raises — deletion must go through `delete_alias()` flow which inserts into `deleted_alias`/`domain_deleted_alias`.

---

## 4. `contact` (class `Contact`, L2049-2254)

`MAX_NAME_LENGTH = 512`; `FLAG_PARTNER_CREATED = 1`.

| column | PG type | nullable | default | server default | unique/index | FK |
|---|---|---|---|---|---|---|
| `user_id` | INTEGER | NO | — | — | ix_contact_user_id_id (user_id,id) | users.id CASCADE |
| `alias_id` | INTEGER | NO | — | — | part of uq_contact | alias.id CASCADE |
| `name` | VARCHAR(512) | YES | None | `NULL` | | |
| `website_email` | VARCHAR(512) | NO | — | — | UNIQUE(alias_id, website_email) `uq_contact` | (the real sender/recipient address) |
| `website_from` | VARCHAR(1024) | YES | — | — | | (raw From header, e.g. `AB CD <ab@cd.com>`) |
| `reply_email` | VARCHAR(512) | NO | — | — | index | (**the reverse-alias**) |
| `is_cc` | BOOLEAN | NO | False | `'0'` | | |
| `pgp_public_key` | TEXT | YES | — | — | | |
| `pgp_finger_print` | VARCHAR(512) | YES | — | — | index | |
| `mail_from` | TEXT | YES | None | — | | (envelope MAIL FROM, debugging) |
| `invalid_email` | BOOLEAN | NO | False | `'0'` | | |
| `block_forward` | BOOLEAN | NO | False | `'0'` | | |
| `automatic_created` | BOOLEAN | **YES** | False | — | | |
| `flags` | INTEGER | NO | 0 | `'0'` | | |

- `Contact.create`: sanitizes `website_email`; if `website_email not in config.NOREPLIES`
  and an existing contact has `reply_email == website_email`, raises
  `CannotCreateContactForReverseAlias` (can't create a contact pointing at a reverse-alias).
- `email` property = `website_email`.

### 4.1 Reverse-alias (`reply_email`) generation — `generate_reply_email(contact_email, alias)` (email_utils.py L1322-1372)

1. `include_sender_in_reverse_alias = user.include_sender_in_reverse_alias` (bool column).
2. If including sender and contact_email non-empty: `contact_email.replace("@","_at_").replace(".","_")`,
   then `convert_to_id` (lowercase, unidecode, remove spaces, non-`[a-zA-Z0-9_-.]` → `_`, cap 64),
   `sanitize_email`, truncate to **45 chars**, `convert_to_alphanumeric`.
3. `reply_domain = config.EMAIL_DOMAIN`, **unless** the alias's own domain is an `SLDomain`
   with `use_as_reverse_alias = true`, in which case reply_domain = alias domain.
4. Up to 1000 attempts:
   - with sender: `f"{contact_email}_{random_string(random.randint(5,10))}@{reply_domain}"`
   - without: `f"{random_string(random.randint(20,50))}@{reply_domain}"`
   accept the first address passing `available_sl_email` (not an alias email, not another
   contact's reply_email, not a deleted alias email). Raise after 1000 failures.
   (`random_string` = lowercase a-z only here.)
5. Legacy reverse-aliases start with `reply+` or `ra+` — `is_reverse_alias()` checks the
   contact table first, then those prefixes on `EMAIL_DOMAIN`.

### 4.2 Sender-format rendering (needed by forwarding)

- `website_send_to()` (L2161): produces `"Name | john at wick.com" <reply_email>` (or `(a)`
  variant per user.sender_format; name parsed from `website_from` if column empty; `"`
  stripped from names).
- `new_addr()` (L2205): per `user.sender_format`: `NO_NAME` → bare reply_email;
  `NAME_ONLY` → contact.name; `AT_ONLY` → `john at wick.com`; `AT` → `Name - john at wick.com`;
  `A` → `Name - john(a)wick.com`; RFC-2047-encoded via `sl_formataddr`.

---

## 5. `email_log` (class `EmailLog`, L2257-2370)

| column | PG type | nullable | default | server default | unique/index | FK |
|---|---|---|---|---|---|---|
| `user_id` | INTEGER | NO | — | — | ix_email_log_user_id_email_log_id (user_id,id) | users.id CASCADE |
| `contact_id` | INTEGER | NO | — | — | index | contact.id CASCADE |
| `alias_id` | INTEGER | YES | — | — | index | alias.id CASCADE |
| `is_reply` | BOOLEAN | NO | False | — | | |
| `blocked` | BOOLEAN | NO | False | — | | |
| `bounced` | BOOLEAN | NO | False | `'0'` | | |
| `auto_replied` | BOOLEAN | NO | False | `'0'` | | |
| `is_spam` | BOOLEAN | NO | False | `'0'` | | |
| `spam_score` | FLOAT | YES | — | — | | |
| `spam_status` | TEXT | YES | None | — | | |
| `spam_report` | JSON | YES | — | — | | (deferred/lazy in ORM) |
| `refused_email_id` | INTEGER | YES | — | — | index | refused_email.id SET NULL |
| `mailbox_id` | INTEGER | YES | — | — | index | mailbox.id CASCADE |
| `bounced_mailbox_id` | INTEGER | YES | — | — | index | mailbox.id CASCADE |
| `message_id` | VARCHAR(1024) | YES | — | — | | truncated to **250 chars** in `create()` |
| `sl_message_id` | VARCHAR(512) | YES | — | — | | |

Extra index: `ix_email_log_created_at`. `EmailLog.create` flushes then runs
`UPDATE alias SET last_email_log_id = :el_id WHERE id = :alias_id` (call
`Alias.lock_for_update(alias_id)` first in Postgres to avoid deadlock — in D1 (single
writer) this is a plain UPDATE).
`get_action()`: `reply` if is_reply, else `bounced` if bounced, else `block` if blocked, else `forward`.
`get_phase()`: `reply` if is_reply else `forward`.

---

## 6. `mailbox` (class `Mailbox`, L2956-3091)

`FLAG_ADMIN_DISABLED = 1` (1 << 0).

| column | PG type | nullable | default | server default | unique/index | FK |
|---|---|---|---|---|---|---|
| `user_id` | INTEGER | NO | — | — | UNIQUE(user_id, email) `uq_mailbox_user` | users.id CASCADE |
| `email` | VARCHAR(256) | NO | — | — | index (+ PG trgm idx, drop) | |
| `verified` | BOOLEAN | NO | False | — | | |
| `force_spf` | BOOLEAN | NO | True | `'1'` | | |
| `new_email` | VARCHAR(256) | YES | — | — | UNIQUE | (pending email change) |
| `pgp_public_key` | TEXT | YES | — | — | | |
| `pgp_finger_print` | VARCHAR(512) | YES | — | — | index | |
| `disable_pgp` | BOOLEAN | NO | False | `'0'` | | |
| `nb_failed_checks` | INTEGER | NO | 0 | `'0'` | | |
| `disabled` | BOOLEAN | NO | False | `'0'` | | |
| `flags` | BIGINT | NO | 0 | `'0'` | | |
| `generic_subject` | VARCHAR(78) | YES | — | — | | |

- `pgp_enabled()` = `pgp_finger_print AND NOT disable_pgp`.
- `can_send_or_receive()` = not admin-disabled, not disabled, and `user.can_send_or_receive()`.
- `Mailbox.create` sanitizes email. Note: email is unique **per user**, not globally.
- `Mailbox.delete` reassigns aliases with multiple mailboxes, else trashes/deletes per `user.alias_delete_action`.

## 7. `alias_mailbox` (class `AliasMailbox`, L3215)

| column | type | nullable | FK | constraint |
|---|---|---|---|---|
| `alias_id` | INTEGER | NO | alias.id CASCADE | UNIQUE(alias_id, mailbox_id) `uq_alias_mailbox` |
| `mailbox_id` | INTEGER | NO | mailbox.id CASCADE, index | |

Holds *additional* mailboxes only; the primary one is `alias.mailbox_id`.

## 8. `api_key` (class `ApiKey`, L2558-2584)

| column | PG type | nullable | default | unique/index | FK |
|---|---|---|---|---|---|
| `user_id` | INTEGER | NO | — | ix_api_key_user_id | users.id CASCADE |
| `code` | VARCHAR(128) | NO | — | UNIQUE | |
| `name` | VARCHAR(128) | YES | — | | |
| `last_used` | ArrowType | YES | None | | |
| `times` | INTEGER | NO | 0 | | |
| `sudo_mode_at` | ArrowType | YES | None | | (set by PATCH /api/sudo; sudo valid `sudo_mode_at >= now - 5 minutes`) |

**Code generation** (`ApiKey.create`): `code = random_string(60)` — 60 chars of lowercase
`a-z` only (no digits). If that code already exists (checked via `get_by`), fall back to
`str(uuid.uuid4())`. Auth lookups are exact-match on `code`.

## 9. `account_activation` (L3104-3121)

| column | PG type | nullable | default | unique | FK |
|---|---|---|---|---|---|
| `user_id` | INTEGER | NO | — | UNIQUE | users.id CASCADE |
| `code` | VARCHAR(10) | NO | — | | (6-digit numeric string in practice) |
| `tries` | INTEGER | NO | 3 | | CHECK `tries >= 0` (`account_activation_tries_positive`) |

## 10. `reset_password_code` (L1328-1343)

| column | PG type | nullable | default | unique/index | FK |
|---|---|---|---|---|---|
| `user_id` | INTEGER | NO | — | ix_reset_password_code_user_id | users.id CASCADE |
| `code` | VARCHAR(128) | NO | — | UNIQUE | |
| `expired` | ArrowType | NO | now + **1 hour** | | `is_expired()` = expired < now |

(Related: `activation_code` — same shape, expiry now + 1h, for web account activation;
`email_change` — user_id UNIQUE, new_email UNIQUE VARCHAR(256), code UNIQUE VARCHAR(128), expired default now + **12h**;
`mailbox_activation` — mailbox_id FK CASCADE index, code VARCHAR(32) index, tries INTEGER default 0.)

## 11. `custom_domain` (class `CustomDomain`, L2587-2722)

| column | PG type | nullable | default | server default | unique/index | FK |
|---|---|---|---|---|---|---|
| `user_id` | INTEGER | NO | — | — | ix_custom_domain_user_id | users.id CASCADE |
| `domain` | VARCHAR(128) | NO | — | — | UNIQUE (plus PG partial unique idx `ix_unique_domain` WHERE ownership_verified) | |
| `name` | VARCHAR(128) | YES | None | — | | (default display name for aliases) |
| `verified` | BOOLEAN | NO | False | — | | (MX verified) |
| `dkim_verified` | BOOLEAN | NO | False | `'0'` | | |
| `spf_verified` | BOOLEAN | NO | False | `'0'` | | |
| `dmarc_verified` | BOOLEAN | NO | False | `'0'` | | |
| `catch_all` | BOOLEAN | NO | False | `'0'` | | |
| `random_prefix_generation` | BOOLEAN | NO | False | `'0'` | | |
| `nb_failed_checks` | INTEGER | NO | 0 | `'0'` | | |
| `ownership_verified` | BOOLEAN | NO | False | `'0'` | | |
| `ownership_txt_token` | VARCHAR(128) | YES | — (set to `random_string(30)` on create) | — | | TXT record `sl-verification=<token>` |
| `is_sl_subdomain` | BOOLEAN | NO | False | `'0'` | | |
| `partner_id` | INTEGER | YES | None | NULL | | partner.id (no ondelete) |
| `pending_deletion` | BOOLEAN | NO | False | `'0'` | ix_custom_domain_pending_deletion | |

- `mailboxes` property: rows via `domain_mailbox`, else `[user.default_mailbox]`.
- `create()`: strips `\n` from domain; raises `SubdomainInTrashError` if in `deleted_subdomain`; creating an SL subdomain decrements `users.subdomain_quota`.

Association table `domain_mailbox`: `domain_id` FK custom_domain.id CASCADE NOT NULL,
`mailbox_id` FK mailbox.id CASCADE NOT NULL, UNIQUE(domain_id, mailbox_id) `uq_domain_mailbox`.

Catch-all auto-create rules: `auto_create_rule` (custom_domain_id FK CASCADE NOT NULL,
`regex` VARCHAR(512) NOT NULL, `order` INTEGER NOT NULL default 0, `display_name`
VARCHAR(128) NULL, UNIQUE(custom_domain_id, "order") `uq_auto_create_rule_order`) and
`auto_create_rule__mailbox` (auto_create_rule_id FK CASCADE, mailbox_id FK CASCADE,
UNIQUE pair `uq_auto_create_rule_mailbox`).

## 12. `public_domain` (class `SLDomain`, L3400-3435)

| column | PG type | nullable | default | server default | unique | FK |
|---|---|---|---|---|---|---|
| `domain` | VARCHAR(128) | NO | — | — | UNIQUE | |
| `premium_only` | BOOLEAN | NO | False | `'0'` | | |
| `can_use_subdomain` | BOOLEAN | NO | False | `'0'` | | |
| `partner_id` | INTEGER | YES | None | NULL | | partner.id CASCADE |
| `hidden` | BOOLEAN | NO | False | `'0'` | | (hidden domains never offered for new aliases) |
| `order` | INTEGER | NO | 0 | `'0'` | | (sort key; note: reserved word in SQL) |
| `use_as_reverse_alias` | BOOLEAN | NO | False | `'0'` | | (see reverse-alias generation) |

`User.get_sl_domains()` (L1194) — exact selection logic for suggesting domains:
`hidden == false AND (
  (id = user.default_alias_public_domain_id [AND premium_only = false if not premium]) OR
  (partner_id = <user's partner> [AND premium_only = false unless partner-premium]) — only when alias_options.show_partner_domains OR
  (partner_id IS NULL [AND premium_only = false if not premium]) — when show_sl_domains (default true)
) ORDER BY "order"`.

## 13. `deleted_alias` (L2489-2510) and `domain_deleted_alias` (L2777-2815)

`deleted_alias` (global trash — blocks reuse of any alias email forever):

| column | PG type | nullable | default | unique/index |
|---|---|---|---|---|
| `email` | VARCHAR(256) | NO | — | UNIQUE |
| `reason` | INTEGER (AliasDeleteReason) | NO | 0 | server `'0'` |
| `alias_id` | INTEGER | YES | None | index (no FK) |

`domain_deleted_alias` (per-custom-domain trash; deleted aliases of a custom domain go
here instead so the domain owner can restore them):

| column | PG type | nullable | default | unique/index | FK |
|---|---|---|---|---|---|
| `email` | VARCHAR(256) | NO | — | UNIQUE(domain_id, email) `uq_domain_trash` | |
| `domain_id` | INTEGER | NO | — | | custom_domain.id CASCADE |
| `user_id` | INTEGER | NO | — | index | users.id CASCADE |
| `reason` | INTEGER | NO | 0 | server `'0'` | |
| `alias_id` | INTEGER | YES | None | index (no FK) | |

Both classes override `create()` to raise — rows are inserted only by the
`delete_alias()` flow (raw inserts). `Alias.create` checks BOTH tables and raises
`AliasInTrashError` on a hit.

## 14. `directory` (L2856-2912) and `directory_mailbox` (L3253)

`directory`: `user_id` FK users.id CASCADE NOT NULL (index), `name` VARCHAR(128) UNIQUE NOT NULL,
`disabled` BOOLEAN NOT NULL default False server `'0'`.
- `create()` raises `DirectoryInTrashError` if name in `deleted_directory`; decrements `users.directory_quota`.
- `mailboxes` property: via `directory_mailbox`, else `[user.default_mailbox]`.
- On-the-fly alias `name.something@directory-domain` is created during forwarding when directory not disabled.

`directory_mailbox`: `directory_id` FK CASCADE NOT NULL, `mailbox_id` FK CASCADE NOT NULL,
UNIQUE(directory_id, mailbox_id) `uq_directory_mailbox`.

Also `deleted_directory` (`name` VARCHAR(128) UNIQUE NOT NULL) and `deleted_subdomain`
(`domain` VARCHAR(128) UNIQUE NOT NULL) block reuse.

## 15. `notification` (L3343)

| column | PG type | nullable | default | index | FK |
|---|---|---|---|---|---|
| `user_id` | INTEGER | NO | — | index | users.id CASCADE |
| `message` | TEXT | NO | — | | (HTML) |
| `title` | VARCHAR(512) | YES | — | | |
| `read` | BOOLEAN | NO | False | | |

API returns `created_at` via `.humanize()` (relative string, e.g. "2 hours ago") — implement arrow-compatible humanize.

## 16. `api_cookie_token` (class `ApiToCookieToken`, L4091)

| column | PG type | nullable | default | unique/index | FK |
|---|---|---|---|---|---|
| `code` | VARCHAR(128) | NO | `secrets.token_urlsafe(32)` (43-char base64url) | UNIQUE | |
| `user_id` | INTEGER | NO | — | index | users.id CASCADE |
| `api_key_id` | INTEGER | NO | — | index | api_key.id CASCADE |

## 17. `recovery_code` (L3288-3340)

| column | PG type | nullable | default | unique | FK |
|---|---|---|---|---|---|
| `user_id` | INTEGER | NO | — | UNIQUE(user_id, code) `uq_recovery_code` | users.id CASCADE |
| `code` | VARCHAR(64) | NO | — | | **HMAC digest, not raw code** |
| `used` | BOOLEAN | NO | False | | |
| `used_at` | ArrowType | YES | None | | |

Hashing: `base64.urlsafe_b64encode(hmac.new(RECOVERY_CODE_HMAC_SECRET, code, "sha3_224").digest()).rstrip("=")`.
Generation: delete all existing, create **8** codes, each raw code = `random_string(8)` (lowercase a-z).

## 18. TOTP / FIDO

TOTP lives on `users`: `otp_secret` (VARCHAR(16)), `enable_otp` (bool), `last_otp`
(VARCHAR(12), last accepted code — checked to prevent replay). FIDO: `users.fido_uuid`
(VARCHAR UNIQUE, nullable) + `fido` table (L353-373):

| column | PG type | nullable | unique/index | FK |
|---|---|---|---|---|
| `credential_id` | VARCHAR | NO | UNIQUE, index | |
| `uuid` | VARCHAR | NO | | **FK → users.fido_uuid** (non-PK FK!) ON DELETE CASCADE |
| `public_key` | VARCHAR | NO | UNIQUE | |
| `sign_count` | BIGINT | NO | | |
| `name` | VARCHAR(128) | NO | | |
| `user_id` | INTEGER | YES | ix_fido_user_id | users.id CASCADE |
| `credential_type` | VARCHAR(32) | YES | | |
| `authenticator_attachment` | VARCHAR(32) | YES | | |
| `transports` | JSON | YES | | e.g. `["usb","nfc"]` |
| `aaguid` | VARCHAR(36) | YES | | |

`user.two_factor_authentication_enabled()` = `enable_otp OR fido_uuid IS NOT NULL`.

## 19. `alias_used_on` (L2537)

`alias_id` FK alias.id CASCADE NOT NULL, `user_id` FK users.id CASCADE NOT NULL (index),
`hostname` VARCHAR(1024) NOT NULL; UNIQUE(alias_id, hostname) `uq_alias_used`.

## 20. `refused_email` (L3124-3152)

| column | PG type | nullable | default | unique/index | FK |
|---|---|---|---|---|---|
| `full_report_path` | VARCHAR(128) | NO | — | UNIQUE | (S3 path → R2 in CF) |
| `path` | VARCHAR(128) | YES | — | UNIQUE | |
| `user_id` | INTEGER | NO | — | index | users.id CASCADE |
| `delete_at` | ArrowType | NO | now + **7 days** | | |
| `deleted` | BOOLEAN | NO | False, server `'0'` | | |

## 21. `job` (L2915-2953) — referenced by API (account deletion, alias/mailbox jobs)

| column | PG type | nullable | default | server default |
|---|---|---|---|---|
| `name` | VARCHAR(128) | NO | — | — |
| `payload` | JSON | YES | — | — |
| `taken` | BOOLEAN | NO | False | — |
| `run_at` | ArrowType | YES | — | — |
| `state` | INTEGER | NO | 0 (ready) | `'0'` |
| `attempts` | INTEGER | NO | 0 | `'0'` |
| `taken_at` | ArrowType | YES | — | — |
| `priority` | INTEGER (JobPriority) | NO | 50 (Default) | `'50'` |

Index: `ix_state_run_at_taken_at_priority_attempts (state, run_at, taken_at, priority, attempts)`.

## 22. Subscription tables

### 22.1 `subscription` (Paddle, L2373-2402)
| column | PG type | nullable | default | unique | FK |
|---|---|---|---|---|---|
| `cancel_url` | VARCHAR(1024) | NO | — | | |
| `update_url` | VARCHAR(1024) | NO | — | | |
| `subscription_id` | VARCHAR(1024) | NO | — | UNIQUE | (Paddle id) |
| `event_time` | ArrowType | NO | — | | |
| `next_bill_date` | **DATE** | NO | — | | store TEXT `YYYY-MM-DD` |
| `cancelled` | BOOLEAN | NO | False | | |
| `plan` | PG ENUM `planenum` | NO | — | | **stored as `'monthly'`/`'yearly'`** |
| `user_id` | INTEGER | NO | — | UNIQUE | users.id CASCADE |

### 22.2 `apple_subscription` (L2460-2486)
`user_id` FK CASCADE NOT NULL UNIQUE; `expires_date` ArrowType NOT NULL;
`original_transaction_id` VARCHAR(256) NOT NULL UNIQUE; `receipt_data` TEXT NOT NULL;
`plan` ENUM (`'monthly'`/`'yearly'`) NOT NULL; `product_id` VARCHAR(256) NULL.
`is_valid()` = `expires_date > now - 16 days`.

### 22.3 `manual_subscription` (L2405-2430)
`user_id` FK CASCADE NOT NULL UNIQUE; `end_at` ArrowType NOT NULL; `comment` TEXT NULL;
`is_giveaway` BOOLEAN NOT NULL default False server `'0'`. `is_active()` = `end_at > now`.

### 22.4 `coinbase_subscription` (L2433-2453)
`user_id` FK CASCADE NOT NULL UNIQUE; `end_at` ArrowType NOT NULL; `code` VARCHAR(64) NULL.
`is_active()` = `end_at > now`.

### 22.5 `partner`, `partner_user`, `partner_subscription` (L3372, L3994, L4020)
- `partner`: `name` VARCHAR(128) UNIQUE NOT NULL; `contact_email` VARCHAR(128) UNIQUE NOT NULL.
- `partner_user`: `user_id` FK users.id CASCADE **UNIQUE** NOT NULL (index); `partner_id` FK partner.id CASCADE NOT NULL; `external_user_id` VARCHAR(128) NOT NULL; `partner_email` VARCHAR(255) NULL; UNIQUE(partner_id, external_user_id) `uq_partner_id_external_user_id`.
- `partner_subscription`: `partner_user_id` FK partner_user.id CASCADE NOT NULL UNIQUE; `end_at` ArrowType **NULL** (index); `lifetime` BOOLEAN NOT NULL default False server `'0'`. `is_active()` = `lifetime OR end_at > now - 14 days`.

## 23. Other forwarding-support tables (brief)

- `authorized_address`: user_id FK CASCADE NOT NULL (index), mailbox_id FK CASCADE NOT NULL, email VARCHAR(256) NOT NULL; UNIQUE(mailbox_id, email) `uq_authorize_address`. Extra addresses allowed to send via a mailbox's reverse-aliases.
- `message_id_matching`: `sl_message_id` VARCHAR(512) UNIQUE NOT NULL, `original_message_id` VARCHAR(1024) UNIQUE NOT NULL, `email_log_id` FK email_log.id CASCADE NULL (index). Maps SL Message-IDs ↔ original for threading in replies.
- `sent_alert`: user_id FK CASCADE NOT NULL, `to_email` VARCHAR(256) NOT NULL, `alert_type` VARCHAR(256) NOT NULL (all three indexed). Rate-limits abuse/bounce alert emails.
- `bounce`: `email` VARCHAR(256) NOT NULL (index), `info` TEXT NULL; index on created_at (7-day retention).
- `transactional_email`: `email` VARCHAR(256) NOT NULL; index on created_at; rows only written when `config.STORE_TRANSACTIONAL_EMAILS` (7-day retention).
- `ignored_email`: `mail_from` VARCHAR(512) NOT NULL, `rcpt_to` VARCHAR(512) NOT NULL — matching messages silently accepted+dropped.
- `ignore_bounce_sender`: `mail_from` VARCHAR(512) UNIQUE NOT NULL.
- `file`: `path` VARCHAR(128) UNIQUE NOT NULL, `user_id` FK users.id CASCADE NULL (index) — S3/R2 object registry (profile pictures, batch imports).
- `batch_import`: user_id FK CASCADE NOT NULL (index), file_id FK file.id CASCADE NOT NULL (index), processed BOOLEAN NOT NULL default False, summary TEXT NULL.
- `referral`: user_id FK CASCADE NOT NULL (index), name VARCHAR(512) NULL, code VARCHAR(128) UNIQUE NOT NULL (FK target of users.referral_id).
- `lifetime_coupon`: code VARCHAR(128) UNIQUE NOT NULL, nb_used INTEGER NOT NULL, paid BOOLEAN NOT NULL default False server `'0'`, comment TEXT NULL (FK target of users.lifetime_coupon_id).
- `hibp`: name VARCHAR UNIQUE NOT NULL (index), description TEXT, date ArrowType NULL. `alias_hibp`: alias_id FK CASCADE, hibp_id FK CASCADE (index), UNIQUE(alias_id, hibp_id).
- `activation_code` / `email_change` / `mailbox_activation`: see section 10.

---

## 24. Complete SQLite (Cloudflare D1) DDL

Conventions used below:
- All timestamps: `TEXT` in `YYYY-MM-DD HH:MM:SS+00:00` (UTC, second precision — arrow's default `.format()`), except `subscription.next_bill_date` (`TEXT 'YYYY-MM-DD'`).
- Booleans: `INTEGER NOT NULL DEFAULT 0/1` (0=false, 1=true).
- Postgres native enums (`users.block_behaviour`, `subscription.plan`, `apple_subscription.plan`) stay **TEXT storing the enum NAME** with CHECK constraints, to keep data 1:1 with production.
- `DEFAULT` clauses replicate the *Python* default where server/Python defaults differ (the Worker is the only writer, so this matches production row values). Where the DDL default cannot express a dynamic value (e.g. `trial_end = now + 7d1h`, generated codes), the Worker must set it — marked `-- app-set`.
- The Python-side `created_at`/`updated_at` are given SQL defaults for safety; the Worker should still set `updated_at` on every UPDATE (SQLite has no ON UPDATE).
- Dropped (Postgres-only): `alias.ts_vector` + GIN indexes, trigram indexes `idx_users_email_trgm`, `note_pg_trgm_index`, `ix_mailbox_email_trgm_idx`; partial unique index `ix_unique_domain` is kept as a plain note (SQLite supports partial indexes — included below).
- Enable `PRAGMA foreign_keys = ON` per connection (D1 has it on by default).

```sql
-- ===== helper note: every table's base columns =====
-- id INTEGER PRIMARY KEY AUTOINCREMENT
-- created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00')
-- updated_at TEXT NULL  -- app must set on UPDATE

CREATE TABLE file (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  path VARCHAR(128) NOT NULL UNIQUE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX ix_file_user_id ON file(user_id);

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  password VARCHAR(128),                                -- bcrypt hash, NFKC-normalized input
  email VARCHAR(256) NOT NULL UNIQUE,
  name VARCHAR(128),
  is_admin INTEGER NOT NULL DEFAULT 0,
  alias_generator INTEGER NOT NULL DEFAULT 1,           -- AliasGeneratorEnum.word
  notification INTEGER NOT NULL DEFAULT 1,
  activated INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  profile_picture_id INTEGER REFERENCES file(id),
  otp_secret VARCHAR(16),
  enable_otp INTEGER NOT NULL DEFAULT 0,
  last_otp VARCHAR(12),
  fido_uuid VARCHAR(128) UNIQUE,
  default_alias_custom_domain_id INTEGER REFERENCES custom_domain(id) ON DELETE SET NULL,
  default_alias_public_domain_id INTEGER REFERENCES public_domain(id) ON DELETE SET NULL,
  lifetime INTEGER NOT NULL DEFAULT 0,
  paid_lifetime INTEGER NOT NULL DEFAULT 0,
  lifetime_coupon_id INTEGER REFERENCES lifetime_coupon(id) ON DELETE SET NULL,
  trial_end TEXT,                                       -- app-set: now + 7 days 1 hour (NULL for partner users)
  default_mailbox_id INTEGER REFERENCES mailbox(id),
  sender_format INTEGER NOT NULL DEFAULT 0,             -- SenderFormatEnum.AT
  sender_format_updated_at TEXT,
  replace_reverse_alias INTEGER NOT NULL DEFAULT 0,
  referral_id INTEGER REFERENCES referral(id) ON DELETE SET NULL,
  intro_shown INTEGER NOT NULL DEFAULT 0,
  max_spam_score INTEGER,
  newsletter_alias_id INTEGER REFERENCES alias(id) ON DELETE SET NULL,
  include_sender_in_reverse_alias INTEGER NOT NULL DEFAULT 1,   -- python default True (PG server default 0)
  random_alias_suffix INTEGER NOT NULL DEFAULT 0,       -- python default word=0 (PG server default '1')
  expand_alias_info INTEGER NOT NULL DEFAULT 0,
  ignore_loop_email INTEGER NOT NULL DEFAULT 0,
  alternative_id VARCHAR(128) UNIQUE,                   -- app-set: uuid4
  disable_automatic_alias_note INTEGER NOT NULL DEFAULT 0,
  one_click_unsubscribe_block_sender INTEGER NOT NULL DEFAULT 0,
  include_website_in_one_click_alias INTEGER NOT NULL DEFAULT 1, -- python default True
  directory_quota INTEGER NOT NULL DEFAULT 50,
  subdomain_quota INTEGER NOT NULL DEFAULT 5,
  disable_import INTEGER NOT NULL DEFAULT 0,
  can_use_phone INTEGER NOT NULL DEFAULT 0,
  phone_quota INTEGER,
  block_behaviour TEXT NOT NULL DEFAULT 'return_2xx'
    CHECK (block_behaviour IN ('return_2xx','return_5xx')),     -- PG enum stored by NAME
  include_header_email_header INTEGER NOT NULL DEFAULT 1,
  enable_data_breach_check INTEGER NOT NULL DEFAULT 0,
  flags INTEGER NOT NULL DEFAULT 1,                     -- python default FLAG_FREE_DISABLE_CREATE_CONTACTS=1
  unsub_behaviour INTEGER NOT NULL DEFAULT 2,           -- python default PreserveOriginal=2
  delete_on TEXT,
  alias_delete_action INTEGER NOT NULL DEFAULT 0        -- MoveToTrash
);
CREATE INDEX ix_users_activated_trial_end_lifetime ON users(activated, trial_end, lifetime);
CREATE INDEX ix_users_delete_on ON users(delete_on);
CREATE INDEX ix_users_default_mailbox_id ON users(default_mailbox_id);
CREATE INDEX ix_users_default_alias_custom_domain_id ON users(default_alias_custom_domain_id);
CREATE INDEX ix_users_profile_picture_id ON users(profile_picture_id);
CREATE INDEX ix_users_referral_id ON users(referral_id);
CREATE INDEX ix_users_newsletter_alias_id ON users(newsletter_alias_id);

CREATE TABLE referral (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(512),
  code VARCHAR(128) NOT NULL UNIQUE
);
CREATE INDEX ix_referral_user_id ON referral(user_id);

CREATE TABLE lifetime_coupon (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  code VARCHAR(128) NOT NULL UNIQUE,
  nb_used INTEGER NOT NULL,
  paid INTEGER NOT NULL DEFAULT 0,
  comment TEXT
);

CREATE TABLE partner (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  name VARCHAR(128) NOT NULL UNIQUE,
  contact_email VARCHAR(128) NOT NULL UNIQUE
);

CREATE TABLE public_domain (                            -- class SLDomain
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  domain VARCHAR(128) NOT NULL UNIQUE,
  premium_only INTEGER NOT NULL DEFAULT 0,
  can_use_subdomain INTEGER NOT NULL DEFAULT 0,
  partner_id INTEGER REFERENCES partner(id) ON DELETE CASCADE,
  hidden INTEGER NOT NULL DEFAULT 0,
  "order" INTEGER NOT NULL DEFAULT 0,                   -- reserved word: always quote
  use_as_reverse_alias INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE custom_domain (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain VARCHAR(128) NOT NULL UNIQUE,
  name VARCHAR(128),
  verified INTEGER NOT NULL DEFAULT 0,
  dkim_verified INTEGER NOT NULL DEFAULT 0,
  spf_verified INTEGER NOT NULL DEFAULT 0,
  dmarc_verified INTEGER NOT NULL DEFAULT 0,
  catch_all INTEGER NOT NULL DEFAULT 0,
  random_prefix_generation INTEGER NOT NULL DEFAULT 0,
  nb_failed_checks INTEGER NOT NULL DEFAULT 0,
  ownership_verified INTEGER NOT NULL DEFAULT 0,
  ownership_txt_token VARCHAR(128),                     -- app-set: random_string(30)
  is_sl_subdomain INTEGER NOT NULL DEFAULT 0,
  partner_id INTEGER REFERENCES partner(id),
  pending_deletion INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_custom_domain_user_id ON custom_domain(user_id);
CREATE INDEX ix_custom_domain_pending_deletion ON custom_domain(pending_deletion);
CREATE UNIQUE INDEX ix_unique_domain ON custom_domain(domain) WHERE ownership_verified;

CREATE TABLE mailbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email VARCHAR(256) NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  force_spf INTEGER NOT NULL DEFAULT 1,
  new_email VARCHAR(256) UNIQUE,
  pgp_public_key TEXT,
  pgp_finger_print VARCHAR(512),
  disable_pgp INTEGER NOT NULL DEFAULT 0,
  nb_failed_checks INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  flags INTEGER NOT NULL DEFAULT 0,                     -- bit 0 = FLAG_ADMIN_DISABLED
  generic_subject VARCHAR(78),
  CONSTRAINT uq_mailbox_user UNIQUE (user_id, email)
);
CREATE INDEX ix_mailbox_email ON mailbox(email);
CREATE INDEX ix_mailbox_pgp_finger_print ON mailbox(pgp_finger_print);

CREATE TABLE directory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(128) NOT NULL UNIQUE,
  disabled INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_directory_user_id ON directory(user_id);

CREATE TABLE directory_mailbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  directory_id INTEGER NOT NULL REFERENCES directory(id) ON DELETE CASCADE,
  mailbox_id INTEGER NOT NULL REFERENCES mailbox(id) ON DELETE CASCADE,
  CONSTRAINT uq_directory_mailbox UNIQUE (directory_id, mailbox_id)
);

CREATE TABLE batch_import (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  file_id INTEGER NOT NULL REFERENCES file(id) ON DELETE CASCADE,
  processed INTEGER NOT NULL DEFAULT 0,
  summary TEXT
);
CREATE INDEX ix_batch_import_file_id ON batch_import(file_id);
CREATE INDEX ix_batch_import_user_id ON batch_import(user_id);

CREATE TABLE alias (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email VARCHAR(128) NOT NULL UNIQUE,
  name VARCHAR(128),
  enabled INTEGER NOT NULL DEFAULT 1,
  flags INTEGER NOT NULL DEFAULT 0,                     -- bit 0 = FLAG_PARTNER_CREATED
  custom_domain_id INTEGER REFERENCES custom_domain(id) ON DELETE CASCADE,
  automatic_creation INTEGER NOT NULL DEFAULT 0,
  directory_id INTEGER REFERENCES directory(id) ON DELETE CASCADE,
  note TEXT,
  mailbox_id INTEGER NOT NULL REFERENCES mailbox(id) ON DELETE CASCADE,
  disable_pgp INTEGER NOT NULL DEFAULT 0,
  cannot_be_disabled INTEGER NOT NULL DEFAULT 0,
  disable_email_spoofing_check INTEGER NOT NULL DEFAULT 0,
  batch_import_id INTEGER REFERENCES batch_import(id) ON DELETE SET NULL,
  original_owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  pinned INTEGER NOT NULL DEFAULT 0,
  transfer_token VARCHAR(64) UNIQUE,
  transfer_token_expiration TEXT,                       -- app-set: utcnow on create
  hibp_last_check TEXT,
  -- ts_vector dropped (Postgres full-text generated column)
  last_email_log_id INTEGER,
  delete_on TEXT,                                       -- non-NULL => alias is in trash
  delete_reason INTEGER                                 -- AliasDeleteReason int
);
CREATE INDEX ix_alias_user_id ON alias(user_id);
CREATE INDEX ix_alias_flags ON alias(flags);
CREATE INDEX ix_alias_custom_domain_id ON alias(custom_domain_id);
CREATE INDEX ix_alias_directory_id ON alias(directory_id);
CREATE INDEX ix_alias_mailbox_id ON alias(mailbox_id);
CREATE INDEX ix_alias_hibp_last_check ON alias(hibp_last_check);
CREATE INDEX ix_alias_original_owner_id ON alias(original_owner_id);
CREATE INDEX ix_alias_delete_on ON alias(delete_on);

CREATE TABLE alias_mailbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  alias_id INTEGER NOT NULL REFERENCES alias(id) ON DELETE CASCADE,
  mailbox_id INTEGER NOT NULL REFERENCES mailbox(id) ON DELETE CASCADE,
  CONSTRAINT uq_alias_mailbox UNIQUE (alias_id, mailbox_id)
);
CREATE INDEX ix_alias_mailbox_mailbox_id ON alias_mailbox(mailbox_id);

CREATE TABLE alias_used_on (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  alias_id INTEGER NOT NULL REFERENCES alias(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hostname VARCHAR(1024) NOT NULL,
  CONSTRAINT uq_alias_used UNIQUE (alias_id, hostname)
);
CREATE INDEX ix_alias_used_on_user_id ON alias_used_on(user_id);

CREATE TABLE contact (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  alias_id INTEGER NOT NULL REFERENCES alias(id) ON DELETE CASCADE,
  name VARCHAR(512) DEFAULT NULL,
  website_email VARCHAR(512) NOT NULL,
  website_from VARCHAR(1024),
  reply_email VARCHAR(512) NOT NULL,                    -- the reverse-alias
  is_cc INTEGER NOT NULL DEFAULT 0,
  pgp_public_key TEXT,
  pgp_finger_print VARCHAR(512),
  mail_from TEXT,
  invalid_email INTEGER NOT NULL DEFAULT 0,
  block_forward INTEGER NOT NULL DEFAULT 0,
  automatic_created INTEGER DEFAULT 0,                  -- NULLABLE bool
  flags INTEGER NOT NULL DEFAULT 0,                     -- bit 0 = FLAG_PARTNER_CREATED
  CONSTRAINT uq_contact UNIQUE (alias_id, website_email)
);
CREATE INDEX ix_contact_user_id_id ON contact(user_id, id);
CREATE INDEX ix_contact_reply_email ON contact(reply_email);
CREATE INDEX ix_contact_pgp_finger_print ON contact(pgp_finger_print);

CREATE TABLE email_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  contact_id INTEGER NOT NULL REFERENCES contact(id) ON DELETE CASCADE,
  alias_id INTEGER REFERENCES alias(id) ON DELETE CASCADE,
  is_reply INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0,
  bounced INTEGER NOT NULL DEFAULT 0,
  auto_replied INTEGER NOT NULL DEFAULT 0,
  is_spam INTEGER NOT NULL DEFAULT 0,
  spam_score REAL,
  spam_status TEXT,
  spam_report TEXT,                                     -- JSON
  refused_email_id INTEGER REFERENCES refused_email(id) ON DELETE SET NULL,
  mailbox_id INTEGER REFERENCES mailbox(id) ON DELETE CASCADE,
  bounced_mailbox_id INTEGER REFERENCES mailbox(id) ON DELETE CASCADE,
  message_id VARCHAR(1024),                             -- app truncates to 250 chars on insert
  sl_message_id VARCHAR(512)
);
CREATE INDEX ix_email_log_created_at ON email_log(created_at);
CREATE INDEX ix_email_log_contact_id ON email_log(contact_id);
CREATE INDEX ix_email_log_alias_id ON email_log(alias_id);
CREATE INDEX ix_email_log_mailbox_id ON email_log(mailbox_id);
CREATE INDEX ix_email_log_bounced_mailbox_id ON email_log(bounced_mailbox_id);
CREATE INDEX ix_email_log_refused_email_id ON email_log(refused_email_id);
CREATE INDEX ix_email_log_user_id_email_log_id ON email_log(user_id, id);

CREATE TABLE deleted_alias (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  email VARCHAR(256) NOT NULL UNIQUE,
  reason INTEGER NOT NULL DEFAULT 0,                    -- AliasDeleteReason
  alias_id INTEGER                                      -- no FK on purpose
);
CREATE INDEX ix_deleted_alias_alias_id ON deleted_alias(alias_id);

CREATE TABLE domain_deleted_alias (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  email VARCHAR(256) NOT NULL,
  domain_id INTEGER NOT NULL REFERENCES custom_domain(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reason INTEGER NOT NULL DEFAULT 0,
  alias_id INTEGER,
  CONSTRAINT uq_domain_trash UNIQUE (domain_id, email)
);
CREATE INDEX ix_domain_deleted_alias_user_id ON domain_deleted_alias(user_id);
CREATE INDEX ix_domain_deleted_alias_alias_id ON domain_deleted_alias(alias_id);

CREATE TABLE api_key (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code VARCHAR(128) NOT NULL UNIQUE,                    -- app-set: random_string(60) lowercase a-z
  name VARCHAR(128),
  last_used TEXT,
  times INTEGER NOT NULL DEFAULT 0,
  sudo_mode_at TEXT
);
CREATE INDEX ix_api_key_user_id ON api_key(user_id);

CREATE TABLE api_cookie_token (                         -- class ApiToCookieToken
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  code VARCHAR(128) NOT NULL UNIQUE,                    -- app-set: secrets.token_urlsafe(32)
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  api_key_id INTEGER NOT NULL REFERENCES api_key(id) ON DELETE CASCADE
);
CREATE INDEX ix_api_to_cookie_token_api_key_id ON api_cookie_token(api_key_id);
CREATE INDEX ix_api_to_cookie_token_user_id ON api_cookie_token(user_id);

CREATE TABLE account_activation (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  code VARCHAR(10) NOT NULL,
  tries INTEGER NOT NULL DEFAULT 3,
  CONSTRAINT account_activation_tries_positive CHECK (tries >= 0)
);

CREATE TABLE activation_code (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code VARCHAR(128) NOT NULL UNIQUE,
  expired TEXT NOT NULL                                 -- app-set: now + 1 hour
);
CREATE INDEX ix_activation_code_user_id ON activation_code(user_id);

CREATE TABLE reset_password_code (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code VARCHAR(128) NOT NULL UNIQUE,
  expired TEXT NOT NULL                                 -- app-set: now + 1 hour
);
CREATE INDEX ix_reset_password_code_user_id ON reset_password_code(user_id);

CREATE TABLE email_change (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  new_email VARCHAR(256) NOT NULL UNIQUE,
  code VARCHAR(128) NOT NULL UNIQUE,
  expired TEXT NOT NULL                                 -- app-set: now + 12 hours
);
CREATE INDEX ix_email_change_user_id ON email_change(user_id);

CREATE TABLE mailbox_activation (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  mailbox_id INTEGER NOT NULL REFERENCES mailbox(id) ON DELETE CASCADE,
  code VARCHAR(32) NOT NULL,
  tries INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_mailbox_activation_mailbox_id ON mailbox_activation(mailbox_id);
CREATE INDEX ix_mailbox_activation_code ON mailbox_activation(code);

CREATE TABLE recovery_code (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code VARCHAR(64) NOT NULL,                            -- HMAC-SHA3-224, base64url no padding
  used INTEGER NOT NULL DEFAULT 0,
  used_at TEXT,
  CONSTRAINT uq_recovery_code UNIQUE (user_id, code)
);

CREATE TABLE fido (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  credential_id VARCHAR(256) NOT NULL UNIQUE,
  uuid VARCHAR(128) NOT NULL REFERENCES users(fido_uuid) ON DELETE CASCADE,  -- FK to non-PK unique col
  public_key VARCHAR(1024) NOT NULL UNIQUE,
  sign_count INTEGER NOT NULL,
  name VARCHAR(128) NOT NULL,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  credential_type VARCHAR(32),
  authenticator_attachment VARCHAR(32),
  transports TEXT,                                      -- JSON array e.g. ["usb","nfc"]
  aaguid VARCHAR(36)
);
CREATE INDEX ix_fido_credential_id ON fido(credential_id);
CREATE INDEX ix_fido_user_id ON fido(user_id);

CREATE TABLE notification (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  title VARCHAR(512),
  read INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_notification_user_id ON notification(user_id);

CREATE TABLE refused_email (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  full_report_path VARCHAR(128) NOT NULL UNIQUE,        -- R2 object key
  path VARCHAR(128) UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  delete_at TEXT NOT NULL,                              -- app-set: now + 7 days
  deleted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_refused_email_user_id ON refused_email(user_id);

CREATE TABLE job (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  name VARCHAR(128) NOT NULL,
  payload TEXT,                                         -- JSON
  taken INTEGER NOT NULL DEFAULT 0,
  run_at TEXT,
  state INTEGER NOT NULL DEFAULT 0,                     -- JobState: 0 ready,1 taken,2 done,3 error
  attempts INTEGER NOT NULL DEFAULT 0,
  taken_at TEXT,
  priority INTEGER NOT NULL DEFAULT 50                  -- JobPriority
);
CREATE INDEX ix_state_run_at_taken_at_priority_attempts
  ON job(state, run_at, taken_at, priority, attempts);

CREATE TABLE subscription (                             -- Paddle
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  cancel_url VARCHAR(1024) NOT NULL,
  update_url VARCHAR(1024) NOT NULL,
  subscription_id VARCHAR(1024) NOT NULL UNIQUE,
  event_time TEXT NOT NULL,
  next_bill_date TEXT NOT NULL,                         -- DATE: 'YYYY-MM-DD'
  cancelled INTEGER NOT NULL DEFAULT 0,
  plan TEXT NOT NULL CHECK (plan IN ('monthly','yearly')),  -- PG enum stored by NAME
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE manual_subscription (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  end_at TEXT NOT NULL,
  comment TEXT,
  is_giveaway INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE coinbase_subscription (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  end_at TEXT NOT NULL,
  code VARCHAR(64)
);

CREATE TABLE apple_subscription (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  expires_date TEXT NOT NULL,
  original_transaction_id VARCHAR(256) NOT NULL UNIQUE,
  receipt_data TEXT NOT NULL,
  plan TEXT NOT NULL CHECK (plan IN ('monthly','yearly')),
  product_id VARCHAR(256)
);

CREATE TABLE partner_user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  partner_id INTEGER NOT NULL REFERENCES partner(id) ON DELETE CASCADE,
  external_user_id VARCHAR(128) NOT NULL,
  partner_email VARCHAR(255),
  CONSTRAINT uq_partner_id_external_user_id UNIQUE (partner_id, external_user_id)
);
CREATE INDEX ix_partner_user_user_id ON partner_user(user_id);

CREATE TABLE partner_subscription (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  partner_user_id INTEGER NOT NULL UNIQUE REFERENCES partner_user(id) ON DELETE CASCADE,
  end_at TEXT,                                          -- NULLABLE (lifetime partner subs)
  lifetime INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_partner_subscription_end_at ON partner_subscription(end_at);

-- ===== forwarding-support tables =====

CREATE TABLE domain_mailbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  domain_id INTEGER NOT NULL REFERENCES custom_domain(id) ON DELETE CASCADE,
  mailbox_id INTEGER NOT NULL REFERENCES mailbox(id) ON DELETE CASCADE,
  CONSTRAINT uq_domain_mailbox UNIQUE (domain_id, mailbox_id)
);

CREATE TABLE auto_create_rule (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  custom_domain_id INTEGER NOT NULL REFERENCES custom_domain(id) ON DELETE CASCADE,
  regex VARCHAR(512) NOT NULL,
  "order" INTEGER NOT NULL DEFAULT 0,
  display_name VARCHAR(128),
  CONSTRAINT uq_auto_create_rule_order UNIQUE (custom_domain_id, "order")
);

CREATE TABLE auto_create_rule__mailbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  auto_create_rule_id INTEGER NOT NULL REFERENCES auto_create_rule(id) ON DELETE CASCADE,
  mailbox_id INTEGER NOT NULL REFERENCES mailbox(id) ON DELETE CASCADE,
  CONSTRAINT uq_auto_create_rule_mailbox UNIQUE (auto_create_rule_id, mailbox_id)
);

CREATE TABLE authorized_address (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mailbox_id INTEGER NOT NULL REFERENCES mailbox(id) ON DELETE CASCADE,
  email VARCHAR(256) NOT NULL,
  CONSTRAINT uq_authorize_address UNIQUE (mailbox_id, email)
);
CREATE INDEX ix_authorized_address_user_id ON authorized_address(user_id);

CREATE TABLE message_id_matching (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  sl_message_id VARCHAR(512) NOT NULL UNIQUE,
  original_message_id VARCHAR(1024) NOT NULL UNIQUE,
  email_log_id INTEGER REFERENCES email_log(id) ON DELETE CASCADE
);
CREATE INDEX ix_message_id_matching_email_log_id ON message_id_matching(email_log_id);

CREATE TABLE sent_alert (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_email VARCHAR(256) NOT NULL,
  alert_type VARCHAR(256) NOT NULL
);
CREATE INDEX ix_sent_alert_user_id ON sent_alert(user_id);
CREATE INDEX ix_sent_alert_to_email ON sent_alert(to_email);
CREATE INDEX ix_sent_alert_alert_type ON sent_alert(alert_type);

CREATE TABLE bounce (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  email VARCHAR(256) NOT NULL,
  info TEXT
);
CREATE INDEX ix_bounce_email ON bounce(email);
CREATE INDEX ix_bounce_created_at ON bounce(created_at);

CREATE TABLE transactional_email (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  email VARCHAR(256) NOT NULL
);
CREATE INDEX ix_transactional_email_created_at ON transactional_email(created_at);

CREATE TABLE ignored_email (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  mail_from VARCHAR(512) NOT NULL,
  rcpt_to VARCHAR(512) NOT NULL
);

CREATE TABLE ignore_bounce_sender (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  mail_from VARCHAR(512) NOT NULL UNIQUE
);

CREATE TABLE deleted_directory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  name VARCHAR(128) NOT NULL UNIQUE
);

CREATE TABLE deleted_subdomain (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  domain VARCHAR(128) NOT NULL UNIQUE
);

CREATE TABLE hibp (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  name VARCHAR(512) NOT NULL UNIQUE,
  description TEXT,
  date TEXT
);

CREATE TABLE alias_hibp (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  alias_id INTEGER REFERENCES alias(id) ON DELETE CASCADE,
  hibp_id INTEGER REFERENCES hibp(id) ON DELETE CASCADE,
  CONSTRAINT uq_alias_hibp UNIQUE (alias_id, hibp_id)
);
CREATE INDEX ix_alias_hibp_hibp_id ON alias_hibp(hibp_id);
```

---

## Implementation notes for Cloudflare

- **Datetime format is load-bearing**: `*_date` API fields must be exactly
  `YYYY-MM-DD HH:MM:SS+00:00` (arrow 0.16 `.format()` default). Do NOT emit `T` separator,
  `Z` suffix, or fractional seconds — mobile apps parse this string. `*_timestamp` fields
  are integer epoch seconds. Notifications use `.humanize()` (relative English strings:
  "just now", "X minutes ago", "an hour ago", "2 days ago", ...).
- **Python default vs server default divergence** (the ORM default wins in production
  data): `users.flags` (ORM 1 / DDL 0), `users.unsub_behaviour` (ORM 2 / DDL 0),
  `users.include_sender_in_reverse_alias` (ORM 1 / DDL 0),
  `users.include_website_in_one_click_alias` (ORM 1 / DDL 0),
  `users.random_alias_suffix` (ORM 0=word / DDL 1=random_string). The D1 DDL above bakes
  in the ORM defaults; the Worker insert layer should still set them explicitly.
- **Enums stored as names, not ints**: `users.block_behaviour` (`'return_2xx'`/`'return_5xx'`),
  `subscription.plan` & `apple_subscription.plan` (`'monthly'`/`'yearly'`). All other enums
  are plain integers (`IntEnumType`) or raw ints.
- **`subscription.next_bill_date` is a DATE**, not a timestamp; Paddle grace check compares
  `next_bill_date >= date(now - 14 days)` at date granularity.
- **Subscription precedence**: Paddle → Apple → Manual → Coinbase → Partner. Grace periods:
  Paddle 14d after next_bill_date, Apple 16d after expires_date, Partner 14d after end_at
  (or lifetime flag), Manual/Coinbase none. A *cancelled* Paddle sub still counts until
  next_bill_date + 14d.
- **Trash semantics**: alias "deleted" via trash = `alias.delete_on` set (row stays);
  permanent deletion inserts into `deleted_alias` (or `domain_deleted_alias` for custom
  domains) and both tables block future `Alias.create` with `AliasInTrashError`.
  Free-plan alias counting excludes trashed rows (`delete_on IS NULL`).
- **Alias uniqueness is global** (`alias.email` UNIQUE) and new addresses must also avoid
  `contact.reply_email` and `deleted_alias.email` (`available_sl_email`).
- **Mailbox email is unique per (user_id, email)**, not globally — two users can register
  the same mailbox address.
- **`EmailLog.create` must update `alias.last_email_log_id`** in the same transaction and
  truncate `message_id` to 250 chars.
- **Generated secrets**: api_key.code = 60 lowercase a-z chars (uuid4 on collision);
  api_cookie_token.code = `token_urlsafe(32)`; recovery codes stored as
  HMAC-SHA3-224/base64url (secret `RECOVERY_CODE_HMAC_SECRET`); custom_domain
  ownership token = 30 lowercase chars; reverse-alias per §4.1.
- **Config constants consulted by this layer**: `MAX_NB_EMAIL_FREE_PLAN` (5),
  `MAX_NB_EMAIL_OLD_FREE_PLAN` (15), `MAX_NB_DIRECTORY` (50), `MAX_NB_SUBDOMAIN` (5),
  `ALIAS_RANDOM_SUFFIX_LENGTH` (5), `ALIAS_CREATE_RATE_LIMIT_FREE` `[(10,900),(50,3600)]`,
  `ALIAS_CREATE_RATE_LIMIT_PAID` `[(50,900),(200,3600)]`, `FIRST_ALIAS_DOMAIN`
  (defaults to `EMAIL_DOMAIN`), `EMAIL_DOMAIN`, `NOREPLIES`,
  `DISABLE_CREATE_CONTACTS_FOR_FREE_USERS`, `PROTON_EMAIL_DOMAINS` / `PROTON_MX_SERVERS`
  (Mailbox.is_proton), `STORE_TRANSACTIONAL_EMAILS`.
- **Dropped Postgres features**: `alias.ts_vector` generated TSVECTOR + GIN index
  (note-search must be reimplemented, e.g. LIKE or FTS5), trigram GIN indexes on
  users.email / alias.note / mailbox.email (admin search only), `SELECT ... FOR UPDATE`
  row locks (D1 is single-writer; not needed).
- **FK to a non-PK column**: `fido.uuid REFERENCES users(fido_uuid)` — SQLite allows this
  because `users.fido_uuid` is UNIQUE; keep the UNIQUE constraint or the FK fails.
- **`"order"` is a reserved word** (columns in `public_domain` and `auto_create_rule`) —
  always quote it in SQL.
- `sanitize_email`: strip whitespace, remove internal spaces, replace `\n` with space,
  lowercase (unless `not_lower`), strip U+200F. Applied to user email, mailbox email,
  alias email, contact website_email.
