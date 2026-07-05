# Spec 03 — Alias creation & alias options

Source files:
- `app/api/views/alias_options.py` (GET /v4/alias/options, GET /v5/alias/options)
- `app/api/views/new_custom_alias.py` (POST /v2/alias/custom/new, POST /v3/alias/custom/new)
- `app/api/views/new_random_alias.py` (POST /alias/random/new)
- Helpers: `app/alias_suffix.py`, `app/alias_utils.py`, `app/utils.py`, `app/models.py`, `app/api/base.py`, `app/api/serializer.py`, `app/parallel_limiter.py`, `app/rate_limiter.py`, `app/extensions.py`, `simplelogin_app.py`

All routes live on the `api` Blueprint with `url_prefix="/api"`, so the externally visible paths are `/api/v4/alias/options`, `/api/v2/alias/custom/new`, etc.

Routes documented: **5**
1. `GET /api/v4/alias/options`
2. `GET /api/v5/alias/options`
3. `POST /api/v2/alias/custom/new`
4. `POST /api/v3/alias/custom/new`
5. `POST /api/alias/random/new`

---

## 1. Common infrastructure

### 1.1 Authentication — `@require_api_auth` (`app/api/base.py`)

All 5 routes use `@require_api_auth`. Logic of `authorize_request()`:

1. Read header **`Authentication`** (NOT `Authorization`). `api_key = ApiKey.get_by(code=<header value>)` (exact match on `api_key.code` column).
2. If **no matching ApiKey row**:
   - If the flask-login session user is authenticated **and** the request has header **`X-Sl-Allowcookies`** (constant `HEADER_ALLOW_API_COOKIES = "X-Sl-Allowcookies"`, any non-empty value): `g.user = current_user` (cookie-based auth fallback, used by the web app).
   - If session user is **not** authenticated: return `401` with body `{"error": "Wrong api key"}`.
   - Edge case (faithful to code): if a session user IS authenticated but the `X-Sl-Allowcookies` header is missing, `g.user` is never set and the subsequent `g.user.disabled` access raises `AttributeError` → global exception handler → `500 {"error": "Internal error"}`.
3. If a matching ApiKey exists: update stats — `api_key.last_used = arrow.now()`, `api_key.times += 1`, commit. `g.user = api_key.user`.
4. If `g.user.disabled` → `403 {"error": "Disabled account"}`.
5. If `not g.user.is_active()` → `401 {"error": "Account does not exist"}`.
   - `User.is_active()`: `True` if `delete_on IS NULL`, else `delete_on < now()` (yes — a user scheduled for future deletion is *inactive*; a user whose delete_on already passed counts as "active" per this code — copy as-is).
6. `g.api_key = api_key` (may be `None` in the cookie path).

### 1.2 Global JSON error handlers (`simplelogin_app.py` `setup_error_page`)

For any request whose path starts with `/api/`, framework-level errors are JSON:

| Status | Body |
|---|---|
| 400 (framework, e.g. malformed JSON body) | `{"error": "Bad Request"}` |
| 401 | `{"error": "Unauthorized"}` |
| 403 | `{"error": "Forbidden"}` |
| 404 | `{"error": "No such endpoint"}` |
| 405 | `{"error": "Method not allowed"}` |
| 429 (any rate limit / lock) | `{"error": "Rate limit exceeded"}` |
| Unhandled exception | `500 {"error": "Internal error"}` |

### 1.3 Rate limiting — `@limiter.limit(ALIAS_LIMIT)`

Applied to all three **creation** routes (not to the options routes):

- `ALIAS_LIMIT = os.environ.get("ALIAS_LIMIT") or "100/day;50/hour;5/minute"` (flask-limiter syntax; all three windows enforced).
- Key function (`app/extensions.py`): `f"userid:{current_user.id}"` if the **flask-login session** user is authenticated, else `f"ip:{remote_addr}"`. **Gotcha:** pure API-key requests are not flask-login-authenticated, so they are rate limited **per IP**, not per user.
- Disabled entirely when env var `DISABLE_RATE_LIMIT` is set.
- Storage: Redis at `MEM_STORE_URI` if configured, else in-memory.
- On breach → `429 {"error": "Rate limit exceeded"}`.

### 1.4 Concurrency lock — `@parallel_limiter.lock(name="alias_creation")`

Applied to all three creation routes. Behavior (`app/parallel_limiter.py`):

- No-op if Redis (`lock_redis`) is not configured.
- Lock key: `cl:{current_user.id}:alias_creation` if flask-login user has an `id`, else `cl:{request.remote_addr}:alias_creation` (again: API-key requests key on IP).
- Redis `SET key value NX EX 5` (5-second TTL, `max_wait_secs=5`). If the key already exists → raise `TooManyRequests` → `429 {"error": "Rate limit exceeded"}`. Lock value is `str(uuid4())[:10]`; released in `finally` only if the stored value still matches.
- Net effect: at most one in-flight alias creation per user/IP; a second concurrent request gets 429.

### 1.5 Per-user creation bucket limits inside `Alias.create` (`app/models.py`)

Every alias creation (all 3 creation routes) additionally runs, inside `Alias.create`:

```python
if user.is_premium() and not user.in_trial():
    limits = config.ALIAS_CREATE_RATE_LIMIT_PAID   # default "50,900:200,3600" → [(50, 900), (200, 3600)]
else:
    limits = config.ALIAS_CREATE_RATE_LIMIT_FREE   # default "10,900:50,3600" → [(10, 900), (50, 3600)]
for (max_hits, bucket_seconds) in limits:
    key = f"alias_create_{bucket_seconds}:{user.id}"
    rate_limiter.check_bucket_limit(key, max_hits, bucket_seconds)
```

`check_bucket_limit`: fixed-window buckets in Redis. `bucket_id = int_time - (int_time % bucket_seconds)`, Redis key `bl:{key}:{bucket_id}`, `INCR` with TTL `bucket_seconds`; if the counter exceeds `max_hits` → `TooManyRequests` → `429 {"error": "Rate limit exceeded"}`. No-op when rate limits disabled or Redis missing. So free users: max 10 aliases per 15-min bucket and 50 per hour bucket; paid: 50 / 200.

### 1.6 Alias count limit — `User.can_create_new_alias()`

Exact logic (`app/models.py`):

```python
def max_alias_for_free_account(self) -> int:
    if self.FLAG_FREE_OLD_ALIAS_LIMIT == self.flags & self.FLAG_FREE_OLD_ALIAS_LIMIT:   # flag bit 1<<2
        return config.MAX_NB_EMAIL_OLD_FREE_PLAN   # env MAX_NB_EMAIL_OLD_FREE_PLAN, default 15
    else:
        return config.MAX_NB_EMAIL_FREE_PLAN       # env MAX_NB_EMAIL_FREE_PLAN, default 5

def can_create_new_alias(self) -> bool:
    return self.can_create_num_aliases(1)

def can_create_num_aliases(self, num_aliases: int) -> bool:
    if not self.is_active():          # delete_on semantics, see 1.1
        return False
    if self.disabled:
        return False
    if self.lifetime_or_active_subscription():
        return True
    else:
        active_alias_count = Alias.filter_by(user_id=self.id, delete_on=None).count()
        return (active_alias_count + num_aliases) <= self.max_alias_for_free_account()
```

- `lifetime_or_active_subscription(include_partner_subscription=True)`: `user.lifetime == True` OR any active subscription among: Paddle `Subscription` (via `get_paddle_subscription()`), valid `AppleSubscription`, active `ManualSubscription`, active `CoinbaseSubscription`, active `PartnerSubscription`.
- **The free-plan cap applies even during the free trial** (trial makes `is_premium()` true, but `can_create_num_aliases` checks `lifetime_or_active_subscription()`, which is false during trial).
- The count includes **disabled** aliases; excludes only aliases with `delete_on` set.
- Plan constants: `MAX_NB_EMAIL_FREE_PLAN` default **5**; `MAX_NB_EMAIL_OLD_FREE_PLAN` default **15**; user flag `FLAG_FREE_OLD_ALIAS_LIMIT = 1 << 2` (value 4) selects the old limit.
- `is_premium(include_partner_subscription=True)`: `lifetime_or_active_subscription()` OR (`trial_end` set AND `now < trial_end`).

---

## 2. Suffix signing — exact algorithm (`app/alias_suffix.py`)

```python
signer = itsdangerous.TimestampSigner(config.CUSTOM_ALIAS_SECRET)
```

- **Secret**: `CUSTOM_ALIAS_SECRET = FLASK_SECRET + "custom_alias"` (string concatenation; `FLASK_SECRET` is the required env var, also used as the Flask session secret).
- **Library**: `itsdangerous ~= 1.1.0`, class `TimestampSigner`, all defaults:
  - separator `sep = "."`
  - salt = `"itsdangerous.Signer"` (the library default — no custom salt)
  - key derivation = `"django-concat"`: `derived_key = SHA1(b"itsdangerous.Signer" + b"signer" + secret_key_bytes).digest()` (20 bytes)
  - signature algorithm: `HMAC-SHA1(derived_key, message)`
  - encoding: URL-safe base64 (`base64.urlsafe_b64encode`) with **all trailing `=` padding stripped**
  - timestamp: `int(time.time())` — plain unix epoch seconds (itsdangerous 1.x; no custom epoch offset) — encoded as minimal big-endian bytes (`int_to_bytes` with leading `\x00` stripped) then URL-safe base64 without padding.

**Sign** (`signer.sign(suffix)`):
```
payload    = suffix_bytes + b"." + b64(int_to_bytes(unix_now))
signed     = payload + b"." + b64(HMAC_SHA1(derived_key, payload))
```
Example: `.test123@example.com.akpD2w.I_6B3-nfGCI8r1LoN42ttSrSPj8` (suffix itself contains dots; parsing must use **rightmost** separators).

**Verify** (`check_suffix_signature(signed_suffix)`):
```python
def check_suffix_signature(signed_suffix: str) -> Optional[str]:
    try:
        return signer.unsign(signed_suffix, max_age=600).decode()
    except itsdangerous.BadSignature:
        return None
```
- `unsign` splits on the rightmost `"."` for the signature, verifies HMAC over everything before it, then splits the rightmost `"."` again for the timestamp, and checks `now - timestamp > max_age` (**600 seconds**) → `SignatureExpired` (a `BadSignature` subclass).
- **Gotcha:** both *expired* and *tampered/invalid* signatures raise `BadSignature`, which is caught here and returns `None`. In the routes, `None` → `412 {"error": "Alias creation time is expired, please retry"}`. The routes' `except Exception:` → `400 {"error": "Tampered suffix"}` branch is effectively dead code (would only fire on a non-BadSignature exception). A tampered suffix therefore produces the **412 "expired" message**, not the 400 "Tampered suffix" one.

---

## 3. Shared helpers

### 3.1 `convert_to_id(s)` (`app/utils.py`)

```python
_ALLOWED_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."

def convert_to_alphanumeric(s):  # each char not in _ALLOWED_CHARS → "_"
def convert_to_id(s):
    s = s.lower()
    s = unidecode(s)          # transliterate accents/unicode to ASCII (e.g. "é"→"e", "北"→"Bei ")
    s = s.replace(" ", "")
    return convert_to_alphanumeric(s)[:64]   # truncate to 64 chars
```

### 3.2 `check_alias_prefix(alias_prefix)` (`app/alias_utils.py`)

```python
_ALIAS_PREFIX_PATTERN = r"[0-9a-z-_.]{1,}"

def check_alias_prefix(alias_prefix) -> bool:
    if len(alias_prefix) > 40:
        return False
    if re.fullmatch(_ALIAS_PREFIX_PATTERN, alias_prefix) is None:
        return False
    return True
```
Max 40 chars, min 1 char, only `0-9 a-z - _ .`. **Only the v3 custom-alias route calls this; v2 does not.**

### 3.3 Random word/string generators (`app/utils.py`)

- Word list: loaded once from `WORDS_FILE_PATH` (env, default `local_data/words.txt`; ~7590 lowercase English words, split on whitespace).
- `random_word()` → one random word (`secrets.choice`).
- `random_words(words=2, numbers=0)` → `words` random words joined by `"_"`; if `numbers > 0` append that many random digits (no separator). E.g. `random_words(2, 3)` → `"abacus_zebra123"`; `random_words(1, 3)` → `"abacus123"`; `random_words(1)` → `"abacus"`.
- `random_string(length=10, include_digits=False)` → random string of lowercase ASCII letters (+ digits `0-9` if `include_digits`), via `secrets.choice`.

### 3.4 `User.get_random_alias_suffix(custom_domain=None)` (`app/models.py`)

```python
if self.random_alias_suffix == AliasSuffixEnum.random_string.value:   # == 1
    return random_string(config.ALIAS_RANDOM_SUFFIX_LENGTH, include_digits=True)  # env ALIAS_RAND_SUFFIX_LENGTH, default 5
if custom_domain is None:
    return random_words(1, 3)      # one word + 3 digits, e.g. "cat123"
return random_words(1)             # one word (shorter suffix for custom domains)
```
User column `random_alias_suffix`: int, python default `0` (word), DB server_default `"1"` (random_string). Enum: `AliasSuffixEnum.word = 0`, `AliasSuffixEnum.random_string = 1`.

### 3.5 `User.get_sl_domains(alias_options=None)` → list of SLDomain rows

Table `public_domain` (model `SLDomain`): columns `domain` (unique), `premium_only` (bool), `hidden` (bool), `order` (int), `partner_id` (nullable FK), `can_use_subdomain`, `use_as_reverse_alias`.

Query (with default `AliasOptions(show_sl_domains=True, show_partner_domains=None, show_partner_premium=None)` as used by these API routes):
- `WHERE hidden = false AND (<or-conditions>)`, ordered by `SLDomain.order`.
- OR-conditions assembled:
  - If `user.default_alias_public_domain_id` is not NULL: `(id = default_alias_public_domain_id [AND premium_only = false if user not premium])`.
  - (partner-domain condition — skipped here, `show_partner_domains` is None in these routes)
  - `show_sl_domains` (always True here): `(partner_id IS NULL [AND premium_only = false if user not premium])`.
- Net: free users see non-hidden, non-partner, non-premium SL domains (plus their default public domain if it is free); premium users also see `premium_only` domains.

### 3.6 `User.available_alias_domains()` / `verified_custom_domains()`

- `verified_custom_domains()`: `CustomDomain` rows with `user_id = user.id AND ownership_verified = true`, ordered by `domain ASC`.
- `available_alias_domains()`: `list(set(sl_domain.domain for get_sl_domains()) + [cd.domain for verified_custom_domains()))` — deduplicated, **unordered**.

### 3.7 `verify_prefix_suffix(user, alias_prefix, alias_suffix)` (`app/alias_suffix.py`)

Returns bool. Exact logic:

1. `False` if `alias_prefix` or `alias_suffix` falsy.
2. `user_custom_domains = [cd.domain for cd in user.verified_custom_domains()]`.
3. `alias_suffix = alias_suffix.strip()`; `alias_domain_prefix, alias_domain = alias_suffix.split("@", 1)` (suffix always contains `@` because it passed signature verification; a missing `@` would raise → 500).
4. If `alias_domain not in user.available_alias_domains()` → `False`.
5. If `alias_domain` is in `available_sl_domains` (list from `get_sl_domains()`) **and** not in `user_custom_domains` **and** `config.DISABLE_ALIAS_SUFFIX` is false: require `alias_domain_prefix.startswith(".")` else `False`. (SL-domain suffixes must look like `.word123@domain`.)
6. Else branch: if `alias_domain not in user_custom_domains`: if `DISABLE_ALIAS_SUFFIX` is false → `False`; if it's true and `alias_domain not in available_sl_domains` → `False`.
7. Otherwise `True`.

`DISABLE_ALIAS_SUFFIX = "DISABLE_ALIAS_SUFFIX" in os.environ` (bool; when true, SL-domain suffixes have no random `.word` part, i.e. suffix is just `@domain`).

### 3.8 `get_alias_suffixes(user)` → `List[AliasSuffix]` (`app/alias_suffix.py`)

`AliasSuffix` dataclass fields: `is_custom: bool`, `suffix: str`, `signed_suffix: str`, `is_premium: bool`, `domain: str`, `mx_verified: bool = True`.

Construction order (ORDER MATTERS — clients show these in order and `/alias/random/new` uses `suffixes[0]`):

1. For each `custom_domain` in `user.verified_custom_domains()` (i.e. `ownership_verified = true`; ordered by domain ASC):
   - If `custom_domain.random_prefix_generation` (bool column on `custom_domain`): add `AliasSuffix(is_custom=True, suffix=f".{user.get_random_alias_suffix(custom_domain)}@{custom_domain.domain}", signed_suffix=sign(suffix), is_premium=False, domain=custom_domain.domain, mx_verified=custom_domain.verified)`. Inserted at index 0 if `user.default_alias_custom_domain_id == custom_domain.id`, else appended.
   - Always add the plain suffix `f"@{custom_domain.domain}"` (same fields). Inserted at index 0 if it is the default custom domain **and** `random_prefix_generation` is off, else appended.
   - Note `mx_verified` mirrors `custom_domain.verified` (MX check), distinct from `ownership_verified`.
2. For each `sl_domain` in `user.get_sl_domains()` (ordered by `order`):
   - `prefix = "" if config.DISABLE_ALIAS_SUFFIX else f".{user.get_random_alias_suffix()}"`; `suffix = f"{prefix}@{sl_domain.domain}"`.
   - `AliasSuffix(is_custom=False, suffix=suffix, signed_suffix=sign(suffix), is_premium=sl_domain.premium_only, domain=sl_domain.domain, mx_verified=True)`.
   - If `user.default_alias_public_domain_id` equals this domain's id → **insert at index 0** (i.e. ahead of custom domains!) and set `default_domain_found = True`; else append.
3. If `default_domain_found` is still False: look up `SLDomain.get_by(id=user.default_alias_public_domain_id, hidden=False[, premium_only=False if not user.is_premium()])`; if found, build the same SL-domain suffix and insert at index 0. (With `default_alias_public_domain_id = None` this lookup matches nothing.)

Every suffix gets a **fresh random word/string and a fresh signature on every call**.

### 3.9 `Alias.create(**kw)` (`app/models.py`) — used by all creation paths

1. Pops `commit` / `flush` kwargs.
2. Bucket rate limits (see 1.5) — may raise 429.
3. `email = sanitize_email(kw["email"])`: strip, remove spaces, `\n`→space, lowercase, strip `‏`.
4. If `DeletedAlias.get_by(email=email)` or `DomainDeletedAlias.get_by(email=email)` → raise `AliasInTrashError`.
5. Custom-domain detection: if `custom_domain_id` not passed, `Alias.get_custom_domain(email)` — this calls `validate_email(email, check_deliverability=False, allow_smtputf8=False)` (**python `email-validator ~= 2.2.0`; raises `EmailNotValidError` for invalid addresses**) and takes the domain part; if that domain exists in `custom_domain` but NOT in `public_domain`, returns the CustomDomain row.
6. If a custom domain was found and `custom_domain.user_id != user.id` → raise `AliasDomainForbidden` (unhandled in these routes → 500; can't normally happen because `verify_prefix_suffix` runs first).
7. Sets `custom_domain_id`; if the custom domain has `partner_id`, sets alias flag `FLAG_PARTNER_CREATED = 1<<0` and possibly user flag `FLAG_CREATED_ALIAS_FROM_PARTNER = 1<<3`.
8. `DailyMetric.get_or_create_today_metric().nb_alias += 1` (row in `daily_metric` for today's date).
9. Emits: `AliasCreated` event via `EventDispatcher` (partner sync webhooks/queue, protobuf: `id, email, note, enabled=True, created_at=int(created_at.timestamp)`), an alias audit-log entry (`alias_audit_log` table, action `CreateAlias`, message `"New alias created"`), and a NewRelic custom event.
10. Column defaults on insert: `enabled=true`, `flags=0`, `automatic_creation=false`, `pinned=false`, `disable_pgp=false`, `id/created_at/updated_at` from ModelMixin (`created_at = arrow.utcnow()`).

### 3.10 `Alias.create_new_random(user, scheme, in_hex=False, note=None)`

```python
custom_domain = None
random_email = None
if user.default_alias_custom_domain_id:
    custom_domain = CustomDomain.get(user.default_alias_custom_domain_id)
    random_email = generate_random_alias_email(scheme=scheme, in_hex=in_hex, alias_domain=custom_domain.domain)
elif user.default_alias_public_domain_id:
    sl_domain = SLDomain.get(user.default_alias_public_domain_id)
    if sl_domain.premium_only and not user.is_premium():
        pass  # log warning; random_email stays None
    else:
        random_email = generate_random_alias_email(scheme=scheme, in_hex=in_hex, alias_domain=sl_domain.domain)
if not random_email:
    random_email = generate_random_alias_email(scheme=scheme, in_hex=in_hex)   # FIRST_ALIAS_DOMAIN
alias = Alias.create(user_id=user.id, email=random_email, mailbox_id=user.default_mailbox_id, note=note)
if custom_domain:
    alias.custom_domain_id = custom_domain.id
return alias
```

`generate_random_alias_email(scheme, in_hex=False, alias_domain=config.FIRST_ALIAS_DOMAIN, retries=10)`:
- `scheme == AliasGeneratorEnum.uuid.value (2)` → local part = `uuid.uuid4()` string (hex form only if `in_hex`, which the API never sets → dashed UUID).
- else (word scheme, 1) → local part = `random_words(2, 3)` → `word_word` + 3 digits, e.g. `sunny_falcon123`.
- `random_email = (local + "@" + alias_domain).lower().strip()`.
- Availability check `available_sl_email(email)`: email must not exist in `alias.email`, `contact.reply_email`, or `deleted_alias.email` (note: `domain_deleted_alias` NOT checked here — but `Alias.create` re-checks it and raises `AliasInTrashError`).
- On collision, recurses up to 10 times — **gotcha: the recursive call does not pass `alias_domain`, so retries fall back to `FIRST_ALIAS_DOMAIN`**. After 10 retries raises `Exception("Cannot generate alias after many retries")` → 500.
- `FIRST_ALIAS_DOMAIN = env FIRST_ALIAS_DOMAIN or EMAIL_DOMAIN` (EMAIL_DOMAIN env, lowercased).

Enum: `AliasGeneratorEnum.word = 1`, `AliasGeneratorEnum.uuid = 2`. User column `alias_generator` default `1` (word).

### 3.11 Response serializer — `serialize_alias_info_v2(get_alias_info_v2(alias))` (`app/api/serializer.py`)

`get_alias_info_v2(alias)`: mailbox = `alias.mailbox` (the row for `alias.mailbox_id`); `mailboxes = [mailbox] + alias._mailboxes` (the `alias_mailbox` join table), then `list(set(...))` — **deduplicated, order not guaranteed**. Counts over all `(Contact, EmailLog)` pairs of the alias: `nb_reply` (email_log.is_reply), `nb_blocked` (email_log.blocked), `nb_forward` (otherwise); tracks the latest email_log/contact by `created_at` (must be strictly greater than `alias.created_at`).

`serialize_alias_info_v2` returns exactly:

```python
{
    "id": alias.id,                                   # int
    "email": alias.email,                             # str
    "creation_date": alias.created_at.format(),       # arrow 0.16 default: "YYYY-MM-DD HH:mm:ssZZ" e.g. "2021-03-10 20:36:08+00:00"
    "creation_timestamp": alias.created_at.timestamp, # int unix seconds (arrow 0.16 property)
    "enabled": alias.enabled,                         # bool (true for new aliases)
    "note": alias.note,                               # str | null
    "name": alias.name,                               # str | null
    "nb_forward": 0, "nb_block": 0, "nb_reply": 0,    # ints (0 for a brand-new alias)
    "mailbox": {"id": mailbox.id, "email": mailbox.email},
    "mailboxes": [{"id": mb.id, "email": mb.email}, ...],
    "support_pgp": alias.mailbox_support_pgp(),       # bool: any mailbox has PGP enabled
    "disable_pgp": alias.disable_pgp,                 # bool (false for new)
    "latest_activity": None,                          # null for a brand-new alias, else {"timestamp": int, "action": "forward"|"reply"|"block"|"bounced", "contact": {"email","name","reverse_alias"}}
    "pinned": alias.pinned,                           # bool (false for new)
}
```

The creation routes return `jsonify(alias=<full alias email str>, **serialize_alias_info_v2(...))` — i.e. the serialized dict **plus** a top-level `"alias"` key (string), status **201**.

---

## 4. Route: `GET /api/v4/alias/options`

```python
@api_bp.route("/v4/alias/options")
@require_api_auth
def options_v4():
```

- **Method**: GET only (Flask default). Full path `/api/v4/alias/options`.
- **Auth**: `require_api_auth` (see 1.1). No rate limit decorator. No body.
- **Query params**: `hostname` (optional string; e.g. `www.groupon.com`).

Behavior:
1. `ret = {"can_create": user.can_create_new_alias(), "suffixes": [], "prefix_suggestion": ""}`.
2. If `hostname` (non-empty): query `AliasUsedOn ⋈ Alias` where `AliasUsedOn.alias_id = Alias.id AND Alias.user_id = user.id AND AliasUsedOn.hostname = <hostname>` (exact string match), ordered by `AliasUsedOn.created_at DESC`, take first. If found: `ret["recommendation"] = {"alias": alias.email, "hostname": hostname}`. (The `recommendation` key is **absent**, not null, when there is no match or no hostname.) *(Implementation detail: the ORM query also selects `User` with no join condition — a cross join; irrelevant to results, don't replicate.)*
3. If `hostname`: `ret["prefix_suggestion"] = convert_to_id(tldextract.extract(hostname).domain)` — tldextract splits using the Public Suffix List; `.domain` is the registrable label without TLD/subdomain (`www.groupon.com` → `groupon`, `foo.co.uk` → `foo`).
4. `suffixes = get_alias_suffixes(user)` (see 3.8); `ret["suffixes"] = [[suffix.suffix, suffix.signed_suffix], ...]` — **array of 2-element arrays** `[suffix, signed_suffix]`, in the order from 3.8.
5. `200` with `jsonify(ret)`.

**Success 200 body**:
```json
{
  "can_create": true,
  "prefix_suggestion": "groupon",
  "suffixes": [[".cat123@sl.local", ".cat123@sl.local.aKpD2w.sig..."], ...],
  "recommendation": {"alias": "x@y.z", "hostname": "www.groupon.com"}   // optional key
}
```

**Errors**: only the auth errors from 1.1.

---

## 5. Route: `GET /api/v5/alias/options`

```python
@api_bp.route("/v5/alias/options")
@require_api_auth
def options_v5():
```

Identical to v4 (same auth, same `hostname` param, same `can_create` / `prefix_suggestion` / optional `recommendation`) **except** `suffixes` is a list of objects:

```python
ret["suffixes"] = [
    {
        "suffix": suffix.suffix,
        "signed_suffix": suffix.signed_suffix,
        "is_custom": suffix.is_custom,      # bool: custom domain vs SL domain
        "is_premium": suffix.is_premium,    # bool: SLDomain.premium_only; always false for custom domains
    }
    for suffix in suffixes
]
```

(`domain` and `mx_verified` fields of the dataclass are NOT exposed.) Status 200.

---

## 6. Route: `POST /api/v2/alias/custom/new`

```python
@api_bp.route("/v2/alias/custom/new", methods=["POST"])
@require_api_auth
@limiter.limit(ALIAS_LIMIT)                       # "100/day;50/hour;5/minute"
@parallel_limiter.lock(name="alias_creation")
def new_custom_alias_v2():
```

- **Query param**: `hostname` (optional).
- **JSON body**: `alias_prefix` (str, required non-empty), `signed_suffix` (str, required non-empty), `note` (optional, any JSON value — stored as-is).

Exact flow (order matters for which error wins):

1. `if not user.can_create_new_alias()` → `400 {"error": "You have reached the limitation of a free account with the maximum of {MAX_NB_EMAIL_FREE_PLAN} aliases, please upgrade your plan to create more aliases"}` — note: the number interpolated is always `MAX_NB_EMAIL_FREE_PLAN` (default 5) even for old-limit users.
2. `data = request.get_json()`; if falsy (no/empty JSON, or non-JSON content type) → `400 {"error": "request body cannot be empty"}`. (Malformed JSON with a JSON content-type → framework `400 {"error": "Bad Request"}`.)
3. `alias_prefix = data.get("alias_prefix", "")`; if not a str or empty → `400 {"error": "invalid value for alias_prefix"}`.
4. `alias_prefix = alias_prefix.strip().lower().replace(" ", "")`.
5. `signed_suffix = data.get("signed_suffix", "")`; if not str or empty → `400 {"error": "invalid value for signed_suffix"}`; then `signed_suffix = signed_suffix.strip()`.
6. `note = data.get("note")`; `alias_prefix = convert_to_id(alias_prefix)` (see 3.1; truncates to 64 chars).
   - **v2 does NOT run `check_alias_prefix`** — no 40-char/regex prefix validation.
7. Suffix verification: `alias_suffix = check_suffix_signature(signed_suffix)` (see section 2). If it returns `None` → `412 {"error": "Alias creation time is expired, please retry"}`. If it raises a non-BadSignature exception → `400 {"error": "Tampered suffix"}` (effectively unreachable).
8. `if not verify_prefix_suffix(user, alias_prefix, alias_suffix)` (see 3.7) → `400 {"error": "wrong alias prefix or suffix"}`.
9. `full_alias = alias_prefix + alias_suffix`. If it exists in `Alias`, `DeletedAlias`, or `DomainDeletedAlias` (by `email` column) → `409 {"error": "alias {full_alias} already exists"}` (message includes the alias).
10. If `".." in full_alias` → `400 {"error": "2 consecutive dot signs aren't allowed in an email address"}`.
11. `alias = Alias.create(user_id=user.id, email=full_alias, mailbox_id=user.default_mailbox_id, note=note)` (see 3.9). If `EmailNotValidError` is raised (from the internal `validate_email` in `get_custom_domain`) → `400 {"error": "Email is not valid"}`. (An `AliasInTrashError` here is unhandled → 500, but step 9 pre-checks the same tables.)
12. `Session.commit()`.
13. If `hostname`: `AliasUsedOn.create(alias_id=alias.id, hostname=hostname, user_id=alias.user_id)` + commit (unconditional insert; table has unique `(alias_id, hostname)` — safe because alias is new).
14. **`201`** with `jsonify(alias=full_alias, **serialize_alias_info_v2(get_alias_info_v2(alias)))` (see 3.11). The new alias's mailbox is the user's `default_mailbox_id`; `name` is null.

---

## 7. Route: `POST /api/v3/alias/custom/new`

```python
@api_bp.route("/v3/alias/custom/new", methods=["POST"])
@require_api_auth
@limiter.limit(ALIAS_LIMIT)
@parallel_limiter.lock(name="alias_creation")
def new_custom_alias_v3():
```

- **Query param**: `hostname` (optional).
- **JSON body**: `alias_prefix` (str), `signed_suffix` (str), `mailbox_ids` (**required** list of ints), `note` (optional), `name` (optional str).

Exact flow:

1. `can_create_new_alias()` check → same `400` message as v2 (with `MAX_NB_EMAIL_FREE_PLAN`).
2. `data = request.get_json()`; falsy → `400 {"error": "request body cannot be empty"}`.
3. `if not isinstance(data, dict)` → `400 {"error": "request body does not follow the required format"}`.
4. `alias_prefix_data = data.get("alias_prefix", "") or ""`; if not str → `400 {"error": "request body does not follow the required format"}`. (`None` becomes `""`; a non-str like an int → this error.)
5. `alias_prefix = alias_prefix_data.strip().lower().replace(" ", "")`.
6. `signed_suffix = data.get("signed_suffix", "") or ""`; if not str → `400 {"error": "request body does not follow the required format"}`; then `.strip()`.
7. `mailbox_ids = data.get("mailbox_ids")`; `note = data.get("note")`; `name = data.get("name")`; if `name`: `name = name.replace("\n", "")`.
8. `alias_prefix = convert_to_id(alias_prefix)`.
9. `if not check_alias_prefix(alias_prefix)` (see 3.2; empty prefix fails too) → `400 {"error": "alias prefix invalid format or too long"}`.
10. `if not isinstance(mailbox_ids, list)` → `400 {"error": "mailbox_ids must be an array of id"}`.
11. For each `mailbox_id`: `mailbox = Mailbox.get(mailbox_id)`; if missing, or `mailbox.user_id != user.id`, or `not mailbox.verified` → `400 {"error": "Errors with Mailbox"}`.
12. If the resulting list is empty (`mailbox_ids == []`) → `400 {"error": "At least one mailbox must be selected"}`.
13. Suffix signature check — identical to v2 step 7: `None` → `412 {"error": "Alias creation time is expired, please retry"}`; exception → `400 {"error": "Tampered suffix"}`.
14. `verify_prefix_suffix` → `400 {"error": "wrong alias prefix or suffix"}`.
15. Existence check in `Alias`/`DeletedAlias`/`DomainDeletedAlias` → `409 {"error": "alias {full_alias} already exists"}`.
16. `".." in full_alias` → `400 {"error": "2 consecutive dot signs aren't allowed in an email address"}`.
17. Explicit `validate_email(full_alias, check_deliverability=False, allow_smtputf8=False)` (email-validator 2.2.0); on `EmailNotValidError` → `400 {"error": "Email alias is invalid"}` (**different message than v2's "Email is not valid"**).
18. `alias = Alias.create(user_id=user.id, email=full_alias, note=note, name=name or None, mailbox_id=mailboxes[0].id)`; `Session.flush()`. First mailbox in the submitted list becomes `alias.mailbox_id`.
19. For each remaining mailbox (index 1..n): `AliasMailbox.create(alias_id=alias.id, mailbox_id=mailboxes[i].id)`. Then `Session.commit()`.
20. If `hostname`: insert `AliasUsedOn(alias_id, hostname, user_id)` + commit.
21. **`201`** with `jsonify(alias=full_alias, **serialize_alias_info_v2(get_alias_info_v2(alias)))`. `mailboxes` in the response contains all selected mailboxes (deduplicated, order not guaranteed); `name` echoes the (newline-stripped) name or null.

Duplicate ids inside `mailbox_ids` are NOT deduplicated before insert — duplicates would violate the `alias_mailbox` unique constraint → 500. (Clients don't send duplicates; note for robustness.)

---

## 8. Route: `POST /api/alias/random/new`

```python
@api_bp.route("/alias/random/new", methods=["POST"])
@require_api_auth
@limiter.limit(ALIAS_LIMIT)
@parallel_limiter.lock(name="alias_creation")
def new_random_alias():
```

- **Query params**: `hostname` (optional str), `mode` (optional; must be `"word"` or `"uuid"` if present).
- **JSON body**: optional; parsed with `request.get_json(silent=True)` — malformed/absent JSON is tolerated (never a body-related 400). If a JSON object is present, `note = data.get("note")`.

Exact flow:

1. `can_create_new_alias()` check → `400` with the same free-plan message (note: this variant of the string is built with an f-string over two concatenated pieces; the final text is identical to v2/v3: `"You have reached the limitation of a free account with the maximum of {MAX_NB_EMAIL_FREE_PLAN} aliases, please upgrade your plan to create more aliases"`).
2. **Hostname one-click path** — only if `hostname` is present AND `user.include_website_in_one_click_alias` (bool column; python default `True` for new users, DB server_default `"0"`):
   - `prefix_suggestion = convert_to_id(tldextract.extract(hostname).domain)`.
   - `suffixes = get_alias_suffixes(user)`; `suggested_alias = prefix_suggestion + suffixes[0].suffix` (**the first suffix**, i.e. the user's default domain per 3.8 ordering, with a freshly generated random word).
   - `alias = Alias.get_by(email=suggested_alias)`:
     - exists and belongs to another user → `alias = None` (fall through to random path);
     - exists and belongs to this user → reused **only if** an `AliasUsedOn` row with `(alias_id, hostname, user_id)` exists, else `alias = None`;
     - doesn't exist → `Alias.create(user_id=user.id, email=suggested_alias, note=note, mailbox_id=user.default_mailbox_id, commit=True)`; on `AliasInTrashError` → `alias = None` (fall through).
   - (Because the suffix contains a fresh random word, `Alias.get_by(email=suggested_alias)` virtually never matches unless `DISABLE_ALIAS_SUFFIX` is on or a custom-domain plain suffix is first.)
3. **Random path** — if `alias` is still None:
   - `scheme = user.alias_generator` (int column, default `1` = word).
   - If query param `mode` present: `"word"` → scheme 1; `"uuid"` → scheme 2; anything else → `400 {"error": "{mode} must be either word or uuid"}` (the submitted mode value is interpolated, e.g. `"foo must be either word or uuid"`).
   - `alias = Alias.create_new_random(user=user, scheme=scheme, note=note)` (see 3.10; domain = default custom domain > default public domain (if allowed) > `FIRST_ALIAS_DOMAIN`; local part = `word_word###` or dashed UUID4); `Session.commit()`.
4. If `hostname` and no `AliasUsedOn` row `(alias_id=alias.id, hostname=hostname)` exists yet: `AliasUsedOn.create(alias_id=alias.id, hostname=hostname, user_id=alias.user_id, commit=True)`.
5. **`201`** with `jsonify(alias=alias.email, **serialize_alias_info_v2(get_alias_info_v2(alias)))`.

**Gotcha:** this endpoint can return an *existing* alias (hostname reuse path) — still with status 201, and in that case `nb_forward`/`latest_activity`/etc. reflect the existing alias's history.

**Errors**: auth errors (1.1); free-plan 400; invalid mode 400; 429s (1.3/1.4/1.5); `Exception("Cannot generate alias after many retries")` → 500 `{"error": "Internal error"}`.

---

## 9. Implementation notes for Cloudflare

### DB tables/columns touched

| Table | Access | Columns used |
|---|---|---|
| `api_key` | R/W | `code` (lookup), `user_id`, `last_used` (write now()), `times` (increment) |
| `users` | R (+rare W) | `id, disabled, delete_on, lifetime, trial_end, flags, default_mailbox_id, default_alias_custom_domain_id, default_alias_public_domain_id, alias_generator, random_alias_suffix, include_website_in_one_click_alias` (+ `flags` write for FLAG_CREATED_ALIAS_FROM_PARTNER) |
| `subscription`, `apple_subscription`, `manual_subscription`, `coinbase_subscription`, `partner_subscription`/`partner_user` | R | active-subscription checks for `is_premium` / `lifetime_or_active_subscription` |
| `alias` | R/W | count by `(user_id, delete_on IS NULL)`; lookup by `email`; insert `user_id, email, note, name, mailbox_id, custom_domain_id, flags, enabled(default true), created_at` |
| `alias_mailbox` | W | v3: `(alias_id, mailbox_id)` for mailboxes[1:] ; R via `alias._mailboxes` for serialization |
| `mailbox` | R | `id, user_id, verified, email`, PGP fields (`pgp_finger_print`/disable flags) for `support_pgp` |
| `alias_used_on` | R/W | `(alias_id, hostname, user_id, created_at)`; unique `(alias_id, hostname)` |
| `deleted_alias` | R | `email` (global trash) |
| `domain_deleted_alias` | R | `email` (custom-domain trash) |
| `custom_domain` | R | `user_id, domain, ownership_verified, verified (MX), random_prefix_generation, partner_id` |
| `public_domain` (SLDomain) | R | `id, domain, premium_only, hidden, order, partner_id` |
| `contact` / `email_log` | R | activity counts + latest activity for the serialized response; `contact.reply_email` for `available_sl_email` |
| `daily_metric` | W | `nb_alias` increment on every creation |
| `alias_audit_log` | W | one row per creation (action `CreateAlias`, message `"New alias created"`) |
| Redis | R/W | flask-limiter counters, `cl:{key}:alias_creation` lock (SET NX EX 5), `bl:alias_create_{bucket}:{user_id}:{bucket_id}` counters |

### Python-specific behaviors to replicate exactly

- **Datetime format**: `creation_date` uses arrow 0.16 `Arrow.format()` default → `"YYYY-MM-DD HH:mm:ssZZ"` → e.g. `2021-03-10 20:36:08+00:00` (UTC, `+00:00` with colon). `creation_timestamp` / `latest_activity.timestamp` are integer unix seconds.
- **Suffix signature** (must be byte-compatible if old signed suffixes should verify across implementations; max age is only 600 s so a hard cutover is also viable):
  - `derived_key = SHA1(utf8("itsdangerous.Signer") || utf8("signer") || utf8(FLASK_SECRET + "custom_alias"))` (20 bytes)
  - `ts_b64 = b64url_nopad(big_endian_minimal_bytes(unix_seconds))`
  - `signed = suffix + "." + ts_b64 + "." + b64url_nopad(HMAC_SHA1(derived_key, utf8(suffix + "." + ts_b64)))`
  - Verify by splitting on the **rightmost** two dots (the suffix itself contains dots and an `@`). Constant-time HMAC compare. Age check: `now - ts > 600` → expired.
  - Both bad signature and expiry → `412 {"error": "Alias creation time is expired, please retry"}`. Keep the `400 {"error": "Tampered suffix"}` string for schema completeness, but it is effectively unreachable in the Python code.
- **`convert_to_id`**: lowercase → `unidecode` transliteration (approximate with a JS lib like `unidecode`/`any-ascii`; must at least strip accents) → remove spaces → map every char outside `[a-zA-Z0-9_\-.]` to `_` → truncate to 64.
- **email validation**: python `email-validator` 2.2.0 with `check_deliverability=False, allow_smtputf8=False` — ASCII-only addresses, RFC-based local-part/domain validation, requires a dot in the domain (no TLD-less domains), rejects leading/trailing dots etc. Closest JS equivalence needs care; error → v2 `"Email is not valid"`, v3 `"Email alias is invalid"`.
- **tldextract** uses the Public Suffix List; `ext.domain` = registrable label (SLD) without suffix. Reimplement with a PSL library; note tldextract 3.x may fetch a live PSL copy at first use (bundle a snapshot instead).
- **Word list**: `local_data/words.txt` (~7590 words) must be bundled; selection uses a CSPRNG (`secrets.choice`).
- **uuid mode**: standard lowercase dashed UUIDv4 as the local part.
- **Random suffix**: default length 5 (`ALIAS_RAND_SUFFIX_LENGTH` env, config name `ALIAS_RANDOM_SUFFIX_LENGTH`) lowercase alphanumeric when user `random_alias_suffix == 1`; otherwise `word + 3 digits` (SL domains / no custom domain) or bare `word` (custom domains).
- **Config flags consulted**: `MAX_NB_EMAIL_FREE_PLAN` (5), `MAX_NB_EMAIL_OLD_FREE_PLAN` (15), `DISABLE_ALIAS_SUFFIX` (presence-of-env bool), `ALIAS_LIMIT` (`"100/day;50/hour;5/minute"`), `ALIAS_CREATE_RATE_LIMIT_FREE` (`"10,900:50,3600"`), `ALIAS_CREATE_RATE_LIMIT_PAID` (`"50,900:200,3600"`), `DISABLE_RATE_LIMIT`, `FIRST_ALIAS_DOMAIN` (falls back to `EMAIL_DOMAIN`), `CUSTOM_ALIAS_SECRET = FLASK_SECRET + "custom_alias"`, `WORDS_FILE_PATH`.
- **Response envelope**: creation responses are the alias-info dict with an extra top-level `"alias"` string; key order is irrelevant (Flask 1.x jsonify sorts keys alphabetically by default — clients must not depend on order, but note the bodies you see in production are alphabetically sorted).
- **`recommendation`** key in options responses is omitted (not `null`) when absent.
- Side-effect events (protobuf `AliasCreated` to the partner event dispatcher, audit log, daily metric, NewRelic event) should be mapped to whatever eventing exists in the new stack; they do not affect the HTTP contract.
