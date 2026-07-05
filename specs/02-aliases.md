# Spec 02 — Alias & Contact API

Source files (authoritative):
- `/app/api/views/alias.py` (all routes below)
- `/app/api/serializer.py` (AliasInfo, serializers, pagination queries)
- `/app/alias_delete.py` (delete/trash logic)
- `/app/contact_utils.py`, `/app/dashboard/views/alias_contact_manager.py` (contact creation)
- `/app/dashboard/views/alias_log.py` (`get_alias_log`)
- `/app/api/base.py` (auth), `/app/models.py` (Alias, Contact, EmailLog, Mailbox)

All routes are registered on the `api` Blueprint with `url_prefix="/api"` — final paths are `/api/...`.

Constant: `PAGE_LIMIT = 20` (`app/config.py` line 339). Every paginated endpoint in this file uses page size 20.

---

## 0. Authentication (`require_api_auth`, from `app/api/base.py`)

Every route in this spec uses `@require_api_auth`. Behavior of `authorize_request()`:

1. Read header **`Authentication`** (NOT `Authorization`). Look up `ApiKey` by `code == header value`.
2. If **no ApiKey found**:
   - If a Flask-Login session cookie user is authenticated **and** header **`X-Sl-Allowcookies`** (constant `HEADER_ALLOW_API_COOKIES = "X-Sl-Allowcookies"`, any non-empty value) is present → `g.user = current_user` (cookie fallback for the web app).
   - If the session user is **not** authenticated → `401 {"error": "Wrong api key"}`.
   - Edge case (faithful bug): session user authenticated but `X-Sl-Allowcookies` header absent → `g.user` is never set → Python `AttributeError` on `g.user.disabled` → HTTP 500.
3. If ApiKey found: update stats (`api_key.last_used = now`, `api_key.times += 1`, commit) and set `g.user = api_key.user`.
4. If `g.user.disabled` → `403 {"error": "Disabled account"}`.
5. If `not g.user.is_active()` → `401 {"error": "Account does not exist"}`. `User.is_active()` returns True if `user.delete_on IS NULL`, else `delete_on < now()` (i.e. a user scheduled for future deletion is inactive).
6. `g.api_key = api_key` (may be None with cookie auth).

No route in this file uses `require_api_sudo`.

### Rate limiting
`limiter` (flask-limiter) default key func: `f"userid:{current_user.id}"` if a Flask-Login session user is authenticated, else `f"ip:{remote_address}"`. NOTE: with header API-key auth there is no Flask-Login user, so default-keyed limits (`toggle_alias`, `get_alias_activities`) are keyed **by IP**. The two list endpoints override with `key_func=lambda: g.user.id` (keyed by user id). All rate limits are disabled when config `DISABLE_RATE_LIMIT` is set.

### Date/timestamp formats (critical for compatibility)
The project pins `arrow ~= 0.16.0`:
- `created_at.format()` → arrow default format `"YYYY-MM-DD HH:mm:ssZZ"`, e.g. `"2021-03-12 09:53:26+00:00"` (space separator, offset with colon; DB stores UTC so it is `+00:00`).
- `created_at.timestamp` → **property** (arrow < 1.0) returning an **integer** Unix timestamp (seconds).

---

## 1. GET|POST `/api/aliases` — list aliases v1 (deprecated)

```python
@deprecated
@api_bp.route("/aliases", methods=["GET", "POST"])
@require_api_auth
@limiter.limit("10/minute", key_func=lambda: g.user.id)
def get_aliases():
```

Request:
- Query param `page_id` (int, **required**). Parsed via `int(request.args.get("page_id"))`; `ValueError/TypeError` → `400 {"error": "page_id must be provided in request query"}`.
- Optional JSON body (yes, even on GET): `{"query": "<search>"}` — read with `request.get_json(silent=True)`.

Logic — `get_alias_infos_with_pagination(user, page_id, query)`:
- `SELECT alias WHERE user_id = :uid AND delete_on IS NULL ORDER BY created_at DESC LIMIT 20 OFFSET page_id*20`
- If `query`: additional filter `(alias.email ILIKE '%query%' OR alias.note ILIKE '%query%')`.
- For each alias, `get_alias_info(alias)` iterates all `(Contact, EmailLog)` rows joined on `Contact.alias_id == alias.id AND EmailLog.contact_id == Contact.id` and counts: `is_reply` → nb_reply, elif `blocked` → nb_blocked, else nb_forward.

Response `200`:
```json
{"aliases": [ {
  "id": <int>,
  "email": <str>,
  "creation_date": "<arrow format, e.g. 2021-03-12 09:53:26+00:00>",
  "creation_timestamp": <int>,
  "enabled": <bool>,
  "note": <str|null>,
  "nb_forward": <int>,
  "nb_block": <int>,
  "nb_reply": <int>
} ] }
```
(Exactly `serialize_alias_info` — note key is `nb_block`, not `nb_blocked`.)

---

## 2. GET|POST `/api/v2/aliases` — list aliases v2

```python
@api_bp.route("/v2/aliases", methods=["GET", "POST"])
@require_api_auth
@limiter.limit("50/minute", key_func=lambda: g.user.id)
def get_aliases_v2():
```

Request:
- Query param `page_id` (int, **required**) — same parsing/error as v1: `400 {"error": "page_id must be provided in request query"}`.
- Query flags `pinned`, `disabled`, `enabled` — **presence-based**: `"pinned" in request.args` (value is ignored; `?pinned=false` still activates it). Precedence if several present: `pinned` > `disabled` > `enabled`; only one filter is applied. None present → no filter.
- Optional JSON body: `{"query": "<search>"}` (via `request.get_json(silent=True)`).

Logic — `get_alias_infos_with_pagination_v3(user, page_id=page_id, query=query, alias_filter=alias_filter)` (sort is never passed by this route → always the default sort):

`construct_alias_query(user)` builds, in SQL terms:
```sql
-- activity subquery, one row per alias:
SELECT alias.id,
       SUM(CASE WHEN email_log.is_reply THEN 1 ELSE 0 END)                                        AS nb_reply,
       SUM(CASE WHEN email_log.is_reply IS FALSE AND email_log.blocked THEN 1 ELSE 0 END)          AS nb_blocked,
       SUM(CASE WHEN email_log.is_reply IS FALSE AND email_log.blocked IS FALSE THEN 1 ELSE 0 END) AS nb_forward
FROM alias LEFT OUTER JOIN email_log ON alias.id = email_log.alias_id
WHERE alias.user_id = :uid AND alias.delete_on IS NULL
GROUP BY alias.id

-- main query:
SELECT alias.*, contact.*, email_log.*, sub.nb_reply, sub.nb_blocked, sub.nb_forward
FROM alias
LEFT OUTER JOIN email_log ON alias.last_email_log_id = email_log.id   -- latest activity comes from alias.last_email_log_id
LEFT OUTER JOIN contact   ON email_log.contact_id = contact.id
WHERE alias.id = sub.id
```
(also `joinedload` of `hibp_breaches` and `custom_domain`, which don't affect JSON here.)

Filters applied by `get_alias_infos_with_pagination_v3`:
- `query`: `OR(alias.email ILIKE '%q%', alias.note ILIKE '%q%', alias.ts_vector @@ plainto_tsquery('english', q), alias.name ILIKE '%q%')`. `ts_vector` is a generated Postgres column `to_tsvector('english', note)` — full-text search over the note only.
- `alias_filter == "enabled"` → `WHERE alias.enabled`; `"disabled"` → `WHERE alias.enabled IS FALSE`; `"pinned"` → `WHERE alias.pinned`. (The function also supports `"hibp"`, `mailbox_id`, `directory_id`, and sorts `old2new|new2old|a2z|z2a`, but this API route never passes them.)
- Default sort (always used here): `ORDER BY alias.pinned DESC, GREATEST(alias.created_at, email_log.created_at) DESC` — pinned aliases first, then by most recent of (creation, latest activity). Postgres `GREATEST` ignores NULLs, so aliases with no activity sort by `created_at`.
- `LIMIT 20 OFFSET page_id * 20`.

Each row becomes `AliasInfo(alias, mailbox=alias.mailbox, mailboxes=alias.mailboxes, nb_forward, nb_blocked, nb_reply, latest_email_log=email_log, latest_contact=contact, custom_domain=alias.custom_domain)`.

`Alias.mailboxes` property (used for the list): `[alias.mailbox] + alias._mailboxes (alias_mailbox join table)`, dedup by id, **filtered to `verified == true` only**, **sorted by mailbox email ascending**.

Response `200` — `{"aliases": [serialize_alias_info_v2(...)]}`:
```json
{
  "id": <int>,
  "email": <str>,
  "creation_date": "<arrow format>",
  "creation_timestamp": <int>,
  "enabled": <bool>,
  "note": <str|null>,
  "name": <str|null>,
  "nb_forward": <int>,
  "nb_block": <int>,
  "nb_reply": <int>,
  "mailbox": {"id": <int>, "email": <str>},
  "mailboxes": [{"id": <int>, "email": <str>}, ...],
  "support_pgp": <bool>,
  "disable_pgp": <bool>,
  "latest_activity": null | {
    "timestamp": <int>,
    "action": "forward" | "reply" | "block" | "bounced",
    "contact": {
      "email": <str>,          // contact.website_email
      "name": <str|null>,
      "reverse_alias": <str>   // contact.website_send_to(), see §12
    }
  },
  "pinned": <bool>
}
```
- `mailbox` = the alias's primary mailbox (`alias.mailbox_id`).
- `support_pgp` = `alias.mailbox_support_pgp()`: True if ANY verified mailbox of the alias has `pgp_finger_print` set and `mailbox.disable_pgp` false.
- `latest_activity` present only when `alias.last_email_log_id` resolves to an EmailLog row; `action` = `EmailLog.get_action()`: `is_reply` → `"reply"`, elif `bounced` → `"bounced"`, elif `blocked` → `"block"`, else `"forward"`.

---

## 3. GET `/api/aliases/<int:alias_id>` — get one alias

```python
@api_bp.route("/aliases/<int:alias_id>", methods=["GET"])
@require_api_auth
def get_alias(alias_id):
```
No rate limit decorator.

Errors:
- Alias not found → **`400 {"error": "Unknown error"}`** (NOT 404 — clients may rely on this).
- `alias.user_id != user.id` → `403 {"error": "Forbidden"}`.

Success `200`: `serialize_alias_info_v2(get_alias_info_v2(alias))` — same JSON shape as one element of §2, but computed differently:

`get_alias_info_v2(alias)` (no mailbox arg → `mailbox = alias.mailbox`):
- Iterates ALL `(Contact, EmailLog)` for the alias (`Contact.alias_id == alias.id AND EmailLog.contact_id == Contact.id`) counting nb_reply / nb_blocked (`blocked` and not reply) / nb_forward, and tracking the email_log with max `created_at` **strictly greater than `alias.created_at`** as latest activity (`latest_activity` starts at `alias.created_at`; log equal to it is ignored).
- `mailboxes = [alias.mailbox] + alias._mailboxes`, deduped via `list(set(...))` — **unordered** (Python set order), and **includes unverified secondary mailboxes** (unlike the list endpoints, which use the verified/sorted `Alias.mailboxes` property).

---

## 4. DELETE `/api/aliases/<int:alias_id>` — delete alias

```python
@api_bp.route("/aliases/<int:alias_id>", methods=["DELETE"])
@require_api_auth
def delete_alias(alias_id):
```
No rate limit decorator.

- Not found or not owner → `403 {"error": "Forbidden"}`.
- Calls `alias_delete.delete_alias(alias, user, AliasDeleteReason.ManualAction, commit=True)`.
- Success `200 {"deleted": true}`.

### `alias_delete.delete_alias` semantics
`AliasDeleteReason` enum (int): Unspecified=0, UserHasBeenDeleted=1, **ManualAction=2**, DirectoryDeleted=3, MailboxDeleted=4, CustomDomainDeleted=5. `UserAliasDeleteAction` enum: MoveToTrash=0, DeleteImmediately=1.

Decision: if `alias.delete_on IS NOT NULL` (already trashed) **or** `user.alias_delete_action == DeleteImmediately` → `perform_alias_deletion`; else `move_alias_to_trash`.

`perform_alias_deletion(alias, user, reason, commit)`:
1. If `alias.custom_domain_id` set (`__delete_if_custom_domain`): if no `DomainDeletedAlias` row with `(email=alias.email, domain_id=alias.custom_domain_id)` exists, insert one with `user_id, email, domain_id, reason, alias_id`. Then hard delete (step 3). Return.
2. Else: if no `DeletedAlias` row with `email=alias.email` exists, insert `DeletedAlias(email, reason=alias.delete_reason or reason, alias_id)` (global trash — blocks the address from ever being reused, see `available_sl_email`).
3. `__delete_alias`: emit alias audit log (`action="delete"`, message `"Alias deleted by user action"`), `DELETE FROM alias WHERE id = :id` (contacts/email_logs cascade), dispatch `AliasDeleted(id, email)` webhook/event, commit.

`move_alias_to_trash(alias, user, reason, commit)`:
1. **Custom-domain aliases are never soft-trashed**: same `__delete_if_custom_domain` short-circuit as above (hard delete + DomainDeletedAlias row).
2. Else soft delete: `alias.delete_on = now() + ALIAS_TRASH_DAYS days` (config `ALIAS_TRASH_DAYS`, default **30**), `alias.delete_reason = reason`, `alias.enabled = False`. Emit audit log (`action="trash"`, `"Alias moved to trash by user action"`), dispatch `AliasDeleted` event, commit. Trashed aliases disappear from all list/query endpoints (`delete_on IS NULL` filter) but `Alias.get(id)` still returns them.

---

## 5. POST `/api/aliases/<int:alias_id>/toggle` — enable/disable

```python
@api_bp.route("/aliases/<int:alias_id>/toggle", methods=["POST"])
@require_api_auth
@limiter.limit("100/hour")            # default key func → IP for API-key clients
def toggle_alias(alias_id):
```
- Not found or not owner → `403 {"error": "Forbidden"}`.
- `alias_utils.change_alias_status(alias, enabled=not alias.enabled, message=f"Set enabled={not alias.enabled} via API")`: flips `alias.enabled`, dispatches `AliasStatusChanged` event, emits audit log (`action="change_status"`, message `"Set alias status to {enabled}. Set enabled={enabled} via API"`). Then `Session.commit()`.
- Success `200 {"enabled": <new bool>}`.

---

## 6. GET `/api/aliases/<int:alias_id>/activities`

```python
@api_bp.route("/aliases/<int:alias_id>/activities")
@require_api_auth
@limiter.limit("30/minute")           # default key func → IP for API-key clients
def get_alias_activities(alias_id):
```
- Query param `page_id` (int, **required**) — else `400 {"error": "page_id must be provided in request query"}`.
- Not found or not owner → `403 {"error": "Forbidden"}`.

`get_alias_log(alias, page_id)`: `SELECT contact, email_log WHERE contact.id = email_log.contact_id AND contact.alias_id = :aid ORDER BY email_log.id DESC LIMIT 20 OFFSET page_id*20`, then re-sorted in Python by `email_log.created_at` descending.

Response `200 {"activities": [...]}`, each activity dict:
```json
{
  "timestamp": <int>,                       // email_log.created_at.timestamp
  "reverse_alias": <str>,                   // contact.website_send_to() — full '"name | email at x" <ra@sl>'
  "reverse_alias_address": <str>,           // contact.reply_email (bare address)
  // if email_log.is_reply:
  "from": <alias.email>, "to": <contact.website_email>, "action": "reply"
  // else:
  "to": <alias.email>, "from": <contact.website_email>,
  "action": "bounced" (if bounced) | "block" (elif blocked) | "forward"
}
```

---

## 7. PUT|PATCH `/api/aliases/<int:alias_id>` — update alias

```python
@api_bp.route("/aliases/<int:alias_id>", methods=["PUT", "PATCH"])
@require_api_auth
def update_alias(alias_id):
```
No rate limit decorator.

- Empty/missing JSON body → `400 {"error": "request body cannot be empty"}` (uses `request.get_json()`; a non-JSON content type raises → Flask returns 400).
- Alias not found or not owner → `403 {"error": "Forbidden"}`.

Fields are checked by **key presence** (`"x" in data`), all optional, processed in this order:

1. `note` (str|null): `change_alias_note(alias, new_note)` — sets `alias.note`, dispatches `AliasNoteChanged` event. No validation; null clears the note.
2. `mailbox_id` (int): `int(data.get("mailbox_id"))` — **no try/except**: a non-numeric value raises and yields HTTP 500 (faithful behavior). Mailbox must exist, belong to user, and be verified, else **`400 {"error": "Forbidden"}`** (status 400 with body "Forbidden" — not 403). Sets `alias.mailbox_id`.
3. `mailbox_ids` (list of int): parse each with `int()`; `ValueError/TypeError` → `400 {"error": "Invalid mailbox_id"}`. Then `set_mailboxes_for_alias(user_id, alias, mailbox_ids)`:
   - empty list → error value `"Must choose at least one mailbox"` (400, `{"error": "<value>"}`)
   - more than 20 ids → `"Too many mailboxes"` (400)
   - fetch mailboxes `WHERE id IN (:ids) AND user_id = :uid AND verified = true ORDER BY id ASC`; if count mismatch (unknown/unverified/foreign id, or duplicate ids in request) → `"Forbidden"` (400)
   - any mailbox with admin-disabled flag (`flags & 1`) → `"Forbidden"` (400)
   - success: delete all `alias_mailbox` rows for the alias, set `alias.mailbox_id` to the **lowest-id** mailbox (ordering is by id ASC, NOT request order), create `AliasMailbox(alias_id, mailbox_id)` rows for the rest; emit audit log `action="changed_mailboxes"`.
4. `name` (str|null): if truthy and `len > 128` → `400 {"error": "Name can't be longer than 128 characters"}`. If truthy, strip `"\n"` chars (`replace("\n", "")`). Sets `alias.name` (null clears it; empty string is stored as-is).
5. `disable_pgp` (bool): set raw value on `alias.disable_pgp`.
6. `pinned` (bool): set raw value on `alias.pinned`.

If anything changed: emit audit log (`action="update"`, message `"Alias fields updated ({comma-separated field names})"` — mailbox entries formatted as `mailbox_id (123)` / `mailbox_ids (1,2,3)`), commit.

Success `200 {"ok": true}` (even when the body contained none of the known keys).

---

## 8. GET `/api/aliases/<int:alias_id>/contacts`

```python
@api_bp.route("/aliases/<int:alias_id>/contacts")
@require_api_auth
def get_alias_contacts_route(alias_id):
```
No rate limit decorator.

- Query param `page_id` (int, **required**) — else `400 {"error": "page_id must be provided in request query"}`.
- Alias not found → **`404 {"error": "No such alias"}`** (unlike GET alias which returns 400).
- Not owner → `403 {"error": "Forbidden"}`.

`get_alias_contacts(alias, page_id)`: `SELECT contact WHERE alias_id = :aid ORDER BY contact.id DESC LIMIT 20 OFFSET page_id*20`, each serialized with `serialize_contact` (§11).

Success `200 {"contacts": [ <serialize_contact>... ]}`.

---

## 9. POST `/api/aliases/<int:alias_id>/contacts` — create contact

```python
@api_bp.route("/aliases/<int:alias_id>/contacts", methods=["POST"])
@require_api_auth
def create_contact_route(alias_id):
```
No rate limit decorator.

- Empty/missing JSON body → `400 {"error": "request body cannot be empty"}`.
- Alias looked up by `Alias.get_by(id=alias_id, user_id=g.user.id)`; miss → `403 {"error": "Forbidden"}`.
- Body field: `contact` (str) — the contact address, may be `"email@example.com"` or `"Name <email@example.com>"`.

Calls dashboard `create_contact(alias, contact_address)` which wraps `contact_utils.create_contact(email=contact_address, alias=alias)`:

1. Empty/missing `contact` → raises `ErrAddressInvalid("Empty address")` → `400 {"error": "Empty address is not a valid email address"}`.
2. Permission: `alias.user.can_create_contacts()` — True if user is premium; OR if `user.flags & 1 == 0` (FLAG_FREE_DISABLE_CREATE_CONTACTS not set); else `not config.DISABLE_CREATE_CONTACTS_FOR_FREE_USERS`. Failure → `ContactCreateError.NotAllowed` → `ErrContactErrorUpgradeNeeded` → `403 {"error": "Please upgrade to premium to create reverse-alias"}`.
3. Parse with flanker `address.parse` (`parse_full_address`): `"AB CD <ab@cd.com>"` → name `"AB CD"`, email `"ab@cd.com"`; on parse failure both become `""`.
4. `name` = parsed display name truncated to 512 chars (`Contact.MAX_NAME_LENGTH`); empty → `None`; containing `\x00` → `""`.
5. `email = sanitize_email(email, not_lower=True)`: `strip()`, remove all `" "`, replace `"\n"` with `" "`, remove `"‏"`. **Case is preserved** in the stored `website_email`.
6. Validate with `email_validator.validate_email(email, check_deliverability=False, allow_smtputf8=False)`; invalid → `ContactCreateError.InvalidEmail` → `ErrAddressInvalid(contact_address)` → `400 {"error": "{contact_address} is not a valid email address"}` (message contains the ORIGINAL body value, not the parsed email).
7. If `Contact.get_by(alias_id, website_email=email)` exists: update its `name` (if parsed name differs) — then `created=False` → `ErrContactAlreadyExists` → **`200`** with `serialize_contact(contact, existed=True)` (not 409, despite the docstring).
8. Generate `reply_email = generate_reply_email(email, alias)` (§13) and `Contact.create(user_id=alias.user_id, alias_id, website_email=email, name, reply_email, mail_from=None, automatic_created=False, flags=0, invalid_email=(email==""), commit=True)`.
   - `Contact.create` guard: if lowercased `website_email` is not in `config.NOREPLIES` and equals some existing contact's `reply_email` → raises `CannotCreateContactForReverseAlias`; `contact_utils` catches it and maps to `InvalidEmail` → so the API answers `400 {"error": "{contact_address} is not a valid email address"}` (the route's dedicated `CannotCreateContactForReverseAlias` handler returning `"You can't create contact for a reverse alias"` is effectively dead code on this path).
   - `IntegrityError` (unique `(alias_id, website_email)` race): rollback, re-fetch existing contact → treated as "already exists" (200 with `existed: true`); if re-fetch fails → `ContactCreateError.Unknown` → `ErrAddressInvalid("Invalid address")` → `400 {"error": "Invalid address is not a valid email address"}`.
   - Emits audit log `action="create_contact"`, message `"Created contact {id} ({email}). Created by user action"`.

Success `201` with `serialize_contact(contact)` (§11, `existed: false`).

---

## 10. DELETE `/api/contacts/<int:contact_id>` and POST `/api/contacts/<int:contact_id>/toggle`

```python
@api_bp.route("/contacts/<int:contact_id>", methods=["DELETE"])
@require_api_auth
def delete_contact(contact_id):
```
- Contact not found or `contact.alias.user_id != user.id` → `403 {"error": "Forbidden"}`.
- Emit audit log on the contact's alias (`action="delete_contact"`, message `"Deleted contact {contact_id} ({contact.website_email})"`), `Contact.delete(contact_id)`, commit.
- Success `200 {"deleted": true}`.

```python
@api_bp.route("/contacts/<int:contact_id>/toggle", methods=["POST"])
@require_api_auth
def toggle_contact(contact_id):
```
- Same 403 ownership check.
- `contact_toggle_block(contact)`: `contact.block_forward = not contact.block_forward`, emit audit log (`action="update_contact"`, message `"Set contact state {id} {email} -> {website_email} to blocked {bool}"`), commit.
- Success `200 {"block_forward": <new bool>}`.

---

## 11. `serialize_contact(contact, existed=False)` — exact shape

```json
{
  "id": <int>,
  "creation_date": "<arrow format>",
  "creation_timestamp": <int>,
  "last_email_sent_date": null | "<arrow format>",
  "last_email_sent_timestamp": null | <int>,
  "contact": <str>,                 // contact.website_email
  "reverse_alias": <str>,           // contact.website_send_to() — quoted display form
  "reverse_alias_address": <str>,   // contact.reply_email — bare address
  "existed": <bool>,
  "block_forward": <bool>
}
```
`last_email_sent_*` come from `contact.last_reply()`: `SELECT email_log WHERE contact_id = :cid AND is_reply = true ORDER BY created_at DESC LIMIT 1` (one query per contact — N+1 in the list endpoint).

---

## 12. `Contact.website_send_to()` — the "reverse_alias" display string

Returns `'"{display}" <{reply_email}>'` where display is built as:
1. `email = website_email`, transformed by the alias owner's `user.sender_format` (enum values: AT=0, A=2, NAME_ONLY=5, AT_ONLY=6, NO_NAME=7):
   - user missing, invalid enum value, or AT (0, default) → `email.replace("@", " at ")`
   - A (2) → `email.replace("@", "(a)")`
   - 5/6/7 → email left unchanged (keeps `@`)
2. `name = contact.name`; if empty and `contact.website_from` set, parse its display name with flanker (on failure name = `""`).
3. Remove all `"` characters from name.
4. `display = f"{name} | {email}"` if name else `email`.

Example: `'"John Wick | john at wick.com" <xyz123abc@simplelogin.co>'`.

---

## 13. `generate_reply_email(contact_email, alias)` — reverse-alias generation

1. `include_sender_in_reverse_alias = user.include_sender_in_reverse_alias` if not None else False.
2. If including sender and contact_email non-empty, transform contact_email: `replace("@", "_at_")`, `replace(".", "_")`, `convert_to_id` (lowercase, unidecode to ASCII, remove spaces, non-`[a-zA-Z0-9_-.]` chars → `_`, truncate 64), `sanitize_email`, truncate to 45 chars, `convert_to_alphanumeric` again.
3. Reply domain: `config.EMAIL_DOMAIN`, EXCEPT if the alias's domain is an `SLDomain` row with `use_as_reverse_alias = true` — then the alias's own domain.
4. Up to 1000 attempts:
   - with sender: `f"{contact_email}_{random_string(5..10)}@{reply_domain}"`
   - without: `f"{random_string(20..50)}@{reply_domain}"`
   - `random_string(n)` = n random lowercase ASCII letters (no digits).
   - Accept if `available_sl_email(email)`: no `Alias.email`, no `Contact.reply_email`, no `DeletedAlias.email` equals it.
5. After 1000 failures raise (500).

---

## 14. Implementation notes for Cloudflare

DB tables touched by these routes:
- `alias` (read/update/delete: email, name, note, enabled, pinned, disable_pgp, mailbox_id, custom_domain_id, directory_id, user_id, created_at, delete_on, delete_reason, last_email_log_id, ts_vector, hibp join)
- `contact` (read/insert/update/delete: alias_id, user_id, website_email, website_from, name, reply_email, block_forward, invalid_email, automatic_created, flags, mail_from, created_at; unique `(alias_id, website_email)`)
- `email_log` (read: is_reply, blocked, bounced, contact_id, alias_id, created_at)
- `mailbox` (read: email, verified, pgp_finger_print, disable_pgp, flags/admin-disabled), `alias_mailbox` (read/rewrite)
- `deleted_alias`, `domain_deleted_alias` (insert on alias delete), `custom_domain` (read)
- `alias_audit_log` (insert on every mutation: user_id, alias_id, alias_email, action, message)
- `api_key` (read + update last_used/times on EVERY authenticated request), `users` (read: disabled, delete_on, alias_delete_action, sender_format, include_sender_in_reverse_alias, premium/flags for can_create_contacts)
- `sl_domain` (read: use_as_reverse_alias for reverse-alias domain)

Python/Postgres specifics to replicate:
- Dates: arrow 0.16 — `creation_date`/`last_email_sent_date` format `YYYY-MM-DD HH:mm:ssZZ` → `"2021-03-12 09:53:26+00:00"`; `*_timestamp` are integer Unix seconds.
- `ILIKE '%q%'` search — the raw query string is interpolated into the LIKE pattern, so `%`/`_` in user input act as wildcards.
- `plainto_tsquery('english', query)` full-text over `to_tsvector('english', note)` — an extra OR branch on top of the ILIKEs; approximating with LIKE-on-note loses stemming but usually overlaps the note ILIKE branch.
- `GREATEST(a, b)` with NULL ignores the NULL (Postgres semantics) — needed for the default sort.
- Flask `jsonify` returns `Content-Type: application/json`; booleans are JSON true/false; `note`/`name` may be JSON null.
- Route converters: `<int:alias_id>` — a non-integer path segment 404s before the handler runs.
- Event dispatch (`AliasDeleted`, `AliasStatusChanged`, `AliasNoteChanged`, `AliasCreated`) goes to the partner webhook/event system — replicate only if events are in scope.
