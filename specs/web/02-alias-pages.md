# Web Spec 02 — Alias-centric dashboard pages

Server-rendered pages of the `dashboard` blueprint (`url_prefix="/dashboard"`) that manage aliases,
their activity, contacts and transfers.

Source files (authoritative):
- `app/dashboard/views/index.py` (alias list + htmx contact toggle)
- `app/dashboard/views/custom_alias.py` (new custom alias page)
- `app/dashboard/views/alias_log.py` (per-alias activity)
- `app/dashboard/views/alias_export.py` (CSV export)
- `app/dashboard/views/alias_transfer.py` (transfer send/receive)
- `app/dashboard/views/alias_contact_manager.py` (contacts of an alias)
- `app/dashboard/views/contact_detail.py` (contact PGP page)
- Templates: `templates/dashboard/index.html`, `custom_alias.html`, `alias_log.html`,
  `alias_transfer_send.html`, `alias_transfer_receive.html`, `alias_contact_manager.html`,
  `contact_detail.html`, `templates/partials/toggle_contact.html`, `templates/_formhelpers.html`
- Client JS driving AJAX from these pages: `static/js/index.js`

Existing API-port correspondences (do NOT re-implement, reuse):
- Alias listing/pagination v3 → `cloudflare/src/lib/serializer.ts` (`getAliasInfosWithPaginationV3`, `AliasInfo`)
- Suffix signing/verification, `get_alias_suffixes`, `verify_prefix_suffix`, `check_alias_prefix`,
  random alias generation → `cloudflare/src/routes/alias-creation.ts` + `cloudflare/src/lib/crypto.ts`
  (`timestampSign`/`timestampUnsign`) — algorithm spec in `cloudflare/specs/03-alias-creation.md` §2–3
- Alias delete/trash semantics (`alias_delete.delete_alias`) → `cloudflare/specs/02-aliases.md` §4
- Contact creation (`contact_utils.create_contact`) and `contact_toggle_block` →
  `cloudflare/specs/02-aliases.md` §9–10, implemented in `cloudflare/src/routes/aliases.ts`
- `get_alias_log` → `cloudflare/specs/02-aliases.md` §6
- `Contact.website_send_to()` (reverse-alias display string) → `cloudflare/specs/02-aliases.md` §12,
  `reverseAliasDisplay` in `cloudflare/src/lib/serializer.ts`
- Session cookie / sudo (`session["sudo_time"]`) → `cloudflare/specs/00-routes-inventory.md`,
  `cloudflare/src/lib/session.ts`

Routes documented (10 URL rules / 9 view functions):

| # | Method(s) | Path (full) | Endpoint name (`url_for`) | Auth | Rate limit |
|---|---|---|---|---|---|
| 1 | GET, POST | `/dashboard/` | `dashboard.index` | `@login_required` | POST: `ALIAS_LIMIT` (`100/day;50/hour;5/minute`), **exempt unless** `form-name == "create-random-email"`; GET: `10/minute` keyed by `current_user.id`; `parallel_limiter.lock(name="alias_creation", only_when=form-name=="create-random-email")` |
| 2 | POST | `/dashboard/contacts/<int:contact_id>/toggle` | `dashboard.toggle_contact` | `@login_required` | none |
| 3 | GET, POST | `/dashboard/custom_alias` | `dashboard.custom_alias` | `@login_required` | POST only: `ALIAS_LIMIT`; `parallel_limiter.lock(name="alias_creation")` (no `only_when` → also held on GET) |
| 4a | GET | `/dashboard/alias_log/<int:alias_id>` (defaults `page_id=0`) | `dashboard.alias_log` | `@login_required` | none |
| 4b | GET | `/dashboard/alias_log/<int:alias_id>/<int:page_id>` | `dashboard.alias_log` | `@login_required` | none |
| 5 | GET | `/dashboard/alias_export` | `dashboard.alias_export_route` | `@login_required` + `@sudo_required` | `2/minute` |
| 6 | GET, POST | `/dashboard/alias_transfer/send/<int:alias_id>/` | `dashboard.alias_transfer_send_route` | `@login_required` + `@sudo_required` | none |
| 7 | GET, POST | `/dashboard/alias_transfer/receive` | `dashboard.alias_transfer_receive_route` | `@login_required` | `5/minute` |
| 8 | GET, POST | `/dashboard/alias_contact_manager/<int:alias_id>/` | `dashboard.alias_contact_manager` | `@login_required` | `parallel_limiter.lock(name="contact_creation")` (no `only_when`) |
| 9 | GET, POST | `/dashboard/contact/<int:contact_id>/` | `dashboard.contact_detail_route` | `@login_required` | none |

`app.url_map.strict_slashes = False` — every path matches with and without the trailing slash.
`<int:...>` converters: non-integer segments 404 (HTML `error/404.html`) before the handler runs.

---

## 0. Shared web infrastructure used by every route here

### 0.1 `@login_required` (web behavior)

No `login_view` is configured on the LoginManager; an unauthenticated request raises 401 which hits the
global 401 handler (`simplelogin_app.py::setup_error_page`): for non-`/api/` paths it does
`flash("You need to login to see this page", "error")` and
`redirect(url_for("auth.login", next=request.full_path))`. Note `request.full_path` includes the query
string and a trailing `?` when there is none (Flask quirk), e.g. `next=/dashboard/?`.

### 0.2 `@sudo_required` (`app/dashboard/views/enter_sudo.py`)

- Web sudo gap is `_SUDO_GAP = 120` **seconds** (2 minutes) — NOT the 5 minutes used by the API's
  `require_api_sudo`.
- If `"sudo_time" not in session` or `time() - int(session["sudo_time"]) > 120`:
  - if `session["_flashes"]` is non-empty, move it to `session["_preserved_flashes"]` (so pending flash
    messages survive the sudo detour instead of being consumed by the sudo page),
  - `redirect(url_for("dashboard.enter_sudo", next=request.path))` → `/dashboard/enter_sudo?next=<path>`.
- Else: if `session["_preserved_flashes"]` exists, append its entries back onto `session["_flashes"]`
  and delete it; then run the view.
- `session["sudo_time"]` is written by `dashboard.enter_sudo` (out of scope — auth/settings group).

### 0.3 CSRF — `CSRFValidationForm`

`class CSRFValidationForm(FlaskForm): pass` (`app/utils.py`) — an empty flask-wtf form used purely for
CSRF. Templates emit `{{ csrf_form.csrf_token }}` → `<input type="hidden" name="csrf_token" value="...">`.
`csrf_form.validate()` fails when the token is missing/expired/invalid. Every POST view in this group
(except `contact_detail_route`, see §9) starts with:
```python
if not csrf_form.validate():
    flash("Invalid request", "warning")
    return redirect(request.url)      # request.url = current path INCLUDING query string
```
Exception: `toggle_contact` (htmx) returns plain `("Invalid request", 400)` instead.

### 0.4 Flash messages

Standard Flask session flashes (`session["_flashes"]`, list of `(category, message)`), rendered by the
base layout. Categories used in this group: `success`, `error`, `warning`, `info` (none), and one
**default** category `message` (see §9 "Invalid pgp key").

### 0.5 Template globals / filters these pages rely on

- Filter `dt`: `arrow.get(value).humanize()` → English humanized delta, e.g. `"2 hours ago"`, `"just now"`,
  `"a day ago"`. (Port: dayjs `fromNow()`-style with arrow's wording, or replicate arrow 0.16 humanize.)
- Filter `length` (Jinja builtin), `|safe` inside `_formhelpers.html`.
- Context-processor globals (from `simplelogin_app.py::jinja2_filter`) referenced by this group's
  templates: `PAGE_LIMIT` (20), `FIRST_ALIAS_DOMAIN`, `HEADER_ALLOW_API_COOKIES`
  (= `"X-Sl-Allowcookies"`), plus base-layout ones (URL, YEAR, ...) handled by web infra.
- Macros: `render_field_errors(field)` from `templates/_formhelpers.html` (imported once in
  `base.html`, so available everywhere):
  ```jinja
  {% if field.errors %}<ul class="errors">{% for error in field.errors %}<li class="text-danger">{{ error }}</li>{% endfor %}</ul>{% endif %}
  ```
- All templates here: `{% extends "default.html" %}`, `{% set active_page = "dashboard" %}` (drives
  navbar highlight), blocks used: `title`, `head`, `default_content`, `script`.

### 0.6 Web error pages

Framework errors on non-`/api/` paths render templates: 400 → `error/400.html`, 403 → `error/403.html`,
404 → `error/404.html`, 405 → `error/405.html`, 429 → `error/429.html`, unhandled exception →
`error/500.html` (all status codes preserved).

### 0.7 Constants

`PAGE_LIMIT = 20`; `ALIAS_LIMIT = "100/day;50/hour;5/minute"` (env-overridable);
`DISABLE_ALIAS_SUFFIX = "DISABLE_ALIAS_SUFFIX" in os.environ`;
`ALIAS_TRANSFER_TOKEN_SECRET = env or FLASK_SECRET + "aliastransfertoken"`.

---

## 1. GET|POST `/dashboard/` — alias list (`dashboard.index`)

Decorators (order): `@login_required`, `@limiter.limit(ALIAS_LIMIT, methods=["POST"],
exempt_when=lambda: request.form.get("form-name") != "create-random-email")`,
`@limiter.limit("10/minute", methods=["GET"], key_func=lambda: current_user.id)`,
`@parallel_limiter.lock(name="alias_creation", only_when=form-name == "create-random-email")`.
So: only the random-alias POST is rate-limited/locked; delete/disable/custom POSTs are exempt; GET is
10/minute per user.

### Query params (read on both GET and POST)

- `query` (default `""`), `sort` (default `""`), `filter` (default `""`).
- `page`: `int(...)`, `ValueError` → stays `0`.
- `highlight_alias_id`: `int(...)`, `ValueError` → `None` (warning logged, no flash).

### 1.1 POST behavior

`csrf_form.validate()` fail → flash `"Invalid request"` (warning), redirect `request.url` (§0.3).

Branch on `request.form.get("form-name")`:

**`create-custom-email`**
- `current_user.can_create_new_alias()` (exact logic: `cloudflare/specs/03-alias-creation.md` §1.6) →
  `redirect(url_for("dashboard.custom_alias"))`.
- else flash `"You need to upgrade your plan to create new alias."` (warning) → falls to the common
  final redirect (below).

**`create-random-email`**
- If `can_create_new_alias()`:
  - `scheme = int(request.form.get("generator_scheme") or current_user.alias_generator)` —
    **GOTCHA**: a non-numeric `generator_scheme` raises `ValueError` → 500 page.
  - If `scheme` falsy or not in `AliasGeneratorEnum` (word=1, uuid=2) → `scheme = current_user.alias_generator`.
  - `alias = Alias.create_new_random(user=current_user, scheme=scheme)` (domain choice, word/uuid local
    part, retry semantics: `cloudflare/specs/03-alias-creation.md` §3.10; per-user creation bucket
    limits inside `Alias.create` may raise 429 → HTML `error/429.html`).
  - `alias.mailbox_id = current_user.default_mailbox_id` (redundant, already set); `Session.commit()`.
  - flash `f"Alias {alias.email} has been created"` (success).
  - `redirect(url_for("dashboard.index", highlight_alias_id=alias.id, query=query, sort=sort, filter=alias_filter))`
    — **no `page` arg** (returns to page 0).
- else flash `"You need to upgrade your plan to create new alias."` (warning) → common final redirect.

**`delete-alias`** / **`disable-alias`**
- `alias_id = int(request.form.get("alias-id"))`:
  - `ValueError` (non-numeric) → flash `"unknown error"` (error), redirect `request.url`.
  - **GOTCHA**: missing field → `int(None)` raises `TypeError` (not caught) → 500 page.
- `alias = Alias.get(alias_id)`; if not found or `alias.user_id != current_user.id` → flash
  `"Unknown error, sorry for the inconvenience"` (error), redirect
  `url_for("dashboard.index", query=query, sort=sort, filter=alias_filter)` (no page).
  **GOTCHA**: `Alias.get` also returns trashed aliases (`delete_on` set) — deleting an already-trashed
  alias performs a **hard** delete (spec 02 §4).
- `delete-alias`: `alias_delete.delete_alias(alias, current_user, AliasDeleteReason.ManualAction,
  commit=True)` (full semantics incl. custom-domain hard delete + `domain_deleted_alias` row, or
  soft-trash with `delete_on = now + ALIAS_TRASH_DAYS`: spec 02 §4). Flash (success):
  - if `current_user.alias_delete_action == UserAliasDeleteAction.MoveToTrash` (enum value 0, the
    default): `f"Alias {email} has been moved to the trash"`
  - else: `f"Alias {email} has been deleted"`
  - **GOTCHA**: message is chosen purely by the user preference — a custom-domain alias is always hard
    deleted yet the flash still says "moved to the trash" for MoveToTrash users.
- `disable-alias`: `alias_utils.change_alias_status(alias, enabled=False, message="Set enabled=False
  from dashboard")` (sets `alias.enabled = false`, audit log `change_status` with message
  `"Set alias status to False. Set enabled=False from dashboard"`, dispatches `AliasStatusChanged`
  event), `Session.commit()`, flash `f"Alias {alias.email} has been disabled"` (success).

**Common final redirect** (all POST paths that didn't return earlier, including unknown `form-name`,
which is a no-op): `redirect(url_for("dashboard.index", query=query, sort=sort, filter=alias_filter,
page=page))`.

### 1.2 GET behavior

1. `mailboxes = [mb for mb in current_user.mailboxes() if not mb.is_admin_disabled()]` —
   `User.mailboxes()` returns **verified** mailboxes only (`mailbox WHERE user_id=? AND verified=1`);
   `is_admin_disabled()` = `flags & 1` (Mailbox.FLAG_ADMIN_DISABLED = 1).
2. **GET with a side effect**: if `not current_user.intro_shown` → `show_intro = True`,
   `current_user.intro_shown = True`, `Session.commit()` (intro shown exactly once, persisted on GET).
3. `stats = get_stats(current_user)` — dataclass `Stats(nb_alias, nb_forward, nb_reply, nb_block)`:
   - `nb_alias`: `COUNT(*) FROM alias WHERE user_id=? AND delete_on IS NULL`
   - `nb_forward`: `COUNT(*) FROM email_log WHERE user_id=? AND is_reply=0 AND blocked=0 AND bounced=0`
   - `nb_reply`: same with `is_reply=1 AND blocked=0 AND bounced=0`
   - `nb_block`: same with `is_reply=0 AND blocked=1 AND bounced=0`
   - **GOTCHA**: no date filter — the UI labels say "Last 14 days" only because a cron prunes old
     `email_log` rows; the queries themselves are all-time.
4. `filter` prefix parsing: `filter.startswith("mailbox:")` → `mailbox_id = int(filter[8:])`;
   `"directory:"` → `directory_id = int(filter[10:])`. **GOTCHA**: non-numeric suffix raises
   `ValueError` → 500 page.
5. `alias_infos = get_alias_infos_with_pagination_v3(current_user, page, query, sort, alias_filter,
   mailbox_id, directory_id, page_limit=PAGE_LIMIT + 1)` — same function as API `/api/v2/aliases`
   (spec 02 §2; ported as `getAliasInfosWithPaginationV3`), with the web-only extras:
   - `sort` ∈ `old2new` (created_at ASC) | `new2old` (created_at DESC) | `a2z` (email ASC) |
     `z2a` (email DESC) | anything else → default `pinned DESC, GREATEST(created_at,
     last_email_log.created_at) DESC`.
   - `alias_filter` ∈ `pinned` | `enabled` | `disabled` | `hibp` (`Alias.hibp_breaches.any()` — alias
     has ≥1 row in `alias_hibp`) | `mailbox:<id>` (alias's `mailbox_id` = id OR an `alias_mailbox` row
     with that mailbox) | `directory:<id>` (`alias.directory_id = id`).
   - Fetches 21 rows (`page_limit = 21`) with `OFFSET page * 20` (`page_size` stays 20);
     `last_page = len(alias_infos) <= PAGE_LIMIT`; then truncate to first 20.
6. Highlight: if `highlight_alias_id` set and not among the 20 fetched, `get_alias_info_v3(current_user,
   alias_id)` (same query filtered to the alias id; returns `None` if not the user's / trashed) and, if
   found, `alias_infos.insert(0, ...)` (so the page may show 21 cards).

Render `dashboard/index.html` with context:

| name | value |
|---|---|
| `alias_infos` | list of `AliasInfo` (fields: `alias`, `mailbox`, `mailboxes` (verified, email-sorted), `nb_forward`, `nb_blocked`, `nb_reply`, `latest_email_log`, `latest_contact`, `custom_domain`; method `contain_mailbox(id)`) |
| `highlight_alias_id` | int or None |
| `query`, `sort`, `filter` | echoed strings (context key for filter is `filter`) |
| `AliasGeneratorEnum` | the enum class — template reads `.word.value` (1), `.uuid.value` (2) |
| `UserAliasDeleteAction` | the enum class — template reads `.MoveToTrash.name` (`"MoveToTrash"`) |
| `mailboxes` | user's verified, non-admin-disabled mailboxes |
| `show_intro` | bool |
| `page`, `last_page` | pagination state |
| `stats` | `Stats` dataclass |
| `csrf_form` | CSRF form |

### 1.3 Template `dashboard/index.html` — porting notes

- Title block: `Alias`. Vue micro-app `#filter-app` with delimiters `[[ ]]` for show/hide of the stats
  and filter panels (state persisted in localStorage via store.js) — static JS, keep as-is.
- Three POST mini-forms at top (`create-custom-email`, `create-random-email`, and two
  `create-random-email` variants with hidden `generator_scheme` = `AliasGeneratorEnum.word.value` /
  `AliasGeneratorEnum.uuid.value`), each embedding `{{ csrf_form.csrf_token }}`.
- Stats cards print `stats.nb_alias` (label "All time"), `stats.nb_forward`, `stats.nb_reply`,
  `stats.nb_block` (labels "Last 14 days").
- Filter form is `method="get"` and **includes `{{ csrf_form.csrf_token }}`** — GOTCHA: the CSRF token
  leaks into the URL query string (`?csrf_token=...&sort=...&filter=...&query=...`); the GET handler
  ignores it. Selects auto-submit `onchange`. Sort options (labels): `""` "Sort by most recent
  activity", `old2new` "Alias Old-Recent", `new2old` "Alias Recent-Old", `a2z` "Alias A-Z", `z2a`
  "Alias Z-A". Filter options: `""` "All Aliases", `pinned` "Pinned Aliases", `enabled` "Only Enabled
  Aliases", `disabled` "Only Disabled Aliases", `hibp` "Only Aliases Found In Data Breaches", then one
  `mailbox:{{ mailbox.id }}` option per `current_user.mailboxes()` (label `{{ mailbox.email }}'s
  aliases` — note this loop does NOT exclude admin-disabled mailboxes, it calls
  `current_user.mailboxes()` directly in the template), then one `directory:{{ directory.id }}` per
  `current_user.directories` (SQLAlchemy backref; label `Directory <b>{{ directory.name }}</b> aliases`).
  Search input `name="query"` (placeholder "Enter to search for alias"). "Reset" link to
  `url_for("dashboard.index")` shown iff `query or sort or filter`.
- Per-alias card (`{% for alias_info in alias_infos %}`, `{% set alias = alias_info.alias %}`):
  - container id `alias-container-{{ alias.id }}`; card class `highlight-row` when
    `alias.id == highlight_alias_id`.
  - intro.js `data-intro`/`data-step` attributes on `loop.index == 1` (first card) — steps 2,3,4; the
    whole tour only runs when `show_intro` and `window.innerWidth >= 1024`.
  - alias email with clipboard copy (`data-clipboard-text` only when `alias.enabled`).
  - icon badges: `alias.automatic_creation` (tooltip "This alias was automatically generated because of
    an incoming email"), `alias.pinned` ("This alias is pinned"), `alias.hibp_breaches | length > 0`
    (link to `https://haveibeenpwned.com/account/{{ alias.email }}`, tooltip "This alias was found in
    {{ n }} data breaches. Check haveibeenpwned.com for more information."), `alias.custom_domain and
    not alias.custom_domain.verified` (tooltip "Alias can't receive emails as its domain doesn't have
    MX records set up." — `verified` here is the MX flag, not `ownership_verified`).
  - enable/disable checkbox (class `enable-disable-alias`) — **AJAX** `POST /api/aliases/{id}/toggle`
    with headers `Content-Type: application/json` + `X-Sl-Allowcookies: allow` (cookie-auth API path).
    Toasts: success `"{alias} is enabled"` / `"{alias} is disabled"`; failure
    `"Sorry for the inconvenience! Could you refresh the page & retry please?"` titled "Unknown Error".
  - latest activity line: if `alias_info.latest_email_log != None`, uses `latest_contact.website_email`
    + `email_log.created_at | dt` with icon by `is_reply` / `bounced` / `blocked` / else forward; the
    **forward** branch additionally `{% include 'partials/toggle_contact.html' %}` (context: `contact`
    = `alias_info.latest_contact`, `csrf_form`; `toast_msg` undefined → its `<script>` block is
    omitted). Else: `No emails received/sent in the last 14 days. Created {{ alias.created_at | dt }}.`
  - note textarea (id `note-{{ alias.id }}`, placeholder "e.g. where the alias is used or why is it
    created") — AJAX `PUT /api/aliases/{id}` body `{"note": ...}`; toast `"Description saved for
    {email}"`. Helper caption "(automatically saved when you click outside the field)".
  - "Contacts" button → `url_for('dashboard.alias_contact_manager', alias_id=alias.id)`, gets class
    `disabled` when `not alias.enabled`.
  - More/Less collapse toggle rendered only when `not current_user.expand_alias_info`; the collapse
    body has class `collapse` in that case (expanded permanently otherwise).
  - Collapse body:
    - "Alias created {{ alias.created_at | dt }}" (only when there IS a latest email log);
    - `{{ alias_info.nb_forward }}` forwarded, `{{ alias_info.nb_blocked }}` blocked,
      `{{ alias_info.nb_reply }}` sent "in the last 14 days" + "See All →" link to
      `url_for('dashboard.alias_log', alias_id=alias.id)`;
    - `{% set has_admin_disabled_mailbox = namespace(value=false) %}` + loop over
      `alias_info.mailboxes` calling `mb.is_admin_disabled()` (Jinja `namespace()` — Nunjucks port:
      plain object);
    - if `mailboxes|length > 1 or has_admin_disabled_mailbox.value`: optional warning box "The alias
      uses a mailbox disabled by an admin. Please change it to an active mailbox." + multi-select
      (id `mailbox-{{ alias.id }}`) over `mailboxes` with `selected` when
      `alias_info.contain_mailbox(mailbox.id)` — AJAX `PUT /api/aliases/{id}` `{"mailbox_ids": [...]}`;
      toasts `"You must select at least a mailbox"` (client-side) / `"Mailbox updated for {email}"`;
    - elif `alias_info.mailbox != None and alias_info.mailbox.email != current_user.email`: static line
      `Owned by <b>{{ alias_info.mailbox.email }}</b> mailbox`;
    - display-name input (value `alias.name or ''`, placeholder `{{ alias.custom_domain.name or "Alias
      name" }}` — when `custom_domain` is None Jinja resolves to undefined → falls back to
      `"Alias name"`; tooltip "When sending an email from this alias, the email will have 'Display Name
      <{{ alias.email }}>' as sender.") — AJAX `PUT /api/aliases/{id}` `{"name": ...}`, toast
      `"Display name saved for {email}"`;
    - PGP switch rendered only if `alias.mailbox_support_pgp()` (any verified mailbox has
      `pgp_finger_print` set and not `disable_pgp`); checked = `alias.pgp_enabled()`
      (support && not `alias.disable_pgp`) — AJAX `PUT /api/aliases/{id}` `{"disable_pgp": <bool>}`;
      toasts `"PGP is enabled for {email}"` (success) / `"PGP is disabled for {email}"` (info);
    - pin switch (checked = `alias.pinned`) — AJAX `PUT /api/aliases/{id}` `{"pinned": <bool>}`; toasts
      `"{email} is pinned"` / `"{email} is unpinned"`;
    - "Transfer" link → `url_for('dashboard.alias_transfer_send_route', alias_id=alias.id)`;
    - Delete form (hidden `form-name=delete-alias`, `alias-id`, `alias`) — bootbox confirm dialog built
      in inline JS: title `Delete ${alias}`; message default "Maybe you want to disable the alias
      instead? Please note once deleted, it <b>can't</b> be restored." with button label "Delete it, I
      don't need it anymore"; when `current_user.alias_delete_action.name == "MoveToTrash"` message
      becomes "Maybe you want to disable the alias instead so you can easily enable it when needed."
      and button "Move to Trash"; when the alias has a custom domain the message becomes "Maybe you
      want to disable the alias instead? When it's deleted, it's moved to the domain <a
      href="...">trash</a>" using `alias.custom_domain.get_trash_url()` =
      `config.URL + "/dashboard/domains/{id}/trash"`. Dialog buttons: "Disable it" (rewrites the form's
      `form-name` to `disable-alias` then submits), the delete button, "Cancel".
- Pagination block rendered iff `page > 0 or not last_page`: Previous/Next links to
  `url_for('dashboard.index', page=page±1, query=query, sort=sort, filter=filter)` with class
  `disabled` when `page == 0` / `last_page` (Previous at page 0 still renders an href with `page=-1`).
- `{% block script %}` loads `/static/js/index.js?v=0` and inline JS above; `current_user` attributes
  referenced by this template: `mailboxes()`, `directories`, `expand_alias_info`, `email`,
  `alias_delete_action.name`.
- `url_for` endpoints referenced: `dashboard.index`, `dashboard.alias_contact_manager`,
  `dashboard.alias_log`, `dashboard.alias_transfer_send_route`, `dashboard.toggle_contact` (via
  the included partial). Base layout (`default.html`) adds the navbar's other endpoints (out of scope).

---

## 2. POST `/dashboard/contacts/<int:contact_id>/toggle` — htmx block/unblock (`dashboard.toggle_contact`)

`@login_required` only. Called by htmx from `partials/toggle_contact.html` (`hx-post`,
`hx-swap="outerHTML"`).

- CSRF invalid → **plain-text** `"Invalid request"`, status **400** (no flash, no redirect).
- `contact = Contact.get(contact_id)`; missing or `contact.alias.user_id != current_user.id` →
  plain-text `"Forbidden"`, status **403**. (Ownership via the **alias's** user, not `contact.user_id`.)
- `contact_toggle_block(contact)`: `contact.block_forward = not contact.block_forward`; alias audit log
  `action="update_contact"`, message `f"Set contact state {contact.id} {contact.email} ->
  {contact.website_email} to blocked {contact.block_forward}"` (`contact.email` is a property aliasing
  `website_email`, so the address appears twice); commit. Same helper as API
  `POST /api/contacts/<id>/toggle` (spec 02 §10).
- Toast message:
  - now blocked: `f"{contact.website_email} can no longer send emails to {contact.alias.email}"`
  - now unblocked: `f"{contact.website_email} can now send emails to {contact.alias.email}"`
- Response **200**: renders `partials/toggle_contact.html` with `contact`, `toast_msg`, `csrf_form`.

### `templates/partials/toggle_contact.html`

```jinja
<form class="d-inline" hx-post="{{ url_for('dashboard.toggle_contact', contact_id=contact.id) }}" hx-swap="outerHTML">
  {{ csrf_form.csrf_token }}
  <button class="btn btn-sm {% if contact.block_forward %} text-primary {% else %} text-warning {% endif %}">
  {% if contact.block_forward %}<i class="fe fe-play-circle" ... title="Unblock sender"></i>
  {% else %}<i class="fe fe-pause-circle" ... title="Block sender"></i>{% endif %}
  </button>
</form>
{% if toast_msg %}<script>toastr.success("{{ toast_msg }}");</script>{% endif %}
```
Used two ways: included inline in `index.html` (no `toast_msg`) and returned as the htmx swap fragment
(with `toast_msg` → the swapped-in `<script>` fires a toastr success). **GOTCHA**: `toast_msg` is
HTML-escaped into a JS string literal — an email containing `"` renders as `&#34;` inside the JS string
(faithful behavior).

---

## 3. GET|POST `/dashboard/custom_alias` (`dashboard.custom_alias`)

Decorators: `@limiter.limit(ALIAS_LIMIT, methods=["POST"])`, `@login_required`,
`@parallel_limiter.lock(name="alias_creation")` (lock held on GET too — no `only_when`).

Web sibling of `POST /api/v3/alias/custom/new` (spec 03 §7) — same helpers
(`check_alias_prefix`, `check_suffix_signature`, `verify_prefix_suffix`, `Alias.create` + `AliasMailbox`
rows), different strings and flow.

### 3.0 Common guard (GET and POST)

`if not current_user.can_create_new_alias()`: flash
`"You have reached free plan limit, please upgrade to create new aliases"` (warning) → redirect
`dashboard.index`.

### 3.1 GET behavior

Context computed:
- `user_custom_domains` = `[cd.domain for cd in current_user.verified_custom_domains()]`
  (`ownership_verified=1`, ordered by domain ASC) — list of **strings**.
- `alias_suffixes = get_alias_suffixes(current_user)` — exact order/fields in spec 03 §3.8 (already
  ported in `alias-creation.ts::buildAliasSuffixes`). Each `AliasSuffix`: `is_custom`, `suffix`,
  `signed_suffix`, `is_premium`, `domain`, `mx_verified`. Fresh random word + fresh signature per
  request; signature max age 600 s.
- `at_least_a_premium_domain` = any suffix with `not is_custom and is_premium`.
- `mailboxes` = verified, non-admin-disabled mailboxes (same as §1.2 step 1).
- `csrf_form`.

Render `dashboard/custom_alias.html` with
`user_custom_domains, alias_suffixes, at_least_a_premium_domain, mailboxes, csrf_form`.

### 3.2 POST behavior (form fields: `prefix`, `signed-alias-suffix`, `mailboxes` (multi), `note`)

Ordered branches; every failure below (unless noted) flashes and `redirect(request.url)`:

1. CSRF fail → `"Invalid request"` (warning).
2. `alias_prefix = request.form.get("prefix").strip().lower().replace(" ", "")` — **GOTCHA**: missing
   `prefix` field → `None.strip()` → `AttributeError` → 500 page. Note the web page does NOT run
   `convert_to_id` (unlike the API) — just strip/lower/despace.
3. `check_alias_prefix` fail (>40 chars or not `^[0-9a-z-_.]+$`) → flash (error):
   `"Only lowercase letters, numbers, dashes (-), dots (.) and underscores (_) are currently supported for alias prefix. Cannot be more than 40 letters"`.
4. Mailbox validation — for each id in `request.form.getlist("mailboxes")`: `Mailbox.get(id)`; missing
   / `user_id != current_user.id` / not `verified` → flash `"Something went wrong, please retry"`
   (warning); `is_admin_disabled()` → flash
   `"Cannot assign admin-disabled mailbox to alias. Please contact support."` (error).
   Empty selection → flash `"At least one mailbox must be selected"` (error).
   **GOTCHA**: from here on the local `mailboxes` variable holds the POSTed mailboxes — any later
   re-render (branches 7–10) shows only those in the select.
5. `suffix = check_suffix_signature(request.form.get("signed-alias-suffix"))`:
   - returns `None` (bad signature OR >600 s old — both) → flash
     `"Alias creation time is expired, please retry"` (warning).
   - non-`BadSignature` exception (effectively unreachable) → flash `"Unknown error, refresh the page"`
     (error).
6. `verify_prefix_suffix(current_user, alias_prefix, suffix)` (spec 03 §3.7) **false** → flash
   `"something went wrong"` (warning) and **fall through to re-render** the page (200, no redirect).
7. `full_alias = alias_prefix + suffix`; `".." in full_alias` → flash
   `"Your alias can't contain 2 consecutive dots (..)"` (error), redirect.
8. `validate_email(full_alias, check_deliverability=False, allow_smtputf8=False)` raises →
   flash `str(e)` (error) — the raw python `email_validator` message (e.g. "The email address is not
   valid. It must have exactly one @-sign."), redirect.
9. Existence checks — these flash and **fall through to re-render** (200, no redirect):
   - `Alias.get_by(email=full_alias)` exists:
     - owned by current user → flash `f"You already have this alias {full_alias}"` (error)
     - else → flash `f"{full_alias} cannot be used"` (error)
   - elif `DomainDeletedAlias.get_by(email=full_alias)` → flash
     `f"You have deleted this alias before. If you want to re-create it, please delete it from {custom_domain.domain} 'Deleted Alias' page"`
     (error) — `custom_domain` = the DomainDeletedAlias row's domain.
   - elif `DeletedAlias.get_by(email=full_alias)` → flash `f"{full_alias} cannot be used"` (error).
10. Else create:
    - `Alias.create(user_id, email=full_alias, note=alias_note, mailbox_id=mailboxes[0].id)` +
      `Session.flush()`; `IntegrityError` race → rollback, flash `"Unknown error, please retry"`
      (error), redirect `url_for("dashboard.custom_alias")` (fresh page, not `request.url`).
      (`Alias.create` internals — trash check raising `AliasInTrashError` → 500, bucket rate limits →
      429 page, daily metric, `AliasCreated` event, audit log: spec 03 §3.9.)
    - `AliasMailbox.create(alias_id, mailbox_id)` for `mailboxes[1:]`; `Session.commit()`.
    - flash `f"Alias {full_alias} has been created"` (success);
      `redirect(url_for("dashboard.index", highlight_alias_id=alias.id))`.

### 3.3 Template `dashboard/custom_alias.html`

- Title: `Custom Alias`. H1 "New Custom Alias".
- Info alert shown when `user_custom_domains|length == 0 and not DISABLE_ALIAS_SUFFIX` — **GOTCHA**:
  `DISABLE_ALIAS_SUFFIX` is NOT injected into the template context (not in the context processor), so
  in Jinja it is Undefined → falsy → the alert effectively shows whenever the user has no verified
  custom domain, regardless of the env var. Replicate faithfully (treat as always-undefined) or inject
  and accept the behavior change consciously. Alert text mentions `hello@{{ FIRST_ALIAS_DOMAIN }}` and
  `me@{{ FIRST_ALIAS_DOMAIN }}` (global).
- Prefix input: `name="prefix"`, parsley attrs `data-parsley-pattern="[0-9a-z-_.]{1,}"`,
  `maxlength="40"`, client error message
  `"Only lowercase letters, dots, numbers, dashes (-) and underscores (_) are currently supported."`,
  placeholder `"Alias prefix, for example newsletter.com-123_xyz"`, `required`, `autofocus`.
- Suffix `<select name="signed-alias-suffix">`: option `value="{{ alias_suffix.signed_suffix }}"`,
  option `title` = "Only available to Premium accounts" when `is_premium`, else "Available to all
  accounts" when `not is_custom and at_least_a_premium_domain`; label text:
  - custom + mx_verified: `{{ suffix }} (your domain)`
  - custom + not mx_verified: `{{ suffix }} (your domain, not MX verified yet)`
  - premium: `{{ suffix }} (Premium domain)`
  - else: `{{ suffix }} (Public domain)`
- Mailbox multi-select `name="mailboxes"` over `mailboxes`, `selected` when
  `mailbox.id == current_user.default_mailbox_id`; caption "The mailbox(es) that owns this alias."
- Note textarea `name="note"` (placeholder "Note, can be anything to help you remember why you created
  this alias. This field is optional.").
- Submit button id `create` label "Create"; inline JS validates client-side with toastr errors
  `"You must select at least a mailbox"` and `"Alias cannot be empty"` before submitting; multipleSelect
  init; Ctrl-Enter submit.
- `current_user` attrs: `default_mailbox_id`. Globals: `FIRST_ALIAS_DOMAIN`. No `url_for` links besides
  base layout.

---

## 4. GET `/dashboard/alias_log/<int:alias_id>[/<int:page_id>]` (`dashboard.alias_log`)

`@login_required`. Two URL rules; the first defaults `page_id=0`.

- `alias = Alias.get(alias_id)`; missing → flash `"You do not have access to this page"` (warning),
  redirect `dashboard.index`. `alias.user_id != current_user.id` → same flash + redirect.
  (Trashed aliases still render — `Alias.get` ignores `delete_on`.)
- `logs = get_alias_log(alias, page_id)` — identical helper to API activities (spec 02 §6):
  `(Contact ⋈ EmailLog)` for the alias, `ORDER BY email_log.id DESC LIMIT 20 OFFSET page_id*20`,
  re-sorted in Python by `created_at` DESC. Each `AliasLog` object: `website_email`
  (contact.website_email), `reverse_alias` (`contact.website_send_to()`), `alias` (alias.email string),
  `when` (email_log.created_at), `is_reply`, `blocked`, `bounced`, `email_log`, `contact`.
- Counters over `base = (Contact ⋈ EmailLog WHERE contact.alias_id=?)`:
  - `total = COUNT(*)`
  - `email_forwarded = COUNT WHERE is_reply = false AND blocked = false` (**includes bounced** rows)
  - `email_replied = COUNT WHERE is_reply = true`
  - `email_blocked = COUNT WHERE blocked = true`
- `last_page = len(logs) < PAGE_LIMIT`.
- **GOTCHA**: `render_template("dashboard/alias_log.html", **locals())` — the context is every local:
  `alias_id`, `page_id`, `alias`, `logs`, `base` (query object, unused), `total`, `email_forwarded`,
  `email_replied`, `email_blocked`, `last_page`. Port: pass the named ones the template uses.

### Template `dashboard/alias_log.html`

- Title: `Alias Activity`. H1 = `{{ alias.email }}`.
- Four stat cards: Total/`total`, Forwarded/`email_forwarded`, Replies\/Sent/`email_replied`,
  Blocked/`email_blocked` (all labeled "Last 14 days" — same all-time caveat as §1.2).
- Log cards: `{{ log.when | dt }}`; icon: `log.bounced` → `⚠️` (literal emoji), else `log.is_reply` →
  reply icon, `log.blocked` → ban icon, else paper-plane. Body:
  - `log.bounced and not log.is_reply`: `{{ log.website_email }}` → forward-arrow img → `{{ log.alias }}`
    → blocked-arrow img → `{{ log.email_log.bounced_mailbox() }}`
  - `log.bounced and log.is_reply`: `{{ log.email_log.bounced_mailbox() }}` → forward-arrow →
    `{{ log.alias }}` → blocked-arrow → `{{ log.website_email }}`
  - else: `{{ log.website_email }}` only.
  - `EmailLog.bounced_mailbox()`: `Mailbox.get(bounced_mailbox_id).email` if set, else
    `contact.alias.mailboxes[0].email` (legacy fallback).
  - Arrow images via `url_for('static', filename='arrows/forward-arrow.svg')` /
    `'arrows/blocked-arrow.svg'`.
- Pagination (always rendered): Previous → `url_for('dashboard.alias_log', alias_id=alias_id,
  page_id=page_id-1)` with class `disabled` when `page_id == 0` (href still points to `-1` — Flask
  would 404 it since the int converter rejects negatives... actually `page_id=-1` builds
  `/alias_log/<id>/-1` which the `int` converter does NOT match → requesting it 404s; the button is
  CSS-disabled so users normally can't); Next → `page_id+1`, disabled class when `last_page`.
- No `{% block script %}` content.

---

## 5. GET `/dashboard/alias_export` (`dashboard.alias_export_route`)

`@login_required`, `@sudo_required` (§0.2 — may redirect to `/dashboard/enter_sudo?next=/dashboard/alias_export`),
`@limiter.limit("2/minute")` (default key: `userid:{id}` for logged-in users).

Returns `alias_export_csv(current_user)` — no template:
- Rows: header `alias,note,enabled,mailboxes` then one row per
  `Alias WHERE user_id=? AND delete_on IS NULL` (insertion order = primary key order):
  - `alias` = email
  - `note` = alias.note (`None` → empty cell; notes with commas/newlines/quotes get standard CSV
    quoting/doubling)
  - `enabled` = Python bool stringification: **`True`** / **`False`** (capitalized)
  - `mailboxes` = mailbox emails joined by a single space, **primary mailbox first** then the remaining
    verified mailboxes email-ascending (implementation: take `alias.mailboxes` — verified-only, sorted
    by email — and move `alias.mailbox` to the front).
  - **GOTCHA**: if the alias's primary mailbox is unverified it is absent from `alias.mailboxes` →
    `list.index` raises `ValueError` → 500. Faithful edge case; a port may keep it or guard it.
- CSV serialization: python `csv.writer` defaults — `\r\n` line terminator, minimal quoting.
- Response headers: `Content-Disposition: attachment; filename=aliases.csv`, `Content-Type: text/csv`
  (Flask adds charset → `text/csv; charset=utf-8` is acceptable).

---

## 6. GET|POST `/dashboard/alias_transfer/send/<int:alias_id>/` (`dashboard.alias_transfer_send_route`)

`@login_required`, `@sudo_required`. No limiter.

Guards (GET and POST):
- alias missing or not owner → flash `"You cannot see this page"` (warning), redirect `dashboard.index`.
- `current_user.newsletter_alias_id == alias.id` → flash
  `"This alias is currently used for receiving the newsletter and cannot be transferred"` (error),
  redirect `dashboard.index`.

### Token scheme

```
transfer_token (plaintext, shown once) = f"{alias.id}." + secrets.token_urlsafe(32)
stored alias.transfer_token           = b64url_nopad( HMAC_SHA3-224( key=ALIAS_TRANSFER_TOKEN_SECRET, msg=transfer_token ) )
alias.transfer_token_expiration       = utcnow + 24h
```
`ALIAS_TRANSFER_TOKEN_SECRET = env ALIAS_TRANSFER_TOKEN_SECRET or FLASK_SECRET + "aliastransfertoken"`.
**PORTING NOTE**: WebCrypto has no SHA3 — use a JS SHA3-224 HMAC (e.g. `@noble/hashes/sha3` +
`hmac`). The DB column is `alias.transfer_token` (unique) + `transfer_token_expiration` — both already
in `cloudflare/migrations/0001_init.sql`.

### POST

- CSRF fail → `"Invalid request"` (warning), redirect `request.url`.
- `form-name == "create"`: generate token as above, store hash + expiration, alias audit log
  `action="initiate_transfer_alias"`, message `"Initiated alias transfer"`, commit;
  `alias_transfer_url = config.URL + "/dashboard/alias_transfer/receive?token=" + transfer_token`
  (plaintext); flash `"Share alias URL created"` (success). **No redirect** — falls through to render
  with the URL visible exactly once.
- any other `form-name` (the form sends `"remove"`): `alias.transfer_token = None`,
  `transfer_token_expiration = None`, commit, `alias_transfer_url = None`, flash
  `"Share URL deleted"` (success). Render.

### GET / render context

`dashboard/alias_transfer_send.html` with: `alias`, `alias_transfer_url` (None on GET),
`link_active` = `transfer_token_expiration is not None and transfer_token_expiration > utcnow`,
`csrf_form`.

### Template `dashboard/alias_transfer_send.html`

- Title: `Send {{ alias.email }}`. H1 "Transfer {{ alias.email }}".
- If `alias_transfer_url`: shows it in a click-to-copy `<em>` (`data-clipboard-text`), copy warning
  "Please copy the transfer URL. **We won't be able to display it again**. If you need to access it
  again you can generate a new URL.", validity note "This transfer URL is **valid for 24 hours**. ...",
  and a `remove` form (button "Remove alias transfer URL", caption "If you don't want to share this
  alias anymore, you can remove the share URL.").
- elif `link_active`: alert-info "You have an active transfer link. If you don't want to share this
  alias anymore, please delete the link." + `remove` form (button "Remove alias transfer URL").
- else: prompt "In order to transfer ownership, please create the <b>Share URL</b> 👇 and send it to
  the other person." + `create` form (button "Generate a new alias transfer URL").
- Footer lines: "This person can then confirm the reception and become the owner of the alias." and
  alert-danger "After the confirmation, you can no longer use this alias."

---

## 7. GET|POST `/dashboard/alias_transfer/receive` (`dashboard.alias_transfer_receive_route`)

`@limiter.limit("5/minute")` (both methods), `@login_required`. **No sudo.**

`token = request.args.get("token")` — read from the **query string** on both GET and POST (the POST
form action preserves it because `redirect(request.url)` / form has no action attribute).

Guards, in order (each: flash + redirect `dashboard.index`):
1. no token → `"Invalid transfer token"` (error)
2. lookup `Alias.get_by(transfer_token=token)` **or** `Alias.get_by(transfer_token=hmac(token))` —
   legacy plaintext tokens are still honored (migration TODO in source); miss → `"Invalid link"` (error)
3. `transfer_token_expiration is not None and < utcnow` → `"Expired link, please request a new one"`
   (error) — a NULL expiration (legacy) never expires
4. `alias.user_id == current_user.id` → `"You already own this alias"` (warning)
5. `not current_user.can_create_new_alias()` →
   `"You have reached free plan limit, please upgrade to create new aliases"` (warning)

### GET

Render `dashboard/alias_transfer_receive.html` with `alias`, `mailboxes` (current user's verified,
non-admin-disabled), `csrf_form`.

Template: title `Receive {{ alias.email }}`; H1 "Receive {{ alias.email }}"; "You are invited to become
the owner of the alias <b>{{ alias.email }}</b>", "Please choose the mailbox(es) that owns this alias 👇";
multi-select `name="mailbox_ids"` (selected when `mailbox.id == current_user.default_mailbox_id`);
button "Confirm"; `$('.mailbox-select').multipleSelect();` in script block.

### POST

- CSRF fail → `"Invalid request"` (warning), redirect `request.url` (keeps `?token=`).
- Validate `request.form.getlist("mailbox_ids")`: each `Mailbox.get(id)`; missing / not owner / not
  verified → flash `"Something went wrong, please retry"` (warning), redirect `request.url`;
  admin-disabled → flash `"Cannot assign admin-disabled mailbox. Please contact support."` (error)
  (note: slightly different string than custom_alias's — no "to alias").
  Empty → flash `"You must select at least 1 mailbox"` (warning), redirect.
- `transfer_alias(alias, current_user, mailboxes)` (`app/alias_utils.py`):
  1. Guard: another user has `newsletter_alias_id == alias.id` → raises → 500 page.
  2. `UPDATE contact SET user_id = :new WHERE alias_id = :aid`; same for `alias_used_on` and
     `client_user`.
  3. `DELETE FROM alias_mailbox WHERE alias_id = :aid`; `alias.mailbox_id = new_mailboxes.pop().id`
     — **GOTCHA: `.pop()` takes the LAST submitted mailbox as primary**; the remaining ones get
     `alias_mailbox` rows.
  4. `alias.original_owner_id = old user id` if not already set.
  5. **Email to the previous owner** (only if `old_user.can_send_or_receive()` — not disabled, no
     `delete_on`): recipient `old_user.email`, subject `f"Alias {alias.email} has been received"`,
     bodies `templates/emails/transactional/alias-transferred.txt|.html` ("{{ alias.email }} has been
     transferred. / Your (previously) alias {{ alias.email }} has been received by another user.").
  6. `alias.user_id = new_user.id`; reset `alias.disable_pgp = False`, `alias.pinned = False`.
  7. Audit logs: `action="transferred_alias"`, message `f"Lost ownership of alias due to alias transfer
     confirmed. New owner is {new_user.id}"`, `user_id=old_user.id`; and
     `action="accept_transfer_alias"`, message `f"Accepted alias transfer from user {old_user.id}"`,
     `user_id=new_user.id`.
  8. Events: `AliasDeleted` to old user, `AliasCreated` to new user; commit.
- Route then clears `alias.transfer_token` / `transfer_token_expiration`, commits, flashes
  `f"You are now owner of {alias.email}"` (success) and redirects
  `url_for("dashboard.index", highlight_alias_id=alias.id)`.

---

## 8. GET|POST `/dashboard/alias_contact_manager/<int:alias_id>/` (`dashboard.alias_contact_manager`)

`@login_required`, `@parallel_limiter.lock(name="contact_creation")` (held on GET too).

### Request parsing (both methods)

- `highlight_contact_id = int(request.args.get("highlight_contact_id"))`; `ValueError` → flash
  `"Invalid contact id"` (error), redirect `dashboard.index`.
- `page = int(request.args.get("page"))`; `ValueError` → 0.
- `query = request.args.get("query") or ""`.
- `alias = Alias.get(alias_id)`; missing → flash `"You do not have access to this page"` (warning),
  redirect `dashboard.index`; not owner → identical flash + redirect (two separate checks).

### Form — `NewContactForm` (flask-wtf)

| field | type | validators | error strings |
|---|---|---|---|
| `email` | StringField("Email") | `DataRequired()` | `"This field is required."` |
| | | custom `email_validator()` | `"Invalid email format. Email must be either email@example.com or *First Last <email@example.com>*"` |

Custom validator: strip the value; if it contains `<` and `>` with `find("<")+1 < find(">")`, the
checked part is the text between the first `<` and first `>` (stripped); validity =
`email_validator.validate_email(part, check_deliverability=False, allow_smtputf8=False)` succeeds
(ASCII only). Note: form-level CSRF also applies (`new_contact_form` is a FlaskForm) — but the view
gates CSRF via the separate `csrf_form` first.

### POST branches (`form-name`)

CSRF (`csrf_form`) fail → `"Invalid request"` (warning), redirect `request.url`.

**`create`**
- If `new_contact_form.validate()` fails → **falls through to re-render** (200) with field errors shown
  via `render_field_errors(new_contact_form.email)`.
- `contact_address = new_contact_form.email.data.strip()`; `create_contact(alias, contact_address)`
  (dashboard wrapper over `contact_utils.create_contact` — full semantics incl. flanker full-address
  parsing, name truncation, reverse-alias generation, `CannotCreateContactForReverseAlias` guard:
  spec 02 §9, ported in `cloudflare/src/routes/aliases.ts`). Exceptions → flash
  `excp.error_for_user()` (error) + redirect `request.url`:
  - `ErrContactErrorUpgradeNeeded` → `"Please upgrade to premium to create reverse-alias"`
    (raised when `user.can_create_contacts()` is false — allowed if premium, OR if
    `users.flags & FLAG_FREE_DISABLE_CREATE_CONTACTS (1<<0)` is unset, OR if
    `DISABLE_CREATE_CONTACTS_FOR_FREE_USERS` config is false; ported as `canCreateContacts` in
    `cloudflare/src/routes/aliases.ts`)
  - `ErrAddressInvalid(addr)` → `f"{addr} is not a valid email address"` (addr = the submitted string,
    or literal `"Empty address"` / `"Invalid address"` for the empty/unknown-error cases)
  - `ErrContactAlreadyExists(contact)` → `f"{contact.website_email} is already added"`
  - `CannotCreateContactForReverseAlias` → `"You can't create contact for a reverse alias"` — dead code
    in practice (contact_utils maps it to InvalidEmail → `ErrAddressInvalid`), keep for completeness.
- Success → flash `f"Reverse alias for {contact_address} is created"` (success), redirect
  `url_for("dashboard.alias_contact_manager", alias_id=alias_id, highlight_contact_id=contact.id)`.

**`delete`**
- `contact_id = request.form.get("contact-id")` (string; `Contact.get` coerces).
- `delete_contact(alias, contact_id)`:
  - contact missing → flash `"Unknown error. Refresh the page"` (warning)
  - `contact.alias_id != alias.id` → flash `"You cannot delete reverse-alias"` (warning)
  - else: alias audit log `action="delete_contact"`, message
    `f"Delete contact {contact_id} ({contact.email})"`; `Contact.delete(contact_id)`; commit; flash
    `f"Reverse-alias for {delete_contact_email} has been deleted"` (success) — `delete_contact_email` =
    the contact's `website_email`.
- Always: redirect `url_for("dashboard.alias_contact_manager", alias_id=alias_id)` (drops
  page/query/highlight).

**`search`**
- `query = request.form.get("query")`; redirect `url_for("dashboard.alias_contact_manager",
  alias_id=alias_id, query=query, highlight_contact_id=highlight_contact_id)` (POST-redirect-GET;
  `query=None` serializes as `query=None`? No — Flask url_for drops None args; empty string stays).

### GET data — `get_contact_infos(alias, page, contact_id=None, query="")`

One row per contact of the alias (contacts with **no** email logs included), each a
`ContactInfo(contact, nb_forward, nb_reply, latest_email_log)`:

```sql
-- per-contact aggregate subquery `sub`:
SELECT contact.id,
       SUM(CASE WHEN email_log.is_reply THEN 1 ELSE 0 END)                                   AS nb_reply,
       SUM(CASE WHEN email_log.is_reply IS FALSE AND email_log.blocked IS FALSE THEN 1 ELSE 0 END) AS nb_forward,
       MAX(email_log.created_at)                                                             AS max_email_log_created_at
FROM contact LEFT OUTER JOIN email_log ON email_log.contact_id = contact.id
WHERE contact.alias_id = :aid GROUP BY contact.id

-- main query:
SELECT contact.*, email_log.*, sub.nb_reply, sub.nb_forward
FROM contact LEFT OUTER JOIN email_log ON email_log.contact_id = contact.id
WHERE contact.alias_id = :aid
  AND contact.id = sub.id
  AND (email_log.created_at = sub.max_email_log_created_at OR sub.max_email_log_created_at IS NULL)
[AND (contact.website_email ILIKE '%q%' OR contact.name ILIKE '%q%')]     -- when query
[AND contact.id = :contact_id]                                            -- when contact_id
ORDER BY CASE WHEN email_log.created_at > contact.created_at THEN email_log.created_at
              WHEN email_log.created_at < contact.created_at THEN contact.created_at
              ELSE contact.created_at END DESC          -- "latest activity" desc
LIMIT 20 OFFSET :page * 20
```
(There is no blocked bucket here — `nb_forward` counts non-reply non-blocked; blocked rows count toward
neither number. Two logs sharing the exact max timestamp would duplicate the contact row — ignore.)

- `last_page = len(contact_infos) < PAGE_LIMIT`.
- `nb_contact = COUNT(*) FROM contact WHERE alias_id = :aid` (unfiltered).
- Highlight: if `highlight_contact_id` not among the fetched ids →
  `get_contact_infos(alias, contact_id=highlight_contact_id, query=query) + contact_infos` (prepended;
  note the query filter still applies to the highlight fetch).

Render `dashboard/alias_contact_manager.html` with context: `contact_infos`, `alias`,
`new_contact_form`, `highlight_contact_id`, `page`, `last_page`, `query`, `nb_contact`,
`can_create_contacts` (= `current_user.can_create_contacts()`), `csrf_form`.

### Template `dashboard/alias_contact_manager.html`

- Title: `Alias Contact Manager`. H1 "{{ alias.email }} contacts" + collapsible "How to use" alert:
  explains reverse-aliases; branch on `alias.mailbox_id` (always truthy in practice):
  - one mailbox (`alias.mailboxes | length == 1`): "Make sure you send the email from your mailbox
    <b>{{ alias.mailbox.email }}</b>."
  - several: "Make sure you send the email from one of the following mailboxes:" + list.
  - else-branch (no mailbox_id, legacy): "...your personal email address ({{ current_user.email }})."
  - YouTube link "How to send emails from an alias" → `https://www.youtube.com/watch?v=VsypF-DBaow`.
- Create form rendered only `{% if can_create_contacts %}`: hidden `form-name=create`,
  `{{ new_contact_form.csrf_token }}`, `{{ new_contact_form.email(class="form-control",
  placeholder="First Last <email@example.com>", autofocus=True) }}`,
  `{{ render_field_errors(new_contact_form.email) }}`, caption "Where do you want to send the email?",
  button "Create reverse-alias". (The inner `{% if can_create_contacts %}` around the button is dead —
  outer if guarantees true; the disabled-button branch with title "Upgrade to premium to create
  reverse-aliases" is unreachable. **GOTCHA**: when `can_create_contacts` is false the opening
  `<div class="row mb-5">` is also skipped but the search column's closing `</div>` still renders —
  the original markup is unbalanced; port the template faithfully rather than "fixing" structure.)
- Search form: hidden `form-name=search`, `csrf_form.csrf_token`, input `name="query"` value
  `{{ query }}`, placeholder "Enter to search for contacts". Reset link shown `{% if query %}`:
  with highlight → `url_for(..., alias_id, highlight_contact_id=highlight_contact_id)`, else
  `url_for(..., alias_id)`; label "Reset".
- Contact card per `contact_info` (`{% set contact = contact_info.contact %}`):
  - `highlight-row` class when `contact.id == highlight_contact_id`.
  - `{{ contact.website_email }}` bold; `🗝` badge (tooltip "PGP Enabled") when
    `contact.pgp_finger_print`.
  - block/unblock switch class `enable-disable-contact`, checked when **not** `contact.block_forward`;
    tooltips: blocked → "Unblock sender - start receiving emails from this sender", else "Block sender -
    stop receiving emails from this sender". **AJAX** (not htmx here): `POST
    /api/contacts/{id}/toggle` with `Content-Type: application/json` and header
    `'{{ HEADER_ALLOW_API_COOKIES }}': 'allow'` (the header NAME is templated from the global =
    `X-Sl-Allowcookies`). Toasts: `"${contactEmail} is blocked"` / `"${contactEmail} is unblocked"`;
    failure "Sorry for the inconvenience! Could you refresh the page & retry please?" / "Unknown Error".
  - mailto link `href="{{ 'mailto:' + contact.website_send_to() }}"` displaying literal
    `*************************` (obfuscated placeholder text), plus copy button with
    `data-clipboard-text="{{ contact.website_send_to() }}"` labeled "Copy reverse-alias" (tooltip
    "Copy the reverse-alias to clipboard"; mailto tooltip "You can click on this to open your email
    client. Or use the copy button 👉").
  - latest-activity block (same icon/branching pattern as index cards) using
    `contact_info.latest_email_log`; then "Contact created {{ contact.created_at | dt }}"; when no log:
    "No Activity in the last 14 days. Contact created {{ contact.created_at | dt }}".
  - `{{ contact_info.nb_forward }}` forwarded, `{{ contact_info.nb_reply }}` sent in the last 14 days.
  - "Edit ➡" link → `url_for('dashboard.contact_detail_route', contact_id=contact.id)`.
  - Delete form: hidden `form-name=delete`, `contact-id`; the visible span "Delete" triggers a bootbox
    confirm: message "All activities associated with this contact will also be deleted, please
    confirm.", buttons "Yes, delete it" (danger) / "Cancel".
- Pagination `{% if nb_contact > PAGE_LIMIT or page > 0 %}` (uses the `PAGE_LIMIT` global): Previous /
  Next → `url_for('dashboard.alias_contact_manager', alias_id=alias.id, page=page±1)` with `disabled`
  class at `page == 0` / `last_page`. **Note**: pagination links drop `query` and
  `highlight_contact_id`.
- `current_user` attrs: `email`. Globals: `PAGE_LIMIT`, `HEADER_ALLOW_API_COOKIES`.

---

## 9. GET|POST `/dashboard/contact/<int:contact_id>/` (`dashboard.contact_detail_route`)

`@login_required`. No limiter, no lock.

- `contact = Contact.get(contact_id)`; missing or **`contact.user_id != current_user.id`** (checks the
  contact's own user_id column, not via the alias) → flash `"You cannot see this page"` (warning),
  redirect `dashboard.index`.
- `alias = contact.alias`.

### Form — `PGPContactForm`

| field | type | validators | error strings |
|---|---|---|---|
| `action` | StringField("action") | `DataRequired()`, `AnyOf(("save","remove"))` | `"This field is required."` / `"Invalid value, must be one of: save, remove."` |
| `pgp` | StringField("pgp") | `Optional()` | — |

**GOTCHA — CSRF handling differs here**: there is no separate `csrf_form`; CSRF is validated as part of
`pgp_form.validate()` (FlaskForm). A POST with `form-name != "pgp"` (or missing) does nothing and
falls straight to re-render (200) with no flash.

### POST (`form-name == "pgp"`)

- `pgp_form.validate()` fail (bad CSRF or bad `action`) → flash `"Invalid request"` (warning),
  redirect `request.url`.
- `action == "save"`:
  - `not current_user.is_premium()` → flash `"Only premium plan can add PGP Key"` (warning), redirect
    `url_for("dashboard.contact_detail_route", contact_id=contact_id)`.
  - empty `pgp` field → `flash("Invalid pgp key")` — **no category → default category `message`** —
    then **falls through to re-render** (200).
  - else: `contact.pgp_public_key = pgp_form.pgp.data`; `contact.pgp_finger_print =
    load_public_key_and_check(...)` (imports the key into GnuPG and does a test-encrypt; see BLOCKER
    B1):
    - `PGPException` → flash `"Cannot add the public key, please verify it"` (error) → falls through to
      re-render. **GOTCHA**: no commit and no rollback — the in-memory mutation shows the rejected key
      in the textarea for this response only; DB unchanged.
    - success → alias audit log `action="update_contact"`, message
      `f"Added PGP key {contact.pgp_public_key} for contact {contact_id} ({contact.email})"` (the FULL
      key text goes into the audit message); commit; flash
      `f"PGP public key for {contact.email} is saved successfully"` (success); redirect
      `url_for("dashboard.contact_detail_route", contact_id=contact_id)`.
- `action == "remove"` (allowed for **free** users too):
  - audit log `action="update_contact"`, message `f"Removed PGP key {contact.pgp_public_key} for
    contact {contact_id} ({contact.email})"` (logs the OLD key before clearing);
  - `contact.pgp_public_key = None; contact.pgp_finger_print = None`; commit;
  - flash `f"PGP public key for {contact.email} is removed"` (success); redirect
    `url_for("dashboard.contact_detail_route", contact_id=contact_id)`.

### GET / fall-through render

`dashboard/contact_detail.html` with `contact`, `alias`, `pgp_form`.

Template:
- Title: `Contact {{ contact.email }} - Alias {{ alias.email }}` (`contact.email` ≡ `website_email`).
- Breadcrumb: link `{{ alias.email }}` → `url_for('dashboard.alias_contact_manager',
  alias_id=alias.id)`; active item `{{ contact.email }}` + `🗝` badge when `pgp_finger_print`.
- Card "Pretty Good Privacy (PGP)" with explainer "By importing your contact PGP Public Key into
  SimpleLogin, all emails sent to <b>{{ contact.email }}</b> from your alias <b>{{ alias.email }}</b>
  are <b>encrypted</b>."
- Premium gate: `{% if not current_user.is_premium() %}` alert-danger
  `"This feature is only available in premium plan."`; the textarea and the Save button both carry
  `disabled` for free users. Remove button (btn-danger, `value="remove"`) rendered only when
  `contact.pgp_finger_print` — NOT premium-gated.
- Textarea `name="pgp"` id `pgp-public-key`, rows 10, content `{{ contact.pgp_public_key or "" }}`,
  placeholder `(Drag and drop or paste your pgp public key here)\n-----BEGIN PGP PUBLIC KEY BLOCK-----`
  (`&#10;` newline). Buttons are `name="action"` with `value="save"` / `value="remove"` (HTML button
  value submission). Hidden `form-name=pgp`, `{{ pgp_form.csrf_token }}`.
- Script: `/static/js/utils/drag-drop-into-text.js` + `enableDragDropForPGPKeys('#pgp-public-key');`.
- `current_user` attrs: `is_premium()`.

---

## 10. DB tables/columns touched by this group (all already in `cloudflare/migrations/0001_init.sql`)

| Table | Access | Columns |
|---|---|---|
| `alias` | R/W | list/filter columns (spec 02 §14) + `transfer_token`, `transfer_token_expiration`, `original_owner_id`, `directory_id`, `automatic_creation`, `custom_domain_id`, `mailbox_id`, `pinned`, `disable_pgp`, `note`, `name`, `delete_on` |
| `users` | R/W | `intro_shown` (W on GET /dashboard/), `expand_alias_info`, `alias_generator`, `alias_delete_action`, `default_mailbox_id`, `newsletter_alias_id`, `email`, premium/trial columns, `flags` |
| `email_log` | R | `user_id`, `is_reply`, `blocked`, `bounced`, `contact_id`, `alias_id`, `created_at`, `bounced_mailbox_id` |
| `contact` | R/W | `alias_id`, `user_id` (rewritten on transfer), `website_email`, `name`, `reply_email`, `block_forward`, `pgp_public_key`, `pgp_finger_print`, `created_at` |
| `mailbox` | R | `email`, `verified`, `flags` (admin-disabled), `pgp_finger_print`, `disable_pgp` |
| `alias_mailbox` | R/W | rewritten on custom-alias create and transfer |
| `alias_used_on`, `client_user` | W | `user_id` rewritten on transfer |
| `directory` | R | `id`, `name` (filter dropdown) |
| `custom_domain` | R | `domain`, `name`, `verified` (MX), `ownership_verified`, `random_prefix_generation` |
| `public_domain` | R | suffix building |
| `deleted_alias`, `domain_deleted_alias` | R/W | pre-create checks, delete flows |
| `alias_hibp` (+ `hibp`) | R | `hibp` filter + breach-count badge |
| `alias_audit_log` | W | actions: `change_status`, `delete`/`trash`, `update_contact`, `delete_contact`, `create_contact`, `initiate_transfer_alias`, `transferred_alias`, `accept_transfer_alias`, `create` |
| `daily_metric` | W | alias creation |

---

## 11. BLOCKERS / external dependencies

| ID | Feature | Flask behavior | Recommended stance |
|---|---|---|---|
| B1 | **GPG/PGP key import** (§9) | `load_public_key_and_check` shells into GnuPG via `python-gnupg` (`gnupg.GPG(gnupghome=GNUPGHOME)`): imports the armored key, extracts the fingerprint, test-encrypts, deletes on failure; raises `PGPException` → flash "Cannot add the public key, please verify it". | No GnuPG on Workers. Replace with a JS OpenPGP implementation (e.g. `openpgp.js`: `readKey` + fingerprint + canEncrypt check) to compute `pgp_finger_print`; if not ported yet, make save always flash the PGPException error string and keep remove working (remove has no GPG dependency). |
| B2 | **SMTP transactional email** on transfer accept (§7) | `send_email` to the previous owner (subject `"Alias {alias.email} has been received"`, `alias-transferred` templates) via the SMTP/postfix stack. | Route through the existing `cloudflare/src/lib/mailer.ts` abstraction; if the mailer is unconfigured, skip silently (Flask only sends when `old_user.can_send_or_receive()` — treat missing mailer like a can't-send owner). |
| B3 | **Redis** — flask-limiter windows (`ALIAS_LIMIT`, `10/minute` GET, `2/minute` export, `5/minute` receive), `parallel_limiter` locks (`alias_creation`, `contact_creation`), `Alias.create` bucket limits | All no-ops when Redis (`MEM_STORE_URI`) absent / `DISABLE_RATE_LIMIT` set. | Reuse the API port's KV/DO limiter (`cloudflare/src/lib/ratelimit.ts`); web breach renders HTML `error/429.html` instead of JSON. Parallel-lock → same 429 page; acceptable to config-gate off exactly like Flask-without-Redis. |
| B4 | **Postgres FTS** in alias search (`ts_vector @@ plainto_tsquery`) | One OR-branch of the search filter (over `note`). | Already handled by the API port (`getAliasInfosWithPaginationV3` approximates with LIKE); reuse — the note-ILIKE branch overlaps it. |
| B5 | **HIBP data** (`hibp` filter, breach badge, haveibeenpwned.com links) | Breach rows are populated by an out-of-scope cron; the web views only READ `alias_hibp`. | Port the read path as-is (empty tables → badge never shows, `hibp` filter returns nothing). No gating needed. |
| B6 | **intro.js / Vue / jQuery / bootbox / toastr / multipleSelect / store.js / htmx** static assets | Served from `/static`. | Not external at runtime — bundle the same static files; no gating. |
| B7 | **SHA3-224 HMAC** for transfer tokens (§6) | `hmac.new(secret, token, "sha3_224")` via hashlib. | WebCrypto lacks SHA3 — use `@noble/hashes` (sha3_224 + hmac). Keep byte-compatibility so previously issued (hashed) tokens keep working; legacy PLAINTEXT tokens must also still match (§7 step 2). |
| B8 | **Premium subscription checks** (`is_premium`, `can_create_new_alias`, `can_create_contacts`) | Read Paddle/Apple/Manual/Coinbase/Partner subscription tables. | Already ported for the API (`cloudflare/src/lib/models.ts`); reuse. No live Paddle/Coinbase calls happen in these views. |

### Porting gotchas checklist (recap)

1. GET `/dashboard/` **writes** `users.intro_shown` (first visit).
2. Filter `mailbox:<x>` / `directory:<x>` with non-numeric x, missing `alias-id` on delete POST,
   non-numeric `generator_scheme`, and missing `prefix` on custom-alias POST are all **500s** in Flask,
   not handled errors.
3. `page_limit = PAGE_LIMIT + 1` fetch trick on the index; `last_page` on the contact page is
   `< PAGE_LIMIT` while on the index it's `<= PAGE_LIMIT` (after fetching 21).
4. Highlighted alias/contact is **prepended**, potentially yielding 21 cards.
5. Both expired AND tampered suffix signatures flash the "expired" message (§3.2 step 5).
6. `custom_alias` failure branches split between redirect-after-flash and re-render-after-flash —
   §3.2 lists which is which; re-renders show the POSTed mailbox subset in the select.
7. Sudo gap is 120 s for web (vs 300 s for API sudo); sudo redirect preserves `?next=` and preserved
   flashes via `session["_preserved_flashes"]`.
8. Transfer receive accepts legacy plaintext tokens and NULL expirations; primary mailbox after
   transfer = **last** submitted mailbox.
9. `contact_detail` uses the form's own CSRF (no `csrf_form`), has a category-less flash
   (`"Invalid pgp key"` → category `message`), and free users can REMOVE but not SAVE keys.
10. `toggle_contact` returns plain-text 400/403 (htmx target), not flash/redirect.
11. GET filter form leaks `csrf_token` into the query string (harmless, faithful).
12. CSV export: `True`/`False` capitalization, primary-mailbox-first ordering, `\r\n` rows,
    2/minute + sudo.
