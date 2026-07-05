# Web Spec 00 — Cross-cutting web infrastructure (layout, jinja env, auth/CSRF/flash plumbing, error pages)

Everything the other five web specs (`01-auth-pages` … `05-*`) assume. Source files:

- `simplelogin_app.py` (app factory: blueprint registration, error handlers, jinja filters + context processor, index/health/favicon/openid/dnt routes, request hooks)
- `app/extensions.py` (login_manager + limiter), `app/session.py` (Redis server-side session), `app/dashboard/views/enter_sudo.py` (`sudo_required`)
- `app/config.py`, `app/constants.py`, `app/build_info.py`
- `templates/base.html`, `default.html`, `single.html`, `sign_in_with_sl_base.html`, `header.html`, `menu.html`, `footer.html`, `_formhelpers.html`, `error.html`, `templates/error/{400,403,404,405,429,500,503}.html`, `templates/partials/toggle_contact.html`
- `static/js/{theme.js,an.js,index.js}`, `static/js/utils/drag-drop-into-text.js`, `static/package.json`
- `app/monitor/views.py`, `app/internal/{exit_sudo.py,integrations.py}`, `maintenance_app.py`

Port correspondences already in the repo (do not re-invent):
- KV session: `cloudflare/src/lib/session.ts` (cookie `slapp`, 7-day TTL, `SessionData` with `user_id/sudo_time/flashes/csrf/extra`).
- Rate limiting: `cloudflare/src/lib/ratelimit.ts` (`parseLimits`, `rateLimit`, key `userid:{id}` / `ip:{addr}`).
- Nunjucks runtime: `cloudflare/src/lib/web/templates.ts` (precompiled loader, `dt` + `enumerate` filters, `none` test already registered).
- Humanized dates: `cloudflare/src/lib/dates.ts` (`humanize`).

---

## 1. Registered blueprints & port scope

`simplelogin_app.py:202-215` (`register_blueprints`) — registration order:

| Blueprint | url_prefix | Port scope |
|---|---|---|
| `auth` | `/auth` | **IN** (web spec 01) |
| `monitor` | `/` (yes, root) | OUT — but `/git`,`/version`,`/live` are trivial; see §3 |
| `dashboard` | `/dashboard` | **IN** (web specs 02–05) |
| `developer` | `/developer` | OUT (SIWSL app management) |
| `phone` | `/phone` | OUT |
| `oauth` | registered **twice**: `/oauth` **and** `/oauth2` | OUT (OAuth/OIDC provider) |
| `onboarding` | `/onboarding` | OUT |
| `discover` | `/discover` | OUT |
| `internal` | `/internal` | OUT except `exit-sudo-mode` (§3, trivially portable) |
| `api` | `/api` | already ported (`cloudflare/src/routes/*`) |

Also registered at app level (outside blueprints): flask-admin at `/admin` (OUT), paddle webhooks `/paddle` + `/paddle_coupon` (OUT, BLOCKER), flask-profiler (config-gated by `FLASK_PROFILER_PATH`, OUT), `/dnt`, `/`, `/health`, `/favicon.ico`, `/.well-known/openid-configuration`, `/jwks`.

`app.url_map.strict_slashes = False` app-wide (`simplelogin_app.py:421`) — every path also matches with/without trailing slash. The Hono port must mirror this (e.g. accept both `/dashboard` and `/dashboard/`).

### 1.1 url_for → path map (all endpoints referenced by templates, including OUT-of-scope blueprints)

The port needs a `urlFor(endpoint, args)` helper. Unknown endpoint = build-time error, so this table must be complete. Query args that are not path params are appended as query string (e.g. `url_for("dashboard.enter_sudo", next="/x")` → `/dashboard/enter_sudo?next=%2Fx`); `_anchor="x"` appends `#x`.

**In-scope endpoints referenced by the base layout** (implemented by web specs 01–05):

| Endpoint | Path |
|---|---|
| `dashboard.index` | `/dashboard/` |
| `dashboard.notifications_route` | `/dashboard/notifications` |
| `dashboard.pricing` | `/dashboard/pricing` |
| `dashboard.api_key` | `/dashboard/api_key` |
| `dashboard.account_setting` | `/dashboard/account_setting` |
| `dashboard.setting` | `/dashboard/setting` |
| `dashboard.mailbox_route` | `/dashboard/mailbox` |
| `dashboard.custom_domain` | `/dashboard/custom_domain` |
| `dashboard.directory` | `/dashboard/directory` |
| `dashboard.subdomain_route` | `/dashboard/subdomain` |
| `dashboard.app_route` | `/dashboard/app` |
| `dashboard.enter_sudo` | `/dashboard/enter_sudo` |
| `dashboard.toggle_contact` | `/dashboard/contacts/<int:contact_id>/toggle` |
| `auth.login` | `/auth/login` |
| `auth.logout` | `/auth/logout` |
| `static` | `/static/<filename>` (extra kwargs become query string: `url_for('static', filename='js/an.js', v='2')` → `/static/js/an.js?v=2`) |

**OUT-of-scope endpoints whose links must keep pointing at the right (unported) URL** — extracted from the blueprint code:

| Endpoint | Path | Defined in |
|---|---|---|
| `phone.index` | `/phone/` | `app/phone/views/index.py:13` |
| `phone.reservation_route` | `/phone/reservation/<int:reservation_id>` | `app/phone/views/phone_reservation.py:12` |
| `developer.index` | `/developer/` | `app/developer/views/index.py:10` |
| `developer.new_client` | `/developer/new_client` | `app/developer/views/new_client.py:18` |
| `developer.client_detail` | `/developer/clients/<client_id>` | `app/developer/views/client_detail.py:32` |
| `developer.client_detail_oauth_setting` | `/developer/clients/<client_id>/oauth_setting` | `client_detail.py:120` |
| `developer.client_detail_oauth_endpoint` | `/developer/clients/<client_id>/oauth_endpoint` | `client_detail.py:156` |
| `developer.client_detail_advanced` | `/developer/clients/<client_id>/advanced` | `client_detail.py:177` |
| `developer.client_detail_referral` | `/developer/clients/<client_id>/referral` | `client_detail.py:205` |
| `discover.index` | `/discover/` | `app/discover/views/index.py:8` |
| `onboarding.index` | `/onboarding/` | redirects to `onboarding.setup` |
| `onboarding.setup` | `/onboarding/setup` | `app/onboarding/views/index.py:11` |
| `onboarding.setup_done` | `/onboarding/setup_done` | sets `setup_done` cookie (30 d) |
| `onboarding.final` | `/onboarding/final` | `@login_required`, `10/minute` |
| `onboarding.account_activated` | `/onboarding/account_activated` | `@login_required` |
| `onboarding.extension_redirect` | `/onboarding/extension_redirect` | UA-based redirect |
| `oauth.authorize` | `/oauth/authorize` (alias `/oauth2/authorize`) | `app/oauth/views/authorize.py:41` |
| `oauth.token` | `/oauth/token` (alias `/oauth2/token`) | `app/oauth/views/token.py:13` |
| `oauth.user_info` | `/oauth/user_info`, `/oauth/me`, `/oauth/userinfo` (+ `/oauth2/…`) | `app/oauth/views/user_info.py:10-12` |
| `internal.exit_sudo_mode` | `/internal/exit-sudo-mode` | `app/internal/exit_sudo.py:6` |
| `internal.set_enable_proton_cookie` | `/internal/integrations/proton` | `app/internal/integrations.py:7` |
| `monitor.git_sha1` | `/git` | `app/monitor/views.py:5` |
| `monitor.version` | `/version` | `app/monitor/views.py:10` |
| `monitor.live` | `/live` | `app/monitor/views.py:15` |
| `monitor.test_exception` | `/exception` | `app/monitor/views.py:20` |

Hardcoded hrefs in the base layout that bypass `url_for` (keep as-is): `/dashboard/support` (`header.html:101`, `menu.html:119`), `/admin` (`menu.html:91`), `/static/*` asset paths, `https://simplelogin.io/*` marketing links, `/` (error pages' Home button).

---

## 2. App-level request hooks (must run on every web request)

From `set_index_page()` and `create_simplelogin_app()`:

1. `before_request` (`simplelogin_app.py:226-240`): skips `/static`, `/admin/static`, `/_debug_toolbar`. Sets `g.start_time`, `g.request_id`. **Referral capture**: if `?slref=<code>` on ANY url → `session["slref"] = code` (read later by register; see web spec 01).
2. `before_request` `make_session_permanent` (`simplelogin_app.py:480-483`): `session.permanent = True`, lifetime **7 days** (this is why the KV TTL in `session.ts` is 7 d).
3. `after_request` (`simplelogin_app.py:242-267`): request logging + NewRelic event — no port needed (Workers analytics instead).
4. `teardown_appcontext`: SQLAlchemy `Session.remove()` — N/A for D1.
5. ProxyFix `x_for=1, x_host=1` — N/A (Workers gives real IP via `CF-Connecting-IP`; `ratelimit.ts` `clientIp` already handles this).

---

## 3. Routes owned by this spec (14)

| # | Path | Methods | Auth | Behavior |
|---|------|---------|------|----------|
| 1 | `/` | GET, POST | none | `current_user.is_authenticated` → 302 `dashboard.index` (`/dashboard/`); else 302 `auth.login` (`/auth/login`). Note: POST also accepted, same behavior. |
| 2 | `/health` | GET | none | body `success`, 200, plain text. |
| 3 | `/favicon.ico` | GET | none | 302 → `/static/favicon.ico`. |
| 4 | `/dnt` | GET | none | Returns a raw HTML fragment (no template, no doctype): two `<script>` tags — loads `/static/local-storage-polyfill.js`, then `store.set('analytics-ignore', 't'); alert("Analytics disabled"); window.location.href = "/";`. Port: static response, keep byte-identical semantics. |
| 5 | `/.well-known/openid-configuration` | GET | none, **CORS `*`** | JSON: `issuer`=`URL`, `authorization_endpoint`=`URL+"/oauth2/authorize"`, `token_endpoint`=`URL+"/oauth2/token"`, `userinfo_endpoint`=`URL+"/oauth2/userinfo"`, `jwks_uri`=`URL+"/jwks"`, `response_types_supported`=`["code","token","id_token","id_token token","id_token code"]`, `subject_types_supported`=`["public"]`, `id_token_signing_alg_values_supported`=`["RS256"]`. OAuth provider itself is OUT of scope — still serve this metadata (it is static given `URL`) or 404 it consciously. |
| 6 | `/jwks` | GET | none, CORS `*` | `{"keys": [get_jwk_key()]}` — RSA public key from `OPENID_PRIVATE_KEY_PATH`. **BLOCKER** (OIDC provider key); defer with the oauth blueprint. |
| 7 | `/git` | GET | none | body = `build_info.SHA1` (string, `"dev"` in repo). |
| 8 | `/version` | GET | none | body = `build_info.VERSION` (= SHA1). |
| 9 | `/live` | GET | none | body `live`. |
| 10 | `/exception` | GET | none | raises → 500 page (Sentry test). Port: optional. |
| 11 | `/internal/exit-sudo-mode` | GET | none (works even anonymous) | **GET with side effects**: `session["sudo_time"] = 0`; flash `Exited sudo mode` (**info**); 302 → `dashboard.index`. |
| 12 | `/internal/integrations/proton` | GET | none | flash `You can now connect your Proton and your SimpleLogin account` (**success**); 302 → `/dashboard/setting#connect-with-proton` if authenticated else `/auth/login`. (Historically also set a cookie; current code only redirects + flashes.) |
| 13 | `/paddle` | GET, POST | none (webhook, signature-verified) | Paddle subscription webhook. **BLOCKER: Paddle** — do not port; return 404 or 501. |
| 14 | `/paddle_coupon` | GET, POST | none | Paddle coupon webhook. **BLOCKER: Paddle**. |

No wtforms on any of these. None are CSRF-protected (all effectively GET). Rate limits: none.

---

## 4. Error handlers (`setup_error_page`, `simplelogin_app.py:310-365`)

Every handler branches on `request.path.startswith("/api/")` → JSON, else HTML template. The web port must reproduce the HTML side; the API side already exists.

| Status | API JSON | Web behavior |
|---|---|---|
| 400 | `{"error":"Bad Request"}` | render `error/400.html`, 400 |
| 401 | `{"error":"Unauthorized"}` | **flash `You need to login to see this page` (error) + 302 `url_for("auth.login", next=request.full_path)`** — this is the `@login_required` funnel; `request.full_path` includes the query string and a trailing `?` when there is none (e.g. `/dashboard/setting?`). |
| 403 | `{"error":"Forbidden"}` | render `error/403.html`, 403 |
| 404 | `{"error":"No such endpoint"}` | render `error/404.html`, 404 |
| 405 | `{"error":"Method not allowed"}` | render `error/405.html`, 405 |
| 429 | `{"error":"Rate limit exceeded"}` | render `error/429.html`, 429 (rate-limit breaches from flask-limiter land here) |
| any Exception | `{"error":"Internal error"}` | render `error/500.html`, 500 |

### Error templates (`templates/error/*` all `{% extends "error.html" %}`)

`error.html` extends `base.html`, fills `block content` with a centered `page-content` div: `block error_name` (display-3, with `<i class="si si-exclamation">`), `block error_description` (h3), `block suggestion` (default: `<a class="btn btn-primary" href="/">…Home Page</a>`).

Exact strings:
- **400**: name `400`, description `We are sorry but your request contains bad syntax and cannot be fulfilled`, suggestion: Home Page button.
- **403**: name `403`, description `We are sorry but you do not have permission to access this page`, Home Page button.
- **404**: name `404`, description `This page does not exist.`, suggestion `<a … href="javascript:history.back()">…Go Back</a>`.
- **405**: name `405`, description `Client used wrong method when accessing resource.`, Go Back button.
- **429**: name `429`, description `Whoa, slow down there, pardner!`, Home Page button.
- **500**: name `Server error`, description `Looks like we are having some server issues...` `<br/><br/>` `We are notified and will look at this issue asap!`, Go Back button.
- **503** (`error/503.html`): standalone full HTML page (does NOT extend base — used by `maintenance_app.py` without DB). Title `Maintenance | SimpleLogin`, text `SimpleLogin is currently undergoing scheduled maintenance.` `<br/>` `Please try again in a few moments.`, button `Refresh Page` (`javascript:location.reload()`). Maintenance app also returns JSON `{"error": "Service is under maintenance, please try again later"}` 503 for `/api/*`. Port stance: optional; Workers has no maintenance mode — keep the template available.

Gotcha: error pages extend `base.html`, so they consume pending flash messages and reference `current_user` — the anonymous-user object (`is_authenticated=False`) must exist when rendering 4xx for logged-out users.

---

## 5. Jinja environment (`jinja2_filter`, `simplelogin_app.py:374-409`)

### 5.1 Custom filters

- `dt` — `arrow.get(value).humanize()` (e.g. "3 days ago"). Port: already in `templates.ts` via `dates.ts humanize`. Used 34× across templates.
- `enumerate` — Python `enumerate(iterable)`; consumed as `{% for idx, item in list|enumerate %}`. Port: already in `templates.ts` (returns `[i, item]` pairs) — but see §7 tuple-unpack caveat. Used 3× (all in `templates/admin/*`, OUT of scope — keep the filter anyway).

No other `jinja_env` tweaks exist (no autoescape changes, no extensions, no globals besides the context processor).

### 5.2 Context processor globals (injected into EVERY render)

| Key | Value | Source |
|---|---|---|
| `YEAR` | `arrow.now().year` | computed per request |
| `NOW` | `arrow.now()` Arrow object — templates access **`NOW.timestamp`** (arrow 0.16: property, unix float) | computed per request |
| `URL` | `config.URL` | env `URL` (required) |
| `SENTRY_DSN` | `config.SENTRY_FRONT_END_DSN` | env `SENTRY_FRONT_END_DSN` or fallback `SENTRY_DSN` |
| `VERSION` | `build_info.SHA1` | `app/build_info.py` (`"dev"`; used for CSS cache-busting `?v=`) |
| `FIRST_ALIAS_DOMAIN` | `config.FIRST_ALIAS_DOMAIN` | env `FIRST_ALIAS_DOMAIN` or `EMAIL_DOMAIN` |
| `PLAUSIBLE_HOST` | env `PLAUSIBLE_HOST` (None default) | gate for analytics `<script>` |
| `PLAUSIBLE_DOMAIN` | env `PLAUSIBLE_DOMAIN` (None default) | " |
| `GITHUB_CLIENT_ID` | env (None) | social-login button gating in auth pages |
| `GOOGLE_CLIENT_ID` | env (None) | " |
| `FACEBOOK_CLIENT_ID` | env (None) | " |
| `LANDING_PAGE_URL` | env or `https://simplelogin.io` | logo links in `single.html`/`sign_in_with_sl_base.html` |
| `STATUS_PAGE_URL` | env or `https://status.simplelogin.io` | |
| `SUPPORT_EMAIL` | env (required) | shown on several dashboard pages |
| `PGP_SIGNER` | env (None) | settings page |
| `CANONICAL_URL` | `f"{config.URL}{request.path}"` — **per request** | `<link rel="canonical">` in base.html:29 |
| `PAGE_LIMIT` | `20` (constant) | pagination page size everywhere |
| `ZENDESK_ENABLED` | `"ZENDESK_ENABLED" in os.environ` (presence bool) | gates Help dropdown + `/dashboard/support` links |
| `MAX_NB_EMAIL_FREE_PLAN` | env or `5` | trial tooltip in header.html:137 |
| `HEADER_ALLOW_API_COOKIES` | constant `"X-Sl-Allowcookies"` (`app/constants.py:3`) | injected into JS fetch headers (footer.html:213 etc.) |

Port: make these part of the base render context in `templates.ts`'s `renderTemplate` (config-derived ones from `env.ts`, `NOW`/`YEAR`/`CANONICAL_URL` computed per request). `NOW` must be an object exposing at least `.timestamp` (unix seconds) and `.year`.

---

## 6. Base templates

### 6.1 Template inheritance graph

```
base.html                       (html skeleton, head assets, flash drain, global JS)
├── default.html                (block content = header.html + container + block default_content + footer.html) — all logged-in dashboard pages
├── single.html                 (block content = centered 32rem card + logo → block single_content) — auth pages
├── sign_in_with_sl_base.html   (48rem variant with siwsl.svg logo) — oauth provider pages, OUT of scope
└── error.html                  (block content = centered error blocks) → error/4xx,500
```

Blocks defined by `base.html`: `title` (rendered as `{% block title %}{% endblock %} | SimpleLogin` — page specs must give exact titles), `head` (extra head tags), `announcement`, `content`, `script` (extra body-end scripts).

### 6.2 `base.html` details (line refs)

- **:1** `{% from "_formhelpers.html" import render_field, render_field_errors %}` — GOTCHA: this import in the PARENT makes `render_field` available inside child-template blocks; child templates do NOT import it themselves (`_formhelpers` appears in no other file). In Nunjucks, parent-scope imports are **not** visible in child blocks — the precompile pipeline must inject the import into every child (or register `render_field` as a global/macro in the environment).
- **:5** `<html data-theme="{%- if request.cookies.get('dark-mode') == 'true' -%} dark{%- endif -%}">` — server-side dark mode from cookie `dark-mode` (note the leading space in the emitted value: `data-theme=" dark"`; CSS selector is `[data-theme="dark"]` in `darkmode.css:16`, matched anyway because browsers… no — attribute selector does NOT match `" dark"`; in practice `static/js/theme.js` re-sets the attribute to `dark` on DOM-ready, which is what makes dark mode work. Replicate as-is or normalize; do not "fix" silently without noting).
- Head meta: viewport (user-scalable=no), `X-UA-Compatible`, `Content-Language en`, msapplication-TileColor `#2d89ef`, theme-color `#4188c9`, apple-mobile-web-app tags, `referrer no-referrer`, Bing `msvalidate.01` = `2A313A69CBFD1A378C3B91734DC221A8`, Yandex verification `c9e5d4d68bc983a1`, description `Protect your email address with email ALIAS. Create a different email alias for each website. No more phishing, or spam.`
- **:29** `<link rel="canonical" href="{{ CANONICAL_URL }}">`.
- **:30-33** `<title>{% block title %}{% endblock %} | SimpleLogin</title>`.
- **:72-76** Plausible gate: `{% if PLAUSIBLE_HOST and PLAUSIBLE_DOMAIN %}` → script tag. GOTCHA base.html:75: the attributes use **typographic curly quotes** (`”` U+201D) — `data-domain=”{{ PLAUSIBLE_DOMAIN }}”` — literally malformed HTML shipped in prod. Preserve or fix consciously.
- **:78, :81** cache-busted `darkmode.css?v={{ VERSION }}` and `/static/style.css?v={{ VERSION }}`.
- **:83** `<script>toastr.options.closeButton = true;</script>`.
- **:89-94** Black-Friday banner: `{% if NOW.timestamp < 1701475201 and current_user.is_authenticated and current_user.should_show_upgrade_button() %}` → green alert `Black Friday: $20 for the first year instead of $30. Available until December 1st.` — the timestamp gate (2023-12-01) makes this dead code now, but it forces `NOW.timestamp` (number) and an anonymous-safe `current_user` into the context of EVERY page.
- **:98-104 flash drain**: `{% with messages = get_flashed_messages(with_categories=true) %}` … `{% for category, message in messages %}<script>toastr.{{category }}("{{ message }}");</script>{% endfor %}`. See §9.
- **:106** `{% block content %}{% endblock %}`.
- **:108-188 inline script**: Sentry.init gated `{% if SENTRY_DSN %}` (with the long ignoreErrors/blacklistUrls lists); `bootbox.setDefaults({closeButton:false, backdrop:true})`; ClipboardJS on `.clipboard` with success toast `Copied to clipboard`; `.back-or-close` click handler (`window.close()` if `history.length == 1` else `history.back()`); **htmx global error hook**: `document.body.addEventListener('htmx:responseError', … toastr.error("Sorry for the inconvenience! Could you refresh the page & retry please?", "Unknown Error"))`.
- **:189-190** `/static/local-storage-polyfill.js` and `/static/js/an.js?v=2`.

Static assets loaded by `base.html` head, in order (the port must serve all of these; `static/node_modules/*` are NOT in git — they come from `npm install` inside `static/` per `static/package.json`, pin: @sentry/browser ^5.30.0, bootbox ^5.5.3, font-awesome ^4.7.0, htmx.org ^1.6.1, intro.js ^2.9.3, multiple-select ^1.5.2, parsleyjs ^2.9.2, qrious ^4.0.2, toastr ^2.1.4, vue ^2.6.14):

```
/static/node_modules/font-awesome/css/font-awesome.css
/static/assets/css/dashboard.css                     (tabler; + dashboard.rtl.css exists)
/static/assets/js/vendors/jquery-3.2.1.min.js
/static/assets/js/vendors/bootstrap.bundle.min.js
/static/assets/js/vendors/jquery.sparkline.min.js
/static/assets/js/vendors/selectize.min.js
/static/assets/js/vendors/jquery.tablesorter.min.js
/static/assets/js/vendors/jquery-jvectormap-2.0.3.min.js
/static/assets/js/vendors/jquery-jvectormap-de-merc.js
/static/assets/js/vendors/jquery-jvectormap-world-mill.js
/static/assets/js/vendors/circle-progress.min.js
/static/assets/js/core.js
/static/vendor/clipboard.min.js
/static/node_modules/intro.js/minified/introjs.min.css + intro.min.js
/static/node_modules/@sentry/browser/build/bundle.min.js
/static/vendor/bootstrap-social.min.css
/static/node_modules/toastr/build/toastr.min.css + toastr.min.js
/static/node_modules/bootbox/dist/bootbox.min.js
/static/node_modules/multiple-select/dist/multiple-select.min.css + .js
/static/node_modules/parsleyjs/dist/parsley.min.js + i18n/en.js
/static/node_modules/htmx.org/dist/htmx.min.js
/static/darkmode.css?v={VERSION}
/static/style.css?v={VERSION}
/static/js/theme.js
/static/local-storage-polyfill.js
/static/js/an.js?v=2
(footer) /static/node_modules/vue/dist/vue.min.js
(images) /static/favicon.ico /static/logo.svg /static/logo-white.svg /static/logo-without-text.svg /static/siwsl.svg /static/default-avatar.png
```

Also present in `static/assets/js/vendors/` but loaded per-page, not by base: `base64.js`, `chart.bundle.min.js`, `jquery-3.2.1.slim.min.js`, `webauthn.js` (FIDO pages), `require.min.js`, `dashboard.js`. External asset referenced by footer.html:38: `https://img.shields.io/github/stars/simple-login/app?style=social` (external image — fine, browser-side).

Port stance for assets: serve `static/` via Workers Assets/Sites verbatim; run `npm ci` in `static/` at build time to materialize `node_modules` paths (only the 11 packages above are referenced).

### 6.3 `default.html`

`{% extends "base.html" %}`; `block content` = `<div class="flex-fill">` + `{% include "header.html" %}` + `<div class="container pt-1" style="min-height: 800px">{% block default_content %}{% endblock %}</div>` + `{% include "footer.html" %}`. All dashboard pages extend this.

### 6.4 `single.html`

`block content` = `page-single` container, max-width 32rem column, centered logo `<a href="{{ LANDING_PAGE_URL }}"><img src="/static/logo.svg" …height:20px></a>`, then `{% block single_content %}{% endblock %}`. Used by all `/auth/*` pages. `sign_in_with_sl_base.html` is the 48rem `siwsl.svg` variant for oauth-provider consent pages (OUT of scope).

### 6.5 `header.html` (included by default.html — logged-in pages only)

- **:4** brand logo → `url_for("dashboard.index")`; responsive `<picture>` (`logo-without-text.svg` ≤650px).
- **:14-18** dark-mode toggle `<div data-toggle="dark-mode">` (handled by `theme.js`).
- **:20-28** intro.js trigger `onclick="startIntro()"` with `data-intro` welcome text, `data-step="1"` (function defined in footer.html:181-184).
- **:30-70 notifications bell** — `<div id="notification-app" v-if="showNotification">` Vue 2 micro-app (code in footer.html:187-261, delimiters `[[ ]]`): on mount fetches `GET /api/notifications?page=0` with headers `Content-Type: application/json` + `{{HEADER_ALLOW_API_COOKIES}}: allow`; shows unread dot (`nav-unread` class when any `!notification.read`); dropdown lists `notification.title || notification.message` (rendered `v-html`!), link "More" → `/dashboard/notification/' + notification.id`, "See all notifications ➡" → `url_for("dashboard.notifications_route")`; per-item mark-as-read `POST /api/notifications/${id}/read` (same headers, error toast `Sorry for the inconvenience! Could you refresh the page & retry please?` / title `Unknown Error`); "Load more" button when `json.more`. The whole app stays hidden (`showNotification=false`) when the first page returns 0 notifications.
- **:71-114 Help**: `{% if ZENDESK_ENABLED %}` → dropdown (Docs / Github repo / Forum external links + `/dashboard/support`); else plain Docs link.
- **:115-121 Upgrade button**: `{% if current_user.should_show_upgrade_button() %}` → `btn-outline-primary` "Upgrade" → `url_for("dashboard.pricing")`. (`should_show_upgrade_button` = NOT lifetime-or-active-subscription, `app/models.py:880`.)
- **:122-158 avatar dropdown**: avatar = `current_user.profile_picture_url()` if `profile_picture_id` (S3-backed — **BLOCKER: S3**; falls back to `url_for("static", filename="default-avatar.png")`, `app/models.py:1001`) else initials `current_user.get_name_initial() or "👻"` (initials = first letter of each space-separated name word, uppercased; `""` when no name). Name line: `{{ current_user.name or current_user.email }}`. Premium badge: `{% if current_user.in_trial() %}` → `Premium expires {{ current_user.trial_end|dt }}` + tooltip `When you signed up, you have a free 7-day Premium trial. After that your account will automatically be downgraded to the Free plan. During the trial, the only limit is you can't create more than {{ MAX_NB_EMAIL_FREE_PLAN }} aliases.`; `{% elif current_user.is_premium() %}` → `Premium`. Menu items: `API Keys` → `dashboard.api_key`, `Account settings` → `dashboard.account_setting`, `Sign out` → `auth.logout`.
- **:169-178** collapsed nav row includes `menu.html`.

### 6.6 `menu.html` — main nav tabs

Active tab: each page template does `{% set active_page = "<name>" %}` at top-level; menu renders `class="nav-link {{ 'active' if active_page == '<name>' }}"`. Values in use: `dashboard`, `subdomain`, `mailbox`, `custom_domain`, `directory`, `app`, `setting`, `phone`, `api_key`, `developer`, `discover`. (Top-level `set` in the child must be visible inside the included menu — true in both Jinja and Nunjucks since include shares the render context.)

Items and gates:
1. `Aliases` → `dashboard.index` — always.
2. `Subdomains` → `dashboard.subdomain_route` — `{% if current_user.subdomain_is_available() %}` (**static method**: `SLDomain WHERE can_use_subdomain=true` count > 0, `app/models.py:681` — same for every user; port: one D1 count, cacheable).
3. `Mailboxes` → `dashboard.mailbox_route` — always.
4. `Domains` → `dashboard.custom_domain` — always.
5. `Directories` → `dashboard.directory` — always.
6. **menu.html:36-43 GOTCHA**: a block wrapped in an HTML comment `<!-- … -->` still contains live Jinja `{{ url_for('discover.index') }}` — Jinja EVALUATES inside HTML comments, so `discover.index` must resolve in the port's urlFor map even though the link is invisible. (menu.html:44-50 `developer.index` is inside `{# #}` Jinja comments → NOT evaluated; same for the api_key block at :68-74.)
7. `Apps` → `dashboard.app_route` — `{% if current_user.should_show_app_page() %}` (`ClientUser` count + `Client` count for the user > 0, `app/models.py:1250`).
8. `Settings` → `dashboard.setting` — always.
9. `Phone` (+ `Beta` badge) → `phone.index` — `{% if current_user.can_use_phone %}` (column attr, no parens).
10. `Admin ☢️` → hardcoded `/admin` — `{% if current_user.is_admin %}`.
11. Help dropdown — `{% if ZENDESK_ENABLED %}` (Docs, Forum, `/dashboard/support`).

### 6.7 `footer.html`

Marketing footer (all external `https://simplelogin.io/*`, extension-store links, social links — static HTML, copy verbatim). Plus: `startIntro()` definition, `vue.min.js` load, and the notification Vue app described in §6.5. No `current_user` access. Uses `HEADER_ALLOW_API_COOKIES` global in JS string interpolation (footer.html:213/230/248).

### 6.8 `_formhelpers.html`

```jinja
{% macro render_field(field) %}     → form-group row: label col-sm-2, widget col-sm-10,
                                      {{ field(**kwargs)|safe }}, description in <small>,
                                      errors as <ul class="errors"><li>…
{% macro render_field_errors(field) %} → <ul class="errors"><li class="text-danger">…
```

Port notes: `field(**kwargs)` calls the WTForms widget with extra HTML attrs (`class`, `placeholder`, …) — Nunjucks has no `**kwargs` splat. The port's form layer must expose each field as an object with `label`, `description`, `errors`, and a render function/pre-rendered widget HTML accepting attrs. `{{ form.csrf_token }}` must render `<input id="csrf_token" name="csrf_token" type="hidden" value="<token>">` (templates never call `hidden_tag()` — zero occurrences).

### 6.9 `current_user` attributes accessed by the base layout (superset needed on every logged-in render)

`is_authenticated`, `should_show_upgrade_button()`, `profile_picture_id`, `profile_picture_url()`, `get_name_initial()`, `name`, `email`, `in_trial()`, `trial_end` (arrow, piped through `|dt`), `is_premium()`, `subdomain_is_available()` (static), `should_show_app_page()`, `can_use_phone`, `is_admin`. Port: compute once per request into a `userCtx` view-model (booleans + strings), don't expose live methods to Nunjucks.

---

## 7. Jinja → Nunjucks incompatibility inventory (file:line)

Patch these at precompile time (a codemod pass over `templates/` before `nunjucks.precompile`) or via environment shims:

1. **`{% with %}` block** — base.html:98. Nunjucks has no `with`; rewrite to `{% set messages = get_flashed_messages(true) %}`.
2. **Tuple unpacking over arrays** — `{% for category, message in messages %}` base.html:102; `{% for is_public, domain in current_user.available_domains_for_random_alias() %}` dashboard/setting.html:169; `{% for scope, val in client_user.get_user_info().items() %}` dashboard/app.html:45; `{% for dkim_prefix, dkim_cname_value in dkim_records.items() %}` dashboard/domain_detail/dns.html:240 and :289; `{% for idx, x in y|enumerate %}` admin/abuser_lookup.html:46/74/103 (admin OUT of scope). Nunjucks only unpacks `k, v` over plain objects — for arrays-of-pairs rewrite to `{% for pair in messages %}{{ pair[0] }}…` or pass objects/dicts from the route.
3. **Python method calls on context objects** — every `current_user.X()` in §6.9; `request.cookies.get('dark-mode')` base.html:5; `.items()` calls above; arrow `.format("YYYY-MM-DD")` dashboard/setting.html:45/60/74, pricing.html:78/99, extend_subscription.html:10; datetime `.strftime("%Y-%m-%d")` dashboard/pricing.html:89, billing.html:15/33; `.upper()` dashboard/setting.html:156 (`AliasGeneratorEnum.uuid.name.upper()`). Stance: precompute in route context (view-model), never call methods in templates.
4. **`is none` / `is not none` / `is defined` tests** — dashboard/setting.html:299 (`current_user.include_sender_in_reverse_alias is none or …`), dashboard/account_setting.html:112 (`current_user.fido_uuid is none`), developer/client_details/referral.html:22, admin/domain_check.html:162, emails/base_sl.html:594 (`is defined`). `templates.ts` already registers a `none` test; Nunjucks has `defined` built in.
5. **Slicing** — `breached_aliases[:10]` / `breaches[:4]` emails/transactional/hibp-new-breaches.{txt.jinja2:6,10 / html:10,17} (email templates — handled by email worker, not web; noted for completeness).
6. **Filters**: used across templates — `length`(43×), `dt`(34×, custom), `safe`(29×), `join`(6×), `int`(admin only), `count`, `tojson`(3× — auth/fido.html:51, dashboard/enter_admin.html:45, dashboard/fido_setup.html:48; Nunjucks equivalent is `dump`), `sort(attribute='date', reverse=True)` (emails + admin; Nunjucks `sort` exists but the keyword-arg form differs — Nunjucks signature `sort(reverse, caseSens, attr)`), `enumerate` (custom). Register `tojson`→`dump` alias and keep `dt`/`enumerate` (already done in templates.ts).
7. **Parent-scope macro import invisible to child blocks** — base.html:1 (`render_field`), see §6.8 gotcha.
8. **Globals to provide**: `url_for(endpoint, **kwargs)` (incl. `_anchor`), `get_flashed_messages(with_categories=true)` (keyword-arg call — Nunjucks supports kwargs on functions; drain from KV session), `request` shim exposing `request.path`, `request.args.get(...)` (used widely in page templates), `request.cookies.get('dark-mode')` (base.html:5), `request.url` (some auth pages). Plus every §5.2 global.
9. **`{{ field(**kwargs) }}` splat** — _formhelpers.html:5 (no `**` in Nunjucks).
10. **Comparison of arrow objects** — base.html:89 `NOW.timestamp < 1701475201` fine if `NOW.timestamp` is a number; ensure the port's `NOW` mirrors arrow-0.16's *property* semantics (arrow ≥1.0 made it a method — do not "upgrade").
11. **Auto-escaping inside `<script>`** — base.html:102 flash messages are emitted into a JS string with HTML auto-escaping only. Nunjucks autoescape matches Jinja here; messages containing `"` become `&#34;` and render fine through toastr (which innerHTML-injects). Do not switch to JSON-encoding without checking message strings that intentionally contain HTML (several flashes include `<a href=…>` links and rely on this pipeline).

---

## 8. Flask-Login → session middleware

- **No `login_manager.login_view` is configured** (grep: only `session_protection = "strong"` is set, `app/extensions.py:8`). Therefore `@login_required` → `unauthorized()` → **`abort(401)`** → the app-level 401 handler (§4) does the actual flash + redirect to `/auth/login?next=<request.full_path>`. There is NO flask-login "Please log in" message — the string is `You need to login to see this page` (error), and `next` keeps the query string.
- **User loader** (`simplelogin_app.py:189-199`): `User.get_by(alternative_id=<session "_user_id">)`; returns anonymous when `user.disabled` or `not user.is_active()` (`delete_on` in the past... precisely: `is_active()` is False when `delete_on is not None and delete_on >= now`). Port middleware: load `user_id` from KV session (`session.ts getSession`), fetch user row, treat as anonymous if `disabled` or pending deletion. Because Flask keys the session on **`alternative_id`** (regenerated on password reset to kill other sessions), the KV session must ALSO store `alternative_id` and compare against the user row on each request (or delete all the user's KV sessions on password reset).
- **`login_user(user)`** always called without `remember=` — there is **no remember-me cookie** anywhere; persistence = the 7-day permanent session only. Flask-login session keys written: `_user_id` (= `user.get_id()` = `alternative_id`, falls back to `str(id)` when null), `_fresh=True`, `_id` (sha512 fingerprint of remote-addr+user-agent).
- **Session protection "strong" is effectively a NO-OP**: flask-login 0.5.0's check runs `if mode == "basic" or sess.permanent:` FIRST — since every session is permanent (§2), a fingerprint mismatch only sets `_fresh=False`, and nothing in the app uses freshness (`fresh_login_required`/`confirm_login`: zero occurrences). Port stance: skip fingerprinting entirely, document here.
- **Fresh-login semantics: none.** The sudo mechanism below replaces it.
- **`@sudo_required`** (`app/dashboard/views/enter_sudo.py:76-95`), gap `_SUDO_GAP = 120` seconds: if `session["sudo_time"]` missing or older than 120 s → stash pending flashes (`session["_preserved_flashes"] = session.pop("_flashes")`) and 302 `url_for("dashboard.enter_sudo", next=request.path)`. On a sudo-fresh request, `_preserved_flashes` are appended back onto `_flashes` (so a flash set just before a sudo interstitial survives it). `sudo_time` is granted by: `/dashboard/enter_sudo` POST success, password login (`after_login`), FIDO completion — NOT by TOTP/recovery login (web spec 01 §after_login). Cleared by `/internal/exit-sudo-mode` (sets 0). NOTE the API uses a different window: 5 min (`app/api/base.py SUDO_MODE_MINUTES_VALID`), and the API's session-sudo check reads the SAME `session["sudo_time"]` — web sudo also unlocks `require_api_sudo` endpoints for 5 min. The `/dashboard/enter_sudo` route itself (form, flash `Incorrect password` warning, proton/oidc buttons) is specced in web spec 04.
- **Redis session store** (`app/session.py`) — cookie `slapp` holds an itsdangerous-Signer-signed session id (`Signer(FLASK_SECRET, salt="session", key_derivation="hmac")`); pickled dict in Redis `session:<id>`; TTL 7 d authenticated / **300 s anonymous** (kept only for CSRF + flashes); HttpOnly, SameSite=Lax, Secure iff `URL` startswith https. Session-id rotation on login (`session.session_id = uuid4()`), `logout_session()` = logout + Redis delete + fresh id. **Port: replaced by `cloudflare/src/lib/session.ts`** (opaque KV token). Remaining deltas the web port must add to `session.ts` usage: store `alternative_id`; rotate token on login (new token + Set-Cookie, old key deleted or abandoned); the extra keys listed in web spec 01 (`mfa_user_id`, `slref`, `_preserved_flashes` equivalent, oauth state keys) go in `SessionData.extra`.

---

## 9. Flask-WTF CSRF (flask-wtf 0.14.3, wtforms 2.3.3)

- No global `CSRFProtect` — protection exists ONLY on views that instantiate a `FlaskForm` subclass and call `validate_on_submit()` / `form.validate()`. Views with bare POST handling and no form have **no CSRF check**; several use the empty `CSRFValidationForm(FlaskForm): pass` (`app/utils.py:163`) purely to get the csrf field (rendered as `{{ csrf_form.csrf_token }}`).
- Config: all defaults — `WTF_CSRF_ENABLED=True`, secret = `app.secret_key` = `FLASK_SECRET`, field/session key `csrf_token`, methods `{POST,PUT,PATCH,DELETE}`, **time limit 3600 s**.
- Token generation (`generate_csrf`): if `session["csrf_token"]` missing → `sha1(urandom(64)).hexdigest()`; the hidden-field value = `URLSafeTimedSerializer(FLASK_SECRET, salt="wtf-csrf-token").dumps(session["csrf_token"])`.
- Validation errors (exact strings, land in `form.csrf_token.errors`): `The CSRF token is missing.`, `The CSRF session token is missing.`, `The CSRF token has expired.`, `The CSRF token is invalid.`, `The CSRF tokens do not match.`
- On CSRF failure `validate_on_submit()` is just False → the view re-renders with **200** (no 400). Most templates don't render `csrf_token.errors`, so failure is silent (user sees the form again; sometimes a flash like `Invalid request` when the view checks `csrf_form.validate()` explicitly — those flashes are per-view, see group specs).
- FlaskForm reads the token from **form data only** (no header fallback — that's CSRFProtect-only). The htmx partial (`partials/toggle_contact.html:2`) therefore embeds `{{ csrf_form.csrf_token }}` inside the `hx-post` form and htmx serializes it as a normal field.
- Port: keep session-random + HMAC-token design against `SessionData.csrf` (already reserved in `session.ts`), 1 h expiry, same error strings, same "re-render 200" behavior. GOTCHA inherited from Flask: anonymous Redis sessions die after 300 s, so a login form left open >5 min fails CSRF silently — the KV port should either replicate (300 s anonymous TTL) or consciously fix.

---

## 10. flash()

- Categories in use (grep over `app/ simplelogin_app.py`): **error (150), warning (141), success (111), info (8)**. No other category is ever passed (the base.html:99 comment mentioning "danger" is stale — `toastr.danger` doesn't exist and would throw).
- Storage: `session["_flashes"]` (list of `(category, message)`), drained by `get_flashed_messages(with_categories=true)` on the NEXT render — messages must survive a redirect. Port: `SessionData.flashes` in KV (already defined); render drains and persists the emptied list.
- Rendering (base.html:98-104): NOT bootstrap alerts — each message becomes `<script>toastr.{{category}}("{{ message }}");</script>` inside `<div class="container">`. Mapping is 1:1 to toastr methods `toastr.success/error/warning/info`. `toastr.options.closeButton = true` globally (base.html:83).
- Interaction with sudo: `_preserved_flashes` shuffle in §8.
- Some flash messages contain raw HTML links (rendered via toastr's innerHTML) — do not double-escape beyond Jinja's standard autoescape.

---

## 11. Frontend JS inventory (must keep working against the port)

| File | Loaded from | Behavior the port must support |
|---|---|---|
| `static/js/theme.js` | base.html (head) | Dark mode: reads/writes cookie `dark-mode` (`true`/`false`, 30 d, `SameSite=Lax`, `Secure` on https, `domain=hostname`, path `/`), sets `document.documentElement data-theme`. Server side must keep reading this cookie (base.html:5). |
| `static/js/an.js` | base.html (body end, `?v=2`) | Plausible bootstrap — only runs when host ends with `simplelogin.io` and localStorage `analytics-ignore != 't'`; injects `/p.outbound.js` with `data-api=/p/api/event` (reverse-proxied on prod nginx — NOT a Worker concern; config-gate). |
| `static/local-storage-polyfill.js` | base.html + `/dnt` | `store.get/set` shim used by an.js, index.js filter toggles, `/dnt`. |
| `static/js/index.js` | dashboard index page | Alias toggles: `POST /api/aliases/{id}/toggle`, `PUT /api/aliases/{id}` (disable_pgp / pinned / note / name / mailbox_ids) — all with headers `Content-Type: application/json` + **`X-Sl-Allowcookies: allow`** (must match `constants.HEADER_ALLOW_API_COOKIES`; the ported API's cookie-auth path must accept this header — see `app/api/base.py authorize_request`). Toast strings: `${alias} is enabled` / `is disabled` / `PGP is enabled for ${alias}` (success) / `PGP is disabled for ${alias}` (info) / `${alias} is pinned` (success) / `is unpinned` (info) / `Description saved for ${email}` / `Display name saved for ${email}` / `Mailbox updated for ${email}` / error `You must select at least a mailbox` / generic `Sorry for the inconvenience! Could you refresh the page & retry please?` titled `Unknown Error`. Also the `#filter-app` Vue toggle persisting `showFilter`/`showStats` in localStorage. |
| `static/js/utils/drag-drop-into-text.js` | PGP textareas (mailbox detail etc.) | drag-drop `.asc/.pub/.pgp/.key` files into textarea, max 10 KiB, warn toast `File ${name} is not a public key file`. |
| footer.html inline Vue | every dashboard page | Notification bell: `GET /api/notifications?page=N`, `POST /api/notifications/{id}/read`, headers incl. `X-Sl-Allowcookies: allow` (§6.5). |
| base.html inline | everywhere | toastr defaults, bootbox defaults, ClipboardJS `.clipboard` (+ `Copied to clipboard` toast), `.back-or-close`, htmx `htmx:responseError` global toast. |
| `static/assets/js/core.js` | everywhere | Tabler UI glue (tooltips, dropdowns) — no network calls. |

**htmx usage**: htmx.min.js is loaded globally; the only `hx-*` markup is `templates/partials/toggle_contact.html` — `hx-post="{{ url_for('dashboard.toggle_contact', contact_id=contact.id) }}" hx-swap="outerHTML"` with embedded csrf field; the endpoint returns the same partial re-rendered (and `{% if toast_msg %}<script>toastr.success("{{ toast_msg }}")</script>{% endif %}`). Details in web spec 02. The infra requirement: partial templates must be renderable standalone (no base.html), and non-2xx responses trigger the global error toast.

**bootbox usage pattern**: page templates call `bootbox.confirm({message, buttons, callback})` before destructive form submits (delete alias/mailbox/domain/account etc. — enumerated in group specs). Infra only guarantees bootbox + its defaults are loaded.

**Parsley**: form validation via `data-parsley-*` attributes in page templates (client-side only; server re-validates).

---

## 12. BLOCKER entries (external dependencies touched by this group)

| # | Feature | Flask behavior | Port stance |
|---|---|---|---|
| B1 | **Redis sessions + flashes** (`app/session.py`, `MEM_STORE_URI`) | server-side pickled session in Redis | REPLACE with KV (`session.ts`) — done; extend per §8 |
| B2 | **Redis rate-limit storage** (flask-limiter `storage_url`) | fixed-window counters in Redis | REPLACE — `ratelimit.ts` D1 windows (exists) |
| B3 | **Sentry** (backend + `SENTRY_FRONT_END_DSN` browser bundle, base.html:57,109-159) | error reporting; browser init gated on `SENTRY_DSN` global | config-gate exactly like Flask: omit `<script>` when unset |
| B4 | **Plausible** (base.html:72-76, an.js) | analytics, gated on `PLAUSIBLE_HOST and PLAUSIBLE_DOMAIN` / prod hostname | config-gate; default off |
| B5 | **Paddle webhooks** `/paddle`, `/paddle_coupon` (`app/payments/paddle.py`) + `static/vendor/paddle.js` on pricing page | subscription lifecycle | DEFER — 404/501; pricing/billing pages spec'd in group 05 |
| B6 | **Zendesk** (`ZENDESK_ENABLED` presence flag) | gates Help dropdown + `/dashboard/support` page | config-gate identically (nav renders Docs-only when off) |
| B7 | **S3 profile pictures** (`current_user.profile_picture_url()`, header.html:127) | S3 GET url for `profile_picture_id` | config-gate: when no S3 binding, always render initials fallback (`profile_picture_id` is only settable via unported Google/Facebook login, so field is null for port-created users) |
| B8 | **OIDC provider metadata** `/jwks` (+ `/.well-known/openid-configuration`) | RSA JWK from `OPENID_PRIVATE_KEY_PATH` | DEFER with oauth blueprint; metadata JSON itself is static if kept |
| B9 | **flask-admin `/admin`** + flask-profiler | ops UIs | OUT of scope; `/admin` nav link only shows for `is_admin` — keep link pointing at unported path |
| B10 | **NewRelic/monitoring** (`after_request`, `/exception`) | custom events | drop; Workers observability |
| B11 | **npm `static/node_modules`** | served from disk after `npm install` in `static/` | build step: `npm ci` + upload to Workers Assets (11 packages, §6.2) |

---

## 13. Gotchas rollup (things that WILL bite the port)

1. `strict_slashes=False` app-wide (§1).
2. 401-handler funnel supplies the `?next=` behavior for every `@login_required` page; `next` = `request.full_path` (keeps `?`); it is sanitized on the login side by `sanitize_next_url` (web spec 01).
3. `?slref=` capture on ANY route writes to the session (§2) — a GET side effect on every endpoint.
4. `/internal/exit-sudo-mode` and `/auth/logout` are GETs with side effects.
5. Jinja evaluates inside HTML comments — `menu.html:38` needs `discover.index` in the urlFor map (§6.6).
6. `data-theme=" dark"` leading-space bug + theme.js rescue (§6.2); Plausible curly-quote bug base.html:75.
7. Parent-template macro import (`render_field`) implicitly global (§6.8/§7.7).
8. Flash categories map to toastr method NAMES — an unknown category is a client-side crash (§10).
9. `sudo_time` shared between web (120 s) and API (5 min) checks (§8).
10. Session protection "strong" is dead code due to permanent sessions — don't port fingerprinting (§8).
11. Anonymous-session 300 s TTL silently breaks CSRF on slow form fills (§9).
12. Error pages render through base.html → need anonymous `current_user` + flash drain even on 4xx (§4).
13. `NOW.timestamp` is arrow-0.16 property semantics (number) (§7.10).
14. Black-Friday banner (base.html:89) is time-dead but forces context keys; keep or strip consciously.
15. The two oauth prefixes (`/oauth` AND `/oauth2`) both exist; openid metadata advertises `/oauth2/*` (§1, §3.5).
16. `X-Sl-Allowcookies: allow` header is the ONLY thing letting the browser JS use cookie-auth against `/api/*` — the ported API must honor it for same-origin fetches (`app/api/base.py:25-28`), and CORS must NOT reflect it cross-origin.
