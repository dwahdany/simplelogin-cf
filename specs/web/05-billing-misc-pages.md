# Web Spec 05 — Billing + misc pages

Server-rendered pages of the `dashboard` blueprint (`url_prefix="/dashboard"`) covering Paddle
billing management, the pricing/upgrade page, coupon & lifetime-licence redemption, referrals,
Zendesk support, "Sign in with SimpleLogin" authorized apps, the `setup_done` extension cookie and
the admin FIDO gate.

Source files (authoritative):
- `app/dashboard/views/billing.py`
- `app/dashboard/views/pricing.py` (also `subscription_success`)
- `app/dashboard/views/coupon.py`
- `app/dashboard/views/lifetime_licence.py`
- `app/dashboard/views/referral.py`
- `app/dashboard/views/support.py`
- `app/dashboard/views/app.py`
- `app/dashboard/views/setup_done.py`
- `app/dashboard/views/enter_admin.py`
- Helpers: `app/coupon_utils.py` (`redeem_coupon`, `redeem_lifetime_coupon`,
  `CouponUserCannotRedeemError`), `app/paddle_utils.py` (`cancel_subscription`, `change_plan`),
  `app/proton/proton_partner.py` (`get_proton_partner`), `app/utils.py` (`CSRFValidationForm`,
  `sanitize_next_url`)
- Templates (`templates/dashboard/`): `billing.html`, `pricing.html`, `thank-you.html`,
  `coupon.html`, `lifetime_licence.html`, `referral.html`, `support.html`, `app.html`,
  `enter_admin.html`

There is no shared `app/dashboard/views/__init__` logic beyond importing every view module (side
effect: route registration); `app/dashboard/base.py` only declares
`Blueprint(name="dashboard", url_prefix="/dashboard", template_folder="templates")`.

Existing API-port correspondences (do NOT re-describe / reuse):
- Subscription-activity semantics (`get_paddle_subscription` 14-day grace, Apple 16-day grace,
  Manual/Coinbase `end_at > now`, Partner `lifetime OR end_at > now-14d`, `get_active_subscription`
  precedence Paddle → Apple → Manual → Coinbase → Partner) →
  `cloudflare/src/lib/models.ts` (`paddleActive`, `appleValid`, `manualActive`, `coinbaseActive`,
  `partnerActive`, `loadSubscriptions`) — reuse, don't reimplement.
- Session / flash / CSRF (`CSRFValidationForm`) / `@login_required` 401→login redirect / error
  pages / `dt` filter / `render_field_errors` macro / context-processor globals → web spec 02 §0
  (shared web infrastructure). This spec only documents deltas.
- Rate limiting (keyed `userid:{id}` when logged in, `ip:{addr}` otherwise; `DISABLE_RATE_LIMIT`
  bypass; `deduct_when` flag) → `cloudflare/src/lib/ratelimit.ts` + web spec 01 blockers table.
- `sanitize_next_url` (`ALLOWED_REDIRECT_DOMAINS`) → web spec 01 (auth pages) — same helper.
- `emit_user_audit_log` / `EventDispatcher` partner events: the API port skips both (no
  `user_audit_log` table in D1, no event system) — same stance here; noted per-route.

`app.url_map.strict_slashes = False` — every path also matches with a trailing slash.

---

## Route inventory (10 routes)

| # | Methods | Path (full) | Endpoint (`url_for`) | Auth | Rate limit / lock |
|---|---------|-------------|----------------------|------|-------------------|
| 1 | GET, POST | `/dashboard/billing` | `dashboard.billing` | `@login_required` | none |
| 2 | GET, POST | `/dashboard/pricing` | `dashboard.pricing` | `@login_required` | none (POST is accepted but there is **no POST branch** — a POST just renders like GET) |
| 3 | GET | `/dashboard/subscription_success` | `dashboard.subscription_success` | `@login_required` | none |
| 4 | GET, POST | `/dashboard/coupon` | `dashboard.coupon_route` | `@login_required` | `parallel_limiter.lock()` (Redis lock keyed by user+endpoint, held on GET too) |
| 5 | GET, POST | `/dashboard/lifetime_licence` | `dashboard.lifetime_licence` | `@login_required` | `parallel_limiter.lock()` |
| 6 | GET, POST | `/dashboard/referral` | `dashboard.referral_route` | `@login_required` | none |
| 7 | GET, POST | `/dashboard/support` | `dashboard.support_route` | `@login_required` | `2/hour` POST only, **`deduct_when=g.deduct_limit`** — only *successful* ticket creations count |
| 8 | GET, POST | `/dashboard/app` | `dashboard.app_route` | `@login_required` | none |
| 9 | GET, POST | `/dashboard/setup_done` | `dashboard.setup_done` | `@login_required` | none |
| 10 | GET, POST | `/dashboard/enter_admin` | `dashboard.enter_admin` | `@login_required` | `10/minute` (all methods) — **BLOCKER: WebAuthn** |

Decorator-order gotcha on route 10: source order is `@route` → `@limiter.limit("10/minute")` →
`@login_required`, i.e. the **limiter wraps `login_required`** — anonymous requests are counted
(keyed by IP) and can 429 *before* the login redirect fires.

`parallel_limiter.lock()` (routes 4, 5) is a Redis mutex (max wait 5 s) preventing the same user
from running the endpoint concurrently (double-submit coupon redemption). Port stance: the
D1 coupon redemption below is a single atomic conditional `UPDATE`, which already guarantees
at-most-once semantics — the lock can be **dropped** (document in code comment), same stance web
spec 02 takes for `alias_creation`.

---

## 1. GET|POST `/dashboard/billing` (`dashboard.billing`)

`@login_required`. Manages an existing **Paddle** subscription.

### Common guard (both methods, runs first)

`sub = current_user.get_paddle_subscription()` (active-within-14-day-grace Paddle row, see
`lib/models.ts::paddleActive`). If `None`:
- flash `"You don't have any active subscription"` (**warning**), `302 → dashboard.index`.

Form: `CSRFValidationForm` (empty CSRF-only form; template emits `{{ csrf_form.csrf_token }}`).

### POST behavior

1. `if not csrf_form.validate()`: flash `"Invalid request"` (**warning**),
   `302 → redirect(request.url)` (same URL **including query string**, not a named endpoint).
2. Dispatch on hidden `form-name`:

| `form-name` | Action | Success | Failure |
|---|---|---|---|
| `cancel` | `paddle_utils.cancel_subscription(sub.subscription_id)` — POST `https://vendors.paddle.com/api/2.0/subscription/users_cancel` with `vendor_id=PADDLE_VENDOR_ID`, `vendor_auth_code=PADDLE_AUTH_CODE`, `subscription_id` | `UPDATE subscription SET cancelled=1` + commit; flash `"Your subscription has been canceled successfully"` (**success**) | flash `"Something went wrong, sorry for the inconvenience. Please retry. We are already notified and will be on it asap"` (**error**); **no DB change** |
| `change-monthly` | `paddle_utils.change_plan(user, sub.subscription_id, PADDLE_MONTHLY_PRODUCT_ID)` — POST `https://vendors.paddle.com/api/2.0/subscription/users/update` | `UPDATE subscription SET plan='monthly'` + commit; flash `"Your subscription has been updated"` (**success**) | if Paddle error code **147**: flash `"Your card cannot be charged"` (**error**); any other error: flash the same generic `"Something went wrong, …asap"` (**error**) |
| `change-yearly` | same with `PADDLE_YEARLY_PRODUCT_ID` | `plan='yearly'`, same strings | same strings |
| anything else | falls through to the GET render (200) | | |

All three named branches end `302 → url_for("dashboard.billing")` regardless of success/failure.

### GET behavior

`render_template("dashboard/billing.html", sub=sub, PlanEnum=PlanEnum, csrf_form=csrf_form)`.

### Template `dashboard/billing.html`

- Extends `default.html`; title `Billing`; empty `head` block; blocks `default_content`, `script`.
- Branches on `sub.cancelled`:
  - cancelled: shows plan name + `sub.next_bill_date.strftime("%Y-%m-%d")` end date, and a
    Re-subscribe button → `url_for("dashboard.pricing")`.
  - active: "Update billing information" external link `href="{{ sub.update_url }}"` (Paddle-hosted
    URL stored on the row); "Change Plan" form — shows `change-monthly` when
    `sub.plan == PlanEnum.yearly`, else `change-yearly`; "Cancel subscription" form
    (`form-name=cancel`) triggered via bootbox confirm
    (`"This operation is irreversible, please confirm."`).
- Data accessed: `sub.cancelled`, `sub.plan_name()` (**method call**: `"Monthly"` if
  `plan == monthly` else `"Yearly"` — precompute for Nunjucks), `sub.next_bill_date.strftime(...)`
  (**Python date method** — precompute the `YYYY-MM-DD` string), `sub.update_url`, `sub.plan`,
  `PlanEnum` comparison (PG enum stored by name; D1 `subscription.plan` is `'monthly'|'yearly'` —
  compare strings).
- `csrf_token` via `{{ csrf_form.csrf_token }}`; `url_for`: `dashboard.pricing`. jQuery/bootbox in
  `script` block.

---

## 2. GET|POST `/dashboard/pricing` (`dashboard.pricing`)

`@login_required`. Route accepts POST but the view has no POST logic — POST renders identically.

### Redirect guards (in order)

1. `current_user.lifetime` → flash `"You already have a lifetime subscription"` (**error**),
   `302 → dashboard.index`.
2. `paddle_sub = current_user.get_paddle_subscription()`; if it exists **and not
   `paddle_sub.cancelled`** → flash `"You already have an active subscription"` (**error**),
   `302 → dashboard.index`. (A *cancelled but still in paid period* sub may re-subscribe.)
3. Partner check: `partner_user = PartnerUser.get_by(user_id)`; if exists and its
   `PartnerSubscription.is_active()` → flash
   `f"You already have a subscription provided by {partner_user.partner.name}"` (**error**),
   `302 → dashboard.index`.

### Non-redirecting flash

`apple_sub = AppleSubscription.get_by(user_id)`; if valid (16-day grace) → flash
`"Please make sure to cancel your subscription on Apple first"` (**warning**) and **continue
rendering** the page.

### `proton_upgrade` flag

Only computed when `partner_user` exists (and its partner sub is not active):
`proton_upgrade = partner_user.partner_id == get_proton_partner().id`.
`get_proton_partner()` = lookup `partner` row with `name = 'Proton'` (module-cached);
**raises `ProtonPartnerNotSetUp` → 500** if no such row exists. Port: same lookup against D1
`partner` table; treat "no Proton partner row" as `proton_upgrade = false` (or replicate the 500 —
recommend the graceful false since a Workers deployment may not seed partners).

### Render context

```python
render_template("dashboard/pricing.html",
    PADDLE_VENDOR_ID=..., PADDLE_MONTHLY_PRODUCT_ID=..., PADDLE_YEARLY_PRODUCT_ID=...,
    success_url=URL + "/dashboard/subscription_success",
    manual_sub=manual_sub,        # ManualSubscription with end_at > now, else None
    coinbase_sub=coinbase_sub,    # CoinbaseSubscription with end_at > now, else None
    now=now,                      # arrow.now() captured once
    proton_upgrade=proton_upgrade)
```

### What renders WITHOUT Paddle credentials (BLOCKER detail)

Flask has **no config gate** on this page. When the `PADDLE_VENDOR_ID` /
`PADDLE_MONTHLY_PRODUCT_ID` / `PADDLE_YEARLY_PRODUCT_ID` env vars are absent, `app/config.py` sets
all three to **`-1`** (ints, not None) and the page still renders fully: the template emits
`Paddle.Setup({vendor: -1});` and `onclick="upgradePaddle(-1)"` — the upgrade buttons exist but
the Paddle checkout fails client-side. The only true gate is the *navbar*: the "Upgrade" button in
`header.html` shows iff `current_user.should_show_upgrade_button()` (base-layout concern). Port:
replicate — render the page with `-1` defaults; optionally hide the checkout buttons when vendor id
is `-1` (deviation, mark in code).

### Template `dashboard/pricing.html`

- Extends `default.html`; `{% set active_page = "dashboard" %}`; title `Pricing`; blocks `head`
  (loads `https://cdn.paddle.com/paddle/paddle.js` with local fallback
  `/static/vendor/paddle.js` via `document.write`), `announcement` (emptied), `default_content`.
- **`{% if NOW.timestamp < 1733184000 %}`** — Black-Friday banner using the context-processor
  global `NOW` (`arrow.now()` per request). Cutoff = 2024-12-03; permanently false now — port can
  drop the block or keep the constant comparison (`Date.now()/1000 < 1733184000`).
- `manual_sub` box: `manual_sub.end_at.format("YYYY-MM-DD")` (**arrow** `.format`, not strftime)
  and `(manual_sub.end_at - now).days` (timedelta days) — precompute both.
- `{% set sub = current_user.get_paddle_subscription() %}` — **template calls a DB-touching method
  on `current_user`** (twice: once for the cancelled-sub alert, once per free-plan card for the
  `invisible` class). Port MUST precompute and pass `sub` (the view already fetched `paddle_sub`;
  pass it through). Uses `sub.cancelled`, `sub.next_bill_date.strftime("%Y-%m-%d")`.
- `coinbase_sub` box: `.end_at.format("YYYY-MM-DD")`, `(coinbase_sub.end_at - now).days`.
- Free-plan "Current plan" button gets class `invisible` if `sub or manual_sub or coinbase_sub`.
- Proton cards (monthly + yearly) render iff `proton_upgrade`; column classes switch
  `col-md-6 col-lg-4` vs `col-md-6` on `proton_upgrade`.
- Upgrade buttons: `onclick="upgradePaddle({{ PADDLE_MONTHLY_PRODUCT_ID }})"` /
  `{{ PADDLE_YEARLY_PRODUCT_ID }}`; inline script:
  `Paddle.Setup({vendor: {{ PADDLE_VENDOR_ID }}})`, checkout `success: "{{ success_url }}"`,
  `passthrough: "{\"user_id\": {{current_user.id}} }"` — `current_user.id` accessed in template.
- Static FAQ accordion (pure HTML); `url_for` references: `dashboard.coupon_route` (FAQ link).
  External links only otherwise.
- Prices/features are hardcoded strings ($4 / month, $36 / year, "Save $18", 10 aliases, etc.).

---

## 3. GET `/dashboard/subscription_success` (`dashboard.subscription_success`)

`@login_required`. No logic: `render_template("dashboard/thank-you.html")` (no extra context).
This is the Paddle checkout `success_url` target.

### Template `dashboard/thank-you.html`

Extends **`single.html`** (the navbar-less single-card layout used by auth pages — web spec 01);
`{% set active_page = "dashboard" %}`; title `Thank you`; block `single_content`. Static copy:
heading `Thanks so much for supporting SimpleLogin!`, close button `href="/"`. No dynamic data,
no CSRF.

---

## 4. GET|POST `/dashboard/coupon` (`dashboard.coupon_route`)

`@login_required`, `@parallel_limiter.lock()`.

Form `CouponForm(FlaskForm)`:
- `code = StringField("Coupon Code", validators=[DataRequired()])` — error string
  `"This field is required."` (rendered by `render_field_errors(coupon_form.code)`).

### POST behavior (order matters)

1. `validate_on_submit()` (CSRF + DataRequired). On CSRF/validation failure: **no flash**, falls
   through to render (200) — the field error shows under the input; CSRF errors are silent (web
   spec 01 §CSRF gotcha).
2. **Lifetime-code sniff (before anything else):** if `LifetimeCoupon.get_by(code=code)` exists →
   flash `"Redirect to the lifetime coupon page instead"` (**success**),
   `302 → dashboard.lifetime_licence`. (GET-side note: this check does NOT redeem.)
3. Compute `can_use_coupon` (also computed on GET, see below).
4. Re-run `validate_on_submit()` (same result — quirk of the code, harmless) and call
   `coupon_utils.redeem_coupon(code, current_user)`:
   - returns a Coupon → flash
     `"Your account has been upgraded to Premium, thanks for your support!"` (**success**);
   - returns `None` → flash
     `"This coupon cannot be redeemed. It's invalid or has expired"` (**warning**);
   - raises `CouponUserCannotRedeemError` → flash
     `"You have an active subscription. Please remove it before redeeming a coupon"` (**warning**).
5. **No redirect** — falls through to the same render as GET (flash shows on the re-rendered page;
   browser refresh re-posts). GOTCHA: the redeem branch is **not** gated by `can_use_coupon`
   (the template merely hides the form); `redeem_coupon` enforces eligibility itself.

### `redeem_coupon(code, user)` — DB side effects (needs new D1 table `coupon`)

1. Raise `CouponUserCannotRedeemError` if `user.lifetime`.
2. `sub = user.get_active_subscription()` (Paddle→Apple→Manual→Coinbase→Partner). If `sub` exists
   and is **not** a ManualSubscription → raise `CouponUserCannotRedeemError`.
3. `SELECT * FROM coupon WHERE code = ?` — missing → return None.
4. Atomic redeem:
   `UPDATE coupon SET used=1, used_by_user_id=?, updated_at=now WHERE code=? AND used=0 AND (expires_date IS NULL OR expires_date > now)`
   — `rowcount == 0` → return None (already used / expired).
5. Extend/create manual subscription (`manual_subscription` table, exists in D1):
   - active ManualSubscription (`sub` from step 2): `end_at = end_at + nb_year years`;
   - else if an (expired) `manual_subscription` row exists: `end_at = now + nb_year years + 1 day`;
   - else INSERT `manual_subscription(user_id, end_at = now + nb_year years + 1 day,
     comment='using coupon code', is_giveaway=coupon.is_giveaway)`.
6. `emit_user_audit_log(Upgrade, f"User {user} redeemed coupon {coupon.id} for {coupon.nb_year} years")`
   + `EventDispatcher(UserPlanChanged(plan_end_time=sub.end_at.timestamp))` — **skip in port**
   (no audit table / event system, same as API port). Commit; return coupon.

### GET behavior / `can_use_coupon`

```python
can_use_coupon = True
if current_user.lifetime: can_use_coupon = False
if current_user.get_paddle_subscription(): can_use_coupon = False           # even if cancelled
apple_sub valid (16d grace)               → can_use_coupon = False
coinbase_sub = CoinbaseSubscription.get_by(user_id)                          # NO end_at filter
if coinbase_sub and coinbase_sub.end_at > now + 30 days: can_use_coupon = False
# (coinbase users may redeem within 30 days of expiry — deliberate)
```

Context:
`coupon_form`, `PADDLE_VENDOR_ID`, `PADDLE_COUPON_ID`, `can_use_coupon`,
`max_coupon_date = arrow.now().shift(years=1, days=-1)`.

### Template `dashboard/coupon.html`

- Extends `default.html`; `active_page = "dashboard"`; title `Coupon`; blocks `head` (Paddle CDN
  JS + fallback, same as pricing), `default_content`, `script`
  (`Paddle.Setup({vendor: {{PADDLE_VENDOR_ID }} })`).
- Redeem card rendered only `{% if can_use_coupon %}`: form POSTs `code`, emits
  `{{ coupon_form.csrf_token }}`, `render_field_errors(coupon_form.code)`, placeholder
  `Coupon Code`, button `Apply`.
- "1-year coupon" buy card renders **unconditionally**: alert
  `The coupon must be used before {{ max_coupon_date.date().isoformat() }}` (precompute the ISO
  date string), Paddle buy link
  `<a class="paddle_button …" data-product="{{ PADDLE_COUPON_ID }}">Buy 1-year SimpleLogin coupon</a>`.
  **Without config:** `PADDLE_COUPON_ID = os.environ.get(...)` → `None` → Jinja renders
  `data-product="None"` (broken button, page still 200). Port: same render; optionally hide the
  buy card when unset (deviation, mark in code).

---

## 5. GET|POST `/dashboard/lifetime_licence` (`dashboard.lifetime_licence`)

`@login_required`, `@parallel_limiter.lock()`.

Form `CouponForm(FlaskForm)` (own copy, identical): `code = StringField("Coupon Code",
validators=[DataRequired()])`.

### Redirect guards (both methods)

1. `current_user.lifetime` → flash `"You already have a lifetime licence"` (**warning**),
   `302 → dashboard.index`.
2. `sub = current_user.get_paddle_subscription()`; if exists and not cancelled → flash
   `"Please cancel your current subscription first"` (**warning**), `302 → dashboard.index`.

### POST behavior

`validate_on_submit()` then `redeem_lifetime_coupon(code, current_user)`:
- returns coupon → flash `"You are upgraded to lifetime premium!"` (**success**),
  `302 → dashboard.index`;
- returns None → flash `"Coupon code expired or invalid"` (**warning**), fall through to render
  (200, no redirect).

### `redeem_lifetime_coupon(code, user)` — DB side effects (`lifetime_coupon` table exists in D1)

1. Return None if `user.lifetime`.
2. Return None if a `partner_subscription` row with `lifetime = 1` exists for the user (join via
   `partner_user`).
3. `SELECT` lifetime_coupon by code — missing → None.
4. Atomic: `UPDATE lifetime_coupon SET nb_used = nb_used - 1 WHERE code = ? AND nb_used > 0` —
   `rowcount == 0` → None.
5. `UPDATE users SET lifetime = 1, lifetime_coupon_id = <coupon.id>` and, if `coupon.paid`,
   `paid_lifetime = 1`. Commit.
6. `EventDispatcher(UserPlanChanged(lifetime=True))` — skip in port.
7. **Email to admin**: `send_email(ADMIN_EMAIL, subject=f"User {user} used lifetime
   coupon({coupon.comment}). Coupon nb_used: {coupon.nb_used}", plaintext="", html="")` —
   `{user}` is the User `__str__`; `nb_used` is the *post-decrement* value. Port: send via
   `lib/mailer.ts` only when an admin address is configured; otherwise skip (config-gate).

### GET behavior

`render_template("dashboard/lifetime_licence.html", coupon_form=coupon_form)`.

### Template `dashboard/lifetime_licence.html`

Extends `default.html`; `active_page = "dashboard"`; title `Lifetime Licence`. Single card, form
with `{{ coupon_form.csrf_token }}`, `code` input placeholder `Licence Code`,
`render_field_errors(coupon_form.code)`, button `Apply`. No other dynamic data.

---

## 6. GET|POST `/dashboard/referral` (`dashboard.referral_route`)

`@login_required`. **No wtforms / NO CSRF protection on any branch** (raw `request.form`) —
faithful port keeps CSRF-less POSTs; recommended deviation: require the session CSRF token and
mark the deviation in code.

Referral code pattern: `_REFERRAL_PATTERN = r"[0-9a-z-_]{3,}"` matched with `re2.fullmatch`.

### POST dispatch on `form-name`

- **`create`** (fields `code`, `name`):
  1. Pattern mismatch → flash `"At least 3 characters. Only lowercase letters, numbers, dashes (-)
     and underscores (_) are currently supported."` (**error**),
     `302 → dashboard.referral_route`.
     GOTCHA: a missing `code` field makes `re.fullmatch(pattern, None)` raise TypeError → **500**
     in Flask. Port: treat missing as `""` → pattern-mismatch flash (deviation, or replicate 500).
  2. `Referral.get_by(code=code)` exists (any user's) → flash `"Code already used"` (**error**),
     `302 → dashboard.referral_route`.
  3. INSERT `referral(user_id, code, name)` (name may be NULL), commit, flash
     `"A new referral code has been created"` (**success**),
     `302 → url_for("dashboard.referral_route", highlight_id=referral.id)`
     (i.e. `/dashboard/referral?highlight_id=<id>`).
- **`update`** (fields `referral-id`, `name`): load `Referral.get(referral_id)`; if it exists AND
  `referral.user_id == current_user.id`: `UPDATE referral SET name = ?`, commit, flash
  `"Referral name updated"` (**success**), `302 → referral_route?highlight_id=<id>`.
  Otherwise (missing/foreign row): **no flash, no redirect — falls through to GET render (200)**.
- **`delete`** (field `referral-id`): same ownership check; on success DELETE row
  (`users.referral_id` FK is ON DELETE SET NULL — referred users keep their account), commit,
  flash `"Referral deleted"` (**success**), `302 → dashboard.referral_route`. Missing/foreign →
  fall through to GET render.
- Unknown `form-name` → GET render.

### GET behavior

- `highlight_id = request.args.get("highlight_id")`; if present, `int(highlight_id)` —
  **ValueError → 500** on non-numeric (port: parse-or-ignore recommended, mark deviation).
- `referrals = Referral.filter_by(user_id=current_user.id).all()` (no explicit ORDER BY — port:
  `ORDER BY id` for determinism).
- Move the highlighted referral to the front: find its index; `if highlight_index:` (index 0 is
  falsy — harmless, already first) then `referrals.insert(0, referrals.pop(highlight_index))`.
- `payouts = Payout.filter_by(user_id=current_user.id).all()` — **`payout` table missing from D1**
  (see §11); add it or always pass `[]`.
- `render_template("dashboard/referral.html", **locals())` — GOTCHA: passes *every* local
  (`referrals`, `payouts`, `highlight_id`, `highlight_index`, leaked loop vars `ix`/`referral`,
  and on the fall-through-after-POST paths also `code`/`name`/`referral_id`). The template only
  uses `referrals`, `highlight_id`, `payouts` — port passes exactly those three.

### Template `dashboard/referral.html`

- Extends `default.html`; title `Referral`; **`{% set active_page = "setting" %}`** (settings nav
  highlighted, not dashboard); blocks `default_content`, `script` (bootbox delete confirm:
  `"This operation is irreversible, please confirm."` / buttons `Yes, delete it` / `Cancel`).
- Empty state (`referrals|length == 0`): info alert `You don't have any referral code yet. Let's
  create the first one and start inviting your friends!`.
- Per referral card: class `highlight-row` iff `referral.id == highlight_id` (int compare —
  that's why the view int()s the query param); inline update form (hidden `form-name=update`,
  `referral-id`, text input `name` prefilled `{{ referral.name or '' }}`, button `Update` — **no
  csrf_token in the form**); stats block if `referral.nb_user > 0` with singular/plural
  person/people copy using `referral.nb_user` and `referral.nb_paid_user`; referral link input +
  clipboard button with `referral.link()`; code display + `?slref={{ referral.code }}` snippet;
  delete form (hidden `form-name=delete`, `referral-id`, styled span `Delete`).
- **Computed properties to precompute in the port** (N+1 in Flask):
  - `referral.nb_user` = `SELECT COUNT(*) FROM users WHERE referral_id = ? AND activated = 1`;
  - `referral.nb_paid_user` = count of those users that are "paid" (`User.is_paid()` — an active
    non-trial paid plan; reuse `lib/models.ts` premium helpers per user);
  - `referral.link()` = `f"{LANDING_PAGE_URL}?slref={code}"` (`LANDING_PAGE_URL` default
    `https://simplelogin.io`).
- Create form: inputs `code` (client-side `pattern="[0-9a-z-_]{3,}"`, `title` = same string as the
  server flash) and `name` (required client-side), button `Create`, hidden `form-name=create`.
- Payout table rendered iff `payouts|length > 0`: columns `Sent at` (`payout.created_at | dt` —
  humanized filter), `Amount` (`${{ payout.amount }}`), `Payment Method`
  (`payout.payment_method`), `Number of upgraded accounts` (`payout.number_upgraded_account`).
- No `csrf_token` anywhere; `url_for`: none (mailto link only).

---

## 7. GET|POST `/dashboard/support` (`dashboard.support_route`) — BLOCKER: Zendesk

`@login_required`,
`@limiter.limit("2/hour", methods=["POST"], deduct_when=lambda r: hasattr(g,"deduct_limit") and g.deduct_limit)`
— POSTs only *deduct* from the 2/hour budget when the handler sets `g.deduct_limit = True`
(i.e. only successful ticket creation; failed validation/Zendesk errors are free). The **check**
still happens on every POST once the budget is exhausted → 429 `error/429.html`.
`lib/ratelimit.ts` already models `deduct_when`.

### Config gates (both methods, in order)

1. `if not config.ZENDESK_HOST` → flash `"Support isn't enabled"` (**error**),
   `302 → dashboard.index`. (Nav-level: the "Help" menu in `header.html`/`menu.html` shows iff
   `ZENDESK_ENABLED` = env-var *presence*; the route itself gates on `ZENDESK_HOST`.)
2. `if config.PARTNER_SUPPORT_URL is not None` and the user has a `partner_user` row →
   `302 → PARTNER_SUPPORT_URL` (external redirect, no flash).

### POST behavior (multipart form: `ticket_content`, `ticket_email`, files `ticket_files[]`)

1. `not content` → flash `"Please add a description"` (**error**), re-render
   `dashboard/support.html` with context `ticket_email=email` (200).
2. `not email` → flash `"Please provide an email address"` (**error**), re-render with
   `ticket_content=content` (200).
3. `create_zendesk_request(email, content, files)`:
   - Files with empty `filename` are skipped. Each other file is uploaded to
     `https://{ZENDESK_HOST}/api/v2/uploads?filename=...` (basic auth `{email}/token`:
     `ZENDESK_API_TOKEN`, body = file stream, content-type = file mimetype), collecting upload
     tokens. Mime gate: allowed iff mimetype in `["text/plain", "message/rfc822"]` or startswith
     `image/`; otherwise flash `"File {filename} is not an image, text or an email"` (**warning**)
     and the whole request fails.
   - Then POST `https://{ZENDESK_HOST}/api/v2/requests.json` with JSON
     `{"request": {"subject": "Ticket created for user {user_id}", "comment": {"type": "Comment",
     "body": content, "uploads": tokens}, "requester": {"name": "SimpleLogin user {user_id}",
     "email": email}}}`. Success iff HTTP 201.
4. Failure → flash `"Cannot create a Zendesk ticket, sorry for the inconvenience! Please retry
   later."` (**error**), re-render with `ticket_email=email, ticket_content=content` (200).
5. Success → `g.deduct_limit = True` (rate-limit deduction), flash
   `"Support ticket is created. You will receive an email about its status."` (**success**),
   `302 → dashboard.index`.

### GET behavior

`render_template("dashboard/support.html", ticket_email=current_user.email)`.

### Template `dashboard/support.html`

- Extends `default.html`; `active_page = "dashboard"`; title `Support`; blocks `default_content`,
  `script`.
- `url_for` referenced: **`dashboard.notifications_route`** (web spec 04 route 14) in the info
  alert.
- Form `enctype="multipart/form-data"`, **no csrf_token** (raw form POST — same stance note as §6).
  Textarea `ticket_content` prefilled `{{- ticket_content or '' -}}` (whitespace-trimmed); file
  input `ticket_files` multiple; email input `ticket_email` bound to a Vue instance
  (`v-model='ticket_email'`, initial data `'{{ ticket_email }}'`).
- "Generate a random alias" button calls `POST /api/alias/random/new` with request header
  `'{{HEADER_ALLOW_API_COOKIES}}': 'allow'` — the context-processor global
  `HEADER_ALLOW_API_COOKIES = "X-Sl-Allowcookies"` (API port already supports cookie-auth'd API
  calls with this header). Client-side toasts: 429 →
  `"You've created too many aliases recently. Wait a bit before creating more"`, other errors →
  `"You can't create more aliases"`.
- jQuery file-label updater in `script` block.

---

## 8. GET|POST `/dashboard/app` (`dashboard.app_route`) — authorized apps list/revoke

`@login_required`. Lists `ClientUser` rows ("Sign in with SimpleLogin" OAuth grants).
**Needs D1 tables `client` + `client_user` — currently missing** (see §11).

### Data (both methods)

`client_users = ClientUser.filter_by(user_id=current_user.id)` with joined `client` and `alias`.
GOTCHA: the source calls `sorted(client_users, key=lambda cu: cu.client.name)` **and discards the
result** — the rendered order is the unsorted query order (effectively PK order). Port: either
replicate (`ORDER BY id`) or actually sort by client name (marked deviation).

### POST behavior (field `client-user-id`; **no CSRF**)

1. Load `ClientUser.get(client_user_id)`; if missing or `client_user.user_id !=
   current_user.id` → flash `"Unknown error, sorry for the inconvenience, refresh the page"`
   (**error**), `302 → redirect(request.url)`.
2. Else: DELETE the `client_user` row, commit, flash
   `f"Link with {client.name}  has been removed"` (**success** — note the **double space** before
   `has`, replicate exactly), `302 → redirect(request.url)`.

### GET behavior

`render_template("dashboard/app.html", client_users=client_users)`.

### Template `dashboard/app.html`

- Extends `default.html`; **`{% set active_page = "app" %}`** (its own nav entry in `menu.html`
  via `url_for("dashboard.app_route")`); title `Sign in with SimpleLogin apps`.
- Table per `client_user`: `client_user.client.name`; info cell iterates
  `client_user.get_user_info().items()` and renders **only** the `email` (as mailto link) and
  `name` scopes — `get_user_info()` returns `{id, client, email_verified, sub, name, avatar_url,
  email}` where scopes are hardcoded `[NAME, EMAIL, AVATAR_URL]`; `name` = `client_user.name or
  user.name or ''`; `email` = alias email if `alias_id` set else the user's real email. Port:
  precompute `{name, email}` per row.
- `client_user.created_at | dt` (humanized). Revoke form: hidden `client-user-id`, button
  `Remove`, no csrf.

---

## 9. GET|POST `/dashboard/setup_done` (`dashboard.setup_done`)

`@login_required`. **GET route with a side effect** (cookie write) — no template, no flash:

- `302 → url_for("dashboard.index")` with
  `Set-Cookie: setup_done=true; Expires=<now+30 days>; HttpOnly; SameSite=Lax` and `Secure` iff
  `URL` starts with `https`. (No `Path` set → Flask default `Path=/`.)
- Nothing server-side ever reads this cookie — it is consumed by the browser extension (legacy;
  the sibling `onboarding.setup_done` carries a "TODO: Remove when the extension is updated"
  comment). Port: trivial passthrough, keep for extension compatibility.

---

## 10. GET|POST `/dashboard/enter_admin` (`dashboard.enter_admin`) — BLOCKER: WebAuthn + no admin panel

`@limiter.limit("10/minute")` **outside** `@login_required` (see inventory gotcha), then
`@login_required`.

Flask behavior (documented for completeness):

- Purpose: step-up FIDO authentication before the Flask-Admin panel (`/admin`). Reads
  `next` from `request.args`, sanitized via `sanitize_next_url` (allowed-domain check, web spec 01).
- `ADMIN_FIDO_REQUIRED` env ∈ `{"none", "any", "hardware"}` (default `"none"`):
  - `"none"` → immediately `302 → next_url or dashboard.index` (route is a no-op).
  - Otherwise, if `not current_user.fido_enabled()` → flash `"A security key is required for admin
    access but none is configured on your account."` (**warning**), `302 → dashboard.index`.
- Form `FidoTokenForm(FlaskForm)`: `sk_assertion = HiddenField("sk_assertion",
  validators=[DataRequired()])`.
- POST (`validate_on_submit()`):
  1. `json.loads` failure → flash `"Key verification failed. Error: Invalid Payload"`
     (**warning**), `302 → enter_admin?next=<raw request.args next>`.
  2. Missing `session["admin_fido_challenge"]` → flash `"Session expired. Please try again."`
     (**warning**), same redirect.
  3. `ADMIN_FIDO_REQUIRED == "hardware"` and `sk_assertion.authenticatorAttachment !=
     "cross-platform"` → flash `"Only hardware security keys (e.g. YubiKey) are accepted for
     admin access."` (**warning**), same redirect.
  4. WebAuthn assertion verify against the `fido` row (`uuid = current_user.fido_uuid`,
     `credential_id = sk_assertion["id"]`); any failure → flash `"Key verification failed."`
     (**warning**), same redirect.
  5. Success: `UPDATE fido SET sign_count = <new>`, commit; session writes:
     `session["admin_time"] = int(unix_now)`,
     `session["admin_hardware_auth"] = (authenticatorAttachment == "cross-platform")`;
     `302 → next_url or dashboard.index`. (`admin_time` is consumed by `app/admin/base.py` with
     `ADMIN_GRACE_PERIOD` = 43200 s.)
- GET: pops and regenerates `session["admin_fido_challenge"]` (`secrets.token_urlsafe(32)` with
  trailing `=` stripped), builds `webauthn_assertion_options` (with
  `userVerification="required"`; hardware mode adds `extensions.uvm`, `hints`, and rewrites
  credential transports to `["usb","nfc"]`), renders `dashboard/enter_admin.html` with
  `fido_token_form`, `webauthn_assertion_options`, `next_url`, `hardware_required`.
- Template: extends `default.html`; `active_page = "setting"`; title `Admin Authentication`;
  loads static `assets/js/vendors/base64.js` + `webauthn.js` (`url_for('static', ...)`); emits
  `{{ fido_token_form.csrf_token }}`, hidden `sk_assertion` field; inline JS reads
  `{{webauthn_assertion_options|tojson|safe}}` (filter `tojson`); button copy
  `Use your security key`, waiting copy `Waiting for Security Key...`, client toast
  `"An error occurred when trying to verify your key."`.

**Port stance: gate/404.** The Workers port has no Flask-Admin panel, so this route has no
destination. Recommended: register the path and return **404** (`error/404.html`) unconditionally
— equivalently "ADMIN_FIDO_REQUIRED absent" deployments never link here (nothing in any
in-scope template links to `dashboard.enter_admin`; only `/admin` redirects into it). Do NOT port
the WebAuthn flow. Session keys `admin_time` / `admin_hardware_auth` / `admin_fido_challenge` are
then never written — do not add them to `SessionData`.

---

## 11. BLOCKERS / external dependencies

| Dependency | Where | Flask behavior | Port stance |
|---|---|---|---|
| **Paddle vendor API** | §1 billing POST (`users_cancel`, `users/update` with `PADDLE_VENDOR_ID` + `PADDLE_AUTH_CODE`) | Synchronous HTTPS calls; failure → generic error flash, error 147 → `"Your card cannot be charged"` | Config-gate: if `PADDLE_VENDOR_ID` unset (`-1`) the billing page is unreachable in practice (no `subscription` rows get created without webhooks); implement the two calls behind an env check via `fetch`; without creds always take the failure branch (generic flash), never mutate DB |
| **Paddle checkout JS** | §2 pricing, §4 coupon (CDN `paddle.js`, `Paddle.Setup`, product ids, `PADDLE_COUPON_ID`) | Renders regardless of config; ids default `-1` / `None` | Render as-is (client-side only). Static fallback `/static/vendor/paddle.js` must be served |
| **Paddle webhooks** (`/paddle`, creates/updates `subscription` rows) | out of scope (not a dashboard route) | — | Defer; without it `billing`/`pricing` guards simply see no Paddle sub |
| **Coinbase Commerce** | §2 §4 read `coinbase_subscription` rows only | Display/eligibility only — **no API call** in these views (webhook creates rows, out of scope) | No blocker for rendering; port reads the D1 table |
| **Zendesk** | §7 support (upload + request API, `ZENDESK_HOST`/`ZENDESK_API_TOKEN`) | Gated: no `ZENDESK_HOST` → flash `"Support isn't enabled"` + redirect | Config-gate exactly like Flask (`env.ZENDESK_HOST`); implement with `fetch` (multipart passthrough) when configured |
| **WebAuthn / FIDO** | §10 enter_admin | Full assertion verify | **Do not port** — 404 the route (no admin panel) |
| **Redis `parallel_limiter.lock`** | §4 §5 | Per-user mutex around coupon redemption | Drop; atomicity comes from the conditional `UPDATE` |
| **SMTP admin notification** | §5 `redeem_lifetime_coupon` | `send_email(ADMIN_EMAIL, …)` | Config-gate on admin address; use `lib/mailer.ts`; skip silently when unset |
| **Proton partner lookup** | §2 `get_proton_partner()` | 500 if `partner` row `name='Proton'` missing | Graceful `proton_upgrade=false` fallback (marked deviation) |
| **EventDispatcher / user_audit_log** | §4 §5 redemption helpers | Protobuf partner events + audit rows | Skip (established port-wide stance) |
| **PARTNER_SUPPORT_URL redirect** | §7 | External 302 for partner users | Port as-is (pure config + `partner_user` lookup) |

## 12. D1 schema gaps (new migration required for full fidelity)

`cloudflare/migrations/0001_init.sql` already has: `subscription`, `manual_subscription`,
`coinbase_subscription`, `apple_subscription`, `partner_user`, `partner_subscription`,
`referral`, `lifetime_coupon`, `fido`, and `users.lifetime` / `paid_lifetime` /
`lifetime_coupon_id` / `referral_id`. Missing tables used by this group:

- **`coupon`** (§4): `id, created_at, updated_at, code VARCHAR(128) NOT NULL UNIQUE,
  nb_year INTEGER NOT NULL DEFAULT 1, used INTEGER NOT NULL DEFAULT 0,
  used_by_user_id INTEGER NULL REFERENCES users(id) ON DELETE CASCADE,
  is_giveaway INTEGER NOT NULL DEFAULT 0, comment TEXT, expires_date TEXT NULL` +
  index `ix_coupon_used_by_user_id`.
- **`payout`** (§6): `id, created_at, updated_at, user_id NOT NULL REFERENCES users(id) ON DELETE
  CASCADE, amount REAL NOT NULL, payment_method VARCHAR(256) NOT NULL,
  number_upgraded_account INTEGER NOT NULL, comment TEXT` + index `ix_payout_user_id`.
- **`client` + `client_user`** (§8): minimum viable subset — `client(id, name VARCHAR(128) NOT
  NULL, …)`, `client_user(id, created_at, user_id NOT NULL, client_id NOT NULL, alias_id NULL,
  name VARCHAR(128) NULL, default_avatar INTEGER NOT NULL DEFAULT 0, UNIQUE(user_id, client_id))`.
  Alternative if the OAuth-provider feature is not ported at all: render `/dashboard/app` with an
  always-empty list (rows can never exist) — acceptable, but then hide the nav entry.

## 13. Cross-blueprint `url_for` endpoints referenced by this group's templates

| Endpoint | Used in | Maps to |
|---|---|---|
| `dashboard.index` | redirects everywhere | `/dashboard/` (web spec 02) |
| `dashboard.pricing` | `billing.html` | §2 |
| `dashboard.coupon_route` | `pricing.html` FAQ | §4 |
| `dashboard.lifetime_licence` | §4 redirect | §5 |
| `dashboard.billing` | redirects §1; linked from `setting.html` (web spec 04) | §1 |
| `dashboard.referral_route` | redirects §6; linked from `templates/developer/client_details/referral.html` (out-of-scope developer blueprint) and `menu.html` | §6 |
| `dashboard.notifications_route` | `support.html` | web spec 04 route 14 |
| `dashboard.app_route` | `menu.html` nav | §8 |
| `dashboard.subscription_success` | pricing `success_url` (absolute URL, not `url_for`) | §3 |
| `static` (`assets/js/vendors/base64.js`, `webauthn.js`, `/static/vendor/paddle.js`) | `enter_admin.html`, `pricing.html`, `coupon.html` | static assets pipeline |

Template filters/globals recap for the precompile pipeline (beyond web spec 02 §0.5): `dt`
(humanize), `tojson|safe` (§10 only — droppable with the route), context globals `NOW`,
`HEADER_ALLOW_API_COOKIES`, `ZENDESK_ENABLED` (nav), plus Python-isms to precompute:
`.strftime("%Y-%m-%d")`, arrow `.format("YYYY-MM-DD")`, `(end_at - now).days`,
`.date().isoformat()`, `sub.plan_name()`, `referral.link()`/`nb_user`/`nb_paid_user`,
`client_user.get_user_info()`, `current_user.get_paddle_subscription()` (pricing template).
