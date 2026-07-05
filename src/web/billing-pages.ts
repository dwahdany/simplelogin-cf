/**
 * Web spec 05 — billing + misc pages of the dashboard blueprint:
 * /billing, /pricing, /subscription_success, /coupon, /lifetime_licence,
 * /referral, /support, /app, /setup_done, /enter_admin.
 *
 * Port stances taken from specs/web/05-billing-misc-pages.md:
 * - Paddle vendor API calls are config-gated on PADDLE_VENDOR_ID +
 *   PADDLE_AUTH_CODE; without credentials the failure branch runs (generic
 *   error flash, no DB mutation) — BLOCKER B5/§11.
 * - parallel_limiter.lock() on /coupon and /lifetime_licence is dropped:
 *   redemption is a single atomic conditional UPDATE, which already
 *   guarantees at-most-once semantics.
 * - /enter_admin is registered but 404s unconditionally (no Flask-Admin
 *   panel, WebAuthn flow not ported) — §10 port stance.
 * - EventDispatcher / user_audit_log emission is skipped (port-wide stance).
 */

import { type Context, Hono } from "hono";
import { setCookie } from "hono/cookie";
import { addDays, nowStr, toDate, toStr } from "../lib/dates";
import type { Env } from "../lib/env";
import { sendTransactionalEmail } from "../lib/mailer";
import {
  appleValid,
  coinbaseActive,
  manualActive,
  type PremiumInputs,
  paddleActive,
  partnerActive,
  premiumInputsForUser,
} from "../lib/models";
import type {
  AppleSubscriptionRow,
  CoinbaseSubscriptionRow,
  ManualSubscriptionRow,
  PartnerSubscriptionRow,
  PartnerUserRow,
  SubscriptionRow,
  UserRow,
} from "../lib/rows";
import {
  csrfTokenField,
  generateCsrfToken,
  makeField,
  validateCsrfToken,
} from "../lib/web/forms";
import {
  buildCurrentUser,
  flash,
  renderErrorPage,
  webRender,
} from "../lib/web/render";
import { urlFor } from "../lib/web/urls";
import { requireWebLogin, type WebEnv } from "../lib/web/webauth";

export const webBillingPagesRoutes = new Hono<WebEnv>();

/**
 * Config keys used by this group but not part of the core Env interface
 * (all optional, Flask defaults documented in the spec).
 */
type ExtEnv = Env & {
  PADDLE_VENDOR_ID?: string;
  PADDLE_AUTH_CODE?: string;
  PADDLE_MONTHLY_PRODUCT_ID?: string;
  PADDLE_YEARLY_PRODUCT_ID?: string;
  PADDLE_COUPON_ID?: string;
  ZENDESK_HOST?: string;
  ZENDESK_API_TOKEN?: string;
  PARTNER_SUPPORT_URL?: string;
  ADMIN_EMAIL?: string;
  LANDING_PAGE_URL?: string;
};

const extEnv = (c: Context<WebEnv>): ExtEnv => c.env as ExtEnv;

const GENERIC_PADDLE_ERROR =
  "Something went wrong, sorry for the inconvenience. Please retry. " +
  "We are already notified and will be on it asap";

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

/** Flask `redirect(request.url)` — same URL including query string. */
function requestUrl(c: Context<WebEnv>): string {
  const url = new URL(c.req.url);
  return url.pathname + url.search;
}

/** Flask config int(...) defaults: -1 when the env var is absent. */
function intConfig(v: string | undefined): number {
  if (v === undefined || v === "") return -1;
  const n = Number(v);
  return Number.isFinite(n) ? n : -1;
}

/** 'YYYY-MM-DD' from a stored timestamp/date string. */
const dateOnly = (s: string): string => s.slice(0, 10);

/** arrow shift(years=n) equivalent on the stored timestamp format. */
function addYears(d: Date, years: number): Date {
  const out = new Date(d.getTime());
  out.setUTCFullYear(out.getUTCFullYear() + years);
  return out;
}

/** current_user.get_paddle_subscription(): row active within the 14-day grace. */
async function getPaddleSub(
  db: D1Database,
  userId: number,
  now: Date,
): Promise<SubscriptionRow | null> {
  const sub = await db
    .prepare("SELECT * FROM subscription WHERE user_id = ?1")
    .bind(userId)
    .first<SubscriptionRow>();
  return sub && paddleActive(sub, now) ? sub : null;
}

const getAppleSub = (db: D1Database, userId: number) =>
  db
    .prepare("SELECT * FROM apple_subscription WHERE user_id = ?1")
    .bind(userId)
    .first<AppleSubscriptionRow>();

const getPartnerUser = (db: D1Database, userId: number) =>
  db
    .prepare("SELECT * FROM partner_user WHERE user_id = ?1")
    .bind(userId)
    .first<PartnerUserRow>();

const formStr = (
  body: Record<string, unknown>,
  key: string,
): string | undefined => {
  const v = body[key];
  return typeof v === "string" ? v : undefined;
};

// ---------------------------------------------------------------------------
// Paddle vendor API (spec §1 / §11 — config-gated; no creds => failure branch)
// ---------------------------------------------------------------------------

async function paddleVendorCall(
  env: ExtEnv,
  endpoint: string,
  fields: Record<string, string>,
): Promise<{ success: boolean; errorCode: number | null }> {
  if (!env.PADDLE_VENDOR_ID || !env.PADDLE_AUTH_CODE) {
    // BLOCKER B5: without credentials never call out, never mutate DB.
    return { success: false, errorCode: null };
  }
  try {
    const res = await fetch(`https://vendors.paddle.com/api/2.0/${endpoint}`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        vendor_id: env.PADDLE_VENDOR_ID,
        vendor_auth_code: env.PADDLE_AUTH_CODE,
        ...fields,
      }),
    });
    const json = await res.json<{
      success?: boolean;
      error?: { code?: number };
    }>();
    return {
      success: !!json.success,
      errorCode: json.error?.code ?? null,
    };
  } catch {
    return { success: false, errorCode: null };
  }
}

const paddleCancelSubscription = (env: ExtEnv, subscriptionId: string) =>
  paddleVendorCall(env, "subscription/users_cancel", {
    subscription_id: subscriptionId,
  });

const paddleChangePlan = (
  env: ExtEnv,
  subscriptionId: string,
  planId: number,
) =>
  paddleVendorCall(env, "subscription/users/update", {
    subscription_id: subscriptionId,
    plan_id: String(planId),
  });

// ---------------------------------------------------------------------------
// 1. GET|POST /billing
// ---------------------------------------------------------------------------

webBillingPagesRoutes.on(
  ["GET", "POST"],
  "/billing",
  requireWebLogin,
  async (c) => {
    const user = c.get("webUser");
    const db = c.env.DB;
    const now = new Date();

    const sub = await getPaddleSub(db, user.id, now);
    if (!sub) {
      await flash(c, "You don't have any active subscription", "warning");
      return c.redirect(urlFor("dashboard.index"), 302);
    }

    if (c.req.method === "POST") {
      const body = await c.req.parseBody();
      const csrfErr = await validateCsrfToken(
        c,
        formStr(body, "csrf_token"),
        c.get("webSession"),
      );
      if (csrfErr) {
        await flash(c, "Invalid request", "warning");
        return c.redirect(requestUrl(c), 302);
      }

      const formName = formStr(body, "form-name");
      if (formName === "cancel") {
        const { success } = await paddleCancelSubscription(
          extEnv(c),
          sub.subscription_id,
        );
        if (success) {
          await db
            .prepare(
              "UPDATE subscription SET cancelled = 1, updated_at = ?1 WHERE id = ?2",
            )
            .bind(nowStr(), sub.id)
            .run();
          await flash(
            c,
            "Your subscription has been canceled successfully",
            "success",
          );
        } else {
          await flash(c, GENERIC_PADDLE_ERROR, "error");
        }
        return c.redirect(urlFor("dashboard.billing"), 302);
      }
      if (formName === "change-monthly" || formName === "change-yearly") {
        const env = extEnv(c);
        const plan = formName === "change-monthly" ? "monthly" : "yearly";
        const planId =
          plan === "monthly"
            ? intConfig(env.PADDLE_MONTHLY_PRODUCT_ID)
            : intConfig(env.PADDLE_YEARLY_PRODUCT_ID);
        const { success, errorCode } = await paddleChangePlan(
          env,
          sub.subscription_id,
          planId,
        );
        if (success) {
          await db
            .prepare(
              "UPDATE subscription SET plan = ?1, updated_at = ?2 WHERE id = ?3",
            )
            .bind(plan, nowStr(), sub.id)
            .run();
          await flash(c, "Your subscription has been updated", "success");
        } else if (errorCode === 147) {
          // "could not charge the customer for the resubscription"
          await flash(c, "Your card cannot be charged", "error");
        } else {
          await flash(c, GENERIC_PADDLE_ERROR, "error");
        }
        return c.redirect(urlFor("dashboard.billing"), 302);
      }
      // unknown form-name falls through to the GET render (Flask parity)
    }

    const currentUser = await buildCurrentUser(c, user);
    const token = await generateCsrfToken(c, c.get("webSession"));
    return webRender(
      c,
      "dashboard-billing/billing.html",
      {
        sub: {
          cancelled: !!sub.cancelled,
          plan: sub.plan,
          // Subscription.plan_name(), precomputed for Nunjucks
          plan_name: sub.plan === "monthly" ? "Monthly" : "Yearly",
          // stored as 'YYYY-MM-DD' — strftime("%Y-%m-%d") is a no-op
          next_bill_date: dateOnly(sub.next_bill_date),
          update_url: sub.update_url,
        },
        csrf_form: { csrf_token: csrfTokenField(token) },
      },
      { currentUser },
    );
  },
);

// ---------------------------------------------------------------------------
// 2. GET|POST /pricing (POST accepted, no POST branch — renders like GET)
// ---------------------------------------------------------------------------

webBillingPagesRoutes.on(
  ["GET", "POST"],
  "/pricing",
  requireWebLogin,
  async (c) => {
    const user = c.get("webUser");
    const db = c.env.DB;
    const env = extEnv(c);
    const now = new Date();

    if (user.lifetime) {
      await flash(c, "You already have a lifetime subscription", "error");
      return c.redirect(urlFor("dashboard.index"), 302);
    }

    const paddleSub = await getPaddleSub(db, user.id, now);
    // a cancelled-but-still-in-paid-period sub may re-subscribe
    if (paddleSub && !paddleSub.cancelled) {
      await flash(c, "You already have an active subscription", "error");
      return c.redirect(urlFor("dashboard.index"), 302);
    }

    const manualRow = await db
      .prepare("SELECT * FROM manual_subscription WHERE user_id = ?1")
      .bind(user.id)
      .first<ManualSubscriptionRow>();
    const manualSub =
      manualRow && manualActive(manualRow, now) ? manualRow : null;

    const coinbaseRow = await db
      .prepare("SELECT * FROM coinbase_subscription WHERE user_id = ?1")
      .bind(user.id)
      .first<CoinbaseSubscriptionRow>();
    const coinbaseSub =
      coinbaseRow && coinbaseActive(coinbaseRow, now) ? coinbaseRow : null;

    const appleSub = await getAppleSub(db, user.id);
    if (appleSub && appleValid(appleSub, now)) {
      await flash(
        c,
        "Please make sure to cancel your subscription on Apple first",
        "warning",
      );
    }

    let protonUpgrade = false;
    const partnerUser = await getPartnerUser(db, user.id);
    if (partnerUser) {
      const partnerSub = await db
        .prepare(
          "SELECT * FROM partner_subscription WHERE partner_user_id = ?1",
        )
        .bind(partnerUser.id)
        .first<PartnerSubscriptionRow>();
      if (partnerSub && partnerActive(partnerSub, now)) {
        const partner = await db
          .prepare("SELECT name FROM partner WHERE id = ?1")
          .bind(partnerUser.partner_id)
          .first<{ name: string }>();
        await flash(
          c,
          `You already have a subscription provided by ${partner?.name}`,
          "error",
        );
        return c.redirect(urlFor("dashboard.index"), 302);
      }
      // get_proton_partner() raises (=> 500) in Flask when the partner row is
      // missing; deviation: graceful proton_upgrade=false for unseeded deploys.
      const proton = await db
        .prepare("SELECT id FROM partner WHERE name = 'Proton'")
        .bind()
        .first<{ id: number }>();
      protonUpgrade = !!proton && partnerUser.partner_id === proton.id;
    }

    const daysLeft = (endAt: string) =>
      Math.floor((toDate(endAt).getTime() - now.getTime()) / 86400000);

    const currentUser = await buildCurrentUser(c, user);
    return webRender(
      c,
      "dashboard-billing/pricing.html",
      {
        PADDLE_VENDOR_ID: intConfig(env.PADDLE_VENDOR_ID),
        PADDLE_MONTHLY_PRODUCT_ID: intConfig(env.PADDLE_MONTHLY_PRODUCT_ID),
        PADDLE_YEARLY_PRODUCT_ID: intConfig(env.PADDLE_YEARLY_PRODUCT_ID),
        success_url: `${c.env.URL}/dashboard/subscription_success`,
        manual_sub: manualSub
          ? {
              end_at_date: dateOnly(manualSub.end_at),
              days_left: daysLeft(manualSub.end_at),
            }
          : null,
        coinbase_sub: coinbaseSub
          ? {
              end_at_date: dateOnly(coinbaseSub.end_at),
              days_left: daysLeft(coinbaseSub.end_at),
            }
          : null,
        // the Flask template calls current_user.get_paddle_subscription();
        // precomputed and passed instead (spec §2 template notes)
        sub: paddleSub
          ? {
              cancelled: !!paddleSub.cancelled,
              next_bill_date: dateOnly(paddleSub.next_bill_date),
            }
          : null,
        proton_upgrade: protonUpgrade,
      },
      { currentUser },
    );
  },
);

// ---------------------------------------------------------------------------
// 3. GET /subscription_success
// ---------------------------------------------------------------------------

webBillingPagesRoutes.get(
  "/subscription_success",
  requireWebLogin,
  async (c) => {
    const currentUser = await buildCurrentUser(c, c.get("webUser"));
    return webRender(
      c,
      "dashboard-billing/thank-you.html",
      {},
      { currentUser },
    );
  },
);

// ---------------------------------------------------------------------------
// coupon redemption helpers (app/coupon_utils.py port)
// ---------------------------------------------------------------------------

class CouponUserCannotRedeemError extends Error {}

interface CouponRow {
  id: number;
  code: string;
  nb_year: number;
  used: number;
  is_giveaway: number;
  comment: string | null;
  expires_date: string | null;
}

interface LifetimeCouponRow {
  id: number;
  code: string;
  nb_used: number;
  paid: number;
  comment: string | null;
}

/**
 * redeem_coupon(): atomic conditional UPDATE gives at-most-once redemption
 * (replaces the Redis parallel_limiter lock). Audit log / partner events are
 * skipped per the port-wide stance.
 */
async function redeemCoupon(
  db: D1Database,
  user: UserRow,
  code: string,
  now: Date,
): Promise<CouponRow | null> {
  if (user.lifetime) throw new CouponUserCannotRedeemError();

  const subs: PremiumInputs = await premiumInputsForUser(db, user);
  // get_active_subscription precedence Paddle -> Apple -> Manual -> Coinbase
  // -> Partner; anything active that is not a ManualSubscription blocks.
  const activeManual =
    !paddleActive(subs.paddle, now) &&
    !appleValid(subs.apple, now) &&
    manualActive(subs.manual, now)
      ? subs.manual
      : null;
  const hasNonManualActive =
    paddleActive(subs.paddle, now) ||
    appleValid(subs.apple, now) ||
    (!activeManual &&
      (coinbaseActive(subs.coinbase, now) || partnerActive(subs.partner, now)));
  if (hasNonManualActive) throw new CouponUserCannotRedeemError();

  const coupon = await db
    .prepare("SELECT * FROM coupon WHERE code = ?1")
    .bind(code)
    .first<CouponRow>();
  if (!coupon) return null;

  const nowS = nowStr();
  const res = await db
    .prepare(
      `UPDATE coupon SET used = 1, used_by_user_id = ?1, updated_at = ?2
       WHERE code = ?3 AND used = 0
         AND (expires_date IS NULL OR expires_date > ?2)`,
    )
    .bind(user.id, nowS, code)
    .run();
  if (res.meta.changes === 0) return null; // already used / expired

  if (activeManual) {
    // active manual subscription: extend from its current end
    const newEnd = toStr(addYears(toDate(activeManual.end_at), coupon.nb_year));
    await db
      .prepare(
        "UPDATE manual_subscription SET end_at = ?1, updated_at = ?2 WHERE id = ?3",
      )
      .bind(newEnd, nowS, activeManual.id)
      .run();
  } else {
    const endAt = toStr(addDays(addYears(now, coupon.nb_year), 1));
    const existing = await db
      .prepare("SELECT id FROM manual_subscription WHERE user_id = ?1")
      .bind(user.id)
      .first<{ id: number }>();
    if (existing) {
      await db
        .prepare(
          "UPDATE manual_subscription SET end_at = ?1, updated_at = ?2 WHERE id = ?3",
        )
        .bind(endAt, nowS, existing.id)
        .run();
    } else {
      await db
        .prepare(
          `INSERT INTO manual_subscription (user_id, end_at, comment, is_giveaway)
           VALUES (?1, ?2, 'using coupon code', ?3)`,
        )
        .bind(user.id, endAt, coupon.is_giveaway)
        .run();
    }
  }
  return coupon;
}

/** redeem_lifetime_coupon() — returns the coupon row (with post-decrement nb_used) or null. */
async function redeemLifetimeCoupon(
  db: D1Database,
  env: ExtEnv,
  user: UserRow,
  code: string,
): Promise<LifetimeCouponRow | null> {
  if (user.lifetime) return null;
  const partnerLifetime = await db
    .prepare(
      `SELECT ps.id FROM partner_subscription ps
       JOIN partner_user pu ON pu.id = ps.partner_user_id
       WHERE pu.user_id = ?1 AND ps.lifetime = 1`,
    )
    .bind(user.id)
    .first();
  if (partnerLifetime) return null;

  const exists = await db
    .prepare("SELECT id FROM lifetime_coupon WHERE code = ?1")
    .bind(code)
    .first();
  if (!exists) return null;

  const coupon = await db
    .prepare(
      `UPDATE lifetime_coupon SET nb_used = nb_used - 1
       WHERE code = ?1 AND nb_used > 0
       RETURNING *`,
    )
    .bind(code)
    .first<LifetimeCouponRow>();
  if (!coupon) return null;

  await db
    .prepare(
      `UPDATE users SET lifetime = 1, lifetime_coupon_id = ?1,
        paid_lifetime = CASE WHEN ?2 THEN 1 ELSE paid_lifetime END,
        updated_at = ?3
       WHERE id = ?4`,
    )
    .bind(coupon.id, coupon.paid, nowStr(), user.id)
    .run();

  // Admin notification (config-gated; Flask interpolates the User repr —
  // simplified here to "id email").
  if (env.ADMIN_EMAIL) {
    await sendTransactionalEmail(env, {
      to: env.ADMIN_EMAIL,
      subject: `User ${user.id} ${user.email} used lifetime coupon(${coupon.comment}). Coupon nb_used: ${coupon.nb_used}`,
      text: "",
    });
  }
  return coupon;
}

// ---------------------------------------------------------------------------
// 4. GET|POST /coupon
// ---------------------------------------------------------------------------

async function renderCouponPage(
  c: Context<WebEnv>,
  user: UserRow,
  codeValue: string,
  codeErrors: string[],
): Promise<Response> {
  const db = c.env.DB;
  const env = extEnv(c);
  const now = new Date();

  let canUseCoupon = true;
  if (user.lifetime) canUseCoupon = false;
  if (await getPaddleSub(db, user.id, now)) canUseCoupon = false; // even if cancelled
  const appleSub = await getAppleSub(db, user.id);
  if (appleSub && appleValid(appleSub, now)) canUseCoupon = false;
  const coinbaseSub = await db
    .prepare("SELECT * FROM coinbase_subscription WHERE user_id = ?1")
    .bind(user.id)
    .first<CoinbaseSubscriptionRow>();
  // coinbase users may redeem within 30 days of expiry — deliberate
  if (
    coinbaseSub &&
    toDate(coinbaseSub.end_at).getTime() > addDays(now, 30).getTime()
  ) {
    canUseCoupon = false;
  }

  const currentUser = await buildCurrentUser(c, user);
  const token = await generateCsrfToken(c, c.get("webSession"));
  return webRender(
    c,
    "dashboard-billing/coupon.html",
    {
      coupon_form: {
        csrf_token: csrfTokenField(token),
        code: makeField(
          { name: "code", label: "Coupon Code", value: codeValue },
          codeErrors,
        ),
      },
      PADDLE_VENDOR_ID: intConfig(env.PADDLE_VENDOR_ID),
      // Flask renders data-product="None" when PADDLE_COUPON_ID is unset
      PADDLE_COUPON_ID: env.PADDLE_COUPON_ID ?? "None",
      can_use_coupon: canUseCoupon,
      // a coupon is only valid until now + 1 year - 1 day
      max_coupon_date: dateOnly(toStr(addDays(addYears(now, 1), -1))),
    },
    { currentUser },
  );
}

webBillingPagesRoutes.on(
  ["GET", "POST"],
  "/coupon",
  requireWebLogin,
  async (c) => {
    const user = c.get("webUser");
    const db = c.env.DB;

    let codeValue = "";
    let codeErrors: string[] = [];
    if (c.req.method === "POST") {
      const body = await c.req.parseBody();
      codeValue = formStr(body, "code") ?? "";
      if (!codeValue) codeErrors = ["This field is required."];
      const csrfErr = await validateCsrfToken(
        c,
        formStr(body, "csrf_token"),
        c.get("webSession"),
      );
      // validate_on_submit(): CSRF failures are silent (re-render 200)
      if (!csrfErr && codeValue) {
        const lifetimeCoupon = await db
          .prepare("SELECT id FROM lifetime_coupon WHERE code = ?1")
          .bind(codeValue)
          .first();
        if (lifetimeCoupon) {
          await flash(
            c,
            "Redirect to the lifetime coupon page instead",
            "success",
          );
          return c.redirect(urlFor("dashboard.lifetime_licence"), 302);
        }
        try {
          const coupon = await redeemCoupon(db, user, codeValue, new Date());
          if (coupon) {
            await flash(
              c,
              "Your account has been upgraded to Premium, thanks for your support!",
              "success",
            );
          } else {
            await flash(
              c,
              "This coupon cannot be redeemed. It's invalid or has expired",
              "warning",
            );
          }
        } catch (e) {
          if (e instanceof CouponUserCannotRedeemError) {
            await flash(
              c,
              "You have an active subscription. Please remove it before redeeming a coupon",
              "warning",
            );
          } else {
            throw e;
          }
        }
      }
    }
    return renderCouponPage(c, user, codeValue, codeErrors);
  },
);

// ---------------------------------------------------------------------------
// 5. GET|POST /lifetime_licence
// ---------------------------------------------------------------------------

async function lifetimeLicenceHandler(c: Context<WebEnv>): Promise<Response> {
  const user = c.get("webUser");
  const db = c.env.DB;
  const now = new Date();

  if (user.lifetime) {
    await flash(c, "You already have a lifetime licence", "warning");
    return c.redirect(urlFor("dashboard.index"), 302);
  }
  const paddleSub = await getPaddleSub(db, user.id, now);
  if (paddleSub && !paddleSub.cancelled) {
    await flash(c, "Please cancel your current subscription first", "warning");
    return c.redirect(urlFor("dashboard.index"), 302);
  }

  let codeValue = "";
  let codeErrors: string[] = [];
  if (c.req.method === "POST") {
    const body = await c.req.parseBody();
    codeValue = formStr(body, "code") ?? "";
    if (!codeValue) codeErrors = ["This field is required."];
    const csrfErr = await validateCsrfToken(
      c,
      formStr(body, "csrf_token"),
      c.get("webSession"),
    );
    if (!csrfErr && codeValue) {
      const coupon = await redeemLifetimeCoupon(db, extEnv(c), user, codeValue);
      if (coupon) {
        await flash(c, "You are upgraded to lifetime premium!", "success");
        return c.redirect(urlFor("dashboard.index"), 302);
      }
      await flash(c, "Coupon code expired or invalid", "warning");
    }
  }

  const currentUser = await buildCurrentUser(c, user);
  const token = await generateCsrfToken(c, c.get("webSession"));
  return webRender(
    c,
    "dashboard-billing/lifetime_licence.html",
    {
      coupon_form: {
        csrf_token: csrfTokenField(token),
        code: makeField(
          { name: "code", label: "Coupon Code", value: codeValue },
          codeErrors,
        ),
      },
    },
    { currentUser },
  );
}

// Flask registers /lifetime_licence; the shared urlFor map emits
// /dashboard/lifetime-licence — serve both spellings (see notes).
webBillingPagesRoutes.on(
  ["GET", "POST"],
  "/lifetime_licence",
  requireWebLogin,
  lifetimeLicenceHandler,
);
webBillingPagesRoutes.on(
  ["GET", "POST"],
  "/lifetime-licence",
  requireWebLogin,
  lifetimeLicenceHandler,
);

// ---------------------------------------------------------------------------
// 6. GET|POST /referral (no wtforms / no CSRF in Flask — faithful port)
// ---------------------------------------------------------------------------

const REFERRAL_PATTERN = /^[0-9a-z_-]{3,}$/;

/** User.is_paid(): active subscription that is not a giveaway manual sub. */
function isPaidFromInputs(subs: PremiumInputs, now: Date): boolean {
  if (paddleActive(subs.paddle, now)) return true;
  if (appleValid(subs.apple, now)) return true;
  if (manualActive(subs.manual, now)) return !subs.manual?.is_giveaway;
  if (coinbaseActive(subs.coinbase, now)) return true;
  return partnerActive(subs.partner, now);
}

webBillingPagesRoutes.on(
  ["GET", "POST"],
  "/referral",
  requireWebLogin,
  async (c) => {
    const user = c.get("webUser");
    const db = c.env.DB;

    if (c.req.method === "POST") {
      const body = await c.req.parseBody();
      const formName = formStr(body, "form-name");
      if (formName === "create") {
        // Flask 500s on a missing code (re.fullmatch(p, None)); deviation:
        // treat missing as "" -> pattern-mismatch flash.
        const code = formStr(body, "code") ?? "";
        if (!REFERRAL_PATTERN.test(code)) {
          await flash(
            c,
            "At least 3 characters. Only lowercase letters, numbers, " +
              "dashes (-) and underscores (_) are currently supported.",
            "error",
          );
          return c.redirect(urlFor("dashboard.referral_route"), 302);
        }
        const existing = await db
          .prepare("SELECT id FROM referral WHERE code = ?1")
          .bind(code)
          .first();
        if (existing) {
          await flash(c, "Code already used", "error");
          return c.redirect(urlFor("dashboard.referral_route"), 302);
        }
        const created = await db
          .prepare(
            "INSERT INTO referral (user_id, code, name) VALUES (?1, ?2, ?3) RETURNING id",
          )
          .bind(user.id, code, formStr(body, "name") ?? null)
          .first<{ id: number }>();
        await flash(c, "A new referral code has been created", "success");
        return c.redirect(
          urlFor("dashboard.referral_route", { highlight_id: created?.id }),
          302,
        );
      }
      if (formName === "update") {
        const referralId = formStr(body, "referral-id") ?? "";
        const referral = await db
          .prepare("SELECT id, user_id FROM referral WHERE id = ?1")
          .bind(referralId)
          .first<{ id: number; user_id: number }>();
        if (referral && referral.user_id === user.id) {
          await db
            .prepare(
              "UPDATE referral SET name = ?1, updated_at = ?2 WHERE id = ?3",
            )
            .bind(formStr(body, "name") ?? null, nowStr(), referral.id)
            .run();
          await flash(c, "Referral name updated", "success");
          return c.redirect(
            urlFor("dashboard.referral_route", { highlight_id: referral.id }),
            302,
          );
        }
        // missing/foreign row: fall through to the GET render (Flask parity)
      } else if (formName === "delete") {
        const referralId = formStr(body, "referral-id") ?? "";
        const referral = await db
          .prepare("SELECT id, user_id FROM referral WHERE id = ?1")
          .bind(referralId)
          .first<{ id: number; user_id: number }>();
        if (referral && referral.user_id === user.id) {
          // users.referral_id FK is ON DELETE SET NULL — referred users stay
          await db
            .prepare("DELETE FROM referral WHERE id = ?1")
            .bind(referral.id)
            .run();
          await flash(c, "Referral deleted", "success");
          return c.redirect(urlFor("dashboard.referral_route"), 302);
        }
      }
    }

    // GET render (also the POST fall-through)
    // Flask int()s highlight_id and 500s on garbage; deviation: parse-or-ignore.
    const rawHighlight = c.req.query("highlight_id");
    let highlightId: number | null = null;
    if (rawHighlight) {
      const n = Number.parseInt(rawHighlight, 10);
      if (Number.isFinite(n)) highlightId = n;
    }

    const { results: referralRows } = await db
      .prepare("SELECT * FROM referral WHERE user_id = ?1 ORDER BY id")
      .bind(user.id)
      .all<{ id: number; code: string; name: string | null }>();
    // move the highlighted referral to the front (index 0 stays put, like
    // Flask's `if highlight_index:`)
    const idx = referralRows.findIndex((r) => r.id === highlightId);
    if (idx > 0) {
      const [row] = referralRows.splice(idx, 1);
      referralRows.unshift(row);
    }

    const env = extEnv(c);
    const landing = env.LANDING_PAGE_URL ?? "https://simplelogin.io";
    const now = new Date();
    const referrals = [];
    for (const r of referralRows) {
      const { results: referred } = await db
        .prepare("SELECT * FROM users WHERE referral_id = ?1 AND activated = 1")
        .bind(r.id)
        .all<UserRow>();
      let nbPaid = 0;
      for (const ru of referred) {
        if (isPaidFromInputs(await premiumInputsForUser(db, ru), now)) nbPaid++;
      }
      referrals.push({
        id: r.id,
        code: r.code,
        name: r.name,
        nb_user: referred.length,
        nb_paid_user: nbPaid,
        link: `${landing}?slref=${r.code}`,
      });
    }

    const { results: payouts } = await db
      .prepare("SELECT * FROM payout WHERE user_id = ?1 ORDER BY id")
      .bind(user.id)
      .all();

    const currentUser = await buildCurrentUser(c, user);
    return webRender(
      c,
      "dashboard-billing/referral.html",
      { referrals, highlight_id: highlightId, payouts },
      { currentUser },
    );
  },
);

// ---------------------------------------------------------------------------
// 7. GET|POST /support — BLOCKER: Zendesk (config-gated on ZENDESK_HOST)
// ---------------------------------------------------------------------------

const SUPPORT_LIMIT = 2;
const SUPPORT_WINDOW_SECS = 3600; // "2/hour"

const supportRateKey = (userId: number) =>
  `rl:web:dashboard.support_route:user:${userId}:${SUPPORT_WINDOW_SECS}`;

/**
 * flask-limiter "2/hour" with deduct_when: the CHECK runs on every POST but
 * the budget is only deducted on successful ticket creation.
 */
async function supportTicketsCreated(
  db: D1Database,
  userId: number,
  nowSecs: number,
): Promise<number> {
  const windowStart = Math.floor(nowSecs / SUPPORT_WINDOW_SECS);
  const row = await db
    .prepare(
      "SELECT count FROM rate_limit WHERE key = ?1 AND window_start = ?2",
    )
    .bind(supportRateKey(userId), windowStart)
    .first<{ count: number }>();
  return row?.count ?? 0;
}

async function deductSupportTicket(
  db: D1Database,
  userId: number,
  nowSecs: number,
): Promise<void> {
  const windowStart = Math.floor(nowSecs / SUPPORT_WINDOW_SECS);
  await db
    .prepare(
      `INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, 1)
       ON CONFLICT(key) DO UPDATE SET
         count = CASE WHEN window_start = ?2 THEN count + 1 ELSE 1 END,
         window_start = ?2`,
    )
    .bind(supportRateKey(userId), windowStart)
    .run();
}

async function createZendeskRequest(
  c: Context<WebEnv>,
  env: ExtEnv,
  userId: number,
  email: string,
  content: string,
  files: Array<File | string>,
): Promise<boolean> {
  const auth = `Basic ${btoa(`${email}/token:${env.ZENDESK_API_TOKEN ?? ""}`)}`;
  const tokens: string[] = [];
  for (const f of files) {
    if (typeof f === "string" || !f.name) continue; // empty filename => skip
    const mime = f.type;
    if (
      mime !== "text/plain" &&
      mime !== "message/rfc822" &&
      !mime.startsWith("image/")
    ) {
      await flash(
        c,
        `File ${f.name} is not an image, text or an email`,
        "warning",
      );
      return false;
    }
    try {
      const qs = new URLSearchParams({ filename: f.name });
      const res = await fetch(
        `https://${env.ZENDESK_HOST}/api/v2/uploads?${qs}`,
        {
          method: "POST",
          headers: { "content-type": mime, Authorization: auth },
          body: f,
        },
      );
      if (res.status !== 201) return false;
      const data = await res.json<{ upload: { token: string } }>();
      tokens.push(data.upload.token);
    } catch {
      return false;
    }
  }
  try {
    const res = await fetch(
      `https://${env.ZENDESK_HOST}/api/v2/requests.json`,
      {
        method: "POST",
        headers: { "content-type": "application/json", Authorization: auth },
        body: JSON.stringify({
          request: {
            subject: `Ticket created for user ${userId}`,
            comment: { type: "Comment", body: content, uploads: tokens },
            requester: { name: `SimpleLogin user ${userId}`, email },
          },
        }),
      },
    );
    return res.status === 201;
  } catch {
    return false;
  }
}

webBillingPagesRoutes.on(
  ["GET", "POST"],
  "/support",
  requireWebLogin,
  async (c) => {
    const user = c.get("webUser");
    const db = c.env.DB;
    const env = extEnv(c);

    const renderSupport = async (ctx: Record<string, unknown>) =>
      webRender(c, "dashboard-billing/support.html", ctx, {
        currentUser: await buildCurrentUser(c, user),
      });

    // "2/hour" POST budget check runs before the view gates (limiter wraps
    // the view in Flask); deduction happens only on success below.
    if (c.req.method === "POST" && !c.env.DISABLE_RATE_LIMIT) {
      const used = await supportTicketsCreated(db, user.id, Date.now() / 1000);
      if (used >= SUPPORT_LIMIT) return renderErrorPage(c, 429);
    }

    if (!env.ZENDESK_HOST) {
      await flash(c, "Support isn't enabled", "error");
      return c.redirect(urlFor("dashboard.index"), 302);
    }
    if (env.PARTNER_SUPPORT_URL !== undefined) {
      const pu = await getPartnerUser(db, user.id);
      if (pu) return c.redirect(env.PARTNER_SUPPORT_URL, 302);
    }

    if (c.req.method === "POST") {
      const fd = await c.req.formData();
      const content = fd.get("ticket_content");
      const email = fd.get("ticket_email");
      const contentStr = typeof content === "string" ? content : "";
      const emailStr = typeof email === "string" ? email : "";

      if (!contentStr) {
        await flash(c, "Please add a description", "error");
        return renderSupport({ ticket_email: emailStr });
      }
      if (!emailStr) {
        await flash(c, "Please provide an email address", "error");
        return renderSupport({ ticket_content: contentStr });
      }
      const ok = await createZendeskRequest(
        c,
        env,
        user.id,
        emailStr,
        contentStr,
        fd.getAll("ticket_files"),
      );
      if (!ok) {
        await flash(
          c,
          "Cannot create a Zendesk ticket, sorry for the inconvenience! Please retry later.",
          "error",
        );
        return renderSupport({
          ticket_email: emailStr,
          ticket_content: contentStr,
        });
      }
      if (!c.env.DISABLE_RATE_LIMIT) {
        await deductSupportTicket(db, user.id, Date.now() / 1000);
      }
      await flash(
        c,
        "Support ticket is created. You will receive an email about its status.",
        "success",
      );
      return c.redirect(urlFor("dashboard.index"), 302);
    }

    return renderSupport({ ticket_email: user.email });
  },
);

// ---------------------------------------------------------------------------
// 8. GET|POST /app — authorized "Sign in with SimpleLogin" apps
// ---------------------------------------------------------------------------

webBillingPagesRoutes.on(
  ["GET", "POST"],
  "/app",
  requireWebLogin,
  async (c) => {
    const user = c.get("webUser");
    const db = c.env.DB;

    if (c.req.method === "POST") {
      // no CSRF in Flask (raw request.form) — faithful port
      const body = await c.req.parseBody();
      const clientUserId = formStr(body, "client-user-id") ?? "";
      const row = await db
        .prepare(
          `SELECT cu.id, cu.user_id, cl.name AS client_name
         FROM client_user cu JOIN client cl ON cl.id = cu.client_id
         WHERE cu.id = ?1`,
        )
        .bind(clientUserId)
        .first<{ id: number; user_id: number; client_name: string }>();
      if (!row || row.user_id !== user.id) {
        await flash(
          c,
          "Unknown error, sorry for the inconvenience, refresh the page",
          "error",
        );
        return c.redirect(requestUrl(c), 302);
      }
      await db
        .prepare("DELETE FROM client_user WHERE id = ?1")
        .bind(row.id)
        .run();
      // NB: double space before "has" — Flask parity
      await flash(
        c,
        `Link with ${row.client_name}  has been removed`,
        "success",
      );
      return c.redirect(requestUrl(c), 302);
    }

    // Flask sorts by client name and DISCARDS the result — PK order rendered.
    const { results } = await db
      .prepare(
        `SELECT cu.id, cu.created_at, cu.name AS cu_name,
              cl.name AS client_name, a.email AS alias_email
       FROM client_user cu
       JOIN client cl ON cl.id = cu.client_id
       LEFT JOIN alias a ON a.id = cu.alias_id
       WHERE cu.user_id = ?1 ORDER BY cu.id`,
      )
      .bind(user.id)
      .all<{
        id: number;
        created_at: string;
        cu_name: string | null;
        client_name: string;
        alias_email: string | null;
      }>();

    const clientUsers = results.map((r) => ({
      id: r.id,
      created_at: r.created_at,
      client: { name: r.client_name },
      // ClientUser.get_user_info() name/email scopes, precomputed
      info: {
        name: r.cu_name || user.name || "",
        email: r.alias_email ?? user.email,
      },
    }));

    const currentUser = await buildCurrentUser(c, user);
    return webRender(
      c,
      "dashboard-billing/app.html",
      { client_users: clientUsers },
      { currentUser },
    );
  },
);

// ---------------------------------------------------------------------------
// 9. GET|POST /setup_done — cookie for the browser extension (legacy)
// ---------------------------------------------------------------------------

webBillingPagesRoutes.on(
  ["GET", "POST"],
  "/setup_done",
  requireWebLogin,
  async (c) => {
    setCookie(c, "setup_done", "true", {
      path: "/",
      expires: new Date(Date.now() + 30 * 86400 * 1000),
      httpOnly: true,
      sameSite: "Lax",
      secure: c.env.URL.startsWith("https"),
    });
    return c.redirect(urlFor("dashboard.index"), 302);
  },
);

// ---------------------------------------------------------------------------
// 10. GET|POST /enter_admin — BLOCKER: WebAuthn + no admin panel => 404
// ---------------------------------------------------------------------------

webBillingPagesRoutes.on(["GET", "POST"], "/enter_admin", (c) =>
  renderErrorPage(c, 404),
);
