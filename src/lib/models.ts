/**
 * Model-layer business logic ported from app/models.py.
 *
 * Split so the premium/trial precedence rules are pure & unit-testable
 * (`isPremium`, `hasActiveSubscription`, `inTrial`) while DB access lives in
 * thin async wrappers (`getPremiumInputs`, `userIsPremium`, ...).
 *
 * Faithful to the Flask semantics in specs/06-data-model.md §2.2/§2.3:
 * - subscription precedence Paddle -> Apple -> Manual -> Coinbase -> Partner
 * - grace periods Paddle 14d (DATE granularity, cancelled subs still count),
 *   Apple 16d, Partner 14d (or lifetime), Manual/Coinbase none
 * - free alias limit excludes trashed aliases and applies even during trial
 */

import type { Env } from "./env";
import type {
  AliasRow,
  AppleSubscriptionRow,
  CoinbaseSubscriptionRow,
  ContactRow,
  CustomDomainRow,
  ManualSubscriptionRow,
  MailboxRow,
  PartnerSubscriptionRow,
  PublicDomainRow,
  SubscriptionRow,
  UserRow,
} from "./rows";
import { toDate, nowStr } from "./dates";

// ---- constants (specs/06 §2.2, §2.3; specs/08 §2) ----
export const PADDLE_SUBSCRIPTION_GRACE_DAYS = 14;
export const PARTNER_SUBSCRIPTION_GRACE_DAYS = 14;
export const APPLE_GRACE_PERIOD_DAYS = 16;
export const MAX_NB_EMAIL_OLD_FREE_PLAN = 15;
export const MAX_NB_EMAIL_FREE_PLAN_DEFAULT = 5;

// User.flags bit constants (models.py L88-91)
export const FLAG_FREE_DISABLE_CREATE_CONTACTS = 1; // 1 << 0
export const FLAG_CREATED_FROM_PARTNER = 2; // 1 << 1
export const FLAG_FREE_OLD_ALIAS_LIMIT = 4; // 1 << 2
export const FLAG_CREATED_ALIAS_FROM_PARTNER = 8; // 1 << 3

const DAY_MS = 86400 * 1000;
const pad = (n: number) => String(n).padStart(2, "0");

/** UTC date-only "YYYY-MM-DD" — matches arrow `.date()` for the Paddle check. */
function dateOnlyUTC(d: Date): string {
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

/**
 * The raw rows needed to compute premium status without further DB access.
 * Includes the user's own lifetime/trial_end so `isPremium` is fully pure.
 */
export interface PremiumInputs {
  lifetime: boolean;
  trialEnd: string | null;
  paddle: SubscriptionRow | null;
  apple: AppleSubscriptionRow | null;
  manual: ManualSubscriptionRow | null;
  coinbase: CoinbaseSubscriptionRow | null;
  partner: PartnerSubscriptionRow | null;
}

// ---- pure subscription predicates (models.py L788-1055) ----

/** Paddle: active until next_bill_date + 14d (DATE granularity, cancelled included). */
export function paddleActive(sub: SubscriptionRow | null, now: Date): boolean {
  if (!sub) return false;
  const graceDate = dateOnlyUTC(new Date(now.getTime() - PADDLE_SUBSCRIPTION_GRACE_DAYS * DAY_MS));
  // next_bill_date is stored 'YYYY-MM-DD'; lexicographic compare == date compare.
  return sub.next_bill_date >= graceDate;
}

/** Apple: expires_date > now - 16 days. */
export function appleValid(sub: AppleSubscriptionRow | null, now: Date): boolean {
  if (!sub) return false;
  return toDate(sub.expires_date).getTime() > now.getTime() - APPLE_GRACE_PERIOD_DAYS * DAY_MS;
}

/** Manual: end_at > now. */
export function manualActive(sub: ManualSubscriptionRow | null, now: Date): boolean {
  if (!sub) return false;
  return toDate(sub.end_at).getTime() > now.getTime();
}

/** Coinbase: end_at > now. */
export function coinbaseActive(sub: CoinbaseSubscriptionRow | null, now: Date): boolean {
  if (!sub) return false;
  return toDate(sub.end_at).getTime() > now.getTime();
}

/** Partner: lifetime OR end_at > now - 14 days (end_at nullable for lifetime subs). */
export function partnerActive(sub: PartnerSubscriptionRow | null, now: Date): boolean {
  if (!sub) return false;
  if (sub.lifetime) return true;
  if (!sub.end_at) return false;
  return toDate(sub.end_at).getTime() > now.getTime() - PARTNER_SUBSCRIPTION_GRACE_DAYS * DAY_MS;
}

/**
 * User.get_active_subscription() is not None — precedence
 * Paddle -> Apple -> Manual -> Coinbase -> Partner. For a boolean the order
 * is irrelevant (it's an OR), but partner can be excluded like the Flask arg.
 */
export function hasActiveSubscription(
  subs: PremiumInputs,
  now: Date = new Date(),
  includePartner = true,
): boolean {
  return (
    paddleActive(subs.paddle, now) ||
    appleValid(subs.apple, now) ||
    manualActive(subs.manual, now) ||
    coinbaseActive(subs.coinbase, now) ||
    (includePartner && partnerActive(subs.partner, now))
  );
}

/** User.lifetime_or_active_subscription(). */
export function lifetimeOrActiveSubscription(
  subs: PremiumInputs,
  now: Date = new Date(),
  includePartner = true,
): boolean {
  if (subs.lifetime) return true;
  return hasActiveSubscription(subs, now, includePartner);
}

/**
 * User.is_premium(): lifetime/active subscription OR still inside the trial
 * window. Note the trial branch is the *simple* check (trial_end && now <
 * trial_end), independent of subscriptions — same as Flask.
 */
export function isPremium(subs: PremiumInputs, now: Date = new Date(), includePartner = true): boolean {
  if (lifetimeOrActiveSubscription(subs, now, includePartner)) return true;
  return !!subs.trialEnd && now.getTime() < toDate(subs.trialEnd).getTime();
}

/**
 * User.in_trial() — the *simple* pure form on just the user row, as used by the
 * `is_premium` trial branch: trial_end set AND now < trial_end.
 *
 * NB: Flask's full `in_trial()` also requires NOT lifetime_or_active_subscription;
 * use `userInTrial(db, user)` for that (needs subscription rows).
 */
export function inTrial(user: UserRow, now: Date = new Date()): boolean {
  if (!user.trial_end) return false;
  return now.getTime() < toDate(user.trial_end).getTime();
}

/** User.max_alias_for_free_account() (models.py L957). */
export function maxAliasForFreeAccount(user: UserRow, env: Env): number {
  if ((user.flags & FLAG_FREE_OLD_ALIAS_LIMIT) === FLAG_FREE_OLD_ALIAS_LIMIT) {
    return MAX_NB_EMAIL_OLD_FREE_PLAN;
  }
  const n = parseInt(env.MAX_NB_EMAIL_FREE_PLAN, 10);
  return Number.isNaN(n) ? MAX_NB_EMAIL_FREE_PLAN_DEFAULT : n;
}

/** User.is_active(): delete_on is NULL, else delete_on < now. */
function isActive(user: UserRow, now: Date): boolean {
  if (user.delete_on === null) return true;
  return toDate(user.delete_on).getTime() < now.getTime();
}

// ---- DB access ----

async function fetchSubs(
  db: D1Database,
  userId: number,
): Promise<Omit<PremiumInputs, "lifetime" | "trialEnd">> {
  const [paddle, apple, manual, coinbase, partner] = await Promise.all([
    db.prepare("SELECT * FROM subscription WHERE user_id = ?1").bind(userId).first<SubscriptionRow>(),
    db.prepare("SELECT * FROM apple_subscription WHERE user_id = ?1").bind(userId).first<AppleSubscriptionRow>(),
    db.prepare("SELECT * FROM manual_subscription WHERE user_id = ?1").bind(userId).first<ManualSubscriptionRow>(),
    db.prepare("SELECT * FROM coinbase_subscription WHERE user_id = ?1").bind(userId).first<CoinbaseSubscriptionRow>(),
    db
      .prepare(
        `SELECT ps.* FROM partner_subscription ps
         JOIN partner_user pu ON ps.partner_user_id = pu.id
         WHERE pu.user_id = ?1`,
      )
      .bind(userId)
      .first<PartnerSubscriptionRow>(),
  ]);
  return { paddle, apple, manual, coinbase, partner };
}

/** Build PremiumInputs from an already-loaded user row + its subscription rows. */
export async function premiumInputsForUser(db: D1Database, user: UserRow): Promise<PremiumInputs> {
  const subs = await fetchSubs(db, user.id);
  return { lifetime: !!user.lifetime, trialEnd: user.trial_end, ...subs };
}

/** Load everything needed to evaluate `isPremium` for a user id. */
export async function getPremiumInputs(db: D1Database, userId: number): Promise<PremiumInputs> {
  const user = await getUserById(db, userId);
  const subs = await fetchSubs(db, userId);
  return { lifetime: !!user?.lifetime, trialEnd: user?.trial_end ?? null, ...subs };
}

/** Convenience: fetch + evaluate premium status for a loaded user. */
export async function userIsPremium(db: D1Database, user: UserRow, now: Date = new Date()): Promise<boolean> {
  return isPremium(await premiumInputsForUser(db, user), now);
}

/** Faithful User.in_trial(): NOT lifetime/active subscription AND simple trial. */
export async function userInTrial(db: D1Database, user: UserRow, now: Date = new Date()): Promise<boolean> {
  const subs = await premiumInputsForUser(db, user);
  if (lifetimeOrActiveSubscription(subs, now)) return false;
  return inTrial(user, now);
}

/**
 * User.can_create_new_alias() / can_create_num_aliases(1) (models.py L973).
 * Trashed aliases (delete_on set) do not count; the free cap applies during trial.
 */
export async function canCreateNewAlias(
  db: D1Database,
  env: Env,
  user: UserRow,
  now: Date = new Date(),
): Promise<boolean> {
  if (!isActive(user, now)) return false;
  if (user.disabled) return false;
  const subs = await premiumInputsForUser(db, user);
  if (lifetimeOrActiveSubscription(subs, now)) return true;
  const row = await db
    .prepare("SELECT COUNT(*) AS n FROM alias WHERE user_id = ?1 AND delete_on IS NULL")
    .bind(user.id)
    .first<{ n: number }>();
  const count = row?.n ?? 0;
  return count + 1 <= maxAliasForFreeAccount(user, env);
}

/**
 * User.get_sl_domains() with default AliasOptions (models.py L1194):
 * hidden=0 AND ( (default public domain, premium-gated) OR (partner_id IS NULL,
 * premium-gated) ). Partner-domain branch is skipped (show_partner_domains
 * defaults to None). Ordered by "order".
 */
export async function getSLDomains(
  db: D1Database,
  user: UserRow,
  _env: Env,
  now: Date = new Date(),
): Promise<PublicDomainRow[]> {
  const premium = await userIsPremium(db, user, now);
  const orConds: string[] = [];
  const params: unknown[] = [];

  if (user.default_alias_public_domain_id !== null) {
    if (premium) {
      orConds.push("(id = ?)");
    } else {
      orConds.push("(id = ? AND premium_only = 0)");
    }
    params.push(user.default_alias_public_domain_id);
  }
  // show_sl_domains defaults to true.
  orConds.push(premium ? "(partner_id IS NULL)" : "(partner_id IS NULL AND premium_only = 0)");

  const sql = `SELECT * FROM public_domain WHERE hidden = 0 AND (${orConds.join(" OR ")}) ORDER BY "order"`;
  const res = await db
    .prepare(sql)
    .bind(...params)
    .all<PublicDomainRow>();
  return res.results;
}

/**
 * available_sl_email() (models.py L1557): an address is free iff it is not an
 * alias email, not a contact reply_email, and not a deleted_alias email.
 */
export async function availableSlEmail(db: D1Database, email: string): Promise<boolean> {
  const alias = await db.prepare("SELECT 1 FROM alias WHERE email = ?1 LIMIT 1").bind(email).first();
  if (alias) return false;
  const contact = await db.prepare("SELECT 1 FROM contact WHERE reply_email = ?1 LIMIT 1").bind(email).first();
  if (contact) return false;
  const deleted = await db.prepare("SELECT 1 FROM deleted_alias WHERE email = ?1 LIMIT 1").bind(email).first();
  if (deleted) return false;
  return true;
}

/**
 * User.default_random_alias_domain() (models.py L1104). Fallback is
 * FIRST_ALIAS_DOMAIN || EMAIL_DOMAIN. Replicates the Flask side effect of
 * clearing the default domain when a non-premium user points at a premium one.
 */
export async function defaultRandomAliasDomain(
  db: D1Database,
  user: UserRow,
  env: Env,
  now: Date = new Date(),
): Promise<string> {
  const firstAliasDomain = env.FIRST_ALIAS_DOMAIN || env.EMAIL_DOMAIN;

  if (user.default_alias_custom_domain_id) {
    const cd = await getCustomDomainById(db, user.default_alias_custom_domain_id);
    if (!cd || !cd.verified || cd.user_id !== user.id) return firstAliasDomain;
    return cd.domain;
  }

  if (user.default_alias_public_domain_id) {
    const sl = await getPublicDomainById(db, user.default_alias_public_domain_id);
    if (!sl) return firstAliasDomain;
    if (sl.premium_only && !(await userIsPremium(db, user, now))) {
      await db
        .prepare(
          `UPDATE users SET default_alias_custom_domain_id = NULL,
             default_alias_public_domain_id = NULL, updated_at = ?1 WHERE id = ?2`,
        )
        .bind(nowStr(), user.id)
        .run();
      return firstAliasDomain;
    }
    return sl.domain;
  }

  return firstAliasDomain;
}

// ---- small typed query helpers used across routes ----

export function getUserById(db: D1Database, id: number): Promise<UserRow | null> {
  return db.prepare("SELECT * FROM users WHERE id = ?1").bind(id).first<UserRow>();
}

export function getAliasById(db: D1Database, id: number): Promise<AliasRow | null> {
  return db.prepare("SELECT * FROM alias WHERE id = ?1").bind(id).first<AliasRow>();
}

export function getMailboxById(db: D1Database, id: number): Promise<MailboxRow | null> {
  return db.prepare("SELECT * FROM mailbox WHERE id = ?1").bind(id).first<MailboxRow>();
}

export function getContactById(db: D1Database, id: number): Promise<ContactRow | null> {
  return db.prepare("SELECT * FROM contact WHERE id = ?1").bind(id).first<ContactRow>();
}

export function getCustomDomainById(db: D1Database, id: number): Promise<CustomDomainRow | null> {
  return db.prepare("SELECT * FROM custom_domain WHERE id = ?1").bind(id).first<CustomDomainRow>();
}

export function getPublicDomainById(db: D1Database, id: number): Promise<PublicDomainRow | null> {
  return db.prepare("SELECT * FROM public_domain WHERE id = ?1").bind(id).first<PublicDomainRow>();
}

/**
 * Mailbox ids for an alias, primary (alias.mailbox_id) first, then the
 * additional alias_mailbox rows (id-ordered), deduped.
 */
export async function aliasMailboxIds(db: D1Database, aliasId: number): Promise<number[]> {
  const alias = await getAliasById(db, aliasId);
  if (!alias) return [];
  const rows = await db
    .prepare("SELECT mailbox_id FROM alias_mailbox WHERE alias_id = ?1 ORDER BY id")
    .bind(aliasId)
    .all<{ mailbox_id: number }>();
  const ids = [alias.mailbox_id];
  for (const r of rows.results) if (!ids.includes(r.mailbox_id)) ids.push(r.mailbox_id);
  return ids;
}

/** All verified mailboxes for a user, email-sorted. */
export async function userVerifiedMailboxes(db: D1Database, userId: number): Promise<MailboxRow[]> {
  const res = await db
    .prepare("SELECT * FROM mailbox WHERE user_id = ?1 AND verified = 1 ORDER BY email")
    .bind(userId)
    .all<MailboxRow>();
  return res.results;
}
