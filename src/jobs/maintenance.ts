/**
 * Daily maintenance pass (cron "17 3 * * *") — the Workers port of the Flask
 * crontab entries that matter for this deployment (crontab.yml):
 *
 * 1. "SimpleLogin remove aliases in trash" — clear_aliases_pending_to_be_deleted
 *    (cron.py L1243-1245 -> tasks/cleanup_alias.py): purge trashed aliases whose
 *    delete_on has passed, with the perform_alias_deletion bookkeeping
 *    (app/alias_delete.py L89-108): custom-domain aliases land in
 *    domain_deleted_alias, everything else in deleted_alias, then the alias
 *    row is deleted.
 *    DEVIATION: the purge cutoff is `delete_on <= now`. Flask compares
 *    delete_on against `now - ALIAS_TRASH_DAYS` (cron.py L1244) even though
 *    delete_on is already set to trash-time + ALIAS_TRASH_DAYS
 *    (alias_delete.py L123), which silently doubles the advertised grace
 *    window. delete_on is the purge date the dashboard shows the user, so the
 *    rewrite honors it directly.
 * 2. rate_limit trim — no Flask crontab counterpart: Flask keeps limiter and
 *    lock state in Redis with per-key TTLs, while the D1 `rate_limit` table
 *    that replaces it (migrations/0002_rate_limit.sql) never expires rows on
 *    its own and would grow forever. Rows are dropped once their window is
 *    at least RATE_LIMIT_GRACE_SECS in the past; see rateLimitRowExpiry for
 *    the per-key-family window formats.
 * 3. "SimpleLogin Delete Old data" — delete_old_data (cron.py L1226-1230,
 *    KEEP_OLD_DATA_DAYS = 30, config.py L488):
 *    - cleanup_old_notifications (tasks/cleanup_old_notifications.py L9-12)
 *    - cleanup_old_jobs (tasks/cleanup_old_jobs.py L10-24) — matters here
 *      because the D1-backed job runner (src/jobs/index.ts) leaves done rows
 *      behind on every onboarding/report/deletion job.
 *    - cleanup_old_imports is NOT ported: batch-import file storage (S3) is
 *      out of scope (HANDOVER §4).
 *
 * NOT ported from crontab.yml (out of scope, HANDOVER §4): growth stats,
 * monitoring/log trims (delete_logs, delete_old_monitoring), custom-domain
 * re-checks, HIBP, Apple subscription polling, trial/subscription-end
 * notifications, delete_scheduled_users, audit-log trims (the rewrite's
 * audit-log writes are best-effort side tables), send_undelivered_mails.
 * sent_alert is deliberately NOT trimmed: Flask has no sent_alert cleanup and
 * sendAlertAtMostOnce (src/email.ts) relies on rows persisting forever.
 */

import { addDays, toStr } from "../lib/dates";
import type { Env } from "../lib/env";
import type { AliasRow, UserRow } from "../lib/rows";
import { JOB_STATE_DONE, JOB_STATE_ERROR, JOB_STATE_TAKEN } from "./index";

const KEEP_OLD_DATA_DAYS = 30; // config.py L488
const JOB_MAX_ATTEMPTS = 5; // config.JOB_MAX_ATTEMPTS — keep in sync with src/jobs/index.ts
const REQUEST_LOCK_TTL_SECS = 5; // src/lib/ratelimit.ts requestLock TTL
/**
 * Grace before an expired rate-limit row is dropped. The longest window any
 * limiter uses is 1 day ("N/day" specs), so one extra day means a row is only
 * removed once it can no longer influence any limit decision.
 */
const RATE_LIMIT_GRACE_SECS = 86400;
const TRIM_PAGE_SIZE = 500;
const DELETE_CHUNK = 50; // stay well under D1's 100-bound-parameter cap

export async function runMaintenance(env: Env): Promise<void> {
  const now = new Date();
  await purgeTrashedAliases(env.DB, now);
  await trimRateLimitRows(env.DB, now);
  await deleteOldData(env.DB, now);
}

// ---------------------------------------------------------------------------
// 1. trashed-alias purge — tasks/cleanup_alias.py
// ---------------------------------------------------------------------------

/**
 * cleanup_alias (tasks/cleanup_alias.py L10-22): every alias whose delete_on
 * has passed goes through perform_alias_deletion with reason =
 * alias.delete_reason. See the file-top comment for the cutoff deviation.
 */
async function purgeTrashedAliases(db: D1Database, now: Date): Promise<void> {
  const due = await db
    .prepare(
      "SELECT * FROM alias WHERE delete_on IS NOT NULL AND delete_on <= ?1 ORDER BY id",
    )
    .bind(toStr(now))
    .all<AliasRow>();
  for (const alias of due.results) {
    const user = await db
      .prepare("SELECT * FROM users WHERE id = ?1")
      .bind(alias.user_id)
      .first<UserRow>();
    if (!user) continue; // defensive: FK guarantees the user exists
    await performAliasDeletion(db, alias, user, alias.delete_reason ?? 0);
  }
}

// alias hard-delete bookkeeping (duplicated from src/routes/aliases.ts —
// module-private there; hoisting into src/lib is tracked refactor debt).

/** __delete_if_custom_domain (app/alias_delete.py L40-62). */
async function deleteIfCustomDomain(
  db: D1Database,
  alias: AliasRow,
  user: UserRow,
  reason: number,
): Promise<boolean> {
  if (!alias.custom_domain_id) return false;
  const existing = await db
    .prepare(
      "SELECT 1 FROM domain_deleted_alias WHERE email = ?1 AND domain_id = ?2 LIMIT 1",
    )
    .bind(alias.email, alias.custom_domain_id)
    .first();
  if (!existing) {
    await db
      .prepare(
        `INSERT INTO domain_deleted_alias (user_id, email, domain_id, reason, alias_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
      )
      .bind(
        user.id,
        alias.email,
        alias.custom_domain_id,
        reason,
        alias.id,
        toStr(new Date()),
      )
      .run();
  }
  await db.prepare("DELETE FROM alias WHERE id = ?1").bind(alias.id).run();
  return true;
}

/** perform_alias_deletion (app/alias_delete.py L89-108). */
async function performAliasDeletion(
  db: D1Database,
  alias: AliasRow,
  user: UserRow,
  reason: number,
): Promise<void> {
  if (await deleteIfCustomDomain(db, alias, user, reason)) return;
  const existing = await db
    .prepare("SELECT 1 FROM deleted_alias WHERE email = ?1 LIMIT 1")
    .bind(alias.email)
    .first();
  if (!existing) {
    await db
      .prepare(
        "INSERT INTO deleted_alias (email, reason, alias_id, created_at) VALUES (?1, ?2, ?3, ?4)",
      )
      // Python `alias.delete_reason or reason` — 0 (Unspecified) also falls back
      .bind(
        alias.email,
        alias.delete_reason || reason,
        alias.id,
        toStr(new Date()),
      )
      .run();
  }
  await db.prepare("DELETE FROM alias WHERE id = ?1").bind(alias.id).run();
}

// ---------------------------------------------------------------------------
// 2. rate_limit trim
// ---------------------------------------------------------------------------

/**
 * Epoch second after which a rate_limit row can no longer affect any limiter
 * decision, or null when the key shape is unknown (such rows are left alone).
 *
 * Key families in the rate_limit table:
 * - "lock:{subject}:{name}"      — src/lib/ratelimit.ts requestLock:
 *   window_start = acquisition epoch second, 5s TTL; rows are deleted in the
 *   handler's finally block, so only crashed-request leftovers reach us.
 * - "bl:{name}_{secs}:{userId}:{bucketId}" — check_bucket_limit ports
 *   (src/routes/alias-creation.ts, src/web/alias-pages.ts): window_start =
 *   bucket-start epoch second, bucket length embedded in the name segment.
 * - "rl:{name}:{subject}:{secs}", "rlw:{...}:{secs}", "rlweb:{...}:{secs}" —
 *   fixed-window flask-limiter ports (src/lib/ratelimit.ts hitWindow,
 *   src/lib/web/limiter.ts webLimiter, src/web/settings-pages.ts,
 *   src/web/mailbox-domain-pages.ts, src/web/billing-pages.ts): window_start
 *   = floor(epoch / secs), i.e. the window covers
 *   [window_start*secs, (window_start+1)*secs).
 */
export function rateLimitRowExpiry(
  key: string,
  windowStart: number,
): number | null {
  if (key.startsWith("lock:")) return windowStart + REQUEST_LOCK_TTL_SECS;
  if (key.startsWith("bl:")) {
    const m = key.match(/^bl:[^:]*_(\d+):/);
    // unknown bl: shape — assume the longest window used anywhere (1 day)
    return windowStart + (m ? Number(m[1]) : 86400);
  }
  if (/^(rl|rlw|rlweb):/.test(key)) {
    const m = key.match(/:(\d+)$/);
    if (!m) return null;
    return (windowStart + 1) * Number(m[1]);
  }
  return null;
}

async function trimRateLimitRows(db: D1Database, now: Date): Promise<void> {
  const cutoff = Math.floor(now.getTime() / 1000) - RATE_LIMIT_GRACE_SECS;
  let lastKey = "";
  for (;;) {
    const page = await db
      .prepare(
        `SELECT key, window_start FROM rate_limit WHERE key > ?1
         ORDER BY key LIMIT ${TRIM_PAGE_SIZE}`,
      )
      .bind(lastKey)
      .all<{ key: string; window_start: number }>();
    const rows = page.results;
    if (!rows.length) return;
    lastKey = rows[rows.length - 1].key;

    const expired = rows
      .filter((r) => {
        const expiry = rateLimitRowExpiry(r.key, r.window_start);
        return expiry !== null && expiry <= cutoff;
      })
      .map((r) => r.key);
    for (let i = 0; i < expired.length; i += DELETE_CHUNK) {
      const chunk = expired.slice(i, i + DELETE_CHUNK);
      await db
        .prepare(
          `DELETE FROM rate_limit WHERE key IN (${chunk.map((_, j) => `?${j + 1}`).join(", ")})`,
        )
        .bind(...chunk)
        .run();
    }
    if (rows.length < TRIM_PAGE_SIZE) return;
  }
}

// ---------------------------------------------------------------------------
// 3. old-data cleanup — cron.py delete_old_data
// ---------------------------------------------------------------------------

async function deleteOldData(db: D1Database, now: Date): Promise<void> {
  const oldestAllowed = toStr(addDays(now, -KEEP_OLD_DATA_DAYS));

  // cleanup_old_notifications (tasks/cleanup_old_notifications.py L9-12)
  await db
    .prepare("DELETE FROM notification WHERE created_at < ?1")
    .bind(oldestAllowed)
    .run();

  // cleanup_old_jobs (tasks/cleanup_old_jobs.py L10-24): done or error jobs,
  // plus taken jobs that exhausted their attempts, last updated before the
  // cutoff. Ready jobs (updated_at possibly NULL) never match — NULL < x is
  // NULL in SQLite, like in Postgres.
  await db
    .prepare(
      `DELETE FROM job
        WHERE (state = ${JOB_STATE_DONE}
               OR state = ${JOB_STATE_ERROR}
               OR (state = ${JOB_STATE_TAKEN} AND attempts >= ${JOB_MAX_ATTEMPTS}))
          AND updated_at < ?1`,
    )
    .bind(oldestAllowed)
    .run();
}
