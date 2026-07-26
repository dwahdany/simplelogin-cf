/**
 * D1-backed port of the Flask job runner (job_runner.py), driven by a cron
 * `scheduled()` trigger instead of a long-running process.
 *
 * Claim semantics match get_jobs_to_run_query / take_job (job_runner.py:315-368):
 * - runnable: state == ready OR (state == taken AND taken_at < now - 30 min
 *   AND attempts < JOB_MAX_ATTEMPTS), AND (run_at IS NULL OR run_at <= now + 10 min)
 * - ordered by priority DESC then run_at ASC, max 50 per batch
 * - claim is an atomic conditional UPDATE (state -> taken, attempts += 1)
 * - handler success -> state = done; handler error -> stays taken for the
 *   30-min retry, or state = error once attempts >= JOB_MAX_ATTEMPTS
 */

import { addMinutes, nowStr, toStr } from "../lib/dates";
import type { Env } from "../lib/env";
import { handleBatchImport } from "./handlers/batch-import";
import { handleDeleteAccount } from "./handlers/delete-account";
import { handleDeleteDomain } from "./handlers/delete-domain";
import { handleDeleteMailbox } from "./handlers/delete-mailbox";
import {
  handleOnboarding1,
  handleOnboarding2,
  handleOnboarding4,
} from "./handlers/onboarding";
import { handleRetryEmail } from "./handlers/retry-email";
import { handleSendUserReport } from "./handlers/send-user-report";

export const JOB_STATE_READY = 0;
export const JOB_STATE_TAKEN = 1;
export const JOB_STATE_DONE = 2;
export const JOB_STATE_ERROR = 3;

const JOB_MAX_ATTEMPTS = 5; // config.JOB_MAX_ATTEMPTS
const JOB_TAKEN_RETRY_WAIT_MINS = 30; // config.JOB_TAKEN_RETRY_WAIT_MINS
const MAX_JOBS_PER_BATCH = 50; // job_runner._MAX_JOBS_PER_BATCH

export interface JobRow {
  id: number;
  created_at: string;
  updated_at: string | null;
  name: string;
  payload: string | null;
  taken: number;
  run_at: string | null;
  state: number;
  attempts: number;
  taken_at: string | null;
  priority: number;
}

export type JobHandler = (
  env: Env,
  payload: Record<string, unknown>,
  job: JobRow,
) => Promise<void>;

/** Job names as enqueued by the web/API layers (config.JOB_* in Flask). */
export const jobHandlers: Record<string, JobHandler> = {
  "batch-import": handleBatchImport,
  "delete-mailbox": handleDeleteMailbox,
  "delete-domain": handleDeleteDomain,
  "delete-account": handleDeleteAccount,
  "send-user-report": handleSendUserReport,
  "onboarding-1": handleOnboarding1,
  "onboarding-2": handleOnboarding2,
  "onboarding-4": handleOnboarding4,
  // No Flask job counterpart (transient-send retry deviation, src/email.ts):
  // the handler catches its own send failures and re-enqueues follow-up rows
  // on its own 5m/30m/2h/12h/24h backoff, so each row normally ends done and
  // the generic 30-min retry above only covers unexpected handler errors.
  "retry-email": handleRetryEmail,
};

/** One job_runner.execute() pass: claim and run due jobs. Returns #done. */
export async function runPendingJobs(env: Env): Promise<number> {
  const now = new Date();
  const takenBefore = toStr(addMinutes(now, -JOB_TAKEN_RETRY_WAIT_MINS));
  const runAtLatest = toStr(addMinutes(now, 10));

  const due = await env.DB.prepare(
    `SELECT * FROM job
      WHERE (state = ${JOB_STATE_READY}
             OR (state = ${JOB_STATE_TAKEN} AND taken_at < ?1 AND attempts < ${JOB_MAX_ATTEMPTS}))
        AND (run_at IS NULL OR run_at <= ?2)
      ORDER BY priority DESC, run_at ASC
      LIMIT ${MAX_JOBS_PER_BATCH}`,
  )
    .bind(takenBefore, runAtLatest)
    .all<JobRow>();

  let done = 0;
  for (const job of due.results) {
    // take_job: conditional claim so concurrent cron invocations don't
    // double-run (rowcount check == Flask's res.rowcount > 0).
    const claim = await env.DB.prepare(
      `UPDATE job SET taken_at = ?1, attempts = attempts + 1, state = ${JOB_STATE_TAKEN}, updated_at = ?1
        WHERE id = ?2
          AND (state = ${JOB_STATE_READY} OR (state = ${JOB_STATE_TAKEN} AND taken_at < ?3))`,
    )
      .bind(nowStr(), job.id, takenBefore)
      .run();
    if (!claim.meta.changes) continue;

    const handler = jobHandlers[job.name];
    if (!handler) {
      // Flask LOG.e("Unknown job name") and leaves the job; it would retry
      // forever — here it goes through the same attempts/error path.
      console.error(`Unknown job name ${job.name} (id=${job.id})`);
    }
    try {
      if (!handler) throw new Error(`Unknown job name ${job.name}`);
      const payload = job.payload
        ? (JSON.parse(job.payload) as Record<string, unknown>)
        : {};
      await handler(env, payload, job);
      await env.DB.prepare(
        `UPDATE job SET state = ${JOB_STATE_DONE}, updated_at = ?1 WHERE id = ?2`,
      )
        .bind(nowStr(), job.id)
        .run();
      done += 1;
    } catch (e) {
      console.error(`Error processing job (id=${job.id} name=${job.name})`, e);
      if (job.attempts + 1 >= JOB_MAX_ATTEMPTS) {
        await env.DB.prepare(
          `UPDATE job SET state = ${JOB_STATE_ERROR}, updated_at = ?1 WHERE id = ?2`,
        )
          .bind(nowStr(), job.id)
          .run();
      }
      // else: stays taken; retried after JOB_TAKEN_RETRY_WAIT_MINS
    }
  }
  return done;
}
