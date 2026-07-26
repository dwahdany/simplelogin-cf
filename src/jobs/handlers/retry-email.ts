/**
 * JOB 'retry-email' handler — transient-send retry for the rewrite
 * forward/reply path (scheduled by src/email.ts scheduleEmailRetry).
 *
 * Deviation with no Flask equivalent: Flask hands a transient SMTP failure to
 * the Postfix queue, which retries on its own backoff for days and emits a
 * bounce DSN when it gives up (that DSN then drives handle_bounce over VERP).
 * This platform has no MTA queue, so the fully-built outbound message is
 * stashed in KV ("retry:<uuid>", 7-day TTL) and re-sent here.
 *
 * Retry policy — deliberately explicit, NOT the dispatcher's generic
 * 30-min/5-attempt retry: every attempt is its own job row. A send failure is
 * caught HERE and the next attempt is enqueued with a growing run_at
 * (RETRY_EMAIL_BACKOFF_MINS: 5m/30m/2h/12h/24h before attempts 1-5), then the
 * handler returns normally so the current row always goes state=done. After
 * the final failed attempt the Flask handle_bounce side effects run
 * (handleBounceForwardPhase / handleBounceReplyPhase: email_log.bounced +
 * bounced_mailbox_id, Bounce row, Notification row, rate-controlled
 * ALERT_BOUNCE_EMAIL / ALERT_BOUNCE_EMAIL_REPLY_PHASE alert) — exactly what a
 * Postfix queue-lifetime bounce would have triggered through VERP — and the
 * KV stash is deleted. Only an unexpected error (e.g. D1 unavailable) escapes
 * to the dispatcher's generic retry, which re-runs the same attempt: the
 * stash is still there and re-sending is at-least-once, like an MTA queue.
 */

import {
  enqueueRetryEmailJob,
  handleBounceForwardPhase,
  handleBounceReplyPhase,
  RETRY_EMAIL_BACKOFF_MINS,
  RETRY_EMAIL_MAX_ATTEMPTS,
  type RetryEmailPayload,
  sendRawEmail,
  userIsActiveRow,
} from "../../email";
import type { Env } from "../../lib/env";
import { getUserById } from "../../lib/models";
import type { EmailLogRow } from "../../lib/rows";
import type { JobRow } from "../index";

export async function handleRetryEmail(
  env: Env,
  payload: Record<string, unknown>,
  _job: JobRow,
): Promise<void> {
  const kvKey = typeof payload.kv_key === "string" ? payload.kv_key : null;
  const to = typeof payload.to === "string" ? payload.to : null;
  const envelopeFrom =
    typeof payload.envelope_from === "string" ? payload.envelope_from : "";
  if (!kvKey || !to) return; // malformed payload: nothing actionable

  // Defensive: a payload without a sane counter must not retry forever —
  // treat it as the final attempt.
  const attempt =
    typeof payload.attempt === "number" &&
    Number.isInteger(payload.attempt) &&
    payload.attempt >= 1
      ? payload.attempt
      : RETRY_EMAIL_MAX_ATTEMPTS;

  // Stash gone: the 7-day TTL expired, or a duplicate run already delivered
  // and cleaned up — nothing left to send, the job completes silently.
  const raw = await env.KV.get(kvKey, "arrayBuffer");
  if (!raw) return;

  try {
    await sendRawEmail(env, envelopeFrom, to, new Uint8Array(raw));
  } catch (e) {
    console.error(
      `retry-email: attempt ${attempt}/${RETRY_EMAIL_MAX_ATTEMPTS} to ${to} failed:`,
      e,
    );
    if (attempt < RETRY_EMAIL_MAX_ATTEMPTS) {
      // The delay before attempt N is RETRY_EMAIL_BACKOFF_MINS[N-1].
      await enqueueRetryEmailJob(
        env.DB,
        { ...(payload as unknown as RetryEmailPayload), attempt: attempt + 1 },
        RETRY_EMAIL_BACKOFF_MINS[attempt] ??
          RETRY_EMAIL_BACKOFF_MINS[RETRY_EMAIL_BACKOFF_MINS.length - 1],
      );
      return; // this row goes state=done; the new row carries the next attempt
    }
    await notifyFinalFailure(env, payload);
    await env.KV.delete(kvKey);
    return;
  }
  await env.KV.delete(kvKey);
}

/**
 * The backoff is exhausted: run the bounce-path side effects on the retried
 * delivery's EmailLog, like the DSN a real MTA queue emits when it gives up.
 */
async function notifyFinalFailure(
  env: Env,
  payload: Record<string, unknown>,
): Promise<void> {
  const id = payload.email_log_id;
  if (typeof id !== "number") return;
  const emailLog = await env.DB.prepare("SELECT * FROM email_log WHERE id = ?1")
    .bind(id)
    .first<EmailLogRow>();
  if (!emailLog) return; // log deleted since (e.g. alias removed): drop silently
  // handle_bounce parity: no side effects for a soft-deleted user (the
  // inbound bounce paths reject those with E510).
  const user = await getUserById(env.DB, emailLog.user_id);
  if (user && !userIsActiveRow(user)) return;
  if (emailLog.is_reply) await handleBounceReplyPhase(env.DB, env, emailLog);
  else await handleBounceForwardPhase(env.DB, env, emailLog);
}
