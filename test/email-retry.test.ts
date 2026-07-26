/**
 * Transient-send retry (src/email.ts scheduleEmailRetry + the 'retry-email'
 * job in src/jobs/handlers/retry-email.ts). Deviation with no Flask
 * equivalent — Flask hands transient SMTP failures to the Postfix queue:
 * a send_email binding failure on a fully-built forward/reply stashes the
 * message in KV ("retry:<uuid>", 7-day TTL), enqueues a 'retry-email' job a
 * few minutes out and ACCEPTS the inbound message; the job re-sends through
 * sendRawEmail, re-enqueues itself on a 5m/30m/2h/12h/24h backoff (each
 * attempt its own job row ending state=done) and, once the 5 attempts are
 * exhausted, runs the bounce-path side effects and deletes the stash.
 *
 * Helper functions are duplicated from test/email.test.ts (they are file
 * local there and this file is owned by a different work stream).
 */

import {
  createExecutionContext,
  env,
  waitOnExecutionContext,
} from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { handleEmail, outboundEmails } from "../src/email";
import {
  JOB_STATE_DONE,
  JOB_STATE_READY,
  type JobRow,
  runPendingJobs,
} from "../src/jobs";
import { nowStr, toDate, toStr } from "../src/lib/dates";
import type { Env } from "../src/lib/env";
import { sentEmails } from "../src/lib/mailer";
import type { ContactRow, EmailLogRow, MailboxRow } from "../src/lib/rows";
import {
  createAlias,
  createContact,
  createEmailLog,
  createUser,
} from "./fixtures";

let seq = 0;
const uniq = () => ++seq;

// ---------------------------- helpers ------------------------------------

interface RecordedForward {
  to: string;
  headers: Record<string, string>;
}

interface MockMessage extends ForwardableEmailMessage {
  forwards: RecordedForward[];
  rejectReason: string | null;
}

function makeMessage(opts: {
  from: string;
  to: string;
  raw: string;
}): MockMessage {
  const rawBytes = new TextEncoder().encode(opts.raw);
  const headers = new Headers();
  let lastName: string | null = null;
  for (const line of opts.raw.split(/\r?\n\r?\n/)[0].split(/\r?\n/)) {
    if (!line) continue;
    if ((line.startsWith(" ") || line.startsWith("\t")) && lastName) {
      headers.set(lastName, `${headers.get(lastName)} ${line.trim()}`);
      continue;
    }
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    lastName = line.slice(0, colon).trim();
    headers.append(lastName, line.slice(colon + 1).trim());
  }

  const mock = {
    from: opts.from,
    to: opts.to,
    headers,
    rawSize: rawBytes.length,
    raw: new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(rawBytes);
        controller.close();
      },
    }),
    forwards: [] as RecordedForward[],
    rejectReason: null as string | null,
    setReject(reason: string) {
      mock.rejectReason = reason;
    },
    async forward(rcptTo: string, fwHeaders?: Headers) {
      const recorded: Record<string, string> = {};
      if (fwHeaders) for (const [k, v] of fwHeaders.entries()) recorded[k] = v;
      mock.forwards.push({ to: rcptTo, headers: recorded });
      return { messageId: "mock-forward" };
    },
    async reply() {
      return { messageId: "mock-reply" };
    },
  };
  return mock as unknown as MockMessage;
}

function buildRaw(headers: [string, string][], body = "test body\r\n"): string {
  return `${headers.map(([k, v]) => `${k}: ${v}`).join("\r\n")}\r\n\r\n${body}`;
}

async function deliver(message: MockMessage, testEnv: Env = env) {
  const ctx = createExecutionContext();
  await handleEmail(message, testEnv, ctx);
  await waitOnExecutionContext(ctx);
}

function envWithSendMock(): {
  testEnv: Env;
  sends: { from: string; to: string }[];
} {
  const sends: { from: string; to: string }[] = [];
  const mock = {
    send: async (m: EmailMessage) => {
      sends.push({ from: m.from, to: m.to });
    },
  } as unknown as SendEmail;
  return { testEnv: { ...env, SEND_EMAIL: mock }, sends };
}

/** Env whose SEND_EMAIL binding always fails (SMTP error during send). */
function envWithFailingSend(): Env {
  const mock = {
    send: async () => {
      throw new Error("smtp down");
    },
  } as unknown as SendEmail;
  return { ...env, SEND_EMAIL: mock };
}

function one<T>(sql: string, ...binds: unknown[]): Promise<T | null> {
  return env.DB.prepare(sql)
    .bind(...binds)
    .first<T>();
}

async function count(sql: string, ...binds: unknown[]): Promise<number> {
  const row = await env.DB.prepare(sql)
    .bind(...binds)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

async function forwardSetup(userOverrides: Record<string, unknown> = {}) {
  const user = await createUser(env.DB, userOverrides);
  const mailbox = await one<MailboxRow>(
    "SELECT * FROM mailbox WHERE id = ?1",
    user.default_mailbox_id,
  );
  if (!mailbox) throw new Error("fixture mailbox missing");
  const alias = await createAlias(env.DB, user.id, mailbox.id);
  return { user, mailbox, alias };
}

/** Reply-phase fixture: alias on EMAIL_DOMAIN (registered as an SLDomain). */
async function replySetup() {
  const user = await createUser(env.DB);
  const mailbox = await one<MailboxRow>(
    "SELECT * FROM mailbox WHERE id = ?1",
    user.default_mailbox_id,
  );
  if (!mailbox) throw new Error("fixture mailbox missing");
  await env.DB.prepare(
    "INSERT OR IGNORE INTO public_domain (domain) VALUES ('sl.example.com')",
  ).run();
  const n = uniq();
  const alias = await createAlias(env.DB, user.id, mailbox.id, {
    email: `ali${n}@sl.example.com`,
  });
  const contact = await createContact(env.DB, user.id, alias.id, {
    website_email: "friend@remote.example",
    name: "Friend",
    reply_email: `rvrs${n}abc@sl.example.com`,
  });
  return { user, mailbox, alias, contact };
}

interface RetryPayload {
  kv_key: string;
  email_log_id: number;
  phase: string;
  attempt: number;
  envelope_from: string;
  to: string;
}

async function retryJobs(): Promise<(JobRow & { parsed: RetryPayload })[]> {
  const rows = await env.DB.prepare(
    "SELECT * FROM job WHERE name = 'retry-email' ORDER BY id",
  ).all<JobRow>();
  return rows.results.map((r) => ({
    ...r,
    parsed: JSON.parse(r.payload ?? "{}") as RetryPayload,
  }));
}

async function insertRetryJob(
  payload: Record<string, unknown>,
  runAt: string = nowStr(),
): Promise<number> {
  const res = await env.DB.prepare(
    "INSERT INTO job (name, payload, run_at) VALUES ('retry-email', ?1, ?2)",
  )
    .bind(JSON.stringify(payload), runAt)
    .run();
  return res.meta.last_row_id;
}

function getJob(id: number): Promise<JobRow | null> {
  return env.DB.prepare("SELECT * FROM job WHERE id = ?1")
    .bind(id)
    .first<JobRow>();
}

/** Deliver an ordinary inbound forward against a failing binding, so the
 *  rewrite path builds the message and scheduleEmailRetry runs. */
async function failedForward() {
  const setup = await forwardSetup();
  const msg = makeMessage({
    from: "john@wick.example",
    to: setup.alias.email,
    raw: buildRaw([
      ["From", "John Wick <john@wick.example>"],
      ["To", setup.alias.email],
      ["Subject", "retry me"],
      ["Content-Type", "text/plain"],
    ]),
  });
  await deliver(msg, envWithFailingSend());
  const contact = await one<ContactRow>(
    "SELECT * FROM contact WHERE alias_id = ?1",
    setup.alias.id,
  );
  if (!contact) throw new Error("fixture contact missing");
  return { ...setup, msg, contact };
}

beforeEach(async () => {
  sentEmails.length = 0;
  outboundEmails.length = 0;
  await env.DB.prepare("DELETE FROM job").run();
});

// ==================== scheduling (src/email.ts side) ======================

describe("binding failure schedules a retry", () => {
  it("stashes a failed forward in KV and enqueues a retry job (accepted, log kept)", async () => {
    const { msg, mailbox, contact } = await failedForward();

    // Accepted — before this feature the failure became a permanent E407.
    expect(msg.rejectReason).toBeNull();
    // The EmailLog stays as the record of the pending forward, unbounced.
    const log = await one<EmailLogRow>(
      "SELECT * FROM email_log WHERE contact_id = ?1",
      contact.id,
    );
    expect(log).not.toBeNull();
    expect(log?.bounced).toBe(0);
    expect(log?.mailbox_id).toBe(mailbox.id);

    const jobs = await retryJobs();
    expect(jobs).toHaveLength(1);
    expect(jobs[0].state).toBe(JOB_STATE_READY);
    const p = jobs[0].parsed;
    expect(p.phase).toBe("forward");
    expect(p.attempt).toBe(1);
    expect(p.email_log_id).toBe(log?.id);
    expect(p.to).toBe(mailbox.email);
    expect(p.kv_key.startsWith("retry:")).toBe(true);
    // Flask-parity VERP envelope kept as payload metadata.
    expect(p.envelope_from.startsWith("sl.")).toBe(true);
    // run_at "a few minutes out": first backoff step is 5 minutes.
    const runAt = toDate(jobs[0].run_at ?? "").getTime();
    expect(runAt).toBeGreaterThan(Date.now() + 3 * 60_000);
    expect(runAt).toBeLessThan(Date.now() + 7 * 60_000);

    // The stash is the fully-built rewrite-mode forward (reverse-alias From).
    const stash = await env.KV.get(p.kv_key, "text");
    expect(stash).not.toBeNull();
    expect(stash).toContain("X-SimpleLogin-Type: Forward");
    expect(stash).toContain(contact.reply_email);
    expect(stash).toContain("Subject: retry me");
  });

  it("stashes a failed reply without warning the mailbox (retry replaces the warning)", async () => {
    const { user, mailbox, alias, contact } = await replySetup();
    const msg = makeMessage({
      from: user.email,
      to: contact.reply_email,
      raw: buildRaw([
        ["From", user.email],
        ["To", contact.reply_email],
        ["Subject", "re: hello"],
      ]),
    });
    await deliver(msg, envWithFailingSend());

    expect(msg.rejectReason).toBeNull();
    // Pre-retry behavior deleted the log and told the user to retry by hand;
    // now the log survives and the warning is deferred to the final attempt.
    const log = await one<EmailLogRow>(
      "SELECT * FROM email_log WHERE contact_id = ?1",
      contact.id,
    );
    expect(log).not.toBeNull();
    expect(log?.is_reply).toBe(1);
    expect(log?.mailbox_id).toBe(mailbox.id);
    expect(
      sentEmails.some((e) => e.subject.startsWith("Email cannot be sent")),
    ).toBe(false);

    const jobs = await retryJobs();
    expect(jobs).toHaveLength(1);
    const p = jobs[0].parsed;
    expect(p.phase).toBe("reply");
    expect(p.attempt).toBe(1);
    expect(p.email_log_id).toBe(log?.id);
    expect(p.to).toBe(contact.website_email);
    expect(await env.KV.get(p.kv_key, "text")).toContain(
      `From: ${alias.email}`,
    );
  });
});

// ======================== the 'retry-email' job ===========================

describe("retry-email job", () => {
  it("re-sends the stashed message on a healed binding and cleans up", async () => {
    const { mailbox, contact } = await failedForward();
    const [job] = await retryJobs();
    outboundEmails.length = 0;

    const { testEnv, sends } = envWithSendMock();
    expect(await runPendingJobs(testEnv)).toBe(1);

    // Delivered through the same sendRawEmail path (binding From = the
    // reverse alias re-derived from the stashed From header).
    expect(sends).toHaveLength(1);
    expect(sends[0].to).toBe(mailbox.email);
    expect(sends[0].from).toBe(contact.reply_email);
    const out = outboundEmails.at(-1);
    expect(out?.to).toBe(mailbox.email);
    expect(out?.envelopeFrom).toBe(job.parsed.envelope_from);
    expect(out?.raw).toContain("Subject: retry me");

    expect((await getJob(job.id))?.state).toBe(JOB_STATE_DONE);
    expect(await env.KV.get(job.parsed.kv_key)).toBeNull();
    expect(await retryJobs()).toHaveLength(1); // no follow-up row
  });

  it("re-enqueues itself with the 30-min backoff when the send fails again", async () => {
    const { contact } = await failedForward();
    const [job] = await retryJobs();

    // The handler catches its own failure and returns normally: the row goes
    // state=done (NOT the dispatcher's taken/30-min generic retry).
    expect(await runPendingJobs(envWithFailingSend())).toBe(1);
    expect((await getJob(job.id))?.state).toBe(JOB_STATE_DONE);

    const jobs = await retryJobs();
    expect(jobs).toHaveLength(2);
    const next = jobs[1];
    expect(next.state).toBe(JOB_STATE_READY);
    expect(next.parsed.attempt).toBe(2);
    expect(next.parsed.kv_key).toBe(job.parsed.kv_key);
    const runAt = toDate(next.run_at ?? "").getTime();
    expect(runAt).toBeGreaterThan(Date.now() + 25 * 60_000);
    expect(runAt).toBeLessThan(Date.now() + 35 * 60_000);
    // Stash survives for the next attempt; nothing bounced yet.
    expect(await env.KV.get(job.parsed.kv_key)).not.toBeNull();
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM email_log WHERE contact_id = ?1 AND bounced = 1",
        contact.id,
      ),
    ).toBe(0);
    // +30m is outside the dispatcher's +10min pickup window.
    expect(await runPendingJobs(envWithFailingSend())).toBe(0);
  });

  it("runs the forward-phase bounce path after the final failed attempt", async () => {
    const { user, mailbox, alias } = await forwardSetup();
    const contact = await createContact(env.DB, user.id, alias.id, {
      website_email: "john@wick.example",
    });
    const emailLog = await createEmailLog(env.DB, user.id, contact.id, {
      mailbox_id: mailbox.id,
    });
    const kvKey = `retry:exhausted-fwd-${uniq()}`;
    await env.KV.put(kvKey, buildRaw([["From", contact.reply_email]]));
    const jobId = await insertRetryJob({
      kv_key: kvKey,
      email_log_id: emailLog.id,
      phase: "forward",
      attempt: 5,
      envelope_from: "sl.x.y@sl.example.com",
      to: mailbox.email,
    });

    expect(await runPendingJobs(envWithFailingSend())).toBe(1);

    expect((await getJob(jobId))?.state).toBe(JOB_STATE_DONE);
    expect(await retryJobs()).toHaveLength(1); // no 6th attempt
    expect(await env.KV.get(kvKey)).toBeNull();
    // Flask handle_bounce_forward_phase side effects (what a Postfix
    // queue-lifetime bounce would have triggered through VERP).
    const after = await one<EmailLogRow>(
      "SELECT * FROM email_log WHERE id = ?1",
      emailLog.id,
    );
    expect(after?.bounced).toBe(1);
    expect(after?.bounced_mailbox_id).toBe(mailbox.id);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM bounce WHERE email = ?1",
        mailbox.email,
      ),
    ).toBe(1);
    const title = `Email from ${contact.website_email} to ${alias.email} cannot be delivered to ${mailbox.email}`;
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM notification WHERE user_id = ?1 AND title = ?2",
        user.id,
        title,
      ),
    ).toBe(1);
    expect(
      sentEmails.some(
        (e) =>
          e.subject ===
            `An email sent to ${alias.email} cannot be delivered to your mailbox` &&
          e.to === user.email,
      ),
    ).toBe(true);
  });

  it("runs the reply-phase bounce path (alert to the sending mailbox) when exhausted", async () => {
    const { user, mailbox, alias, contact } = await replySetup();
    const emailLog = await createEmailLog(env.DB, user.id, contact.id, {
      mailbox_id: mailbox.id,
      is_reply: 1,
    });
    const kvKey = `retry:exhausted-reply-${uniq()}`;
    await env.KV.put(kvKey, buildRaw([["From", alias.email]]));
    const jobId = await insertRetryJob({
      kv_key: kvKey,
      email_log_id: emailLog.id,
      phase: "reply",
      attempt: 5,
      envelope_from: "sl.x.y@sl.example.com",
      to: contact.website_email,
    });

    expect(await runPendingJobs(envWithFailingSend())).toBe(1);

    expect((await getJob(jobId))?.state).toBe(JOB_STATE_DONE);
    expect(await env.KV.get(kvKey)).toBeNull();
    const after = await one<EmailLogRow>(
      "SELECT * FROM email_log WHERE id = ?1",
      emailLog.id,
    );
    expect(after?.bounced).toBe(1);
    expect(after?.bounced_mailbox_id).toBe(mailbox.id);
    // Bounce row is for the contact's real address, not the mailbox.
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM bounce WHERE email = ?1",
        contact.website_email,
      ),
    ).toBe(1);
    const title = `Email cannot be sent to ${contact.website_email} from your alias ${alias.email}`;
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM notification WHERE user_id = ?1 AND title = ?2",
        user.id,
        title,
      ),
    ).toBe(1);
    // reply-phase alert goes to the sending mailbox, not the user address.
    expect(
      sentEmails.some((e) => e.subject === title && e.to === mailbox.email),
    ).toBe(true);
  });

  it("skips the bounce side effects for a soft-deleted user (E510 parity)", async () => {
    const future = toStr(new Date(Date.now() + 30 * 86400 * 1000));
    const { user, mailbox, alias } = await forwardSetup({ delete_on: future });
    const contact = await createContact(env.DB, user.id, alias.id);
    const emailLog = await createEmailLog(env.DB, user.id, contact.id, {
      mailbox_id: mailbox.id,
    });
    const kvKey = `retry:soft-deleted-${uniq()}`;
    await env.KV.put(kvKey, buildRaw([["From", contact.reply_email]]));
    const jobId = await insertRetryJob({
      kv_key: kvKey,
      email_log_id: emailLog.id,
      phase: "forward",
      attempt: 5,
      envelope_from: "sl.x.y@sl.example.com",
      to: mailbox.email,
    });

    expect(await runPendingJobs(envWithFailingSend())).toBe(1);

    expect((await getJob(jobId))?.state).toBe(JOB_STATE_DONE);
    expect(await env.KV.get(kvKey)).toBeNull();
    const after = await one<EmailLogRow>(
      "SELECT * FROM email_log WHERE id = ?1",
      emailLog.id,
    );
    expect(after?.bounced).toBe(0);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM bounce WHERE email = ?1",
        mailbox.email,
      ),
    ).toBe(0);
    expect(sentEmails).toHaveLength(0);
  });

  it("completes silently when the KV stash is gone (7-day TTL expired)", async () => {
    const jobId = await insertRetryJob({
      kv_key: `retry:expired-${uniq()}`,
      email_log_id: 12345,
      phase: "forward",
      attempt: 2,
      envelope_from: "sl.x.y@sl.example.com",
      to: "someone@mailbox.example",
    });

    const { testEnv, sends } = envWithSendMock();
    expect(await runPendingJobs(testEnv)).toBe(1);

    expect((await getJob(jobId))?.state).toBe(JOB_STATE_DONE);
    expect(sends).toHaveLength(0);
    expect(await retryJobs()).toHaveLength(1); // no re-enqueue either
    expect(sentEmails).toHaveLength(0);
  });
});
