/**
 * Transactional email seam (activation codes, reset links, mailbox
 * verification...). Routes call `sendTransactionalEmail`; delivery goes
 * through the `SEND_EMAIL` binding when it is bound, otherwise the message is
 * only logged. Every message is also pushed to `sentEmails` so tests can
 * assert on what would have been sent (vitest-pool-workers runs tests and the
 * worker in the same isolate, so the array is shared with SELF.fetch calls).
 */

import type { Env } from "./env";

export interface OutgoingEmail {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

const MAX_CAPTURED = 200;

/** Sent messages, oldest first. Tests may truncate it between cases. */
export const sentEmails: OutgoingEmail[] = [];

function buildMime(from: string, msg: OutgoingEmail): string {
  const headers = [
    `From: ${from}`,
    `To: ${msg.to}`,
    `Subject: ${msg.subject}`,
    `Message-ID: <${crypto.randomUUID()}@${from.split("@")[1]}>`,
    `Date: ${new Date().toUTCString()}`,
    "MIME-Version: 1.0",
  ];
  if (msg.html) {
    const boundary = `b-${crypto.randomUUID()}`;
    return [
      ...headers,
      `Content-Type: multipart/alternative; boundary="${boundary}"`,
      "",
      `--${boundary}`,
      'Content-Type: text/plain; charset="utf-8"',
      "Content-Transfer-Encoding: 8bit",
      "",
      msg.text,
      `--${boundary}`,
      'Content-Type: text/html; charset="utf-8"',
      "Content-Transfer-Encoding: 8bit",
      "",
      msg.html,
      `--${boundary}--`,
      "",
    ].join("\r\n");
  }
  return [
    ...headers,
    'Content-Type: text/plain; charset="utf-8"',
    "Content-Transfer-Encoding: 8bit",
    "",
    msg.text,
    "",
  ].join("\r\n");
}

/**
 * Fire-and-forget send: a delivery failure is logged, never surfaced to the
 * caller — an activation email that bounces must not turn the API call into
 * a 500 (matches the Flask app, where sends go through a background queue).
 */
export async function sendTransactionalEmail(
  env: Env,
  msg: OutgoingEmail,
): Promise<void> {
  sentEmails.push(msg);
  if (sentEmails.length > MAX_CAPTURED) sentEmails.shift();

  if (!env.SEND_EMAIL) {
    console.log(`[mailer] (unbound) to=${msg.to} subject=${msg.subject}`);
    return;
  }

  const from = `no-reply@${env.EMAIL_DOMAIN}`;
  try {
    const { EmailMessage } = await import("cloudflare:email");
    const raw = buildMime(from, msg);
    await env.SEND_EMAIL.send(new EmailMessage(from, msg.to, raw));
  } catch (e) {
    console.error(`[mailer] send failed to=${msg.to}:`, e);
  }
}
