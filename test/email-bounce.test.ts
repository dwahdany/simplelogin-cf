/**
 * Inbound DSN / bounce detection under the no-VERP envelope model (HANDOVER
 * §0, src/email.ts handleInboundDsn). Outbound forwards/replies are enveloped
 * with their From address (reverse alias / alias), so downstream bounces come
 * back as ordinary inbound mail with a null or mailer-daemon sender. These
 * tests craft realistic multipart/report DSNs wrapping the original outbound
 * message and assert the Flask handle_bounce side effects (email_log.bounced,
 * Bounce row, Notification row, rate-controlled alert email) plus the
 * documented fall-through for unattributable reports.
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
import { toStr } from "../src/lib/dates";
import type { Env } from "../src/lib/env";
import { sentEmails } from "../src/lib/mailer";
import type { EmailLogRow, MailboxRow } from "../src/lib/rows";
import {
  createAlias,
  createContact,
  createEmailLog,
  createMailbox,
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

/** Read a single header value (case-insensitive, unfolded) from a raw message. */
function rawHeader(raw: string, name: string): string | null {
  const lines = raw.split(/\r?\n\r?\n/)[0].split(/\r?\n/);
  const lower = name.toLowerCase();
  for (let i = 0; i < lines.length; i++) {
    const colon = lines[i].indexOf(":");
    if (colon === -1) continue;
    if (lines[i].slice(0, colon).trim().toLowerCase() !== lower) continue;
    let value = lines[i].slice(colon + 1).trim();
    while (i + 1 < lines.length && /^[ \t]/.test(lines[i + 1]))
      value += ` ${lines[++i].trim()}`;
    return value;
  }
  return null;
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

async function insert<T>(
  table: string,
  values: Record<string, unknown>,
): Promise<T> {
  const cols = Object.keys(values);
  const placeholders = cols.map((_, i) => `?${i + 1}`).join(", ");
  const columnList = cols.map((c) => `"${c}"`).join(", ");
  const row = await env.DB.prepare(
    `INSERT INTO ${table} (${columnList}) VALUES (${placeholders}) RETURNING *`,
  )
    .bind(...cols.map((c) => values[c]))
    .first<T>();
  if (!row) throw new Error(`insert into ${table} returned no row`);
  return row;
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

/**
 * A realistic RFC 3464 delivery report: text/plain human part,
 * message/delivery-status part, and the original message either as a full
 * message/rfc822 part or as a text/rfc822-headers block.
 */
function buildDsnRaw(opts: {
  rcpt: string;
  original?: string;
  originalHeaders?: string;
  headerFrom?: string;
}): string {
  const lines: string[] = [
    "--dsnb",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "The following message could not be delivered to one or more recipients.",
    "--dsnb",
    "Content-Type: message/delivery-status",
    "",
    "Reporting-MTA: dns; mx.remote.example",
    "Final-Recipient: rfc822; dead@mailbox.example",
    "Action: failed",
    "Status: 5.1.1",
  ];
  if (opts.original)
    lines.push("--dsnb", "Content-Type: message/rfc822", "", opts.original);
  if (opts.originalHeaders)
    lines.push(
      "--dsnb",
      "Content-Type: text/rfc822-headers",
      "",
      opts.originalHeaders,
    );
  lines.push("--dsnb--", "");
  return buildRaw(
    [
      [
        "From",
        opts.headerFrom ??
          "Mail Delivery Subsystem <mailer-daemon@mx.remote.example>",
      ],
      ["To", opts.rcpt],
      ["Subject", "Delivery Status Notification (Failure)"],
      ["Message-ID", `<dsn-${uniq()}@mx.remote.example>`],
      [
        "Content-Type",
        'multipart/report; report-type=delivery-status; boundary="dsnb"',
      ],
    ],
    lines.join("\r\n"),
  );
}

/** What a rewrite-mode forward that bounced looked like when it left us. */
function forwardedOriginal(opts: {
  replyEmail: string;
  aliasEmail: string;
  emailLogId?: number;
  messageId?: string;
}): string {
  const headers: [string, string][] = [
    ["From", `"John Wick - john at wick.example" <${opts.replyEmail}>`],
    ["To", opts.aliasEmail],
    ["Subject", "hello"],
    ["Message-ID", opts.messageId ?? `<orig-${uniq()}@wick.example>`],
    ["X-SimpleLogin-Type", "Forward"],
  ];
  if (opts.emailLogId !== undefined)
    headers.push(["X-SimpleLogin-EmailLog-ID", String(opts.emailLogId)]);
  headers.push(["X-SimpleLogin-Envelope-To", opts.aliasEmail]);
  headers.push(["Content-Type", "text/plain"]);
  return buildRaw(headers, "hi there\r\n");
}

beforeEach(() => {
  sentEmails.length = 0;
  outboundEmails.length = 0;
});

// ================== attributed DSNs (bounce side effects) =================

describe("inbound DSN bounces (envelope model)", () => {
  it("attributes a null-sender DSN to the reverse alias (forward-phase bounce)", async () => {
    const { user, mailbox, alias } = await forwardSetup();
    const contact = await createContact(env.DB, user.id, alias.id, {
      website_email: "john@wick.example",
    });
    const emailLog = await createEmailLog(env.DB, user.id, contact.id, {
      mailbox_id: mailbox.id,
    });

    const { testEnv, sends } = envWithSendMock();
    const msg = makeMessage({
      from: "<>",
      to: contact.reply_email,
      raw: buildDsnRaw({
        rcpt: contact.reply_email,
        original: forwardedOriginal({
          replyEmail: contact.reply_email,
          aliasEmail: alias.email,
          emailLogId: emailLog.id,
        }),
      }),
    });
    await deliver(msg, testEnv);

    // Before this feature the message died on the null-sender E206 drop.
    expect(msg.rejectReason).toBeNull();
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
    // rate-controlled ALERT_BOUNCE_EMAIL to the user's account address.
    expect(
      sentEmails.some(
        (e) =>
          e.subject ===
            `An email sent to ${alias.email} cannot be delivered to your mailbox` &&
          e.to === user.email,
      ),
    ).toBe(true);
    // the report itself is consumed: nothing is forwarded or re-sent — the
    // only binding send is the alert email itself (mailbox email == user
    // email for the default fixture mailbox, so assert via the phase seam).
    expect(msg.forwards).toHaveLength(0);
    expect(outboundEmails).toHaveLength(0);
    expect(sends.map((s) => s.to)).toEqual([user.email]);
  });

  it("attributes a mailer-daemon DSN with a non-null envelope sender", async () => {
    const { user, mailbox, alias } = await forwardSetup();
    const contact = await createContact(env.DB, user.id, alias.id);
    const emailLog = await createEmailLog(env.DB, user.id, contact.id, {
      mailbox_id: mailbox.id,
    });

    const msg = makeMessage({
      from: "mailer-daemon@mx.remote.example",
      to: contact.reply_email,
      raw: buildDsnRaw({
        rcpt: contact.reply_email,
        original: forwardedOriginal({
          replyEmail: contact.reply_email,
          aliasEmail: alias.email,
          emailLogId: emailLog.id,
        }),
      }),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBeNull();
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
  });

  it("attributes a reply-phase DSN to the alias and alerts the sending mailbox", async () => {
    const { user, mailbox, alias, contact } = await replySetup();
    const emailLog = await createEmailLog(env.DB, user.id, contact.id, {
      mailbox_id: mailbox.id,
      is_reply: 1,
      sl_message_id: `<${uniq()}@sl.example.com>`,
    });

    const { testEnv, sends } = envWithSendMock();
    const msg = makeMessage({
      from: "<>",
      to: alias.email,
      raw: buildDsnRaw({
        rcpt: alias.email,
        original: buildRaw(
          [
            ["From", alias.email],
            ["To", contact.website_email],
            ["Subject", "re: hello"],
            ["Message-ID", emailLog.sl_message_id ?? ""],
            ["X-SimpleLogin-Type", "Reply"],
            ["X-SimpleLogin-EmailLog-ID", String(emailLog.id)],
          ],
          "my reply\r\n",
        ),
      }),
    });
    await deliver(msg, testEnv);

    expect(msg.rejectReason).toBeNull();
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
    // the DSN is NOT forwarded on to the mailbox as ordinary alias mail: the
    // only binding send is the alert to the sending mailbox.
    expect(outboundEmails).toHaveLength(0);
    expect(sends.map((s) => s.to)).toEqual([mailbox.email]);
  });

  it("falls back to the embedded Message-ID when the EmailLog-ID header is missing", async () => {
    const { user, mailbox, alias } = await forwardSetup();
    const contact = await createContact(env.DB, user.id, alias.id);
    const messageId = `<orig-fallback-${uniq()}@wick.example>`;
    const emailLog = await createEmailLog(env.DB, user.id, contact.id, {
      mailbox_id: mailbox.id,
      message_id: messageId,
    });

    const msg = makeMessage({
      from: "<>",
      to: contact.reply_email,
      raw: buildDsnRaw({
        rcpt: contact.reply_email,
        // some MTAs strip X- headers from the returned copy: only the
        // original Message-ID (kept verbatim by the forward phase) survives.
        original: forwardedOriginal({
          replyEmail: contact.reply_email,
          aliasEmail: alias.email,
          messageId,
        }),
      }),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBeNull();
    const after = await one<EmailLogRow>(
      "SELECT * FROM email_log WHERE id = ?1",
      emailLog.id,
    );
    expect(after?.bounced).toBe(1);
    expect(after?.bounced_mailbox_id).toBe(mailbox.id);
  });

  it("reads the original headers from a text/rfc822-headers part", async () => {
    const { user, mailbox, alias } = await forwardSetup();
    const contact = await createContact(env.DB, user.id, alias.id);
    const emailLog = await createEmailLog(env.DB, user.id, contact.id, {
      mailbox_id: mailbox.id,
    });

    const msg = makeMessage({
      from: "<>",
      to: contact.reply_email,
      raw: buildDsnRaw({
        rcpt: contact.reply_email,
        originalHeaders: [
          `From: "John Wick - john at wick.example" <${contact.reply_email}>`,
          `To: ${alias.email}`,
          "Subject: hello",
          `Message-ID: <orig-${uniq()}@wick.example>`,
          `X-SimpleLogin-EmailLog-ID: ${emailLog.id}`,
        ].join("\r\n"),
      }),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBeNull();
    const after = await one<EmailLogRow>(
      "SELECT * FROM email_log WHERE id = ?1",
      emailLog.id,
    );
    expect(after?.bounced).toBe(1);
  });

  it("rejects a DSN for a soft-deleted user with E510", async () => {
    const future = toStr(new Date(Date.now() + 30 * 86400 * 1000));
    const { user, mailbox, alias } = await forwardSetup({ delete_on: future });
    const contact = await createContact(env.DB, user.id, alias.id);
    const emailLog = await createEmailLog(env.DB, user.id, contact.id, {
      mailbox_id: mailbox.id,
    });

    const msg = makeMessage({
      from: "<>",
      to: contact.reply_email,
      raw: buildDsnRaw({
        rcpt: contact.reply_email,
        original: forwardedOriginal({
          replyEmail: contact.reply_email,
          aliasEmail: alias.email,
          emailLogId: emailLog.id,
        }),
      }),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBe("550 SL E510 so such user");
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
  });
});

// =================== unattributable / forged DSNs ==========================

describe("unattributable DSNs (documented fall-through)", () => {
  it("drops an unattributable DSN to a reverse alias on the old E206 path", async () => {
    const { user, mailbox, alias } = await forwardSetup();
    const contact = await createContact(env.DB, user.id, alias.id);
    const emailLog = await createEmailLog(env.DB, user.id, contact.id, {
      mailbox_id: mailbox.id,
    });

    const { testEnv, sends } = envWithSendMock();
    const msg = makeMessage({
      from: "<>",
      to: contact.reply_email,
      // no message/rfc822 part at all — some MTAs return no original.
      raw: buildDsnRaw({ rcpt: contact.reply_email }),
    });
    await deliver(msg, testEnv);

    // accepted (E206 null-sender drop), nothing marked, nothing sent.
    expect(msg.rejectReason).toBeNull();
    const after = await one<EmailLogRow>(
      "SELECT * FROM email_log WHERE id = ?1",
      emailLog.id,
    );
    expect(after?.bounced).toBe(0);
    expect(sends).toHaveLength(0);
    expect(sentEmails).toHaveLength(0);
  });

  it("forwards an unattributable DSN addressed to an alias like ordinary mail", async () => {
    const { mailbox, alias } = await forwardSetup();
    const { testEnv, sends } = envWithSendMock();

    const msg = makeMessage({
      from: "mailer-daemon@mx.remote.example",
      to: alias.email,
      // wraps some message this worker never sent (no id headers match).
      raw: buildDsnRaw({
        rcpt: alias.email,
        original: buildRaw(
          [
            ["From", "someone@else.example"],
            ["To", "third@party.example"],
            ["Message-ID", `<unrelated-${uniq()}@else.example>`],
          ],
          "not ours\r\n",
        ),
      }),
    });
    await deliver(msg, testEnv);

    // pre-existing behavior: delivered to the mailbox through the forward
    // phase — the replayed raw stream survives the DSN inspection intact.
    expect(msg.rejectReason).toBeNull();
    expect(sends).toHaveLength(1);
    expect(sends[0].to).toBe(mailbox.email);
    const out = outboundEmails.at(-1);
    expect(out?.to).toBe(mailbox.email);
    expect(out?.raw).toContain("Final-Recipient: rfc822; dead@mailbox.example");
    const log = await one<EmailLogRow>(
      "SELECT * FROM email_log WHERE alias_id = ?1",
      alias.id,
    );
    expect(log?.bounced).toBe(0);
  });

  it("ignores a forged EmailLog-ID whose outbound sender is not the DSN recipient", async () => {
    // victim: a forward email log behind reverse alias A...
    const victim = await forwardSetup();
    const victimContact = await createContact(
      env.DB,
      victim.user.id,
      victim.alias.id,
    );
    const victimLog = await createEmailLog(
      env.DB,
      victim.user.id,
      victimContact.id,
      { mailbox_id: victim.mailbox.id },
    );
    // ...attacked through an unrelated reverse alias B.
    const attacker = await forwardSetup();
    const attackerContact = await createContact(
      env.DB,
      attacker.user.id,
      attacker.alias.id,
    );

    const msg = makeMessage({
      from: "<>",
      to: attackerContact.reply_email,
      raw: buildDsnRaw({
        rcpt: attackerContact.reply_email,
        original: forwardedOriginal({
          replyEmail: victimContact.reply_email,
          aliasEmail: victim.alias.email,
          emailLogId: victimLog.id,
        }),
      }),
    });
    await deliver(msg);

    // not attributed: falls through to the null-sender drop, no side effects.
    expect(msg.rejectReason).toBeNull();
    const after = await one<EmailLogRow>(
      "SELECT * FROM email_log WHERE id = ?1",
      victimLog.id,
    );
    expect(after?.bounced).toBe(0);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM bounce WHERE email = ?1",
        victim.mailbox.email,
      ),
    ).toBe(0);
    expect(sentEmails).toHaveLength(0);
  });
});

// =================== notify-other-mailbox transactional ====================

describe("notify-other-mailbox bounce isolation", () => {
  it("stamps notification copies with the transactional id, not the reply's log id", async () => {
    const { user, alias, contact } = await replySetup();
    const second = await createMailbox(env.DB, user.id, "second@other.example");
    await insert("alias_mailbox", {
      alias_id: alias.id,
      mailbox_id: second.id,
    });

    const msg = makeMessage({
      from: user.email,
      to: contact.reply_email,
      raw: buildRaw([
        ["From", user.email],
        ["To", contact.reply_email],
        ["Subject", "watch the headers"],
      ]),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBeNull();
    const reply = outboundEmails.find((o) => o.to === contact.website_email);
    const notif = outboundEmails.find((o) => o.to === second.email);
    expect(reply).toBeDefined();
    expect(notif).toBeDefined();
    // the reply keeps its EmailLog-ID; the notification swaps it for the
    // transactional id so a bounced notification cannot flag the reply.
    expect(rawHeader(reply?.raw ?? "", "X-SimpleLogin-EmailLog-ID")).not.toBe(
      null,
    );
    expect(rawHeader(notif?.raw ?? "", "X-SimpleLogin-EmailLog-ID")).toBeNull();
    const tx = await one<{ id: number }>(
      "SELECT id FROM transactional_email WHERE email = ?1 ORDER BY id DESC",
      second.email,
    );
    expect(rawHeader(notif?.raw ?? "", "X-SimpleLogin-Transactional-ID")).toBe(
      String(tx?.id),
    );
  });

  it("records a bounced notification as a transactional bounce (E205 parity)", async () => {
    const { user, alias } = await replySetup();
    const second = await createMailbox(env.DB, user.id, "dead@other.example");
    const tx = await insert<{ id: number }>("transactional_email", {
      email: second.email,
    });

    const { testEnv, sends } = envWithSendMock();
    const msg = makeMessage({
      from: "<>",
      to: alias.email,
      raw: buildDsnRaw({
        rcpt: alias.email,
        original: buildRaw(
          [
            ["From", alias.email],
            ["To", second.email],
            ["Subject", "on behalf of"],
            ["X-SimpleLogin-Transactional-ID", String(tx.id)],
          ],
          "notification body\r\n",
        ),
      }),
    });
    await deliver(msg, testEnv);

    expect(msg.rejectReason).toBeNull();
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM bounce WHERE email = ?1",
        second.email,
      ),
    ).toBe(1);
    // no email log is touched or created and nothing is forwarded.
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM email_log WHERE alias_id = ?1",
        alias.id,
      ),
    ).toBe(0);
    expect(sends).toHaveLength(0);
  });
});
