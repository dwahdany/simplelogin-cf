/**
 * Integration tests for the Email Routing worker (specs/07-email-handling.md).
 * `handleEmail` is called directly with a mock ForwardableEmailMessage; the
 * DB comes from the cloudflare:test env, outbound reply sends are asserted
 * through a recorded SEND_EMAIL mock + the exported `outboundEmails` seam,
 * and transactional alerts through `sentEmails` from the shared mailer.
 */

import {
  createExecutionContext,
  env,
  waitOnExecutionContext,
} from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import {
  generateVerpEmail,
  handleEmail,
  outboundEmails,
  replaceInMimeBody,
} from "../src/email";
import { toStr } from "../src/lib/dates";
import type { Env } from "../src/lib/env";
import { sentEmails } from "../src/lib/mailer";
import type {
  AliasRow,
  ContactRow,
  EmailLogRow,
  MailboxRow,
} from "../src/lib/rows";
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

/** Escape a domain for use inside a RegExp. */
const reDomain = (d: string) => d.replace(/\./g, "\\.");

/** Body of a serialized message (everything after the first blank line). */
function bodyOf(raw: string): string {
  const idx = raw.indexOf("\r\n\r\n");
  return idx === -1 ? "" : raw.slice(idx + 4);
}

/** Raw MIME parts of a multipart section (excludes preamble/epilogue). */
function mimeParts(section: string, boundary: string): string[] {
  const segments = section.split(`--${boundary}`);
  const parts: string[] = [];
  for (let i = 1; i < segments.length; i++) {
    if (segments[i].startsWith("--")) break; // closing delimiter
    parts.push(segments[i]);
  }
  return parts;
}

/** Body of a single MIME part (everything after its header block). */
function partBody(part: string): string {
  const idx = part.indexOf("\r\n\r\n");
  return idx === -1 ? "" : part.slice(idx + 4);
}

function decodeQpText(s: string): string {
  return s
    .replace(/=\r\n/g, "")
    .replace(/=\n/g, "")
    .replace(/=([0-9A-Fa-f]{2})/g, (_m, h: string) =>
      String.fromCharCode(Number.parseInt(h, 16)),
    );
}

const decodeB64Text = (s: string): string => atob(s.replace(/\s+/g, ""));

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
  // idempotent: storage may be shared between tests
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

beforeEach(() => {
  sentEmails.length = 0;
  outboundEmails.length = 0;
});

// ============================ forward phase ===============================

describe("forward phase", () => {
  it("rewrites From to the reverse alias and sends via the binding", async () => {
    const { user, mailbox, alias } = await forwardSetup();
    const { testEnv, sends } = envWithSendMock();
    const msg = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw: buildRaw(
        [
          ["From", "John Wick <john@wick.example>"],
          ["To", alias.email],
          ["Subject", "hello"],
          ["Message-ID", "<orig-1@wick.example>"],
          ["Content-Type", "text/plain"],
          ["X-Mailer", "EvilMailer 1.0"],
          ["DKIM-Signature", "v=1; a=rsa-sha256; d=wick.example; s=sel"],
        ],
        "hi there\r\n",
      ),
    });
    await deliver(msg, testEnv);

    expect(msg.rejectReason).toBeNull();
    expect(msg.forwards).toHaveLength(0); // no longer message.forward()

    const contact = await one<ContactRow>(
      "SELECT * FROM contact WHERE alias_id = ?1",
      alias.id,
    );
    expect(contact).not.toBeNull();
    expect(contact?.website_email).toBe("john@wick.example");
    expect(contact?.name).toBe("John Wick");
    expect(contact?.mail_from).toBe("john@wick.example");
    expect(contact?.automatic_created).toBe(1);
    expect(contact?.invalid_email).toBe(0);
    // new-format reverse alias with the sender included (user default).
    expect(contact?.reply_email).toMatch(
      new RegExp(
        `^john_at_wick_example_[a-z]{5,10}@${reDomain(env.EMAIL_DOMAIN)}$`,
      ),
    );

    const emailLog = await one<EmailLogRow>(
      "SELECT * FROM email_log WHERE contact_id = ?1",
      contact?.id,
    );
    expect(emailLog).not.toBeNull();
    expect(emailLog?.user_id).toBe(user.id);
    expect(emailLog?.alias_id).toBe(alias.id);
    expect(emailLog?.mailbox_id).toBe(mailbox.id);
    expect(emailLog?.is_reply).toBe(0);
    expect(emailLog?.blocked).toBe(0);
    expect(emailLog?.message_id).toBe("<orig-1@wick.example>");

    const aliasAfter = await one<AliasRow>(
      "SELECT * FROM alias WHERE id = ?1",
      alias.id,
    );
    expect(aliasAfter?.last_email_log_id).toBe(emailLog?.id);

    // Delivered through the SEND_EMAIL binding. The binding requires the
    // envelope sender to equal the From header (the reverse alias); the
    // Flask-parity VERP envelope is still recorded on outboundEmails.
    expect(sends).toHaveLength(1);
    expect(sends[0].to).toBe(mailbox.email);
    expect(sends[0].from).toBe(contact?.reply_email);

    const out = outboundEmails[0];
    expect(out.to).toBe(mailbox.email);
    expect(out.envelopeFrom).toMatch(
      new RegExp(`^sl\\.[a-z2-7]+\\.[a-z2-7]+@${reDomain(env.EMAIL_DOMAIN)}$`),
    );
    expect(out.bindingFrom).toBe(contact?.reply_email);
    // From is the reverse alias (default AT sender_format), NOT the sender.
    expect(rawHeader(out.raw, "From")).toBe(
      `"John Wick - john at wick.example" <${contact?.reply_email}>`,
    );
    expect(rawHeader(out.raw, "To")).toBe(alias.email);
    expect(rawHeader(out.raw, "Subject")).toBe("hello");
    expect(rawHeader(out.raw, "X-SimpleLogin-Type")).toBe("Forward");
    expect(rawHeader(out.raw, "X-SimpleLogin-EmailLog-ID")).toBe(
      String(emailLog?.id),
    );
    expect(rawHeader(out.raw, "X-SimpleLogin-Envelope-To")).toBe(alias.email);
    expect(rawHeader(out.raw, "X-SimpleLogin-Envelope-From")).toBe(
      "john@wick.example",
    );
    expect(rawHeader(out.raw, "X-SimpleLogin-Original-From")).toBe(
      "John Wick <john@wick.example>",
    );
    // header whitelist strips non-allowed headers.
    expect(rawHeader(out.raw, "X-Mailer")).toBeNull();
    expect(rawHeader(out.raw, "DKIM-Signature")).toBeNull();
    expect(out.raw).toContain("hi there");
  });

  it("reuses the existing contact on subsequent emails (no duplicate rows)", async () => {
    const { alias } = await forwardSetup();
    const { testEnv, sends } = envWithSendMock();
    const raw = buildRaw([
      ["From", "John Wick <john@wick.example>"],
      ["To", alias.email],
      ["Subject", "hello again"],
    ]);
    const first = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw,
    });
    await deliver(first, testEnv);
    const firstContact = await one<ContactRow>(
      "SELECT * FROM contact WHERE alias_id = ?1",
      alias.id,
    );

    const second = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw,
    });
    await deliver(second, testEnv);

    expect(sends).toHaveLength(2);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM contact WHERE alias_id = ?1",
        alias.id,
      ),
    ).toBe(1);
    const after = await one<ContactRow>(
      "SELECT * FROM contact WHERE alias_id = ?1",
      alias.id,
    );
    expect(after?.id).toBe(firstContact?.id);
    expect(after?.reply_email).toBe(firstContact?.reply_email);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM email_log WHERE alias_id = ?1",
        alias.id,
      ),
    ).toBe(2);
  });

  it("creates a blocked email log and accepts when the alias is disabled", async () => {
    const { user, mailbox, alias: enabledAlias } = await forwardSetup();
    void enabledAlias;
    const alias = await createAlias(env.DB, user.id, mailbox.id, {
      enabled: 0,
    });
    const msg = makeMessage({
      from: "sender@ext.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "sender@ext.example"],
        ["To", alias.email],
        ["Subject", "blocked?"],
      ]),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBeNull();
    expect(msg.forwards).toHaveLength(0);
    const emailLog = await one<EmailLogRow>(
      "SELECT * FROM email_log WHERE alias_id = ?1",
      alias.id,
    );
    expect(emailLog?.blocked).toBe(1);
    expect(emailLog?.mailbox_id).toBeNull();
    const aliasAfter = await one<AliasRow>(
      "SELECT * FROM alias WHERE id = ?1",
      alias.id,
    );
    expect(aliasAfter?.last_email_log_id).toBe(emailLog?.id);
  });

  it("rejects with E502 for a disabled alias when the user chose return_5xx", async () => {
    const { user, mailbox } = await forwardSetup({
      block_behaviour: "return_5xx",
    });
    const alias = await createAlias(env.DB, user.id, mailbox.id, {
      enabled: 0,
    });
    const msg = makeMessage({
      from: "sender@ext.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "sender@ext.example"],
        ["To", alias.email],
      ]),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBe("550 SL E502 Email not exist");
    expect(msg.forwards).toHaveLength(0);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM email_log WHERE alias_id = ?1 AND blocked = 1",
        alias.id,
      ),
    ).toBe(1);
  });

  it("blocks forwarding from a blocked contact", async () => {
    const { user, alias } = await forwardSetup();
    await createContact(env.DB, user.id, alias.id, {
      website_email: "spammer@bad.example",
      reply_email: `blk${uniq()}@sl.example.com`,
      block_forward: 1,
    });
    const msg = makeMessage({
      from: "spammer@bad.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "spammer@bad.example"],
        ["To", alias.email],
      ]),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBeNull();
    expect(msg.forwards).toHaveLength(0);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM email_log WHERE alias_id = ?1 AND blocked = 1",
        alias.id,
      ),
    ).toBe(1);
    // contact must be reused, not duplicated
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM contact WHERE alias_id = ?1",
        alias.id,
      ),
    ).toBe(1);
  });

  it("rejects an unknown recipient with E515", async () => {
    const msg = makeMessage({
      from: "someone@ext.example",
      to: "ghost@sl.example.com",
      raw: buildRaw([
        ["From", "someone@ext.example"],
        ["To", "ghost@sl.example.com"],
      ]),
    });
    await deliver(msg);
    expect(msg.rejectReason).toBe("550 SL E515 Email not exist");
    expect(msg.forwards).toHaveLength(0);
  });

  it("auto-creates an alias via custom domain catch-all", async () => {
    const user = await createUser(env.DB);
    const cd = await insert<{ id: number }>("custom_domain", {
      user_id: user.id,
      domain: "catch.example",
      verified: 1,
      ownership_verified: 1,
      catch_all: 1,
    });
    const { testEnv, sends } = envWithSendMock();
    const msg = makeMessage({
      from: "someone@ext.example",
      to: "anything@catch.example",
      raw: buildRaw([
        ["From", "someone@ext.example"],
        ["To", "anything@catch.example"],
      ]),
    });
    await deliver(msg, testEnv);

    expect(msg.rejectReason).toBeNull();
    const alias = await one<AliasRow>(
      "SELECT * FROM alias WHERE email = ?1",
      "anything@catch.example",
    );
    expect(alias).not.toBeNull();
    expect(alias?.custom_domain_id).toBe(cd.id);
    expect(alias?.automatic_creation).toBe(1);
    expect(alias?.note).toBe("Created by catchall option");
    expect(alias?.mailbox_id).toBe(user.default_mailbox_id);
    expect(sends).toHaveLength(1);
    expect(sends[0].to).toBe(user.email);

    // a second email reuses the alias
    const again = makeMessage({
      from: "someone@ext.example",
      to: "anything@catch.example",
      raw: buildRaw([
        ["From", "someone@ext.example"],
        ["To", "anything@catch.example"],
      ]),
    });
    await deliver(again, testEnv);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM alias WHERE email = ?1",
        "anything@catch.example",
      ),
    ).toBe(1);
  });

  it("applies auto-create rules when catch-all is off", async () => {
    const user = await createUser(env.DB);
    const cd = await insert<{ id: number }>("custom_domain", {
      user_id: user.id,
      domain: "rules.example",
      verified: 1,
      ownership_verified: 1,
      catch_all: 0,
    });
    await insert("auto_create_rule", {
      custom_domain_id: cd.id,
      regex: "prefix.*",
      order: 0,
    });

    const { testEnv } = envWithSendMock();
    const matching = makeMessage({
      from: "a@ext.example",
      to: "prefix-abc@rules.example",
      raw: buildRaw([
        ["From", "a@ext.example"],
        ["To", "prefix-abc@rules.example"],
      ]),
    });
    await deliver(matching, testEnv);
    expect(matching.rejectReason).toBeNull();
    const alias = await one<AliasRow>(
      "SELECT * FROM alias WHERE email = ?1",
      "prefix-abc@rules.example",
    );
    expect(alias?.note).toBe("Created by rule 0 with regex prefix.*");

    const nonMatching = makeMessage({
      from: "a@ext.example",
      to: "other@rules.example",
      raw: buildRaw([
        ["From", "a@ext.example"],
        ["To", "other@rules.example"],
      ]),
    });
    await deliver(nonMatching);
    expect(nonMatching.rejectReason).toBe("550 SL E515 Email not exist");
  });

  it("auto-creates an alias via directory", async () => {
    const user = await createUser(env.DB);
    const name = `dir${uniq()}`;
    const directory = await insert<{ id: number }>("directory", {
      user_id: user.id,
      name,
    });
    const aliasDomain = env.ALIAS_DOMAINS.split(",")[0].trim();
    const address = `${name}+shop@${aliasDomain}`;
    const { testEnv, sends } = envWithSendMock();
    const msg = makeMessage({
      from: "shop@ext.example",
      to: address,
      raw: buildRaw([
        ["From", "shop@ext.example"],
        ["To", address],
      ]),
    });
    await deliver(msg, testEnv);

    expect(msg.rejectReason).toBeNull();
    const alias = await one<AliasRow>(
      "SELECT * FROM alias WHERE email = ?1",
      address,
    );
    expect(alias).not.toBeNull();
    expect(alias?.directory_id).toBe(directory.id);
    expect(alias?.note).toBe(`Created by directory ${name}`);
    expect(alias?.mailbox_id).toBe(user.default_mailbox_id);
    expect(sends).toHaveLength(1);
    expect(sends[0].to).toBe(user.email);
  });

  it("rate-controls the directory-disabled cannot-create alert (FWD-8)", async () => {
    const user = await createUser(env.DB);
    const name = `disdir${uniq()}`;
    await insert("directory", { user_id: user.id, name, disabled: 1 });
    const aliasDomain = env.ALIAS_DOMAINS.split(",")[0].trim();
    const address = `${name}+shop@${aliasDomain}`;
    const msg = makeMessage({
      from: "shop@ext.example",
      to: address,
      raw: buildRaw([
        ["From", "shop@ext.example"],
        ["To", address],
      ]),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBe("550 SL E515 Email not exist");
    expect(
      sentEmails.some(
        (e) =>
          e.subject === `Alias ${address} cannot be created` &&
          e.to === user.email,
      ),
    ).toBe(true);
    // a sent_alert row is recorded so repeat probes are rate-limited.
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM sent_alert WHERE alert_type = ?1 AND to_email = ?2",
        "alert_directory_disabled_alias_creation",
        user.email,
      ),
    ).toBe(1);
  });

  it("suppresses the cannot-create alert for a pending-delete user (FWD-10)", async () => {
    const future = toStr(new Date(Date.now() + 30 * 86400 * 1000));
    const user = await createUser(env.DB, { delete_on: future });
    const name = `disdir${uniq()}`;
    await insert("directory", { user_id: user.id, name, disabled: 1 });
    const aliasDomain = env.ALIAS_DOMAINS.split(",")[0].trim();
    const address = `${name}+shop@${aliasDomain}`;
    const msg = makeMessage({
      from: "shop@ext.example",
      to: address,
      raw: buildRaw([
        ["From", "shop@ext.example"],
        ["To", address],
      ]),
    });
    await deliver(msg);

    // user.can_send_or_receive() is false -> no notification email at all.
    expect(
      sentEmails.some(
        (e) => e.subject === `Alias ${address} cannot be created`,
      ),
    ).toBe(false);
  });

  it("re-notifies mailbox-is-alias after the 24h window (FWD-9/SF-07)", async () => {
    const user = await createUser(env.DB);
    const loopMailbox = await createMailbox(
      env.DB,
      user.id,
      "loopwin@ext.example",
    );
    const alias = await createAlias(env.DB, user.id, loopMailbox.id);
    await createAlias(env.DB, user.id, user.default_mailbox_id as number, {
      email: "loopwin@ext.example",
    });
    // A stale alert (2 days ago) must NOT suppress a fresh one: the alert is
    // rate-controlled per rolling day, not deduped once-ever.
    await env.DB.prepare(
      "INSERT INTO sent_alert (user_id, to_email, alert_type, created_at) VALUES (?1, ?2, 'mailbox_is_alias', ?3)",
    )
      .bind(user.id, user.email, toStr(new Date(Date.now() - 2 * 86400 * 1000)))
      .run();
    const msg = makeMessage({
      from: "s@remote.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "s@remote.example"],
        ["To", alias.email],
      ]),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBe("550 SL E525 Alias loop");
    expect(
      sentEmails.some(
        (e) => e.subject === "Your mailbox loopwin@ext.example is an alias",
      ),
    ).toBe(true);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM sent_alert WHERE alert_type = ?1 AND to_email = ?2",
        "mailbox_is_alias",
        user.email,
      ),
    ).toBe(2);
  });

  it("detects an email cycle from the alias's own mailbox", async () => {
    const { user, mailbox, alias } = await forwardSetup();
    const msg = makeMessage({
      from: mailbox.email,
      to: alias.email,
      raw: buildRaw([
        ["From", mailbox.email],
        ["To", alias.email],
      ]),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBeNull();
    expect(msg.forwards).toHaveLength(0);
    const title = `Email sent to ${alias.email} from its own mailbox ${mailbox.email}`;
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM notification WHERE user_id = ?1 AND title = ?2",
        user.id,
        title,
      ),
    ).toBe(1);
    expect(
      sentEmails.some((e) => e.subject === title && e.to === mailbox.email),
    ).toBe(true);
  });

  it("unverifies a mailbox that is itself an alias and rejects with E525", async () => {
    const user = await createUser(env.DB);
    const loopMailbox = await createMailbox(
      env.DB,
      user.id,
      "loop@ext.example",
    );
    const alias = await createAlias(env.DB, user.id, loopMailbox.id);
    // another alias with the mailbox's address -> loop
    await createAlias(env.DB, user.id, user.default_mailbox_id as number, {
      email: "loop@ext.example",
    });
    const msg = makeMessage({
      from: "someone@remote.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "someone@remote.example"],
        ["To", alias.email],
      ]),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBe("550 SL E525 Alias loop");
    expect(msg.forwards).toHaveLength(0);
    const mbAfter = await one<MailboxRow>(
      "SELECT * FROM mailbox WHERE id = ?1",
      loopMailbox.id,
    );
    expect(mbAfter?.verified).toBe(0);
    expect(
      sentEmails.some(
        (e) => e.subject === "Your mailbox loop@ext.example is an alias",
      ),
    ).toBe(true);
  });

  it("rejects with E518 when the only mailbox is disabled", async () => {
    const user = await createUser(env.DB);
    const disabled = await createMailbox(env.DB, user.id, "off@ext.example", {
      verified: 1,
      disabled: 1,
    });
    const alias = await createAlias(env.DB, user.id, disabled.id);
    const msg = makeMessage({
      from: "someone@remote.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "someone@remote.example"],
        ["To", alias.email],
      ]),
    });
    await deliver(msg);
    expect(msg.rejectReason).toBe("550 SL E518 Disabled mailbox");
  });

  it("rejects an alias on an unverified custom domain with E520", async () => {
    const { user, mailbox } = await forwardSetup();
    const cd = await insert<{ id: number }>("custom_domain", {
      user_id: user.id,
      domain: "unverified.example",
      verified: 0,
      ownership_verified: 1,
    });
    const alias = await createAlias(env.DB, user.id, mailbox.id, {
      email: "x@unverified.example",
      custom_domain_id: cd.id,
    });
    const msg = makeMessage({
      from: "someone@remote.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "someone@remote.example"],
        ["To", alias.email],
      ]),
    });
    await deliver(msg);
    expect(msg.rejectReason).toBe("550 SL E520 Unverified custom domain");
  });

  it("rejects with E504 when the From-header sender address is a reverse alias", async () => {
    // FWD-2: get_or_create_contact -> create_contact catches
    // CannotCreateContactForReverseAlias and returns None, so handle_forward
    // rejects with E504 (not the E524 reserved for To/Cc rewriting).
    const { user: userA, alias: aliasA } = await forwardSetup();
    const reverse = `rvsender${uniq()}@sl.example.com`;
    await createContact(env.DB, userA.id, aliasA.id, {
      website_email: "real@remote.example",
      reply_email: reverse,
    });
    const { alias: aliasB } = await forwardSetup();

    const msg = makeMessage({
      from: reverse,
      to: aliasB.email,
      raw: buildRaw([
        ["From", reverse],
        ["To", aliasB.email],
      ]),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBe("550 SL E504 Account disabled");
    expect(msg.forwards).toHaveLength(0);
    expect(
      sentEmails.some(
        (e) =>
          e.subject ===
            "SimpleLogin shouldn't be used with another email forwarding system" &&
          e.to === userA.email,
      ),
    ).toBe(true);
  });

  it("delivers mail whose Reply-To is a reverse alias, skipping that contact (FWD-1)", async () => {
    // A Reply-To that is itself a reverse alias must be skipped (like Flask's
    // create_contact returning None), NOT reject the whole message with E524.
    const { user: userA, alias: aliasA } = await forwardSetup();
    const reverse = `rvreplyto${uniq()}@sl.example.com`;
    await createContact(env.DB, userA.id, aliasA.id, {
      website_email: "real@remote.example",
      reply_email: reverse,
    });
    const { alias } = await forwardSetup();
    const { testEnv, sends } = envWithSendMock();

    const msg = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "John Wick <john@wick.example>"],
        ["To", alias.email],
        ["Reply-To", `Boss <${reverse}>, real2@remote.example`],
        ["Subject", "hi"],
      ]),
    });
    await deliver(msg, testEnv);

    // delivered (not rejected), and the reverse-alias reply-to was dropped.
    expect(msg.rejectReason).toBeNull();
    expect(sends).toHaveLength(1);
    const out = outboundEmails[outboundEmails.length - 1].raw;
    const replyToOut = rawHeader(out, "Reply-To") ?? "";
    expect(replyToOut).not.toContain(reverse);
    // the other (valid) reply-to became a reverse-alias contact
    expect(replyToOut).toContain("real2_at_remote_example_");
  });

  it("creates Reply-To contacts nameless (FWD-4/EM-07)", async () => {
    const { alias } = await forwardSetup();
    const { testEnv } = envWithSendMock();
    const msg = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "john@wick.example"],
        ["To", alias.email],
        ["Reply-To", "Boss Person <boss@corp.example>"],
        ["Subject", "s"],
      ]),
    });
    await deliver(msg, testEnv);

    const boss = await one<ContactRow>(
      "SELECT * FROM contact WHERE alias_id = ?1 AND website_email = ?2",
      alias.id,
      "boss@corp.example",
    );
    expect(boss).not.toBeNull();
    // Flask stores reply-to contacts nameless (re-parses the bare address).
    expect(boss?.name).toBeNull();
    const out = outboundEmails[outboundEmails.length - 1].raw;
    const replyToOut = rawHeader(out, "Reply-To") ?? "";
    expect(replyToOut).not.toContain("Boss Person");
    expect(replyToOut).toContain("boss at corp.example");
  });

  it("silently drops an IgnoredEmail pair", async () => {
    const { alias } = await forwardSetup();
    await insert("ignored_email", {
      mail_from: "noise@ext.example",
      rcpt_to: alias.email,
    });
    const msg = makeMessage({
      from: "noise@ext.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "noise@ext.example"],
        ["To", alias.email],
      ]),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBeNull();
    expect(msg.forwards).toHaveLength(0);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM contact WHERE alias_id = ?1",
        alias.id,
      ),
    ).toBe(0);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM email_log WHERE alias_id = ?1",
        alias.id,
      ),
    ).toBe(0);
  });
});

// =================== forward phase — header rewriting =====================

describe("forward phase header rewriting", () => {
  /** Forward a message with the given From header; return the outbound From
   *  header, the created sender Contact, and the raw outbound message. */
  async function forwardWithFrom(
    fromHeader: string,
    userOverrides: Record<string, unknown> = {},
    extraHeaders: [string, string][] = [],
  ) {
    const { alias } = await forwardSetup(userOverrides);
    const { testEnv, sends } = envWithSendMock();
    const msg = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw: buildRaw([
        ["From", fromHeader],
        ["To", alias.email],
        ["Subject", "s"],
        ["Content-Type", "text/plain"],
        ...extraHeaders,
      ]),
    });
    await deliver(msg, testEnv);
    const contact = await one<ContactRow>(
      "SELECT * FROM contact WHERE alias_id = ?1 AND website_email = ?2",
      alias.id,
      "john@wick.example",
    );
    const out = outboundEmails[outboundEmails.length - 1].raw;
    return {
      from: rawHeader(out, "From") ?? "",
      contact: contact as ContactRow,
      alias,
      out,
      sends,
    };
  }

  it("sender_format AT (default): 'Name - user at domain'", async () => {
    const { from, contact } = await forwardWithFrom(
      "John Wick <john@wick.example>",
    );
    expect(from).toBe(
      `"John Wick - john at wick.example" <${contact.reply_email}>`,
    );
  });

  it("sender_format A: 'Name - user(a)domain'", async () => {
    const { from, contact } = await forwardWithFrom(
      "John Wick <john@wick.example>",
      { sender_format: 2 },
    );
    expect(from).toBe(
      `"John Wick - john(a)wick.example" <${contact.reply_email}>`,
    );
  });

  it("sender_format NAME_ONLY: just the display name", async () => {
    const { from, contact } = await forwardWithFrom(
      "John Wick <john@wick.example>",
      { sender_format: 5 },
    );
    expect(from).toBe(`John Wick <${contact.reply_email}>`);
  });

  it("sender_format AT_ONLY: 'user at domain'", async () => {
    const { from, contact } = await forwardWithFrom(
      "John Wick <john@wick.example>",
      { sender_format: 6 },
    );
    expect(from).toBe(`"john at wick.example" <${contact.reply_email}>`);
  });

  it("sender_format NO_NAME: the reverse alias only", async () => {
    const { from, contact } = await forwardWithFrom(
      "John Wick <john@wick.example>",
      { sender_format: 7 },
    );
    expect(from).toBe(contact.reply_email);
  });

  it("dedupes the name when it equals the sender's email address", async () => {
    const { from, contact } = await forwardWithFrom(
      '"john@wick.example" <john@wick.example>',
    );
    // no "john@wick.example - ..." prefix; just the formatted address.
    expect(from).toBe(`"john at wick.example" <${contact.reply_email}>`);
  });

  it("RFC 2047-encodes a non-ASCII display name", async () => {
    const { from, contact } = await forwardWithFrom(
      "Jöhn Wíck <john@wick.example>",
    );
    const m = from.match(/^=\?utf-8\?b\?([A-Za-z0-9+/]+=*)\?= <(.+)>$/);
    expect(m).not.toBeNull();
    expect(m?.[2]).toBe(contact.reply_email);
    const decoded = new TextDecoder().decode(
      Uint8Array.from(atob(m?.[1] ?? ""), (c) => c.charCodeAt(0)),
    );
    expect(decoded).toBe("Jöhn Wíck - john at wick.example");
  });

  it("rewrites To/Cc recipients to reverse aliases and keeps the alias", async () => {
    const { alias } = await forwardSetup();
    const { testEnv } = envWithSendMock();
    const msg = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "John Wick <john@wick.example>"],
        ["To", `${alias.email}, Alice <alice@ext.example>`],
        ["Cc", "Bob <bob@ext.example>"],
        ["Subject", "s"],
      ]),
    });
    await deliver(msg, testEnv);
    const out = outboundEmails[outboundEmails.length - 1].raw;

    const alice = await one<ContactRow>(
      "SELECT * FROM contact WHERE alias_id = ?1 AND website_email = ?2",
      alias.id,
      "alice@ext.example",
    );
    const bob = await one<ContactRow>(
      "SELECT * FROM contact WHERE alias_id = ?1 AND website_email = ?2",
      alias.id,
      "bob@ext.example",
    );
    expect(alice).not.toBeNull();
    expect(alice?.is_cc).toBe(0);
    expect(bob?.is_cc).toBe(1);

    const toOut = rawHeader(out, "To") ?? "";
    expect(toOut).toContain(alias.email); // alias kept verbatim
    expect(toOut).toContain(alice?.reply_email ?? "x");
    expect(toOut).not.toContain("alice@ext.example");
    const ccOut = rawHeader(out, "Cc") ?? "";
    expect(ccOut).toContain(bob?.reply_email ?? "x");
    expect(ccOut).not.toContain("bob@ext.example");
  });

  it("clears an existing contact's name when the To header carries a bare address (FWD-3)", async () => {
    const { user, alias } = await forwardSetup();
    const named = await createContact(env.DB, user.id, alias.id, {
      website_email: "friend@clear.example",
      name: "Friend",
      reply_email: `friendclear${uniq()}@sl.example.com`,
    });
    const { testEnv } = envWithSendMock();
    const msg = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "john@wick.example"],
        ["To", `${alias.email}, <friend@clear.example>`],
        ["Subject", "s"],
      ]),
    });
    await deliver(msg, testEnv);

    const after = await one<ContactRow>(
      "SELECT * FROM contact WHERE id = ?1",
      named.id,
    );
    // bare address in the header clears the stored name (Flask assigns "").
    expect(after?.name).toBeNull();
    const out = outboundEmails[outboundEmails.length - 1].raw;
    const toOut = rawHeader(out, "To") ?? "";
    expect(toOut).toContain(`"friend at clear.example" <${named.reply_email}>`);
    expect(toOut).not.toContain("Friend -");
  });

  it("deletes the Cc header when no recipient survives", async () => {
    const { alias } = await forwardSetup();
    const { testEnv } = envWithSendMock();
    const msg = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "john@wick.example"],
        ["To", alias.email],
        ["Cc", "invalid@"],
        ["Subject", "s"],
      ]),
    });
    await deliver(msg, testEnv);
    const out = outboundEmails[outboundEmails.length - 1].raw;
    expect(rawHeader(out, "Cc")).toBeNull();
  });

  it("adds the alias to To when it was BCC'd (absent from headers)", async () => {
    const { alias } = await forwardSetup();
    const { testEnv } = envWithSendMock();
    const msg = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "john@wick.example"],
        ["Subject", "bcc"],
      ]),
    });
    await deliver(msg, testEnv);
    const out = outboundEmails[outboundEmails.length - 1].raw;
    expect(rawHeader(out, "To")).toBe(alias.email);
  });

  it("rewrites Reply-To to the reply-to contacts' reverse aliases (max 5)", async () => {
    const { alias } = await forwardSetup();
    const { testEnv } = envWithSendMock();
    const replyTos = Array.from(
      { length: 6 },
      (_, i) => `rt${i}@ext.example`,
    ).join(", ");
    const msg = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "john@wick.example"],
        ["To", alias.email],
        ["Reply-To", replyTos],
        ["Subject", "s"],
      ]),
    });
    await deliver(msg, testEnv);
    const out = outboundEmails[outboundEmails.length - 1].raw;
    const replyToOut = rawHeader(out, "Reply-To") ?? "";

    // all 6 reply-to contacts are created, but only 5 appear in the header.
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM contact WHERE alias_id = ?1 AND website_email LIKE '%@ext.example'",
        alias.id,
      ),
    ).toBe(6);
    const reverseAliasCount = (replyToOut.match(/_at_ext_example_/g) ?? [])
      .length;
    expect(reverseAliasCount).toBe(5);
    expect(replyToOut).not.toContain("@ext.example>");
  });

  it("preserves an http List-Unsubscribe and stashes the sender's originals", async () => {
    const { alias } = await forwardSetup();
    const { testEnv } = envWithSendMock();
    const msg = makeMessage({
      from: "news@ext.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "news@ext.example"],
        ["To", alias.email],
        ["Subject", "newsletter"],
        ["List-Unsubscribe", "<https://ext.example/unsub?id=1>"],
        ["List-Id", "News <news.ext.example>"],
        ["X-Mailer", "Bulk 2.0"],
      ]),
    });
    await deliver(msg, testEnv);
    const out = outboundEmails[outboundEmails.length - 1].raw;

    expect(rawHeader(out, "X-Mailer")).toBeNull();
    expect(rawHeader(out, "List-Unsubscribe")).toBe(
      "<https://ext.example/unsub?id=1>",
    );
    expect(rawHeader(out, "List-Unsubscribe-Post")).toBe(
      "List-Unsubscribe=One-Click",
    );
    expect(rawHeader(out, "X-SimpleLogin-Original-List-Unsubscribe")).toBe(
      "<https://ext.example/unsub?id=1>",
    );
    expect(rawHeader(out, "X-SimpleLogin-Original-List-Id")).toBe(
      "News <news.ext.example>",
    );
    // the original List-Id itself is dropped from the forwarded message.
    expect(rawHeader(out, "List-Id")).toBeNull();
    expect(rawHeader(out, "X-SimpleLogin-Unsub-Behaviour")).toBe(
      "original-behaviour",
    );
  });

  it("drops a mailto-only List-Unsubscribe but stashes the original", async () => {
    const { alias } = await forwardSetup();
    const { testEnv } = envWithSendMock();
    const msg = makeMessage({
      from: "news@ext.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "news@ext.example"],
        ["To", alias.email],
        ["Subject", "newsletter"],
        ["List-Unsubscribe", "<mailto:unsub@ext.example>"],
      ]),
    });
    await deliver(msg, testEnv);
    const out = outboundEmails[outboundEmails.length - 1].raw;
    expect(rawHeader(out, "List-Unsubscribe")).toBeNull();
    expect(rawHeader(out, "X-SimpleLogin-Original-List-Unsubscribe")).toBe(
      "<mailto:unsub@ext.example>",
    );
  });

  it("uses an https unsubscribe link for the DisableAlias behaviour", async () => {
    const { alias } = await forwardSetup({ unsub_behaviour: 0 });
    const { testEnv } = envWithSendMock();
    const msg = makeMessage({
      from: "news@ext.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "news@ext.example"],
        ["To", alias.email],
        ["Subject", "newsletter"],
      ]),
    });
    await deliver(msg, testEnv);
    const out = outboundEmails[outboundEmails.length - 1].raw;
    expect(rawHeader(out, "List-Unsubscribe")).toBe(
      `<${env.URL}/dashboard/unsubscribe/${alias.id}>`,
    );
    expect(rawHeader(out, "X-SimpleLogin-Unsub-Behaviour")).toBe(
      "alias-disable",
    );
  });

  it("omits Envelope-From / Original-From when include_header_email_header is off", async () => {
    const { alias } = await forwardSetup({ include_header_email_header: 0 });
    const { testEnv } = envWithSendMock();
    const msg = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "John Wick <john@wick.example>"],
        ["To", alias.email],
        ["Subject", "s"],
      ]),
    });
    await deliver(msg, testEnv);
    const out = outboundEmails[outboundEmails.length - 1].raw;
    expect(rawHeader(out, "X-SimpleLogin-Type")).toBe("Forward");
    expect(rawHeader(out, "X-SimpleLogin-Envelope-To")).toBe(alias.email);
    expect(rawHeader(out, "X-SimpleLogin-Envelope-From")).toBeNull();
    expect(rawHeader(out, "X-SimpleLogin-Original-From")).toBeNull();
  });

  it("adds a Date header when the original lacks one", async () => {
    const { out } = await forwardWithFrom("john@wick.example");
    expect(rawHeader(out, "Date")).toMatch(
      /^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} -0000$/,
    );
  });

  it("prepends the generic-subject banner with original sender/subject (FWD-6)", async () => {
    const { user, mailbox, alias } = await forwardSetup();
    await env.DB.prepare(
      "UPDATE mailbox SET generic_subject = ?1 WHERE id = ?2",
    )
      .bind("A new email", mailbox.id)
      .run();
    void user;
    const { testEnv } = envWithSendMock();
    const msg = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw: buildRaw(
        [
          ["From", "John Wick <john@wick.example>"],
          ["To", alias.email],
          ["Subject", "Secret subject"],
          ["Content-Type", "text/plain"],
        ],
        "hello there\r\n",
      ),
    });
    await deliver(msg, testEnv);

    const out = outboundEmails[outboundEmails.length - 1].raw;
    expect(rawHeader(out, "Subject")).toBe("A new email");
    const body = bodyOf(out);
    expect(body).toContain(
      `Forwarded by SimpleLogin to ${alias.email} from "John Wick <john@wick.example>" with "Secret subject" as subject`,
    );
    expect(body).toContain("hello there");
  });

  it("prepends the invalid-sender banner for an unparseable From (FWD-7)", async () => {
    const { alias } = await forwardSetup();
    const { testEnv } = envWithSendMock();
    const msg = makeMessage({
      from: "notanemail",
      to: alias.email,
      raw: buildRaw(
        [
          ["From", "notanemail"],
          ["To", alias.email],
          ["Subject", "s"],
          ["Content-Type", "text/plain"],
        ],
        "hi\r\n",
      ),
    });
    await deliver(msg, testEnv);

    const contact = await one<ContactRow>(
      "SELECT * FROM contact WHERE alias_id = ?1",
      alias.id,
    );
    expect(contact?.invalid_email).toBe(1);
    const body = bodyOf(outboundEmails[outboundEmails.length - 1].raw);
    expect(body).toContain(
      `Email sent to ${alias.email} from an invalid address and cannot be replied`,
    );
  });

  it("uses a VERP envelope sender and deletes the EmailLog on send failure", async () => {
    const { alias } = await forwardSetup();
    const testEnv = envWithFailingSend();
    const msg = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "john@wick.example"],
        ["To", alias.email],
        ["Subject", "s"],
      ]),
    });
    await deliver(msg, testEnv);

    expect(msg.rejectReason).toBe("421 SL E407 Retry later");
    expect(outboundEmails[outboundEmails.length - 1].envelopeFrom).toMatch(
      new RegExp(`^sl\\.[a-z2-7]+\\.[a-z2-7]+@${reDomain(env.EMAIL_DOMAIN)}$`),
    );
    const contact = await one<ContactRow>(
      "SELECT * FROM contact WHERE alias_id = ?1",
      alias.id,
    );
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM email_log WHERE contact_id = ?1",
        contact?.id,
      ),
    ).toBe(0);
  });

  it("falls back to message.forward() when SEND_EMAIL is not bound", async () => {
    const { mailbox, alias } = await forwardSetup();
    const testEnv = { ...env, SEND_EMAIL: undefined } as unknown as Env;
    const msg = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw: buildRaw([
        ["From", "John Wick <john@wick.example>"],
        ["To", alias.email],
        ["Subject", "s"],
      ]),
    });
    await deliver(msg, testEnv);

    expect(msg.rejectReason).toBeNull();
    expect(msg.forwards).toHaveLength(1);
    expect(msg.forwards[0].to).toBe(mailbox.email);
    expect(msg.forwards[0].headers["x-simplelogin-type"]).toBe("Forward");
    expect(msg.forwards[0].headers["x-simplelogin-envelope-to"]).toBe(
      alias.email,
    );
  });
});

// ============================= reply phase ================================

describe("reply phase", () => {
  it("rewrites and sends the reply from the authorized mailbox", async () => {
    const { user, mailbox, alias, contact } = await replySetup();
    const { testEnv, sends } = envWithSendMock();
    const msg = makeMessage({
      from: user.email,
      to: contact.reply_email,
      raw: buildRaw(
        [
          ["From", user.email],
          ["To", contact.reply_email],
          ["Subject", "Re: hello"],
          ["Message-ID", "<orig-reply-1@mail.example>"],
          ["Content-Type", "text/plain"],
          ["X-Should-Be-Dropped", "secret"],
        ],
        "hello friend\r\n",
      ),
    });
    await deliver(msg, testEnv);

    expect(msg.rejectReason).toBeNull();
    expect(msg.forwards).toHaveLength(0);
    expect(sends).toHaveLength(1);
    expect(sends[0].to).toBe("friend@remote.example");
    // Binding sender = From header (the alias); VERP envelope kept on the
    // outboundEmails capture only (binding rejects misaligned senders).
    expect(sends[0].from).toBe(alias.email);
    expect(outboundEmails.at(-1)?.envelopeFrom).toMatch(
      /^sl\.[a-z2-7]+\.[a-z2-7]+@sl\.example\.com$/,
    );

    const emailLog = await one<EmailLogRow>(
      "SELECT * FROM email_log WHERE contact_id = ?1",
      contact.id,
    );
    expect(emailLog).not.toBeNull();
    expect(emailLog?.is_reply).toBe(1);
    expect(emailLog?.mailbox_id).toBe(mailbox.id);
    expect(emailLog?.message_id).toBe("<orig-reply-1@mail.example>");
    expect(emailLog?.sl_message_id).toBeTruthy();

    const matching = await one<{
      sl_message_id: string;
      email_log_id: number;
    }>(
      "SELECT * FROM message_id_matching WHERE original_message_id = ?1",
      "<orig-reply-1@mail.example>",
    );
    expect(matching?.sl_message_id).toBe(emailLog?.sl_message_id);
    expect(matching?.email_log_id).toBe(emailLog?.id);

    const out = outboundEmails[0];
    expect(out.to).toBe("friend@remote.example");
    expect(out.raw).toContain(`From: ${alias.email}`);
    expect(out.raw).toContain("To: Friend <friend@remote.example>");
    expect(out.raw).toContain("Subject: Re: hello");
    expect(out.raw).toContain("X-SimpleLogin-Type: Reply");
    expect(out.raw).toContain(`X-SimpleLogin-EmailLog-ID: ${emailLog?.id}`);
    expect(out.raw).toContain(`Message-ID: ${emailLog?.sl_message_id}`);
    expect(out.raw).toContain("hello friend");
    // the mailbox address and original message id never leak
    expect(out.raw).not.toContain(user.email);
    expect(out.raw).not.toContain("<orig-reply-1@mail.example>");
    expect(out.raw).not.toContain("X-Should-Be-Dropped");

    const aliasAfter = await one<AliasRow>(
      "SELECT * FROM alias WHERE id = ?1",
      alias.id,
    );
    expect(aliasAfter?.last_email_log_id).toBe(emailLog?.id);
  });

  it("accepts a reply from an authorized address of the mailbox", async () => {
    const { user, mailbox, contact } = await replySetup();
    await insert("authorized_address", {
      user_id: user.id,
      mailbox_id: mailbox.id,
      email: "personal@other.example",
    });
    const { testEnv, sends } = envWithSendMock();
    const msg = makeMessage({
      from: "personal@other.example",
      to: contact.reply_email,
      raw: buildRaw([
        ["From", "personal@other.example"],
        ["To", contact.reply_email],
        ["Subject", "authorized"],
      ]),
    });
    await deliver(msg, testEnv);

    expect(msg.rejectReason).toBeNull();
    expect(sends).toHaveLength(1);
    const emailLog = await one<EmailLogRow>(
      "SELECT * FROM email_log WHERE contact_id = ?1",
      contact.id,
    );
    expect(emailLog?.mailbox_id).toBe(mailbox.id);
    expect(emailLog?.is_reply).toBe(1);
  });

  it("alerts the user and drops a reply from a stranger", async () => {
    const { user, alias, contact } = await replySetup();
    const { testEnv, sends } = envWithSendMock();
    const msg = makeMessage({
      from: "attacker@evil.example",
      to: contact.reply_email,
      raw: buildRaw([
        ["From", "attacker@evil.example"],
        ["To", contact.reply_email],
        ["Subject", "spoof"],
      ]),
    });
    await deliver(msg, testEnv);

    // 250-class E214: accepted but silently dropped
    expect(msg.rejectReason).toBeNull();
    // nothing goes to the contact; the only SEND_EMAIL use is the user alert
    expect(outboundEmails).toHaveLength(0);
    expect(sends.map((s) => s.to)).toEqual([user.email]);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM email_log WHERE contact_id = ?1",
        contact.id,
      ),
    ).toBe(0);
    expect(
      sentEmails.some(
        (e) =>
          e.subject ===
            `Attempt to use your alias ${alias.email} from attacker@evil.example` &&
          e.to === user.email,
      ),
    ).toBe(true);
  });

  it("drops the reply and informs the mailbox when To contains a non reverse-alias", async () => {
    const { user, mailbox, contact } = await replySetup();
    const { testEnv, sends } = envWithSendMock();
    const msg = makeMessage({
      from: user.email,
      to: contact.reply_email,
      raw: buildRaw([
        ["From", user.email],
        ["To", `${contact.reply_email}, outsider@ext.example`],
        ["Subject", "leaky"],
      ]),
    });
    await deliver(msg, testEnv);

    expect(msg.rejectReason).toBeNull();
    // nothing goes to the contact; the only SEND_EMAIL use is the mailbox alert
    expect(outboundEmails).toHaveLength(0);
    expect(sends.map((s) => s.to)).toEqual([mailbox.email]);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM email_log WHERE contact_id = ?1",
        contact.id,
      ),
    ).toBe(0);
    expect(
      sentEmails.some(
        (e) =>
          e.subject ===
            `Email sent to ${contact.website_email} contains non reverse-alias addresses` &&
          e.to === mailbox.email,
      ),
    ).toBe(true);
  });

  it("notifies the alias's other mailboxes about the reply", async () => {
    const { user, mailbox, alias, contact } = await replySetup();
    const second = await createMailbox(env.DB, user.id, "second@other.example");
    await insert("alias_mailbox", {
      alias_id: alias.id,
      mailbox_id: second.id,
    });
    const { testEnv, sends } = envWithSendMock();
    const msg = makeMessage({
      from: user.email,
      to: contact.reply_email,
      raw: buildRaw([
        ["From", user.email],
        ["To", contact.reply_email],
        ["Subject", "multi-mailbox"],
      ]),
    });
    await deliver(msg, testEnv);

    expect(msg.rejectReason).toBeNull();
    expect(sends).toHaveLength(2);
    expect(sends[0].to).toBe("friend@remote.example");
    expect(sends[1].to).toBe("second@other.example");
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM transactional_email WHERE email = ?1",
        "second@other.example",
      ),
    ).toBe(1);
    const notif = outboundEmails[1];
    expect(notif.raw).toContain(`From: ${alias.email}`);
    // the original To (the reverse alias) is restored for easy reply
    expect(notif.raw).toContain(`To: ${contact.reply_email}`);
    // reply-1: the notification carries the "sent on behalf of" warning banner.
    expect(notif.raw).toContain(
      "**** Don't forget to remove this section if you reply to this email ****",
    );
    expect(notif.raw).toContain(
      `Email sent on behalf of alias ${alias.email} using mailbox ${mailbox.email}`,
    );
  });

  it("rejects an unknown legacy reverse alias with E502", async () => {
    const legacy = `ra+doesnotexist@${env.EMAIL_DOMAIN}`;
    const msg = makeMessage({
      from: "someone@ext.example",
      to: legacy,
      raw: buildRaw([
        ["From", "someone@ext.example"],
        ["To", legacy],
      ]),
    });
    await deliver(msg);
    expect(msg.rejectReason).toBe("550 SL E502 Email not exist");
  });

  it("delivers a reply whose To wraps the reverse alias in group syntax (reply-3)", async () => {
    const { user, contact } = await replySetup();
    const { testEnv, sends } = envWithSendMock();
    const msg = makeMessage({
      from: user.email,
      to: contact.reply_email,
      raw: buildRaw([
        ["From", user.email],
        ["To", `Recipients: ${contact.reply_email};`],
        ["Cc", "undisclosed-recipients:;"],
        ["Subject", "grouped"],
      ]),
    });
    await deliver(msg, testEnv);

    // Flask's getaddresses flattens the group and skips the empty Cc member, so
    // the reply is delivered (not dropped as a non-reverse-alias).
    expect(msg.rejectReason).toBeNull();
    expect(sends.map((s) => s.to)).toEqual(["friend@remote.example"]);
    const out = outboundEmails[outboundEmails.length - 1].raw;
    expect(rawHeader(out, "To")).toBe("Friend <friend@remote.example>");
    expect(rawHeader(out, "Cc")).toBeNull();
  });

  it("rejects a display-name From on the same domain as the envelope (reply-4)", async () => {
    // Flask compares the raw From header, so a display-name form yields a bogus
    // domain and fails the same-domain fallback -> unknown mailbox (E214).
    const user = await createUser(env.DB);
    const mailbox = await createMailbox(
      env.DB,
      user.id,
      `box${uniq()}@svc.example`,
      { verified: 1 },
    );
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
      reply_email: `rvr${n}@sl.example.com`,
    });
    const { testEnv, sends } = envWithSendMock();

    const spoofed = makeMessage({
      from: `bounce@svc.example`,
      to: contact.reply_email,
      raw: buildRaw([
        ["From", `Agent <${mailbox.email}>`],
        ["To", contact.reply_email],
        ["Subject", "display-name spoof"],
      ]),
    });
    await deliver(spoofed, testEnv);
    expect(spoofed.rejectReason).toBeNull(); // E214 is 250-class
    expect(sends.map((s) => s.to)).toEqual([user.email]); // only the alert
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM email_log WHERE contact_id = ?1",
        contact.id,
      ),
    ).toBe(0);

    // control: the bare From on the same domain IS accepted (delivered).
    const bare = makeMessage({
      from: `bounce@svc.example`,
      to: contact.reply_email,
      raw: buildRaw([
        ["From", mailbox.email],
        ["To", contact.reply_email],
        ["Subject", "bare from"],
      ]),
    });
    await deliver(bare, testEnv);
    expect(sends.map((s) => s.to)).toContain("friend@remote.example");
  });

  it("rate-limits the unknown-mailbox alert (reply-2)", async () => {
    const { user, alias, contact } = await replySetup();
    const { testEnv } = envWithSendMock();
    for (let i = 0; i < 5; i++) {
      const msg = makeMessage({
        from: "attacker@evil.example",
        to: contact.reply_email,
        raw: buildRaw([
          ["From", "attacker@evil.example"],
          ["To", contact.reply_email],
          ["Subject", `spoof ${i}`],
        ]),
      });
      await deliver(msg, testEnv);
    }
    const subject = `Attempt to use your alias ${alias.email} from attacker@evil.example`;
    // MAX_ALERT_24H = 4: at most 4 alerts sent, and 4 sent_alert rows recorded.
    expect(sentEmails.filter((e) => e.subject === subject)).toHaveLength(4);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM sent_alert WHERE alert_type = ?1 AND to_email = ?2",
        "reverse_alias_unknown_mailbox",
        user.email,
      ),
    ).toBe(4);
  });

  it("does not warn a disabled mailbox on a non reverse-alias reply (reply-6)", async () => {
    const { user, contact } = await replySetup();
    // The sending mailbox is verified but disabled.
    await env.DB.prepare("UPDATE mailbox SET disabled = 1 WHERE user_id = ?1")
      .bind(user.id)
      .run();
    const { testEnv } = envWithSendMock();
    const msg = makeMessage({
      from: user.email,
      to: contact.reply_email,
      raw: buildRaw([
        ["From", user.email],
        ["To", `${contact.reply_email}, outsider@ext.example`],
        ["Subject", "leaky"],
      ]),
    });
    await deliver(msg, testEnv);

    // no warning email (mailbox.can_send_or_receive() is false), log deleted.
    expect(
      sentEmails.some((e) =>
        e.subject.startsWith(
          `Email sent to ${contact.website_email} contains non reverse-alias`,
        ),
      ),
    ).toBe(false);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM email_log WHERE contact_id = ?1",
        contact.id,
      ),
    ).toBe(0);
  });

  it("swallows out-of-office replies sent to a reverse alias", async () => {
    const { contact } = await replySetup();
    const msg = makeMessage({
      from: "<>",
      to: contact.reply_email,
      raw: buildRaw([
        ["From", "mailer-daemon@remote.example"],
        ["To", contact.reply_email],
        ["Subject", "Out of office"],
      ]),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBeNull();
    expect(outboundEmails).toHaveLength(0);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM email_log WHERE contact_id = ?1",
        contact.id,
      ),
    ).toBe(0);
  });
});

// =================== reply phase reverse-alias replacement ================

/** Enable the user's replace_reverse_alias flag (default off). */
async function enableReplaceReverseAlias(userId: number): Promise<void> {
  await env.DB.prepare(
    "UPDATE users SET replace_reverse_alias = 1 WHERE id = ?1",
  )
    .bind(userId)
    .run();
}

describe("reply phase reverse-alias replacement", () => {
  it("replaces the reverse alias and mailbox in a plain 7bit reply body", async () => {
    const { user, alias, contact } = await replySetup();
    await enableReplaceReverseAlias(user.id);
    const { testEnv } = envWithSendMock();
    const body =
      `On Mon, 1 Jan 2025, Friend <${contact.reply_email}> wrote:\r\n` +
      "> earlier message\r\n" +
      `Replying from ${user.email}.\r\n`;
    const msg = makeMessage({
      from: user.email,
      to: contact.reply_email,
      raw: buildRaw(
        [
          ["From", user.email],
          ["To", contact.reply_email],
          ["Subject", "Re: hello"],
          ["Content-Type", "text/plain"],
        ],
        body,
      ),
    });
    await deliver(msg, testEnv);

    const out = outboundEmails.at(-1);
    expect(out).toBeDefined();
    const outBody = bodyOf(out?.raw ?? "");
    // reverse alias -> contact real address, mailbox -> alias
    expect(outBody).toContain(contact.website_email);
    expect(outBody).toContain(alias.email);
    expect(outBody).not.toContain(contact.reply_email);
    expect(outBody).not.toContain(user.email);
    // never leaks anywhere in the delivered message
    expect(out?.raw).not.toContain(contact.reply_email);
    expect(out?.raw).not.toContain(user.email);
  });

  it("replaces a reverse alias split across a quoted-printable soft line break", async () => {
    const { user, alias, contact } = await replySetup();
    await enableReplaceReverseAlias(user.id);
    const { testEnv } = envWithSendMock();
    const ra = contact.reply_email;
    const split = `${ra.slice(0, 6)}=\r\n${ra.slice(6)}`; // spans a QP soft break
    const body = `On Mon, Friend <${split}> wrote:\r\nsent from ${user.email}\r\n`;
    const msg = makeMessage({
      from: user.email,
      to: contact.reply_email,
      raw: buildRaw(
        [
          ["From", user.email],
          ["To", contact.reply_email],
          ["Subject", "Re: qp"],
          ["Content-Type", "text/plain; charset=utf-8"],
          ["Content-Transfer-Encoding", "quoted-printable"],
        ],
        body,
      ),
    });
    await deliver(msg, testEnv);

    const out = outboundEmails.at(-1);
    const outBody = bodyOf(out?.raw ?? "");
    const decoded = decodeQpText(outBody);
    expect(decoded).toContain(contact.website_email);
    expect(decoded).toContain(alias.email);
    expect(decoded).not.toContain(ra);
    expect(decoded).not.toContain(user.email);
    // output is still valid QP: no line exceeds 76 columns
    for (const line of outBody.split("\r\n"))
      expect(line.length).toBeLessThanOrEqual(76);
  });

  it("replaces in every text part of a multipart reply, leaving attachments intact", async () => {
    const { user, alias, contact } = await replySetup();
    await enableReplaceReverseAlias(user.id);
    const { testEnv } = envWithSendMock();
    const ra = contact.reply_email;
    const splitRa = `${ra.slice(0, 6)}=\r\n${ra.slice(6)}`;
    const html = `<p>Reply to <a href="mailto:${ra}">${ra}</a> - mailbox ${user.email}</p>`;
    const htmlB64 = btoa(html);
    // 1x1 PNG; passes through untouched (application/octet-stream).
    const png =
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
    const mpBody =
      "This is a MIME multipart message.\r\n" +
      "--OUTER\r\n" +
      'Content-Type: multipart/alternative; boundary="INNER"\r\n\r\n' +
      "--INNER\r\n" +
      "Content-Type: text/plain; charset=utf-8\r\n" +
      "Content-Transfer-Encoding: quoted-printable\r\n\r\n" +
      `On Mon, Friend <${splitRa}> wrote:\r\nsent from ${user.email}\r\n` +
      "--INNER\r\n" +
      "Content-Type: text/html; charset=utf-8\r\n" +
      "Content-Transfer-Encoding: base64\r\n\r\n" +
      `${htmlB64}\r\n` +
      "--INNER--\r\n" +
      "--OUTER\r\n" +
      'Content-Type: application/octet-stream; name="logo.png"\r\n' +
      "Content-Transfer-Encoding: base64\r\n" +
      'Content-Disposition: attachment; filename="logo.png"\r\n\r\n' +
      `${png}\r\n` +
      "--OUTER--\r\n";
    const msg = makeMessage({
      from: user.email,
      to: contact.reply_email,
      raw: buildRaw(
        [
          ["From", user.email],
          ["To", contact.reply_email],
          ["Subject", "Re: multipart"],
          ["MIME-Version", "1.0"],
          ["Content-Type", 'multipart/mixed; boundary="OUTER"'],
        ],
        mpBody,
      ),
    });
    await deliver(msg, testEnv);

    const raw = outboundEmails.at(-1)?.raw ?? "";
    // reverse alias and mailbox gone from the whole message (base64 part too)
    expect(raw).not.toContain(ra);
    expect(raw).not.toContain(user.email);
    // boundaries intact (2 openers + closing "--OUTER--"/"--INNER--" each)
    expect(raw.split("--OUTER").length - 1).toBe(3);
    expect(raw.split("--INNER").length - 1).toBe(3);
    expect(raw).toContain("--OUTER--");
    expect(raw).toContain("--INNER--");
    // attachment byte-identical
    expect(raw).toContain(`${png}\r\n`);

    const outerParts = mimeParts(bodyOf(raw), "OUTER");
    expect(outerParts).toHaveLength(2);
    const innerParts = mimeParts(partBody(outerParts[0]), "INNER");
    expect(innerParts).toHaveLength(2);

    const plain = decodeQpText(partBody(innerParts[0]));
    expect(plain).toContain(contact.website_email);
    expect(plain).toContain(alias.email);
    expect(plain).not.toContain(ra);
    expect(plain).not.toContain(user.email);

    const htmlOut = decodeB64Text(partBody(innerParts[1]));
    expect(htmlOut).toContain(contact.website_email);
    expect(htmlOut).toContain(alias.email);
    expect(htmlOut).not.toContain(ra);
    expect(htmlOut).not.toContain(user.email);
  });

  it("leaves the body byte-identical when replace_reverse_alias is off", async () => {
    const { user, contact } = await replySetup(); // flag defaults to 0
    const { testEnv } = envWithSendMock();
    const body = `Quoting <${contact.reply_email}> and mailbox ${user.email} here.\r\n`;
    const msg = makeMessage({
      from: user.email,
      to: contact.reply_email,
      raw: buildRaw(
        [
          ["From", user.email],
          ["To", contact.reply_email],
          ["Subject", "Re: off"],
          ["Content-Type", "text/plain"],
        ],
        body,
      ),
    });
    await deliver(msg, testEnv);

    const out = outboundEmails.at(-1);
    expect(bodyOf(out?.raw ?? "")).toBe(body);
    expect(out?.raw).toContain(contact.reply_email);
    expect(out?.raw).toContain(user.email);
  });
});

describe("replaceInMimeBody", () => {
  it("returns the body unchanged for malformed multipart (boundary never appears)", () => {
    const headers = [
      { name: "Content-Type", value: 'multipart/mixed; boundary="NOPE"' },
    ];
    const body = new TextEncoder().encode(
      "write to secret@reverse.example - no boundary here\r\n",
    );
    const out = replaceInMimeBody(headers, body, [
      ["secret@reverse.example", "real@person.example"],
    ]);
    expect(new TextDecoder().decode(out)).toBe(
      "write to secret@reverse.example - no boundary here\r\n",
    );
  });

  it("passes a non-text part through untouched", () => {
    const headers = [{ name: "Content-Type", value: "application/pdf" }];
    const body = new TextEncoder().encode("secret@reverse.example inside\r\n");
    const out = replaceInMimeBody(headers, body, [
      ["secret@reverse.example", "real@person.example"],
    ]);
    expect(new TextDecoder().decode(out)).toBe(
      "secret@reverse.example inside\r\n",
    );
  });

  it("replaces in a text/plain leaf with no explicit encoding", () => {
    const headers = [{ name: "Content-Type", value: "text/plain" }];
    const body = new TextEncoder().encode(
      "write to secret@reverse.example please\r\n",
    );
    const out = replaceInMimeBody(headers, body, [
      ["secret@reverse.example", "real@person.example"],
    ]);
    expect(new TextDecoder().decode(out)).toBe(
      "write to real@person.example please\r\n",
    );
  });
});

// ============================ bounces (VERP) ==============================

describe("VERP bounces", () => {
  it("marks the email log as bounced on a forward-phase bounce", async () => {
    const { user, mailbox, alias } = await forwardSetup();
    const contact = await createContact(env.DB, user.id, alias.id);
    const emailLog = await createEmailLog(env.DB, user.id, contact.id, {
      mailbox_id: mailbox.id,
    });

    const verpAddress = await generateVerpEmail(env, 0, emailLog.id);
    const msg = makeMessage({
      from: "<>",
      to: verpAddress,
      raw: buildRaw(
        [
          ["From", "MAILER-DAEMON@remote.example"],
          ["To", verpAddress],
          [
            "Content-Type",
            'multipart/report; report-type=delivery-status; boundary="b1"',
          ],
        ],
        "--b1\r\ndelivery failed\r\n--b1--\r\n",
      ),
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
    // SF-01: the user is notified (Notification row + rate-controlled email).
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

  it("records bounce side effects on a reply-phase bounce (SF-02)", async () => {
    const { user, mailbox, alias } = await forwardSetup();
    const contact = await createContact(env.DB, user.id, alias.id, {
      website_email: "friend@remote.example",
    });
    const emailLog = await createEmailLog(env.DB, user.id, contact.id, {
      mailbox_id: mailbox.id,
      is_reply: 1,
    });

    const verpAddress = await generateVerpEmail(env, 1, emailLog.id);
    const msg = makeMessage({
      from: "<>",
      to: verpAddress,
      raw: buildRaw(
        [
          ["From", "MAILER-DAEMON@remote.example"],
          ["To", verpAddress],
          [
            "Content-Type",
            'multipart/report; report-type=delivery-status; boundary="b1"',
          ],
        ],
        "--b1\r\ndelivery failed\r\n--b1--\r\n",
      ),
    });
    await deliver(msg);

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
        "friend@remote.example",
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

  it("rejects a bounce for a soft-deleted user with E510 (SF-06)", async () => {
    const future = toStr(new Date(Date.now() + 30 * 86400 * 1000));
    const { user, mailbox, alias } = await forwardSetup({ delete_on: future });
    const contact = await createContact(env.DB, user.id, alias.id);
    const emailLog = await createEmailLog(env.DB, user.id, contact.id, {
      mailbox_id: mailbox.id,
    });

    const verpAddress = await generateVerpEmail(env, 0, emailLog.id);
    const msg = makeMessage({
      from: "<>",
      to: verpAddress,
      raw: buildRaw(
        [
          ["From", "MAILER-DAEMON@remote.example"],
          ["To", verpAddress],
          ["Content-Type", "multipart/report; report-type=delivery-status"],
        ],
        "delivery failed\r\n",
      ),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBe("550 SL E510 so such user");
    const after = await one<EmailLogRow>(
      "SELECT * FROM email_log WHERE id = ?1",
      emailLog.id,
    );
    // no DB mutation for a soft-deleted account.
    expect(after?.bounced).toBe(0);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM bounce WHERE email = ?1",
        mailbox.email,
      ),
    ).toBe(0);
    void alias;
  });

  it("rejects a bounce for a missing email log with E512", async () => {
    const verpAddress = await generateVerpEmail(env, 0, 987654);
    const msg = makeMessage({
      from: "<>",
      to: verpAddress,
      raw: buildRaw(
        [
          ["From", "MAILER-DAEMON@remote.example"],
          ["To", verpAddress],
          ["Content-Type", "multipart/report; report-type=delivery-status"],
        ],
        "delivery failed\r\n",
      ),
    });
    await deliver(msg);
    expect(msg.rejectReason).toBe("550 SL E512 No such email log");
  });
});
