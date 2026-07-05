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
import { generateVerpEmail, handleEmail, outboundEmails } from "../src/email";
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
  it("forwards to the verified mailbox, creating contact and email log", async () => {
    const { user, mailbox, alias } = await forwardSetup();
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
        ],
        "hi there\r\n",
      ),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBeNull();
    expect(msg.forwards).toHaveLength(1);
    expect(msg.forwards[0].to).toBe(mailbox.email);

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
      /^john_at_wick_example_[a-z]{5,10}@sl\.example\.com$/,
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

    const h = msg.forwards[0].headers;
    expect(h["x-simplelogin-type"]).toBe("Forward");
    expect(h["x-simplelogin-emaillog-id"]).toBe(String(emailLog?.id));
    expect(h["x-simplelogin-envelope-to"]).toBe(alias.email);
    expect(h["x-simplelogin-envelope-from"]).toBe("john@wick.example");
    expect(h["x-simplelogin-original-from"]).toBe(
      "John Wick <john@wick.example>",
    );
  });

  it("reuses the existing contact on subsequent emails (no duplicate rows)", async () => {
    const { alias } = await forwardSetup();
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
    await deliver(first);
    const firstContact = await one<ContactRow>(
      "SELECT * FROM contact WHERE alias_id = ?1",
      alias.id,
    );

    const second = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw,
    });
    await deliver(second);

    expect(second.forwards).toHaveLength(1);
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
    const msg = makeMessage({
      from: "someone@ext.example",
      to: "anything@catch.example",
      raw: buildRaw([
        ["From", "someone@ext.example"],
        ["To", "anything@catch.example"],
      ]),
    });
    await deliver(msg);

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
    expect(msg.forwards).toHaveLength(1);
    expect(msg.forwards[0].to).toBe(user.email);

    // a second email reuses the alias
    const again = makeMessage({
      from: "someone@ext.example",
      to: "anything@catch.example",
      raw: buildRaw([
        ["From", "someone@ext.example"],
        ["To", "anything@catch.example"],
      ]),
    });
    await deliver(again);
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

    const matching = makeMessage({
      from: "a@ext.example",
      to: "prefix-abc@rules.example",
      raw: buildRaw([
        ["From", "a@ext.example"],
        ["To", "prefix-abc@rules.example"],
      ]),
    });
    await deliver(matching);
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
    const address = `${name}+shop@sl.example.com`;
    const msg = makeMessage({
      from: "shop@ext.example",
      to: address,
      raw: buildRaw([
        ["From", "shop@ext.example"],
        ["To", address],
      ]),
    });
    await deliver(msg);

    expect(msg.rejectReason).toBeNull();
    const alias = await one<AliasRow>(
      "SELECT * FROM alias WHERE email = ?1",
      address,
    );
    expect(alias).not.toBeNull();
    expect(alias?.directory_id).toBe(directory.id);
    expect(alias?.note).toBe(`Created by directory ${name}`);
    expect(alias?.mailbox_id).toBe(user.default_mailbox_id);
    expect(msg.forwards).toHaveLength(1);
    expect(msg.forwards[0].to).toBe(user.email);
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

  it("rejects with E524 when the sender address is a reverse alias", async () => {
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

    expect(msg.rejectReason).toBe("550 SL E524 Wrong use of reverse-alias");
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
    // VERP envelope sender on the alias domain
    expect(sends[0].from).toMatch(
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
    const { user, alias, contact } = await replySetup();
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
  });

  it("rejects an unknown legacy reverse alias with E502", async () => {
    const msg = makeMessage({
      from: "someone@ext.example",
      to: "ra+doesnotexist@sl.example.com",
      raw: buildRaw([
        ["From", "someone@ext.example"],
        ["To", "ra+doesnotexist@sl.example.com"],
      ]),
    });
    await deliver(msg);
    expect(msg.rejectReason).toBe("550 SL E502 Email not exist");
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
