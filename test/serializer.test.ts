import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { toEpoch } from "../src/lib/dates";
import type { AliasInfo } from "../src/lib/serializer";
import {
  getAliasInfoV2,
  getAliasInfosWithPaginationV3,
  reverseAliasDisplay,
  serializeAliasInfo,
  serializeAliasInfoV2,
  serializeContact,
} from "../src/lib/serializer";
import type { ContactRow } from "../src/lib/rows";
import {
  createAlias,
  createContact,
  createEmailLog,
  createMailbox,
  createUser,
} from "./fixtures";

const CREATED = "2021-03-12 09:53:26+00:00";

function baseInfo(over: Partial<AliasInfo> = {}): AliasInfo {
  return {
    alias: {
      id: 7,
      created_at: CREATED,
      updated_at: null,
      user_id: 1,
      email: "abc@sl.test",
      name: "My alias",
      enabled: 1,
      flags: 0,
      custom_domain_id: null,
      automatic_creation: 0,
      directory_id: null,
      note: "a note",
      mailbox_id: 3,
      disable_pgp: 0,
      cannot_be_disabled: 0,
      disable_email_spoofing_check: 0,
      batch_import_id: null,
      original_owner_id: null,
      pinned: 0,
      transfer_token: null,
      transfer_token_expiration: null,
      hibp_last_check: null,
      last_email_log_id: null,
      delete_on: null,
      delete_reason: null,
    },
    mailbox: { id: 3, email: "mb@sl.test" },
    mailboxes: [{ id: 3, email: "mb@sl.test" }],
    nb_forward: 2,
    nb_blocked: 1,
    nb_reply: 4,
    supportPgp: false,
    latestEmailLog: null,
    latestContact: null,
    senderFormat: 0,
    ...over,
  };
}

describe("serializeAliasInfo (v1)", () => {
  it("has exactly the v1 keys and the nb_block spelling", () => {
    const out = serializeAliasInfo(baseInfo());
    expect(Object.keys(out).sort()).toEqual(
      [
        "creation_date",
        "creation_timestamp",
        "email",
        "enabled",
        "id",
        "nb_block",
        "nb_forward",
        "nb_reply",
        "note",
      ].sort(),
    );
    expect(out.creation_date).toBe(CREATED);
    expect(out.creation_timestamp).toBe(toEpoch(CREATED));
    expect(out.enabled).toBe(true);
    expect(out.nb_block).toBe(1);
    expect(out.nb_reply).toBe(4);
  });
});

describe("serializeAliasInfoV2", () => {
  it("has exactly the v2 keys with mailbox/mailboxes and null latest_activity", () => {
    const out = serializeAliasInfoV2(baseInfo());
    expect(Object.keys(out).sort()).toEqual(
      [
        "creation_date",
        "creation_timestamp",
        "disable_pgp",
        "email",
        "enabled",
        "id",
        "latest_activity",
        "mailbox",
        "mailboxes",
        "name",
        "nb_block",
        "nb_forward",
        "nb_reply",
        "note",
        "pinned",
        "support_pgp",
      ].sort(),
    );
    expect(out.mailbox).toEqual({ id: 3, email: "mb@sl.test" });
    expect(out.support_pgp).toBe(false);
    expect(out.disable_pgp).toBe(false);
    expect(out.pinned).toBe(false);
    expect(out.latest_activity).toBeNull();
  });

  it("emits latest_activity with action + contact when a log is present", () => {
    const contact: ContactRow = {
      id: 9,
      created_at: CREATED,
      updated_at: null,
      user_id: 1,
      alias_id: 7,
      name: "John Wick",
      website_email: "john@wick.com",
      website_from: null,
      reply_email: "ra@sl.test",
      is_cc: 0,
      pgp_public_key: null,
      pgp_finger_print: null,
      mail_from: null,
      invalid_email: 0,
      block_forward: 0,
      automatic_created: 0,
      flags: 0,
    };
    const out = serializeAliasInfoV2(
      baseInfo({
        latestEmailLog: {
          id: 5, created_at: "2024-06-01 00:00:00+00:00", updated_at: null, user_id: 1,
          contact_id: 9, alias_id: 7, is_reply: 1, blocked: 0, bounced: 0, auto_replied: 0,
          is_spam: 0, spam_score: null, spam_status: null, spam_report: null,
          refused_email_id: null, mailbox_id: null, bounced_mailbox_id: null,
          message_id: null, sl_message_id: null,
        },
        latestContact: contact,
        senderFormat: 0,
      }),
    );
    expect(out.latest_activity).toEqual({
      timestamp: toEpoch("2024-06-01 00:00:00+00:00"),
      action: "reply",
      contact: {
        email: "john@wick.com",
        name: "John Wick",
        reverse_alias: '"John Wick | john at wick.com" <ra@sl.test>',
      },
    });
  });
});

describe("reverseAliasDisplay / serializeContact", () => {
  const contact = (over: Partial<ContactRow> = {}): ContactRow => ({
    id: 1, created_at: CREATED, updated_at: null, user_id: 1, alias_id: 1,
    name: "John Wick", website_email: "john@wick.com", website_from: null,
    reply_email: "ra@sl.test", is_cc: 0, pgp_public_key: null, pgp_finger_print: null,
    mail_from: null, invalid_email: 0, block_forward: 0, automatic_created: 0, flags: 0,
    ...over,
  });

  it("AT format (0/default/unknown): @ becomes ' at '", () => {
    expect(reverseAliasDisplay(contact(), 0)).toBe('"John Wick | john at wick.com" <ra@sl.test>');
    expect(reverseAliasDisplay(contact(), null)).toBe('"John Wick | john at wick.com" <ra@sl.test>');
  });

  it("A format (2): @ becomes '(a)'", () => {
    expect(reverseAliasDisplay(contact(), 2)).toBe('"John Wick | john(a)wick.com" <ra@sl.test>');
  });

  it("NO_NAME/AT_ONLY/NAME_ONLY (5/6/7) keep the address unchanged", () => {
    expect(reverseAliasDisplay(contact(), 7)).toBe('"John Wick | john@wick.com" <ra@sl.test>');
  });

  it("no name -> just the (formatted) email", () => {
    expect(reverseAliasDisplay(contact({ name: null }), 0)).toBe('"john at wick.com" <ra@sl.test>');
  });

  it("parses the name from website_from when name is empty, stripping quotes", () => {
    const c = contact({ name: null, website_from: '"AB CD" <john@wick.com>' });
    expect(reverseAliasDisplay(c, 0)).toBe('"AB CD | john at wick.com" <ra@sl.test>');
  });

  it("strips double quotes out of the display name", () => {
    expect(reverseAliasDisplay(contact({ name: 'Jo"hn' }), 0)).toBe('"John | john at wick.com" <ra@sl.test>');
  });

  it("serializeContact has the exact key set and fills last_email_sent_* from lastReply", () => {
    const out = serializeContact(contact(), false, { sender_format: 0 } as any);
    expect(Object.keys(out).sort()).toEqual(
      [
        "block_forward",
        "contact",
        "creation_date",
        "creation_timestamp",
        "existed",
        "id",
        "last_email_sent_date",
        "last_email_sent_timestamp",
        "reverse_alias",
        "reverse_alias_address",
      ].sort(),
    );
    expect(out.last_email_sent_date).toBeNull();
    expect(out.reverse_alias_address).toBe("ra@sl.test");
    expect(out.reverse_alias).toBe('"John Wick | john at wick.com" <ra@sl.test>');

    const withReply = serializeContact(contact(), true, { sender_format: 0 } as any, {
      created_at: "2024-06-01 00:00:00+00:00",
    } as any);
    expect(withReply.existed).toBe(true);
    expect(withReply.last_email_sent_date).toBe("2024-06-01 00:00:00+00:00");
    expect(withReply.last_email_sent_timestamp).toBe(toEpoch("2024-06-01 00:00:00+00:00"));
  });
});

describe("getAliasInfoV2", () => {
  it("counts all logs, latest is strictly after created_at, includes unverified secondary mailbox", async () => {
    const user = await createUser(env.DB, { sender_format: 2 });
    const primary = await createMailbox(env.DB, user.id, "primary@mb.test", {
      pgp_finger_print: "FPR",
    });
    const secondary = await createMailbox(env.DB, user.id, "sec@mb.test", { verified: 0 });
    const alias = await createAlias(env.DB, user.id, primary.id, {
      created_at: "2024-01-01 00:00:00+00:00",
    });
    await env.DB.prepare("INSERT INTO alias_mailbox (alias_id, mailbox_id) VALUES (?1,?2)")
      .bind(alias.id, secondary.id).run();

    const contact = await createContact(env.DB, user.id, alias.id, { name: "C", website_email: "c@ex.test" });
    await createEmailLog(env.DB, user.id, contact.id, { created_at: "2024-01-02 00:00:00+00:00", blocked: 1 });
    await createEmailLog(env.DB, user.id, contact.id, { created_at: "2024-01-03 00:00:00+00:00", is_reply: 1 });

    const info = await getAliasInfoV2(env.DB, alias, user);
    expect(info.nb_blocked).toBe(1);
    expect(info.nb_reply).toBe(1);
    expect(info.nb_forward).toBe(0);
    expect(info.latestEmailLog?.created_at).toBe("2024-01-03 00:00:00+00:00");
    expect(info.latestContact?.website_email).toBe("c@ex.test");
    // includes the unverified secondary mailbox (single-alias quirk)
    expect(info.mailboxes.map((m) => m.email).sort()).toEqual(["primary@mb.test", "sec@mb.test"]);
    // support_pgp is computed only over verified mailboxes (primary has a fingerprint)
    expect(info.supportPgp).toBe(true);

    const out = serializeAliasInfoV2(info);
    expect((out.latest_activity as any).action).toBe("reply");
    // sender_format A(2) applied to the reverse alias
    expect((out.latest_activity as any).contact.reverse_alias).toBe('"C | c(a)ex.test" <' + contact.reply_email + ">");
  });

  it("a log exactly at created_at is counted but is not the latest activity", async () => {
    const user = await createUser(env.DB);
    const alias = await createAlias(env.DB, user.id, user.default_mailbox_id!, {
      created_at: "2024-01-01 00:00:00+00:00",
    });
    const contact = await createContact(env.DB, user.id, alias.id);
    await createEmailLog(env.DB, user.id, contact.id, { created_at: "2024-01-01 00:00:00+00:00", blocked: 1 });

    const info = await getAliasInfoV2(env.DB, alias, user);
    expect(info.nb_blocked).toBe(1);
    expect(info.latestEmailLog).toBeNull();
    expect(serializeAliasInfoV2(info).latest_activity).toBeNull();
  });
});

describe("getAliasInfosWithPaginationV3", () => {
  it("orders pinned first, then by most-recent activity, and paginates by 20", async () => {
    const user = await createUser(env.DB);
    const mb = user.default_mailbox_id!;

    // A: created early, but a recent email_log -> recent activity
    const aliasA = await createAlias(env.DB, user.id, mb, {
      email: "a@sl.test", created_at: "2024-01-01 00:00:00+00:00",
    });
    const cA = await createContact(env.DB, user.id, aliasA.id);
    await createEmailLog(env.DB, user.id, cA.id, { created_at: "2024-06-01 00:00:00+00:00", is_reply: 1 });

    // B: created later, no activity
    await createAlias(env.DB, user.id, mb, { email: "b@sl.test", created_at: "2024-03-01 00:00:00+00:00" });

    // P: pinned, oldest -> must still sort first
    await createAlias(env.DB, user.id, mb, {
      email: "p@sl.test", created_at: "2020-01-01 00:00:00+00:00", pinned: 1,
    });

    const page = await getAliasInfosWithPaginationV3(env.DB, user, 0);
    expect(page.map((i) => i.alias.email)).toEqual(["p@sl.test", "a@sl.test", "b@sl.test"]);

    // latest_activity correctness on A
    const infoA = page.find((i) => i.alias.email === "a@sl.test")!;
    expect(infoA.nb_reply).toBe(1);
    expect(serializeAliasInfoV2(infoA).latest_activity).toMatchObject({
      action: "reply",
      timestamp: toEpoch("2024-06-01 00:00:00+00:00"),
    });
  });

  it("presence filters follow precedence pinned > disabled > enabled", async () => {
    const user = await createUser(env.DB);
    const mb = user.default_mailbox_id!;
    await createAlias(env.DB, user.id, mb, { email: "en@sl.test", enabled: 1, pinned: 0 });
    await createAlias(env.DB, user.id, mb, { email: "dis@sl.test", enabled: 0, pinned: 0 });
    await createAlias(env.DB, user.id, mb, { email: "pin@sl.test", enabled: 1, pinned: 1 });

    const enabled = await getAliasInfosWithPaginationV3(env.DB, user, 0, { enabled: true });
    expect(enabled.map((i) => i.alias.email).sort()).toEqual(["en@sl.test", "pin@sl.test"]);

    const disabled = await getAliasInfosWithPaginationV3(env.DB, user, 0, { disabled: true });
    expect(disabled.map((i) => i.alias.email)).toEqual(["dis@sl.test"]);

    const pinned = await getAliasInfosWithPaginationV3(env.DB, user, 0, { pinned: true });
    expect(pinned.map((i) => i.alias.email)).toEqual(["pin@sl.test"]);

    // all three flags -> pinned wins
    const both = await getAliasInfosWithPaginationV3(env.DB, user, 0, {
      pinned: true, disabled: true, enabled: true,
    });
    expect(both.map((i) => i.alias.email)).toEqual(["pin@sl.test"]);
  });

  it("query filter matches email, note, and name; trashed aliases are excluded", async () => {
    const user = await createUser(env.DB);
    const mb = user.default_mailbox_id!;
    await createAlias(env.DB, user.id, mb, { email: "shopping@sl.test", note: "for stores" });
    await createAlias(env.DB, user.id, mb, { email: "x@sl.test", note: "banking stuff" });
    await createAlias(env.DB, user.id, mb, { email: "y@sl.test", name: "Newsletter" });
    await createAlias(env.DB, user.id, mb, {
      email: "trashed@sl.test", note: "banking", delete_on: "2030-01-01 00:00:00+00:00",
    });

    expect((await getAliasInfosWithPaginationV3(env.DB, user, 0, { query: "shop" })).map((i) => i.alias.email))
      .toEqual(["shopping@sl.test"]);
    expect((await getAliasInfosWithPaginationV3(env.DB, user, 0, { query: "banking" })).map((i) => i.alias.email))
      .toEqual(["x@sl.test"]); // trashed one excluded
    expect((await getAliasInfosWithPaginationV3(env.DB, user, 0, { query: "Newsletter" })).map((i) => i.alias.email))
      .toEqual(["y@sl.test"]);
  });

  it("list mailboxes are verified-only and email-sorted", async () => {
    const user = await createUser(env.DB);
    const primary = await createMailbox(env.DB, user.id, "zzz@mb.test");
    const secondaryVerified = await createMailbox(env.DB, user.id, "aaa@mb.test");
    const secondaryUnverified = await createMailbox(env.DB, user.id, "unv@mb.test", { verified: 0 });
    const alias = await createAlias(env.DB, user.id, primary.id, { email: "list@sl.test" });
    await env.DB.batch([
      env.DB.prepare("INSERT INTO alias_mailbox (alias_id, mailbox_id) VALUES (?1,?2)").bind(alias.id, secondaryVerified.id),
      env.DB.prepare("INSERT INTO alias_mailbox (alias_id, mailbox_id) VALUES (?1,?2)").bind(alias.id, secondaryUnverified.id),
    ]);

    const [info] = await getAliasInfosWithPaginationV3(env.DB, user, 0);
    expect(info.mailboxes.map((m) => m.email)).toEqual(["aaa@mb.test", "zzz@mb.test"]);
    expect(info.mailbox.email).toBe("zzz@mb.test"); // primary regardless of order
  });

  it("paginates 21 aliases into pages of 20 + 1 without overlap", async () => {
    const user = await createUser(env.DB);
    const mb = user.default_mailbox_id!;
    for (let i = 0; i < 21; i++) await createAlias(env.DB, user.id, mb);

    const page0 = await getAliasInfosWithPaginationV3(env.DB, user, 0);
    const page1 = await getAliasInfosWithPaginationV3(env.DB, user, 1);
    expect(page0.length).toBe(20);
    expect(page1.length).toBe(1);
    const ids = new Set([...page0, ...page1].map((i) => i.alias.id));
    expect(ids.size).toBe(21);
  });
});
