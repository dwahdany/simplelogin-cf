import { env } from "cloudflare:test";
import { inflateRawSync } from "node:zlib";
import { beforeEach, describe, expect, it } from "vitest";
import {
  JOB_STATE_DONE,
  JOB_STATE_READY,
  JOB_STATE_TAKEN,
  type JobRow,
  runPendingJobs,
} from "../src/jobs";
import { sentUserReports } from "../src/jobs/handlers/send-user-report";
import { rateLimitRowExpiry, runMaintenance } from "../src/jobs/maintenance";
import { addDays, nowStr, toStr } from "../src/lib/dates";
import type { Env } from "../src/lib/env";
import { sentEmails } from "../src/lib/mailer";
import {
  createAlias,
  createContact,
  createEmailLog,
  createMailbox,
  createUser,
} from "./fixtures";

const tenv = env as unknown as Env;
const URL = "https://app.sl.example.com"; // pinned in vitest.config.ts

let seq = 9000;
const uniq = () => ++seq;

async function insertJob(
  name: string,
  payload: Record<string, unknown> | null = null,
  over: Partial<JobRow> = {},
): Promise<number> {
  const res = await tenv.DB.prepare(
    `INSERT INTO job (name, payload, run_at, state, attempts, taken_at, priority)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
  )
    .bind(
      name,
      payload ? JSON.stringify(payload) : null,
      over.run_at ?? null,
      over.state ?? JOB_STATE_READY,
      over.attempts ?? 0,
      over.taken_at ?? null,
      over.priority ?? 50,
    )
    .run();
  return res.meta.last_row_id;
}

function getJob(id: number): Promise<JobRow | null> {
  return tenv.DB.prepare("SELECT * FROM job WHERE id = ?1")
    .bind(id)
    .first<JobRow>();
}

async function insertRateRow(key: string, windowStart: number): Promise<void> {
  await tenv.DB.prepare(
    "INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, 1)",
  )
    .bind(key, windowStart)
    .run();
}

beforeEach(async () => {
  await tenv.DB.prepare("DELETE FROM job").run();
  await tenv.DB.prepare("DELETE FROM rate_limit").run();
  await tenv.DB.prepare("DELETE FROM notification").run();
  sentEmails.length = 0;
  sentUserReports.length = 0;
});

// ---------------------------------------------------------------------------
// runMaintenance: trashed-alias purge (cron.py clear_aliases_pending_to_be_deleted)
// ---------------------------------------------------------------------------

describe("runMaintenance — trashed alias purge", () => {
  it("hard-deletes overdue trashed aliases into deleted_alias, keeps the rest", async () => {
    const user = await createUser(tenv.DB);
    const overdue = await createAlias(
      tenv.DB,
      user.id,
      user.default_mailbox_id!,
      {
        delete_on: toStr(addDays(new Date(), -1)),
        delete_reason: 1,
        enabled: 0,
      },
    );
    const stillTrashed = await createAlias(
      tenv.DB,
      user.id,
      user.default_mailbox_id!,
      {
        delete_on: toStr(addDays(new Date(), 5)),
        delete_reason: 1,
        enabled: 0,
      },
    );
    const live = await createAlias(tenv.DB, user.id, user.default_mailbox_id!);

    await runMaintenance(tenv);

    const remaining = await tenv.DB.prepare(
      "SELECT id FROM alias WHERE id IN (?1, ?2, ?3)",
    )
      .bind(overdue.id, stillTrashed.id, live.id)
      .all<{ id: number }>();
    expect(remaining.results.map((r) => r.id).sort()).toEqual(
      [stillTrashed.id, live.id].sort(),
    );

    const trashRow = await tenv.DB.prepare(
      "SELECT * FROM deleted_alias WHERE email = ?1",
    )
      .bind(overdue.email)
      .first<{ email: string; reason: number; alias_id: number }>();
    expect(trashRow).not.toBeNull();
    expect(trashRow?.reason).toBe(1);
    expect(trashRow?.alias_id).toBe(overdue.id);
  });

  it("moves overdue custom-domain aliases into domain_deleted_alias", async () => {
    const user = await createUser(tenv.DB);
    const domain = await tenv.DB.prepare(
      "INSERT INTO custom_domain (user_id, domain, verified) VALUES (?1, ?2, 1) RETURNING id",
    )
      .bind(user.id, `d${uniq()}.example.com`)
      .first<{ id: number }>();
    const alias = await createAlias(
      tenv.DB,
      user.id,
      user.default_mailbox_id!,
      {
        custom_domain_id: domain?.id,
        delete_on: toStr(addDays(new Date(), -2)),
        delete_reason: 3,
        enabled: 0,
      },
    );

    await runMaintenance(tenv);

    expect(
      await tenv.DB.prepare("SELECT 1 FROM alias WHERE id = ?1")
        .bind(alias.id)
        .first(),
    ).toBeNull();
    const row = await tenv.DB.prepare(
      "SELECT * FROM domain_deleted_alias WHERE email = ?1",
    )
      .bind(alias.email)
      .first<{
        user_id: number;
        domain_id: number;
        reason: number;
        alias_id: number;
      }>();
    expect(row?.user_id).toBe(user.id);
    expect(row?.domain_id).toBe(domain?.id);
    expect(row?.reason).toBe(3);
    expect(row?.alias_id).toBe(alias.id);
    // NOT in the global trash (alias_delete.py __delete_if_custom_domain)
    expect(
      await tenv.DB.prepare("SELECT 1 FROM deleted_alias WHERE email = ?1")
        .bind(alias.email)
        .first(),
    ).toBeNull();
  });

  it("does not duplicate an existing deleted_alias row", async () => {
    const user = await createUser(tenv.DB);
    const alias = await createAlias(
      tenv.DB,
      user.id,
      user.default_mailbox_id!,
      {
        delete_on: toStr(addDays(new Date(), -1)),
        enabled: 0,
      },
    );
    await tenv.DB.prepare(
      "INSERT INTO deleted_alias (email, reason, alias_id) VALUES (?1, 0, NULL)",
    )
      .bind(alias.email)
      .run();

    await runMaintenance(tenv);

    expect(
      await tenv.DB.prepare("SELECT 1 FROM alias WHERE id = ?1")
        .bind(alias.id)
        .first(),
    ).toBeNull();
    const count = await tenv.DB.prepare(
      "SELECT COUNT(*) AS n FROM deleted_alias WHERE email = ?1",
    )
      .bind(alias.email)
      .first<{ n: number }>();
    expect(count?.n).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// runMaintenance: rate_limit trim
// ---------------------------------------------------------------------------

describe("runMaintenance — rate_limit trim", () => {
  it("computes per-family expiries", () => {
    // fixed windows: expiry = end of window
    expect(rateLimitRowExpiry("rl:auth_login:ip:1.2.3.4:60", 100)).toBe(6060);
    expect(rateLimitRowExpiry("rlw:reset:ip:1.2.3.4:3600", 5)).toBe(21600);
    expect(rateLimitRowExpiry("rlweb:contacts:userid:7:86400", 2)).toBe(259200);
    // bucket keys: window_start is the bucket-start epoch second
    expect(rateLimitRowExpiry("bl:alias_create_900:1:1000", 1000)).toBe(1900);
    expect(rateLimitRowExpiry("bl:alias_restore_all_3600:1:0", 0)).toBe(3600);
    // request locks: 5s TTL
    expect(rateLimitRowExpiry("lock:user:1:mailbox_detail", 50)).toBe(55);
    // unknown shapes are never touched
    expect(rateLimitRowExpiry("something:weird", 0)).toBeNull();
  });

  it("drops rows whose window is long past, keeps live and unknown rows", async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    // expired (window ended > 1 day ago)
    await insertRateRow(
      "rl:auth_login:ip:1.2.3.4:60",
      Math.floor(nowSec / 60) - 10000,
    );
    await insertRateRow(
      "rlw:forgot:ip:1.2.3.4:3600",
      Math.floor(nowSec / 3600) - 1000,
    );
    await insertRateRow(
      "rlweb:contacts:userid:7:86400",
      Math.floor(nowSec / 86400) - 30,
    );
    const oldBucket = nowSec - 90000 - ((nowSec - 90000) % 900);
    await insertRateRow(`bl:alias_create_900:1:${oldBucket}`, oldBucket);
    await insertRateRow("lock:user:1:mailbox_detail", nowSec - 200000);
    // live
    await insertRateRow("rl:auth_login:ip:5.6.7.8:60", Math.floor(nowSec / 60));
    await insertRateRow(
      "rlweb:contacts:userid:8:86400",
      Math.floor(nowSec / 86400),
    );
    const freshBucket = nowSec - (nowSec % 900);
    await insertRateRow(`bl:alias_create_900:2:${freshBucket}`, freshBucket);
    await insertRateRow("lock:user:2:mailbox_detail", nowSec);
    // unknown shape
    await insertRateRow("something:weird", 0);

    await runMaintenance(tenv);

    const left = await tenv.DB.prepare(
      "SELECT key FROM rate_limit ORDER BY key",
    ).all<{ key: string }>();
    expect(left.results.map((r) => r.key)).toEqual(
      [
        `bl:alias_create_900:2:${freshBucket}`,
        "lock:user:2:mailbox_detail",
        "rl:auth_login:ip:5.6.7.8:60",
        "rlweb:contacts:userid:8:86400",
        "something:weird",
      ].sort(),
    );
  });
});

// ---------------------------------------------------------------------------
// runMaintenance: old-data cleanup (cron.py delete_old_data)
// ---------------------------------------------------------------------------

describe("runMaintenance — old-data cleanup", () => {
  it("deletes notifications older than KEEP_OLD_DATA_DAYS", async () => {
    const user = await createUser(tenv.DB);
    const old = await tenv.DB.prepare(
      "INSERT INTO notification (user_id, message, created_at) VALUES (?1, 'old', ?2) RETURNING id",
    )
      .bind(user.id, toStr(addDays(new Date(), -31)))
      .first<{ id: number }>();
    const recent = await tenv.DB.prepare(
      "INSERT INTO notification (user_id, message, created_at) VALUES (?1, 'recent', ?2) RETURNING id",
    )
      .bind(user.id, toStr(addDays(new Date(), -29)))
      .first<{ id: number }>();

    await runMaintenance(tenv);

    const left = await tenv.DB.prepare("SELECT id FROM notification").all<{
      id: number;
    }>();
    expect(left.results.map((r) => r.id)).toEqual([recent?.id]);
    expect(old).not.toBeNull();
  });

  it("deletes finished jobs older than KEEP_OLD_DATA_DAYS, keeps pending ones", async () => {
    const oldStamp = toStr(addDays(new Date(), -31));
    const oldDone = await insertJob("x", null, { state: JOB_STATE_DONE });
    const oldExhausted = await insertJob("x", null, {
      state: JOB_STATE_TAKEN,
      attempts: 5,
    });
    const oldReady = await insertJob("x"); // updated_at stays NULL -> kept
    const freshDone = await insertJob("x", null, { state: JOB_STATE_DONE });
    await tenv.DB.prepare("UPDATE job SET updated_at = ?1 WHERE id IN (?2, ?3)")
      .bind(oldStamp, oldDone, oldExhausted)
      .run();
    await tenv.DB.prepare("UPDATE job SET updated_at = ?1 WHERE id = ?2")
      .bind(nowStr(), freshDone)
      .run();

    await runMaintenance(tenv);

    const left = await tenv.DB.prepare("SELECT id FROM job ORDER BY id").all<{
      id: number;
    }>();
    expect(left.results.map((r) => r.id)).toEqual([oldReady, freshDone]);
  });
});

// ---------------------------------------------------------------------------
// onboarding-1/2/4 handlers via runPendingJobs
// ---------------------------------------------------------------------------

describe("onboarding jobs", () => {
  it("onboarding-1 sends the send-from-alias tip to the user", async () => {
    const user = await createUser(tenv.DB);
    const id = await insertJob("onboarding-1", { user_id: user.id });

    expect(await runPendingJobs(tenv)).toBe(1);
    expect((await getJob(id))?.state).toBe(JOB_STATE_DONE);

    expect(sentEmails).toHaveLength(1);
    const msg = sentEmails[0];
    expect(msg.to).toBe(user.email);
    expect(msg.subject).toBe("SimpleLogin Tip: Send emails from your alias");
    expect(msg.text.startsWith(`This email is sent to ${user.email} `)).toBe(
      true,
    );
    expect(msg.text).toContain(`${URL}/dashboard/setting#notification`);
    expect(msg.text).toContain(
      "Do you know you can send an email to anyone from your alias?",
    );
    expect(msg.text.endsWith("SimpleLogin Team.")).toBe(true);
    expect(msg.html).toContain("<h1>Send emails from your alias.</h1>");
    expect(msg.html).toContain("part of our onboarding series");
  });

  it("onboarding-2 sends the multiple-mailboxes tip", async () => {
    const user = await createUser(tenv.DB);
    const id = await insertJob("onboarding-2", { user_id: user.id });

    await runPendingJobs(tenv);

    expect((await getJob(id))?.state).toBe(JOB_STATE_DONE);
    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].subject).toBe("SimpleLogin Tip: Multiple mailboxes");
    expect(sentEmails[0].text).toContain(`${URL}/dashboard/mailbox`);
    expect(sentEmails[0].html).toContain(
      "<h1>Add other mailboxes to SimpleLogin.</h1>",
    );
  });

  it("skips users who disabled notifications / are not activated / are gone (job still done)", async () => {
    const noNotif = await createUser(tenv.DB, { notification: 0 });
    const notActivated = await createUser(tenv.DB, { activated: 0 });
    const j1 = await insertJob("onboarding-1", { user_id: noNotif.id });
    const j2 = await insertJob("onboarding-2", { user_id: notActivated.id });
    const j3 = await insertJob("onboarding-4", { user_id: 99999999 });

    expect(await runPendingJobs(tenv)).toBe(3);

    for (const id of [j1, j2, j3])
      expect((await getJob(id))?.state).toBe(JOB_STATE_DONE);
    expect(sentEmails).toHaveLength(0);
  });

  it("sends to the newsletter alias when set and enabled, skips when disabled", async () => {
    const user = await createUser(tenv.DB);
    const alias = await createAlias(tenv.DB, user.id, user.default_mailbox_id!);
    await tenv.DB.prepare(
      "UPDATE users SET newsletter_alias_id = ?1 WHERE id = ?2",
    )
      .bind(alias.id, user.id)
      .run();
    await insertJob("onboarding-1", { user_id: user.id });
    await runPendingJobs(tenv);
    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].to).toBe(alias.email);

    sentEmails.length = 0;
    await tenv.DB.prepare("UPDATE alias SET enabled = 0 WHERE id = ?1")
      .bind(alias.id)
      .run();
    const id = await insertJob("onboarding-1", { user_id: user.id });
    await runPendingJobs(tenv);
    expect((await getJob(id))?.state).toBe(JOB_STATE_DONE);
    expect(sentEmails).toHaveLength(0);
  });

  it("onboarding-4 is skipped when the only verified mailbox is a Proton one", async () => {
    const user = await createUser(tenv.DB);
    await tenv.DB.prepare("UPDATE mailbox SET email = ?1 WHERE id = ?2")
      .bind(`proton${uniq()}@proton.me`, user.default_mailbox_id)
      .run();
    const id = await insertJob("onboarding-4", { user_id: user.id });

    await runPendingJobs(tenv);

    expect((await getJob(id))?.state).toBe(JOB_STATE_DONE);
    expect(sentEmails).toHaveLength(0);
  });

  it("onboarding-4 sends when a second verified mailbox exists", async () => {
    const user = await createUser(tenv.DB);
    await tenv.DB.prepare("UPDATE mailbox SET email = ?1 WHERE id = ?2")
      .bind(`proton${uniq()}@pm.me`, user.default_mailbox_id)
      .run();
    await createMailbox(tenv.DB, user.id, `second${uniq()}@example.com`);
    await insertJob("onboarding-4", { user_id: user.id });

    await runPendingJobs(tenv);

    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].subject).toBe(
      "SimpleLogin Tip: Secure your emails with PGP",
    );
    expect(sentEmails[0].text).toContain("Pretty Good Privacy");
    expect(sentEmails[0].html).toContain(
      "<h1>Secure your emails with PGP.</h1>",
    );
  });
});

// ---------------------------------------------------------------------------
// send-user-report handler (ExportUserDataJob port)
// ---------------------------------------------------------------------------

describe("send-user-report job", () => {
  it("emails the user_report.zip with the Flask file layout", async () => {
    const user = await createUser(tenv.DB);
    const alias = await createAlias(tenv.DB, user.id, user.default_mailbox_id!);
    const contact = await createContact(tenv.DB, user.id, alias.id);
    await createEmailLog(tenv.DB, user.id, contact.id);
    const id = await insertJob("send-user-report", { user_id: user.id });

    expect(await runPendingJobs(tenv)).toBe(1);
    expect((await getJob(id))?.state).toBe(JOB_STATE_DONE);

    expect(sentUserReports).toHaveLength(1);
    const report = sentUserReports[0];
    expect(report.to).toBe(user.email);
    expect(report.subject).toBe("Your SimpleLogin data");
    expect(report.html).toContain(
      "a copy of your data which are stored on SimpleLogin",
    );
    expect(report.files.map((f) => f.name)).toEqual([
      "user.json",
      "aliases.json",
      "mailboxes.json",
      "contacts.json",
      "directories.json",
      "domains.json",
      "email_logs.json",
    ]);

    // ExportUserDataJob.REMOVE_FIELDS + arrow isoformat dates
    const userJson = JSON.parse(report.files[0].content);
    expect(userJson.email).toBe(user.email);
    expect(userJson).not.toHaveProperty("password");
    expect(userJson).not.toHaveProperty("otp_secret");
    expect(userJson.created_at).toContain("T");

    const aliases = JSON.parse(report.files[1].content);
    expect(aliases).toHaveLength(1);
    expect(aliases[0].email).toBe(alias.email);
    expect(aliases[0]).not.toHaveProperty("transfer_token");
    expect(aliases[0]).not.toHaveProperty("hibp_last_check");

    expect(JSON.parse(report.files[2].content)).toHaveLength(1); // mailboxes
    expect(JSON.parse(report.files[3].content)).toHaveLength(1); // contacts
    expect(JSON.parse(report.files[4].content)).toHaveLength(0); // directories
    expect(JSON.parse(report.files[6].content)).toHaveLength(1); // email_logs

    // TransactionalEmail.create parity
    expect(
      await tenv.DB.prepare(
        "SELECT 1 FROM transactional_email WHERE email = ?1",
      )
        .bind(user.email)
        .first(),
    ).not.toBeNull();

    // the zip is a real archive: first local header is user.json, deflated
    const zip = report.zip;
    const dv = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
    expect(dv.getUint32(0, true)).toBe(0x04034b50);
    const compressedSize = dv.getUint32(18, true);
    const nameLen = dv.getUint16(26, true);
    expect(new TextDecoder().decode(zip.subarray(30, 30 + nameLen))).toBe(
      "user.json",
    );
    const inflated = inflateRawSync(
      zip.subarray(30 + nameLen, 30 + nameLen + compressedSize),
    );
    expect(new TextDecoder().decode(inflated)).toBe(report.files[0].content);
  });

  it("skips users who cannot send or receive, and missing users", async () => {
    const disabled = await createUser(tenv.DB, { disabled: 1 });
    const j1 = await insertJob("send-user-report", { user_id: disabled.id });
    const j2 = await insertJob("send-user-report", { user_id: 99999999 });

    expect(await runPendingJobs(tenv)).toBe(2);

    expect((await getJob(j1))?.state).toBe(JOB_STATE_DONE);
    expect((await getJob(j2))?.state).toBe(JOB_STATE_DONE);
    expect(sentUserReports).toHaveLength(0);
    expect(
      await tenv.DB.prepare(
        "SELECT 1 FROM transactional_email WHERE email = ?1",
      )
        .bind(disabled.email)
        .first(),
    ).toBeNull();
  });
});
