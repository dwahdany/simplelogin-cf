/**
 * batch-import job handler (src/jobs/handlers/batch-import.ts — port of
 * app/import_utils.py). Jobs are seeded exactly like the upload route
 * (web/mailbox-domain-pages.ts Route 13): file row + KV blob + batch_import
 * row + job row, then driven through runPendingJobs().
 */

import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import {
  JOB_STATE_DONE,
  JOB_STATE_TAKEN,
  type JobRow,
  runPendingJobs,
} from "../src/jobs";
import { addDays, nowStr, toStr } from "../src/lib/dates";
import type { Env } from "../src/lib/env";
import type { AliasRow, CustomDomainRow, UserRow } from "../src/lib/rows";
import { createAlias, createMailbox, createUser } from "./fixtures";

const tenv = env as unknown as Env;

let seq = 0;
const uniq = () => ++seq;

function createCustomDomain(
  userId: number,
  domain: string,
  overrides: Record<string, unknown> = {},
): Promise<CustomDomainRow> {
  const values: Record<string, unknown> = {
    user_id: userId,
    domain,
    verified: 1,
    ownership_verified: 1,
    ...overrides,
  };
  const cols = Object.keys(values);
  return tenv.DB.prepare(
    `INSERT INTO custom_domain (${cols.join(", ")})
     VALUES (${cols.map((_, i) => `?${i + 1}`).join(", ")}) RETURNING *`,
  )
    .bind(...cols.map((c) => values[c]))
    .first<CustomDomainRow>() as Promise<CustomDomainRow>;
}

/** Mirrors the POST /dashboard/batch_import upload side exactly
 * (web/mailbox-domain-pages.ts L3187-3207). */
async function uploadCsv(
  user: UserRow,
  csv: string,
): Promise<{ batchImportId: number; jobId: number }> {
  const filePath = `testimport${uniq()}.csv`; // random_string(20) + ".csv"
  const fileRow = await tenv.DB.prepare(
    "INSERT INTO file (path, user_id) VALUES (?1, ?2) RETURNING id",
  )
    .bind(filePath, user.id)
    .first<{ id: number }>();
  await tenv.KV.put(`file:${filePath}`, new TextEncoder().encode(csv));
  const bi = await tenv.DB.prepare(
    "INSERT INTO batch_import (user_id, file_id) VALUES (?1, ?2) RETURNING id",
  )
    .bind(user.id, fileRow?.id)
    .first<{ id: number }>();
  const job = await tenv.DB.prepare(
    "INSERT INTO job (name, payload, run_at) VALUES ('batch-import', ?1, ?2) RETURNING id",
  )
    .bind(JSON.stringify({ batch_import_id: bi?.id }), nowStr())
    .first<{ id: number }>();
  if (!bi || !job) throw new Error("seed failed");
  return { batchImportId: bi.id, jobId: job.id };
}

function getJob(id: number): Promise<JobRow | null> {
  return tenv.DB.prepare("SELECT * FROM job WHERE id = ?1")
    .bind(id)
    .first<JobRow>();
}

function aliasByEmail(email: string): Promise<AliasRow | null> {
  return tenv.DB.prepare("SELECT * FROM alias WHERE email = ?1")
    .bind(email)
    .first<AliasRow>();
}

async function aliasMailboxIds(aliasId: number): Promise<number[]> {
  const res = await tenv.DB.prepare(
    "SELECT mailbox_id FROM alias_mailbox WHERE alias_id = ?1 ORDER BY id",
  )
    .bind(aliasId)
    .all<{ mailbox_id: number }>();
  return res.results.map((r) => r.mailbox_id);
}

async function importedCount(batchImportId: number): Promise<number> {
  const row = await tenv.DB.prepare(
    "SELECT COUNT(*) AS n FROM alias WHERE batch_import_id = ?1",
  )
    .bind(batchImportId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

async function processedFlag(batchImportId: number): Promise<number> {
  const row = await tenv.DB.prepare(
    "SELECT processed FROM batch_import WHERE id = ?1",
  )
    .bind(batchImportId)
    .first<{ processed: number }>();
  return row?.processed ?? -1;
}

beforeEach(async () => {
  await tenv.DB.prepare("DELETE FROM job").run();
});

describe("batch-import job (import_utils.py port)", () => {
  it("imports rows: note/custom_domain/batch_import ids, mailboxes, job done", async () => {
    const user = await createUser(tenv.DB);
    const mb2 = await createMailbox(tenv.DB, user.id, `mb2-${uniq()}@ex.com`);
    const dom = `d${uniq()}.example.com`;
    const domain = await createCustomDomain(user.id, dom);
    const { batchImportId, jobId } = await uploadCsv(
      user,
      // "enabled" is ignored by Flask; extra mailboxes get alias_mailbox rows
      "alias,note,enabled,mailboxes\n" +
        `hello@${dom},my note,true,\n` +
        `multi@${dom},,false,${user.email} ${mb2.email}\n` +
        `second-only@${dom},n3,true,${mb2.email}\n`,
    );

    expect(await runPendingJobs(tenv)).toBe(1);
    expect((await getJob(jobId))?.state).toBe(JOB_STATE_DONE);
    expect(await processedFlag(batchImportId)).toBe(1);
    expect(await importedCount(batchImportId)).toBe(3);

    const a1 = await aliasByEmail(`hello@${dom}`);
    expect(a1?.note).toBe("my note");
    expect(a1?.custom_domain_id).toBe(domain.id);
    expect(a1?.batch_import_id).toBe(batchImportId);
    expect(a1?.mailbox_id).toBe(user.default_mailbox_id);
    expect(await aliasMailboxIds(a1?.id ?? 0)).toEqual([]);

    // first listed mailbox -> alias.mailbox_id, the rest -> alias_mailbox
    const a2 = await aliasByEmail(`multi@${dom}`);
    expect(a2?.note).toBe("");
    expect(a2?.mailbox_id).toBe(user.default_mailbox_id);
    expect(await aliasMailboxIds(a2?.id ?? 0)).toEqual([mb2.id]);

    const a3 = await aliasByEmail(`second-only@${dom}`);
    expect(a3?.mailbox_id).toBe(mb2.id);
    expect(await aliasMailboxIds(a3?.id ?? 0)).toEqual([]);

    // Alias.create -> emit_alias_audit_log(CreateAlias) (models.py L1862)
    const audit = await tenv.DB.prepare(
      "SELECT action, message FROM alias_audit_log WHERE alias_id = ?1",
    )
      .bind(a1?.id)
      .first<{ action: string; message: string }>();
    expect(audit).toEqual({ action: "create", message: "New alias created" });
  });

  it("silently skips foreign/unverified domains, dupes, bad prefixes, invalid emails", async () => {
    const user = await createUser(tenv.DB);
    const other = await createUser(tenv.DB);
    const n = uniq();
    const d1 = await createCustomDomain(user.id, `d${n}-own.example.com`);
    await createCustomDomain(other.id, `d${n}-other.example.com`); // foreign
    await createCustomDomain(user.id, `d${n}-unowned.example.com`, {
      ownership_verified: 0,
    });
    if (user.default_mailbox_id === null) throw new Error("no default mb");
    await createAlias(tenv.DB, user.id, user.default_mailbox_id, {
      email: `dupe@${d1.domain}`,
    });
    await tenv.DB.prepare("INSERT INTO deleted_alias (email) VALUES (?1)")
      .bind(`gone@${d1.domain}`)
      .run();
    await tenv.DB.prepare(
      "INSERT INTO domain_deleted_alias (email, domain_id, user_id) VALUES (?1, ?2, ?3)",
    )
      .bind(`trashed@${d1.domain}`, d1.id, user.id)
      .run();

    const { batchImportId, jobId } = await uploadCsv(
      user,
      [
        "alias,note",
        `ok@${d1.domain},fine`,
        `foreign@d${n}-other.example.com,skip`, // other user's domain
        `unowned@d${n}-unowned.example.com,skip`, // ownership not verified
        "nodomain@nowhere.example.com,skip", // no matching custom domain
        `dupe@${d1.domain},skip`, // alias exists
        `gone@${d1.domain},skip`, // deleted_alias
        `trashed@${d1.domain},skip`, // domain_deleted_alias
        `Bad#Prefix@${d1.domain},skip`, // '#' fails check_alias_prefix
        "noatsign,skip", // fails validate_email
        "",
      ].join("\n"),
    );

    expect(await runPendingJobs(tenv)).toBe(1);
    expect((await getJob(jobId))?.state).toBe(JOB_STATE_DONE);
    expect(await importedCount(batchImportId)).toBe(1);
    expect(await aliasByEmail(`ok@${d1.domain}`)).not.toBeNull();
  });

  it("falls back to the default mailbox and canonicalizes mailbox emails", async () => {
    const user = await createUser(tenv.DB);
    const other = await createUser(tenv.DB);
    const dom = `d${uniq()}.example.com`;
    await createCustomDomain(user.id, dom);
    const unverified = await createMailbox(
      tenv.DB,
      user.id,
      `unv-${uniq()}@ex.com`,
      { verified: 0 },
    );
    const foreign = await createMailbox(
      tenv.DB,
      other.id,
      `foreign-${uniq()}@ex.com`,
    );
    const gmail = await createMailbox(tenv.DB, user.id, "johndoe@gmail.com");

    const { jobId } = await uploadCsv(
      user,
      "alias,note,mailboxes\n" +
        `fallback@${dom},n,${unverified.email} ${foreign.email}\n` +
        `canonical@${dom},n,John.Doe+tag@gmail.com\n`,
    );

    expect(await runPendingJobs(tenv)).toBe(1);
    expect((await getJob(jobId))?.state).toBe(JOB_STATE_DONE);

    // no usable mailbox in the row -> user.default_mailbox_id (L97-98)
    const fb = await aliasByEmail(`fallback@${dom}`);
    expect(fb?.mailbox_id).toBe(user.default_mailbox_id);
    expect(await aliasMailboxIds(fb?.id ?? 0)).toEqual([]);

    // canonicalize_email: John.Doe+tag@gmail.com -> johndoe@gmail.com (L88)
    const canon = await aliasByEmail(`canonical@${dom}`);
    expect(canon?.mailbox_id).toBe(gmail.id);
  });

  it("handles quoted fields, blank lines, CRLF and BOM like csv.DictReader", async () => {
    const user = await createUser(tenv.DB);
    const dom = `d${uniq()}.example.com`;
    await createCustomDomain(user.id, dom);
    const { batchImportId, jobId } = await uploadCsv(
      user,
      "\ufeffalias,note\r\n" +
        "\r\n" + // blank row: skipped
        `quoted@${dom},"hello, ""world"""\r\n` +
        `short@${dom}\r\n`, // short row: note restval=None
    );

    expect(await runPendingJobs(tenv)).toBe(1);
    expect((await getJob(jobId))?.state).toBe(JOB_STATE_DONE);
    expect(await importedCount(batchImportId)).toBe(2);
    expect((await aliasByEmail(`quoted@${dom}`))?.note).toBe('hello, "world"');
    expect((await aliasByEmail(`short@${dom}`))?.note).toBeNull();
  });

  it("skips every row when the header lacks the alias/note columns (KeyError)", async () => {
    const user = await createUser(tenv.DB);
    const dom = `d${uniq()}.example.com`;
    await createCustomDomain(user.id, dom);
    const { batchImportId, jobId } = await uploadCsv(
      user,
      `email,note\nvalid@${dom},n\n`,
    );

    expect(await runPendingJobs(tenv)).toBe(1);
    expect((await getJob(jobId))?.state).toBe(JOB_STATE_DONE);
    expect(await importedCount(batchImportId)).toBe(0);
    // processed is still flipped first (import_utils.py L26-27)
    expect(await processedFlag(batchImportId)).toBe(1);
  });

  it("skips rows once the user cannot create new aliases (plan gate)", async () => {
    // free user out of trial at the MAX_NB_EMAIL_FREE_PLAN=3 cap (vitest env)
    const user = await createUser(tenv.DB, {
      trial_end: toStr(addDays(new Date(), -1)),
    });
    if (user.default_mailbox_id === null) throw new Error("no default mb");
    for (let i = 0; i < 3; i++) {
      await createAlias(tenv.DB, user.id, user.default_mailbox_id);
    }
    const dom = `d${uniq()}.example.com`;
    await createCustomDomain(user.id, dom);
    const { batchImportId, jobId } = await uploadCsv(
      user,
      `alias,note\ncapped@${dom},n\n`,
    );

    expect(await runPendingJobs(tenv)).toBe(1);
    expect((await getJob(jobId))?.state).toBe(JOB_STATE_DONE);
    expect(await importedCount(batchImportId)).toBe(0);
    expect(await aliasByEmail(`capped@${dom}`)).toBeNull();
  });

  it("fails the job (retry path) when the batch_import row is missing", async () => {
    const res = await tenv.DB.prepare(
      "INSERT INTO job (name, payload, run_at) VALUES ('batch-import', ?1, ?2)",
    )
      .bind(JSON.stringify({ batch_import_id: 999999 }), nowStr())
      .run();

    expect(await runPendingJobs(tenv)).toBe(0);
    const job = await getJob(res.meta.last_row_id);
    expect(job?.state).toBe(JOB_STATE_TAKEN);
    expect(job?.attempts).toBe(1);
  });
});
