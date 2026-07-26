/**
 * Integration tests for the three deletion job handlers
 * (src/jobs/handlers/delete-mailbox.ts / delete-domain.ts /
 * delete-account.ts), driven end-to-end through runPendingJobs like the
 * cron scheduled() handler does. Flask reference: job_runner.py
 * delete_mailbox_job / DELETE_ACCOUNT branch, tasks/delete_custom_domain_job.py,
 * and the Mailbox.delete / CustomDomain.delete / User.delete model overrides.
 */

import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { JOB_STATE_DONE, runPendingJobs } from "../src/jobs";
import {
  CF_OAUTH_REVOKE_URL,
  saveGrant,
  setCfOauthFetch,
} from "../src/lib/cfoauth";
import { nowStr } from "../src/lib/dates";
import type { Env } from "../src/lib/env";
import { sentEmails } from "../src/lib/mailer";
import type {
  AliasRow,
  CustomDomainRow,
  DeletedAliasRow,
  DomainDeletedAliasRow,
} from "../src/lib/rows";
import {
  createAlias,
  createApiKey,
  createContact,
  createMailbox,
  createUser,
} from "./fixtures";

const tenv = env as unknown as Env;
const db = tenv.DB;

let seq = 0;
const uniq = () => ++seq;

async function enqueue(name: string, payload: unknown): Promise<number> {
  const res = await db
    .prepare("INSERT INTO job (name, payload, run_at) VALUES (?1, ?2, ?3)")
    .bind(name, JSON.stringify(payload), nowStr())
    .run();
  return res.meta.last_row_id;
}

async function jobState(id: number): Promise<number | undefined> {
  const row = await db
    .prepare("SELECT state FROM job WHERE id = ?1")
    .bind(id)
    .first<{ state: number }>();
  return row?.state;
}

async function count(sql: string, ...binds: unknown[]): Promise<number> {
  const row = await db
    .prepare(sql)
    .bind(...binds)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

function getAlias(id: number): Promise<AliasRow | null> {
  return db.prepare("SELECT * FROM alias WHERE id = ?1").bind(id).first();
}

async function createCustomDomain(
  userId: number,
  over: Record<string, unknown> = {},
): Promise<CustomDomainRow> {
  const row = await db
    .prepare(
      `INSERT INTO custom_domain (user_id, domain, verified, ownership_verified, is_sl_subdomain)
       VALUES (?1, ?2, 1, 1, ?3) RETURNING *`,
    )
    .bind(
      userId,
      over.domain ?? `d${uniq()}.example.org`,
      over.is_sl_subdomain ?? 0,
    )
    .first<CustomDomainRow>();
  if (!row) throw new Error("custom_domain insert failed");
  return row;
}

function addAliasMailbox(aliasId: number, mailboxId: number): Promise<unknown> {
  return db
    .prepare("INSERT INTO alias_mailbox (alias_id, mailbox_id) VALUES (?1, ?2)")
    .bind(aliasId, mailboxId)
    .run();
}

beforeEach(async () => {
  await db.prepare("DELETE FROM job").run();
  sentEmails.length = 0;
});

// ===========================================================================
// delete-mailbox
// ===========================================================================

describe("delete-mailbox job", () => {
  it("DeleteImmediately user: hard-deletes aliases into deleted_alias and emails", async () => {
    const user = await createUser(db, { alias_delete_action: 1 });
    const mb2 = await createMailbox(db, user.id, `mb${uniq()}@inbox.example`);
    const a1 = await createAlias(db, user.id, mb2.id);

    const jobId = await enqueue("delete-mailbox", {
      mailbox_id: mb2.id,
      transfer_mailbox_id: null,
      send_mail: true,
    });
    expect(await runPendingJobs(tenv)).toBe(1);
    expect(await jobState(jobId)).toBe(JOB_STATE_DONE);

    expect(
      await count("SELECT COUNT(*) AS n FROM mailbox WHERE id = ?1", mb2.id),
    ).toBe(0);
    expect(await getAlias(a1.id)).toBeNull();
    const trash = await db
      .prepare("SELECT * FROM deleted_alias WHERE email = ?1")
      .bind(a1.email)
      .first<DeletedAliasRow>();
    expect(trash?.reason).toBe(4); // AliasDeleteReason.MailboxDeleted
    expect(trash?.alias_id).toBe(a1.id);

    // user_audit_log DeleteMailbox
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM user_audit_log WHERE user_id = ?1 AND action = 'delete_mailbox' AND message = ?2",
        user.id,
        `Delete mailbox ${mb2.id} (${mb2.email})`,
      ),
    ).toBe(1);

    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].to).toBe(user.email);
    expect(sentEmails[0].subject).toBe(
      `Your mailbox ${mb2.email} has been deleted`,
    );
    expect(sentEmails[0].text).toBe(
      `Mailbox ${mb2.email} along with its aliases have been deleted successfully.\n    Regards,\n    SimpleLogin team.\n    `,
    );
  });

  it("MoveToTrash user (default): reassigns the alias to the default mailbox and soft-trashes it", async () => {
    const user = await createUser(db);
    const mb2 = await createMailbox(db, user.id, `mb${uniq()}@inbox.example`);
    const a1 = await createAlias(db, user.id, mb2.id);

    await enqueue("delete-mailbox", {
      mailbox_id: mb2.id,
      transfer_mailbox_id: null,
      send_mail: true,
    });
    await runPendingJobs(tenv);

    const alias = await getAlias(a1.id);
    expect(alias).not.toBeNull();
    expect(alias?.mailbox_id).toBe(user.default_mailbox_id);
    expect(alias?.delete_on).not.toBeNull();
    expect(alias?.enabled).toBe(0);
    expect(alias?.delete_reason).toBe(4);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM deleted_alias WHERE email = ?1",
        a1.email,
      ),
    ).toBe(0);
  });

  it("custom-domain aliases always hard-delete into domain_deleted_alias", async () => {
    const user = await createUser(db); // MoveToTrash default
    const mb2 = await createMailbox(db, user.id, `mb${uniq()}@inbox.example`);
    const cd = await createCustomDomain(user.id);
    const a1 = await createAlias(db, user.id, mb2.id, {
      email: `hello@${cd.domain}`,
      custom_domain_id: cd.id,
    });

    await enqueue("delete-mailbox", {
      mailbox_id: mb2.id,
      transfer_mailbox_id: null,
      send_mail: true,
    });
    await runPendingJobs(tenv);

    expect(await getAlias(a1.id)).toBeNull();
    const trash = await db
      .prepare(
        "SELECT * FROM domain_deleted_alias WHERE email = ?1 AND domain_id = ?2",
      )
      .bind(a1.email, cd.id)
      .first<DomainDeletedAliasRow>();
    expect(trash?.user_id).toBe(user.id);
    expect(trash?.reason).toBe(4);
    expect(trash?.alias_id).toBe(a1.id);
  });

  it("transfers aliases to the transfer mailbox (primary + join-row cases)", async () => {
    const user = await createUser(db);
    const mb2 = await createMailbox(db, user.id, `mb${uniq()}@inbox.example`);
    const mb3 = await createMailbox(db, user.id, `mb${uniq()}@inbox.example`);
    // a1: mb2 is the primary mailbox
    const a1 = await createAlias(db, user.id, mb2.id);
    // a2: mb2 is a secondary mailbox (join row)
    const a2 = await createAlias(db, user.id, user.default_mailbox_id ?? 0);
    await addAliasMailbox(a2.id, mb2.id);
    // a3: mb2 primary AND the transfer target already a secondary
    const a3 = await createAlias(db, user.id, mb2.id);
    await addAliasMailbox(a3.id, mb3.id);

    const jobId = await enqueue("delete-mailbox", {
      mailbox_id: mb2.id,
      transfer_mailbox_id: mb3.id,
      send_mail: true,
    });
    await runPendingJobs(tenv);
    expect(await jobState(jobId)).toBe(JOB_STATE_DONE);

    // a1: primary re-pointed at the transfer mailbox, alias untouched otherwise
    const a1After = await getAlias(a1.id);
    expect(a1After?.mailbox_id).toBe(mb3.id);
    expect(a1After?.delete_on).toBeNull();
    // a2: join row moved from mb2 to mb3, primary unchanged
    expect((await getAlias(a2.id))?.mailbox_id).toBe(user.default_mailbox_id);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM alias_mailbox WHERE alias_id = ?1 AND mailbox_id = ?2",
        a2.id,
        mb3.id,
      ),
    ).toBe(1);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM alias_mailbox WHERE alias_id = ?1 AND mailbox_id = ?2",
        a2.id,
        mb2.id,
      ),
    ).toBe(0);
    // a3: transfer became the primary; the duplicate join row was removed
    expect((await getAlias(a3.id))?.mailbox_id).toBe(mb3.id);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM alias_mailbox WHERE alias_id = ?1",
        a3.id,
      ),
    ).toBe(0);
    // mailbox row is gone
    expect(
      await count("SELECT COUNT(*) AS n FROM mailbox WHERE id = ?1", mb2.id),
    ).toBe(0);

    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].subject).toBe(
      `Your mailbox ${mb2.email} has been deleted`,
    );
    expect(sentEmails[0].text).toBe(
      `Mailbox ${mb2.email} and its alias have been transferred to ${mb3.email}.\n    Regards,\n    SimpleLogin team.\n    `,
    );
  });

  it("without transfer, a multi-mailbox alias falls back to its first VERIFIED secondary", async () => {
    const user = await createUser(db);
    const mb2 = await createMailbox(db, user.id, `mb${uniq()}@inbox.example`);
    const mb3 = await createMailbox(db, user.id, `mb${uniq()}@inbox.example`);
    const mb4 = await createMailbox(db, user.id, `mb${uniq()}@inbox.example`, {
      verified: 0,
    });
    // a1 has a verified secondary -> re-pointed, stays alive
    const a1 = await createAlias(db, user.id, mb2.id);
    await addAliasMailbox(a1.id, mb3.id);
    // a2's only secondary is unverified -> does NOT count (models.py L1728),
    // so the alias goes down the trash path instead
    const a2 = await createAlias(db, user.id, mb2.id);
    await addAliasMailbox(a2.id, mb4.id);

    await enqueue("delete-mailbox", {
      mailbox_id: mb2.id,
      transfer_mailbox_id: null,
      send_mail: true,
    });
    await runPendingJobs(tenv);

    const a1After = await getAlias(a1.id);
    expect(a1After?.mailbox_id).toBe(mb3.id);
    expect(a1After?.delete_on).toBeNull();
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM alias_mailbox WHERE alias_id = ?1",
        a1.id,
      ),
    ).toBe(0);

    const a2After = await getAlias(a2.id);
    expect(a2After?.mailbox_id).toBe(user.default_mailbox_id);
    expect(a2After?.delete_on).not.toBeNull();
    // the unverified secondary's join row is untouched (mb4 still exists)
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM alias_mailbox WHERE alias_id = ?1 AND mailbox_id = ?2",
        a2.id,
        mb4.id,
      ),
    ).toBe(1);
  });

  it("vanished mailbox: job completes silently", async () => {
    const jobId = await enqueue("delete-mailbox", {
      mailbox_id: 999999,
      transfer_mailbox_id: null,
      send_mail: true,
    });
    expect(await runPendingJobs(tenv)).toBe(1);
    expect(await jobState(jobId)).toBe(JOB_STATE_DONE);
    expect(sentEmails).toHaveLength(0);
  });

  it("send_mail=false suppresses the confirmation email", async () => {
    const user = await createUser(db, { alias_delete_action: 1 });
    const mb2 = await createMailbox(db, user.id, `mb${uniq()}@inbox.example`);
    await enqueue("delete-mailbox", {
      mailbox_id: mb2.id,
      transfer_mailbox_id: null,
      send_mail: false,
    });
    await runPendingJobs(tenv);
    expect(
      await count("SELECT COUNT(*) AS n FROM mailbox WHERE id = ?1", mb2.id),
    ).toBe(0);
    expect(sentEmails).toHaveLength(0);
  });

  it("disabled user gets no confirmation email (can_send_or_receive)", async () => {
    const user = await createUser(db, { disabled: 1 });
    const mb2 = await createMailbox(db, user.id, `mb${uniq()}@inbox.example`);
    await enqueue("delete-mailbox", {
      mailbox_id: mb2.id,
      transfer_mailbox_id: null,
      send_mail: true,
    });
    await runPendingJobs(tenv);
    expect(
      await count("SELECT COUNT(*) AS n FROM mailbox WHERE id = ?1", mb2.id),
    ).toBe(0);
    expect(sentEmails).toHaveLength(0);
  });
});

// ===========================================================================
// delete-domain
// ===========================================================================

describe("delete-domain job", () => {
  it("deletes the domain and its aliases, then emails the owner", async () => {
    const user = await createUser(db);
    const cd = await createCustomDomain(user.id);
    const a1 = await createAlias(db, user.id, user.default_mailbox_id ?? 0, {
      email: `a1@${cd.domain}`,
      custom_domain_id: cd.id,
    });
    const a2 = await createAlias(db, user.id, user.default_mailbox_id ?? 0, {
      email: `a2@${cd.domain}`,
      custom_domain_id: cd.id,
    });

    const jobId = await enqueue("delete-domain", { custom_domain_id: cd.id });
    expect(await runPendingJobs(tenv)).toBe(1);
    expect(await jobState(jobId)).toBe(JOB_STATE_DONE);

    expect(
      await count(
        "SELECT COUNT(*) AS n FROM custom_domain WHERE id = ?1",
        cd.id,
      ),
    ).toBe(0);
    expect(await getAlias(a1.id)).toBeNull();
    expect(await getAlias(a2.id)).toBeNull();
    // the aliases went into the DOMAIN trash, not the global one...
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM deleted_alias WHERE email IN (?1, ?2)",
        a1.email,
        a2.email,
      ),
    ).toBe(0);
    // ...and the domain-trash rows themselves cascade away with the domain
    // row (domain_deleted_alias.domain_id ondelete=cascade, Flask parity)
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM domain_deleted_alias WHERE domain_id = ?1",
        cd.id,
      ),
    ).toBe(0);

    expect(
      await count(
        "SELECT COUNT(*) AS n FROM user_audit_log WHERE user_id = ?1 AND action = 'delete_custom_domain' AND message = ?2",
        user.id,
        `Delete custom domain ${cd.id} (${cd.domain})`,
      ),
    ).toBe(1);

    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].to).toBe(user.email);
    expect(sentEmails[0].subject).toBe(
      `Your domain ${cd.domain} has been deleted`,
    );
    expect(sentEmails[0].text).toBe(
      `Domain ${cd.domain} along with its aliases are deleted successfully.\n\n        Regards,\n        SimpleLogin team.\n        `,
    );
  });

  it("SL subdomain: records the name in deleted_subdomain and logs the subdomain message", async () => {
    const user = await createUser(db);
    const cd = await createCustomDomain(user.id, { is_sl_subdomain: 1 });

    await enqueue("delete-domain", { custom_domain_id: cd.id });
    await runPendingJobs(tenv);

    expect(
      await count(
        "SELECT COUNT(*) AS n FROM deleted_subdomain WHERE domain = ?1",
        cd.domain,
      ),
    ).toBe(1);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM user_audit_log WHERE user_id = ?1 AND action = 'delete_custom_domain' AND message = ?2",
        user.id,
        `Delete subdomain ${cd.id} (${cd.domain})`,
      ),
    ).toBe(1);
  });

  it("disabled owner: domain deleted but no email", async () => {
    const user = await createUser(db, { disabled: 1 });
    const cd = await createCustomDomain(user.id);
    await enqueue("delete-domain", { custom_domain_id: cd.id });
    await runPendingJobs(tenv);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM custom_domain WHERE id = ?1",
        cd.id,
      ),
    ).toBe(0);
    expect(sentEmails).toHaveLength(0);
  });

  it("missing custom_domain_id or vanished domain: job completes silently", async () => {
    const j1 = await enqueue("delete-domain", {});
    const j2 = await enqueue("delete-domain", { custom_domain_id: 999999 });
    expect(await runPendingJobs(tenv)).toBe(2);
    expect(await jobState(j1)).toBe(JOB_STATE_DONE);
    expect(await jobState(j2)).toBe(JOB_STATE_DONE);
    expect(sentEmails).toHaveLength(0);
  });
});

// ===========================================================================
// delete-account
// ===========================================================================

describe("delete-account job", () => {
  it("sends the goodbye email, deletes the user, and cascades the account data", async () => {
    const user = await createUser(db, { alias_delete_action: 1 });
    const apiKey = await createApiKey(db, user.id);
    const a1 = await createAlias(db, user.id, user.default_mailbox_id ?? 0);
    const contact = await createContact(db, user.id, a1.id);

    const jobId = await enqueue("delete-account", { user_id: user.id });
    expect(await runPendingJobs(tenv)).toBe(1);
    expect(await jobState(jobId)).toBe(JOB_STATE_DONE);

    expect(
      await count("SELECT COUNT(*) AS n FROM users WHERE id = ?1", user.id),
    ).toBe(0);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM mailbox WHERE user_id = ?1",
        user.id,
      ),
    ).toBe(0);
    expect(await getAlias(a1.id)).toBeNull();
    expect(
      await count("SELECT COUNT(*) AS n FROM api_key WHERE id = ?1", apiKey.id),
    ).toBe(0);
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM contact WHERE id = ?1",
        contact.id,
      ),
    ).toBe(0);
    // DeleteImmediately: the alias email is blocked in the global trash,
    // which has no user FK and survives the account deletion
    const trash = await db
      .prepare("SELECT * FROM deleted_alias WHERE email = ?1")
      .bind(a1.email)
      .first<DeletedAliasRow>();
    expect(trash?.reason).toBe(1); // AliasDeleteReason.UserHasBeenDeleted

    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].to).toBe(user.email);
    expect(sentEmails[0].subject).toBe(
      "Your SimpleLogin account has been deleted",
    );
    expect(sentEmails[0].text).toBe(
      "Your SimpleLogin account has been deleted successfully.\n\nThank you for having used SimpleLogin.\n",
    );
  });

  it("MoveToTrash user: soft-trashed aliases just cascade away, leaving no deleted_alias row", async () => {
    const user = await createUser(db); // alias_delete_action defaults to MoveToTrash
    const a1 = await createAlias(db, user.id, user.default_mailbox_id ?? 0);

    await enqueue("delete-account", { user_id: user.id });
    await runPendingJobs(tenv);

    expect(
      await count("SELECT COUNT(*) AS n FROM users WHERE id = ?1", user.id),
    ).toBe(0);
    expect(await getAlias(a1.id)).toBeNull();
    expect(
      await count(
        "SELECT COUNT(*) AS n FROM deleted_alias WHERE email = ?1",
        a1.email,
      ),
    ).toBe(0);
  });

  it("hands the user's Cloudflare OAuth grant back before the cascade drops it", async () => {
    // The cf_oauth_token row is ON DELETE CASCADE, so this is the last
    // moment anyone can revoke: after the users-row delete the refresh token
    // is live in the ex-user's Cloudflare account and its ciphertext is gone.
    const revoked: Array<Record<string, string>> = [];
    setCfOauthFetch(async (input, init) => {
      if (input !== CF_OAUTH_REVOKE_URL) throw new Error(`unexpected ${input}`);
      revoked.push(
        Object.fromEntries(
          new URLSearchParams(typeof init?.body === "string" ? init.body : ""),
        ),
      );
      return new Response("", { status: 200 });
    });
    try {
      const user = await createUser(db);
      await saveGrant(tenv, user.id, {
        accessToken: "at-live",
        refreshToken: "rt-live",
      });

      await enqueue("delete-account", { user_id: user.id });
      await runPendingJobs(tenv);

      expect(revoked).toEqual([
        { token: "rt-live", token_type_hint: "refresh_token" },
        { token: "at-live", token_type_hint: "access_token" },
      ]);
      expect(
        await count(
          "SELECT COUNT(*) AS n FROM cf_oauth_token WHERE user_id = ?1",
          user.id,
        ),
      ).toBe(0);
    } finally {
      setCfOauthFetch(null); // singleWorker: never leave the seam installed
    }
  });

  it("a failing revoke endpoint does not block the deletion", async () => {
    setCfOauthFetch(async () => {
      throw new Error("network down");
    });
    try {
      const user = await createUser(db);
      await saveGrant(tenv, user.id, { accessToken: "at-live" });
      const jobId = await enqueue("delete-account", { user_id: user.id });
      expect(await runPendingJobs(tenv)).toBe(1);
      expect(await jobState(jobId)).toBe(JOB_STATE_DONE);
      expect(
        await count("SELECT COUNT(*) AS n FROM users WHERE id = ?1", user.id),
      ).toBe(0);
    } finally {
      setCfOauthFetch(null);
    }
  });

  it("vanished user: job completes silently, no email", async () => {
    const jobId = await enqueue("delete-account", { user_id: 999999 });
    expect(await runPendingJobs(tenv)).toBe(1);
    expect(await jobState(jobId)).toBe(JOB_STATE_DONE);
    expect(sentEmails).toHaveLength(0);
  });

  it("goodbye email is sent even to a disabled account (no can_send_or_receive gate)", async () => {
    const user = await createUser(db, { disabled: 1 });
    await enqueue("delete-account", { user_id: user.id });
    await runPendingJobs(tenv);
    expect(
      await count("SELECT COUNT(*) AS n FROM users WHERE id = ?1", user.id),
    ).toBe(0);
    expect(sentEmails).toHaveLength(1);
    expect(sentEmails[0].to).toBe(user.email);
  });
});
