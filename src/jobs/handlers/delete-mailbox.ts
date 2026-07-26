/**
 * JOB_DELETE_MAILBOX handler — port of job_runner.delete_mailbox_job
 * (job_runner.py L154-212) + Mailbox.delete (app/models.py L3042-3070).
 *
 * This file also hosts the app/alias_delete.py helper ports shared by the
 * three deletion job handlers (delete-domain.ts / delete-account.ts import
 * them from here). They duplicate module-private helpers in
 * src/routes/aliases.ts / src/web/alias-pages.ts; extracting them into
 * src/lib is tracked in HANDOVER §4.
 *
 * Deliberate deviations (documented Flask-quirk translations):
 * - Alias._mailboxes has no ORDER BY in SQLAlchemy; wherever Flask takes
 *   `_mailboxes[0]` or iterates the relationship, the port uses
 *   alias_mailbox.id ASC (insertion order — what Postgres returns in
 *   practice for these small sets).
 * - Alias.mailboxes (models.py L1722-1731) dedups the primary mailbox with
 *   `m.id is not self.mailbox.id`, a CPython small-int identity quirk; the
 *   port uses the intended `!=`.
 * - emit_user_audit_log writes to the user_audit_log table (0003 migration),
 *   like src/web/settings-pages.ts; EventDispatcher events / LOG.* / alias
 *   audit log are not ported (port-wide stance).
 */

import { addDays, nowStr, toStr } from "../../lib/dates";
import type { Env } from "../../lib/env";
import { sendTransactionalEmail } from "../../lib/mailer";
import type { AliasRow, MailboxRow, UserRow } from "../../lib/rows";
import type { JobRow } from "../index";

// AliasDeleteReason (models.py L280-286)
export const REASON_USER_HAS_BEEN_DELETED = 1;
export const REASON_MAILBOX_DELETED = 4;
export const REASON_CUSTOM_DOMAIN_DELETED = 5;

// UserAliasDeleteAction.DeleteImmediately (models.py L289-291)
const DELETE_IMMEDIATELY = 1;
// config.ALIAS_TRASH_DAYS default (specs/08 §2)
const ALIAS_TRASH_DAYS = 30;

/** User.can_send_or_receive() (models.py L990-999). */
export function userCanSendOrReceive(user: UserRow): boolean {
  return !user.disabled && user.delete_on === null;
}

/** emit_user_audit_log (app/user_audit_log_utils.py). */
export async function emitUserAuditLog(
  db: D1Database,
  user: UserRow,
  action: string,
  message: string,
): Promise<void> {
  await db
    .prepare(
      "INSERT INTO user_audit_log (user_id, user_email, action, message) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(user.id, user.email, action, message)
    .run();
}

// ---------------------------------------------------------------------------
// app/alias_delete.py ports (shared by the three deletion handlers)
// ---------------------------------------------------------------------------

/** __delete_if_custom_domain: custom-domain aliases always hard-delete into
 * domain_deleted_alias (they are never soft-trashed). */
async function deleteIfCustomDomain(
  db: D1Database,
  alias: AliasRow,
  user: UserRow,
  reason: number,
): Promise<boolean> {
  if (!alias.custom_domain_id) return false;
  const existing = await db
    .prepare(
      "SELECT 1 FROM domain_deleted_alias WHERE email = ?1 AND domain_id = ?2 LIMIT 1",
    )
    .bind(alias.email, alias.custom_domain_id)
    .first();
  if (!existing) {
    await db
      .prepare(
        `INSERT INTO domain_deleted_alias (user_id, email, domain_id, reason, alias_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
      )
      .bind(
        user.id,
        alias.email,
        alias.custom_domain_id,
        reason,
        alias.id,
        nowStr(),
      )
      .run();
  }
  await db.prepare("DELETE FROM alias WHERE id = ?1").bind(alias.id).run();
  return true;
}

/** alias_delete.perform_alias_deletion: hard delete into the global trash. */
export async function performAliasDeletion(
  db: D1Database,
  alias: AliasRow,
  user: UserRow,
  reason: number,
): Promise<void> {
  if (await deleteIfCustomDomain(db, alias, user, reason)) return;
  const existing = await db
    .prepare("SELECT 1 FROM deleted_alias WHERE email = ?1 LIMIT 1")
    .bind(alias.email)
    .first();
  if (!existing) {
    await db
      .prepare(
        "INSERT INTO deleted_alias (email, reason, alias_id, created_at) VALUES (?1, ?2, ?3, ?4)",
      )
      // Python `alias.delete_reason or reason` — 0 (Unspecified) also falls back
      .bind(alias.email, alias.delete_reason || reason, alias.id, nowStr())
      .run();
  }
  await db.prepare("DELETE FROM alias WHERE id = ?1").bind(alias.id).run();
}

/** alias_delete.move_alias_to_trash: soft-trash (delete_on) — except
 * custom-domain aliases, which always hard-delete into the domain trash. */
async function moveAliasToTrash(
  db: D1Database,
  alias: AliasRow,
  user: UserRow,
  reason: number,
): Promise<void> {
  if (await deleteIfCustomDomain(db, alias, user, reason)) return;
  await db
    .prepare(
      "UPDATE alias SET delete_on = ?1, delete_reason = ?2, enabled = 0, updated_at = ?3 WHERE id = ?4",
    )
    .bind(
      toStr(addDays(new Date(), ALIAS_TRASH_DAYS)),
      reason,
      nowStr(),
      alias.id,
    )
    .run();
}

/** alias_delete.delete_alias: trash vs hard-delete decision. */
export async function deleteAliasForUser(
  db: D1Database,
  alias: AliasRow,
  user: UserRow,
  reason: number,
): Promise<void> {
  if (
    alias.delete_on !== null ||
    user.alias_delete_action === DELETE_IMMEDIATELY
  ) {
    await performAliasDeletion(db, alias, user, reason);
  } else {
    await moveAliasToTrash(db, alias, user, reason);
  }
}

// ---------------------------------------------------------------------------
// Mailbox.delete (models.py L3042-3070)
// ---------------------------------------------------------------------------

async function deleteMailboxRow(
  db: D1Database,
  mailbox: MailboxRow,
  user: UserRow,
): Promise<void> {
  const primaries = await db
    .prepare("SELECT * FROM alias WHERE mailbox_id = ?1 ORDER BY id")
    .bind(mailbox.id)
    .all<AliasRow>();
  for (const alias of primaries.results) {
    // len(alias.mailboxes) > 1 — the property counts only VERIFIED mailboxes
    // (primary + join rows, primary deduped), models.py L1722-1728.
    const joins = await db
      .prepare(
        `SELECT COUNT(DISTINCT m.id) AS n
           FROM alias_mailbox am JOIN mailbox m ON m.id = am.mailbox_id
          WHERE am.alias_id = ?1 AND m.id != ?2 AND m.verified = 1`,
      )
      .bind(alias.id, alias.mailbox_id)
      .first<{ n: number }>();
    const nVerified = (mailbox.verified ? 1 : 0) + (joins?.n ?? 0);
    if (nVerified > 1) {
      // "use the first mailbox found in alias._mailboxes" — NOT filtered by
      // verified (Flask picks _mailboxes[0] as-is).
      const first = await db
        .prepare(
          "SELECT id, mailbox_id FROM alias_mailbox WHERE alias_id = ?1 ORDER BY id LIMIT 1",
        )
        .bind(alias.id)
        .first<{ id: number; mailbox_id: number }>();
      if (first) {
        await db
          .prepare(
            "UPDATE alias SET mailbox_id = ?1, updated_at = ?2 WHERE id = ?3",
          )
          .bind(first.mailbox_id, nowStr(), alias.id)
          .run();
        await db
          .prepare("DELETE FROM alias_mailbox WHERE id = ?1")
          .bind(first.id)
          .run();
      }
    } else if (user.alias_delete_action === DELETE_IMMEDIATELY) {
      await performAliasDeletion(db, alias, user, REASON_MAILBOX_DELETED);
    } else {
      // assign the default mailbox, then move to trash
      await db
        .prepare(
          "UPDATE alias SET mailbox_id = ?1, updated_at = ?2 WHERE id = ?3",
        )
        .bind(user.default_mailbox_id, nowStr(), alias.id)
        .run();
      await moveAliasToTrash(
        db,
        { ...alias, mailbox_id: user.default_mailbox_id ?? alias.mailbox_id },
        user,
        REASON_MAILBOX_DELETED,
      );
    }
  }
  // Row delete; alias_mailbox rows still pointing at this mailbox (secondary
  // references from transferred/kept aliases) go via ON DELETE CASCADE.
  await db.prepare("DELETE FROM mailbox WHERE id = ?1").bind(mailbox.id).run();
}

// ---------------------------------------------------------------------------
// delete_mailbox_job (job_runner.py L154-212)
// ---------------------------------------------------------------------------

export async function handleDeleteMailbox(
  env: Env,
  payload: Record<string, unknown>,
  _job: JobRow,
): Promise<void> {
  const db = env.DB;
  const mailboxId = payload.mailbox_id as number | undefined;
  const mailbox = mailboxId
    ? await db
        .prepare("SELECT * FROM mailbox WHERE id = ?1")
        .bind(mailboxId)
        .first<MailboxRow>()
    : null;
  if (!mailbox) return; // mailbox already gone: job completes silently

  const transferMailboxId = payload.transfer_mailbox_id as
    | number
    | null
    | undefined;
  let aliasTransferredTo: string | null = null;
  if (transferMailboxId) {
    const transferMailbox = await db
      .prepare("SELECT * FROM mailbox WHERE id = ?1")
      .bind(transferMailboxId)
      .first<MailboxRow>();
    if (transferMailbox) {
      aliasTransferredTo = transferMailbox.email;
      // mailbox.aliases (models.py L3072-3082): aliases with this mailbox as
      // primary plus aliases with an alias_mailbox join row, deduped.
      const aliases = await db
        .prepare(
          `SELECT * FROM alias WHERE mailbox_id = ?1
           UNION
           SELECT a.* FROM alias a JOIN alias_mailbox am ON am.alias_id = a.id
            WHERE am.mailbox_id = ?1
           ORDER BY id`,
        )
        .bind(mailbox.id)
        .all<AliasRow>();
      for (const alias of aliases.results) {
        if (alias.mailbox_id === mailbox.id) {
          await db
            .prepare(
              "UPDATE alias SET mailbox_id = ?1, updated_at = ?2 WHERE id = ?3",
            )
            .bind(transferMailbox.id, nowStr(), alias.id)
            .run();
          // if transfer_mailbox in alias._mailboxes: remove (it just became
          // the primary; drop the now-duplicate join row)
          await db
            .prepare(
              "DELETE FROM alias_mailbox WHERE alias_id = ?1 AND mailbox_id = ?2",
            )
            .bind(alias.id, transferMailbox.id)
            .run();
        } else {
          await db
            .prepare(
              "DELETE FROM alias_mailbox WHERE alias_id = ?1 AND mailbox_id = ?2",
            )
            .bind(alias.id, mailbox.id)
            .run();
          // if transfer_mailbox not in alias._mailboxes: append it (Flask
          // checks only the join rows, not the primary mailbox_id)
          const has = await db
            .prepare(
              "SELECT 1 FROM alias_mailbox WHERE alias_id = ?1 AND mailbox_id = ?2 LIMIT 1",
            )
            .bind(alias.id, transferMailbox.id)
            .first();
          if (!has) {
            await db
              .prepare(
                "INSERT INTO alias_mailbox (alias_id, mailbox_id) VALUES (?1, ?2)",
              )
              .bind(alias.id, transferMailbox.id)
              .run();
          }
        }
      }
    }
  }

  const mailboxEmail = mailbox.email;
  const user = await db
    .prepare("SELECT * FROM users WHERE id = ?1")
    .bind(mailbox.user_id)
    .first<UserRow>();
  if (!user) return; // FK guarantees the owner exists; defensive only

  await emitUserAuditLog(
    db,
    user,
    "delete_mailbox", // UserAuditLogAction.DeleteMailbox
    `Delete mailbox ${mailbox.id} (${mailbox.email})`,
  );
  await deleteMailboxRow(db, mailbox, user);
  console.log(`Mailbox ${mailbox.id} ${mailboxEmail} deleted`);

  // `if not job.payload.get("send_mail", True)` — any present falsy value
  // suppresses the email; an absent key defaults to sending.
  const sendMail = Object.hasOwn(payload, "send_mail")
    ? payload.send_mail
    : true;
  if (!sendMail) return;
  if (!userCanSendOrReceive(user)) return;

  if (aliasTransferredTo) {
    await sendTransactionalEmail(env, {
      to: user.email,
      subject: `Your mailbox ${mailboxEmail} has been deleted`,
      // exact f-string from job_runner.py L197-200, indentation included
      text: `Mailbox ${mailboxEmail} and its alias have been transferred to ${aliasTransferredTo}.\n    Regards,\n    SimpleLogin team.\n    `,
    });
  } else {
    await sendTransactionalEmail(env, {
      to: user.email,
      subject: `Your mailbox ${mailboxEmail} has been deleted`,
      // exact f-string from job_runner.py L207-210
      text: `Mailbox ${mailboxEmail} along with its aliases have been deleted successfully.\n    Regards,\n    SimpleLogin team.\n    `,
    });
  }
}
