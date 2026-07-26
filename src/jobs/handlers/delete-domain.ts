/**
 * JOB_DELETE_DOMAIN handler — port of tasks/delete_custom_domain_job.py
 * (DeleteCustomDomainJob.create_from_job + run) and CustomDomain.delete
 * (app/models.py L2702-2715). Shared alias_delete.py helpers are imported
 * from ./delete-mailbox (see that file's header).
 *
 * Deliberate deviations:
 * - DeletedSubdomain.create is INSERT OR IGNORE: Flask runs the whole job in
 *   one transaction (a failed run rolls the row back before the retry); D1
 *   statements auto-commit, so OR IGNORE keeps the 30-min retries idempotent
 *   instead of failing forever on the UNIQUE(domain) constraint.
 * - Like Flask/Postgres (ondelete=cascade on domain_deleted_alias.domain_id),
 *   deleting the custom_domain row also cascades away the domain-trash rows
 *   created just before: the domain trash does not survive full domain
 *   deletion. Same for domain_mailbox / auto_create_rule rows.
 */

import type { Env } from "../../lib/env";
import { sendTransactionalEmail } from "../../lib/mailer";
import type { AliasRow, CustomDomainRow, UserRow } from "../../lib/rows";
import type { JobRow } from "../index";
import {
  emitUserAuditLog,
  performAliasDeletion,
  REASON_CUSTOM_DOMAIN_DELETED,
  userCanSendOrReceive,
} from "./delete-mailbox";

export async function handleDeleteDomain(
  env: Env,
  payload: Record<string, unknown>,
  job: JobRow,
): Promise<void> {
  const db = env.DB;
  const customDomainId = payload.custom_domain_id as number | undefined;
  if (!customDomainId) {
    // create_from_job: LOG.error + None — the job still completes
    console.error(
      `Job ${job.id} did not have custom_domain_id property. Payload: ${job.payload}`,
    );
    return;
  }
  const cd = await db
    .prepare("SELECT * FROM custom_domain WHERE id = ?1")
    .bind(customDomainId)
    .first<CustomDomainRow>();
  if (!cd) {
    console.error(`Could not find CustomDomain: ${customDomainId}`);
    return;
  }

  const user = await db
    .prepare("SELECT * FROM users WHERE id = ?1")
    .bind(cd.user_id)
    .first<UserRow>();
  if (!user) return; // FK guarantees the owner exists; defensive only

  // ----- CustomDomain.delete (models.py L2702-2715) -----
  if (cd.is_sl_subdomain) {
    // DeletedSubdomain.create(domain=obj.domain)
    await db
      .prepare("INSERT OR IGNORE INTO deleted_subdomain (domain) VALUES (?1)")
      .bind(cd.domain)
      .run();
  }
  // perform_alias_deletion(alias, alias.user, CustomDomainDeleted) — the
  // alias owner (== the domain owner in every creation flow) goes into
  // domain_deleted_alias.user_id.
  const aliases = await db
    .prepare("SELECT * FROM alias WHERE custom_domain_id = ?1 ORDER BY id")
    .bind(cd.id)
    .all<AliasRow>();
  for (const alias of aliases.results) {
    const aliasUser =
      alias.user_id === user.id
        ? user
        : await db
            .prepare("SELECT * FROM users WHERE id = ?1")
            .bind(alias.user_id)
            .first<UserRow>();
    if (!aliasUser) continue;
    await performAliasDeletion(
      db,
      alias,
      aliasUser,
      REASON_CUSTOM_DOMAIN_DELETED,
    );
  }
  await db.prepare("DELETE FROM custom_domain WHERE id = ?1").bind(cd.id).run();

  // UserAuditLogAction.DeleteCustomDomain
  await emitUserAuditLog(
    db,
    user,
    "delete_custom_domain",
    cd.is_sl_subdomain
      ? `Delete subdomain ${cd.id} (${cd.domain})`
      : `Delete custom domain ${cd.id} (${cd.domain})`,
  );
  console.log(`Domain ${cd.domain} deleted`);

  if (cd.partner_id === null && userCanSendOrReceive(user)) {
    await sendTransactionalEmail(env, {
      to: user.email,
      subject: `Your domain ${cd.domain} has been deleted`,
      // exact f-string from tasks/delete_custom_domain_job.py L56-60
      text: `Domain ${cd.domain} along with its aliases are deleted successfully.\n\n        Regards,\n        SimpleLogin team.\n        `,
    });
  }
}
