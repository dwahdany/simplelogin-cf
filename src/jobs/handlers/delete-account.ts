/**
 * JOB_DELETE_ACCOUNT handler — port of the DELETE_ACCOUNT branch of
 * job_runner.process_job (job_runner.py L254-272) + User.delete
 * (app/models.py L770-787). Shared alias_delete.py helpers are imported from
 * ./delete-mailbox (see that file's header).
 *
 * Flask sends the goodbye email BEFORE deleting the user, with no
 * can_send_or_receive gate (deleting a disabled account still notifies it).
 * The email body is the content block of templates/emails/transactional/
 * account-delete.{txt,html}; like every other transactional send in this
 * port it goes out text-only with the base-template footer omitted.
 *
 * Deletion itself is a manual trash/delete pass over the user's aliases
 * (delete_alias — fills the deleted_alias blocklist so hard-deleted alias
 * emails cannot be re-registered) followed by the users-row delete. Every
 * user_id FK in migrations/0001_init.sql + 0003_web_tables.sql + 0004_cf_
 * oauth.sql is ON DELETE CASCADE (api_key, mailbox, alias, contact,
 * custom_domain → domain_deleted_alias, directory, cf_oauth_token, ...), so
 * no other manual deletes are needed; deleted_alias and the *_audit_log
 * tables have no FK on purpose and survive, matching Flask/Postgres.
 *
 * DEVIATION (no Flask counterpart): a Cloudflare OAuth grant must be handed
 * back BEFORE that cascade runs. The cascade only drops our copy — the
 * refresh token stays live in the (now ex-)user's Cloudflare account, and
 * once the ciphertext is gone nobody here can ever revoke it.
 */

import { getGrant, revokeGrantTokens } from "../../lib/cfoauth";
import type { Env } from "../../lib/env";
import { sendTransactionalEmail } from "../../lib/mailer";
import type { AliasRow, UserRow } from "../../lib/rows";
import type { JobRow } from "../index";
import {
  deleteAliasForUser,
  REASON_USER_HAS_BEEN_DELETED,
} from "./delete-mailbox";

export async function handleDeleteAccount(
  env: Env,
  payload: Record<string, unknown>,
  _job: JobRow,
): Promise<void> {
  const db = env.DB;
  const userId = payload.user_id as number | undefined;
  const user = userId
    ? await db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(userId)
        .first<UserRow>()
    : null;
  if (!user) {
    console.log(`No user found for ${userId}`); // user already gone: job done
    return;
  }

  console.warn(`Delete user ${user.id} ${user.email}`);
  await sendTransactionalEmail(env, {
    to: user.email,
    subject: "Your SimpleLogin account has been deleted",
    // transactional/account-delete.txt content block
    text: "Your SimpleLogin account has been deleted successfully.\n\nThank you for having used SimpleLogin.\n",
  });

  // User.delete: delete_alias(alias, user, UserHasBeenDeleted) per alias...
  const aliases = await db
    .prepare("SELECT * FROM alias WHERE user_id = ?1 ORDER BY id")
    .bind(user.id)
    .all<AliasRow>();
  for (const alias of aliases.results) {
    await deleteAliasForUser(db, alias, user, REASON_USER_HAS_BEEN_DELETED);
  }
  // Hand back the Cloudflare delegated authorization while we still hold the
  // (encrypted) tokens: `DELETE FROM users` cascades cf_oauth_token away, and
  // after that the grant is live at Cloudflare and unrevokable from here.
  // Best effort — revokeGrantTokens never throws and must not block deletion.
  const grant = await getGrant(env, user.id);
  if (grant) await revokeGrantTokens(env, grant);

  // ...then the row delete; the FK cascades cover everything else.
  await db.prepare("DELETE FROM users WHERE id = ?1").bind(user.id).run();
}
