/**
 * Shared alias helpers hoisted from route/web modules (HANDOVER §4 refactor
 * note) so the batch-import job handler can reuse them.
 */

/** check_alias_prefix (app/alias_utils.py): 1-40 chars of [0-9a-z-_.]. */
export function checkAliasPrefix(prefix: string): boolean {
  if (prefix.length > 40) return false;
  return /^[0-9a-z\-_.]+$/.test(prefix);
}
