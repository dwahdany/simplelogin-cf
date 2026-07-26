/**
 * JOB_BATCH_IMPORT handler — port of app/import_utils.py
 * (handle_batch_import L23-39 + import_from_csv L42-117), dispatched by the
 * batch-import branch of job_runner.process_job (job_runner.py L250-253).
 *
 * Flask parity notes:
 * - batch_import.processed is set to 1 BEFORE parsing, exactly like
 *   import_utils.py L26-27 (this is also what clears the row from the
 *   dashboard /batch_import "Pending" list, which shows processed=0 only).
 * - The CSV "enabled" column is ignored — Flask never reads it.
 * - Prefix validation (L53-58) checks only the part BEFORE THE FIRST "@"
 *   (str.find); a row without "@" validates all-but-the-last char and then
 *   fails validate_email, and the domain lookup uses everything after the
 *   first "@" — the indexOf/slice arithmetic below reproduces Python's
 *   find/slicing including the split_pos == -1 case.
 * - Alias.create side effects (models.py L1791): custom-domain partner flag,
 *   FLAG_CREATED_ALIAS_FROM_PARTNER on the user, and
 *   emit_alias_audit_log(CreateAlias, "New alias created") are replicated;
 *   DailyMetric / EventDispatcher / newrelic have no table in this port and
 *   are skipped (same stance as routes/alias-creation.ts).
 * - Bad payload / missing batch_import / undecodable file throw, so the job
 *   goes through the normal retry-then-error path (Flask: AttributeError /
 *   UnicodeDecodeError fail the job the same way).
 *
 * Deliberate deviations:
 * - Storage: the CSV is read from KV key "file:<file.path>" (the upload
 *   route web/mailbox-domain-pages.ts stores it there — HANDOVER S3 stance)
 *   instead of a presigned S3 URL download.
 * - Every skipped row logs its reason via console.log/console.warn (Flask
 *   only LOG.d/LOG.w's), including the can_create_new_alias() gate that
 *   Flask skips silently (L100, no else branch).
 * - Alias.create's bucket rate limits (ALIAS_CREATE_RATE_LIMIT_FREE =
 *   10/15min) are NOT applied: they would crash any import with more than
 *   10 new aliases mid-run and park the job in error state after 5
 *   attempts. The per-row can_create_new_alias() plan gate still applies.
 * - A row shorter than the header gets None-filled by csv.DictReader; a
 *   missing "alias" VALUE then crashes Flask (sanitize_email(None) →
 *   AttributeError → whole job fails). Here it skips just that row. A
 *   missing alias/note COLUMN skips the row exactly like Flask's KeyError.
 */

import { checkAliasPrefix } from "../../lib/alias";
import { canonicalizeEmail, sanitizeEmail } from "../../lib/crypto";
import { nowStr } from "../../lib/dates";
import type { Env } from "../../lib/env";
import {
  canCreateNewAlias,
  FLAG_CREATED_ALIAS_FROM_PARTNER,
  getUserById,
} from "../../lib/models";
import type {
  AliasRow,
  BaseRow,
  CustomDomainRow,
  FileRow,
  MailboxRow,
  UserRow,
} from "../../lib/rows";
import type { JobRow } from "../index";

const ALIAS_FLAG_PARTNER_CREATED = 1; // Alias.FLAG_PARTNER_CREATED = 1 << 0

interface BatchImportRow extends BaseRow {
  user_id: number;
  file_id: number;
  processed: number;
  summary: string | null;
}

// ---------------------------------------------------------------------------
// email validation (email_validator approximation, duplicated from
// web/alias-pages.ts). import_utils.py L61 passes allow_smtputf8=False, so the
// ASCII-only check is the right flavor here; a non-ASCII domain that
// email_validator would IDNA-accept could never match a custom_domain row
// anyway (L66 compares the raw string), so net behavior is identical.
// ---------------------------------------------------------------------------

const LOCAL_PART_RE =
  /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+(?:\.[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+)*$/;
const DOMAIN_LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

function isValidEmail(email: string): boolean {
  if (!email || email.length > 254) return false;
  for (const ch of email) if (ch.charCodeAt(0) > 127) return false;
  const at = email.indexOf("@");
  if (at <= 0 || at !== email.lastIndexOf("@")) return false;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (local.length > 64 || !LOCAL_PART_RE.test(local)) return false;
  if (domain.length > 253) return false;
  const labels = domain.split(".");
  if (labels.length < 2) return false;
  for (const label of labels) if (!DOMAIN_LABEL_RE.test(label)) return false;
  if (!/[A-Za-z]/.test(labels[labels.length - 1])) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Python csv.reader (default dialect) over the pre-stripped lines, as
// csv.DictReader consumes them in import_from_csv (import_utils.py L43).
// Semantics verified against CPython 3.12:
// - RFC-4180 quoting: `"a,b"` keeps the comma, doubled `""` -> literal `"`;
// - non-strict mode: a quote inside an unquoted field is literal, and text
//   after a closing quote is appended (`"a"b` -> `ab`);
// - a quoted field left open at end-of-line continues on the next line;
//   because handle_batch_import strips the line terminators (L35-37) the
//   pieces concatenate with NO separator (['a,"b', 'c"'] -> [['a','bc']]);
// - an empty line yields an empty record [] (DictReader skips those, but the
//   header row is taken as-is, [] included — import_utils inherits that).
// ---------------------------------------------------------------------------

export function parseCsvRecords(lines: string[]): string[][] {
  const records: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  let sawAny = false; // false only for a fully blank record -> []

  for (const line of lines) {
    let i = 0;
    while (i < line.length) {
      const ch = line[i];
      if (inQuotes) {
        if (ch === '"') {
          if (line[i + 1] === '"') {
            field += '"';
            i += 2;
            continue;
          }
          inQuotes = false;
          i += 1;
          continue;
        }
        field += ch;
        i += 1;
        continue;
      }
      sawAny = true;
      if (ch === ",") {
        row.push(field);
        field = "";
      } else if (ch === '"' && field === "") {
        inQuotes = true; // quotes only open at field start (non-strict csv)
      } else {
        field += ch;
      }
      i += 1;
    }
    if (inQuotes) continue; // record continues on the next line
    if (sawAny) {
      row.push(field);
      records.push(row);
    } else {
      records.push([]);
    }
    row = [];
    field = "";
    sawAny = false;
  }
  if (inQuotes || sawAny) {
    // unterminated quote / dangling record at EOF: csv.reader flushes it
    row.push(field);
    records.push(row);
  }
  return records;
}

/** csv.DictReader row mapping: zip with the header (later duplicate column
 * wins, like dict(zip(...))), restval=None fill for short rows, extras
 * dropped (Flask never reads the None restkey). */
function dictRow(
  fieldnames: string[],
  record: string[],
): Map<string, string | null> {
  const row = new Map<string, string | null>();
  for (let i = 0; i < fieldnames.length; i++) {
    row.set(fieldnames[i], i < record.length ? record[i] : null);
  }
  return row;
}

// ---------------------------------------------------------------------------
// handler
// ---------------------------------------------------------------------------

export async function handleBatchImport(
  env: Env,
  payload: Record<string, unknown>,
  _job: JobRow,
): Promise<void> {
  const db = env.DB;
  const batchImportId = payload.batch_import_id;
  const batchImport = await db
    .prepare("SELECT * FROM batch_import WHERE id = ?1")
    .bind(batchImportId ?? null)
    .first<BatchImportRow>();
  // Flask: BatchImport.get(None/stale id) -> handle_batch_import(None) raises
  if (!batchImport) throw new Error(`batch_import ${batchImportId} not found`);
  const user = await getUserById(db, batchImport.user_id);
  if (!user) throw new Error(`user ${batchImport.user_id} not found`);

  // import_utils.py L26-27: mark processed BEFORE downloading/parsing
  await db
    .prepare(
      "UPDATE batch_import SET processed = 1, updated_at = ?1 WHERE id = ?2",
    )
    .bind(nowStr(), batchImport.id)
    .run();

  console.log(`Start batch import ${batchImport.id} for user ${user.id}`);
  const file = await db
    .prepare("SELECT * FROM file WHERE id = ?1")
    .bind(batchImport.file_id)
    .first<FileRow>();
  if (!file) throw new Error(`file ${batchImport.file_id} not found`);
  const body = await env.KV.get(`file:${file.path}`, "arrayBuffer");
  if (body === null) throw new Error(`file:${file.path} not found in KV`);

  // line.decode("utf-8") is strict — fatal:true keeps the job-failure parity;
  // ignoreBOM:true keeps a leading BOM as U+FEFF like Python, removed below.
  const text = new TextDecoder("utf-8", {
    fatal: true,
    ignoreBOM: true,
  }).decode(body);
  // r.iter_lines() + per-line U+FEFF removal + strip() (L35-37)
  const lines = text
    .split(/\r\n|\r|\n/)
    .map((line) => line.replaceAll("\ufeff", "").trim());

  await importFromCsv(db, env, batchImport, user, lines);
}

/** import_from_csv (import_utils.py L42-117). */
async function importFromCsv(
  db: D1Database,
  env: Env,
  batchImport: BatchImportRow,
  user: UserRow,
  lines: string[],
): Promise<void> {
  const records = parseCsvRecords(lines);
  if (records.length === 0) return;
  const fieldnames = records[0]; // DictReader header, taken verbatim
  let userFlags = user.flags;

  for (const record of records.slice(1)) {
    if (record.length === 0) continue; // DictReader skips blank rows
    const row = dictRow(fieldnames, record);

    // L46-51: KeyError when the header lacks "alias"/"note"
    if (!row.has("alias") || !row.has("note")) {
      console.warn("Cannot parse row", Object.fromEntries(row));
      continue;
    }
    const rawAlias = row.get("alias");
    if (rawAlias == null) {
      // deviation: Flask's sanitize_email(None) raises and fails the job
      console.warn("Cannot parse row (empty alias)", Object.fromEntries(row));
      continue;
    }
    const fullAlias = sanitizeEmail(rawAlias);
    const note = row.get("note") ?? null;

    // L53-58: validate only the prefix BEFORE THE FIRST "@" (str.find);
    // slice() reproduces Python slicing for splitPos == -1 too.
    const splitPos = fullAlias.indexOf("@");
    const aliasDomain = fullAlias.slice(splitPos + 1);
    const aliasPrefix = fullAlias.slice(0, splitPos);
    if (!checkAliasPrefix(aliasPrefix)) {
      console.warn(`Invalid alias prefix ${aliasPrefix}`);
      continue;
    }

    // L60-64: validate_email(check_deliverability=False, allow_smtputf8=False)
    if (!isValidEmail(fullAlias)) {
      console.warn(`Invalid email ${fullAlias}`);
      continue;
    }

    // L66-74: domain must exist, be ownership-verified AND owned by the user
    const customDomain = await db
      .prepare("SELECT * FROM custom_domain WHERE domain = ?1 LIMIT 1")
      .bind(aliasDomain)
      .first<CustomDomainRow>();
    if (!customDomain?.ownership_verified || customDomain.user_id !== user.id) {
      console.log(`domain ${aliasDomain} can't be used by user ${user.id}`);
      continue;
    }

    // L76-82: dedupe vs alias / deleted_alias / domain_deleted_alias
    const dupe = await db
      .prepare(
        `SELECT 1 AS x FROM alias WHERE email = ?1
         UNION SELECT 1 FROM deleted_alias WHERE email = ?1
         UNION SELECT 1 FROM domain_deleted_alias WHERE email = ?1 LIMIT 1`,
      )
      .bind(fullAlias)
      .first();
    if (dupe) {
      console.log(`alias already used ${fullAlias}`);
      continue;
    }

    // L84-98: resolve space-separated mailboxes; fall back to default mailbox
    const mailboxIds: (number | null)[] = [];
    const mailboxesRaw = row.get("mailboxes");
    if (mailboxesRaw) {
      // Python str.split(): any-whitespace runs, empties dropped
      for (const mailboxEmail of mailboxesRaw.split(/\s+/).filter(Boolean)) {
        const canonical = canonicalizeEmail(mailboxEmail);
        const mailbox = await db
          .prepare("SELECT * FROM mailbox WHERE email = ?1 LIMIT 1")
          .bind(canonical)
          .first<MailboxRow>();
        if (!mailbox?.verified || mailbox.user_id !== user.id) {
          console.log(`mailbox ${canonical} can't be used by user ${user.id}`);
          continue;
        }
        mailboxIds.push(mailbox.id);
      }
    }
    if (mailboxIds.length === 0) mailboxIds.push(user.default_mailbox_id);

    // L100: silent skip in Flask; logged here (documented deviation)
    if (!(await canCreateNewAlias(db, env, user))) {
      console.log(`user ${user.id} cannot create new alias, skip ${fullAlias}`);
      continue;
    }

    // L101-109 -> Alias.create (models.py L1791): partner flag + insert
    const flags =
      customDomain.partner_id !== null ? ALIAS_FLAG_PARTNER_CREATED : 0;
    const now = nowStr();
    const alias = await db
      .prepare(
        `INSERT INTO alias (user_id, email, note, mailbox_id, custom_domain_id,
                            batch_import_id, flags, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) RETURNING *`,
      )
      .bind(
        user.id,
        fullAlias,
        note,
        mailboxIds[0],
        customDomain.id,
        batchImport.id,
        flags,
        now,
      )
      .first<AliasRow>();
    if (!alias) throw new Error("alias insert returned no row");

    // models.py L1837-1841: first partner-created alias flags the user
    if (
      (flags & ALIAS_FLAG_PARTNER_CREATED) !== 0 &&
      (userFlags & FLAG_CREATED_ALIAS_FROM_PARTNER) === 0
    ) {
      await db
        .prepare(
          "UPDATE users SET flags = flags | ?1, updated_at = ?2 WHERE id = ?3",
        )
        .bind(FLAG_CREATED_ALIAS_FROM_PARTNER, now, user.id)
        .run();
      userFlags |= FLAG_CREATED_ALIAS_FROM_PARTNER;
    }

    // models.py L1862: emit_alias_audit_log(CreateAlias, "New alias created")
    await db
      .prepare(
        `INSERT INTO alias_audit_log (user_id, alias_id, alias_email, action, message)
         VALUES (?1, ?2, ?3, ?4, ?5)`,
      )
      .bind(user.id, alias.id, fullAlias, "create", "New alias created")
      .run();
    console.log(`Create ${fullAlias}`);

    // L112-117: extra mailboxes (index 1+) become alias_mailbox rows
    for (let i = 1; i < mailboxIds.length; i++) {
      await db
        .prepare(
          "INSERT INTO alias_mailbox (alias_id, mailbox_id) VALUES (?1, ?2)",
        )
        .bind(alias.id, mailboxIds[i])
        .run();
      console.log(`Add ${fullAlias} to mailbox ${mailboxIds[i]}`);
    }
  }
}
