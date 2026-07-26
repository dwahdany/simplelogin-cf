/**
 * JOB_SEND_USER_REPORT handler — port of ExportUserDataJob
 * (app/jobs/export_user_data_job.py): collect everything the user owns into
 * user_report.zip (user.json + aliases/mailboxes/contacts/directories/
 * domains/email_logs.json, ZIP_DEFLATED via node:zlib deflateRawSync) and
 * email it as "Your SimpleLogin data" with the transactional/user-report.html
 * body. RefusedEmail is excluded, like in Flask (L119-120).
 *
 * Deliberate deviations (documented per HANDOVER §0/§1):
 * - Envelope sender: Flask sends with a VERP transactional envelope
 *   (L160-168); the send_email binding requires envelope == From header, so
 *   the noreply From address is used for both (same as src/lib/mailer.ts).
 *   The TransactionalEmail row (L159) is still created.
 * - The mailer seam (src/lib/mailer.ts) has no attachment support and lib
 *   files are frozen, so the multipart/mixed message is assembled here,
 *   modeled on mailer.buildMime, and DKIM-signed via dkimSignOutbound.
 * - _model_to_dict value fidelity (L92-104): rows are serialized as stored in
 *   D1 — booleans/enums stay 0/1 integers where Flask emits true/false —
 *   and canonical timestamps are normalized to arrow's isoformat ("T"
 *   separator). JSON is compact (JSON.stringify) instead of json.dumps'
 *   ", "/": " separators. Field names and file layout are exact.
 * - Flask paginates each model 50 rows at a time ordered by id (L53-68); a
 *   single ORDER BY id query per table is equivalent on D1.
 * - sl_sendmail(..., ignore_smtp_error=False) (L168): binding errors
 *   propagate, so a failed send retries through the job runner.
 */

import { deflateRawSync } from "node:zlib";
import { dkimSignOutbound } from "../../lib/dkim";
import type { Env } from "../../lib/env";
import type { UserRow } from "../../lib/rows";
import { renderTemplate } from "../../lib/web/templates";
import type { JobRow } from "../index";

// ExportUserDataJob.REMOVE_FIELDS (L44-48). Alias.ts_vector does not exist in
// the D1 schema (dropped Postgres full-text column) so it needs no filter.
const REMOVE_FIELDS: Record<string, readonly string[]> = {
  users: ["otp_secret", "password"],
  alias: ["transfer_token", "hibp_last_check"],
  custom_domain: ["ownership_txt_token"],
};

/** Canonical D1 timestamp ("YYYY-MM-DD HH:MM:SS[.SSS]+00:00"). */
const CANONICAL_TS =
  /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?\+\d{2}:\d{2}$/;

/** _model_to_dict (L92-104): strip filtered fields, arrow -> isoformat. */
function modelToDict(
  row: Record<string, unknown>,
  table: string,
): Record<string, unknown> {
  const remove = REMOVE_FIELDS[table] ?? [];
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(row)) {
    if (remove.includes(key)) continue;
    out[key] =
      typeof value === "string" && CANONICAL_TS.test(value)
        ? value.replace(" ", "T")
        : value;
  }
  return out;
}

// ---------------------------------------------------------------------------
// minimal ZIP writer (zipfile.ZipFile(..., ZIP_DEFLATED) equivalent)
// ---------------------------------------------------------------------------

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++)
    crc = CRC_TABLE[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

const DOS_EPOCH_DATE = 0x21; // 1980-01-01; Flask stamps wall-clock time — irrelevant

/** Store the entries with local headers + central directory + EOCD. */
export function buildZip(
  files: ReadonlyArray<{ name: string; content: string }>,
): Uint8Array {
  const encoder = new TextEncoder();
  const parts: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  for (const file of files) {
    const name = encoder.encode(file.name);
    const data = encoder.encode(file.content);
    const compressed = deflateRawSync(data);
    const crc = crc32(data);

    const local = new Uint8Array(30 + name.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true); // local file header signature
    lv.setUint16(4, 20, true); // version needed to extract
    lv.setUint16(8, 8, true); // compression method: deflate
    lv.setUint16(12, DOS_EPOCH_DATE, true); // mod date
    lv.setUint32(14, crc, true);
    lv.setUint32(18, compressed.length, true);
    lv.setUint32(22, data.length, true);
    lv.setUint16(26, name.length, true);
    local.set(name, 30);
    parts.push(local, compressed);

    const dir = new Uint8Array(46 + name.length);
    const dv = new DataView(dir.buffer);
    dv.setUint32(0, 0x02014b50, true); // central directory header signature
    dv.setUint16(4, 20, true); // version made by
    dv.setUint16(6, 20, true); // version needed to extract
    dv.setUint16(10, 8, true); // compression method: deflate
    dv.setUint16(14, DOS_EPOCH_DATE, true);
    dv.setUint32(16, crc, true);
    dv.setUint32(20, compressed.length, true);
    dv.setUint32(24, data.length, true);
    dv.setUint16(28, name.length, true);
    dv.setUint32(42, offset, true); // local header offset
    dir.set(name, 46);
    central.push(dir);
    offset += local.length + compressed.length;
  }
  const centralSize = central.reduce((sum, c) => sum + c.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true); // end-of-central-directory signature
  ev.setUint16(8, files.length, true);
  ev.setUint16(10, files.length, true);
  ev.setUint32(12, centralSize, true);
  ev.setUint32(16, offset, true);

  const out = new Uint8Array(offset + centralSize + 22);
  let pos = 0;
  for (const part of [...parts, ...central, eocd]) {
    out.set(part, pos);
    pos += part.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// MIME (multipart/mixed: html body + zip attachment), after mailer.buildMime
// ---------------------------------------------------------------------------

function base64Lines(data: Uint8Array): string {
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < data.length; i += CHUNK)
    binary += String.fromCharCode(...data.subarray(i, i + CHUNK));
  const b64 = btoa(binary);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 76) lines.push(b64.slice(i, i + 76));
  return lines.join("\r\n");
}

function buildReportMime(
  from: string,
  fromHeader: string,
  to: string,
  html: string,
  zip: Uint8Array,
): string {
  const boundary = `b-${crypto.randomUUID()}`;
  return [
    `From: ${fromHeader}`,
    `To: ${to}`,
    "Subject: Your SimpleLogin data", // run() L142
    `Message-ID: <${crypto.randomUUID()}@${from.split("@")[1]}>`,
    `Date: ${new Date().toUTCString()}`,
    "MIME-Version: 1.0",
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    'Content-Type: text/html; charset="utf-8"',
    "Content-Transfer-Encoding: 8bit",
    "",
    html,
    `--${boundary}`,
    "Content-Type: application/zip",
    'Content-Disposition: attachment; filename="user_report.zip"',
    "Content-Transfer-Encoding: base64",
    "",
    base64Lines(zip),
    `--${boundary}--`,
    "",
  ].join("\r\n");
}

// ---------------------------------------------------------------------------
// test capture seam (mirrors outboundEmails in src/email.ts: only populated
// when the vitest-provided TEST_MIGRATIONS binding is present, so production
// never pins a full user export in isolate memory)
// ---------------------------------------------------------------------------

export interface CapturedUserReport {
  to: string;
  subject: string;
  html: string;
  files: { name: string; content: string }[];
  zip: Uint8Array;
}

export const sentUserReports: CapturedUserReport[] = [];
const MAX_CAPTURED = 20;

// ---------------------------------------------------------------------------
// handler
// ---------------------------------------------------------------------------

/** User.can_send_or_receive() (models.py L990-999). */
function canSendOrReceive(user: UserRow): boolean {
  return !user.disabled && user.delete_on === null;
}

export async function handleSendUserReport(
  env: Env,
  payload: Record<string, unknown>,
  _job: JobRow,
): Promise<void> {
  const userId = payload.user_id;
  if (typeof userId !== "number") return; // create_from_job -> None (L171-176)
  const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?1")
    .bind(userId)
    .first<UserRow>();
  if (!user) return;
  if (!canSendOrReceive(user)) return; // run() L134-135

  // _build_zip (L106-131): user.json + the per-model json arrays, ordered by
  // id like _get_paginated_model.
  const files: { name: string; content: string }[] = [
    {
      name: "user.json",
      content: JSON.stringify(
        modelToDict(user as unknown as Record<string, unknown>, "users"),
      ),
    },
  ];
  const models: ReadonlyArray<[string, string]> = [
    ["aliases", "alias"],
    ["mailboxes", "mailbox"],
    ["contacts", "contact"],
    ["directories", "directory"],
    ["domains", "custom_domain"],
    ["email_logs", "email_log"],
  ];
  for (const [fileName, table] of models) {
    const rows = await env.DB.prepare(
      `SELECT * FROM ${table} WHERE user_id = ?1 ORDER BY id`,
    )
      .bind(user.id)
      .all<Record<string, unknown>>();
    files.push({
      name: `${fileName}.json`,
      content: JSON.stringify(rows.results.map((r) => modelToDict(r, table))),
    });
  }
  const zip = buildZip(files);

  const toEmail = user.email;
  const extra = env as Env & Record<string, string | undefined>;
  // email_utils.render context (app/email_utils.py L94-116)
  const html = renderTemplate("emails/transactional/user-report.html", {
    MAX_NB_EMAIL_FREE_PLAN: env.MAX_NB_EMAIL_FREE_PLAN,
    URL: env.URL,
    LANDING_PAGE_URL: extra.LANDING_PAGE_URL ?? "https://simplelogin.io",
    YEAR: new Date().getUTCFullYear(),
    user,
    to_email: toEmail,
  });

  // TransactionalEmail.create(email=to_email, commit=True) (L159)
  await env.DB.prepare("INSERT INTO transactional_email (email) VALUES (?1)")
    .bind(toEmail)
    .run();

  if ((env as { TEST_MIGRATIONS?: unknown }).TEST_MIGRATIONS !== undefined) {
    sentUserReports.push({
      to: toEmail,
      subject: "Your SimpleLogin data",
      html,
      files,
      zip,
    });
    if (sentUserReports.length > MAX_CAPTURED) sentUserReports.shift();
  }

  // From/envelope pair as in sendTransactionalEmail (src/lib/mailer.ts):
  // bare noreply address as the binding envelope, display-name From header.
  const from = `no-reply@${env.EMAIL_DOMAIN}`;
  const fromHeader = `"SimpleLogin (noreply)" <${from}>`;
  const raw = new TextEncoder().encode(
    buildReportMime(from, fromHeader, toEmail, html, zip),
  );
  const signed = await dkimSignOutbound(env, from, raw);

  if (!env.SEND_EMAIL) {
    console.log(`[send-user-report] (unbound) to=${toEmail}`);
    return;
  }
  const { EmailMessage } = await import("cloudflare:email");
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(signed);
      controller.close();
    },
  });
  // errors propagate on purpose — see ignore_smtp_error note in the header
  await env.SEND_EMAIL.send(new EmailMessage(from, toEmail, stream));
}
