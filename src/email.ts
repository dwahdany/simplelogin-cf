/**
 * Email Routing worker: the forwarding/reply pipeline of spec
 * `specs/07-email-handling.md` (Flask source: email_handler.py).
 *
 * Mapping from the aiosmtpd handler to Cloudflare Email Workers:
 * - 250-class SMTP statuses -> accept the message (no call to setReject);
 * - 4xx/5xx statuses -> `message.setReject(<exact status string>)` (Cloudflare
 *   has no tempfail, so 421 statuses are also permanent rejects here);
 * - forward-phase delivery uses `message.forward(mailbox.email, X-* headers)`
 *   (Cloudflare cannot rewrite From/To/Cc or the body of forwarded mail);
 * - reply-phase delivery rebuilds the MIME header section from the raw
 *   message (header whitelist, From = alias, To/Cc = contact addresses,
 *   SL Message-ID) and sends through the SEND_EMAIL binding with a VERP
 *   envelope sender. Under test (TEST_MIGRATIONS binding present) every
 *   outbound send is also recorded in the exported `outboundEmails` array so
 *   tests can assert on the raw content; in production nothing is captured.
 *
 * Deliberate deviations from Flask (each documented at its site):
 * - the per-minute flood limit (app/email/rate_limit.py) accepts-and-drops
 *   with a blocked EmailLog instead of rejecting E522 — rejects are permanent
 *   on this platform (no tempfail), so rejecting would bounce legit bursts;
 * - rewrite-mode forwards stamp an X-SimpleLogin-Loop-Count header and inbound
 *   mail whose count exceeds MAX_LOOP_COUNT is accepted-and-dropped with a
 *   blocked EmailLog (defense-in-depth; Flask relies on other loop signals);
 * - inbound DSN detection (no direct Flask equivalent — Flask receives its
 *   bounces on signed VERP envelopes): because outbound mail is enveloped
 *   with its From address, downstream bounces come back to the reverse alias
 *   (forward phase) or the alias (reply phase) as ordinary inbound mail.
 *   dispatch() detects them (null/mailer-daemon sender + delivery-status
 *   report) before the null-sender E206 drop, attributes them through the
 *   embedded X-SimpleLogin-EmailLog-ID header (Message-ID lookup as a
 *   fallback) and runs the Flask handle_bounce side effects; unattributable
 *   DSNs fall through to the pre-existing paths (see handleInboundDsn);
 * - notify-other-mailbox copies swap the reply's X-SimpleLogin-EmailLog-ID
 *   for an X-SimpleLogin-Transactional-ID so their bounces are recorded like
 *   Flask's transactional VERP bounces instead of flagging the reply;
 * - transient-send retry (no Flask equivalent — Flask hands transient SMTP
 *   failures to the Postfix queue): a send_email binding failure on a fully
 *   built forward/reply stashes the message in KV ("retry:<uuid>", 7-day TTL)
 *   and enqueues the 'retry-email' job with growing backoff instead of
 *   turning into a permanent SMTP reject at the sender's MTA (see
 *   scheduleEmailRetry / src/jobs/handlers/retry-email.ts).
 */

import { canonicalizeEmail, randomString, sanitizeEmail } from "./lib/crypto";
import { addDays, addMinutes, nowStr, toDate, toStr } from "./lib/dates";
import { dkimSignOutbound } from "./lib/dkim";
import type { Env } from "./lib/env";
import { sendTransactionalEmail } from "./lib/mailer";
import {
  availableSlEmail,
  canCreateNewAlias,
  getAliasById,
  getCustomDomainById,
  getMailboxById,
  getUserById,
  userIsPremium,
} from "./lib/models";
import { encryptMessage, PGPException } from "./lib/pgp";
import type {
  AliasRow,
  ContactRow,
  CustomDomainRow,
  DirectoryRow,
  EmailLogRow,
  MailboxRow,
  PublicDomainRow,
  UserRow,
} from "./lib/rows";
import {
  encodeUnsubscribeUrl,
  UnsubscribeAction,
  unsubscribeSecret,
} from "./lib/unsubscribe";

// ---- SMTP statuses (app/email/status.py, verbatim) ----
const E200 = "250 Message accepted for delivery";
const E204 = "250 SL E204 ignore";
const E205 = "250 SL E205 bounce handled";
const E206 = "250 SL E206 Out of office";
const E207 = "250 SL E207 No bounce report";
const E209 = "250 SL E209 Email Loop";
const E211 = "250 SL E211 Bounce Forward phase handled";
const E212 = "250 SL E212 Bounce Reply phase handled";
const E213 = "250 SL E213 Unknown email ignored";
const E214 = "250 SL E214 Unauthorized for using reverse alias";
const E404 = "421 SL E404 Unexpected error - Retry later";
const E405 = "421 SL E405 Mailbox domain problem - Retry later";
const E407 = "421 SL E407 Retry later";
const E501 = "550 SL E501";
const E502 = "550 SL E502 Email not exist";
const E503 = "550 SL E503";
const E504 = "550 SL E504 Account disabled";
const E510 = "550 SL E510 so such user";
const E512 = "550 SL E512 No such email log";
const E515 = "550 SL E515 Email not exist";
const E516 = "550 SL E516 invalid mailbox";
const E518 = "550 SL E518 Disabled mailbox";
const E520 = "550 SL E520 Unverified custom domain";
const E522 =
  "550 SL E522 The user you are trying to contact is receiving mail " +
  "at a rate that prevents additional messages from being delivered.";
const E524 = "550 SL E524 Wrong use of reverse-alias";
const E525 = "550 SL E525 Alias loop";
const E526 = "550 SL E526 Too many recipients";

// ---- config constants (app/config.py defaults) ----
const BOUNCE_PREFIX = "bounce+";
const BOUNCE_PREFIX_FOR_REPLY_PHASE = "bounce_reply";
const VERP_PREFIX = "sl";
const VERP_TIME_START = 1640995200; // 2022-01-01, minutes granularity
const VERP_MESSAGE_LIFETIME = 5 * 86400;
const MAX_EMAIL_FORWARD_RECIPIENTS = 30;
const CONTACT_MAX_NAME_LENGTH = 512;
const MAILBOX_FLAG_ADMIN_DISABLED = 1;

// Per-minute flood limit (app/config.py): nb max of activity (forward/reply)
// an alias / a mailbox can have during 1 min.
const MAX_ACTIVITY_DURING_MINUTE_PER_ALIAS = 10;
const MAX_ACTIVITY_DURING_MINUTE_PER_MAILBOX = 15;

// Loop hardening (deviation, no Flask equivalent): rewrite-mode outbound
// forwards stamp this header; inbound mail whose value exceeds MAX_LOOP_COUNT
// is accepted-and-dropped with a blocked EmailLog (see handleForwardPhase).
const LOOP_COUNT_HEADER = "X-SimpleLogin-Loop-Count";
const MAX_LOOP_COUNT = 5;

// SL_EMAIL_LOG_ID (app/email/headers.py): stamped on every outbound forward /
// reply. Under the envelope model it is also how an inbound DSN is attributed
// back to its email log (see handleInboundDsn).
const EMAIL_LOG_HEADER = "X-SimpleLogin-EmailLog-ID";
// Deviation (no Flask equivalent): notify-other-mailbox copies carry the
// transactional_email id instead of the reply's email-log id, so a bounced
// notification records a Bounce row on the notified mailbox — the same
// outcome as Flask's transactional VERP envelope — instead of marking the
// successfully delivered reply as bounced.
const TRANSACTIONAL_ID_HEADER = "X-SimpleLogin-Transactional-ID";

const VERP_TYPE_BOUNCE_FORWARD = 0;
const VERP_TYPE_BOUNCE_REPLY = 1;
const VERP_TYPE_TRANSACTIONAL = 2;

// Alert types (config.py). The first group is deduped once-ever
// (send_email_at_most_times); the rate-controlled group is capped per rolling
// window (send_email_with_rate_control, MAX_ALERT_24H per nb_day days).
const ALERT_FROM_ADDRESS_IS_REVERSE_ALIAS = "from_address_is_reverse_alias";
const ALERT_SEND_EMAIL_CYCLE = "cycle";
const ALERT_MAILBOX_IS_ALIAS = "mailbox_is_alias";
const ALERT_TO_NOREPLY = "to_noreply";
const ALERT_REVERSE_ALIAS_UNKNOWN_MAILBOX = "reverse_alias_unknown_mailbox";
const ALERT_DIRECTORY_DISABLED_ALIAS_CREATION =
  "alert_directory_disabled_alias_creation";
const ALERT_BOUNCE_EMAIL = "bounce";
const ALERT_BOUNCE_EMAIL_REPLY_PHASE = "bounce-when-reply";
const MAX_ALERT_24H = 4;

// SenderFormatEnum (app/models.py) — how Contact.new_addr() formats the From.
const SENDER_FORMAT_AT = 0; // "John Wick - john at wick.com"
const SENDER_FORMAT_A = 2; // "John Wick - john(a)wick.com"
const SENDER_FORMAT_NAME_ONLY = 5; // "John Wick"
const SENDER_FORMAT_AT_ONLY = 6; // "john at wick.com"
const SENDER_FORMAT_NO_NAME = 7; // reply_email only

// UnsubscribeBehaviourEnum (app/models.py).
const UNSUB_DISABLE_ALIAS = 0;
const UNSUB_BLOCK_CONTACT = 1;
const UNSUB_PRESERVE_ORIGINAL = 2;

type EmailEnv = Env & { VERP_EMAIL_SECRET?: string };

interface HandleResult {
  accepted: boolean;
  status: string;
}
const accept = (status: string): HandleResult => ({ accepted: true, status });
const rejectWith = (status: string): HandleResult => ({
  accepted: false,
  status,
});

interface Delivery {
  success: boolean;
  status: string;
}

/** Raised when a reverse-alias is used as a contact address (models.py). */
class CannotCreateContactForReverseAlias extends Error {}
/** Raised when a reply To/Cc contains a non reverse-alias address. */
class NonReverseAliasInReplyPhase extends Error {}

export interface OutboundEmail {
  /** Flask-parity VERP envelope sender (used verbatim when unbound). */
  envelopeFrom: string;
  /** Sender actually handed to the send_email binding (= From header). */
  bindingFrom?: string;
  to: string;
  raw: string;
}

/**
 * Every reply-phase / notification outbound send, oldest first. Test seam
 * ONLY: sendRawEmail pushes here only when the env carries the vitest-provided
 * TEST_MIGRATIONS binding — in production retaining up to 200 full raw
 * messages would pin users' mail in isolate memory indefinitely.
 */
export const outboundEmails: OutboundEmail[] = [];
const MAX_OUTBOUND_CAPTURED = 200;

// ============================== entry point ===============================

export async function handleEmail(
  message: ForwardableEmailMessage,
  env: Env,
  ctx: ExecutionContext,
): Promise<void> {
  void ctx;
  try {
    const result = await dispatch(message, env as EmailEnv);
    if (!result.accepted) message.setReject(result.status);
  } catch (e) {
    if (e instanceof CannotCreateContactForReverseAlias) {
      message.setReject(E524);
    } else {
      console.error("email handler unexpected error:", e);
      message.setReject(E404);
    }
  }
}

// ============================ top-level dispatch ==========================

async function dispatch(
  message: ForwardableEmailMessage,
  env: EmailEnv,
): Promise<HandleResult> {
  const db = env.DB;
  const mailFrom = sanitizeEmail(message.from);
  const rcptTo = sanitizeEmail(message.to);

  // IgnoredEmail -> E204
  const ignored = await db
    .prepare(
      "SELECT 1 FROM ignored_email WHERE mail_from = ?1 AND rcpt_to = ?2 LIMIT 1",
    )
    .bind(mailFrom, rcptTo)
    .first();
  if (ignored) return accept(E204);

  // Reverse alias used as the sender: alert the user but keep processing.
  await alertIfSentFromReverseAlias(db, env, message, mailFrom);

  // VERP-addressed mail (bounces / out-of-office).
  const verp = await getVerpInfo(env, rcptTo);
  if (verp) return handleVerpInbound(message, env, mailFrom, verp);

  const reverse = await isReverseAlias(db, env, rcptTo);

  // Inbound DSN (bounce) detection MUST run before the null-sender E206 drop
  // below: under the envelope model (§0 of HANDOVER, file-top block) a
  // forward-phase bounce arrives as a null-sender DSN addressed to the
  // reverse alias, which E206 would black-hole. An unattributable DSN falls
  // through to the pre-existing handling (E206 drop here / ordinary
  // forward-phase delivery of the report) — documented deviation.
  const dsn = await handleInboundDsn(message, env, mailFrom, rcptTo, reverse);
  if (dsn.result) return dsn.result;
  // The detector may have consumed the single-use raw stream; when it did,
  // fall through with a replayed copy.
  const inbound = dsn.message ?? message;

  // Out-of-office auto-reply to a reverse alias with a null sender.
  if (isNullSender(mailFrom) && reverse) return accept(E206);

  // noreply address.
  if (getNoReplies(env).includes(rcptTo)) {
    await sendNoReplyResponse(db, env, mailFrom, inbound);
    return accept(E200);
  }

  if (reverse) return handleReplyPhase(inbound, env, mailFrom, rcptTo);
  return handleForwardPhase(inbound, env, mailFrom, rcptTo);
}

function isNullSender(mailFrom: string): boolean {
  return mailFrom === "" || mailFrom === "<>";
}

function getNoReplies(env: Env): string[] {
  // Flask NOREPLIES defaults to [NOREPLY_EMAIL] = ["noreply@EMAIL_DOMAIN"]
  // (app/config.py NOREPLY). The dashed "no-reply@" spelling is ALSO accepted
  // inbound (deviation, defensive): earlier builds of this port sent
  // transactional mail from no-reply@, so replies to that address must keep
  // being swallowed here instead of bouncing with E515.
  return [`noreply@${env.EMAIL_DOMAIN}`, `no-reply@${env.EMAIL_DOMAIN}`];
}

/** Value of the X-SimpleLogin-Loop-Count header; 0 when absent or invalid. */
function getLoopCount(headers: Headers): number {
  const value = getHeaderValue(headers, LOOP_COUNT_HEADER);
  if (!value) return 0;
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

/** is_reverse_alias (email_utils.py): DB lookup first, legacy prefixes after. */
async function isReverseAlias(
  db: D1Database,
  env: Env,
  address: string,
): Promise<boolean> {
  if (await getContactByReplyEmail(db, address)) return true;
  return (
    address.endsWith(`@${env.EMAIL_DOMAIN}`) &&
    (address.startsWith("reply+") || address.startsWith("ra+"))
  );
}

async function alertIfSentFromReverseAlias(
  db: D1Database,
  env: Env,
  message: ForwardableEmailMessage,
  mailFrom: string,
): Promise<void> {
  let contact = mailFrom ? await getContactByReplyEmail(db, mailFrom) : null;
  if (!contact) {
    const fromHeader = getHeaderValue(message.headers, "From");
    if (fromHeader) {
      const parsed = parseOneAddress(fromHeader);
      if (parsed) contact = await getContactByReplyEmail(db, parsed.address);
    }
  }
  if (!contact) return;
  const user = await getUserById(db, contact.user_id);
  if (!user) return;
  await sendAlertAtMostOnce(
    db,
    env,
    user.id,
    ALERT_FROM_ADDRESS_IS_REVERSE_ALIAS,
    user.email,
    "SimpleLogin shouldn't be used with another email forwarding system",
    `The reverse alias ${contact.reply_email} was used as a sender address. ` +
      "SimpleLogin shouldn't be used with another email forwarding system.",
  );
}

async function sendNoReplyResponse(
  db: D1Database,
  env: Env,
  mailFrom: string,
  message: ForwardableEmailMessage,
): Promise<void> {
  const mailbox = await db
    .prepare("SELECT * FROM mailbox WHERE email = ?1 LIMIT 1")
    .bind(mailFrom)
    .first<MailboxRow>();
  if (!mailbox) return;
  const user = await getUserById(db, mailbox.user_id);
  if (!user || !userIsActiveRow(user)) return;
  const subject = `Auto: ${getHeaderValue(message.headers, "Subject") || "No subject"}`;
  await sendAlertAtMostOnce(
    db,
    env,
    user.id,
    ALERT_TO_NOREPLY,
    user.email,
    subject,
    "The noreply address is not a valid alias and emails sent to it are discarded.",
  );
}

// ============================== forward phase =============================

async function handleForwardPhase(
  message: ForwardableEmailMessage,
  env: EmailEnv,
  mailFrom: string,
  rcptTo: string,
): Promise<HandleResult> {
  const db = env.DB;

  let alias = await getAliasByEmail(db, rcptTo);
  if (!alias) alias = await tryAutoCreate(db, env, rcptTo);
  if (!alias) {
    if (await shouldIgnoreBounce(db, mailFrom)) return accept(E207);
    return rejectWith(E515);
  }

  const user = await getUserById(db, alias.user_id);
  if (!user) return rejectWith(E502);
  if (!userIsActiveRow(user)) return rejectWith(E502);
  if (!userCanSendOrReceive(user)) {
    if (await shouldIgnoreBounce(db, mailFrom)) return accept(E207);
    return rejectWith(E504);
  }
  if (alias.custom_domain_id !== null) {
    const cd = await getCustomDomainById(db, alias.custom_domain_id);
    if (cd && !cd.verified) return rejectWith(E520);
  }

  // Cycle detection: email sent from one of the alias's own mailboxes.
  if (mailFrom) {
    const authorized = await aliasAuthorizedAddresses(db, alias);
    if (authorized.includes(mailFrom)) {
      await handleEmailSentToOurself(db, env, alias, mailFrom, user);
      return accept(E209);
    }
  }

  const fromHeader = getHeaderValue(message.headers, "From");
  const contact = await getOrCreateContact(
    db,
    env,
    fromHeader,
    mailFrom,
    alias,
    user,
  );
  if (!contact) return rejectWith(E504);

  // Loop hardening (deviation, defense-in-depth — Flask relies on other
  // signals: the own-mailbox cycle check above and the mailbox-is-alias
  // break below): rewrite-mode forwards stamp X-SimpleLogin-Loop-Count on
  // the outbound copy (forwardToMailbox step 9), so an inbound value above
  // MAX_LOOP_COUNT means the message has re-entered this worker too many
  // times (e.g. the mailbox auto-forwards back into another alias). Accept
  // and drop with a blocked EmailLog: rejects are permanent here (no
  // tempfail) and the drop stays visible in the alias activity.
  if (getLoopCount(message.headers) > MAX_LOOP_COUNT) {
    await createEmailLogRow(db, {
      userId: contact.user_id,
      contactId: contact.id,
      aliasId: contact.alias_id,
      blocked: 1,
    });
    return accept(E209);
  }

  // Per-minute flood limit (rate_limited_forward_phase, app/email/
  // rate_limit.py). Flask rejects with E522; here the message is accepted
  // and dropped with a blocked EmailLog instead (deviation — no tempfail on
  // this platform, an E522 reject would permanently bounce legit bursts).
  if (await rateLimitedForAliasOrMailbox(db, alias)) {
    if (await shouldIgnoreBounce(db, mailFrom)) return accept(E207);
    await createEmailLogRow(db, {
      userId: contact.user_id,
      contactId: contact.id,
      aliasId: contact.alias_id,
      blocked: 1,
    });
    return accept(E522);
  }

  // Reply-To contacts (step 2.5): a reverse-alias contact is created for each
  // Reply-To address; they are collected so the Reply-To header can be
  // rewritten to their reverse aliases in forwardToMailbox (max 5).
  const replyToContacts: ContactRow[] = [];
  const replyToHeader = getHeaderValue(message.headers, "Reply-To");
  if (replyToHeader) {
    for (const part of splitAddressList(replyToHeader)) {
      const parsed = parseOneAddress(part);
      if (!parsed || parsed.address === alias.email) continue;
      if (!isValidEmail(parsed.address)) continue;
      // Flask passes only the bare address to get_or_create_reply_to_contact,
      // which re-parses it -> empty name, so reply-to contacts are nameless.
      // get_or_create_reply_to_contact goes through contact_utils.create_contact,
      // which catches CannotCreateContactForReverseAlias and returns None: a
      // Reply-To that is itself a reverse alias is skipped, not rejected (E524).
      let rtc: ContactRow | null;
      try {
        rtc = await createContact(db, env, parsed.address, alias, user, {
          allowEmptyEmail: false,
        });
      } catch (e) {
        if (e instanceof CannotCreateContactForReverseAlias) continue;
        throw e;
      }
      if (rtc) replyToContacts.push(rtc);
    }
  }

  // Disabled alias / trashed alias / blocked contact -> blocked EmailLog.
  if (!alias.enabled || alias.delete_on !== null || contact.block_forward) {
    await createEmailLogRow(db, {
      userId: contact.user_id,
      contactId: contact.id,
      aliasId: contact.alias_id,
      blocked: 1,
    });
    if (user.block_behaviour === "return_5xx") return rejectWith(E502);
    return accept(E200);
  }

  const mailboxes = await aliasVerifiedMailboxes(db, alias);
  if (mailboxes.length === 0) {
    if (await shouldIgnoreBounce(db, mailFrom)) return accept(E207);
    return rejectWith(E516);
  }

  // `message.raw` is single-use, but the forward phase rebuilds and sends one
  // copy per mailbox. Buffer the raw bytes once here and hand a fresh header
  // copy to each mailbox. Only needed on the SEND_EMAIL rebuild path; the
  // message.forward() passthrough reads the message internally.
  //
  // FORWARD_MODE gates the rebuild: binding-sent mail is only delivered by
  // strict receivers (Gmail) when the domain is onboarded onto Email Sending
  // (paid — Cloudflare strips worker-added DKIM-Signature headers, so
  // self-signing cannot satisfy DMARC). Until then "passthrough" uses
  // message.forward(): reliable delivery, but From stays the original sender.
  // Set FORWARD_MODE=rewrite after onboarding for full Flask-parity forwards.
  const rewriteMode =
    env.SEND_EMAIL !== undefined && env.FORWARD_MODE === "rewrite";
  const buffered = rewriteMode ? await readRawMessage(message) : null;

  const results: Delivery[] = [];
  for (const mailbox of mailboxes) {
    // Mailbox that is itself an alias -> break the loop.
    const mailboxAsAlias = await getAliasByEmail(db, mailbox.email);
    if (mailboxAsAlias) {
      await db
        .prepare(
          "UPDATE mailbox SET verified = 0, updated_at = ?1 WHERE id = ?2",
        )
        .bind(nowStr(), mailbox.id)
        .run();
      await sendAlertWithRateControl(
        db,
        env,
        user.id,
        ALERT_MAILBOX_IS_ALIAS,
        user.email,
        `Your mailbox ${mailbox.email} is an alias`,
        `Your mailbox ${mailbox.email} is itself an alias and cannot receive forwarded emails. It has been unverified.`,
        1,
        1,
      );
      results.push({ success: false, status: E525 });
      continue;
    }
    results.push(
      await forwardToMailbox(
        message,
        env,
        alias,
        contact,
        mailbox,
        user,
        mailFrom,
        replyToContacts,
        buffered,
      ),
    );
  }

  const ok = results.find((r) => r.success);
  if (ok) return accept(ok.status);
  return rejectWith(results[0]?.status ?? E404);
}

/**
 * forward_email_to_mailbox (email_handler.py §2.8). Rebuilds the message so the
 * mailbox sees a reverse-alias From (and To/Cc/Reply-To rewritten to reverse
 * aliases) and clicking Reply reaches the reverse alias, then sends it through
 * the SEND_EMAIL binding with a VERP envelope sender. When the binding is not
 * bound (local dev) it falls back to message.forward(), which cannot rewrite
 * headers — see the fallback branch.
 */
async function forwardToMailbox(
  message: ForwardableEmailMessage,
  env: EmailEnv,
  alias: AliasRow,
  contact: ContactRow,
  mailbox: MailboxRow,
  user: UserRow,
  mailFrom: string,
  replyToContacts: ContactRow[],
  buffered: { headerLines: HeaderLine[]; body: Uint8Array } | null,
): Promise<Delivery> {
  const db = env.DB;

  if (mailbox.disabled) {
    if (await shouldIgnoreBounce(db, mailFrom))
      return { success: true, status: E207 };
    return { success: false, status: E518 };
  }
  if (mailbox.flags & MAILBOX_FLAG_ADMIN_DISABLED)
    return { success: true, status: E207 };

  // Sanity check: same domain on both sides means a mis-configured mailbox.
  if (domainPart(alias.email) === domainPart(mailbox.email)) {
    await sendAlertWithRateControl(
      db,
      env,
      user.id,
      ALERT_MAILBOX_IS_ALIAS,
      user.email,
      `Your mailbox ${mailbox.email} and alias ${alias.email} use the same domain`,
      `Your mailbox ${mailbox.email} and alias ${alias.email} use the same domain; forwarding is not possible.`,
      1,
      1,
    );
    return { success: false, status: E405 };
  }

  const messageId = getHeaderValue(message.headers, "Message-ID");
  const emailLog = await createEmailLogRow(db, {
    userId: contact.user_id,
    contactId: contact.id,
    aliasId: contact.alias_id,
    mailboxId: mailbox.id,
    messageId: messageId ?? null,
  });

  // Recipient limit on the original To + Cc (step 13, before To/Cc rewriting).
  const origToHeader = getHeaderValue(message.headers, "To") ?? "";
  const origCcHeader = getHeaderValue(message.headers, "Cc") ?? "";
  const nbRcpt =
    splitAddressList(origToHeader).length +
    splitAddressList(origCcHeader).length;
  if (nbRcpt > MAX_EMAIL_FORWARD_RECIPIENTS)
    return { success: false, status: E526 };

  // Passthrough delivery (FORWARD_MODE!=rewrite, or no SEND_EMAIL binding):
  // forward as-is with the X-SimpleLogin-* headers. This CANNOT rewrite
  // From/To/Cc, so Reply from the mailbox reaches the original sender — the
  // rebuild path below is the faithful one (requires Email Sending onboarding
  // so the mail is DKIM-signed by Cloudflare).
  if (!buffered) {
    const xHeaders = new Headers();
    xHeaders.set("X-SimpleLogin-Type", "Forward");
    xHeaders.set(EMAIL_LOG_HEADER, String(emailLog.id));
    if (user.include_header_email_header) {
      xHeaders.set("X-SimpleLogin-Envelope-From", mailFrom);
      xHeaders.set(
        "X-SimpleLogin-Original-From",
        formatAddr(contact.name, contact.website_email),
      );
    }
    xHeaders.set("X-SimpleLogin-Envelope-To", alias.email);
    try {
      await message.forward(mailbox.email, xHeaders);
    } catch (e) {
      console.error(`cannot forward to ${mailbox.email}:`, e);
      if (await shouldIgnoreBounce(db, mailFrom))
        return { success: true, status: E207 };
      await deleteEmailLogRow(db, emailLog.id);
      return { success: false, status: E407 };
    }
    return { success: true, status: E200 };
  }

  // ---- rebuild the message (steps 5-18) ----
  const hs = filterHeaders(buffered.headerLines, forwardKeptHeaders(user));
  if (!getHeader(hs, "Content-Transfer-Encoding"))
    hs.push({ name: "Content-Transfer-Encoding", value: "7bit" });

  let outBody = buffered.body;

  // Step 5: invalid-sender notice. The contact was created without a usable
  // address (contact.invalid_email), so the reverse alias goes nowhere — warn
  // the reader they cannot reply.
  if (contact.invalid_email) {
    const banner = `Email sent to ${alias.email} from an invalid address and cannot be replied`;
    outBody = addBodyHeader(hs, outBody, banner, banner);
  }

  // Step 7: generic subject. Replace the Subject and prepend a banner carrying
  // the original sender/subject so that information is not lost. `sender` is the
  // original From, read before the step-11 reverse-alias rewrite below.
  if (mailbox.generic_subject) {
    const origSubject = getHeader(hs, "Subject") ?? "";
    const sender = getHeader(hs, "From") ?? "";
    setHeader(hs, "Subject", mailbox.generic_subject);
    outBody = addBodyHeader(
      hs,
      outBody,
      `Forwarded by SimpleLogin to ${alias.email} from "${sender}" with "${origSubject}" as subject`,
      `Forwarded by SimpleLogin to ${alias.email} from "${sender}" with <b>${origSubject}</b> as subject`,
    );
  }

  // Step 8: PGP (email_handler.py L884-899). Encrypt when the mailbox has PGP
  // enabled (Mailbox.pgp_enabled(): pgp_finger_print set AND not disable_pgp),
  // the user is premium and the alias doesn't opt out. Flask encrypts HERE —
  // before the reverse-alias From/To/Cc rewrites and List-Unsubscribe (steps
  // 9-16) — but prepare_pgp_message moves every non-MIME header onto the
  // OUTER multipart/encrypted envelope, so those later rewrites apply to the
  // outer message; only the MIME headers + body get encrypted. Mutating `hs`
  // in place here reproduces that exactly.
  if (
    mailbox.pgp_finger_print &&
    !mailbox.disable_pgp &&
    !alias.disable_pgp &&
    (await userIsPremium(db, user))
  ) {
    try {
      outBody = await preparePgpMessage(
        hs,
        outBody,
        mailbox.pgp_public_key ?? "",
      );
    } catch (e) {
      if (!(e instanceof PGPException)) throw e;
      // Failure banner (email_handler.py L891-899): deliver unencrypted with
      // the notice prepended (add_header's html defaults to the text).
      console.warn(`cannot encrypt message for mailbox ${mailbox.email}:`, e);
      const banner = `PGP encryption fails with ${mailbox.email}'s PGP key`;
      outBody = addBodyHeader(hs, outBody, banner, banner);
    }
  }
  // Step 4 (SpamAssassin) is config-gated off.

  // Step 9: X-SimpleLogin-* headers (added after the whitelist so they stay).
  setHeader(hs, "X-SimpleLogin-Type", "Forward");
  setHeader(hs, EMAIL_LOG_HEADER, String(emailLog.id));
  if (user.include_header_email_header) {
    setHeader(hs, "X-SimpleLogin-Envelope-From", mailFrom);
    setHeader(
      hs,
      "X-SimpleLogin-Original-From",
      contact.name
        ? `${contact.name} <${contact.website_email}>`
        : contact.website_email,
    );
  }
  setHeader(hs, "X-SimpleLogin-Envelope-To", alias.email);
  // Loop hardening (deviation): count the passes through this worker. The
  // forward whitelist dropped any inbound copy of the header, so re-stamp
  // with the incremented value; handleForwardPhase drops inbound mail whose
  // count exceeds MAX_LOOP_COUNT.
  setHeader(hs, LOOP_COUNT_HEADER, String(getLoopCount(message.headers) + 1));
  if (!getHeader(hs, "Date"))
    setHeader(hs, "Date", formatDateRfc2822(new Date()));

  // Step 10: thread-fix — restore original ids so the mailbox sees its thread.
  await replaceSlMessageIdByOriginal(db, hs);

  // Step 11: From becomes the contact's reverse-alias display address.
  setHeader(hs, "From", contactNewAddr(contact, user));

  // Step 12: Reply-To rewritten to the reply-to contacts' reverse aliases (max
  // 5). Without reply-to contacts the whitelist already dropped Reply-To.
  if (replyToContacts.length > 0) {
    setHeader(
      hs,
      "Reply-To",
      replyToContacts
        .slice(0, 5)
        .map((c) => contactNewAddr(c, user))
        .join(", "),
    );
  }

  // Step 14: rewrite To then Cc to reverse aliases (Cc first, matching Flask).
  try {
    await replaceHeaderWhenForward(db, env, hs, alias, user, "Cc");
    await replaceHeaderWhenForward(db, env, hs, alias, user, "To");
  } catch (e) {
    if (e instanceof CannotCreateContactForReverseAlias) {
      await deleteEmailLogRow(db, emailLog.id);
    }
    throw e;
  }

  // Step 15: make sure the alias appears in To (BCC-delivered mail).
  addAliasToHeaderIfNeeded(hs, alias);

  // Step 16: List-Unsubscribe handling.
  addUnsubscribeHeaders(env, alias, contact, user, hs);

  // Step 17: DKIM signing is skipped — Cloudflare signs binding sends for the
  // routed domain, so no add_dkim_signature equivalent is needed here.

  // Step 18: send with a per-forward VERP envelope sender on the contact's
  // reverse-alias domain.
  const rawOut = serializeMessage(hs, outBody);
  const verpFrom = await generateVerpEmail(
    env,
    VERP_TYPE_BOUNCE_FORWARD,
    emailLog.id,
    domainPart(contact.reply_email),
  );
  try {
    await sendRawEmail(env, verpFrom, mailbox.email, rawOut);
  } catch (e) {
    console.error(`cannot forward to ${mailbox.email}:`, e);
    // Every policy check has passed and the message is fully built, so a
    // throw from sendRawEmail is a transport failure at the binding. Stash
    // the built message and hand it to the 'retry-email' job instead of
    // rejecting (deviation — Flask lets the Postfix queue absorb transient
    // SMTP failures; a reject here is PERMANENT at the sender's MTA). The
    // EmailLog above stays as the record of the pending forward. Only when
    // even scheduling fails does the pre-retry E407 behavior remain.
    if (
      await scheduleEmailRetry(env, {
        emailLogId: emailLog.id,
        phase: "forward",
        envelopeFrom: verpFrom,
        to: mailbox.email,
        raw: rawOut,
      })
    )
      return { success: true, status: E200 };
    if (await shouldIgnoreBounce(db, mailFrom))
      return { success: true, status: E207 };
    await deleteEmailLogRow(db, emailLog.id);
    return { success: false, status: E407 };
  }
  return { success: true, status: E200 };
}

/** Header whitelist for the forward phase (email_handler.py §2.8 step 6). */
function forwardKeptHeaders(user: UserRow): string[] {
  const kept = [
    "from",
    "to",
    "cc",
    "subject",
    "date",
    "message-id",
    "references",
    "in-reply-to",
    "x-sl-queue-id",
    "list-unsubscribe",
    "list-id",
    "list-unsubscribe-post",
    "mime-version",
    "content-type",
    "content-disposition",
    "content-transfer-encoding",
  ];
  if (user.include_header_email_header) kept.push("authentication-results");
  return kept;
}

/** Contact.new_addr() (app/models.py) — the reverse-alias From/To/Cc display. */
function contactNewAddr(contact: ContactRow, user: UserRow): string {
  const senderFormat = user ? user.sender_format : SENDER_FORMAT_AT;
  if (senderFormat === SENDER_FORMAT_NO_NAME) return contact.reply_email;

  const websiteEmail = contact.website_email;
  const name = contact.name;
  let newName: string;
  if (senderFormat === SENDER_FORMAT_NAME_ONLY) {
    newName = name ?? "";
  } else if (senderFormat === SENDER_FORMAT_AT_ONLY) {
    newName = websiteEmail.replaceAll("@", " at ").trim();
  } else if (senderFormat === SENDER_FORMAT_A) {
    const formatted = websiteEmail.replaceAll("@", "(a)").trim();
    newName =
      name && name !== websiteEmail.trim()
        ? `${name} - ${formatted}`
        : formatted;
  } else {
    // SENDER_FORMAT_AT (default) and any unknown value
    const formatted = websiteEmail.replaceAll("@", " at ").trim();
    newName =
      name && name !== websiteEmail.trim()
        ? `${name} - ${formatted}`
        : formatted;
  }
  return formatAddr(newName, contact.reply_email).trim();
}

/**
 * replace_header_when_forward (email_handler.py): rewrite a To/Cc header,
 * substituting each non-alias recipient with a get-or-created reverse alias.
 */
async function replaceHeaderWhenForward(
  db: D1Database,
  env: Env,
  hs: HeaderLine[],
  alias: AliasRow,
  user: UserRow,
  headerName: string,
): Promise<void> {
  const value = getHeader(hs, headerName);
  if (value === null) return;

  const newAddrs: string[] = [];
  for (const part of splitAddressList(value)) {
    const parsed = parseOneAddress(part);
    const rawAddr = parsed ? parsed.address : part;
    const contactEmail = sanitizeEmail(rawAddr, true); // case-preserved
    // Alias already present (Reply-All) is kept verbatim.
    if (contactEmail.toLowerCase() === alias.email) {
      newAddrs.push(formatAddr(parsed?.name ?? "", contactEmail));
      continue;
    }
    // Non-ASCII / invalid contact addresses are skipped.
    if (!isValidEmail(contactEmail)) continue;
    const contactName = (parsed?.name ?? "").slice(0, CONTACT_MAX_NAME_LENGTH);
    const existing = await getContactByAliasAndEmail(
      db,
      alias.id,
      contactEmail,
    );
    let contact: ContactRow | null;
    if (existing) {
      // replace_header_when_forward assigns the display name unconditionally
      // when it differs (including an empty name), so a header carrying a bare
      // address clears a name the contact was previously created with.
      const newName = contactName || null;
      if (existing.name !== newName) {
        await db
          .prepare(
            "UPDATE contact SET name = ?1, updated_at = ?2 WHERE id = ?3",
          )
          .bind(newName, nowStr(), existing.id)
          .run();
        existing.name = newName;
      }
      contact = existing;
    } else {
      // New contacts go through create_contact, which raises
      // CannotCreateContactForReverseAlias for a reverse-alias address (-> E524).
      contact = await createContact(db, env, contactEmail, alias, user, {
        name: contactName,
        isCc: headerName.toLowerCase() === "cc",
        allowEmptyEmail: false,
      });
    }
    if (contact) newAddrs.push(contactNewAddr(contact, user));
  }

  if (newAddrs.length > 0) setHeader(hs, headerName, newAddrs.join(","));
  else deleteHeader(hs, headerName);
}

/** add_alias_to_header_if_needed (email_handler.py) — BCC-delivered mail. */
function addAliasToHeaderIfNeeded(hs: HeaderLine[], alias: AliasRow): void {
  const toHeader = getHeader(hs, "To");
  const ccHeader = getHeader(hs, "Cc");
  if (toHeader?.includes(alias.email)) return;
  if (ccHeader?.includes(alias.email)) return;
  if (toHeader) setHeader(hs, "To", `${toHeader},${alias.email}`);
  else setHeader(hs, "To", alias.email);
}

/**
 * replace_sl_message_id_by_original_message_id (email_handler.py): the forward
 * direction of the reply phase's Message-ID rewriting — SL ids in In-Reply-To
 * and References are mapped back to the sender's original ids.
 */
async function replaceSlMessageIdByOriginal(
  db: D1Database,
  hs: HeaderLine[],
): Promise<void> {
  const inReplyTo = getHeader(hs, "In-Reply-To");
  if (inReplyTo) {
    const m = await db
      .prepare(
        "SELECT original_message_id FROM message_id_matching WHERE sl_message_id = ?1",
      )
      .bind(inReplyTo)
      .first<{ original_message_id: string }>();
    if (m) setHeader(hs, "In-Reply-To", m.original_message_id);
  }

  const refs = getHeader(hs, "References");
  if (refs) {
    const tokens = refs.split(/\s+/).filter(Boolean);
    const out: string[] = [];
    for (const token of tokens) {
      const m = await db
        .prepare(
          "SELECT original_message_id FROM message_id_matching WHERE sl_message_id = ?1",
        )
        .bind(token)
        .first<{ original_message_id: string }>();
      out.push(m ? m.original_message_id : token);
    }
    setHeader(hs, "References", out.join(" "));
  }
}

/**
 * UnsubscribeGenerator.add_header_to_message (app/handler/unsubscribe_generator.py).
 * The mailto UNSUBSCRIBER address is not configured on this port (deviation —
 * mailto unsubscribe would need a dedicated inbound handler), so every link is
 * the https/web form: DisableAlias/BlockContact use encode_url, and the
 * PreserveOriginal path proxies http(s) methods of the original
 * List-Unsubscribe as-is while a mailto-ONLY original is replaced by a signed
 * `/dashboard/unsubscribe/encoded/<payload>` link (FWD-5; the web route
 * re-sends the original unsubscribe mail on the user's click). The
 * force_web / USERS_WITH_HTTP_UNSUBSCRIBE knob is moot without UNSUBSCRIBER.
 */
function addUnsubscribeHeaders(
  env: Env,
  alias: AliasRow,
  contact: ContactRow,
  user: UserRow,
  hs: HeaderLine[],
): void {
  const behaviour = user.unsub_behaviour;
  const proxied = calculateOriginalUnsubHeaders(env, alias, hs);

  // __preserve_original_headers: stash the sender's originals + X-SL-Proxy-*.
  const origLu = getHeader(hs, "List-Unsubscribe");
  if (origLu) setHeader(hs, "X-SimpleLogin-Original-List-Unsubscribe", origLu);
  const origLup = getHeader(hs, "List-Unsubscribe-Post");
  if (origLup)
    setHeader(hs, "X-SimpleLogin-Original-List-Unsubscribe-Post", origLup);
  const origLi = getHeader(hs, "List-Id");
  if (origLi) {
    setHeader(hs, "X-SimpleLogin-Original-List-Id", origLi);
    deleteHeader(hs, "List-Id");
  }
  for (const [k, v] of Object.entries(proxied))
    setHeader(hs, `X-SL-Proxy-${k}`, v);

  if (behaviour === UNSUB_PRESERVE_ORIGINAL) {
    deleteHeader(hs, "List-Unsubscribe");
    deleteHeader(hs, "List-Unsubscribe-Post");
    for (const [k, v] of Object.entries(proxied)) setHeader(hs, k, v);
  } else if (behaviour === UNSUB_DISABLE_ALIAS) {
    setHeader(
      hs,
      "List-Unsubscribe",
      `<${env.URL}/dashboard/unsubscribe/${alias.id}>`,
    );
    setHeader(hs, "List-Unsubscribe-Post", "List-Unsubscribe=One-Click");
  } else {
    setHeader(
      hs,
      "List-Unsubscribe",
      `<${env.URL}/dashboard/block_contact/${contact.id}>`,
    );
    setHeader(hs, "List-Unsubscribe-Post", "List-Unsubscribe=One-Click");
  }

  const headerValue =
    behaviour === UNSUB_DISABLE_ALIAS
      ? "alias-disable"
      : behaviour === UNSUB_BLOCK_CONTACT
        ? "contact-block"
        : behaviour === UNSUB_PRESERVE_ORIGINAL
          ? "original-behaviour"
          : null;
  if (headerValue) setHeader(hs, "X-SimpleLogin-Unsub-Behaviour", headerValue);
}

/**
 * _calculate_header_with_original_behaviour (unsubscribe_generator.py L33-106):
 * when the original List-Unsubscribe carries http(s) methods, forward only
 * those (mailto methods are dropped so the real mailbox never leaks); a
 * mailto-ONLY header is proxied through a signed
 * /dashboard/unsubscribe/encoded/ link encoding (alias, recipient, subject)
 * so the web route can re-send the original unsubscribe mail (FWD-5). Returns
 * the proxied header dict, or {} to drop both headers.
 * Flask's `url_data.path == config.UNSUBSCRIBER` short-circuit (L69-78) is
 * not ported — UNSUBSCRIBER is never configured here (see
 * addUnsubscribeHeaders); with it unset the Python comparison never matches.
 */
function calculateOriginalUnsubHeaders(
  env: Env,
  alias: AliasRow,
  hs: HeaderLine[],
): Record<string, string> {
  const value = getHeader(hs, "List-Unsubscribe");
  if (!value) return {};
  let mailtoUnsub: { recipient: string; subject: string } | null = null;
  const otherUnsubs: string[] = [];
  for (const rawMethod of value.split(",")) {
    const start = rawMethod.indexOf("<");
    const end = rawMethod.lastIndexOf(">");
    if (start === -1 || end === -1 || start >= end) continue;
    const method = rawMethod.slice(start + 1, end);
    const parsed = urlparseLite(method);
    if (!parsed) continue; // urlparse ValueError -> method ignored (L65-67)
    if (parsed.scheme === "mailto") {
      // Flask reassigns mailto_unsubs each iteration: the LAST mailto wins.
      mailtoUnsub = {
        recipient: parsed.path,
        subject: parseQsFirst(parsed.query, "subject"),
      };
    } else {
      // Anything not mailto-schemed (https, http, even scheme-less garbage)
      // lands in the click-method bucket, exactly like Flask's else branch.
      otherUnsubs.push(method);
    }
  }
  // If there are non-mailto unsubscribe methods, use those in the header.
  if (otherUnsubs.length > 0) {
    return {
      "List-Unsubscribe": otherUnsubs.map((m) => `<${m}>`).join(", "),
      "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
    };
  }
  if (!mailtoUnsub) return {};
  const link = encodeUnsubscribeUrl(
    env.URL,
    unsubscribeSecret(env),
    UnsubscribeAction.OriginalUnsubscribeMailto,
    {
      aliasId: alias.id,
      recipient: mailtoUnsub.recipient,
      subject: mailtoUnsub.subject,
    },
  );
  // The link is always the web form here (UNSUBSCRIBER unset => via_email is
  // False), so the One-Click POST header is added like Flask L103-105.
  return {
    "List-Unsubscribe": `<${link}>`,
    "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
  };
}

/**
 * urllib.parse.urlparse subset for unsubscribe methods: scheme (lowercased),
 * path and query. Mirrors urlsplit's framing — scheme prefix must start with
 * an ASCII letter and use only [A-Za-z0-9+.-] (else scheme stays "" and the
 * whole method is the path, i.e. a non-mailto method); an authority follows
 * "//" and runs to the first "/?#"; the fragment splits before the query.
 * Returns null where urlparse raises ValueError (unbalanced [] brackets in
 * the authority), which Flask catches and skips.
 */
function urlparseLite(
  method: string,
): { scheme: string; path: string; query: string } | null {
  let rest = method;
  let scheme = "";
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):([\s\S]*)$/.exec(rest);
  if (m) {
    scheme = m[1].toLowerCase();
    rest = m[2];
  }
  if (rest.startsWith("//")) {
    let delim = rest.length;
    for (const c of ["/", "?", "#"]) {
      const idx = rest.indexOf(c, 2);
      if (idx !== -1 && idx < delim) delim = idx;
    }
    const netloc = rest.slice(2, delim);
    if (netloc.includes("[") !== netloc.includes("]")) return null;
    rest = rest.slice(delim);
  }
  const hash = rest.indexOf("#");
  if (hash !== -1) rest = rest.slice(0, hash);
  const qm = rest.indexOf("?");
  let query = "";
  if (qm !== -1) {
    query = rest.slice(qm + 1);
    rest = rest.slice(0, qm);
  }
  return { scheme, path: rest, query };
}

/** parse_qs(query).get(name, [""])[0]: first NON-BLANK value of the param
 *  (keep_blank_values=False drops empty ones), unquote_plus-decoded. */
function parseQsFirst(query: string, name: string): string {
  for (const pair of query.split("&")) {
    const eq = pair.indexOf("=");
    if (eq === -1) continue; // pairs without "=" are skipped entirely
    if (unquotePlus(pair.slice(0, eq)) !== name) continue;
    const v = pair.slice(eq + 1);
    if (!v) continue;
    return unquotePlus(v);
  }
  return "";
}

/** urllib.parse.unquote_plus with errors="replace" — never throws: "+" is a
 *  space, runs of %XX bytes decode as UTF-8 with U+FFFD replacement, and
 *  malformed % sequences pass through verbatim (unlike decodeURIComponent). */
function unquotePlus(s: string): string {
  return s.replaceAll("+", " ").replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => {
    const bytes = new Uint8Array(run.length / 3);
    for (let i = 0; i < bytes.length; i++)
      bytes[i] = Number.parseInt(run.slice(i * 3 + 1, i * 3 + 3), 16);
    // ignoreBOM keeps a decoded U+FEFF like Python's bytes.decode does.
    return new TextDecoder("utf-8", { fatal: false, ignoreBOM: true }).decode(
      bytes,
    );
  });
}

async function handleEmailSentToOurself(
  db: D1Database,
  env: Env,
  alias: AliasRow,
  fromAddr: string,
  user: UserRow,
): Promise<void> {
  const title = `Email sent to ${alias.email} from its own mailbox ${fromAddr}`;
  await db
    .prepare(
      "INSERT INTO notification (user_id, title, message) VALUES (?1, ?2, ?3)",
    )
    .bind(user.id, title, title)
    .run();
  await sendAlertAtMostOnce(
    db,
    env,
    user.id,
    ALERT_SEND_EMAIL_CYCLE,
    fromAddr,
    title,
    `The email sent to ${alias.email} comes from its own mailbox ${fromAddr} and has not been forwarded to avoid an email loop.`,
  );
}

// ============================ alias auto-creation =========================

async function tryAutoCreate(
  db: D1Database,
  env: EmailEnv,
  address: string,
): Promise<AliasRow | null> {
  // Refuse addresses that look like VERP bounce addresses.
  if (
    address.startsWith(`${BOUNCE_PREFIX_FOR_REPLY_PHASE}+`) &&
    address.includes("+@")
  )
    return null;
  if (
    address.startsWith(BOUNCE_PREFIX) &&
    address.endsWith(`+@${env.EMAIL_DOMAIN}`)
  )
    return null;
  if (!isValidEmail(address)) return null;

  const viaDomain = await tryAutoCreateViaDomain(db, env, address);
  if (viaDomain) return viaDomain;
  return tryAutoCreateDirectory(db, env, address);
}

interface AutoCreateRuleRow {
  id: number;
  custom_domain_id: number;
  regex: string;
  order: number;
  display_name: string | null;
}

async function tryAutoCreateViaDomain(
  db: D1Database,
  env: EmailEnv,
  address: string,
): Promise<AliasRow | null> {
  const domain = domainPart(address);
  const customDomain = await db
    .prepare("SELECT * FROM custom_domain WHERE domain = ?1")
    .bind(domain)
    .first<CustomDomainRow>();
  if (!customDomain?.ownership_verified) return null;

  const user = await getUserById(db, customDomain.user_id);
  if (!user || user.disabled) return null;
  if (!(await canCreateNewAlias(db, env, user))) {
    // send_cannot_create_domain_alias: suppressed for disabled / pending-delete
    // users (user.can_send_or_receive()).
    if (userCanSendOrReceive(user))
      await sendTransactionalEmail(env, {
        to: user.email,
        subject: `Alias ${address} cannot be created`,
        text: `Alias ${address} cannot be created because you have reached the limit of aliases on your plan.`,
      });
    return null;
  }

  let rule: AutoCreateRuleRow | null = null;
  if (!customDomain.catch_all) {
    const rules = await db
      .prepare(
        'SELECT * FROM auto_create_rule WHERE custom_domain_id = ?1 ORDER BY "order"',
      )
      .bind(customDomain.id)
      .all<AutoCreateRuleRow>();
    if (rules.results.length === 0) return null;
    const local = localPart(address);
    rule = rules.results.find((r) => regexFullMatch(r.regex, local)) ?? null;
    if (!rule) return null;
  }

  let mailboxes: MailboxRow[];
  if (rule) {
    const res = await db
      .prepare(
        `SELECT m.* FROM mailbox m
         JOIN auto_create_rule__mailbox rm ON rm.mailbox_id = m.id
         WHERE rm.auto_create_rule_id = ?1 ORDER BY rm.id`,
      )
      .bind(rule.id)
      .all<MailboxRow>();
    mailboxes = res.results;
  } else {
    const res = await db
      .prepare(
        `SELECT m.* FROM mailbox m
         JOIN domain_mailbox dm ON dm.mailbox_id = m.id
         WHERE dm.domain_id = ?1 ORDER BY dm.id`,
      )
      .bind(customDomain.id)
      .all<MailboxRow>();
    mailboxes = res.results;
  }
  if (mailboxes.length === 0) {
    const fallback = user.default_mailbox_id
      ? await getMailboxById(db, user.default_mailbox_id)
      : null;
    if (!fallback) return null;
    mailboxes = [fallback];
  }

  const note = user.disable_automatic_alias_note
    ? null
    : rule
      ? `Created by rule ${rule.order} with regex ${rule.regex}`
      : "Created by catchall option";
  return insertAutoCreatedAlias(db, {
    email: address,
    userId: customDomain.user_id,
    customDomainId: customDomain.id,
    directoryId: null,
    automaticCreation: 1,
    mailboxes,
    name: rule?.display_name ?? null,
    note,
  });
}

async function tryAutoCreateDirectory(
  db: D1Database,
  env: EmailEnv,
  address: string,
): Promise<AliasRow | null> {
  const aliasDomains = env.ALIAS_DOMAINS.split(",")
    .map((d) => d.trim())
    .filter(Boolean);
  if (!aliasDomains.some((d) => address.endsWith(`@${d}`))) return null;

  let sep: string | null = null;
  if (address.includes("/")) sep = "/";
  else if (address.includes("+")) sep = "+";
  else if (address.includes("#")) sep = "#";
  if (!sep) return null;

  const directoryName = address.slice(0, address.indexOf(sep));
  const directory = await db
    .prepare("SELECT * FROM directory WHERE name = ?1")
    .bind(directoryName)
    .first<DirectoryRow>();
  if (!directory) return null;

  const user = await getUserById(db, directory.user_id);
  if (!user || user.disabled) return null;
  if (!(await canCreateNewAlias(db, env, user))) {
    // send_cannot_create_directory_alias: suppressed for disabled /
    // pending-delete users (user.can_send_or_receive()).
    if (userCanSendOrReceive(user))
      await sendTransactionalEmail(env, {
        to: user.email,
        subject: `Alias ${address} cannot be created`,
        text: `Alias ${address} cannot be created because you have reached the limit of aliases on your plan.`,
      });
    return null;
  }
  if (directory.disabled) {
    // send_cannot_create_directory_alias_disabled: guarded by
    // can_send_or_receive AND rate-controlled (MAX_ALERT_24H/day) so repeated
    // probes to a disabled-directory address can't flood the user.
    if (userCanSendOrReceive(user))
      await sendAlertWithRateControl(
        db,
        env,
        user.id,
        ALERT_DIRECTORY_DISABLED_ALIAS_CREATION,
        user.email,
        `Alias ${address} cannot be created`,
        `Alias ${address} cannot be created because the directory ${directoryName} is disabled.`,
      );
    return null;
  }

  const res = await db
    .prepare(
      `SELECT m.* FROM mailbox m
       JOIN directory_mailbox dm ON dm.mailbox_id = m.id
       WHERE dm.directory_id = ?1 ORDER BY dm.id`,
    )
    .bind(directory.id)
    .all<MailboxRow>();
  let mailboxes = res.results;
  if (mailboxes.length === 0) {
    const fallback = user.default_mailbox_id
      ? await getMailboxById(db, user.default_mailbox_id)
      : null;
    if (!fallback) return null;
    mailboxes = [fallback];
  }

  return insertAutoCreatedAlias(db, {
    email: address,
    userId: directory.user_id,
    customDomainId: null,
    directoryId: directory.id,
    automaticCreation: 0,
    mailboxes,
    name: null,
    note: user.disable_automatic_alias_note
      ? null
      : `Created by directory ${directory.name}`,
  });
}

async function insertAutoCreatedAlias(
  db: D1Database,
  opts: {
    email: string;
    userId: number;
    customDomainId: number | null;
    directoryId: number | null;
    automaticCreation: number;
    mailboxes: MailboxRow[];
    name: string | null;
    note: string | null;
  },
): Promise<AliasRow | null> {
  // Alias.create raises AliasInTrashError when the address was deleted before.
  const inTrash =
    (await db
      .prepare("SELECT 1 FROM deleted_alias WHERE email = ?1 LIMIT 1")
      .bind(opts.email)
      .first()) ||
    (await db
      .prepare("SELECT 1 FROM domain_deleted_alias WHERE email = ?1 LIMIT 1")
      .bind(opts.email)
      .first());
  if (inTrash) return null;

  let alias: AliasRow | null;
  try {
    alias = await db
      .prepare(
        `INSERT INTO alias (user_id, email, custom_domain_id, directory_id,
           automatic_creation, mailbox_id, name, note)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) RETURNING *`,
      )
      .bind(
        opts.userId,
        opts.email,
        opts.customDomainId,
        opts.directoryId,
        opts.automaticCreation,
        opts.mailboxes[0].id,
        opts.name,
        opts.note,
      )
      .first<AliasRow>();
  } catch {
    // IntegrityError -> alias created concurrently, return the existing one.
    return getAliasByEmail(db, opts.email);
  }
  if (!alias) return null;
  for (const mb of opts.mailboxes.slice(1)) {
    await db
      .prepare(
        "INSERT INTO alias_mailbox (alias_id, mailbox_id) VALUES (?1, ?2)",
      )
      .bind(alias.id, mb.id)
      .run();
  }
  return alias;
}

// ============================ contact handling ============================

/** get_or_create_contact (email_handler.py). */
async function getOrCreateContact(
  db: D1Database,
  env: Env,
  fromHeader: string | null,
  mailFrom: string,
  alias: AliasRow,
  aliasUser: UserRow,
): Promise<ContactRow | null> {
  let contactName = "";
  let contactEmail = "";
  const parsed = fromHeader ? parseOneAddress(fromHeader) : null;
  if (parsed) {
    contactName = parsed.name;
    contactEmail = parsed.address;
  }
  contactName = contactName.slice(0, CONTACT_MAX_NAME_LENGTH);
  if (!isValidEmail(contactEmail)) {
    if (mailFrom && mailFrom !== "<>") contactEmail = mailFrom;
  }
  // contact_utils.create_contact catches CannotCreateContactForReverseAlias and
  // returns None (-> handle_forward returns E504), rather than letting it become
  // the E524 raised for reverse aliases in the To/Cc rewrite.
  try {
    return await createContact(db, env, contactEmail, alias, aliasUser, {
      name: contactName,
      mailFrom,
      allowEmptyEmail: true,
    });
  } catch (e) {
    if (e instanceof CannotCreateContactForReverseAlias) return null;
    throw e;
  }
}

interface CreateContactOpts {
  name?: string | null;
  mailFrom?: string | null;
  allowEmptyEmail?: boolean;
  isCc?: boolean;
}

/** contact_utils.create_contact with automatic_created=True semantics. */
async function createContact(
  db: D1Database,
  env: Env,
  rawEmail: string,
  alias: AliasRow,
  aliasUser: UserRow,
  opts: CreateContactOpts,
): Promise<ContactRow | null> {
  // Re-parse 'name <email>' form.
  let email = rawEmail;
  let emailName = "";
  const parsed = parseOneAddress(email);
  if (parsed) {
    emailName = parsed.name;
    email = parsed.address;
  } else {
    email = "";
    emailName = "";
  }

  let name: string | null =
    opts.name === undefined || opts.name === null
      ? emailName.slice(0, CONTACT_MAX_NAME_LENGTH)
      : opts.name.slice(0, CONTACT_MAX_NAME_LENGTH);
  if (!name) name = null;
  if (name?.includes("\u0000")) name = "";

  // Contact emails keep their case.
  email = sanitizeEmail(email, true);
  if (!isValidEmail(email)) {
    if (!opts.allowEmptyEmail) return null;
    email = "";
  }

  const existing = await getContactByAliasAndEmail(db, alias.id, email);
  if (existing)
    return updateContactIfNeeded(db, existing, name, opts.mailFrom ?? null);

  const replyEmail = await generateReplyEmail(db, env, email, alias, aliasUser);

  // Refuse to create a contact whose address is someone's reverse alias.
  const lowered = sanitizeEmail(email);
  if (!getNoReplies(env).includes(lowered)) {
    const orig = await getContactByReplyEmail(db, lowered);
    if (orig) throw new CannotCreateContactForReverseAlias(lowered);
  }

  try {
    const row = await db
      .prepare(
        `INSERT INTO contact (user_id, alias_id, website_email, name, reply_email,
           mail_from, is_cc, automatic_created, flags, invalid_email)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, 0, ?8) RETURNING *`,
      )
      .bind(
        alias.user_id,
        alias.id,
        email,
        name,
        replyEmail,
        opts.mailFrom ?? null,
        opts.isCc ? 1 : 0,
        email === "" ? 1 : 0,
      )
      .first<ContactRow>();
    return row;
  } catch {
    // uq_contact race -> re-fetch and update.
    const again = await getContactByAliasAndEmail(db, alias.id, email);
    if (again)
      return updateContactIfNeeded(db, again, name, opts.mailFrom ?? null);
    return null;
  }
}

async function updateContactIfNeeded(
  db: D1Database,
  contact: ContactRow,
  name: string | null,
  mailFrom: string | null,
): Promise<ContactRow> {
  const updated = { ...contact };
  if (name && contact.name !== name) {
    await db
      .prepare("UPDATE contact SET name = ?1, updated_at = ?2 WHERE id = ?3")
      .bind(name, nowStr(), contact.id)
      .run();
    updated.name = name;
  }
  if (mailFrom && contact.mail_from === null) {
    await db
      .prepare(
        "UPDATE contact SET mail_from = ?1, updated_at = ?2 WHERE id = ?3",
      )
      .bind(mailFrom, nowStr(), contact.id)
      .run();
    updated.mail_from = mailFrom;
  }
  return updated;
}

/** email_utils.generate_reply_email — new-format reverse aliases only. */
async function generateReplyEmail(
  db: D1Database,
  env: Env,
  contactEmailInput: string,
  alias: AliasRow,
  user: UserRow,
): Promise<string> {
  let contactEmail = contactEmailInput;
  const includeSender = !!user.include_sender_in_reverse_alias;
  if (includeSender && contactEmail) {
    // use _ instead of . to avoid AC_FROM_MANY_DOTS SpamAssassin rule
    contactEmail = contactEmail.replaceAll("@", "_at_");
    contactEmail = contactEmail.replaceAll(".", "_");
    contactEmail = convertToId(contactEmail);
    contactEmail = sanitizeEmail(contactEmail);
    contactEmail = contactEmail.slice(0, 45);
    contactEmail = convertToAlphanumeric(contactEmail);
  }

  let replyDomain = env.EMAIL_DOMAIN;
  const aliasDomain = domainPart(alias.email);
  const slDomain = await db
    .prepare("SELECT * FROM public_domain WHERE domain = ?1")
    .bind(aliasDomain)
    .first<PublicDomainRow>();
  if (slDomain?.use_as_reverse_alias) replyDomain = aliasDomain;

  for (let i = 0; i < 1000; i++) {
    const replyEmail =
      includeSender && contactEmail
        ? `${contactEmail}_${randomString(randint(5, 10))}@${replyDomain}`
        : `${randomString(randint(20, 50))}@${replyDomain}`;
    if (await availableSlEmail(db, replyEmail)) return replyEmail;
  }
  throw new Error("Cannot generate reply email");
}

// =============================== reply phase ==============================

async function handleReplyPhase(
  message: ForwardableEmailMessage,
  env: EmailEnv,
  mailFrom: string,
  rcptTo: string,
): Promise<HandleResult> {
  const db = env.DB;

  // Reverse alias must be on EMAIL_DOMAIN or an SLDomain.
  if (!rcptTo.endsWith(env.EMAIL_DOMAIN)) {
    const slDomain = await db
      .prepare("SELECT 1 FROM public_domain WHERE domain = ?1 LIMIT 1")
      .bind(domainPart(rcptTo))
      .first();
    if (!slDomain) return rejectWith(E501);
  }

  const replyEmail = normalizeReplyEmail(rcptTo);
  const contact = await getContactByReplyEmail(db, replyEmail);
  if (!contact) return rejectWith(E502);
  const user = await getUserById(db, contact.user_id);
  if (!user || !userIsActiveRow(user)) return rejectWith(E502);

  const alias = await getAliasById(db, contact.alias_id);
  if (!alias) return rejectWith(E502);

  // Per-minute flood limit (rate_limited_reply_phase, app/email/rate_limit
  // .py) — same accept-and-drop deviation as the forward phase (no tempfail
  // on this platform). is_reply on the blocked log so the drop shows up as
  // reply activity.
  if (await rateLimitedForAliasOrMailbox(db, alias)) {
    if (await shouldIgnoreBounce(db, mailFrom)) return accept(E207);
    await createEmailLogRow(db, {
      userId: contact.user_id,
      contactId: contact.id,
      aliasId: contact.alias_id,
      isReply: 1,
      blocked: 1,
    });
    return accept(E522);
  }

  if (alias.custom_domain_id !== null) {
    const cd = await getCustomDomainById(db, alias.custom_domain_id);
    if (cd && !cd.verified) return rejectWith(E520);
  }
  if (alias.delete_on !== null) return rejectWith(E502);

  const aliasDomain = domainPart(alias.email);
  if (!(await isValidAliasAddressDomain(db, aliasDomain)))
    return rejectWith(E503);
  if (!userCanSendOrReceive(user)) return rejectWith(E504);

  // Anti-spoofing: sender must be one of the alias's mailboxes (or an
  // authorized address of one), checked raw then canonicalized, with a
  // header-From fallback when the envelope/header domains match.
  // Flask passes the raw decoded From header (display name included) to the
  // header-From fallback. get_email_domain_part then reads a bogus domain out
  // of a display-name form ("Alice <a@b.com>" -> "b.com>"), so only a bare From
  // header ("a@b.com") can satisfy the same-domain check and match a mailbox.
  const fromHeader = getHeaderValue(message.headers, "From");
  let mailbox = await getMailboxForReplyPhase(
    db,
    mailFrom,
    fromHeader ?? "",
    alias,
  );
  if (!mailbox) {
    if (alias.disable_email_spoofing_check) {
      mailbox = await getMailboxById(db, alias.mailbox_id);
    }
    if (!mailbox) {
      await handleUnknownMailbox(db, env, mailFrom, user, alias);
      // 250-class status: drop silently to avoid backscatter.
      return accept(E214);
    }
  }
  if (mailbox.flags & MAILBOX_FLAG_ADMIN_DISABLED) return accept(E207);

  const emailLog = await createEmailLogRow(db, {
    userId: contact.user_id,
    contactId: contact.id,
    aliasId: contact.alias_id,
    isReply: 1,
    mailboxId: mailbox.id,
    messageId: getHeaderValue(message.headers, "Message-ID"),
  });

  const { headerLines, body } = await readRawMessage(message);
  let hs = filterHeaders(headerLines, REPLY_KEPT_HEADERS);
  if (!getHeader(hs, "Content-Transfer-Encoding"))
    hs.push({ name: "Content-Transfer-Encoding", value: "7bit" });

  const origTo = getHeader(hs, "To");
  const origCc = getHeader(hs, "Cc");

  // From: never expose the mailbox — use the alias (with optional name).
  setHeader(hs, "From", await getAliasRecipientName(db, alias));

  try {
    if ((origTo ?? "").trim().toLowerCase() !== "undisclosed-recipients:;")
      hs = await replaceHeaderWhenReply(db, hs, alias, "To");
    hs = await replaceHeaderWhenReply(db, hs, alias, "Cc");
  } catch (e) {
    if (e instanceof NonReverseAliasInReplyPhase) {
      await deleteEmailLogRow(db, emailLog.id);
      // Flask only warns when the mailbox can_send_or_receive().
      if (mailboxCanSendOrReceive(mailbox, user))
        await sendTransactionalEmail(env, {
          to: mailbox.email,
          subject: `Email sent to ${contact.website_email} contains non reverse-alias addresses`,
          text:
            "The email you sent to your reverse alias contains addresses that are not reverse aliases " +
            "and has not been delivered to protect your real email address.",
        });
      return accept(E200);
    }
    throw e;
  }

  await replaceOriginalMessageId(db, alias, emailLog, hs);

  // Replace the reverse-alias and mailbox addresses in the body by the
  // contact's real address and the alias (email_handler.py: the reverse alias
  // is usually quoted when replying). Config-gated ENABLE_ALL_REVERSE_ALIAS_
  // REPLACEMENT (replacing every contact's reverse alias) is off upstream, so
  // it is intentionally not ported here.
  let outBody = body;
  if (user.replace_reverse_alias) {
    outBody = replaceInMimeBody(hs, body, [
      [contact.reply_email, contact.website_email],
      [mailbox.email, alias.email],
    ]);
  }

  if (!getHeader(hs, "Date"))
    setHeader(hs, "Date", formatDateRfc2822(new Date()));
  setHeader(hs, "X-SimpleLogin-Type", "Reply");
  setHeader(hs, EMAIL_LOG_HEADER, String(emailLog.id));

  const rawOut = serializeMessage(hs, outBody);
  const verpFrom = await generateVerpEmail(
    env,
    VERP_TYPE_BOUNCE_REPLY,
    emailLog.id,
    aliasDomain,
  );
  try {
    await sendRawEmail(env, verpFrom, contact.website_email, rawOut);
  } catch (e) {
    console.error(`cannot send reply from ${alias.email}:`, e);
    // Transient-send retry (deviation, see forwardToMailbox): keep the
    // EmailLog and let the 'retry-email' job re-drive the fully-built reply.
    // The mailbox is warned right away only when even scheduling fails (the
    // pre-retry behavior); otherwise the bounce-path alert fires after the
    // final retry attempt (src/jobs/handlers/retry-email.ts).
    const scheduled = await scheduleEmailRetry(env, {
      emailLogId: emailLog.id,
      phase: "reply",
      envelopeFrom: verpFrom,
      to: contact.website_email,
      raw: rawOut,
    });
    if (!scheduled) {
      await deleteEmailLogRow(db, emailLog.id);
      // Flask only warns when the mailbox can_send_or_receive().
      if (mailboxCanSendOrReceive(mailbox, user))
        await sendTransactionalEmail(env, {
          to: mailbox.email,
          subject: `Email cannot be sent to ${contact.website_email} from ${alias.email}`,
          text: `The email from your alias ${alias.email} could not be delivered to ${contact.website_email}. You can retry sending the email.`,
        });
    }
    // 250 in failure too: the send is queued for retry (or the user was
    // told) — the sender must not additionally receive an MTA bounce.
    return accept(E200);
  }

  // Notify the alias's other mailboxes about this outgoing email. Each other
  // mailbox is notified once here. Flask's per-transaction notified_mailboxes
  // dedup (across multiple reverse-alias recipients of one SMTP transaction)
  // has no analog: Cloudflare invokes the worker once per recipient, so there
  // is no shared cross-recipient state to dedup against. The loop sits after
  // the send try/catch so a notification error can never re-trigger the
  // send-failure handling (retry/EmailLog delete) of a DELIVERED reply.
  for (const mb of await aliasVerifiedMailboxes(db, alias)) {
    if (mb.email === mailbox.email) continue;
    // Each notification send is isolated: a failure must not look like the
    // reply itself could not be sent. Notification copies are best-effort
    // and deliberately NOT retried (documented scope of the retry job).
    try {
      await notifyOtherMailbox(
        db,
        env,
        alias,
        mailbox,
        hs,
        outBody,
        origTo,
        origCc,
        mb,
        aliasDomain,
      );
    } catch (e) {
      console.error(`cannot notify mailbox ${mb.email}:`, e);
    }
  }
  return accept(E200);
}

async function getMailboxForReplyPhase(
  db: D1Database,
  envelopeFrom: string,
  headerFrom: string,
  alias: AliasRow,
): Promise<MailboxRow | null> {
  const direct = await matchAliasMailbox(db, alias, envelopeFrom);
  if (direct) return direct;
  if (!headerFrom) return null;
  if (domainPart(envelopeFrom) !== domainPart(headerFrom)) return null;
  // VERP-sending providers: fall back to the header From.
  return matchAliasMailbox(db, alias, headerFrom);
}

async function matchAliasMailbox(
  db: D1Database,
  alias: AliasRow,
  email: string,
): Promise<MailboxRow | null> {
  const exact = await matchAliasMailboxExact(db, alias, email);
  if (exact) return exact;
  const canonical = canonicalizeEmail(email);
  if (canonical !== email) return matchAliasMailboxExact(db, alias, canonical);
  return null;
}

async function matchAliasMailboxExact(
  db: D1Database,
  alias: AliasRow,
  email: string,
): Promise<MailboxRow | null> {
  if (!email) return null;
  for (const mb of await aliasVerifiedMailboxes(db, alias)) {
    if (mb.email === email) return mb;
    const rows = await db
      .prepare("SELECT email FROM authorized_address WHERE mailbox_id = ?1")
      .bind(mb.id)
      .all<{ email: string }>();
    if (rows.results.some((r) => r.email === email)) return mb;
  }
  return null;
}

async function handleUnknownMailbox(
  db: D1Database,
  env: Env,
  mailFrom: string,
  user: UserRow,
  alias: AliasRow,
): Promise<void> {
  // Rate-controlled (MAX_ALERT_24H/day) so an attacker firing at a known
  // reverse alias can't flood the owner's real mailbox with alert emails.
  await sendAlertWithRateControl(
    db,
    env,
    user.id,
    ALERT_REVERSE_ALIAS_UNKNOWN_MAILBOX,
    user.email,
    `Attempt to use your alias ${alias.email} from ${mailFrom}`,
    `${mailFrom} tried to send an email using your reverse alias of ${alias.email}. ` +
      "Only your mailboxes and their authorized addresses can send emails from a reverse alias.",
  );
}

async function replaceHeaderWhenReply(
  db: D1Database,
  hs: HeaderLine[],
  alias: AliasRow,
  headerName: string,
): Promise<HeaderLine[]> {
  const value = getHeader(hs, headerName);
  if (value === null) return hs;
  const cleaned = value.replaceAll("\r", "").replaceAll("\n", "");

  const newAddrs: string[] = [];
  for (const part of splitAddressList(cleaned)) {
    // Mirror email.utils.getaddresses: flatten RFC 2822 group syntax and skip
    // members that yield no address (e.g. `undisclosed-recipients:;`) rather
    // than treating the raw token as a non-reverse-alias and dropping the mail.
    const token = stripGroupWrapping(part);
    if (!token) continue;
    const parsed = parseOneAddress(token);
    const addr = parsed ? parsed.address : token;
    if (!addr) continue;
    // no transformation when the alias itself is in the header (Reply-All)
    if (addr === alias.email) continue;
    const contact = await getContactByReplyEmail(db, addr);
    if (!contact) throw new NonReverseAliasInReplyPhase(addr);
    newAddrs.push(formatAddr(contact.name, contact.website_email));
  }

  if (newAddrs.length > 0) setHeader(hs, headerName, newAddrs.join(","));
  else deleteHeader(hs, headerName);
  return hs;
}

async function replaceOriginalMessageId(
  db: D1Database,
  alias: AliasRow,
  emailLog: EmailLogRow,
  hs: HeaderLine[],
): Promise<void> {
  const aliasDomain = domainPart(alias.email);
  const original = getHeader(hs, "Message-ID");
  let slMessageId: string;
  if (original) {
    const matching = await db
      .prepare(
        "SELECT sl_message_id FROM message_id_matching WHERE original_message_id = ?1",
      )
      .bind(original)
      .first<{ sl_message_id: string }>();
    if (matching) {
      slMessageId = matching.sl_message_id;
    } else {
      slMessageId = makeMsgId(String(emailLog.id), aliasDomain);
      try {
        await db
          .prepare(
            `INSERT INTO message_id_matching (sl_message_id, original_message_id, email_log_id)
             VALUES (?1, ?2, ?3)`,
          )
          .bind(slMessageId, original, emailLog.id)
          .run();
      } catch {
        const again = await db
          .prepare(
            "SELECT sl_message_id FROM message_id_matching WHERE original_message_id = ?1",
          )
          .bind(original)
          .first<{ sl_message_id: string }>();
        if (again) slMessageId = again.sl_message_id;
      }
    }
  } else {
    slMessageId = makeMsgId(String(emailLog.id), aliasDomain);
  }

  setHeader(hs, "Message-ID", slMessageId);
  await db
    .prepare(
      "UPDATE email_log SET sl_message_id = ?1, updated_at = ?2 WHERE id = ?3",
    )
    .bind(slMessageId, nowStr(), emailLog.id)
    .run();

  const refs = getHeader(hs, "References");
  if (refs) {
    const tokens = refs.split(/\s+/).filter(Boolean);
    const rewritten: string[] = [];
    for (const token of tokens) {
      const m = await db
        .prepare(
          "SELECT sl_message_id FROM message_id_matching WHERE original_message_id = ?1",
        )
        .bind(token)
        .first<{ sl_message_id: string }>();
      rewritten.push(m ? m.sl_message_id : token);
    }
    setHeader(hs, "References", rewritten.join(" "));
  }
}

/** get_alias_recipient_name (alias_utils.py). */
async function getAliasRecipientName(
  db: D1Database,
  alias: AliasRow,
): Promise<string> {
  if (alias.name) return formatAddr(alias.name, alias.email);
  if (alias.custom_domain_id !== null) {
    const cd = await getCustomDomainById(db, alias.custom_domain_id);
    if (cd?.name) return formatAddr(cd.name, alias.email);
  }
  return alias.email;
}

async function notifyOtherMailbox(
  db: D1Database,
  env: EmailEnv,
  alias: AliasRow,
  sendingMailbox: MailboxRow,
  hs: HeaderLine[],
  body: Uint8Array,
  origTo: string | null,
  origCc: string | null,
  otherMailbox: MailboxRow,
  aliasDomain: string,
): Promise<void> {
  const tx = await db
    .prepare("INSERT INTO transactional_email (email) VALUES (?1) RETURNING *")
    .bind(otherMailbox.email)
    .first<{ id: number }>();
  if (!tx) return;
  const notifHs = hs.map((h) => ({ ...h }));
  // The reply's X-SimpleLogin-EmailLog-ID must not survive on this copy: if
  // the notification bounces, handleInboundDsn would attribute the DSN to the
  // reply's email log and flag the (delivered) reply as bounced. Stamp the
  // transactional_email id instead — its bounce then records a Bounce row on
  // the notified mailbox, like Flask's transactional VERP envelope does.
  deleteHeader(notifHs, EMAIL_LOG_HEADER);
  setHeader(notifHs, TRANSACTIONAL_ID_HEADER, String(tx.id));
  // Prepend the notify_mailbox banner so the other mailbox owner sees which
  // mailbox sent the reply and is warned to strip the section before replying.
  const textBanner =
    "**** Don't forget to remove this section if you reply to this email ****\n" +
    `Email sent on behalf of alias ${alias.email} using mailbox ${sendingMailbox.email}`;
  const notifBody = addBodyHeader(
    notifHs,
    body,
    textBanner,
    textBanner.replaceAll("\n", "<br>"),
  );
  // From the alias so it's clear the email was sent on its behalf.
  setHeader(notifHs, "From", alias.email);
  if (origTo !== null) setHeader(notifHs, "To", origTo);
  else deleteHeader(notifHs, "To");
  if (origCc !== null) setHeader(notifHs, "Cc", origCc);
  else deleteHeader(notifHs, "Cc");
  const raw = serializeMessage(notifHs, notifBody);
  await sendRawEmail(
    env,
    await generateVerpEmail(env, VERP_TYPE_TRANSACTIONAL, tx.id, aliasDomain),
    otherMailbox.email,
    raw,
  );
}

// ========================= VERP bounce addresses ==========================

/**
 * generate_verp_email (email_utils.py). Payload/format identical to Flask
 * (json array, base32 without padding, lowercased) but the HMAC uses
 * SHA-256 instead of SHA3-224 (WebCrypto has no SHA3) and the secret falls
 * back to FLASK_SECRET when VERP_EMAIL_SECRET is not configured.
 */
export async function generateVerpEmail(
  env: Env,
  verpType: number,
  objectId: number,
  senderDomain?: string,
): Promise<string> {
  const minutes = Math.floor((Date.now() / 1000 - VERP_TIME_START) / 60);
  // Python json.dumps default separators: ", "
  const payload = `[${verpType}, ${objectId || 0}, ${minutes}]`;
  const digest = await hmacSha256(verpSecret(env), payload);
  const encodedPayload = b32encode(new TextEncoder().encode(payload));
  const encodedSignature = b32encode(digest.slice(0, 8));
  return `${VERP_PREFIX}.${encodedPayload}.${encodedSignature}@${
    senderDomain || env.EMAIL_DOMAIN
  }`.toLowerCase();
}

function verpSecret(env: Env): string {
  return (env as EmailEnv).VERP_EMAIL_SECRET ?? env.FLASK_SECRET;
}

interface VerpInfo {
  verpType: number;
  objectId: number;
}

async function getVerpInfo(
  env: Env,
  address: string,
): Promise<VerpInfo | null> {
  const at = address.indexOf("@");
  if (at === -1) return null;
  const fields = address.slice(0, at).split(".");
  if (fields.length !== 3 || fields[0] !== VERP_PREFIX) return null;
  const payloadBytes = b32decode(fields[1]);
  if (!payloadBytes) return null;
  const payloadText = new TextDecoder().decode(payloadBytes);
  const digest = await hmacSha256(verpSecret(env), payloadText);
  if (b32encode(digest.slice(0, 8)).toLowerCase() !== fields[2].toLowerCase())
    return null;
  let data: unknown;
  try {
    data = JSON.parse(payloadText);
  } catch {
    return null;
  }
  if (!Array.isArray(data) || data.length !== 3) return null;
  const [verpType, objectId, minutes] = data as [number, number, number];
  if (
    minutes >
    (Date.now() / 1000 + VERP_MESSAGE_LIFETIME - VERP_TIME_START) / 60
  )
    return null;
  return { verpType, objectId };
}

async function handleVerpInbound(
  message: ForwardableEmailMessage,
  env: EmailEnv,
  mailFrom: string,
  verp: VerpInfo,
): Promise<HandleResult> {
  const db = env.DB;
  const bounce = isBounce(mailFrom, message);

  if (verp.verpType === VERP_TYPE_TRANSACTIONAL) {
    if (bounce) {
      const tx = await db
        .prepare("SELECT email FROM transactional_email WHERE id = ?1")
        .bind(verp.objectId)
        .first<{ email: string }>();
      if (tx)
        await db
          .prepare("INSERT INTO bounce (email) VALUES (?1)")
          .bind(tx.email)
          .run();
      return accept(E205);
    }
    if (isOutOfOffice(message)) return accept(E206);
    return accept(E213); // VERPTransactional
  }

  const emailLog = await db
    .prepare("SELECT * FROM email_log WHERE id = ?1")
    .bind(verp.objectId)
    .first<EmailLogRow>();
  if (!emailLog) return rejectWith(E512);

  // NOTE (envelope deviation): production outbound mail is enveloped with the
  // From-header address, not this VERP sender, so downstream bounces / OOO
  // replies come back to the alias / reverse alias as ordinary inbound mail and
  // are handled by the forward / reply phases. Only legacy VERP-addressed mail
  // (e.g. migration) reaches here. The bounce side effects below still run for
  // that case; the OOO rewrite-and-redeliver Flask does is intentionally NOT
  // ported (it would re-enter another phase to no production benefit) — the
  // message is dropped with E206 as before.
  if (verp.verpType === VERP_TYPE_BOUNCE_FORWARD) {
    if (bounce) {
      // handle_bounce: reject bounces for a soft-deleted user untouched (E510).
      const elUser = await getUserById(db, emailLog.user_id);
      if (elUser && !userIsActiveRow(elUser)) return rejectWith(E510);
      return handleBounceForwardPhase(db, env, emailLog);
    }
    if (isOutOfOffice(message)) return accept(E206);
    return accept(E213); // VERPForward
  }
  if (verp.verpType === VERP_TYPE_BOUNCE_REPLY) {
    if (bounce) {
      const elUser = await getUserById(db, emailLog.user_id);
      if (elUser && !userIsActiveRow(elUser)) return rejectWith(E510);
      return handleBounceReplyPhase(db, env, emailLog);
    }
    if (isOutOfOffice(message)) return accept(E206);
    return accept(E213); // VERPReply
  }
  return accept(E213);
}

/**
 * handle_bounce_forward_phase (email_handler.py): a forwarded email bounced at
 * the mailbox. Records the Bounce row + email_log.bounced/bounced_mailbox_id,
 * then notifies the user (Notification row + rate-controlled ALERT_BOUNCE_EMAIL,
 * max 10/day). RefusedEmail (S3) storage and the ALIAS_AUTOMATIC_DISABLE-gated
 * auto-disable are the documented skips (the latter is off by default upstream).
 * Exported for the 'retry-email' job: exhausting the retry backoff runs the
 * same side effects a Postfix queue-lifetime bounce triggers through VERP.
 */
export async function handleBounceForwardPhase(
  db: D1Database,
  env: Env,
  emailLog: EmailLogRow,
): Promise<HandleResult> {
  const alias = emailLog.alias_id
    ? await getAliasById(db, emailLog.alias_id)
    : null;
  // Flask falls back to the alias's primary mailbox when the log has none.
  let mailbox = emailLog.mailbox_id
    ? await getMailboxById(db, emailLog.mailbox_id)
    : null;
  if (!mailbox && alias) mailbox = await getMailboxById(db, alias.mailbox_id);

  await db
    .prepare(
      "UPDATE email_log SET bounced = 1, bounced_mailbox_id = ?1, updated_at = ?2 WHERE id = ?3",
    )
    .bind(mailbox?.id ?? null, nowStr(), emailLog.id)
    .run();
  if (mailbox)
    await db
      .prepare("INSERT INTO bounce (email) VALUES (?1)")
      .bind(mailbox.email)
      .run();

  const contact = await getContactById(db, emailLog.contact_id);
  if (alias && contact && mailbox) {
    const user = await getUserById(db, alias.user_id);
    if (user) {
      const title = `Email from ${contact.website_email} to ${alias.email} cannot be delivered to ${mailbox.email}`;
      await db
        .prepare(
          "INSERT INTO notification (user_id, title, message) VALUES (?1, ?2, ?3)",
        )
        .bind(user.id, title, title)
        .run();
      await sendAlertWithRateControl(
        db,
        env,
        user.id,
        ALERT_BOUNCE_EMAIL,
        user.email,
        `An email sent to ${alias.email} cannot be delivered to your mailbox`,
        `An email sent to ${alias.email} from ${contact.website_email} cannot be delivered to your mailbox ${mailbox.email}. You can disable the alias or block the sender from your dashboard.`,
        10,
        1,
      );
    }
  }
  return accept(E211);
}

/**
 * handle_bounce_reply_phase (email_handler.py): a reply sent from an alias
 * bounced at the contact. Records a Bounce row for the contact's real address +
 * email_log.bounced/bounced_mailbox_id, then notifies the user (Notification row
 * + ALERT_BOUNCE_EMAIL_REPLY_PHASE to the sending mailbox). RefusedEmail (S3) is
 * the documented skip. Exported for the 'retry-email' job (see the forward
 * phase handler above).
 */
export async function handleBounceReplyPhase(
  db: D1Database,
  env: Env,
  emailLog: EmailLogRow,
): Promise<HandleResult> {
  const contact = await getContactById(db, emailLog.contact_id);
  const alias = emailLog.alias_id
    ? await getAliasById(db, emailLog.alias_id)
    : null;
  let mailbox = emailLog.mailbox_id
    ? await getMailboxById(db, emailLog.mailbox_id)
    : null;
  if (!mailbox && alias) mailbox = await getMailboxById(db, alias.mailbox_id);

  if (contact)
    await db
      .prepare("INSERT INTO bounce (email) VALUES (?1)")
      .bind(sanitizeEmail(contact.website_email, true))
      .run();
  await db
    .prepare(
      "UPDATE email_log SET bounced = 1, bounced_mailbox_id = ?1, updated_at = ?2 WHERE id = ?3",
    )
    .bind(mailbox?.id ?? null, nowStr(), emailLog.id)
    .run();

  if (alias && contact && mailbox) {
    const user = await getUserById(db, alias.user_id);
    if (user) {
      const title = `Email cannot be sent to ${contact.website_email} from your alias ${alias.email}`;
      await db
        .prepare(
          "INSERT INTO notification (user_id, title, message) VALUES (?1, ?2, ?3)",
        )
        .bind(user.id, title, title)
        .run();
      await sendAlertWithRateControl(
        db,
        env,
        user.id,
        ALERT_BOUNCE_EMAIL_REPLY_PHASE,
        mailbox.email,
        title,
        `The email you sent from your alias ${alias.email} to ${contact.website_email} could not be delivered.`,
      );
    }
  }
  return accept(E212);
}

function isBounce(mailFrom: string, message: ForwardableEmailMessage): boolean {
  const contentType = (
    getHeaderValue(message.headers, "Content-Type") ?? ""
  ).toLowerCase();
  return isNullSender(mailFrom) && contentType.startsWith("multipart/report");
}

function isOutOfOffice(message: ForwardableEmailMessage): boolean {
  const auto = (
    getHeaderValue(message.headers, "Auto-Submitted") ?? ""
  ).toLowerCase();
  return auto.startsWith("auto-replied") || auto.startsWith("auto-generated");
}

// ================= inbound DSN detection (envelope model) =================
// Deviation with no direct Flask equivalent (file-top block, HANDOVER §0):
// Flask receives bounces on signed VERP addresses, but the send_email binding
// requires envelope == From, so downstream DSNs come back to the reverse
// alias (forward phase) or the alias (reply phase) as ordinary inbound mail
// with a null or mailer-daemon sender. Without this, a forward-phase bounce
// is black-holed by the null-sender E206 drop (mail loss). Detection is
// deliberately broader than Flask's is_bounce() (envelope=="<>" plus
// Content-Type multipart/report): real MTAs also bounce from mailer-daemon@
// with a non-empty envelope, and the report-type / message/delivery-status
// checks keep plain multipart/report mail (e.g. arf feedback) out.
// Attribution reads the X-SimpleLogin-EmailLog-ID header this worker stamps
// on every outbound forward/reply out of the DSN's embedded original message
// (message/rfc822 or text/rfc822-headers part), falling back to a Message-ID
// lookup. Both are accepted only when the resolved email log's outbound
// sender (contact.reply_email for forwards, alias.email for replies) is the
// DSN's recipient, so a forged report cannot flag other users' mail as
// bounced. Unattributable DSNs fall through to the pre-existing behavior.

interface DsnMimePart {
  type: string;
  headers: HeaderLine[];
  body: Uint8Array;
}

interface DsnOutcome {
  /** Set when the message was recognized AND attributed (or E510-rejected). */
  result: HandleResult | null;
  /** Set when message.raw was consumed: a replayable copy for fall-through. */
  message: ForwardableEmailMessage | null;
}

const DSN_NO_OUTCOME: DsnOutcome = { result: null, message: null };

/**
 * Detect and attribute an inbound DSN. Returns
 * - `{result}` when the message is a DSN for something this worker sent (the
 *   Flask handle_bounce side effects have run),
 * - `{message}` when the raw stream was consumed but the mail must keep
 *   flowing through the normal phases (not a DSN, or unattributable),
 * - DSN_NO_OUTCOME when the message was not touched at all.
 */
async function handleInboundDsn(
  message: ForwardableEmailMessage,
  env: EmailEnv,
  mailFrom: string,
  rcptTo: string,
  rcptIsReverseAlias: boolean,
): Promise<DsnOutcome> {
  const db = env.DB;
  if (!isDsnCandidateSender(mailFrom)) return DSN_NO_OUTCOME;
  // Only mail addressed to a reverse alias or an existing alias can bounce
  // something this worker sent (envelope == From on all outbound phase mail).
  // Everything else keeps its raw stream untouched. Auto-creatable catch-all
  // aliases are deliberately NOT considered: outbound mail is always sent
  // from an already-existing alias / reverse alias.
  if (!rcptIsReverseAlias && !(await getAliasByEmail(db, rcptTo)))
    return DSN_NO_OUTCOME;

  const reportByHeader = contentTypeIsDeliveryReport(
    getHeaderValue(message.headers, "Content-Type"),
  );

  // Reading the raw consumes the single-use stream: every return from here
  // on hands back a replayed copy so fall-through phases can re-read it.
  const bytes = await readAll(message.raw);
  const replayed = replayableMessage(message, bytes);
  const { headerText, body } = splitRawMessage(bytes);
  const parts: DsnMimePart[] = [];
  collectDsnMimeParts(parseHeaderBlock(headerText), body, parts, 0);

  const isDsn =
    reportByHeader || parts.some((p) => p.type === "message/delivery-status");
  if (!isDsn) return { result: null, message: replayed };

  const blocks = dsnEmbeddedHeaderBlocks(parts);

  // Bounced notify-other-mailbox copy: only a Bounce row on the notified
  // address, then E205 — handle_transactional_bounce (email_handler.py)
  // parity (E205 even when the transactional row no longer exists).
  for (const hs of blocks) {
    const txValue = getHeader(hs, TRANSACTIONAL_ID_HEADER);
    if (!txValue) continue;
    const txId = Number.parseInt(txValue, 10);
    if (!Number.isInteger(txId) || txId <= 0) continue;
    const tx = await db
      .prepare("SELECT email FROM transactional_email WHERE id = ?1")
      .bind(txId)
      .first<{ email: string }>();
    if (tx)
      await db
        .prepare("INSERT INTO bounce (email) VALUES (?1)")
        .bind(tx.email)
        .run();
    return { result: accept(E205), message: replayed };
  }

  const emailLog = await resolveDsnEmailLog(db, blocks, rcptTo);
  // Unattributable: fall through to the pre-existing behavior (E206 drop on
  // a reverse alias, ordinary forward-phase delivery of the report on an
  // alias) — see the call site in dispatch().
  if (!emailLog) return { result: null, message: replayed };

  // handle_bounce: bounces for a soft-deleted user are rejected untouched.
  const elUser = await getUserById(db, emailLog.user_id);
  if (elUser && !userIsActiveRow(elUser))
    return { result: rejectWith(E510), message: replayed };

  const result = emailLog.is_reply
    ? await handleBounceReplyPhase(db, env, emailLog)
    : await handleBounceForwardPhase(db, env, emailLog);
  return { result, message: replayed };
}

/** DSN candidate sender: null/empty envelope or a mailer-daemon mailbox. */
function isDsnCandidateSender(mailFrom: string): boolean {
  if (isNullSender(mailFrom)) return true;
  return localPart(mailFrom).toLowerCase() === "mailer-daemon";
}

/** Content-Type is multipart/report with report-type=delivery-status (RFC 3464). */
function contentTypeIsDeliveryReport(value: string | null): boolean {
  if (!value) return false;
  if (parseContentType(value).type !== "multipart/report") return false;
  return /;\s*report-type\s*=\s*"?delivery-status"?/i.test(value);
}

/** Transfer-decode a MIME part body per its Content-Transfer-Encoding. */
function transferDecodeBody(
  headers: HeaderLine[],
  body: Uint8Array,
): Uint8Array {
  const cte = normalizeCte(getHeader(headers, "Content-Transfer-Encoding"));
  if (cte === "quoted-printable") return qpDecode(body);
  if (cte === "base64") return base64Decode(body);
  return body;
}

/**
 * Flatten the MIME tree of a message into a part list (the message itself
 * first, then each nested part in document order). message/rfc822 parts are
 * recursed into so the embedded original message contributes its own header
 * block. Parsing is defensive: malformed structures just yield fewer parts.
 */
function collectDsnMimeParts(
  headers: HeaderLine[],
  body: Uint8Array,
  out: DsnMimePart[],
  depth: number,
): void {
  const { type, boundary } = parseContentType(
    getHeader(headers, "Content-Type"),
  );
  out.push({ type, headers, body });
  if (depth >= 5) return; // defensive: no legitimate DSN nests deeper
  if (type.startsWith("multipart/")) {
    if (!boundary) return;
    const marker = new TextEncoder().encode(`--${boundary}`);
    const delims = findBoundaryDelimiters(body, marker);
    for (let k = 0; k < delims.length; k++) {
      const d = delims[k];
      if (d.closing) break;
      const end = delims[k + 1] ? delims[k + 1].start : body.length;
      const partBytes = body.subarray(d.lineEnd, end);
      const { headerText, bodyStart } = splitRawMessage(partBytes);
      collectDsnMimeParts(
        parseHeaderBlock(headerText),
        partBytes.subarray(bodyStart),
        out,
        depth + 1,
      );
    }
    return;
  }
  if (type === "message/rfc822") {
    const decoded = transferDecodeBody(headers, body);
    const { headerText, bodyStart } = splitRawMessage(decoded);
    collectDsnMimeParts(
      parseHeaderBlock(headerText),
      decoded.subarray(bodyStart),
      out,
      depth + 1,
    );
  }
}

/**
 * Candidate header blocks of the original outbound message embedded in a
 * DSN: every nested part's own header block (message/rfc822 originals
 * surface here through collectDsnMimeParts) plus parsed text/rfc822-headers
 * bodies. The DSN's own top-level headers (parts[0]) are excluded — only
 * material a real report embeds can attribute a bounce.
 */
function dsnEmbeddedHeaderBlocks(parts: DsnMimePart[]): HeaderLine[][] {
  const blocks: HeaderLine[][] = [];
  for (let i = 1; i < parts.length; i++) {
    blocks.push(parts[i].headers);
    if (parts[i].type === "text/rfc822-headers") {
      const decoded = transferDecodeBody(parts[i].headers, parts[i].body);
      blocks.push(parseHeaderBlock(new TextDecoder().decode(decoded)));
    }
  }
  return blocks;
}

async function resolveDsnEmailLog(
  db: D1Database,
  blocks: HeaderLine[][],
  rcptTo: string,
): Promise<EmailLogRow | null> {
  // Primary: the X-SimpleLogin-EmailLog-ID stamped on every outbound send
  // (both message.forward X-headers and the rebuild/reply paths carry it).
  for (const hs of blocks) {
    const value = getHeader(hs, EMAIL_LOG_HEADER);
    if (!value) continue;
    const id = Number.parseInt(value, 10);
    if (!Number.isInteger(id) || id <= 0) continue;
    const el = await db
      .prepare("SELECT * FROM email_log WHERE id = ?1")
      .bind(id)
      .first<EmailLogRow>();
    if (el && (await dsnEmailLogMatchesRecipient(db, el, rcptTo))) return el;
  }
  // Fallback: the outbound Message-ID — the forward phase keeps the sender's
  // original id (stored as email_log.message_id, truncated to 250 chars on
  // insert), the reply phase rewrites it to the SL id (email_log
  // .sl_message_id). Scoped to logs whose outbound sender is this DSN's
  // recipient; the latest match wins (an alias with several mailboxes writes
  // one log per mailbox for the same Message-ID).
  for (const hs of blocks) {
    const mid = getHeader(hs, "Message-ID");
    if (!mid) continue;
    const el = await db
      .prepare(
        `SELECT el.* FROM email_log el
         LEFT JOIN contact c ON el.contact_id = c.id
         LEFT JOIN alias a ON el.alias_id = a.id
         WHERE (el.sl_message_id = ?1 OR el.message_id = ?2)
           AND ((el.is_reply = 0 AND c.reply_email = ?3)
             OR (el.is_reply = 1 AND a.email = ?3))
         ORDER BY el.id DESC LIMIT 1`,
      )
      .bind(mid, mid.slice(0, 250), rcptTo)
      .first<EmailLogRow>();
    if (el) return el;
  }
  return null;
}

/** The email log's outbound sender must be the DSN's recipient: the forward
 *  phase sends From the contact's reverse alias, the reply phase From the
 *  alias, and the envelope always equals From — so a real DSN comes back to
 *  exactly that address. */
async function dsnEmailLogMatchesRecipient(
  db: D1Database,
  emailLog: EmailLogRow,
  rcptTo: string,
): Promise<boolean> {
  if (emailLog.is_reply) {
    const alias = emailLog.alias_id
      ? await getAliasById(db, emailLog.alias_id)
      : null;
    return alias?.email === rcptTo;
  }
  const contact = await getContactById(db, emailLog.contact_id);
  return contact?.reply_email === rcptTo;
}

/** A ForwardableEmailMessage clone whose raw stream replays `bytes` (each
 *  access yields a fresh stream); everything else delegates to the original. */
function replayableMessage(
  message: ForwardableEmailMessage,
  bytes: Uint8Array,
): ForwardableEmailMessage {
  return {
    from: message.from,
    to: message.to,
    headers: message.headers,
    rawSize: bytes.length,
    get raw(): ReadableStream<Uint8Array> {
      return new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bytes);
          controller.close();
        },
      });
    },
    setReject: (reason: string) => message.setReject(reason),
    forward: (rcptTo: string, headers?: Headers) =>
      message.forward(rcptTo, headers),
    reply: (m: EmailMessage) => message.reply(m),
  };
}

// =============================== DB helpers ===============================

function getAliasByEmail(
  db: D1Database,
  email: string,
): Promise<AliasRow | null> {
  return db
    .prepare("SELECT * FROM alias WHERE email = ?1")
    .bind(email)
    .first<AliasRow>();
}

function getContactByReplyEmail(
  db: D1Database,
  replyEmail: string,
): Promise<ContactRow | null> {
  return db
    .prepare("SELECT * FROM contact WHERE reply_email = ?1 LIMIT 1")
    .bind(replyEmail)
    .first<ContactRow>();
}

function getContactById(
  db: D1Database,
  id: number,
): Promise<ContactRow | null> {
  return db
    .prepare("SELECT * FROM contact WHERE id = ?1 LIMIT 1")
    .bind(id)
    .first<ContactRow>();
}

function getContactByAliasAndEmail(
  db: D1Database,
  aliasId: number,
  websiteEmail: string,
): Promise<ContactRow | null> {
  return db
    .prepare(
      "SELECT * FROM contact WHERE alias_id = ?1 AND website_email = ?2 LIMIT 1",
    )
    .bind(aliasId, websiteEmail)
    .first<ContactRow>();
}

async function shouldIgnoreBounce(
  db: D1Database,
  mailFrom: string,
): Promise<boolean> {
  const row = await db
    .prepare("SELECT 1 FROM ignore_bounce_sender WHERE mail_from = ?1 LIMIT 1")
    .bind(mailFrom)
    .first();
  return row !== null;
}

// ------------- per-minute flood limit (app/email/rate_limit.py) -----------
// The check logic (1-minute window, strict `>` comparison, per-alias and
// per-primary-mailbox counters) is a faithful port. Two documented deviations:
// upstream `rate_limited()` is short-circuited off ("todo: re-enable rate
// limiting") while this port enables it, and the E522 SMTP reject is replaced
// by accept-and-drop with a blocked EmailLog at the call sites.

/** rate_limited_for_alias: nb of EmailLog on the alias in the last minute. */
async function rateLimitedForAlias(
  db: D1Database,
  alias: AliasRow,
): Promise<boolean> {
  const minTime = toStr(addMinutes(new Date(), -1));
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS n FROM email_log el
       JOIN contact c ON el.contact_id = c.id
       WHERE c.alias_id = ?1 AND el.created_at > ?2`,
    )
    .bind(alias.id, minTime)
    .first<{ n: number }>();
  return (row?.n ?? 0) > MAX_ACTIVITY_DURING_MINUTE_PER_ALIAS;
}

/** rate_limited_for_mailbox: nb of EmailLog in the last minute across all
 *  aliases sharing this alias's primary mailbox. */
async function rateLimitedForMailbox(
  db: D1Database,
  alias: AliasRow,
): Promise<boolean> {
  const minTime = toStr(addMinutes(new Date(), -1));
  const row = await db
    .prepare(
      `SELECT COUNT(*) AS n FROM email_log el
       JOIN contact c ON el.contact_id = c.id
       JOIN alias a ON c.alias_id = a.id
       WHERE a.mailbox_id = ?1 AND el.created_at > ?2`,
    )
    .bind(alias.mailbox_id, minTime)
    .first<{ n: number }>();
  return (row?.n ?? 0) > MAX_ACTIVITY_DURING_MINUTE_PER_MAILBOX;
}

/**
 * rate_limited_forward_phase / rate_limited_reply_phase both reduce to this
 * once the alias is resolved. (For a just-auto-created alias Flask runs only
 * the mailbox check; the alias check is vacuously false there — a fresh alias
 * has no EmailLog — so applying both is equivalent.)
 */
async function rateLimitedForAliasOrMailbox(
  db: D1Database,
  alias: AliasRow,
): Promise<boolean> {
  if (await rateLimitedForAlias(db, alias)) return true;
  return rateLimitedForMailbox(db, alias);
}

async function isValidAliasAddressDomain(
  db: D1Database,
  domain: string,
): Promise<boolean> {
  const sl = await db
    .prepare("SELECT 1 FROM public_domain WHERE domain = ?1 LIMIT 1")
    .bind(domain)
    .first();
  if (sl) return true;
  const cd = await db
    .prepare(
      "SELECT 1 FROM custom_domain WHERE domain = ?1 AND verified = 1 LIMIT 1",
    )
    .bind(domain)
    .first();
  return cd !== null;
}

/** Alias.mailboxes property: primary + extra, verified only, email-sorted. */
async function aliasVerifiedMailboxes(
  db: D1Database,
  alias: AliasRow,
): Promise<MailboxRow[]> {
  const primary = await getMailboxById(db, alias.mailbox_id);
  const extra = await db
    .prepare(
      `SELECT m.* FROM mailbox m
       JOIN alias_mailbox am ON am.mailbox_id = m.id
       WHERE am.alias_id = ?1 ORDER BY am.id`,
    )
    .bind(alias.id)
    .all<MailboxRow>();
  const list: MailboxRow[] = [];
  if (primary) list.push(primary);
  for (const m of extra.results)
    if (!list.some((x) => x.id === m.id)) list.push(m);
  return list
    .filter((m) => m.verified)
    .sort((a, b) => (a.email < b.email ? -1 : a.email > b.email ? 1 : 0));
}

/** Alias.authorized_addresses(): mailbox emails + their authorized addresses. */
async function aliasAuthorizedAddresses(
  db: D1Database,
  alias: AliasRow,
): Promise<string[]> {
  const mailboxes = await aliasVerifiedMailboxes(db, alias);
  const ret = mailboxes.map((m) => m.email);
  for (const mb of mailboxes) {
    const rows = await db
      .prepare(
        "SELECT email FROM authorized_address WHERE mailbox_id = ?1 ORDER BY id",
      )
      .bind(mb.id)
      .all<{ email: string }>();
    for (const r of rows.results) ret.push(r.email);
  }
  return ret;
}

interface EmailLogFields {
  userId: number;
  contactId: number;
  aliasId: number;
  mailboxId?: number | null;
  isReply?: number;
  blocked?: number;
  messageId?: string | null;
}

/** EmailLog.create: insert + update alias.last_email_log_id. */
async function createEmailLogRow(
  db: D1Database,
  fields: EmailLogFields,
): Promise<EmailLogRow> {
  const messageId = fields.messageId ? fields.messageId.slice(0, 250) : null;
  const row = await db
    .prepare(
      `INSERT INTO email_log (user_id, contact_id, alias_id, is_reply, blocked,
         mailbox_id, message_id)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) RETURNING *`,
    )
    .bind(
      fields.userId,
      fields.contactId,
      fields.aliasId,
      fields.isReply ?? 0,
      fields.blocked ?? 0,
      fields.mailboxId ?? null,
      messageId,
    )
    .first<EmailLogRow>();
  if (!row) throw new Error("email_log insert returned no row");
  await db
    .prepare(
      "UPDATE alias SET last_email_log_id = ?1, updated_at = ?2 WHERE id = ?3",
    )
    .bind(row.id, nowStr(), fields.aliasId)
    .run();
  return row;
}

async function deleteEmailLogRow(db: D1Database, id: number): Promise<void> {
  await db.prepare("DELETE FROM email_log WHERE id = ?1").bind(id).run();
}

/** send_email_at_most_times: sent_alert-deduped transactional alert (once ever). */
async function sendAlertAtMostOnce(
  db: D1Database,
  env: Env,
  userId: number,
  alertType: string,
  toEmail: string,
  subject: string,
  text: string,
): Promise<void> {
  const row = await db
    .prepare(
      "SELECT COUNT(*) AS n FROM sent_alert WHERE alert_type = ?1 AND to_email = ?2",
    )
    .bind(alertType, toEmail)
    .first<{ n: number }>();
  if ((row?.n ?? 0) >= 1) return;
  await db
    .prepare(
      "INSERT INTO sent_alert (user_id, to_email, alert_type) VALUES (?1, ?2, ?3)",
    )
    .bind(userId, toEmail, alertType)
    .run();
  await sendTransactionalEmail(env, { to: toEmail, subject, text });
}

/**
 * send_email_with_rate_control (email_utils.py): send at most `maxNbAlert`
 * alerts of `alertType` to `toEmail` over the last `nbDay` days, recording a
 * sent_alert row for each one sent. Unlike sendAlertAtMostOnce this uses a
 * rolling time window, so a recurring misconfiguration re-notifies the user.
 */
async function sendAlertWithRateControl(
  db: D1Database,
  env: Env,
  userId: number,
  alertType: string,
  toEmail: string,
  subject: string,
  text: string,
  maxNbAlert = MAX_ALERT_24H,
  nbDay = 1,
): Promise<void> {
  const minDt = toStr(addDays(new Date(), -nbDay));
  const row = await db
    .prepare(
      "SELECT COUNT(*) AS n FROM sent_alert WHERE alert_type = ?1 AND to_email = ?2 AND created_at > ?3",
    )
    .bind(alertType, toEmail, minDt)
    .first<{ n: number }>();
  if ((row?.n ?? 0) >= maxNbAlert) return;
  await db
    .prepare(
      "INSERT INTO sent_alert (user_id, to_email, alert_type) VALUES (?1, ?2, ?3)",
    )
    .bind(userId, toEmail, alertType)
    .run();
  await sendTransactionalEmail(env, { to: toEmail, subject, text });
}

/** User.is_active() (models.py); exported for the 'retry-email' job. */
export function userIsActiveRow(
  user: UserRow,
  now: Date = new Date(),
): boolean {
  if (user.delete_on === null) return true;
  return toDate(user.delete_on).getTime() < now.getTime();
}

function userCanSendOrReceive(user: UserRow): boolean {
  if (user.disabled) return false;
  if (user.delete_on !== null) return false;
  return true;
}

/** Mailbox.can_send_or_receive (models.py): admin-disabled, disabled, or the
 *  owning user unable to send/receive all suppress mail to the mailbox. */
function mailboxCanSendOrReceive(mailbox: MailboxRow, user: UserRow): boolean {
  if (mailbox.flags & MAILBOX_FLAG_ADMIN_DISABLED) return false;
  if (mailbox.disabled) return false;
  return userCanSendOrReceive(user);
}

// ==================== transient-send retry (deviation) ====================
// No Flask equivalent: Flask hands a transient SMTP failure to the Postfix
// queue, which retries on its own backoff for days and emits a bounce DSN
// when it gives up. This platform has no MTA queue, and setReject is a
// PERMANENT failure at the sender's MTA — mail that would have gone through
// a minute later would bounce. So a binding failure on a fully-built
// forward/reply stashes the message in KV and enqueues the 'retry-email' job
// (src/jobs/handlers/retry-email.ts), which re-sends through sendRawEmail
// and manages its own backoff/attempt bookkeeping with the constants below.
// Scope: binding/transport failures only — the scheduling call sites wrap
// nothing but sendRawEmail, after every policy check has passed and the
// outbound message is fully built; policy rejects are unaffected.

export const RETRY_EMAIL_JOB_NAME = "retry-email";
/** Max send attempts by the job (the failed inline delivery not counted). */
export const RETRY_EMAIL_MAX_ATTEMPTS = 5;
/**
 * Minutes before attempt N (1-indexed): 5m/30m/2h/12h/24h — Postfix-queue
 * flavored growth, ~38.5h from the initial failure to the final attempt.
 */
export const RETRY_EMAIL_BACKOFF_MINS = [5, 30, 120, 720, 1440];
const RETRY_KV_PREFIX = "retry:";
/** Stash lifetime: comfortably outlives the last scheduled attempt. */
const RETRY_KV_TTL_SECS = 7 * 86400;

export interface RetryEmailPayload {
  /** KV key ("retry:<uuid>") holding the built raw outbound message. */
  kv_key: string;
  /** EmailLog recording the delivery this retry belongs to. */
  email_log_id: number;
  /** Metadata only — the handler trusts email_log.is_reply, not this. */
  phase: "forward" | "reply";
  /** 1-based number of the attempt this job row will perform. */
  attempt: number;
  /** Flask-parity VERP envelope (sendRawEmail re-derives the binding From). */
  envelope_from: string;
  to: string;
}

/** INSERT the 'retry-email' job row, due `delayMins` from now. */
export async function enqueueRetryEmailJob(
  db: D1Database,
  payload: RetryEmailPayload,
  delayMins: number,
): Promise<void> {
  await db
    .prepare("INSERT INTO job (name, payload, run_at) VALUES (?1, ?2, ?3)")
    .bind(
      RETRY_EMAIL_JOB_NAME,
      JSON.stringify(payload),
      toStr(addMinutes(new Date(), delayMins)),
    )
    .run();
}

/**
 * Stash the built message in KV and enqueue the first retry attempt. Returns
 * false (after logging) when the stash/enqueue itself failed, so the call
 * site can fall back to the pre-retry failure behavior.
 */
async function scheduleEmailRetry(
  env: Env,
  args: {
    emailLogId: number;
    phase: "forward" | "reply";
    envelopeFrom: string;
    to: string;
    raw: Uint8Array;
  },
): Promise<boolean> {
  try {
    const kvKey = `${RETRY_KV_PREFIX}${crypto.randomUUID()}`;
    await env.KV.put(kvKey, args.raw, { expirationTtl: RETRY_KV_TTL_SECS });
    await enqueueRetryEmailJob(
      env.DB,
      {
        kv_key: kvKey,
        email_log_id: args.emailLogId,
        phase: args.phase,
        attempt: 1,
        envelope_from: args.envelopeFrom,
        to: args.to,
      },
      RETRY_EMAIL_BACKOFF_MINS[0],
    );
    return true;
  } catch (e) {
    console.error(`cannot schedule email retry to ${args.to}:`, e);
    return false;
  }
}

// ========================= outbound raw email send ========================

/** Exported for the 'retry-email' job, which replays a KV-stashed message
 *  through this same path (re-signing and re-capturing like the first try). */
export async function sendRawEmail(
  env: Env,
  envelopeFrom: string,
  to: string,
  raw: Uint8Array,
): Promise<void> {
  // Cloudflare's send_email binding rejects messages whose envelope sender
  // differs from the MIME From header (verified in production: the aligned
  // transactional mailer delivers, VERP-enveloped sends bounce with E407).
  // So outbound binding sends go out with the From-header address as the
  // envelope; the Flask-format VERP envelope is kept for the unbound/local
  // mode and for parsing inbound bounces addressed to old VERP addresses.
  // Bounces consequently come back to the alias/reverse-alias as regular
  // inbound mail instead of the VERP mailbox.
  const bindingFrom = extractFromHeaderAddress(raw) ?? envelopeFrom;

  // Sign with DKIM before capturing/sending so both the outboundEmails seam
  // and the binding see the signed message. Only sign mail whose From-header
  // domain is one of ours (env.EMAIL_DOMAIN / ALIAS_DOMAINS); relayed foreign
  // domains must not carry our signature.
  raw = await dkimSignOutbound(env, bindingFrom, raw);

  // Capture for tests only: vitest.config.ts provides the TEST_MIGRATIONS
  // binding to the test worker, so its presence is the "running under vitest"
  // signal. In production nothing is captured — retaining up to 200 full raw
  // messages would pin users' mail in isolate memory.
  if ((env as { TEST_MIGRATIONS?: unknown }).TEST_MIGRATIONS !== undefined) {
    outboundEmails.push({
      envelopeFrom,
      bindingFrom,
      to,
      raw: new TextDecoder().decode(raw),
    });
    if (outboundEmails.length > MAX_OUTBOUND_CAPTURED) outboundEmails.shift();
  }

  if (!env.SEND_EMAIL) {
    console.log(`[email] (unbound) MAIL FROM=${envelopeFrom} RCPT TO=${to}`);
    return;
  }
  const { EmailMessage } = await import("cloudflare:email");
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(raw);
      controller.close();
    },
  });
  await env.SEND_EMAIL.send(new EmailMessage(bindingFrom, to, stream));
}

/** Address part of the From header of a serialized message, if parseable. */
function extractFromHeaderAddress(raw: Uint8Array): string | null {
  const { headerText } = splitRawMessage(raw);
  const from = getHeader(parseHeaderBlock(headerText), "From");
  if (!from) return null;
  return parseOneAddress(from)?.address ?? null;
}

// ======================== raw message / header tools ======================

export interface HeaderLine {
  name: string;
  value: string;
}

const REPLY_KEPT_HEADERS = [
  "from",
  "to",
  "cc",
  "subject",
  "date",
  "message-id",
  "references",
  "in-reply-to",
  "x-sl-queue-id",
  "mime-version",
  "content-type",
  "content-disposition",
  "content-transfer-encoding",
];

async function readRawMessage(
  message: ForwardableEmailMessage,
): Promise<{ headerLines: HeaderLine[]; body: Uint8Array }> {
  const bytes = await readAll(message.raw);
  const { headerText, body } = splitRawMessage(bytes);
  return { headerLines: parseHeaderBlock(headerText), body };
}

async function readAll(
  stream: ReadableStream<Uint8Array>,
): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function splitRawMessage(bytes: Uint8Array): {
  headerText: string;
  body: Uint8Array;
  bodyStart: number;
} {
  let headerEnd = bytes.length;
  let bodyStart = bytes.length;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0x0a) continue;
    if (bytes[i + 1] === 0x0a) {
      headerEnd = i + 1;
      bodyStart = i + 2;
      break;
    }
    if (bytes[i + 1] === 0x0d && bytes[i + 2] === 0x0a) {
      headerEnd = i + 1;
      bodyStart = i + 3;
      break;
    }
  }
  return {
    headerText: new TextDecoder().decode(bytes.slice(0, headerEnd)),
    body: bytes.slice(bodyStart),
    bodyStart,
  };
}

function parseHeaderBlock(text: string): HeaderLine[] {
  const out: HeaderLine[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line) continue;
    if ((line.startsWith(" ") || line.startsWith("\t")) && out.length > 0) {
      out[out.length - 1].value += ` ${line.trim()}`;
      continue;
    }
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    out.push({
      name: line.slice(0, colon).trim(),
      value: line.slice(colon + 1).trim(),
    });
  }
  return out;
}

function filterHeaders(hs: HeaderLine[], kept: string[]): HeaderLine[] {
  return hs
    .filter((h) => kept.includes(h.name.toLowerCase()))
    .map((h) => ({ ...h }));
}

function getHeader(hs: HeaderLine[], name: string): string | null {
  const lower = name.toLowerCase();
  const found = hs.find((h) => h.name.toLowerCase() === lower);
  return found ? found.value : null;
}

/** add_or_replace_header: delete existing then append at the end. */
function setHeader(hs: HeaderLine[], name: string, value: string): void {
  deleteHeader(hs, name);
  hs.push({ name, value });
}

function deleteHeader(hs: HeaderLine[], name: string): void {
  const lower = name.toLowerCase();
  for (let i = hs.length - 1; i >= 0; i--) {
    if (hs[i].name.toLowerCase() === lower) hs.splice(i, 1);
  }
}

function serializeMessage(hs: HeaderLine[], body: Uint8Array): Uint8Array {
  const head = `${hs.map((h) => `${h.name}: ${h.value}`).join("\r\n")}\r\n\r\n`;
  const headBytes = new TextEncoder().encode(head);
  const out = new Uint8Array(headBytes.length + body.length);
  out.set(headBytes, 0);
  out.set(body, headBytes.length);
  return out;
}

function getHeaderValue(headers: Headers, name: string): string | null {
  const value = headers.get(name);
  if (value === null) return null;
  // sanitize_header: strip, \n -> " ", drop \r
  return value.trim().replaceAll("\n", " ").replaceAll("\r", "");
}

// ================================ PGP/MIME ================================
// Port of email_handler.py prepare_pgp_message (L382-459): wrap the built
// message into an RFC 3156 multipart/encrypted envelope. Every non-MIME
// header stays on the OUTER envelope (Flask copies them across L395-398, so
// the later From/To/Cc/List-Unsubscribe rewrites keep applying to the outer
// message); the MIME headers + body form the inner message that gets
// encrypted. sign_msg (forward phase passes can_sign=True, L888) is skipped:
// PGP_SENDER_PRIVATE_KEY is not configured on this deployment and Flask only
// signs when it is set (L426).

/** headers.MIME_HEADERS (app/email/headers.py L50-57), lowercased. */
const PGP_MIME_HEADERS = [
  "mime-version",
  "content-type",
  "content-disposition",
  "content-transfer-encoding",
];

/**
 * Mutates `hs` into the outer multipart/encrypted header set and returns the
 * new outer body. Throws PGPException when the key cannot encrypt — the
 * caller delivers unencrypted with Flask's failure banner.
 */
async function preparePgpMessage(
  hs: HeaderLine[],
  body: Uint8Array,
  publicKey: string,
): Promise<Uint8Array> {
  // Inner message (L400-417): MIME headers only, with Flask's fallbacks for
  // a missing Content-Type / Mime-Version.
  const inner = hs
    .filter((h) => PGP_MIME_HEADERS.includes(h.name.toLowerCase()))
    .map((h) => ({ ...h }));
  if (!getHeader(inner, "Content-Type"))
    inner.push({ name: "Content-Type", value: "text/plain" });
  if (!getHeader(inner, "Mime-Version"))
    inner.push({ name: "Mime-Version", value: "1.0" });
  const armored = await encryptMessage(
    publicKey,
    serializeMessage(inner, body),
  );

  // Outer envelope: the MIME headers moved inside; multipart/encrypted takes
  // their place. (Flask's header-copy loop appends the kept headers in
  // reversed order after the Content-Type — header ORDER is not significant
  // and is kept stable here.)
  for (const name of PGP_MIME_HEADERS) deleteHeader(hs, name);
  const boundary = pgpBoundary();
  hs.push({
    name: "Content-Type",
    value: `multipart/encrypted; protocol="application/pgp-encrypted"; boundary="${boundary}"`,
  });
  hs.push({ name: "MIME-Version", value: "1.0" });

  // Part 1: the RFC 3156 control part (L419-423); part 2: the encrypted
  // payload as inline encrypted.asc (L430-452). Same part headers as
  // Python's MIMEApplication with encode_7or8bit.
  const text =
    `--${boundary}\r\n` +
    "Content-Type: application/pgp-encrypted\r\n" +
    "MIME-Version: 1.0\r\n" +
    "Content-Transfer-Encoding: 7bit\r\n" +
    "\r\n" +
    "Version: 1\r\n" +
    `--${boundary}\r\n` +
    'Content-Type: application/octet-stream; name="encrypted.asc"\r\n' +
    "MIME-Version: 1.0\r\n" +
    "Content-Transfer-Encoding: 7bit\r\n" +
    'Content-Disposition: inline; filename="encrypted.asc"\r\n' +
    "\r\n" +
    `${armored.replace(/\r?\n/g, "\r\n").trimEnd()}\r\n` +
    `--${boundary}--\r\n`;
  return new TextEncoder().encode(text);
}

/** Python email.generator._make_boundary shape: 15 '=' + 19 digits + '=='. */
function pgpBoundary(): string {
  const bytes = new Uint8Array(19);
  crypto.getRandomValues(bytes);
  return `===============${Array.from(bytes, (b) => b % 10).join("")}==`;
}

// ================= reverse-alias body replacement =========================
// Port of app/email_utils.py `replace(msg, old, new)`, invoked by the reply
// phase when the user enabled `replace_reverse_alias`: the reverse-alias
// address and the mailbox address (both commonly quoted when a user replies)
// are swapped for the contact's real address and the alias address in the
// message body. We walk the MIME tree, transfer-decode each text/plain and
// text/html leaf per its Content-Transfer-Encoding, apply the substitutions,
// and re-encode with the same CTE. The set of content types touched vs. left
// alone is copied verbatim from email_utils.replace(). Any non-text part and
// any structure we can't parse is returned byte-for-byte unchanged so we never
// corrupt mail.

type Replacement = [string, string];

const B64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_LOOKUP: Int8Array = (() => {
  const t = new Int8Array(256).fill(-1);
  for (let i = 0; i < B64_ALPHABET.length; i++)
    t[B64_ALPHABET.charCodeAt(i)] = i;
  return t;
})();
const HEX_DIGITS = "0123456789ABCDEF";

/**
 * Apply `replacements` (each `[old, new]`; addresses are ASCII) to the decoded
 * text of a MIME message described by its top-level `headers` and raw `body`
 * bytes. Mirrors email_utils.replace(): the same content types are rewritten,
 * skipped, or recursed into, and each text leaf is decoded/replaced/re-encoded
 * per its Content-Transfer-Encoding.
 */
export function replaceInMimeBody(
  headers: HeaderLine[],
  body: Uint8Array,
  replacements: Replacement[],
): Uint8Array {
  return replaceInEntity(headers, body, replacements);
}

function replaceInEntity(
  headers: HeaderLine[],
  body: Uint8Array,
  replacements: Replacement[],
): Uint8Array {
  const { type, boundary } = parseContentType(
    getHeader(headers, "Content-Type"),
  );

  // Content types email_utils.replace() explicitly leaves untouched. Note
  // multipart/signed is here on purpose: rewriting inside it would break the
  // signature.
  if (
    type.startsWith("image/") ||
    type.startsWith("video/") ||
    type.startsWith("audio/") ||
    type.startsWith("application/") ||
    type === "multipart/signed" ||
    type === "text/calendar" ||
    type === "text/directory" ||
    type === "text/csv" ||
    type === "text/x-python-script"
  ) {
    return body;
  }

  if (type === "text/plain" || type === "text/html")
    return replaceInTextLeaf(headers, body, replacements);

  if (
    type === "multipart/alternative" ||
    type === "multipart/related" ||
    type === "multipart/mixed"
  ) {
    if (!boundary) return body; // malformed: no boundary -> never corrupt mail
    return replaceInMultipart(body, boundary, replacements);
  }

  // message/rfc822: email_utils.replace() recurses into the single embedded
  // message (get_payload() returns a one-element list); the whole body is that
  // nested entity.
  if (type === "message/rfc822") return replaceInNestedPart(body, replacements);

  // Anything else: unchanged (email_utils.replace()'s trailing `return msg`).
  return body;
}

/** MIME type (lowercased) and boundary param of a Content-Type header value. */
function parseContentType(value: string | null): {
  type: string;
  boundary: string | null;
} {
  // Missing Content-Type -> RFC 2045 default text/plain (as Python's
  // Message.get_content_type()).
  if (!value) return { type: "text/plain", boundary: null };
  const semi = value.indexOf(";");
  const type = (semi === -1 ? value : value.slice(0, semi))
    .trim()
    .toLowerCase();
  const m = value.match(/;\s*boundary\s*=\s*(?:"([^"]*)"|([^;\s]+))/i);
  return { type, boundary: m ? (m[1] ?? m[2] ?? null) : null };
}

/** get_encoding(): normalize a Content-Transfer-Encoding to the codec to use. */
function normalizeCte(
  value: string | null,
): "quoted-printable" | "base64" | "none" {
  const cte = (value ?? "")
    .toLowerCase()
    .trim()
    .replace(/^["']+/, "")
    .replace(/["']+$/, "");
  if (cte === "base64") return "base64";
  if (cte === "quoted-printable") return "quoted-printable";
  // "", 7bit/8bit/binary, utf-8, amazonses.com, or anything unknown: treat as
  // no transfer coding, exactly like get_encoding()'s fall-through.
  return "none";
}

function replaceInTextLeaf(
  headers: HeaderLine[],
  body: Uint8Array,
  replacements: Replacement[],
): Uint8Array {
  const cte = normalizeCte(getHeader(headers, "Content-Transfer-Encoding"));

  if (cte === "quoted-printable") {
    const decoded = qpDecode(body);
    const replaced = replaceBytes(decoded, replacements);
    if (replaced === decoded) return body; // nothing matched: keep exact bytes
    return qpEncode(replaced);
  }

  if (cte === "base64") {
    const decoded = base64Decode(body);
    const replaced = replaceBytes(decoded, replacements);
    if (replaced === decoded) return body;
    // b64 re-encode drops all surrounding whitespace; re-attach the body's
    // trailing line terminator so a following multipart boundary stays on its
    // own line.
    return concatBytes(base64Encode(replaced), trailingTerminator(body));
  }

  // 7bit/8bit/binary/none: email_utils uses encode_text(), which is identity
  // for these, so this is a straight byte replace on the raw payload.
  return replaceBytes(body, replacements);
}

/**
 * Byte-level substitution. We treat each byte as a code point (latin1-style)
 * so the search/replace is byte-exact regardless of the declared charset;
 * since the addresses are ASCII this is equivalent to Python's str.replace on
 * any ASCII-superset charset (utf-8, latin-1, ...). Returns the input array
 * unchanged (same reference) when nothing matched, so callers can preserve the
 * original bytes exactly.
 */
function replaceBytes(
  data: Uint8Array,
  replacements: Replacement[],
): Uint8Array {
  let text = bytesToBinaryString(data);
  let changed = false;
  for (const [oldStr, newStr] of replacements) {
    if (!oldStr || !text.includes(oldStr)) continue;
    changed = true;
    text = text.split(oldStr).join(newStr);
  }
  return changed ? binaryStringToBytes(text) : data;
}

function bytesToBinaryString(data: Uint8Array): string {
  let s = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < data.length; i += CHUNK)
    s += String.fromCharCode(...data.subarray(i, i + CHUNK));
  return s;
}

function binaryStringToBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

/** Split a multipart body on `--boundary`, replacing only within each part. */
function replaceInMultipart(
  body: Uint8Array,
  boundary: string,
  replacements: Replacement[],
): Uint8Array {
  const marker = new TextEncoder().encode(`--${boundary}`);
  const delims = findBoundaryDelimiters(body, marker);
  if (delims.length === 0) return body; // malformed: boundary never appears

  // Reassemble preamble + [delimiter line + part]* + epilogue. Framing bytes
  // (preamble, delimiter lines, epilogue) are copied verbatim; only the part
  // content ranges are recursed into.
  const pieces: Uint8Array[] = [body.subarray(0, delims[0].start)];
  for (let k = 0; k < delims.length; k++) {
    const d = delims[k];
    pieces.push(body.subarray(d.start, d.lineEnd));
    if (d.closing) {
      pieces.push(body.subarray(d.lineEnd)); // epilogue
      break;
    }
    const contentEnd = delims[k + 1] ? delims[k + 1].start : body.length;
    pieces.push(
      replaceInNestedPart(body.subarray(d.lineEnd, contentEnd), replacements),
    );
  }
  return concatBytes(...pieces);
}

interface BoundaryDelimiter {
  start: number; // index of the leading '-'
  lineEnd: number; // index just past the delimiter line's terminator (or EOF)
  closing: boolean; // "--boundary--"
}

function findBoundaryDelimiters(
  body: Uint8Array,
  marker: Uint8Array,
): BoundaryDelimiter[] {
  const out: BoundaryDelimiter[] = [];
  const n = body.length;
  let i = 0;
  while (i < n) {
    // i is always at a line start (0, or right after a '\n').
    if (bytesMatchAt(body, i, marker)) {
      let p = i + marker.length;
      let closing = false;
      if (body[p] === 0x2d && body[p + 1] === 0x2d) {
        closing = true;
        p += 2;
      }
      // A real delimiter has only optional whitespace before its line break.
      let valid = true;
      while (p < n && body[p] !== 0x0a && body[p] !== 0x0d) {
        if (body[p] !== 0x20 && body[p] !== 0x09) {
          valid = false;
          break;
        }
        p++;
      }
      if (valid) {
        let lineEnd = p;
        if (body[p] === 0x0d && body[p + 1] === 0x0a) lineEnd = p + 2;
        else if (body[p] === 0x0d || body[p] === 0x0a) lineEnd = p + 1;
        out.push({ start: i, lineEnd, closing });
        i = lineEnd;
        continue;
      }
    }
    while (i < n && body[i] !== 0x0a) i++;
    i++;
  }
  return out;
}

function bytesMatchAt(
  data: Uint8Array,
  pos: number,
  needle: Uint8Array,
): boolean {
  if (pos + needle.length > data.length) return false;
  for (let k = 0; k < needle.length; k++)
    if (data[pos + k] !== needle[k]) return false;
  return true;
}

/** Recurse into one MIME part (its own header block + body), preserving its
 * header bytes verbatim and only rewriting the body. */
function replaceInNestedPart(
  part: Uint8Array,
  replacements: Replacement[],
): Uint8Array {
  const { headerText, bodyStart } = splitRawMessage(part);
  const partHeaders = parseHeaderBlock(headerText);
  const origBody = part.subarray(bodyStart);
  const newBody = replaceInEntity(partHeaders, origBody, replacements);
  if (newBody === origBody) return part; // unchanged: keep exact bytes
  return concatBytes(part.subarray(0, bodyStart), newBody);
}

// ============================ body banners ================================
// Port of app/email_utils.py `add_header(msg, text, html)`: prepend an
// informational banner to the text/plain and text/html leaves of a message.
// Used by the forward phase (invalid-sender / generic-subject notices) and the
// reply phase (notify_mailbox "sent on behalf of" warning). Walks the same MIME
// tree as replaceInMimeBody, decoding/re-encoding each text leaf per its CTE.
// multipart/alternative and multipart/related add to every part; multipart/mixed
// and multipart/signed add to the first part only; other types are unchanged.

const TEXT_HEADER_SEPARATOR = "\n------------------------------\n";

/** Prepend `textHeader`/`htmlHeader` banners to the message's text leaves. */
export function addBodyHeader(
  headers: HeaderLine[],
  body: Uint8Array,
  textHeader: string,
  htmlHeader: string,
): Uint8Array {
  return addBannerToEntity(headers, body, textHeader, htmlHeader);
}

function addBannerToEntity(
  headers: HeaderLine[],
  body: Uint8Array,
  textHeader: string,
  htmlHeader: string,
): Uint8Array {
  const { type, boundary } = parseContentType(
    getHeader(headers, "Content-Type"),
  );
  if (type === "text/plain")
    return addBannerToTextLeaf(headers, body, textHeader, false);
  if (type === "text/html")
    return addBannerToTextLeaf(headers, body, htmlHeader, true);
  if (type === "multipart/alternative" || type === "multipart/related") {
    if (!boundary) return body;
    return addBannerToMultipart(body, boundary, textHeader, htmlHeader, true);
  }
  if (type === "multipart/mixed" || type === "multipart/signed") {
    if (!boundary) return body;
    return addBannerToMultipart(body, boundary, textHeader, htmlHeader, false);
  }
  return body;
}

function htmlBannerWrap(htmlHeader: string, payload: string): string {
  return (
    `<table width="100%" style="width: 100%; -premailer-width: 100%; -premailer-cellpadding: 0;\n` +
    `  -premailer-cellspacing: 0; margin: 0; padding: 0;">\n` +
    `    <tr>\n` +
    `        <td style="border-bottom:1px dashed #5675E2; padding: 10px 0px">${htmlHeader}</td>\n` +
    `    </tr>\n` +
    `    <tr>\n` +
    `        <td>\n` +
    `        ${payload}\n` +
    `        </td>\n` +
    `    </tr>\n` +
    `</table>\n`
  );
}

function addBannerToTextLeaf(
  headers: HeaderLine[],
  body: Uint8Array,
  banner: string,
  isHtml: boolean,
): Uint8Array {
  const enc = new TextEncoder();
  const build = (decoded: Uint8Array): Uint8Array => {
    if (isHtml)
      return enc.encode(
        htmlBannerWrap(banner, bytesToBinaryStringUtf8(decoded)),
      );
    return concatBytes(enc.encode(banner + TEXT_HEADER_SEPARATOR), decoded);
  };

  const cte = normalizeCte(getHeader(headers, "Content-Transfer-Encoding"));
  if (cte === "quoted-printable") return qpEncode(build(qpDecode(body)));
  if (cte === "base64")
    return concatBytes(
      base64Encode(build(base64Decode(body))),
      trailingTerminator(body),
    );
  return build(body);
}

/** Decode already-transfer-decoded bytes as UTF-8 for text interpolation. */
function bytesToBinaryStringUtf8(data: Uint8Array): string {
  return new TextDecoder().decode(data);
}

function addBannerToMultipart(
  body: Uint8Array,
  boundary: string,
  textHeader: string,
  htmlHeader: string,
  allParts: boolean,
): Uint8Array {
  const marker = new TextEncoder().encode(`--${boundary}`);
  const delims = findBoundaryDelimiters(body, marker);
  if (delims.length === 0) return body;

  const pieces: Uint8Array[] = [body.subarray(0, delims[0].start)];
  let firstDone = false;
  for (let k = 0; k < delims.length; k++) {
    const d = delims[k];
    pieces.push(body.subarray(d.start, d.lineEnd));
    if (d.closing) {
      pieces.push(body.subarray(d.lineEnd));
      break;
    }
    const contentEnd = delims[k + 1] ? delims[k + 1].start : body.length;
    const part = body.subarray(d.lineEnd, contentEnd);
    if (allParts || !firstDone) {
      pieces.push(addBannerToNestedPart(part, textHeader, htmlHeader));
    } else {
      pieces.push(part);
    }
    firstDone = true;
  }
  return concatBytes(...pieces);
}

function addBannerToNestedPart(
  part: Uint8Array,
  textHeader: string,
  htmlHeader: string,
): Uint8Array {
  const { headerText, bodyStart } = splitRawMessage(part);
  const partHeaders = parseHeaderBlock(headerText);
  const origBody = part.subarray(bodyStart);
  const newBody = addBannerToEntity(
    partHeaders,
    origBody,
    textHeader,
    htmlHeader,
  );
  if (newBody === origBody) return part;
  return concatBytes(part.subarray(0, bodyStart), newBody);
}

/** Quoted-printable decode (RFC 2045): =XX hex, =<CRLF>/=<LF> soft breaks. */
function qpDecode(data: Uint8Array): Uint8Array {
  const out: number[] = [];
  const n = data.length;
  for (let i = 0; i < n; i++) {
    const c = data[i];
    if (c !== 0x3d) {
      out.push(c);
      continue;
    }
    // soft line break: '=' at end of line
    if (data[i + 1] === 0x0d && data[i + 2] === 0x0a) {
      i += 2;
      continue;
    }
    if (data[i + 1] === 0x0a) {
      i += 1;
      continue;
    }
    // =XX hex escape
    if (isHexByte(data[i + 1]) && isHexByte(data[i + 2])) {
      out.push((hexValue(data[i + 1]) << 4) | hexValue(data[i + 2]));
      i += 2;
      continue;
    }
    // lone '=' (malformed): keep it, matching quopri.decodestring.
    out.push(c);
  }
  return Uint8Array.from(out);
}

function isHexByte(b: number | undefined): boolean {
  return (
    b !== undefined &&
    ((b >= 0x30 && b <= 0x39) ||
      (b >= 0x41 && b <= 0x46) ||
      (b >= 0x61 && b <= 0x66))
  );
}

function hexValue(b: number): number {
  if (b >= 0x30 && b <= 0x39) return b - 0x30;
  if (b >= 0x41 && b <= 0x46) return b - 0x41 + 10;
  return b - 0x61 + 10;
}

/** Quoted-printable encode (RFC 2045) with CRLF hard breaks and `=`-soft-break
 * wrapping so no output line exceeds 76 columns. */
function qpEncode(data: Uint8Array): Uint8Array {
  const result: number[] = [];
  let line: number[] = [];

  const flush = (terminator: number[]) => {
    for (const c of line) result.push(c);
    for (const c of terminator) result.push(c);
    line = [];
  };
  const softBreak = () => {
    line.push(0x3d); // trailing '=' marks a soft line break
    flush([0x0d, 0x0a]);
  };
  const pushAtom = (atom: number[]) => {
    // keep room for a possible trailing soft-break '=' (max line = 76).
    if (line.length + atom.length > 75) softBreak();
    for (const c of atom) line.push(c);
  };
  const encodeTrailingSpace = () => {
    const last = line[line.length - 1];
    if (last === 0x20 || last === 0x09) {
      line.pop();
      pushAtom(qpTriple(last));
    }
  };
  const hardBreak = () => {
    encodeTrailingSpace();
    flush([0x0d, 0x0a]);
  };

  for (let i = 0; i < data.length; i++) {
    const b = data[i];
    if (b === 0x0d && data[i + 1] === 0x0a) {
      hardBreak();
      i++;
    } else if (b === 0x0a) {
      hardBreak();
    } else if (b === 0x0d) {
      pushAtom(qpTriple(b)); // lone CR -> =0D
    } else if (b === 0x20 || b === 0x09) {
      pushAtom([b]); // literal space/tab (fixed up if it ends a line)
    } else if (b >= 0x21 && b <= 0x7e && b !== 0x3d) {
      pushAtom([b]);
    } else {
      pushAtom(qpTriple(b));
    }
  }
  encodeTrailingSpace();
  for (const c of line) result.push(c);
  return Uint8Array.from(result);
}

function qpTriple(b: number): number[] {
  return [
    0x3d,
    HEX_DIGITS.charCodeAt((b >> 4) & 0x0f),
    HEX_DIGITS.charCodeAt(b & 0x0f),
  ];
}

/** Base64 decode, ignoring whitespace/padding/stray bytes (b64decode-style). */
function base64Decode(data: Uint8Array): Uint8Array {
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < data.length; i++) {
    const v = B64_LOOKUP[data[i]];
    if (v < 0) continue; // whitespace, '=' padding, or any non-alphabet byte
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

/** Base64 encode, wrapped at 76 columns with CRLF (RFC 2045). */
function base64Encode(data: Uint8Array): Uint8Array {
  let s = "";
  let i = 0;
  for (; i + 2 < data.length; i += 3) {
    const n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
    s +=
      B64_ALPHABET[(n >> 18) & 63] +
      B64_ALPHABET[(n >> 12) & 63] +
      B64_ALPHABET[(n >> 6) & 63] +
      B64_ALPHABET[n & 63];
  }
  const rem = data.length - i;
  if (rem === 1) {
    const n = data[i] << 16;
    s += `${B64_ALPHABET[(n >> 18) & 63]}${B64_ALPHABET[(n >> 12) & 63]}==`;
  } else if (rem === 2) {
    const n = (data[i] << 16) | (data[i + 1] << 8);
    s +=
      B64_ALPHABET[(n >> 18) & 63] +
      B64_ALPHABET[(n >> 12) & 63] +
      `${B64_ALPHABET[(n >> 6) & 63]}=`;
  }
  const lines: string[] = [];
  for (let j = 0; j < s.length; j += 76) lines.push(s.slice(j, j + 76));
  return new TextEncoder().encode(lines.join("\r\n"));
}

/** The trailing CRLF or LF of `data`, or an empty array if it has neither. */
function trailingTerminator(data: Uint8Array): Uint8Array {
  const n = data.length;
  if (n >= 2 && data[n - 2] === 0x0d && data[n - 1] === 0x0a)
    return new Uint8Array([0x0d, 0x0a]);
  if (n >= 1 && data[n - 1] === 0x0a) return new Uint8Array([0x0a]);
  return new Uint8Array(0);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// ======================= address parsing / formatting =====================

interface ParsedAddress {
  name: string;
  address: string;
}

/** Minimal RFC 2047 decoder for display names (B and Q encodings). */
function decodeRfc2047(value: string): string {
  return value.replace(
    /=\?([^?]+)\?([bBqQ])\?([^?]*)\?=/g,
    (match, charset: string, encoding: string, data: string) => {
      try {
        let bytes: Uint8Array;
        if (encoding.toLowerCase() === "b") {
          const bin = atob(data);
          bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
        } else {
          const qp = data
            .replaceAll("_", " ")
            .replace(/=([0-9A-Fa-f]{2})/g, (_m, hex: string) =>
              String.fromCharCode(Number.parseInt(hex, 16)),
            );
          bytes = Uint8Array.from(qp, (c) => c.charCodeAt(0));
        }
        return new TextDecoder(charset.split("*")[0]).decode(bytes);
      } catch {
        return match;
      }
    },
  );
}

/** Split an address header on top-level commas. */
function splitAddressList(value: string): string[] {
  const parts: string[] = [];
  let current = "";
  let inQuotes = false;
  let angleDepth = 0;
  for (const ch of value) {
    if (ch === '"') inQuotes = !inQuotes;
    else if (!inQuotes && ch === "<") angleDepth++;
    else if (!inQuotes && ch === ">") angleDepth = Math.max(0, angleDepth - 1);
    if (ch === "," && !inQuotes && angleDepth === 0) {
      parts.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  parts.push(current);
  return parts.map((p) => p.trim()).filter(Boolean);
}

/**
 * Flatten an RFC 2822 group entry the way email.utils.getaddresses does: drop a
 * leading `phrase:` group label and the trailing `;` terminator, ignoring `:`
 * and `;` inside quotes or angle brackets. `Group: ra+x@sl.co;` -> `ra+x@sl.co`,
 * `undisclosed-recipients:;` -> "" (an empty member the caller then skips).
 */
function stripGroupWrapping(part: string): string {
  let inQuotes = false;
  let angle = 0;
  let labelEnd = -1;
  for (let i = 0; i < part.length; i++) {
    const ch = part[i];
    if (ch === '"') inQuotes = !inQuotes;
    else if (!inQuotes && ch === "<") angle++;
    else if (!inQuotes && ch === ">") angle = Math.max(0, angle - 1);
    else if (!inQuotes && angle === 0 && ch === ":") {
      labelEnd = i;
      break;
    }
  }
  const body = labelEnd === -1 ? part : part.slice(labelEnd + 1);
  return body.replace(/;\s*$/, "").trim();
}

function parseOneAddress(part: string): ParsedAddress | null {
  const decoded = decodeRfc2047(part).trim();
  const angle = decoded.match(/^([\s\S]*?)<([^<>]*)>\s*$/);
  if (angle) {
    let name = angle[1].trim();
    if (name.startsWith('"') && name.endsWith('"') && name.length >= 2)
      name = name.slice(1, -1).replace(/\\([\s\S])/g, "$1");
    const address = angle[2].trim();
    if (!address.includes("@")) return null;
    return { name, address };
  }
  const bare = decoded.replace(/^"+|"+$/g, "").trim();
  if (bare.includes("@") && !bare.includes(" "))
    return { name: "", address: bare };
  return null;
}

/**
 * is_valid_email (email_validator, no unicode, no MX check; the domain must
 * contain a period).
 */
function isValidEmail(email: string): boolean {
  if (!email) return false;
  for (let i = 0; i < email.length; i++) {
    const code = email.charCodeAt(i);
    if (code < 0x21 || code > 0x7e) return false;
  }
  if (email.length > 254) return false;
  const at = email.lastIndexOf("@");
  if (at <= 0 || at === email.length - 1) return false;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (local.length > 64) return false;
  if (
    !/^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/.test(
      local,
    )
  )
    return false;
  return /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$/.test(
    domain,
  );
}

/** sl_formataddr: RFC 2047-encode non-ascii names, quote specials. */
function formatAddr(name: string | null, address: string): string {
  if (!name) return address;
  if (!isAscii(name)) {
    const b64 = btoa(String.fromCharCode(...new TextEncoder().encode(name)));
    return `=?utf-8?b?${b64}?= <${address}>`;
  }
  if (/[()<>@,:;.\\"[\]]/.test(name)) {
    const escaped = name.replace(/["\\]/g, (c) => `\\${c}`);
    return `"${escaped}" <${address}>`;
  }
  return `${name} <${address}>`;
}

function isAscii(s: string): boolean {
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 127) return false;
  return true;
}

function domainPart(address: string): string {
  const sanitized = sanitizeEmail(address);
  return sanitized.slice(sanitized.indexOf("@") + 1);
}

function localPart(address: string): string {
  const at = address.lastIndexOf("@");
  return at === -1 ? address : address.slice(0, at);
}

// chars allowed in ids / reply emails (app/utils.py, app/email_validation.py)
const ID_ALLOWED_CHARS =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";
const REPLY_ALLOWED_CHARS = `${ID_ALLOWED_CHARS}+@`;

function convertToAlphanumeric(s: string): string {
  let out = "";
  for (const c of s) out += ID_ALLOWED_CHARS.includes(c) ? c : "_";
  return out;
}

/**
 * convert_to_id: lowercase, transliterate (NFKD + strip combining marks —
 * a lighter version of Python's unidecode), remove spaces, keep only
 * alphanumeric-ish chars, truncate to 64.
 */
function convertToId(s: string): string {
  let out = s.toLowerCase();
  out = out.normalize("NFKD").replace(/[\u0300-\u036f]/g, "");
  out = out.replaceAll(" ", "");
  return convertToAlphanumeric(out).slice(0, 64);
}

/** normalize_reply_email: replace disallowed chars by "_". */
function normalizeReplyEmail(replyEmail: string): string {
  let r = replyEmail;
  if (!isAscii(r)) r = convertToId(r);
  let out = "";
  for (const c of r) out += REPLY_ALLOWED_CHARS.includes(c) ? c : "_";
  return out;
}

/** Python random.randint: inclusive on both ends. */
function randint(a: number, b: number): number {
  return Math.floor(Math.random() * (b - a + 1)) + a;
}

/** re2.fullmatch equivalent; an invalid pattern counts as no match. */
function regexFullMatch(pattern: string, value: string): boolean {
  try {
    return new RegExp(`^(?:${pattern})$`).test(value);
  } catch {
    return false;
  }
}

let msgIdCounter = 0;
/** make_msgid-shaped unique Message-ID on the given domain. */
function makeMsgId(idString: string, domain: string): string {
  msgIdCounter += 1;
  return `<${Date.now()}${String(msgIdCounter).padStart(4, "0")}.${randomString(
    12,
  )}.${idString}@${domain}>`;
}

const RFC2822_DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const RFC2822_MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

/** email.utils.formatdate(): RFC 2822 with the -0000 timezone. */
function formatDateRfc2822(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${RFC2822_DAYS[d.getUTCDay()]}, ${pad(d.getUTCDate())} ` +
    `${RFC2822_MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} -0000`
  );
}

// ============================ base32 / HMAC ===============================

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function b32encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function b32decode(s: string): Uint8Array | null {
  const clean = s.toUpperCase().replace(/=+$/, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

async function hmacSha256(secret: string, data: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data),
  );
  return new Uint8Array(signature);
}
