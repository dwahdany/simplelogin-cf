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
 *   envelope sender. Every outbound send is also recorded in the exported
 *   `outboundEmails` array so tests can assert on the raw content.
 */

import { canonicalizeEmail, randomString, sanitizeEmail } from "./lib/crypto";
import { nowStr, toDate } from "./lib/dates";
import type { Env } from "./lib/env";
import { sendTransactionalEmail } from "./lib/mailer";
import {
  availableSlEmail,
  canCreateNewAlias,
  getAliasById,
  getCustomDomainById,
  getMailboxById,
  getUserById,
} from "./lib/models";
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
const E512 = "550 SL E512 No such email log";
const E515 = "550 SL E515 Email not exist";
const E516 = "550 SL E516 invalid mailbox";
const E518 = "550 SL E518 Disabled mailbox";
const E520 = "550 SL E520 Unverified custom domain";
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

const VERP_TYPE_BOUNCE_FORWARD = 0;
const VERP_TYPE_BOUNCE_REPLY = 1;
const VERP_TYPE_TRANSACTIONAL = 2;

// Alert types (config.py) used for the sent_alert-based "at most once" cap.
const ALERT_FROM_ADDRESS_IS_REVERSE_ALIAS = "from_address_is_reverse_alias";
const ALERT_SEND_EMAIL_CYCLE = "cycle";
const ALERT_MAILBOX_IS_ALIAS = "mailbox_is_alias";
const ALERT_TO_NOREPLY = "to_noreply";

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
  envelopeFrom: string;
  to: string;
  raw: string;
}

/** Every reply-phase / notification outbound send, oldest first (test seam). */
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

  // Out-of-office auto-reply to a reverse alias with a null sender.
  if (isNullSender(mailFrom) && reverse) return accept(E206);

  // noreply address.
  if (getNoReplies(env).includes(rcptTo)) {
    await sendNoReplyResponse(db, env, mailFrom, message);
    return accept(E200);
  }

  if (reverse) return handleReplyPhase(message, env, mailFrom, rcptTo);
  return handleForwardPhase(message, env, mailFrom, rcptTo);
}

function isNullSender(mailFrom: string): boolean {
  return mailFrom === "" || mailFrom === "<>";
}

function getNoReplies(env: Env): string[] {
  return [`noreply@${env.EMAIL_DOMAIN}`];
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
      const rtc = await createContact(db, env, parsed.address, alias, user, {
        name: parsed.name,
        allowEmptyEmail: false,
      });
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
  // message.forward() fallback (no binding) reads the message internally.
  const buffered = env.SEND_EMAIL ? await readRawMessage(message) : null;

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
      await sendAlertAtMostOnce(
        db,
        env,
        user.id,
        ALERT_MAILBOX_IS_ALIAS,
        user.email,
        `Your mailbox ${mailbox.email} is an alias`,
        `Your mailbox ${mailbox.email} is itself an alias and cannot receive forwarded emails. It has been unverified.`,
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
    await sendAlertAtMostOnce(
      db,
      env,
      user.id,
      ALERT_MAILBOX_IS_ALIAS,
      user.email,
      `Your mailbox ${mailbox.email} and alias ${alias.email} use the same domain`,
      `Your mailbox ${mailbox.email} and alias ${alias.email} use the same domain; forwarding is not possible.`,
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

  // Fallback for local dev without the SEND_EMAIL binding: forward as-is with
  // the X-SimpleLogin-* headers. This CANNOT rewrite From/To/Cc, so Reply from
  // the mailbox reaches the original sender — the binding path below is the
  // faithful one.
  if (!buffered) {
    const xHeaders = new Headers();
    xHeaders.set("X-SimpleLogin-Type", "Forward");
    xHeaders.set("X-SimpleLogin-EmailLog-ID", String(emailLog.id));
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

  // Step 7: generic subject (header only; the explanatory body banner is
  // skipped — this port does not rewrite MIME bodies, like the reply phase).
  if (mailbox.generic_subject)
    setHeader(hs, "Subject", mailbox.generic_subject);

  // Step 5 (invalid_email banner) and step 8 (PGP) are body rewrites: skipped
  // like the reply phase. Step 4 (SpamAssassin) is config-gated off.

  // Step 9: X-SimpleLogin-* headers (added after the whitelist so they stay).
  setHeader(hs, "X-SimpleLogin-Type", "Forward");
  setHeader(hs, "X-SimpleLogin-EmailLog-ID", String(emailLog.id));
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
  const rawOut = serializeMessage(hs, buffered.body);
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
    const contact = await createContact(db, env, contactEmail, alias, user, {
      name: parsed?.name ?? "",
      isCc: headerName.toLowerCase() === "cc",
      allowEmptyEmail: false,
    });
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
 * The mailto UNSUBSCRIBER address is not configured on this port, so
 * DisableAlias/BlockContact use the https unsubscribe link (encode_url), and
 * the PreserveOriginal path proxies only http(s) methods of the original
 * List-Unsubscribe (mailto-only originals require a signed link we can't build
 * without UNSUBSCRIBE_SECRET, so they are dropped).
 */
function addUnsubscribeHeaders(
  env: Env,
  alias: AliasRow,
  contact: ContactRow,
  user: UserRow,
  hs: HeaderLine[],
): void {
  const behaviour = user.unsub_behaviour;
  const proxied = calculateOriginalUnsubHeaders(hs);

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
 * _calculate_header_with_original_behaviour: keep only the http(s) unsubscribe
 * methods of the original List-Unsubscribe (dropping mailto methods so the real
 * mailbox is never leaked). Returns the proxied header dict, or {} to drop.
 */
function calculateOriginalUnsubHeaders(
  hs: HeaderLine[],
): Record<string, string> {
  const value = getHeader(hs, "List-Unsubscribe");
  if (!value) return {};
  const otherUnsubs: string[] = [];
  for (const rawMethod of value.split(",")) {
    const start = rawMethod.indexOf("<");
    const end = rawMethod.lastIndexOf(">");
    if (start === -1 || end === -1 || start >= end) continue;
    const method = rawMethod.slice(start + 1, end);
    // mailto methods are dropped (would leak the mailbox / need a signed link).
    if (!method.toLowerCase().startsWith("mailto:")) otherUnsubs.push(method);
  }
  if (otherUnsubs.length === 0) return {};
  return {
    "List-Unsubscribe": otherUnsubs.map((m) => `<${m}>`).join(", "),
    "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
  };
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
    await sendTransactionalEmail(env, {
      to: user.email,
      subject: `Alias ${address} cannot be created`,
      text: `Alias ${address} cannot be created because you have reached the limit of aliases on your plan.`,
    });
    return null;
  }
  if (directory.disabled) {
    await sendTransactionalEmail(env, {
      to: user.email,
      subject: `Alias ${address} cannot be created`,
      text: `Alias ${address} cannot be created because the directory ${directoryName} is disabled.`,
    });
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
  return createContact(db, env, contactEmail, alias, aliasUser, {
    name: contactName,
    mailFrom,
    allowEmptyEmail: true,
  });
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
  const fromHeader = getHeaderValue(message.headers, "From");
  const headerFromAddress = fromHeader
    ? (parseOneAddress(fromHeader)?.address ?? "")
    : "";
  let mailbox = await getMailboxForReplyPhase(
    db,
    mailFrom,
    headerFromAddress,
    alias,
  );
  if (!mailbox) {
    if (alias.disable_email_spoofing_check) {
      mailbox = await getMailboxById(db, alias.mailbox_id);
    }
    if (!mailbox) {
      await handleUnknownMailbox(env, mailFrom, user, alias);
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

  if (!getHeader(hs, "Date"))
    setHeader(hs, "Date", formatDateRfc2822(new Date()));
  setHeader(hs, "X-SimpleLogin-Type", "Reply");
  setHeader(hs, "X-SimpleLogin-EmailLog-ID", String(emailLog.id));

  const rawOut = serializeMessage(hs, body);
  const verpFrom = await generateVerpEmail(
    env,
    VERP_TYPE_BOUNCE_REPLY,
    emailLog.id,
    aliasDomain,
  );
  try {
    await sendRawEmail(env, verpFrom, contact.website_email, rawOut);

    // Notify the alias's other mailboxes about this outgoing email.
    for (const mb of await aliasVerifiedMailboxes(db, alias)) {
      if (mb.email === mailbox.email) continue;
      await notifyOtherMailbox(
        db,
        env,
        alias,
        hs,
        body,
        origTo,
        origCc,
        mb,
        aliasDomain,
      );
    }
  } catch (e) {
    console.error(`cannot send reply from ${alias.email}:`, e);
    await deleteEmailLogRow(db, emailLog.id);
    await sendTransactionalEmail(env, {
      to: mailbox.email,
      subject: `Email cannot be sent to ${contact.website_email} from ${alias.email}`,
      text: `The email from your alias ${alias.email} could not be delivered to ${contact.website_email}. You can retry sending the email.`,
    });
  }
  // 250 in both success and failure: the user is informed and can retry.
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
  env: Env,
  mailFrom: string,
  user: UserRow,
  alias: AliasRow,
): Promise<void> {
  await sendTransactionalEmail(env, {
    to: user.email,
    subject: `Attempt to use your alias ${alias.email} from ${mailFrom}`,
    text:
      `${mailFrom} tried to send an email using your reverse alias of ${alias.email}. ` +
      "Only your mailboxes and their authorized addresses can send emails from a reverse alias.",
  });
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
    const parsed = parseOneAddress(part);
    const addr = parsed ? parsed.address : part;
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
  // From the alias so it's clear the email was sent on its behalf.
  setHeader(notifHs, "From", alias.email);
  if (origTo !== null) setHeader(notifHs, "To", origTo);
  else deleteHeader(notifHs, "To");
  if (origCc !== null) setHeader(notifHs, "Cc", origCc);
  else deleteHeader(notifHs, "Cc");
  const raw = serializeMessage(notifHs, body);
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

  if (verp.verpType === VERP_TYPE_BOUNCE_FORWARD) {
    if (bounce) return handleBounceForwardPhase(db, emailLog);
    if (isOutOfOffice(message)) return accept(E206);
    return accept(E213); // VERPForward
  }
  if (verp.verpType === VERP_TYPE_BOUNCE_REPLY) {
    if (bounce) {
      await db
        .prepare(
          "UPDATE email_log SET bounced = 1, updated_at = ?1 WHERE id = ?2",
        )
        .bind(nowStr(), emailLog.id)
        .run();
      return accept(E212);
    }
    if (isOutOfOffice(message)) return accept(E206);
    return accept(E213); // VERPReply
  }
  return accept(E213);
}

async function handleBounceForwardPhase(
  db: D1Database,
  emailLog: EmailLogRow,
): Promise<HandleResult> {
  await db
    .prepare(
      `UPDATE email_log SET bounced = 1, bounced_mailbox_id = mailbox_id,
         updated_at = ?1 WHERE id = ?2`,
    )
    .bind(nowStr(), emailLog.id)
    .run();
  const mailbox = emailLog.mailbox_id
    ? await getMailboxById(db, emailLog.mailbox_id)
    : null;
  if (mailbox)
    await db
      .prepare("INSERT INTO bounce (email) VALUES (?1)")
      .bind(mailbox.email)
      .run();
  return accept(E211);
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

/** send_email_at_most_times: sent_alert-deduped transactional alert. */
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

function userIsActiveRow(user: UserRow, now: Date = new Date()): boolean {
  if (user.delete_on === null) return true;
  return toDate(user.delete_on).getTime() < now.getTime();
}

function userCanSendOrReceive(user: UserRow): boolean {
  if (user.disabled) return false;
  if (user.delete_on !== null) return false;
  return true;
}

// ========================= outbound raw email send ========================

async function sendRawEmail(
  env: Env,
  envelopeFrom: string,
  to: string,
  raw: Uint8Array,
): Promise<void> {
  outboundEmails.push({
    envelopeFrom,
    to,
    raw: new TextDecoder().decode(raw),
  });
  if (outboundEmails.length > MAX_OUTBOUND_CAPTURED) outboundEmails.shift();

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
  await env.SEND_EMAIL.send(new EmailMessage(envelopeFrom, to, stream));
}

// ======================== raw message / header tools ======================

interface HeaderLine {
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
