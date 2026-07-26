/**
 * JOB_ONBOARDING_1/2/4 handlers — port of the onboarding branches of
 * job_runner.process_job (job_runner.py L217-248) and their send helpers
 * onboarding_send_from_alias / onboarding_mailbox / onboarding_pgp
 * (job_runner.py L41-61 / L110-126 / L64-80). The jobs are enqueued at
 * registration with run_at now+1/+2/+3 days (src/routes/auth.ts,
 * src/web/auth-pages.ts).
 *
 * Gating, exactly as in Flask:
 * - job level: the user still exists AND user.notification AND user.activated
 *   (job_runner.py L223, L232, L241);
 * - onboarding-4 only: skipped when the user's single verified mailbox is a
 *   Proton one (job_runner.py L242-245; User.mailboxes() models.py L1065 is
 *   verified-only). Mailbox.is_proton (models.py L3024) is ported as the
 *   static domain-suffix check only — the MX-lookup half is deferred, same as
 *   the existing port in src/web/mailbox-domain-pages.ts.
 * - helper level: get_communication_email returns an address (models.py
 *   L1149-1179) and user.can_send_or_receive() (models.py L990-999).
 *
 * Deliberate deviations (this deployment):
 * - get_communication_email's no-newsletter-alias branch only returns
 *   user.email when config.UNSUBSCRIBER is set (models.py L1169-1177); there
 *   is no UNSUBSCRIBER (mailto unsubscribe needs a dedicated inbound
 *   mailbox), so the port returns user.email there — matching the established
 *   sendWelcomeEmail port in src/web/auth-pages.ts — otherwise the whole
 *   onboarding series would be unreachable.
 * - send_email's List-Unsubscribe headers are dropped: the mailer seam
 *   (src/lib/mailer.ts) has no custom-header support; the bodies already
 *   carry the settings-page unsubscribe URL.
 * - ignore_smtp_error=True is inherent: sendTransactionalEmail never throws.
 * - Text bodies are inlined below byte-for-byte from the Flask sources
 *   (templates/emails/com/onboarding/*.txt*) because the template build only
 *   compiles .html files; HTML bodies render the nunjucks ports under
 *   cloudflare/templates/emails/com/onboarding/.
 */

import type { Env } from "../../lib/env";
import { sendTransactionalEmail } from "../../lib/mailer";
import type { MailboxRow, UserRow } from "../../lib/rows";
import { renderTemplate } from "../../lib/web/templates";
import type { JobRow } from "../index";

// config.PROTON_EMAIL_DOMAINS defaults (app/config.py L192-194)
const PROTON_EMAIL_DOMAINS = [
  "proton.me",
  "protonmail.com",
  "protonmail.ch",
  "proton.ch",
  "pm.me",
];

/** Mailbox.is_proton() — static domain-suffix half only (MX half deferred). */
function isProton(mb: MailboxRow): boolean {
  return PROTON_EMAIL_DOMAINS.some((d) => mb.email.endsWith(`@${d}`));
}

/** User.can_send_or_receive() (models.py L990-999). */
function canSendOrReceive(user: UserRow): boolean {
  return !user.disabled && user.delete_on === null;
}

/**
 * User.get_communication_email() (models.py L1149-1179), address only — the
 * unsubscribe link/via-email parts feed List-Unsubscribe headers the mailer
 * seam cannot set. See the file-top comment for the UNSUBSCRIBER deviation.
 */
async function communicationEmail(
  env: Env,
  user: UserRow,
): Promise<string | null> {
  if (!user.notification || !user.activated || user.disabled) return null;
  if (user.newsletter_alias_id != null) {
    const alias = await env.DB.prepare(
      "SELECT email, enabled FROM alias WHERE id = ?1",
    )
      .bind(user.newsletter_alias_id)
      .first<{ email: string; enabled: number }>();
    // newsletter alias disabled -> user doesn't want to receive newsletters
    if (!alias?.enabled) return null;
    return alias.email;
  }
  return user.email;
}

/** email_utils.render() context (app/email_utils.py L94-116). */
function renderEmailHtml(
  env: Env,
  name: string,
  user: UserRow,
  toEmail: string,
): string {
  const extra = env as Env & Record<string, string | undefined>;
  return renderTemplate(name, {
    MAX_NB_EMAIL_FREE_PLAN: env.MAX_NB_EMAIL_FREE_PLAN,
    URL: env.URL,
    LANDING_PAGE_URL: extra.LANDING_PAGE_URL ?? "https://simplelogin.io",
    YEAR: new Date().getUTCFullYear(),
    user,
    to_email: toEmail,
  });
}

/** Shared job-level gate: user exists && notification && activated. */
async function onboardingUser(
  env: Env,
  payload: Record<string, unknown>,
): Promise<UserRow | null> {
  const userId = payload.user_id;
  if (typeof userId !== "number") return null;
  const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?1")
    .bind(userId)
    .first<UserRow>();
  // user might delete their account in the meantime
  // or disable the notification (job_runner.py L221-223)
  if (!user?.notification || !user.activated) return null;
  return user;
}

// templates/emails/com/onboarding/*.txt* — byte-exact, "{{ to_email }}" and
// "{{URL}}" interpolated; the files carry no trailing newline.
const sendFromAliasTxt = (toEmail: string, url: string) =>
  `This email is sent to ${toEmail} and is part of our onboarding series.
Unsubscribe from our emails on ${url}/dashboard/setting#notification
----------------

Hi

Do you know you can send an email to anyone from your alias?
This below Youtube video walks you quickly through the steps:

https://youtu.be/GN060XMt6Pc

Here are the steps:
1. First click "Contacts" on your alias you want to send email from
2. Enter your contact email, create a "reverse-alias"
3. Use this reverse-alias instead of your contact email when composing your email

And voilà, your contact will receive this email sent from your alias!
Your real mailbox address will stay hidden.

Best regards,
SimpleLogin Team.`;

const mailboxTxt = (toEmail: string, url: string) =>
  `This email is sent to ${toEmail} and is part of our onboarding series.
Unsubscribe from our emails on ${url}/dashboard/setting#notification
----------------

Hi

If you have several email addresses, e.g. Gmail for work and Proton Mail for personal stuffs, you can add them into SimpleLogin and create aliases for them.

A (real) email address is called *mailbox* in SimpleLogin.

When creating an alias, you can choose which mailbox that *owns* this alias, meaning:

- emails sent to this alias are *forwarded* to the owning mailbox.

- the owning mailbox can *send* or reply emails from this alias.

You can also change the owning mailbox for an existing alias.

The mailbox doesn't have to be your personal email: you can also create aliases for your friend by adding his/her email as a mailbox.

Start create you mailbox on ${url}/dashboard/mailbox

As usual, let us know if you have any question by replying to this email.

Best regards,
SimpleLogin team.`;

const pgpTxt = (toEmail: string, url: string) =>
  `This email is sent to ${toEmail} and is part of our onboarding series.
Unsubscribe from our emails on ${url}/dashboard/setting#notification
----------------

Hi

If you happen to use Gmail, Yahoo, Outlook, etc, do you know these services can read your emails?

If you want to keep your emails only readable by you, Pretty Good Privacy (PGP) is maybe the solution.

Highly recommended, open source and free, PGP is unfortunately not widely supported. However with SimpleLogin most recent PGP support, you can now enable PGP on emails sent to your aliases easily.

Without PGP the emails sent to an alias are forwarded by SimpleLogin as-is to your mailbox, leaving anyone in-between or your email service able to read your emails:

https://simplelogin.io/blog/without-pgp.png

With PGP enabled, all emails arrived at SimpleLogin are encrypted with your public key before being forwarded to your mailbox:

https://simplelogin.io/blog/with-pgp.png

You can find more info on our announcement post on https://simplelogin.io/blog/introducing-pgp/

You can create and manage your PGP keys when adding or editing your mailboxes. Check it out on your mailbox dashboard at ${url}/dashboard/mailbox

As usual, let us know if you have any question by replying to this email.

Best regards,
SimpleLogin team.`;

/** onboarding_send_from_alias (job_runner.py L41-61). */
export async function handleOnboarding1(
  env: Env,
  payload: Record<string, unknown>,
  _job: JobRow,
): Promise<void> {
  const user = await onboardingUser(env, payload);
  if (!user) return;
  const to = await communicationEmail(env, user);
  if (!to) return;
  if (!canSendOrReceive(user)) return;
  await sendTransactionalEmail(env, {
    to,
    subject: "SimpleLogin Tip: Send emails from your alias",
    text: sendFromAliasTxt(to, env.URL),
    html: renderEmailHtml(
      env,
      "emails/com/onboarding/send-from-alias.html",
      user,
      to,
    ),
  });
}

/** onboarding_mailbox (job_runner.py L110-126). */
export async function handleOnboarding2(
  env: Env,
  payload: Record<string, unknown>,
  _job: JobRow,
): Promise<void> {
  const user = await onboardingUser(env, payload);
  if (!user) return;
  const to = await communicationEmail(env, user);
  if (!to) return;
  if (!canSendOrReceive(user)) return;
  await sendTransactionalEmail(env, {
    to,
    subject: "SimpleLogin Tip: Multiple mailboxes",
    text: mailboxTxt(to, env.URL),
    html: renderEmailHtml(env, "emails/com/onboarding/mailbox.html", user, to),
  });
}

/** onboarding_pgp (job_runner.py L64-80) + the Proton gate (L242-245). */
export async function handleOnboarding4(
  env: Env,
  payload: Record<string, unknown>,
  _job: JobRow,
): Promise<void> {
  const user = await onboardingUser(env, payload);
  if (!user) return;
  // if user only has 1 mailbox which is Proton then do not send PGP
  // onboarding email (job_runner.py L242-245)
  const mailboxes = await env.DB.prepare(
    "SELECT * FROM mailbox WHERE user_id = ?1 AND verified = 1",
  )
    .bind(user.id)
    .all<MailboxRow>();
  if (mailboxes.results.length === 1 && isProton(mailboxes.results[0])) return;
  const to = await communicationEmail(env, user);
  if (!to) return;
  if (!canSendOrReceive(user)) return;
  await sendTransactionalEmail(env, {
    to,
    subject: "SimpleLogin Tip: Secure your emails with PGP",
    text: pgpTxt(to, env.URL),
    html: renderEmailHtml(env, "emails/com/onboarding/pgp.html", user, to),
  });
}
