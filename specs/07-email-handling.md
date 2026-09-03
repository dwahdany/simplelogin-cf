# 07 — Email Handling (SMTP forward/reply pipeline)

Source files:
- `email_handler.py` (aiosmtpd handler, no HTTP routes)
- `app/email_utils.py`
- `app/contact_utils.py`
- `app/alias_utils.py`
- `app/mailbox_utils.py`
- `app/models.py`

This component is **not a Flask route**. It is an SMTP server (aiosmtpd `Controller`, default port `20381`, size limit `config.SMTP_SIZE_LIMIT`) whose `MailHandler.handle_DATA` parses the raw message (`email.message_from_bytes(envelope.original_content)`) and returns an SMTP status **string** (e.g. `"250 Message accepted for delivery"`). On Cloudflare, this maps to an Email Workers `email()` handler; the SMTP status strings map to accept/reject decisions.

## 0. SMTP status codes (app/email/status.py — copy verbatim)

```python
E200 = "250 Message accepted for delivery"
E201 = "250 SL E201"
E204 = "250 SL E204 ignore"
E205 = "250 SL E205 bounce handled"
E206 = "250 SL E206 Out of office"
E207 = "250 SL E207 No bounce report"
E209 = "250 SL E209 Email Loop"
E211 = "250 SL E211 Bounce Forward phase handled"
E212 = "250 SL E212 Bounce Reply phase handled"
E213 = "250 SL E213 Unknown email ignored"
E214 = "250 SL E214 Unauthorized for using reverse alias"
E216 = "250 SL E216 Handled spf policy"
E402 = "421 SL E402 Encryption failed - Retry later"
E404 = "421 SL E404 Unexpected error - Retry later"
E405 = "421 SL E405 Mailbox domain problem - Retry later"
E407 = "421 SL E407 Retry later"
E501 = "550 SL E501"
E502 = "550 SL E502 Email not exist"
E503 = "550 SL E503"
E504 = "550 SL E504 Account disabled"
E506 = "550 SL E506 Email detected as spam"
E512 = "550 SL E512 No such email log"
E515 = "550 SL E515 Email not exist"
E516 = "550 SL E516 invalid mailbox"
E517 = "550 SL E517 unverified mailbox"
E518 = "550 SL E518 Disabled mailbox"
E519 = "550 SL E519 Email detected as spam"
E520 = "550 SL E520 Unverified custom domain"
E522 = ("550 SL E522 The user you are trying to contact is receiving mail "
        "at a rate that prevents additional messages from being delivered.")
E524 = "550 SL E524 Wrong use of reverse-alias"
E525 = "550 SL E525 Alias loop"
E526 = "550 SL E526 Too many recipients"
```

## 1. Top-level dispatch — `handle(envelope, msg)`

Order of operations (each step returns a status and stops processing):

1. **Sanitize envelope**: `mail_from = sanitize_email(envelope.mail_from)`, each `rcpt_to = sanitize_email(rcpt_to)`.
   `sanitize_email(s, not_lower=False)`: `s.strip().replace(" ", "").replace("\n", " ")`, lowercase unless `not_lower=True`, then `.replace("‏", "")` (removes RTL mark).
2. If `Content-Transfer-Encoding` header missing → set to `"7bit"`.
3. **IgnoredEmail**: if exactly 1 rcpt and `IgnoredEmail.get_by(mail_from=..., rcpt_to=...)` exists → `E204`.
4. **Sanitize headers** `From`, `To`, `Cc`, `Reply-To`, `Message-ID`: in-place `value.strip().replace("\n", " ").replace("\r", "")`.
5. **Reverse-alias-as-sender detection**: if `Contact.get_by(reply_email=mail_from)` or `Contact.get_by(reply_email=<From-header address>)` exists → email the user an alert (`ALERT_FROM_ADDRESS_IS_REVERSE_ALIAS`, subject `"SimpleLogin shouldn't be used with another email forwarding system"`) but **continue processing**.
6. Unsubscribe request (rcpt == `UNSUBSCRIBER`/`OLD_UNSUBSCRIBER`) → `UnsubscribeHandler` (edge case, out of scope here).
7. **VERP-addressed mail** (bounces / out-of-office) — see §5.
8. Hotmail (`staff@hotmail.com` → `POSTMASTER`) / Yahoo (`feedback@arf.mail.yahoo.com` → `POSTMASTER`) complaint handling (edge case).
9. **Rate limit** `rate_limited(mail_from, rcpt_tos)` → `E207` if `should_ignore_bounce(mail_from)` else `E522`.
   `should_ignore_bounce(mail_from)` = `IgnoreBounceSender.get_by(mail_from=mail_from) is not None`.
10. Out-of-office to a reverse alias with `mail_from == "<>"` → `E206`.
11. **Per-recipient loop** over `rcpt_tos` (message deep-copied for all but the last recipient):
    - `rcpt_to in config.NOREPLIES` → `send_no_reply_response` (auto reply to the mailbox owner, at most `ALERT_TO_NOREPLY` times) → return `E200`.
    - `is_reverse_alias(rcpt_to)` → **reply phase** `handle_reply(...)`.
    - else → **forward phase** `handle_forward(...)` (returns list, one entry per mailbox).
12. **Aggregation**: if ANY delivery succeeded, return that success status; else return the first failure status.

Exception mapping in `handle_DATA`: `CannotCreateContactForReverseAlias` → `E524`; `VERPReply/VERPForward/VERPTransactional` → `E213`; any other exception → `E404`. Additionally, after `handle()` returns: if status starts with `"5"` and the rspamd SPF check result was fail/soft_fail, the status is replaced by `E216` (black-hole to avoid backscatter).

**Reverse-alias detection** (`is_reverse_alias`, email_utils.py):

```python
def is_reverse_alias(address: str) -> bool:
    # to take into account the new reverse-alias that doesn't start with "ra+"
    if Contact.get_by(reply_email=address):
        return True

    return address.endswith(f"@{config.EMAIL_DOMAIN}") and (
        address.startswith("reply+") or address.startswith("ra+")
    )
```

i.e. primary detection is a **DB lookup on `contact.reply_email`**; the `ra+`/`reply+` prefix check is only a legacy fallback.

## 2. Forward phase — `handle_forward(envelope, msg, rcpt_to)`

### 2.1 Alias resolution

1. `alias = Alias.get_by(email=rcpt_to)` — **exact match** (rcpt already lowercased by `sanitize_email`).
2. If not found → `try_auto_create(rcpt_to)`:
   - Refuse addresses that look like VERP: starts with `f"{BOUNCE_PREFIX_FOR_REPLY_PHASE}+"` (default `"bounce_reply+"`) and contains `"+@"`; or starts with `BOUNCE_PREFIX` (default `"bounce+"`) and ends with `BOUNCE_SUFFIX` (default `f"+@{EMAIL_DOMAIN}"`).
   - `validate_email(address, check_deliverability=False, allow_smtputf8=False)` must pass (no unicode).
   - Try `try_auto_create_via_domain(address)` **first**, then `try_auto_create_directory(address)`.
3. If still no alias → `E207` if `should_ignore_bounce(mail_from)` else `E515`.

**Catch-all / custom-domain auto-creation** (`try_auto_create_via_domain` + `check_if_alias_can_be_auto_created_for_custom_domain`):
- `custom_domain = CustomDomain.get_by(domain=<domain part of address>)`; requires `custom_domain.ownership_verified`, owner not `disabled`, `user.can_create_new_alias()` (else notify user with "cannot create" email).
- If `custom_domain.catch_all` is false: iterate `custom_domain.auto_create_rules` and regex-match `rule.regex` against the **local part**; first matching rule wins; no match → None.
- Mailboxes: rule mailboxes if rule, else `custom_domain.mailboxes`; if empty → `[custom_domain.user.default_mailbox]`.
- `Alias.create(email=address, user_id=custom_domain.user_id, custom_domain_id=custom_domain.id, automatic_creation=True, mailbox_id=mailboxes[0].id)`; extra mailboxes via `AliasMailbox`. Note set to `f"Created by rule {rule.order} with regex {rule.regex}"` or `"Created by catchall option"` (unless `user.disable_automatic_alias_note`); rule `display_name` becomes alias name.
- `AliasInTrashError` (alias was deleted before) → None (no recreation). `IntegrityError` → return the existing alias.

**Directory auto-creation** (`try_auto_create_directory`):
- Address must end with `@` + one of `config.ALIAS_DOMAINS` (`can_create_directory_for_address`).
- Separator detection order: `"/"` then `"+"` then `"#"` — `directory_name = address[: address.find(sep)]`; `Directory.get_by(name=directory_name)`.
- Checks: directory owner not disabled, `can_create_new_alias()`, directory not `disabled` (each failure optionally notifies user).
- `Alias.create(email=address, user_id=directory.user_id, directory_id=directory.id, mailbox_id=directory.mailboxes[0].id)`, note `f"Created by directory {directory.name}"`, extra `AliasMailbox` rows. Same trash/integrity handling as above.

### 2.2 Pre-forward checks (in order)

- `user.is_active()` false (`delete_on` set and in the future... actually `delete_on is None or delete_on < now`) → `(False, E502)`.
- `user.can_send_or_receive()` false (user `disabled` or `delete_on` set) → `E207` if ignore-bounce sender else `(False, E504)`.
- Alias on unverified custom domain (`alias.custom_domain_id and not alias.custom_domain.verified`) → `(False, E520)`.
- **Cycle detection**: if `envelope.mail_from` equals any of `alias.authorized_addresses()` (all verified mailbox emails + their `authorized_addresses`) → store refused email in S3, create `Notification`, email user (`ALERT_SEND_EMAIL_CYCLE`, subject `f"Email sent to {alias.email} from its own mailbox {from_addr}"`) → `(True, E209)`.

### 2.3 Contact get-or-create from the From header

```python
from_header = get_header_unicode(msg[headers.FROM])
contact = get_or_create_contact(from_header, envelope.mail_from, alias)
```

`get_or_create_contact(from_header, mail_from, alias)`:
- `contact_name, contact_email = parse_full_address(from_header)` (flanker `address.parse`; raises → `("", "")`).
- Name truncated to `Contact.MAX_NAME_LENGTH = 512`.
- If `contact_email` invalid (`is_valid_email` = python email_validator, no unicode, no MX check): fall back to `mail_from` unless it is `""`/`"<>"`.
- Calls `contact_utils.create_contact(email=contact_email, alias=alias, name=contact_name, mail_from=mail_from, allow_empty_email=True, automatic_created=True, from_partner=False)`. Returns `None` on error (`handle_forward` then returns `(False, E504)`).

`contact_utils.create_contact` behavior:
- Re-parses `'name <email>'` form; name defaults from parsed display-name; truncated to 512; empty → `None`; a name containing `"\x00"` → `""`.
- `email = sanitize_email(email, not_lower=True)` — **contact emails preserve case**.
- Invalid email + `allow_empty_email` → contact stored with `website_email=""` and `invalid_email=True`.
- Lookup: `Contact.get_by(alias_id=alias.id, website_email=email)`. If it exists: update `name` if changed and set `mail_from` if previously NULL; return existing (created=False).
- Else `reply_email = generate_reply_email(email, alias)` and `Contact.create(user_id=alias.user_id, alias_id=alias.id, website_email=email, name=name, reply_email=reply_email, mail_from=mail_from, automatic_created=True, flags=0, invalid_email=(email == ""), commit=True)` + an alias audit-log entry `f"Created contact {contact_id} ({email}). Automatically created"`.
- `Contact.create` **raises `CannotCreateContactForReverseAlias`** if `website_email` equals an existing contact's `reply_email` (i.e. someone uses a reverse-alias in the forward phase) — unless the address is in `config.NOREPLIES`.
- Unique constraint `uq_contact (alias_id, website_email)`; `IntegrityError` → rollback and re-fetch.

### 2.4 Reverse-alias generation — copy the exact code (`email_utils.generate_reply_email`)

```python
def generate_reply_email(contact_email: str, alias: Alias) -> str:
    """
    generate a reply_email (aka reverse-alias), make sure it isn't used by any contact
    """
    # shorten email to avoid exceeding the 64 characters
    # from https://tools.ietf.org/html/rfc5321#section-4.5.3
    # "The maximum total length of a user name or other local-part is 64
    #    octets."

    include_sender_in_reverse_alias = False

    user = alias.user
    # user has set this option explicitly
    if user.include_sender_in_reverse_alias is not None:
        include_sender_in_reverse_alias = user.include_sender_in_reverse_alias

    if include_sender_in_reverse_alias and contact_email:
        # use _ instead of . to avoid AC_FROM_MANY_DOTS SpamAssassin rule
        contact_email = contact_email.replace("@", "_at_")
        contact_email = contact_email.replace(".", "_")
        # make sure contact_email can be ascii-encoded
        contact_email = convert_to_id(contact_email)
        contact_email = sanitize_email(contact_email)
        contact_email = contact_email[:45]
        contact_email = convert_to_alphanumeric(contact_email)

    reply_domain = config.EMAIL_DOMAIN
    alias_domain = get_email_domain_part(alias.email)
    sl_domain = SLDomain.get_by(domain=alias_domain)
    if sl_domain and sl_domain.use_as_reverse_alias:
        reply_domain = alias_domain

    # not use while to avoid infinite loop
    for _ in range(1000):
        if include_sender_in_reverse_alias and contact_email:
            random_length = random.randint(5, 10)
            reply_email = (
                # do not use the ra+ anymore
                # f"ra+{contact_email}+{random_string(random_length)}@{config.EMAIL_DOMAIN}"
                f"{contact_email}_{random_string(random_length)}@{reply_domain}"
            )
        else:
            random_length = random.randint(20, 50)
            # do not use the ra+ anymore
            # reply_email = f"ra+{random_string(random_length)}@{config.EMAIL_DOMAIN}"
            reply_email = f"{random_string(random_length)}@{reply_domain}"

        if available_sl_email(reply_email):
            return reply_email

    raise Exception("Cannot generate reply email")
```

- **The historical `ra+{...}+{random}@EMAIL_DOMAIN` / `reply+...` formats are no longer generated** — commented out above — but must still be *recognized* (see `is_reverse_alias` fallback). New reverse aliases are either `{sanitized_sender}_{5-10 random lowercase letters}@{reply_domain}` (when `user.include_sender_in_reverse_alias` is true) or `{20-50 random lowercase letters}@{reply_domain}`.
- `random_string(length)` = lowercase ascii letters only (`secrets.choice(string.ascii_lowercase)`).
- `convert_to_id(s)`: lowercase, `unidecode`, remove spaces, then `convert_to_alphanumeric` (any char not in `"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."` → `"_"`), truncated to 64.
- `available_sl_email(email)` = no `Alias`, no `Contact.reply_email`, no `DeletedAlias` with that address.
- If the alias lives on an `SLDomain` with `use_as_reverse_alias=True`, the reverse alias uses the alias's own domain instead of `EMAIL_DOMAIN`.

### 2.5 Reply-To contacts

If the message has a `Reply-To` header: split on `","`, for each address `parse_full_address`; skip if equal to the alias address; otherwise `get_or_create_reply_to_contact` → `contact_utils.create_contact(contact_address, alias, contact_name, automatic_created=True)` (no `allow_empty_email`; invalid → skipped). Collected into `reply_to_contact` list.

### 2.6 Alias enabled/disabled + blocked contact behavior

- If `alias.user.delete_on is not None`: `Alias.lock_for_update(alias_id)` (raw SQL `SELECT id FROM alias WHERE id = :alias_id FOR UPDATE`), create **blocked** EmailLog (`EmailLog.create(contact_id, user_id, blocked=True, alias_id, commit=True)`) → `(True, E502)`.
- If `not alias.enabled` **or** `alias.is_trashed()` (`delete_on is not None`) **or** `contact.block_forward`:
  - Lock alias row, create blocked EmailLog (same fields as above).
  - Return `(True, E200)` by default; if `user.block_behaviour == BlockBehaviourEnum.return_5xx` (enum: `return_2xx = 0`, `return_5xx = 1`) return `(True, E502)`.
  - Rationale in code: "by default return 2** instead of 5** to allow user to receive emails again when alias is enabled or contact is unblocked".

### 2.7 DMARC, mailboxes fan-out

- `apply_dmarc_policy_for_forward_phase(...)` may quarantine/reject (edge case — returns replacement status).
- `mailboxes = alias.mailboxes` — property: `[alias.mailbox] + alias._mailboxes (deduped)`, filtered to `verified` only, **sorted by email**. Empty → `E207`/`(False, E516)`.
- For each mailbox: unverified → `(False, E517)` (unreachable in practice since property filters); if `Alias.get_by(email=mailbox.email)` exists (mailbox is itself an alias → loop): set `mailbox.verified = False`, alert user (`ALERT_MAILBOX_IS_ALIAS`, subject `f"Your mailbox {mailbox.email} is an alias"`, max 1), append `(False, E525)`.
- Otherwise `forward_email_to_mailbox(alias, copy(msg), contact, envelope, mailbox, user, reply_to_contact)` — a **fresh copy of the message per mailbox**.

### 2.8 `forward_email_to_mailbox` — header rewriting + delivery

1. `mailbox.disabled` → `E207` (ignore-bounce sender) or `(False, E518)`. `mailbox.is_admin_disabled()` (flag bit `1<<0`) → quarantine + `(True, E207)`.
2. Sanity: alias domain == mailbox domain → alert (`ALERT_MAILBOX_IS_ALIAS`, subject `f"Your mailbox {mailbox.email} and alias {alias.email} use the same domain"`) → `(False, E405)` (4xx so Postfix retries).
3. **EmailLog creation**:
   ```python
   Alias.lock_for_update(contact.alias_id)
   email_log = EmailLog.create(
       contact_id=contact.id,
       user_id=contact.user_id,
       mailbox_id=mailbox.id,
       alias_id=contact.alias_id,
       message_id=str(msg[headers.MESSAGE_ID]),
       commit=True,
   )
   ```
4. Spam check via SpamAssassin (edge case; spam → `email_log.is_spam=True`, notify, `(False, E519)`), gated on `config.ENABLE_SPAM_ASSASSIN`.
5. `contact.invalid_email` → prepend text/html banner `f"Email sent to {alias.email} from an invalid address and cannot be replied"`.
6. **Header whitelist** — delete everything except:
   `From, To, Cc, Subject, Date, Message-ID, References, In-Reply-To, X-SL-Queue-Id, List-Unsubscribe, List-Id, List-Unsubscribe-Post` + MIME headers (`Mime-Version, Content-Type, Content-Disposition, Content-Transfer-Encoding`); plus `Authentication-Results` when `user.include_header_email_header`.
7. `mailbox.generic_subject` set → replace Subject and prepend banner `Forwarded by SimpleLogin to {alias.email} from "{sender}" with "{orig_subject}" as subject`.
8. PGP-encrypt when `mailbox.pgp_enabled() and user.is_premium() and not alias.disable_pgp` (edge case).
9. **X-SimpleLogin headers** (exact names from app/email/headers.py):
   - `X-SimpleLogin-Type: Forward` (`SL_DIRECTION`)
   - `X-SimpleLogin-EmailLog-ID: {email_log.id}`
   - if `user.include_header_email_header`: `X-SimpleLogin-Envelope-From: {envelope.mail_from}` and `X-SimpleLogin-Original-From: {contact.name} <{contact.website_email}>` (or just `contact.website_email` if no name)
   - always `X-SimpleLogin-Envelope-To: {alias.email}`
   - missing `Date` → `formatdate()` (RFC 2822 date, e.g. `Sat, 05 Jul 2026 12:00:00 -0000`).
10. **Thread-fix** `replace_sl_message_id_by_original_message_id`: In-Reply-To and each token of References that matches `MessageIDMatching.sl_message_id` is replaced by `original_message_id` (so the mailbox sees the original thread ids).
11. **From rewriting**: `add_or_replace_header(msg, "From", contact.new_addr())`. `Contact.new_addr()` (copy):
    ```python
    def new_addr(self):
        user = self.user
        sender_format = user.sender_format if user else SenderFormatEnum.AT.value

        if sender_format == SenderFormatEnum.NO_NAME.value:
            return self.reply_email

        if sender_format == SenderFormatEnum.NAME_ONLY.value:
            new_name = self.name
        elif sender_format == SenderFormatEnum.AT_ONLY.value:
            new_name = self.website_email.replace("@", " at ").strip()
        elif sender_format == SenderFormatEnum.AT.value:
            formatted_email = self.website_email.replace("@", " at ").strip()
            new_name = (
                (self.name + " - " + formatted_email)
                if self.name and self.name != self.website_email.strip()
                else formatted_email
            )
        else:  # SenderFormatEnum.A.value
            formatted_email = self.website_email.replace("@", "(a)").strip()
            new_name = (
                (self.name + " - " + formatted_email)
                if self.name and self.name != self.website_email.strip()
                else formatted_email
            )

        new_addr = sl_formataddr((new_name, self.reply_email)).strip()
        return new_addr.strip()
    ```
    `SenderFormatEnum`: `AT = 0` ("John Wick - john at wick.com"), `A = 2` ("John Wick - john(a)wick.com"), `NAME_ONLY = 5`, `AT_ONLY = 6`, `NO_NAME = 7`. `sl_formataddr` = `formataddr((name, Header(addr, "utf-8")))` coerced to `str` (RFC 2047 encoding of the display name).
12. **Reply-To rewriting**: if reply-to contacts were created, `Reply-To` is replaced by `", ".join(contact.new_addr() for ... [:5])` (max 5).
13. **Recipient limit**: total flanker-parsed addresses in To + Cc must be `<= config.MAX_EMAIL_FORWARD_RECIPIENTS` (default **30**) → else `(False, E526)`.
14. **To/Cc rewriting** (`replace_header_when_forward` for `Cc` then `To`): for each parsed address:
    - address equal to the alias (case-insensitive) → kept as-is (`full_spec()`);
    - invalid/unicode addresses skipped;
    - otherwise get-or-create a `Contact` for `(alias_id, website_email=<case-preserved address>)` (creating with `reply_email=generate_reply_email(...)`, `is_cc=header.lower()=="cc"`, `automatic_created=True`; existing contact gets name updated) and substitute `contact.new_addr()`.
    - Resulting header is the comma-join; if no addresses survive, the header is **deleted**.
    - `CannotCreateContactForReverseAlias` here deletes the just-created EmailLog and bubbles up → whole message gets `E524`.
15. `add_alias_to_header_if_needed`: if `alias.email` is not a substring of To or Cc, append it to To (`f"{to_header},{alias.email}"` or set To if absent) — handles BCC-delivered mail.
16. `UnsubscribeGenerator().add_header_to_message(alias, contact, msg)`: preserves originals in `X-SimpleLogin-Original-List-Unsubscribe(-Post)/List-Id`, then per `user.unsub_behaviour` either keeps the original List-Unsubscribe (proxied), or points it at a SimpleLogin mailto/https unsubscribe for disable-alias (`alias.id`) or block-contact (`contact.id`); sets `X-SimpleLogin-Unsub-Behaviour`.
17. `add_dkim_signature(msg, config.EMAIL_DOMAIN)` — the forwarded mail is DKIM-signed with **EMAIL_DOMAIN** (or `X-SimpleLogin-Want-Signing: yes` if rspamd signs).
18. **Send with VERP envelope sender**:
    ```python
    contact_domain = get_email_domain_part(contact.reply_email)
    sl_sendmail(
        generate_verp_email(VerpType.bounce_forward, email_log.id, contact_domain),
        mailbox.email, msg, envelope.mail_options, envelope.rcpt_options, is_forward=True,
    )
    ```
    SMTP failure (`SMTPServerDisconnected/SMTPRecipientsRefused/TimeoutError`) → delete the EmailLog and return `(False, E407)` (retry), or `(True, E207)` for ignore-bounce senders. Success → commit, `(True, E200)`.

### 2.9 VERP bounce-address format — exact code

```python
VERP_TIME_START = 1640995200          # 2022-01-01, minutes granularity
VERP_HMAC_ALGO = "sha3-224"
# config: VERP_PREFIX = "sl", VERP_MESSAGE_LIFETIME = 5 * 86400, VERP_EMAIL_SECRET (>= 32 chars)

def generate_verp_email(verp_type: VerpType, object_id: int, sender_domain: Optional[str] = None) -> str:
    data = [
        verp_type.value,
        object_id or 0,
        int((time.time() - VERP_TIME_START) / 60),
    ]
    json_payload = json.dumps(data).encode("utf-8")
    payload_hmac = hmac.new(
        config.VERP_EMAIL_SECRET.encode("utf-8"), json_payload, VERP_HMAC_ALGO
    ).digest()[:8]
    encoded_payload = base64.b32encode(json_payload).rstrip(b"=").decode("utf-8")
    encoded_signature = base64.b32encode(payload_hmac).rstrip(b"=").decode("utf-8")
    return "{}.{}.{}@{}".format(
        config.VERP_PREFIX, encoded_payload, encoded_signature,
        sender_domain or config.EMAIL_DOMAIN,
    ).lower()
```

Shape: `sl.{base32(json [type, id, minutes-since-2022])}.{base32(hmac-sha3-224[:8])}@{domain}`, all lowercased, base32 padding stripped. `VerpType`: `bounce_forward = 0`, `bounce_reply = 1`, `transactional = 2`. Decoding (`get_verp_info_from_email`) splits local part on `"."` into exactly 3 fields, first must equal `VERP_PREFIX`, re-pads base32 (uppercasing first), verifies HMAC, and rejects if the embedded timestamp exceeds `now + VERP_MESSAGE_LIFETIME` (message older than 5 days).

Legacy formats (still guarded against as alias names): forward `bounce+{email_log.id}+@{EMAIL_DOMAIN}`, reply `bounce_reply+{email_log.id}+@{alias_domain}`; `parse_id_from_bounce` extracts the int between the first and last `+`.

## 3. Reply phase — `handle_reply(envelope, msg, rcpt_to, notified_mailboxes)`

Triggered when a recipient satisfies `is_reverse_alias(rcpt_to)` (see §1).

1. **Domain check**: `rcpt_to` must end with `config.EMAIL_DOMAIN`, or its domain must be an `SLDomain` row → else `(False, E501)`.
2. `reply_email = normalize_reply_email(rcpt_to)`: non-ascii → `convert_to_id`; any char not in `"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.+@"` replaced with `"_"`.
3. `contact = Contact.get_by(reply_email=reply_email)` → not found or `contact.user` soft-deleted → `(False, E502)`.
4. `alias = contact.alias`. Unverified custom domain → `(False, E520)`. Trashed alias → `(False, E502)`. `is_valid_alias_address_domain(alias.email)` (domain is an SLDomain or a verified CustomDomain) → else `(False, E503)`. `user.can_send_or_receive()` → else `(False, E504)`.
5. DMARC reply-phase policy (edge case).
6. **Sender verification (anti-spoofing)** — `get_mailbox_for_reply_phase(envelope.mail_from, header_from, alias)`:
   - Match `envelope.mail_from` against each of `alias.mailboxes` (email) and each mailbox's `authorized_addresses` — first as-is, then with `canonicalize_email` (gmail/proton domains: strip `+suffix`, strip dots, lowercase).
   - If no envelope match: fall back to the **header From**, but only if `get_email_domain_part(envelope_mail_from) == get_email_domain_part(header_mail_from)` (covers VERP-sending providers); same email/canonical matching.
   - No mailbox found: if `alias.disable_email_spoofing_check` → use `alias.mailbox` (default) anyway; otherwise `handle_unknown_mailbox` (alert email `ALERT_REVERSE_ALIAS_UNKNOWN_MAILBOX`, subject `f"Attempt to use your alias {alias.email} from {envelope.mail_from}"`) → `(False, E214)` (a 250 status, to avoid backscatter).
   - Admin-disabled mailbox → `(False, E207)`.
7. Optional SPF enforcement (`ENFORCE_SPF` + `mailbox.force_spf`, uses `X-SimpleLogin-Client-IP`; fail → `(True, E201)`) (edge case).
8. **EmailLog creation**:
   ```python
   Alias.lock_for_update(contact.alias_id)
   email_log = EmailLog.create(
       contact_id=contact.id, alias_id=contact.alias_id, is_reply=True,
       user_id=contact.user_id, mailbox_id=mailbox.id,
       message_id=msg[headers.MESSAGE_ID], commit=True,
   )
   ```
9. Spam check with `MAX_REPLY_PHASE_SPAM_SCORE` (edge case; spam → `(False, E506)`).
10. **Header whitelist**: keep only `From, To, Cc, Subject, Date, Message-ID, References, In-Reply-To, X-SL-Queue-Id` + MIME headers. (Note: no List-* headers kept on reply.)
11. Optionally strip the sender's PGP public-key attachment (`DROP_PGP_KEY_ATTACHMENTS_ON_REPLY`).
12. **Body replacement** if `user.replace_reverse_alias`: replace `reply_email` → `contact.website_email` and `mailbox.email` → `alias.email` in the text/html payloads (encoding-aware); with `ENABLE_ALL_REVERSE_ALIAS_REPLACEMENT`, do this for up to `MAX_NB_REVERSE_ALIAS_REPLACEMENT` contacts of the alias.
13. PGP-encrypt to the contact when `contact.pgp_finger_print and user.is_premium()`; failure → delete EmailLog, `(False, E402)`.
14. **From rewriting toward the contact** — `get_alias_recipient_name(alias)`:
    - `alias.name` set → `sl_formataddr((alias.name, alias.email))`
    - else custom domain with `name` → `sl_formataddr((custom_domain.name, alias.email))`
    - else plain `alias.email`
    → `add_or_replace_header(msg, "From", ...)`. **The mailbox address never appears.**
15. **To/Cc rewriting** (`replace_header_when_reply` for To then Cc; skipped for To when it is exactly `"undisclosed-recipients:;"`):
    - Each address in the header **must be a reverse alias** (`Contact.get_by(reply_email=...)`); it is replaced by `sl_formataddr((contact.name, contact.website_email))`.
    - Address equal to `alias.email` is dropped (Reply-All case).
    - Any non-reverse-alias address raises `NonReverseAliasInReplyPhase` → EmailLog deleted, mailbox gets an explanatory email (subject `f"Email sent to {contact.email} contains non reverse-alias addresses"`), return `(True, E200)` — i.e. **the reply is silently dropped with a 250**.
16. **Message-ID rewriting** (`replace_original_message_id`): original `Message-ID` is replaced by a new SL Message-ID (`make_msgid(str(email_log.id), alias_domain)`); the `(sl_message_id, original_message_id, email_log_id)` pair is persisted in `MessageIDMatching` (re-used if the original id was already mapped); every References token that matches a known `original_message_id` is replaced by its `sl_message_id`. `email_log.sl_message_id` is stored.
17. Missing `Date` → `formatdate()`. Headers `X-SimpleLogin-Type: Reply` and `X-SimpleLogin-EmailLog-ID: {email_log.id}` are added.
18. DKIM: `should_add_dkim_signature(alias_domain)` (domain is an SLDomain, or a CustomDomain with `dkim_verified`) → sign with the **alias domain**.
19. **Send**:
    ```python
    sl_sendmail(
        generate_verp_email(VerpType.bounce_reply, email_log.id, alias_domain),
        contact.website_email, msg,
        envelope.mail_options, envelope.rcpt_options, is_forward=False,
    )
    ```
20. **Other-mailbox notification**: for every other mailbox of the alias not yet in `notified_mailboxes`, send a copy with banner `**** Don't forget to remove this section if you reply to this email ****\nEmail sent on behalf of alias {alias.email} using mailbox {mailbox.email}`, `From: alias.email`, original To/Cc restored, envelope sender `generate_verp_email(VerpType.transactional, transaction.id, alias_domain)` (a `TransactionalEmail` row).
21. Send failure → EmailLog deleted, mailbox informed (subject `f"Email cannot be sent to {contact.email} from {alias.email}"`); **return `(True, E200)` in both success and failure**.

## 4. Alias enabled/disabled + blocked contact summary

| Condition | EmailLog | Status returned |
|---|---|---|
| `alias.enabled == False` (forward) | `blocked=True` row created | `E200` (or `E502` if `user.block_behaviour == return_5xx (1)`) |
| `alias.is_trashed()` (forward) | `blocked=True` row | same as above |
| `contact.block_forward == True` (forward) | `blocked=True` row | same as above |
| `alias.is_trashed()` (reply) | none | `E502` |
| Alias disabled (reply) | **no check — replies still go out for disabled aliases** | — |

Automatic disabling on bounces (`should_disable`, used by bounce handling): skip when `alias.cannot_be_disabled` or `ALIAS_AUTOMATIC_DISABLE` unset; disable when > `MAX_BOUNCES_1D` (12) forward bounces in 24h; or >1 in 24h and > `MAX_BOUNCES_1W` (10) in the prior week; or bounces on ≥ 9 distinct days in last 10; or account-wide >10 bounces/day on >4 days in last 10. Disabling goes through `change_alias_status(alias, enabled=False, message=...)` which also emits an `AliasStatusChanged` event and audit log.

## 5. VERP-addressed inbound mail (bounces / OOO) — brief

- rcpt matches `VerpType.transactional` → bounce (`mail_from == "<>"` and content-type `multipart/report`) → record `Bounce` for the transactional recipient, `E205`; OOO (`Auto-Submitted: auto-replied|auto-generated`) → `E206`; else raise `VERPTransactional` (`E213`).
- rcpt matches `VerpType.bounce_forward` → load `EmailLog` (missing → `E512`); bounce → `handle_bounce` (forward phase: store refused email in S3, `email_log.bounced=True`, `Bounce` row for the mailbox, maybe disable alias per §4, notify user; returns `E211`); OOO → rewritten to be re-sent to the **reverse alias** (contact) as a normal forward.
- rcpt matches `VerpType.bounce_reply` → bounce → reply-phase bounce handling (`E212`, refused email + notification to mailbox); OOO → rewritten to the alias and forwarded to the mailbox.
- `email_log.is_reply` bounces that are *not* DSNs are treated as **auto-replies**: `email_log.auto_replied = True`, To rewritten to `alias.email` and re-run through `handle_forward`.
- iCloud special-case: VERP `bounce_forward` in `mail_from` (not rcpt) → `handle_bounce`.

## 6. Edge cases intentionally skipped here (documented briefly)

- SpamAssassin scoring (`ENABLE_SPAM_ASSASSIN`, `SPAMASSASSIN_HOST`, `MAX_SPAM_SCORE`, `MAX_REPLY_PHASE_SPAM_SCORE`, user `max_spam_score`) and `handle_spam` notifications.
- DMARC quarantine/reject for both phases (`app/handler/dmarc.py`, status `E215`).
- Hotmail/Yahoo complaint handling (`E208`, `E210`).
- Rate limiting (`app/email/rate_limit.py`, `E522`).
- PGP encryption/signing (`prepare_pgp_message`, `sign_msg`) — premium gated.
- Unsubscribe handling (`UNSUBSCRIBER` mailbox) and unsubscribe header generation details.
- Premium checks are only relevant for PGP; forwarding itself does not check premium.

## Implementation notes for Cloudflare

**DB tables/columns touched:**
- `alias`: read by `email` (unique, lowercase); insert on auto-create (`email, user_id, custom_domain_id/directory_id, mailbox_id, automatic_creation, name, note`); update `enabled` (auto-disable), `mailbox.verified=False` on loop detection; `SELECT ... FOR UPDATE` row lock **before every EmailLog insert** (`Alias.lock_for_update`) to serialize `last_email_log_id` updates.
- `contact`: read by `(alias_id, website_email)` and by `reply_email` (both need indexes; `reply_email` lookup happens on *every* inbound message via `is_reverse_alias`); insert (`user_id, alias_id, website_email, name, reply_email, mail_from, automatic_created, is_cc, flags, invalid_email`); update `name`, `mail_from`. Unique: `(alias_id, website_email)`; `website_email` **case-preserved** (`sanitize_email(not_lower=True)`), `reply_email` effectively lowercase.
- `email_log`: insert (`user_id, contact_id, alias_id, mailbox_id, is_reply, blocked, message_id`); update `spam_score/spam_report/is_spam/spam_status`, `bounced, refused_email_id, bounced_mailbox_id`, `sl_message_id`, `auto_replied`; **deleted** on SMTP send failure / PGP failure / non-reverse-alias reply.
- `message_id_matching`: read/insert `(sl_message_id, original_message_id, email_log_id)` — unique on `original_message_id`; race handled by re-fetch.
- Also: `custom_domain`, `auto_create_rule(+mailboxes)`, `directory(+mailboxes)`, `alias_mailbox`, `mailbox` (+`authorized_address`), `sl_domain (use_as_reverse_alias, domain)`, `deleted_alias`, `domain_deleted_alias`, `bounce`, `refused_email`, `transactional_email`, `ignored_email`, `ignore_bounce_sender`, `notification`, `users` (flags: `disabled, delete_on, block_behaviour, sender_format, include_sender_in_reverse_alias, include_header_email_header, replace_reverse_alias, disable_automatic_alias_note, max_spam_score, unsub_behaviour`).

**Config flags consulted:** `EMAIL_DOMAIN`, `ALIAS_DOMAINS`, `NOREPLIES`, `VERP_PREFIX="sl"`, `VERP_EMAIL_SECRET`, `VERP_MESSAGE_LIFETIME=432000`, `BOUNCE_PREFIX="bounce+"`, `BOUNCE_SUFFIX=f"+@{EMAIL_DOMAIN}"`, `BOUNCE_PREFIX_FOR_REPLY_PHASE="bounce_reply"`, `MAX_EMAIL_FORWARD_RECIPIENTS=30`, `MAX_BOUNCES_1D=12`, `MAX_BOUNCES_1W=10`, `ALIAS_AUTOMATIC_DISABLE`, `ENABLE_SPAM_ASSASSIN`, `ENFORCE_SPF`, `REPLACE...`/`ENABLE_ALL_REVERSE_ALIAS_REPLACEMENT`, `DROP_PGP_KEY_ATTACHMENTS_ON_REPLY`, `URL`, `POSTMASTER`, `UNSUBSCRIBER`/`OLD_UNSUBSCRIBER`, `SMTP_SIZE_LIMIT`, `RSPAMD_SIGN_DKIM`, `DKIM_PRIVATE_KEY`/`DKIM_SELECTOR`.

**Python-specific behaviors to reproduce:**
- `random.randint(a, b)` is **inclusive** on both ends (reverse-alias random lengths 5–10 and 20–50).
- VERP: HMAC is `sha3-224` truncated to **8 bytes**; payload is `json.dumps([type, id, minutes])` with Python's default separators — i.e. `", "` and spaces, e.g. `[0, 12345, 2100000]`; base32 without padding; final address `.lower()`ed. Decoding must uppercase before b32decode and re-add `=` padding.
- `make_msgid(idstring, domain)` (Python stdlib): `<{epoch-ns}.{pid}.{random}.{idstring}@{domain}>` shape — any unique `<...@alias_domain>` works but must be stored in `message_id_matching`.
- `formatdate()` (stdlib): RFC 2822, always `-0000` timezone.
- Header display names are RFC 2047 encoded via `email.header.Header(addr, "utf-8")`; `Contact.new_addr()`/`sl_formataddr` behavior must match for non-ascii names.
- Flanker (`address.parse`, `address.parse_list`) is used for From/To/Cc parsing (lenient, handles RFC 2047); `getaddresses` (stdlib) is used in the reply phase To/Cc rewriting.
- `sanitize_email` lowercases *envelope* addresses and alias lookups, but **contact `website_email` keeps its case** while the uniqueness check is on the case-preserved string.
- Blocked/disabled deliveries still create `EmailLog(blocked=True)` rows — API endpoints (activities, alias counters) surface these.
- `should_disable` date-bucketing uses SQL `func.date(created_at)` (UTC date grouping).
