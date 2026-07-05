/**
 * D1 row types for tables the API layer touches.
 * Booleans are stored as INTEGER 0/1; timestamps as "YYYY-MM-DD HH:MM:SS+00:00".
 * Column names match migrations/0001_init.sql exactly.
 */

export interface BaseRow {
  id: number;
  created_at: string;
  updated_at: string | null;
}

export interface UserRow extends BaseRow {
  password: string | null;
  email: string;
  name: string | null;
  is_admin: number;
  alias_generator: number; // 1=word, 2=uuid
  notification: number;
  activated: number;
  disabled: number;
  profile_picture_id: number | null;
  otp_secret: string | null;
  enable_otp: number;
  last_otp: string | null;
  fido_uuid: string | null;
  default_alias_custom_domain_id: number | null;
  default_alias_public_domain_id: number | null;
  lifetime: number;
  paid_lifetime: number;
  lifetime_coupon_id: number | null;
  trial_end: string | null;
  default_mailbox_id: number | null;
  sender_format: number;
  sender_format_updated_at: string | null;
  replace_reverse_alias: number;
  referral_id: number | null;
  intro_shown: number;
  max_spam_score: number | null;
  newsletter_alias_id: number | null;
  include_sender_in_reverse_alias: number;
  random_alias_suffix: number; // 0=word, 1=random_string
  expand_alias_info: number;
  ignore_loop_email: number;
  alternative_id: string | null;
  disable_automatic_alias_note: number;
  one_click_unsubscribe_block_sender: number;
  include_website_in_one_click_alias: number;
  directory_quota: number;
  subdomain_quota: number;
  disable_import: number;
  can_use_phone: number;
  phone_quota: number | null;
  block_behaviour: "return_2xx" | "return_5xx";
  include_header_email_header: number;
  enable_data_breach_check: number;
  flags: number; // bit 0 (1) = FLAG_FREE_DISABLE_CREATE_CONTACTS, bit 2 (4) = FLAG_FREE_OLD_ALIAS_LIMIT
  unsub_behaviour: number;
  delete_on: string | null;
  alias_delete_action: number; // 0=MoveToTrash, 1=DeleteImmediately
}

export interface ApiKeyRow extends BaseRow {
  user_id: number;
  code: string;
  name: string | null;
  last_used: string | null;
  times: number;
  sudo_mode_at: string | null;
}

export interface AliasRow extends BaseRow {
  user_id: number;
  email: string;
  name: string | null;
  enabled: number;
  flags: number;
  custom_domain_id: number | null;
  automatic_creation: number;
  directory_id: number | null;
  note: string | null;
  mailbox_id: number;
  disable_pgp: number;
  cannot_be_disabled: number;
  disable_email_spoofing_check: number;
  batch_import_id: number | null;
  original_owner_id: number | null;
  pinned: number;
  transfer_token: string | null;
  transfer_token_expiration: string | null;
  hibp_last_check: string | null;
  last_email_log_id: number | null;
  delete_on: string | null; // non-NULL => alias is in trash
  delete_reason: number | null;
}

export interface ContactRow extends BaseRow {
  user_id: number;
  alias_id: number;
  name: string | null;
  website_email: string;
  website_from: string | null;
  reply_email: string;
  is_cc: number;
  pgp_public_key: string | null;
  pgp_finger_print: string | null;
  mail_from: string | null;
  invalid_email: number;
  block_forward: number;
  automatic_created: number | null;
  flags: number;
}

export interface EmailLogRow extends BaseRow {
  user_id: number;
  contact_id: number;
  alias_id: number | null;
  is_reply: number;
  blocked: number;
  bounced: number;
  auto_replied: number;
  is_spam: number;
  spam_score: number | null;
  spam_status: string | null;
  spam_report: string | null;
  refused_email_id: number | null;
  mailbox_id: number | null;
  bounced_mailbox_id: number | null;
  message_id: string | null;
  sl_message_id: string | null;
}

export interface MailboxRow extends BaseRow {
  user_id: number;
  email: string;
  verified: number;
  force_spf: number;
  new_email: string | null;
  pgp_public_key: string | null;
  pgp_finger_print: string | null;
  disable_pgp: number;
  nb_failed_checks: number;
  disabled: number;
  flags: number; // bit 0 = FLAG_ADMIN_DISABLED
  generic_subject: string | null;
}

export interface CustomDomainRow extends BaseRow {
  user_id: number;
  domain: string;
  name: string | null;
  verified: number;
  dkim_verified: number;
  spf_verified: number;
  dmarc_verified: number;
  catch_all: number;
  random_prefix_generation: number;
  nb_failed_checks: number;
  ownership_verified: number;
  ownership_txt_token: string | null;
  is_sl_subdomain: number;
  partner_id: number | null;
  pending_deletion: number;
}

/** class SLDomain in the Flask app */
export interface PublicDomainRow extends BaseRow {
  domain: string;
  premium_only: number;
  can_use_subdomain: number;
  partner_id: number | null;
  hidden: number;
  order: number;
  use_as_reverse_alias: number;
}

export interface DeletedAliasRow extends BaseRow {
  email: string;
  reason: number;
  alias_id: number | null;
}

export interface DomainDeletedAliasRow extends BaseRow {
  email: string;
  domain_id: number;
  user_id: number;
  reason: number;
  alias_id: number | null;
}

export interface DirectoryRow extends BaseRow {
  user_id: number;
  name: string;
  disabled: number;
}

export interface NotificationRow extends BaseRow {
  user_id: number;
  message: string;
  title: string | null;
  read: number;
}

export interface AccountActivationRow extends BaseRow {
  user_id: number;
  code: string;
  tries: number;
}

export interface ResetPasswordCodeRow extends BaseRow {
  user_id: number;
  code: string;
  expired: string;
}

export interface ApiCookieTokenRow extends BaseRow {
  code: string;
  user_id: number;
  api_key_id: number;
}

export interface AliasUsedOnRow extends BaseRow {
  alias_id: number;
  user_id: number;
  hostname: string;
}

export interface AliasMailboxRow extends BaseRow {
  alias_id: number;
  mailbox_id: number;
}

export interface FileRow extends BaseRow {
  path: string;
  user_id: number | null;
}

export interface JobRow extends BaseRow {
  name: string;
  payload: string | null;
  taken: number;
  run_at: string | null;
  state: number;
  attempts: number;
  taken_at: string | null;
  priority: number;
}

export interface SubscriptionRow extends BaseRow {
  cancel_url: string;
  update_url: string;
  subscription_id: string;
  event_time: string;
  next_bill_date: string; // 'YYYY-MM-DD'
  cancelled: number;
  plan: "monthly" | "yearly";
  user_id: number;
}

export interface AppleSubscriptionRow extends BaseRow {
  user_id: number;
  expires_date: string;
  original_transaction_id: string;
  receipt_data: string;
  plan: "monthly" | "yearly";
  product_id: string | null;
}

export interface ManualSubscriptionRow extends BaseRow {
  user_id: number;
  end_at: string;
  comment: string | null;
  is_giveaway: number;
}

export interface CoinbaseSubscriptionRow extends BaseRow {
  user_id: number;
  end_at: string;
  code: string | null;
}

export interface PartnerUserRow extends BaseRow {
  user_id: number;
  partner_id: number;
  external_user_id: string;
  partner_email: string | null;
}

export interface PartnerSubscriptionRow extends BaseRow {
  partner_user_id: number;
  end_at: string | null;
  lifetime: number;
}
