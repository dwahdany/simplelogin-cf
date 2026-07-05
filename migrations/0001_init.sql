-- ===== helper note: every table's base columns =====
-- id INTEGER PRIMARY KEY AUTOINCREMENT
-- created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00')
-- updated_at TEXT NULL  -- app must set on UPDATE

CREATE TABLE file (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  path VARCHAR(128) NOT NULL UNIQUE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX ix_file_user_id ON file(user_id);

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  password VARCHAR(128),                                -- bcrypt hash, NFKC-normalized input
  email VARCHAR(256) NOT NULL UNIQUE,
  name VARCHAR(128),
  is_admin INTEGER NOT NULL DEFAULT 0,
  alias_generator INTEGER NOT NULL DEFAULT 1,           -- AliasGeneratorEnum.word
  notification INTEGER NOT NULL DEFAULT 1,
  activated INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  profile_picture_id INTEGER REFERENCES file(id),
  otp_secret VARCHAR(16),
  enable_otp INTEGER NOT NULL DEFAULT 0,
  last_otp VARCHAR(12),
  fido_uuid VARCHAR(128) UNIQUE,
  default_alias_custom_domain_id INTEGER REFERENCES custom_domain(id) ON DELETE SET NULL,
  default_alias_public_domain_id INTEGER REFERENCES public_domain(id) ON DELETE SET NULL,
  lifetime INTEGER NOT NULL DEFAULT 0,
  paid_lifetime INTEGER NOT NULL DEFAULT 0,
  lifetime_coupon_id INTEGER REFERENCES lifetime_coupon(id) ON DELETE SET NULL,
  trial_end TEXT,                                       -- app-set: now + 7 days 1 hour (NULL for partner users)
  default_mailbox_id INTEGER REFERENCES mailbox(id),
  sender_format INTEGER NOT NULL DEFAULT 0,             -- SenderFormatEnum.AT
  sender_format_updated_at TEXT,
  replace_reverse_alias INTEGER NOT NULL DEFAULT 0,
  referral_id INTEGER REFERENCES referral(id) ON DELETE SET NULL,
  intro_shown INTEGER NOT NULL DEFAULT 0,
  max_spam_score INTEGER,
  newsletter_alias_id INTEGER REFERENCES alias(id) ON DELETE SET NULL,
  include_sender_in_reverse_alias INTEGER NOT NULL DEFAULT 1,   -- python default True (PG server default 0)
  random_alias_suffix INTEGER NOT NULL DEFAULT 0,       -- python default word=0 (PG server default '1')
  expand_alias_info INTEGER NOT NULL DEFAULT 0,
  ignore_loop_email INTEGER NOT NULL DEFAULT 0,
  alternative_id VARCHAR(128) UNIQUE,                   -- app-set: uuid4
  disable_automatic_alias_note INTEGER NOT NULL DEFAULT 0,
  one_click_unsubscribe_block_sender INTEGER NOT NULL DEFAULT 0,
  include_website_in_one_click_alias INTEGER NOT NULL DEFAULT 1, -- python default True
  directory_quota INTEGER NOT NULL DEFAULT 50,
  subdomain_quota INTEGER NOT NULL DEFAULT 5,
  disable_import INTEGER NOT NULL DEFAULT 0,
  can_use_phone INTEGER NOT NULL DEFAULT 0,
  phone_quota INTEGER,
  block_behaviour TEXT NOT NULL DEFAULT 'return_2xx'
    CHECK (block_behaviour IN ('return_2xx','return_5xx')),     -- PG enum stored by NAME
  include_header_email_header INTEGER NOT NULL DEFAULT 1,
  enable_data_breach_check INTEGER NOT NULL DEFAULT 0,
  flags INTEGER NOT NULL DEFAULT 1,                     -- python default FLAG_FREE_DISABLE_CREATE_CONTACTS=1
  unsub_behaviour INTEGER NOT NULL DEFAULT 2,           -- python default PreserveOriginal=2
  delete_on TEXT,
  alias_delete_action INTEGER NOT NULL DEFAULT 0        -- MoveToTrash
);
CREATE INDEX ix_users_activated_trial_end_lifetime ON users(activated, trial_end, lifetime);
CREATE INDEX ix_users_delete_on ON users(delete_on);
CREATE INDEX ix_users_default_mailbox_id ON users(default_mailbox_id);
CREATE INDEX ix_users_default_alias_custom_domain_id ON users(default_alias_custom_domain_id);
CREATE INDEX ix_users_profile_picture_id ON users(profile_picture_id);
CREATE INDEX ix_users_referral_id ON users(referral_id);
CREATE INDEX ix_users_newsletter_alias_id ON users(newsletter_alias_id);

CREATE TABLE referral (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(512),
  code VARCHAR(128) NOT NULL UNIQUE
);
CREATE INDEX ix_referral_user_id ON referral(user_id);

CREATE TABLE lifetime_coupon (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  code VARCHAR(128) NOT NULL UNIQUE,
  nb_used INTEGER NOT NULL,
  paid INTEGER NOT NULL DEFAULT 0,
  comment TEXT
);

CREATE TABLE partner (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  name VARCHAR(128) NOT NULL UNIQUE,
  contact_email VARCHAR(128) NOT NULL UNIQUE
);

CREATE TABLE public_domain (                            -- class SLDomain
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  domain VARCHAR(128) NOT NULL UNIQUE,
  premium_only INTEGER NOT NULL DEFAULT 0,
  can_use_subdomain INTEGER NOT NULL DEFAULT 0,
  partner_id INTEGER REFERENCES partner(id) ON DELETE CASCADE,
  hidden INTEGER NOT NULL DEFAULT 0,
  "order" INTEGER NOT NULL DEFAULT 0,                   -- reserved word: always quote
  use_as_reverse_alias INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE custom_domain (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain VARCHAR(128) NOT NULL UNIQUE,
  name VARCHAR(128),
  verified INTEGER NOT NULL DEFAULT 0,
  dkim_verified INTEGER NOT NULL DEFAULT 0,
  spf_verified INTEGER NOT NULL DEFAULT 0,
  dmarc_verified INTEGER NOT NULL DEFAULT 0,
  catch_all INTEGER NOT NULL DEFAULT 0,
  random_prefix_generation INTEGER NOT NULL DEFAULT 0,
  nb_failed_checks INTEGER NOT NULL DEFAULT 0,
  ownership_verified INTEGER NOT NULL DEFAULT 0,
  ownership_txt_token VARCHAR(128),                     -- app-set: random_string(30)
  is_sl_subdomain INTEGER NOT NULL DEFAULT 0,
  partner_id INTEGER REFERENCES partner(id),
  pending_deletion INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_custom_domain_user_id ON custom_domain(user_id);
CREATE INDEX ix_custom_domain_pending_deletion ON custom_domain(pending_deletion);
CREATE UNIQUE INDEX ix_unique_domain ON custom_domain(domain) WHERE ownership_verified;

CREATE TABLE mailbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email VARCHAR(256) NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  force_spf INTEGER NOT NULL DEFAULT 1,
  new_email VARCHAR(256) UNIQUE,
  pgp_public_key TEXT,
  pgp_finger_print VARCHAR(512),
  disable_pgp INTEGER NOT NULL DEFAULT 0,
  nb_failed_checks INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  flags INTEGER NOT NULL DEFAULT 0,                     -- bit 0 = FLAG_ADMIN_DISABLED
  generic_subject VARCHAR(78),
  CONSTRAINT uq_mailbox_user UNIQUE (user_id, email)
);
CREATE INDEX ix_mailbox_email ON mailbox(email);
CREATE INDEX ix_mailbox_pgp_finger_print ON mailbox(pgp_finger_print);

CREATE TABLE directory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(128) NOT NULL UNIQUE,
  disabled INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_directory_user_id ON directory(user_id);

CREATE TABLE directory_mailbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  directory_id INTEGER NOT NULL REFERENCES directory(id) ON DELETE CASCADE,
  mailbox_id INTEGER NOT NULL REFERENCES mailbox(id) ON DELETE CASCADE,
  CONSTRAINT uq_directory_mailbox UNIQUE (directory_id, mailbox_id)
);

CREATE TABLE batch_import (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  file_id INTEGER NOT NULL REFERENCES file(id) ON DELETE CASCADE,
  processed INTEGER NOT NULL DEFAULT 0,
  summary TEXT
);
CREATE INDEX ix_batch_import_file_id ON batch_import(file_id);
CREATE INDEX ix_batch_import_user_id ON batch_import(user_id);

CREATE TABLE alias (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email VARCHAR(128) NOT NULL UNIQUE,
  name VARCHAR(128),
  enabled INTEGER NOT NULL DEFAULT 1,
  flags INTEGER NOT NULL DEFAULT 0,                     -- bit 0 = FLAG_PARTNER_CREATED
  custom_domain_id INTEGER REFERENCES custom_domain(id) ON DELETE CASCADE,
  automatic_creation INTEGER NOT NULL DEFAULT 0,
  directory_id INTEGER REFERENCES directory(id) ON DELETE CASCADE,
  note TEXT,
  mailbox_id INTEGER NOT NULL REFERENCES mailbox(id) ON DELETE CASCADE,
  disable_pgp INTEGER NOT NULL DEFAULT 0,
  cannot_be_disabled INTEGER NOT NULL DEFAULT 0,
  disable_email_spoofing_check INTEGER NOT NULL DEFAULT 0,
  batch_import_id INTEGER REFERENCES batch_import(id) ON DELETE SET NULL,
  original_owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  pinned INTEGER NOT NULL DEFAULT 0,
  transfer_token VARCHAR(64) UNIQUE,
  transfer_token_expiration TEXT,                       -- app-set: utcnow on create
  hibp_last_check TEXT,
  -- ts_vector dropped (Postgres full-text generated column)
  last_email_log_id INTEGER,
  delete_on TEXT,                                       -- non-NULL => alias is in trash
  delete_reason INTEGER                                 -- AliasDeleteReason int
);
CREATE INDEX ix_alias_user_id ON alias(user_id);
CREATE INDEX ix_alias_flags ON alias(flags);
CREATE INDEX ix_alias_custom_domain_id ON alias(custom_domain_id);
CREATE INDEX ix_alias_directory_id ON alias(directory_id);
CREATE INDEX ix_alias_mailbox_id ON alias(mailbox_id);
CREATE INDEX ix_alias_hibp_last_check ON alias(hibp_last_check);
CREATE INDEX ix_alias_original_owner_id ON alias(original_owner_id);
CREATE INDEX ix_alias_delete_on ON alias(delete_on);

CREATE TABLE alias_mailbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  alias_id INTEGER NOT NULL REFERENCES alias(id) ON DELETE CASCADE,
  mailbox_id INTEGER NOT NULL REFERENCES mailbox(id) ON DELETE CASCADE,
  CONSTRAINT uq_alias_mailbox UNIQUE (alias_id, mailbox_id)
);
CREATE INDEX ix_alias_mailbox_mailbox_id ON alias_mailbox(mailbox_id);

CREATE TABLE alias_used_on (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  alias_id INTEGER NOT NULL REFERENCES alias(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hostname VARCHAR(1024) NOT NULL,
  CONSTRAINT uq_alias_used UNIQUE (alias_id, hostname)
);
CREATE INDEX ix_alias_used_on_user_id ON alias_used_on(user_id);

CREATE TABLE contact (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  alias_id INTEGER NOT NULL REFERENCES alias(id) ON DELETE CASCADE,
  name VARCHAR(512) DEFAULT NULL,
  website_email VARCHAR(512) NOT NULL,
  website_from VARCHAR(1024),
  reply_email VARCHAR(512) NOT NULL,                    -- the reverse-alias
  is_cc INTEGER NOT NULL DEFAULT 0,
  pgp_public_key TEXT,
  pgp_finger_print VARCHAR(512),
  mail_from TEXT,
  invalid_email INTEGER NOT NULL DEFAULT 0,
  block_forward INTEGER NOT NULL DEFAULT 0,
  automatic_created INTEGER DEFAULT 0,                  -- NULLABLE bool
  flags INTEGER NOT NULL DEFAULT 0,                     -- bit 0 = FLAG_PARTNER_CREATED
  CONSTRAINT uq_contact UNIQUE (alias_id, website_email)
);
CREATE INDEX ix_contact_user_id_id ON contact(user_id, id);
CREATE INDEX ix_contact_reply_email ON contact(reply_email);
CREATE INDEX ix_contact_pgp_finger_print ON contact(pgp_finger_print);

CREATE TABLE email_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  contact_id INTEGER NOT NULL REFERENCES contact(id) ON DELETE CASCADE,
  alias_id INTEGER REFERENCES alias(id) ON DELETE CASCADE,
  is_reply INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0,
  bounced INTEGER NOT NULL DEFAULT 0,
  auto_replied INTEGER NOT NULL DEFAULT 0,
  is_spam INTEGER NOT NULL DEFAULT 0,
  spam_score REAL,
  spam_status TEXT,
  spam_report TEXT,                                     -- JSON
  refused_email_id INTEGER REFERENCES refused_email(id) ON DELETE SET NULL,
  mailbox_id INTEGER REFERENCES mailbox(id) ON DELETE CASCADE,
  bounced_mailbox_id INTEGER REFERENCES mailbox(id) ON DELETE CASCADE,
  message_id VARCHAR(1024),                             -- app truncates to 250 chars on insert
  sl_message_id VARCHAR(512)
);
CREATE INDEX ix_email_log_created_at ON email_log(created_at);
CREATE INDEX ix_email_log_contact_id ON email_log(contact_id);
CREATE INDEX ix_email_log_alias_id ON email_log(alias_id);
CREATE INDEX ix_email_log_mailbox_id ON email_log(mailbox_id);
CREATE INDEX ix_email_log_bounced_mailbox_id ON email_log(bounced_mailbox_id);
CREATE INDEX ix_email_log_refused_email_id ON email_log(refused_email_id);
CREATE INDEX ix_email_log_user_id_email_log_id ON email_log(user_id, id);

CREATE TABLE deleted_alias (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  email VARCHAR(256) NOT NULL UNIQUE,
  reason INTEGER NOT NULL DEFAULT 0,                    -- AliasDeleteReason
  alias_id INTEGER                                      -- no FK on purpose
);
CREATE INDEX ix_deleted_alias_alias_id ON deleted_alias(alias_id);

CREATE TABLE domain_deleted_alias (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  email VARCHAR(256) NOT NULL,
  domain_id INTEGER NOT NULL REFERENCES custom_domain(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reason INTEGER NOT NULL DEFAULT 0,
  alias_id INTEGER,
  CONSTRAINT uq_domain_trash UNIQUE (domain_id, email)
);
CREATE INDEX ix_domain_deleted_alias_user_id ON domain_deleted_alias(user_id);
CREATE INDEX ix_domain_deleted_alias_alias_id ON domain_deleted_alias(alias_id);

CREATE TABLE api_key (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code VARCHAR(128) NOT NULL UNIQUE,                    -- app-set: random_string(60) lowercase a-z
  name VARCHAR(128),
  last_used TEXT,
  times INTEGER NOT NULL DEFAULT 0,
  sudo_mode_at TEXT
);
CREATE INDEX ix_api_key_user_id ON api_key(user_id);

CREATE TABLE api_cookie_token (                         -- class ApiToCookieToken
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  code VARCHAR(128) NOT NULL UNIQUE,                    -- app-set: secrets.token_urlsafe(32)
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  api_key_id INTEGER NOT NULL REFERENCES api_key(id) ON DELETE CASCADE
);
CREATE INDEX ix_api_to_cookie_token_api_key_id ON api_cookie_token(api_key_id);
CREATE INDEX ix_api_to_cookie_token_user_id ON api_cookie_token(user_id);

CREATE TABLE account_activation (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  code VARCHAR(10) NOT NULL,
  tries INTEGER NOT NULL DEFAULT 3,
  CONSTRAINT account_activation_tries_positive CHECK (tries >= 0)
);

CREATE TABLE activation_code (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code VARCHAR(128) NOT NULL UNIQUE,
  expired TEXT NOT NULL                                 -- app-set: now + 1 hour
);
CREATE INDEX ix_activation_code_user_id ON activation_code(user_id);

CREATE TABLE reset_password_code (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code VARCHAR(128) NOT NULL UNIQUE,
  expired TEXT NOT NULL                                 -- app-set: now + 1 hour
);
CREATE INDEX ix_reset_password_code_user_id ON reset_password_code(user_id);

CREATE TABLE email_change (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  new_email VARCHAR(256) NOT NULL UNIQUE,
  code VARCHAR(128) NOT NULL UNIQUE,
  expired TEXT NOT NULL                                 -- app-set: now + 12 hours
);
CREATE INDEX ix_email_change_user_id ON email_change(user_id);

CREATE TABLE mailbox_activation (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  mailbox_id INTEGER NOT NULL REFERENCES mailbox(id) ON DELETE CASCADE,
  code VARCHAR(32) NOT NULL,
  tries INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_mailbox_activation_mailbox_id ON mailbox_activation(mailbox_id);
CREATE INDEX ix_mailbox_activation_code ON mailbox_activation(code);

CREATE TABLE recovery_code (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code VARCHAR(64) NOT NULL,                            -- HMAC-SHA3-224, base64url no padding
  used INTEGER NOT NULL DEFAULT 0,
  used_at TEXT,
  CONSTRAINT uq_recovery_code UNIQUE (user_id, code)
);

CREATE TABLE fido (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  credential_id VARCHAR(256) NOT NULL UNIQUE,
  uuid VARCHAR(128) NOT NULL REFERENCES users(fido_uuid) ON DELETE CASCADE,  -- FK to non-PK unique col
  public_key VARCHAR(1024) NOT NULL UNIQUE,
  sign_count INTEGER NOT NULL,
  name VARCHAR(128) NOT NULL,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  credential_type VARCHAR(32),
  authenticator_attachment VARCHAR(32),
  transports TEXT,                                      -- JSON array e.g. ["usb","nfc"]
  aaguid VARCHAR(36)
);
CREATE INDEX ix_fido_credential_id ON fido(credential_id);
CREATE INDEX ix_fido_user_id ON fido(user_id);

CREATE TABLE notification (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message TEXT NOT NULL,
  title VARCHAR(512),
  read INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_notification_user_id ON notification(user_id);

CREATE TABLE refused_email (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  full_report_path VARCHAR(128) NOT NULL UNIQUE,        -- R2 object key
  path VARCHAR(128) UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  delete_at TEXT NOT NULL,                              -- app-set: now + 7 days
  deleted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_refused_email_user_id ON refused_email(user_id);

CREATE TABLE job (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  name VARCHAR(128) NOT NULL,
  payload TEXT,                                         -- JSON
  taken INTEGER NOT NULL DEFAULT 0,
  run_at TEXT,
  state INTEGER NOT NULL DEFAULT 0,                     -- JobState: 0 ready,1 taken,2 done,3 error
  attempts INTEGER NOT NULL DEFAULT 0,
  taken_at TEXT,
  priority INTEGER NOT NULL DEFAULT 50                  -- JobPriority
);
CREATE INDEX ix_state_run_at_taken_at_priority_attempts
  ON job(state, run_at, taken_at, priority, attempts);

CREATE TABLE subscription (                             -- Paddle
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  cancel_url VARCHAR(1024) NOT NULL,
  update_url VARCHAR(1024) NOT NULL,
  subscription_id VARCHAR(1024) NOT NULL UNIQUE,
  event_time TEXT NOT NULL,
  next_bill_date TEXT NOT NULL,                         -- DATE: 'YYYY-MM-DD'
  cancelled INTEGER NOT NULL DEFAULT 0,
  plan TEXT NOT NULL CHECK (plan IN ('monthly','yearly')),  -- PG enum stored by NAME
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE manual_subscription (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  end_at TEXT NOT NULL,
  comment TEXT,
  is_giveaway INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE coinbase_subscription (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  end_at TEXT NOT NULL,
  code VARCHAR(64)
);

CREATE TABLE apple_subscription (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  expires_date TEXT NOT NULL,
  original_transaction_id VARCHAR(256) NOT NULL UNIQUE,
  receipt_data TEXT NOT NULL,
  plan TEXT NOT NULL CHECK (plan IN ('monthly','yearly')),
  product_id VARCHAR(256)
);

CREATE TABLE partner_user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  partner_id INTEGER NOT NULL REFERENCES partner(id) ON DELETE CASCADE,
  external_user_id VARCHAR(128) NOT NULL,
  partner_email VARCHAR(255),
  CONSTRAINT uq_partner_id_external_user_id UNIQUE (partner_id, external_user_id)
);
CREATE INDEX ix_partner_user_user_id ON partner_user(user_id);

CREATE TABLE partner_subscription (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  partner_user_id INTEGER NOT NULL UNIQUE REFERENCES partner_user(id) ON DELETE CASCADE,
  end_at TEXT,                                          -- NULLABLE (lifetime partner subs)
  lifetime INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_partner_subscription_end_at ON partner_subscription(end_at);

-- ===== forwarding-support tables =====

CREATE TABLE domain_mailbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  domain_id INTEGER NOT NULL REFERENCES custom_domain(id) ON DELETE CASCADE,
  mailbox_id INTEGER NOT NULL REFERENCES mailbox(id) ON DELETE CASCADE,
  CONSTRAINT uq_domain_mailbox UNIQUE (domain_id, mailbox_id)
);

CREATE TABLE auto_create_rule (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  custom_domain_id INTEGER NOT NULL REFERENCES custom_domain(id) ON DELETE CASCADE,
  regex VARCHAR(512) NOT NULL,
  "order" INTEGER NOT NULL DEFAULT 0,
  display_name VARCHAR(128),
  CONSTRAINT uq_auto_create_rule_order UNIQUE (custom_domain_id, "order")
);

CREATE TABLE auto_create_rule__mailbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  auto_create_rule_id INTEGER NOT NULL REFERENCES auto_create_rule(id) ON DELETE CASCADE,
  mailbox_id INTEGER NOT NULL REFERENCES mailbox(id) ON DELETE CASCADE,
  CONSTRAINT uq_auto_create_rule_mailbox UNIQUE (auto_create_rule_id, mailbox_id)
);

CREATE TABLE authorized_address (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mailbox_id INTEGER NOT NULL REFERENCES mailbox(id) ON DELETE CASCADE,
  email VARCHAR(256) NOT NULL,
  CONSTRAINT uq_authorize_address UNIQUE (mailbox_id, email)
);
CREATE INDEX ix_authorized_address_user_id ON authorized_address(user_id);

CREATE TABLE message_id_matching (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  sl_message_id VARCHAR(512) NOT NULL UNIQUE,
  original_message_id VARCHAR(1024) NOT NULL UNIQUE,
  email_log_id INTEGER REFERENCES email_log(id) ON DELETE CASCADE
);
CREATE INDEX ix_message_id_matching_email_log_id ON message_id_matching(email_log_id);

CREATE TABLE sent_alert (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_email VARCHAR(256) NOT NULL,
  alert_type VARCHAR(256) NOT NULL
);
CREATE INDEX ix_sent_alert_user_id ON sent_alert(user_id);
CREATE INDEX ix_sent_alert_to_email ON sent_alert(to_email);
CREATE INDEX ix_sent_alert_alert_type ON sent_alert(alert_type);

CREATE TABLE bounce (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  email VARCHAR(256) NOT NULL,
  info TEXT
);
CREATE INDEX ix_bounce_email ON bounce(email);
CREATE INDEX ix_bounce_created_at ON bounce(created_at);

CREATE TABLE transactional_email (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  email VARCHAR(256) NOT NULL
);
CREATE INDEX ix_transactional_email_created_at ON transactional_email(created_at);

CREATE TABLE ignored_email (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  mail_from VARCHAR(512) NOT NULL,
  rcpt_to VARCHAR(512) NOT NULL
);

CREATE TABLE ignore_bounce_sender (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  mail_from VARCHAR(512) NOT NULL UNIQUE
);

CREATE TABLE deleted_directory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  name VARCHAR(128) NOT NULL UNIQUE
);

CREATE TABLE deleted_subdomain (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  domain VARCHAR(128) NOT NULL UNIQUE
);

CREATE TABLE hibp (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  name VARCHAR(512) NOT NULL UNIQUE,
  description TEXT,
  date TEXT
);

CREATE TABLE alias_hibp (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  alias_id INTEGER REFERENCES alias(id) ON DELETE CASCADE,
  hibp_id INTEGER REFERENCES hibp(id) ON DELETE CASCADE,
  CONSTRAINT uq_alias_hibp UNIQUE (alias_id, hibp_id)
);
CREATE INDEX ix_alias_hibp_hibp_id ON alias_hibp(hibp_id);
