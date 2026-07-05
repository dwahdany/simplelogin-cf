-- Tables needed by the web-dashboard port that are missing from 0001_init.sql.
-- Column sets mirror app/models.py; the tables also created lazily by the
-- ensure* helpers in src/routes/user.ts (user_audit_log, client, phone_*) keep
-- the exact same table + column names so those CREATE TABLE IF NOT EXISTS
-- calls become no-ops once this migration has run.

-- ===== audit logs (class UserAuditLog / AliasAuditLog) =====
-- user_id / alias_id are plain INTEGERs in the model (no FK): audit rows
-- must survive user/alias deletion.

CREATE TABLE user_audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL,
  user_email VARCHAR(255) NOT NULL,
  action VARCHAR(255) NOT NULL,
  message TEXT
);
CREATE INDEX ix_user_audit_log_user_id ON user_audit_log(user_id);
CREATE INDEX ix_user_audit_log_user_email ON user_audit_log(user_email);
CREATE INDEX ix_user_audit_log_created_at ON user_audit_log(created_at);

CREATE TABLE alias_audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL,
  alias_id INTEGER NOT NULL,
  alias_email VARCHAR(255) NOT NULL,
  action VARCHAR(255) NOT NULL,
  message TEXT
);
CREATE INDEX ix_alias_audit_log_user_id ON alias_audit_log(user_id);
CREATE INDEX ix_alias_audit_log_alias_id ON alias_audit_log(alias_id);
CREATE INDEX ix_alias_audit_log_alias_email ON alias_audit_log(alias_email);
CREATE INDEX ix_alias_audit_log_created_at ON alias_audit_log(created_at);

-- ===== login/MFA support =====

CREATE TABLE mfa_browser (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token VARCHAR(64) NOT NULL UNIQUE,                    -- app-set: random_string(64)
  expires TEXT NOT NULL                                 -- app-set: now + 30 days
);
CREATE INDEX ix_mfa_browser_user_id ON mfa_browser(user_id);

CREATE TABLE social_auth (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  social VARCHAR(128) NOT NULL,                         -- facebook / google / github
  CONSTRAINT uq_social_auth UNIQUE (user_id, social)
);

-- ===== billing extras =====

CREATE TABLE coupon (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  code VARCHAR(128) NOT NULL UNIQUE,
  nb_year INTEGER NOT NULL DEFAULT 1,
  used INTEGER NOT NULL DEFAULT 0,
  used_by_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  is_giveaway INTEGER NOT NULL DEFAULT 0,
  comment TEXT,
  expires_date TEXT
);
CREATE INDEX ix_coupon_used_by_user_id ON coupon(used_by_user_id);

CREATE TABLE payout (                                   -- referral payouts
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount REAL NOT NULL,                                 -- in USD
  payment_method VARCHAR(256) NOT NULL,                 -- BTC, PayPal, etc
  number_upgraded_account INTEGER NOT NULL,
  comment TEXT
);
CREATE INDEX ix_payout_user_id ON payout(user_id);

-- ===== "Sign in with SimpleLogin" OAuth-provider tables (dashboard /app) =====
-- The app page reads client.name and client.icon (a file row) via client_user;
-- redirect_uri / oauth code+token tables are not needed by the dashboard.

CREATE TABLE client (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  oauth_client_id VARCHAR(128) UNIQUE,                  -- model: NOT NULL; kept nullable to match ensureClientTable
  oauth_client_secret VARCHAR(128),                     -- model: NOT NULL; kept nullable to match ensureClientTable
  name VARCHAR(128) NOT NULL,
  home_url VARCHAR(1024),
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  icon_id INTEGER REFERENCES file(id),
  approved INTEGER NOT NULL DEFAULT 0,
  description TEXT,
  referral_id INTEGER REFERENCES referral(id) ON DELETE SET NULL
);
CREATE INDEX ix_client_user_id ON client(user_id);
CREATE INDEX ix_client_icon_id ON client(icon_id);
CREATE INDEX ix_client_referral_id ON client(referral_id);

CREATE TABLE client_user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id INTEGER NOT NULL REFERENCES client(id) ON DELETE CASCADE,
  alias_id INTEGER REFERENCES alias(id) ON DELETE CASCADE,   -- NULL => client sees the real email
  name VARCHAR(128),                                    -- user-chosen name sent to the client
  default_avatar INTEGER NOT NULL DEFAULT 0,
  CONSTRAINT uq_client_user UNIQUE (user_id, client_id)
);
CREATE INDEX ix_client_user_alias_id ON client_user(alias_id);

-- ===== phone tables (classes PhoneNumber / PhoneReservation / PhoneMessage) =====

CREATE TABLE phone_number (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  country_id INTEGER,                                   -- model FK phone_country not ported; plain int like ensurePhoneTables
  number VARCHAR(128) NOT NULL UNIQUE,                  -- with country code, e.g. +33612345678
  active INTEGER NOT NULL DEFAULT 1,
  comment TEXT
);

CREATE TABLE phone_reservation (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  number_id INTEGER NOT NULL REFERENCES phone_number(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  "start" TEXT NOT NULL,                                -- reserved word: always quote
  "end" TEXT NOT NULL
);
CREATE INDEX ix_phone_reservation_user_id ON phone_reservation(user_id);

CREATE TABLE phone_message (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  number_id INTEGER NOT NULL REFERENCES phone_number(id) ON DELETE CASCADE,
  from_number VARCHAR(128) NOT NULL,
  body TEXT
);
