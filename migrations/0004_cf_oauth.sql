-- Cloudflare OAuth grant storage for one-click domain provisioning.
-- No Flask counterpart: this is Cloudflare-platform-specific (self-managed
-- OAuth became generally available 2026-06-03), replacing the static
-- CF_API_TOKEN secret with a delegated, dashboard-revocable grant.
--
-- One row per SimpleLogin user who has connected a Cloudflare account.
-- Tokens are stored ENCRYPTED (AES-GCM, key derived from FLASK_SECRET) —
-- see src/lib/cfoauth.ts — so a D1 read alone does not yield usable
-- Cloudflare credentials.

CREATE TABLE cf_oauth_token (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now') || '+00:00'),
  updated_at TEXT,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  -- AES-GCM ciphertext, base64: "<iv>.<ciphertext>"
  access_token_enc TEXT NOT NULL,
  refresh_token_enc TEXT,
  -- canonical timestamp; refresh when now >= expires_at - skew
  expires_at TEXT,
  -- space-separated scope list as granted by Cloudflare
  scopes TEXT,
  -- Cloudflare account this grant belongs to (display + sanity checks)
  cf_account_id VARCHAR(64),
  cf_account_name VARCHAR(255)
);
CREATE INDEX ix_cf_oauth_token_user_id ON cf_oauth_token(user_id);
