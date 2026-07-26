-- Drop the Cloudflare OAuth grant storage introduced by 0004_cf_oauth.sql.
--
-- WHY: the "connect your Cloudflare account" model stored a delegated,
-- refreshable grant (AES-GCM ciphertext, one row per user) that could change
-- a user's DNS long after they clicked anything. It is replaced by a
-- ONE-SHOT authorization: the user approves at Cloudflare, the access token
-- is spent inside that single request and revoked in a `finally`, and
-- nothing is ever written here. `offline_access` is no longer requested, so
-- no refresh token exists to store in the first place — see
-- src/lib/cfoauth.ts and src/web/cloudflare-pages.ts.
--
-- 0004 is left untouched (it is already applied in production); this is the
-- forward migration that removes what it created. Dropping the table is
-- exactly the intent: any row still in it is a credential nobody should be
-- holding. Cloudflare-side, the previous build revoked a grant on every path
-- that dropped it (disconnect, account deletion); anything still live can be
-- withdrawn by the account owner under Manage Account > Authorized apps.

DROP INDEX IF EXISTS ix_cf_oauth_token_user_id;
DROP TABLE IF EXISTS cf_oauth_token;
