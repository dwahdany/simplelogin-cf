export interface Env {
  DB: D1Database;
  KV: KVNamespace;
  SEND_EMAIL?: SendEmail;

  /** Main alias domain, e.g. "sl.example.com" */
  EMAIL_DOMAIN: string;
  /** Comma-separated list of public alias domains */
  ALIAS_DOMAINS: string;
  /** Comma-separated list of premium-only alias domains */
  PREMIUM_ALIAS_DOMAINS: string;
  /** Base URL of the app, used in emails/links */
  URL: string;
  MAX_NB_EMAIL_FREE_PLAN: string;
  DISABLE_REGISTRATION: string;
  /** Secret used to sign alias suffixes and other tokens (wrangler secret) */
  FLASK_SECRET?: string;
}
