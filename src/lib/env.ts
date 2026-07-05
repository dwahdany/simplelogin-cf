export interface Env {
  DB: D1Database;
  KV: KVNamespace;
  SEND_EMAIL?: SendEmail;

  /** Main alias domain, e.g. "sl.example.com" */
  EMAIL_DOMAIN: string;
  /** First/default alias domain, defaults to EMAIL_DOMAIN */
  FIRST_ALIAS_DOMAIN?: string;
  /** Comma-separated list of public alias domains */
  ALIAS_DOMAINS: string;
  /** Comma-separated list of premium-only alias domains */
  PREMIUM_ALIAS_DOMAINS: string;
  /** Base URL of the app, used in emails/links */
  URL: string;
  MAX_NB_EMAIL_FREE_PLAN: string;
  /** Presence-based flag, like the Flask app ("0" still counts as set!) */
  DISABLE_REGISTRATION?: string;
  /** Presence-based flag disabling all rate limits */
  DISABLE_RATE_LIMIT?: string;
  /** Presence-based flag disabling signed alias suffixes */
  DISABLE_ALIAS_SUFFIX?: string;
  /** "100/day;50/hour;5/minute" flask-limiter spec for alias creation */
  ALIAS_LIMIT?: string;
  /**
   * Secret for signing (alias suffixes, mfa keys...). Set via
   * `wrangler secret put FLASK_SECRET`; provided as a plain binding in tests.
   */
  FLASK_SECRET: string;
}
