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
  /**
   * Presence-based flag, like the Flask app ("0" still counts as set!) —
   * EXCEPT "" which counts as unset (deviation: miniflare cannot delete a
   * wrangler var in tests, so "" is the test-config "unset" spelling).
   */
  DISABLE_REGISTRATION?: string;
  /**
   * Expected MX records for custom-domain verification, Flask format:
   * "10 mx1.example.com.,20 mx2.example.com.". On this deployment the hosts
   * are Cloudflare Email Routing's route1/2/3.mx.cloudflare.net.
   * "" counts as unset (same test-config reason as DISABLE_REGISTRATION).
   */
  EMAIL_SERVERS_WITH_PRIORITY?: string;
  /**
   * Scoped Cloudflare API token (Zone:Read, DNS:Edit, Email Routing
   * Rules:Edit) enabling one-click domain provisioning from the dashboard.
   * Set via `wrangler secret put CF_API_TOKEN`; unset (or "") disables the
   * feature: the button is hidden and the POST form-name is ignored (falls
   * through to the page render like an unknown form-name).
   */
  CF_API_TOKEN?: string;
  /** Worker name the provisioned catch-all routes to; default "simplelogin". */
  CF_WORKER_NAME?: string;
  /** Max subdomains per user (Flask config.MAX_NB_SUBDOMAIN, default 5). */
  MAX_NB_SUBDOMAIN?: string;
  /** Max directories per user (Flask config.MAX_NB_DIRECTORY, default 50). */
  MAX_NB_DIRECTORY?: string;
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
  /**
   * PKCS#8 PEM RSA private key used to DKIM-sign outbound mail. When unset,
   * mail is sent unsigned (relies on the send binding / MTA to sign).
   */
  DKIM_PRIVATE_KEY?: string;
  /** DKIM selector; defaults to "dkim" (matches the Flask app). */
  DKIM_SELECTOR?: string;
  /**
   * Alias-forward delivery mode. "rewrite" rebuilds the message with the
   * reverse alias as From (Flask parity) and sends via SEND_EMAIL — only
   * deliverable to strict receivers when the domain is onboarded onto Email
   * Sending (paid). Anything else = passthrough via message.forward().
   */
  FORWARD_MODE?: string;
}
