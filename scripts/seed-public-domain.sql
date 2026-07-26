-- Seed a PUBLIC (shared) alias domain.
--
-- One row per domain that ALL users may create aliases on (Flask: SLDomain,
-- app/models.py). Schema: migrations/0001_init.sql `public_domain`.
--
-- Usage: edit the VALUES below, then
--   npx wrangler d1 execute simplelogin --remote --file scripts/seed-public-domain.sql
-- (local dev: drop --remote). Idempotent: ON CONFLICT(domain) makes re-runs
-- no-ops.
--
-- Where each column bites (this codebase):
--   domain               the alias domain, e.g. 'mail.example.com'. UNIQUE.
--   premium_only         1 = only premium users get this domain offered as an
--                        alias suffix (src/lib/models.ts availableSLDomains).
--   can_use_subdomain    1 = users may claim <their-subdomain>.<domain>
--                        (SL subdomain feature).
--   partner_id           partner-scoped domains (Proton). NULL for ours.
--   hidden               1 = excluded from suffix lists but still a valid
--                        alias domain (reply path / existing aliases keep
--                        working). Use to retire a domain gracefully.
--   "order"              sort order in the suffix dropdown (reserved word —
--                        always quote it).
--   use_as_reverse_alias 1 = domain is eligible for generated reverse-alias
--                        (contact) addresses.
--   id / created_at      auto; updated_at stays NULL until first update.
--
-- REMEMBER (docs/DOMAINS.md): a public_domain row alone is not enough — the
-- domain must also be in the ALIAS_DOMAINS var in wrangler.jsonc (redeploy!),
-- have Email Routing + the catch-all-to-worker rule
-- (scripts/provision-domain.mjs), and be onboarded for Email Sending when
-- FORWARD_MODE=rewrite. A missing public_domain row makes replies fail with
-- "550 SL E503"; a missing ALIAS_DOMAINS entry hides the suffix and skips
-- worker-side DKIM.

INSERT INTO public_domain
  (domain, premium_only, can_use_subdomain, partner_id, hidden, "order", use_as_reverse_alias)
VALUES
  ('CHANGE-ME.example', 0, 0, NULL, 0, 0, 0)
ON CONFLICT (domain) DO NOTHING;
