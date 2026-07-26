#!/usr/bin/env bash
# Dated backup of the remote D1 database `simplelogin`.
#
#   ./scripts/backup-d1.sh          -> backups/simplelogin-YYYY-MM-DD.sql
#
# Node 22 is required for wrangler but is NOT on PATH in this repo's default
# environment — run one of:
#   nvm use 22 && ./scripts/backup-d1.sh
#   nix-shell -p nodejs_22 --run ./scripts/backup-d1.sh
#
# The export is a full SQL dump (schema + data) produced by
# `wrangler d1 export --remote`, restorable with
# `npx wrangler d1 execute simplelogin --remote --file <dump>.sql`
# into a FRESH database (the dump contains CREATE TABLE statements).
#
# NOT covered by this backup: the KV namespace. KV holds sessions (ephemeral)
# but also `file:<path>` blobs — batch-import CSV uploads and profile
# pictures (see src/web/mailbox-domain-pages.ts / src/routes/user.ts). The
# D1 `file` table only stores their paths; the bytes live in KV. Back those
# up separately if they matter:
#   npx wrangler kv key list --namespace-id <id> --prefix "file:"
#   npx wrangler kv key get  --namespace-id <id> "file:<path>"
set -euo pipefail

cd "$(dirname "$0")/.." # cloudflare/

if ! command -v npx >/dev/null 2>&1; then
  echo "ERROR: npx not found — Node 22 is required. Run via one of:" >&2
  echo "  nvm use 22 && $0" >&2
  echo "  nix-shell -p nodejs_22 --run $0" >&2
  exit 1
fi

mkdir -p backups
# Backups contain user data (emails, bcrypt hashes, API keys) — never commit.
printf '*\n' >backups/.gitignore

out="backups/simplelogin-$(date +%Y-%m-%d).sql"
if [ -e "$out" ]; then
  echo "NOTE: $out already exists — overwriting today's backup." >&2
fi

npx wrangler d1 export simplelogin --remote --output "$out"
echo "Backup written to $out ($(du -h "$out" | cut -f1))"
