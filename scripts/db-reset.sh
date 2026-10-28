#!/usr/bin/env bash
# Recreate a database from scratch: (shim) + every migration in order + seed.
#   DATABASE_URL=postgres://postgres@127.0.0.1:54329/bsp_dev scripts/db-reset.sh
# Set SUPABASE_SHIM=0 when targeting a real Supabase database (use `supabase db reset` there instead).
set -euo pipefail
export PGOPTIONS="${PGOPTIONS:--c client_min_messages=warning}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
URL="${DATABASE_URL:-postgres://postgres@127.0.0.1:54329/bsp_dev}"
DB="${URL##*/}"; DB="${DB%%\?*}"
ADMIN_URL="${URL%/*}/postgres"
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -q -c "drop database if exists \"$DB\" with (force)" -c "create database \"$DB\""
if [ "${SUPABASE_SHIM:-1}" = "1" ]; then
  psql "$URL" -v ON_ERROR_STOP=1 -q -f "$ROOT/tests/fixtures/supabase-shim.sql"
fi
for f in "$ROOT"/supabase/migrations/*.sql; do
  psql "$URL" -v ON_ERROR_STOP=1 -q -f "$f"
done
if [ "${SKIP_SEED:-0}" != "1" ]; then
  psql "$URL" -v ON_ERROR_STOP=1 -q -f "$ROOT/supabase/seed.sql"
fi
echo "Database $DB ready"
