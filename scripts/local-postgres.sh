#!/usr/bin/env bash
# Start a throwaway local PostgreSQL (no Docker) for tests: port 54329, data in .pgdata/.
# For full local Supabase (Auth, Studio, PostgREST) use `supabase start` instead.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PGBIN="${PGBIN:-$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)}"
PGDATA="${PGDATA:-$ROOT/.pgdata}"
PORT="${PGPORT:-54329}"
export PATH="$PGBIN:$PATH"

if [ ! -f "$PGDATA/PG_VERSION" ]; then
  mkdir -p "$PGDATA"
  if [ "$(id -u)" = "0" ]; then chown -R postgres "$PGDATA"; RUN="runuser -u postgres --"; else RUN=""; fi
  $RUN initdb -D "$PGDATA" -U postgres --auth=trust >/dev/null
fi
if [ "$(id -u)" = "0" ]; then RUN="runuser -u postgres --"; else RUN=""; fi
if ! $RUN pg_ctl -D "$PGDATA" status >/dev/null 2>&1; then
  $RUN pg_ctl -D "$PGDATA" -o "-p $PORT -k /tmp" -l "$PGDATA/server.log" start >/dev/null
fi
echo "PostgreSQL running: postgres://postgres@127.0.0.1:$PORT/postgres"
