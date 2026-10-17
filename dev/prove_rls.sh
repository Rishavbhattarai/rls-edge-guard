#!/usr/bin/env bash
# Dev-only. Runs an app's pgTAP RLS tests against a throwaway local Postgres.
#   dev/prove_rls.sh <app-dir> <path/to/pgtap.sql>
# Needs: Postgres 14+ binaries (initdb, pg_ctl, psql) on PATH, and pgtap.sql built
# from https://github.com/theory/pgtap (make). Nothing is installed; the cluster
# lives in a temp dir and is deleted on exit. No network.
set -euo pipefail
APP="$(cd "$1" && pwd)"; PGTAP="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
HERE="$(cd "$(dirname "$0")" && pwd)"
DATA="$(mktemp -d /tmp/reg-pg.XXXXXX)"; PORT="${PORT:-54329}"
trap 'pg_ctl -D "$DATA/db" -m immediate stop >/dev/null 2>&1 || true; rm -rf "$DATA"' EXIT
initdb -D "$DATA/db" -U postgres --auth=trust >/dev/null
pg_ctl -D "$DATA/db" -o "-p $PORT -k $DATA -c listen_addresses=''" -l "$DATA/log" -w start >/dev/null
PSQL=(psql -X -q -v ON_ERROR_STOP=1 -h "$DATA" -p "$PORT" -U postgres -d postgres)
"${PSQL[@]}" -f "$HERE/supabase_shim.sql"
"${PSQL[@]}" -c "set search_path = extensions" -f "$PGTAP" >/dev/null
"${PSQL[@]}" -c "alter database postgres set search_path = public, extensions"
for m in "$APP"/supabase/migrations/*.sql; do "${PSQL[@]}" -f "$m"; done
status=0
for t in "$APP"/supabase/tests/database/*.sql; do
  echo "# $(basename "$t")"
  grep -v -i 'create extension.*pgtap' "$t" | psql -X -q -At -h "$DATA" -p "$PORT" -U postgres -d postgres \
    | tee "$DATA/out"
  grep -q '^not ok' "$DATA/out" && status=1
  grep -q '^# Looks like' "$DATA/out" && status=1
done
exit $status
