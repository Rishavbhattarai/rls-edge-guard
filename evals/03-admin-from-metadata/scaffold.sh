#!/usr/bin/env bash
# Starting project for this case (runs in the case's sandbox cwd).
set -euo pipefail
mkdir -p supabase/migrations && printf 'project_id = "app"\n\n[api]\nschemas = ["public", "graphql_public"]\n' > supabase/config.toml
printf 'create table public.reports (\n  id bigint generated always as identity primary key,\n  owner_id uuid not null references auth.users (id),\n  body text not null\n);\nalter table public.reports enable row level security;\n' > supabase/migrations/20261017000000_reports.sql
