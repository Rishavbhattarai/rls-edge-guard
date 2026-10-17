#!/usr/bin/env bash
# Starting project for this case (runs in the case's sandbox cwd).
set -euo pipefail
mkdir -p supabase/migrations && printf 'project_id = "app"\n\n[api]\nschemas = ["public", "graphql_public"]\n' > supabase/config.toml
cat > supabase/migrations/20261017000000_todos.sql <<'SQL'
create table public.todos (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references auth.users (id),
  task text not null,
  done boolean not null default false
);
alter table public.todos enable row level security;
create policy "todos: owner select" on public.todos for select to authenticated
  using ((select auth.uid()) = user_id);
SQL
