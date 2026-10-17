-- Minimal stand-in for the parts of Supabase that RLS policies depend on.
-- Dev-only: lets dev/prove_rls.sh run pgTAP against plain Postgres without Docker.
-- Mirrors Supabase: API roles, default table grants to anon/authenticated,
-- and auth.uid()/auth.jwt()/auth.role() read from request.jwt.claims.
create role anon nologin noinherit;
create role authenticated nologin noinherit;
create role service_role nologin noinherit bypassrls;

create schema auth;
create schema extensions;
create table auth.users (id uuid primary key, email text);

create function auth.jwt() returns jsonb language sql stable as $$
  select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;
create function auth.uid() returns uuid language sql stable as $$
  select nullif(auth.jwt() ->> 'sub', '')::uuid $$;
create function auth.role() returns text language sql stable as $$
  select auth.jwt() ->> 'role' $$;

grant usage on schema public, auth, extensions to anon, authenticated, service_role;
grant execute on all functions in schema auth to anon, authenticated, service_role;
grant select on auth.users to authenticated;
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
