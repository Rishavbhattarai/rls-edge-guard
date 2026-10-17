---
name: rls-policy-author
description: Write Supabase Row-Level Security correctly the first time. Use when creating or changing Supabase tables, RLS policies, storage bucket policies, views, or SECURITY DEFINER functions, or when rls-edge-guard reports an RLS0xx or STO001 finding.
---

# Authoring Supabase RLS

Every table in an exposed schema (`public` by default, see `[api] schemas` in `supabase/config.toml`) can be reached by anyone who has the project's anon key. RLS is the only thing between that key and the rows.

## Checklist for every new table

1. `alter table <t> enable row level security;` in the **same migration** as `create table`.
2. Decide the access model (below) before writing policies.
3. Write one policy per command (`select`, `insert`, `update`, `delete`). Avoid `for all`. Separate policies are easier to review and test.
4. Always say who it is for: `to authenticated` or `to anon`.
5. Wrap auth calls: `(select auth.uid())`, not `auth.uid()`. Postgres then evaluates it once per query instead of once per row.
6. Index the columns that policies filter on (`user_id`, `org_id`).
7. Never read `user_metadata` / `raw_user_meta_data` in a policy: users can edit it. Use `app_metadata` (set only by the server) or a roles table.

## Access models

**Owner only** (notes, todos, settings):

```sql
create policy "notes: owner select" on public.notes for select to authenticated
  using ((select auth.uid()) = user_id);
create policy "notes: owner insert" on public.notes for insert to authenticated
  with check ((select auth.uid()) = user_id);
create policy "notes: owner update" on public.notes for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "notes: owner delete" on public.notes for delete to authenticated
  using ((select auth.uid()) = user_id);
```

Give `user_id` a default of `auth.uid()` so clients cannot choose it.

**Public read, owner write** (profiles, posts): the `select` policy uses `using (true)` *to anon, authenticated*. That is intentional, so mark it: `-- rls-edge-guard-ignore RLS010: profiles are public`. Writes stay owner-only, as above.

**Team / organization membership**: put the membership check in a function in a **non-exposed** schema, so it can't be called over the API and doesn't recurse through RLS on the members table:

```sql
create schema if not exists private;
create function private.is_member(_org uuid) returns boolean
  language sql stable security definer set search_path = ''
as $$ select exists (select 1 from public.members m
                     where m.org_id = _org and m.user_id = (select auth.uid())) $$;

create policy "projects: members read" on public.projects for select to authenticated
  using ((select private.is_member(org_id)));
```

**Admin role**: check `app_metadata` (set server-side via the admin API) or a `user_roles` table. Never `user_metadata`.

```sql
using (((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin')
```

**Server-only tables** (webhooks, audit logs): enable RLS and add **no** policies. Only the service role (which bypasses RLS) can touch them. That is deny-by-default, not a bug.

## Views and functions

- Views in exposed schemas run as their owner and bypass RLS unless created `with (security_invoker = true)`.
- `security definer` functions in exposed schemas are callable by anon over `/rest/v1/rpc`. Prefer `security invoker`. If definer is needed, set `search_path = ''`, schema-qualify everything, and `revoke execute ... from public, anon, authenticated` (or move it to `private`).
- Materialized views have no RLS. Keep them out of exposed schemas.

## Storage

`storage.objects` is shared by every bucket. Every policy must pin `bucket_id`, and usually the owner's folder:

```sql
create policy "avatars: owner upload" on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars'
              and (storage.foldername(name))[1] = (select auth.uid())::text);
```

## Rule reference

| Rule | Severity | Meaning |
|---|---|---|
| RLS001 | block | Exposed table without RLS (or RLS disabled later) |
| RLS002 | block | Write policy that is always true for anon/authenticated |
| RLS003 | warn | Write policy that never checks who the caller is |
| RLS004 | block | Policy trusts `user_metadata` |
| RLS005 | block | SECURITY DEFINER in an exposed schema without `search_path` |
| RLS006 | block | View in an exposed schema without `security_invoker` |
| RLS007 | warn | Policy without a `TO` role |
| RLS008 | warn | Bare `auth.uid()` (per-row evaluation) |
| RLS010 | warn | Table readable by everyone the policy targets |
| RLS011 | warn | SECURITY DEFINER function callable over the API |
| RLS012 | warn | Materialized view in an exposed schema |
| STO001 | block | Storage policy not scoped to a bucket |
| KEY001 | block | Service-role / secret key reachable from the browser |

Static checks show the SQL *looks* right. To show it *is* right, use the `rls-pgtap-prover` skill.
