---
name: rls-pgtap-prover
description: Generate pgTAP tests that prove Supabase RLS policies by impersonating anon and two different signed-in users. Use when the user wants to verify, test, or prove RLS or tenant isolation, or after writing new policies with rls-policy-author.
---

# Proving RLS with pgTAP

Static review says a policy looks right. A pgTAP test that signs in as user A, then as user B, says it **is** right. Tests go in `supabase/tests/database/<table>_rls.test.sql` and run with `supabase test db`.

Running them needs the Supabase CLI and a running local stack (`supabase start`, which uses Docker). Write the tests first. Run them only when the user asks or agrees, and tell them what the command needs.

## What to assert for each table

For an owner-only table, with users A and B:

1. **anon** sees 0 rows and cannot insert.
2. **A** sees only A's rows.
3. **B** cannot read, update, or delete A's rows. RLS hides rows silently, so check that row counts did not change. Don't wait for an error.
4. **B** cannot insert a row whose `user_id` is A's id (`throws_ok`, SQLSTATE `42501`).
5. **A** cannot move a row to B by updating `user_id` (the `with check` side).

Adapt this to the access model: public-read tables assert anon *can* read but not write; team tables use a member and a non-member.

## Template

```sql
begin;
create extension if not exists pgtap with schema extensions;
select plan(7);

-- Two users. auth.users needs only id here; Supabase fills in the rest.
insert into auth.users (id, email) values
  ('00000000-0000-0000-0000-00000000000a', 'a@test.local'),
  ('00000000-0000-0000-0000-00000000000b', 'b@test.local');

-- Seed as the table owner (bypasses RLS).
insert into public.notes (user_id, body) values
  ('00000000-0000-0000-0000-00000000000a', 'A secret');

-- anon
set local role anon;
select is((select count(*) from public.notes)::int, 0, 'anon sees nothing');
select throws_ok($$ insert into public.notes (user_id, body)
                    values ('00000000-0000-0000-0000-00000000000a', 'x') $$,
                 '42501', null, 'anon cannot insert');

-- user A
set local role authenticated;
set local request.jwt.claims = '{"sub":"00000000-0000-0000-0000-00000000000a","role":"authenticated"}';
select is((select count(*) from public.notes)::int, 1, 'A sees own row');

-- user B
set local request.jwt.claims = '{"sub":"00000000-0000-0000-0000-00000000000b","role":"authenticated"}';
select is((select count(*) from public.notes)::int, 0, 'B cannot read A');
update public.notes set body = 'hacked';
delete from public.notes;
select throws_ok($$ insert into public.notes (user_id, body)
                    values ('00000000-0000-0000-0000-00000000000a', 'forged') $$,
                 '42501', null, 'B cannot insert as A');

-- back to owner to see what actually changed
reset role;
select is((select body from public.notes limit 1), 'A secret', 'B could not update A');
select is((select count(*) from public.notes)::int, 1, 'B could not delete A');

select * from finish();
rollback;
```

Notes:
- Everything runs in one transaction and rolls back, so tests leave no data behind.
- `set local request.jwt.claims` is what `auth.uid()` reads. Change it to switch users.
- To check a policy with `with check`, also assert that A's `update ... set user_id = <B>` throws `42501`.
- For storage, insert into `storage.objects (bucket_id, name, owner_id)` as the user and assert the same way.

## Running

```bash
supabase start        # once; needs Docker
supabase test db      # runs supabase/tests/**/*.sql
```

A failing assertion names the test. Fix the policy in a **new** migration, run `supabase db reset` locally, and rerun.
