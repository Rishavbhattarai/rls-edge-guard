begin;
create extension if not exists pgtap with schema extensions;
select plan(9);

insert into auth.users (id, email) values
  ('00000000-0000-0000-0000-00000000000a', 'a@test.local'),
  ('00000000-0000-0000-0000-00000000000b', 'b@test.local');
insert into public.notes (user_id, body) values ('00000000-0000-0000-0000-00000000000a', 'A secret');
insert into public.profiles (id, display_name) values ('00000000-0000-0000-0000-00000000000a', 'Alice');

-- anon
set local role anon;
select is((select count(*) from public.notes)::int, 0, 'anon sees no notes');
select is((select count(*) from public.profiles)::int, 1, 'anon can read profiles');
select throws_ok($$ insert into public.notes (user_id, body)
                    values ('00000000-0000-0000-0000-00000000000a', 'x') $$,
                 '42501', null, 'anon cannot insert notes');

-- user A
set local role authenticated;
set local request.jwt.claims = '{"sub":"00000000-0000-0000-0000-00000000000a","role":"authenticated"}';
select is((select count(*) from public.notes)::int, 1, 'A sees own note');
select throws_ok($$ update public.notes set user_id = '00000000-0000-0000-0000-00000000000b' $$,
                 '42501', null, 'A cannot hand a note to B');

-- user B
set local request.jwt.claims = '{"sub":"00000000-0000-0000-0000-00000000000b","role":"authenticated"}';
select is((select count(*) from public.notes)::int, 0, 'B cannot read A''s note');
update public.notes set body = 'hacked';
delete from public.notes;
update public.profiles set display_name = 'hacked';
select throws_ok($$ insert into public.notes (user_id, body)
                    values ('00000000-0000-0000-0000-00000000000a', 'forged') $$,
                 '42501', null, 'B cannot insert a note as A');

reset role;
select is((select body from public.notes limit 1), 'A secret', 'B could not update or delete A''s note');
select is((select display_name from public.profiles limit 1), 'Alice', 'B could not change A''s profile');

select * from finish();
rollback;
