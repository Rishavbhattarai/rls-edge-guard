import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from rls_edge_guard.rls import lint_sql_texts  # noqa: E402
from rls_edge_guard.sqltok import split  # noqa: E402


def rules(*sqls, schemas=("public", "graphql_public"), severity=None):
    found = lint_sql_texts([(f"{i:03}.sql", s) for i, s in enumerate(sqls)], schemas)
    return sorted(f.rule for f in found if severity is None or f.severity == severity)


GOOD_TODOS = """
create table public.todos (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users on delete cascade default auth.uid(),
  task text not null
);
alter table public.todos enable row level security;
create policy "own todos: select" on public.todos for select to authenticated
  using ((select auth.uid()) = user_id);
create policy "own todos: insert" on public.todos for insert to authenticated
  with check ((select auth.uid()) = user_id);
create policy "own todos: update" on public.todos for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "own todos: delete" on public.todos for delete to authenticated
  using ((select auth.uid()) = user_id);
"""


class Tokenizer(unittest.TestCase):
    def test_semicolons_in_strings_and_bodies_do_not_split(self):
        sql = ("create function f() returns text language plpgsql as $body$ begin return 'a;b'; end; "
               "$body$; select 'x;y'; select \"we;ird\" from t; -- c;d\nselect 1 /* ; */")
        self.assertEqual(len(split(sql)), 4)

    def test_begin_atomic_body(self):
        sql = "create function f() returns int language sql begin atomic select 1; select 2; end; select 3;"
        self.assertEqual(len(split(sql)), 2)

    def test_line_numbers_and_ignores(self):
        sts = split("select 1;\n\n-- rls-edge-guard-ignore RLS002: public form\ncreate policy p on t;")
        self.assertEqual(sts[1].line, 4)
        self.assertEqual(sts[1].ignores, {"RLS002": "public form"})

    def test_ignore_without_reason_is_not_an_ignore(self):
        self.assertEqual(split("-- rls-edge-guard-ignore RLS002:\nselect 1;")[0].ignores, {})


class RlsEnabled(unittest.TestCase):
    def test_clean_owner_pattern(self):
        self.assertEqual(rules(GOOD_TODOS), [])

    def test_table_without_rls(self):
        self.assertEqual(rules("create table todos (id int);"), ["RLS001"])

    def test_rls_enabled_in_later_migration(self):
        self.assertEqual(rules("create table todos (id int);",
                               "alter table todos enable row level security;"), [])

    def test_rls_disabled_later(self):
        self.assertEqual(rules(GOOD_TODOS, "alter table public.todos disable row level security;"),
                         ["RLS001"])

    def test_policies_without_rls_is_reported(self):
        found = lint_sql_texts([("a.sql", "create table t (id int); create policy p on t "
                                          "for select to authenticated using (true);")])
        self.assertIn("policies but RLS is not enabled", [f for f in found if f.rule == "RLS001"][0].message)

    def test_non_exposed_schema_and_temp_tables(self):
        self.assertEqual(rules("create table private.t (id int); create temp table x (id int);"), [])

    def test_custom_exposed_schemas(self):
        self.assertEqual(rules("create table api.t (id int);", schemas=("api",)), ["RLS001"])
        self.assertEqual(rules("create table public.t (id int);", schemas=("api",)), [])

    def test_revoked_from_api_roles(self):
        self.assertEqual(rules("create table t (id int); revoke all on table t from anon, authenticated;"), [])
        self.assertEqual(rules("create table t (id int); revoke all on table t from anon;"), ["RLS001"])

    def test_rename_and_drop(self):
        self.assertEqual(rules("create table a (id int); alter table a rename to b; "
                               "alter table b enable row level security;"), [])
        self.assertEqual(rules("create table a (id int); drop table if exists a;"), [])

    def test_if_not_exists_and_quoted(self):
        self.assertEqual(rules('create table if not exists "Notes" (id int);'), ["RLS001"])
        self.assertEqual(rules('create table "Notes" (id int); alter table "Notes" enable row level security;'), [])


class Policies(unittest.TestCase):
    T = "create table t (id int, user_id uuid); alter table t enable row level security;"

    def test_always_true_write(self):
        self.assertEqual(rules(self.T + "create policy p on t for insert to anon with check (true);",
                               severity="block"), ["RLS002"])
        self.assertEqual(rules(self.T + "create policy p on t for all to authenticated using (true);",
                               severity="block"), ["RLS002"])
        self.assertEqual(rules(self.T + "create policy p on t for update to authenticated "
                                        "using ((select auth.uid()) = user_id) with check (true);",
                               severity="block"), ["RLS002"])

    def test_true_for_service_role_only_is_fine(self):
        self.assertEqual(rules(self.T + "create policy p on t for all to service_role using (true);"), [])

    def test_restrictive_true_is_harmless(self):
        self.assertEqual(rules(self.T + "create policy p on t as restrictive for all to authenticated "
                                        "using (true);", severity="block"), [])

    def test_public_read_is_a_warning_not_a_block(self):
        self.assertEqual(rules(self.T + "create policy p on t for select to anon using (true);"), ["RLS010"])

    def test_ignore_comment_suppresses(self):
        self.assertEqual(rules(self.T + "-- rls-edge-guard-ignore RLS002: waitlist form\n"
                                        "create policy p on t for insert to anon with check (true);"), [])

    def test_alter_policy_fixes_it(self):
        self.assertEqual(rules(self.T + "create policy p on t for insert to anon with check (true);",
                               "alter policy p on t with check ((select auth.uid()) = user_id);"), [])

    def test_drop_policy(self):
        self.assertEqual(rules(self.T + "create policy p on t for insert to anon with check (true);",
                               "drop policy if exists p on t;"), [])

    def test_write_without_identity_warns(self):
        self.assertEqual(rules(self.T + "create policy p on t for update to authenticated "
                                        "using (id > 0);"), ["RLS003"])

    def test_membership_function_counts_as_identity(self):
        self.assertEqual(rules(self.T + "create policy p on t for update to authenticated "
                                        "using (private.is_member(id));"), [])

    def test_user_metadata(self):
        self.assertEqual(rules(self.T + "create policy p on t for select to authenticated using "
                                        "(((select auth.jwt()) -> 'user_metadata' ->> 'role') = 'admin');"),
                         ["RLS004"])
        self.assertEqual(rules(self.T + "create policy p on t for select to authenticated using "
                                        "(((select auth.jwt()) -> 'app_metadata' ->> 'role') = 'admin');"), [])

    def test_user_metadata_via_helper_function(self):
        fn = ("create function private.is_admin() returns boolean language sql stable security definer "
              "set search_path = '' as $$ select coalesce((select (raw_user_meta_data->>'is_admin')::boolean "
              "from auth.users where id = (select auth.uid())), false) $$;")
        self.assertEqual(rules(self.T + fn, "create policy p on t for select to authenticated "
                                            "using ((select private.is_admin()));"), ["RLS004"])

    def test_signup_trigger_reading_metadata_is_fine(self):
        trig = ("create function public.handle_new_user() returns trigger language plpgsql security definer "
                "set search_path = '' as $$ begin insert into public.profiles (id, full_name) values "
                "(new.id, new.raw_user_meta_data->>'full_name'); return new; end; $$; "
                "revoke execute on function public.handle_new_user() from public, anon, authenticated;")
        self.assertEqual(rules(self.T + trig), [])

    def test_missing_to_and_bare_auth_uid(self):
        self.assertEqual(rules(self.T + "create policy p on t for select using (auth.uid() = user_id);"),
                         ["RLS007", "RLS008"])

    def test_storage_policy_needs_bucket(self):
        self.assertEqual(rules("create policy p on storage.objects for insert to authenticated "
                               "with check ((select auth.uid()) is not null);"), ["STO001"])
        self.assertEqual(rules("create policy p on storage.objects for insert to authenticated "
                               "with check (bucket_id = 'avatars' and (select auth.uid())::text = owner_id);"), [])


class FunctionsAndViews(unittest.TestCase):
    def test_security_definer_without_search_path(self):
        self.assertEqual(rules("create function public.f() returns int language sql security definer "
                               "as $$ select 1 $$;"), ["RLS005", "RLS011"])

    def test_security_definer_hardened(self):
        self.assertEqual(rules("create or replace function public.f() returns int language sql "
                               "security definer set search_path = '' as $$ select 1 $$; "
                               "revoke execute on function public.f() from public, anon, authenticated;"), [])

    def test_alter_function_sets_search_path(self):
        self.assertEqual(rules("create function public.f() returns int language sql security definer "
                               "as $$ select 1 $$; alter function public.f() set search_path = '';",
                               "revoke execute on function public.f from public;"), [])

    def test_definer_in_private_schema_is_fine(self):
        self.assertEqual(rules("create function private.f() returns int language sql security definer "
                               "as $$ select 1 $$;"), [])

    def test_invoker_function_is_fine(self):
        self.assertEqual(rules("create function public.f() returns int language sql as $$ select 1 $$;"), [])

    def test_views(self):
        self.assertEqual(rules("create view public.v as select 1;"), ["RLS006"])
        self.assertEqual(rules("create view public.v with (security_invoker = true) as select 1;"), [])
        self.assertEqual(rules("create view public.v with (security_invoker) as select 1;"), [])
        self.assertEqual(rules("create view public.v as select 1; "
                               "alter view public.v set (security_invoker = on);"), [])
        self.assertEqual(rules("create materialized view public.m as select 1;"), ["RLS012"])
        self.assertEqual(rules("create view private.v as select 1;"), [])

    def test_malformed_sql_does_not_crash(self):
        rules("create policy; alter table; create view; drop; grant on; create function")


if __name__ == "__main__":
    unittest.main()
