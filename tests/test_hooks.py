"""End-to-end: run guard.py the way Claude Code does (JSON on stdin, exit code, stderr)."""
import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from rls_edge_guard import keys  # noqa: E402

GUARD = os.path.join(os.path.dirname(__file__), "..", "scripts", "guard.py")


def make(files):
    d = tempfile.mkdtemp(prefix="reg-hook-")
    for rel, text in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(text)
    return d


def run(mode, payload, env=None):
    proc = subprocess.run([sys.executable, GUARD, "hook", mode], input=json.dumps(payload),
                          capture_output=True, text=True, timeout=30,
                          env={**os.environ, **(env or {})})
    return proc.returncode, proc.stdout, proc.stderr


def edit(d, rel):
    return {"tool_name": "Write", "cwd": d, "tool_input": {"file_path": os.path.join(d, rel)}}


SUPA = {"supabase/config.toml": '[api]\nschemas = ["public", "graphql_public"]\n'}
WRANGLER = {"wrangler.toml": 'name = "w"\nmain = "src/index.ts"\ncompatibility_date = "2025-06-01"\n'}


class Gating(unittest.TestCase):
    """Hooks must stay silent outside Supabase / Workers projects."""

    def test_sql_outside_supabase_project(self):
        d = make({"db/schema.sql": "create table t (id int);"})
        self.assertEqual(run("post-edit", edit(d, "db/schema.sql")), (0, "", ""))

    def test_js_outside_workers_project(self):
        d = make({"src/index.ts": "import { exec } from 'node:child_process'; eval(x);"})
        self.assertEqual(run("post-edit", edit(d, "src/index.ts")), (0, "", ""))

    def test_unrelated_file_types(self):
        d = make({**SUPA, **WRANGLER, "README.md": "create table t (id int);"})
        self.assertEqual(run("post-edit", edit(d, "README.md")), (0, "", ""))

    def test_non_deploy_bash(self):
        d = make({**SUPA, "supabase/migrations/1_a.sql": "create table t (id int);"})
        payload = {"tool_name": "Bash", "cwd": d, "tool_input": {"command": "supabase db diff"}}
        self.assertEqual(run("pre-deploy", payload), (0, "", ""))

    def test_non_supabase_mcp_tool(self):
        payload = {"tool_name": "mcp__postgres__query", "cwd": "/", "tool_input": {"query": "create table t (id int)"}}
        self.assertEqual(run("pre-mcp", payload), (0, "", ""))

    def test_kill_switch(self):
        d = make({**SUPA, "supabase/migrations/1_a.sql": "create table t (id int);"})
        self.assertEqual(run("post-edit", edit(d, "supabase/migrations/1_a.sql"),
                             {"RLS_EDGE_GUARD_DISABLE": "1"})[0], 0)

    def test_bad_stdin(self):
        proc = subprocess.run([sys.executable, GUARD, "hook", "post-edit"], input="not json",
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)


class Blocking(unittest.TestCase):
    def test_migration_without_rls_blocks(self):
        d = make({**SUPA, "supabase/migrations/20260101000000_todos.sql": "create table todos (id int);"})
        code, _, err = run("post-edit", edit(d, "supabase/migrations/20260101000000_todos.sql"))
        self.assertEqual(code, 2)
        self.assertIn("RLS001", err)
        self.assertIn("supabase/migrations/20260101000000_todos.sql:1", err)

    def test_only_edited_migration_is_reported(self):
        d = make({**SUPA, "supabase/migrations/1_old.sql": "create table legacy (id int);",
                  "supabase/migrations/2_new.sql": "create table fresh (id int); "
                                                  "alter table fresh enable row level security;"})
        self.assertEqual(run("post-edit", edit(d, "supabase/migrations/2_new.sql"))[0], 0)

    def test_warnings_are_context_not_blocks(self):
        d = make({**SUPA, "supabase/migrations/1_a.sql":
                  "create table t (id int, user_id uuid); alter table t enable row level security;\n"
                  "create policy p on t for select using (auth.uid() = user_id);"})
        code, out, _ = run("post-edit", edit(d, "supabase/migrations/1_a.sql"))
        self.assertEqual(code, 0)
        ctx = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(ctx["hookEventName"], "PostToolUse")
        self.assertIn("RLS008", ctx["additionalContext"])

    def test_settings_file_disables_rules(self):
        d = make({**SUPA, ".rls-edge-guard.json": '{"disable": ["RLS001"]}',
                  "supabase/migrations/1_a.sql": "create table t (id int);"})
        self.assertEqual(run("post-edit", edit(d, "supabase/migrations/1_a.sql"))[0], 0)

    def test_supabase_js_project_sql_outside_cli_layout(self):
        d = make({"package.json": '{"dependencies": {"@supabase/supabase-js": "^2"}}',
                  "db/schema.sql": "create table t (id int);"})
        self.assertEqual(run("post-edit", edit(d, "db/schema.sql"))[0], 2)

    def test_worker_child_process_blocks(self):
        d = make({**WRANGLER, "src/index.ts": "import { exec } from 'node:child_process';\n"})
        code, _, err = run("post-edit", edit(d, "src/index.ts"))
        self.assertEqual(code, 2)
        self.assertIn("EDGE001", err)

    def test_new_import_pulls_in_earlier_file(self):
        d = make({**WRANGLER, "src/hash.ts": "import bcrypt from 'bcrypt';\nexport const h = bcrypt.hash;\n",
                  "src/index.ts": "import { h } from './hash';\nexport default { fetch: h };\n"})
        code, _, err = run("post-edit", edit(d, "src/index.ts"))
        self.assertEqual(code, 2)
        self.assertIn("src/hash.ts:1", err)

    def test_wrangler_edit_rechecks_worker(self):
        d = make({**WRANGLER, "src/index.ts": "import { createHash } from 'node:crypto';\n"})
        code, _, err = run("post-edit", edit(d, "wrangler.toml"))
        self.assertEqual(code, 2)
        self.assertIn("EDGE002", err)

    def test_mcp_apply_migration(self):
        payload = {"tool_name": "mcp__plugin_supabase_supabase__apply_migration", "cwd": "/",
                   "tool_input": {"name": "todos", "query": "create table todos (id int);"}}
        code, _, err = run("pre-mcp", payload)
        self.assertEqual(code, 2)
        self.assertIn("<todos>:1  RLS001", err)

    def test_mcp_apply_migration_clean(self):
        payload = {"tool_name": "mcp__supabase__apply_migration", "cwd": "/",
                   "tool_input": {"name": "todos", "query": "create table todos (id int);"
                                  "alter table todos enable row level security;"}}
        self.assertEqual(run("pre-mcp", payload)[0], 0)

    def test_deploy_gate(self):
        d = make({**SUPA, "supabase/migrations/1_a.sql": "create table t (id int);"})
        payload = {"tool_name": "Bash", "cwd": d, "tool_input": {"command": "npx supabase db push --linked"}}
        code, _, err = run("pre-deploy", payload)
        self.assertEqual(code, 2)
        self.assertIn("before `supabase db push`", err)

    def test_wrangler_deploy_gate_ignores_rls(self):
        d = make({**SUPA, **WRANGLER, "supabase/migrations/1_a.sql": "create table t (id int);",
                  "src/index.ts": "export default { fetch() { return new Response('ok') } };\n"})
        payload = {"tool_name": "Bash", "cwd": d, "tool_input": {"command": "wrangler deploy"}}
        self.assertEqual(run("pre-deploy", payload)[0], 0)


class Keys(unittest.TestCase):
    def jwt(self, role):
        seg = base64.urlsafe_b64encode(json.dumps({"role": role, "iss": "supabase"}).encode()).decode().rstrip("=")
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + seg + ".abcdefghijklmnopqrstu"

    def k(self, path, src):
        return [f.rule for f in keys.check(path, src)]

    def test_public_prefixed_env(self):
        self.assertEqual(self.k(".env.local", "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=x\n"), ["KEY001"])
        self.assertEqual(self.k(".env.local", "SUPABASE_SERVICE_ROLE_KEY=x\nNEXT_PUBLIC_SUPABASE_ANON_KEY=y\n"), [])
        self.assertEqual(self.k("a.ts", "const k = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY;"), ["KEY001"])

    def test_hardcoded_keys(self):
        self.assertEqual(self.k("a.ts", f"const k = '{self.jwt('service_role')}';"), ["KEY001"])
        self.assertEqual(self.k("a.ts", f"const k = '{self.jwt('anon')}';"), [])
        self.assertEqual(self.k("a.ts", "const k = 'sb_secret_abcdefghijklmnop';"), ["KEY001"])
        self.assertEqual(self.k("a.ts", "const k = 'sb_publishable_abcdefghijklmnop';"), [])

    def test_use_client(self):
        src = "'use client'\nconst s = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)\n"
        self.assertEqual(self.k("a.tsx", src), ["KEY001"])
        self.assertEqual(self.k("route.ts", src.replace("'use client'\n", "")), [])

    def test_secret_value_is_never_printed(self):
        d = make({"package.json": '{"dependencies": {"@supabase/ssr": "1"}}',
                  "lib/admin.ts": f"export const k = '{self.jwt('service_role')}';\n"})
        code, _, err = run("post-edit", edit(d, "lib/admin.ts"))
        self.assertEqual(code, 2)
        self.assertNotIn(self.jwt("service_role").split(".")[1], err)


class Audit(unittest.TestCase):
    def test_audit_cli(self):
        d = make({**SUPA, **WRANGLER, "supabase/migrations/1_a.sql": "create table t (id int);",
                  "src/index.ts": "import bcrypt from 'bcrypt';\n"})
        proc = subprocess.run([sys.executable, GUARD, "audit", d, "--json"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(sorted(f["rule"] for f in json.loads(proc.stdout)), ["EDGE003", "RLS001"])


if __name__ == "__main__":
    unittest.main()
