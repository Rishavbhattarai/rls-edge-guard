# RLS & Edge Guard

A Claude Code plugin that stops two kinds of bad full-stack code while Claude is writing it:

- **Supabase RLS holes**: tables exposed without Row-Level Security, `USING (true)` write policies, policies that trust `user_metadata`, RLS-bypassing views and `SECURITY DEFINER` functions, storage policies that cover every bucket, and service-role keys that end up in the browser.
- **Cloudflare Workers runtime breaks**: Node built-ins and native packages that won't run in `workerd` **with this project's** `compatibility_date` and `compatibility_flags`.

Checks are deterministic, local Python (standard library only). A blocking finding is fed back to Claude, which fixes the code before moving on.

> Not affiliated with Supabase or Cloudflare. Works alongside their official plugins (`supabase`, `cloudflare`), which provide MCP access and platform guidance. This plugin adds enforcement.

## What it looks like

Asked for "just the table", Claude writes a migration without RLS. The hook blocks it:

```
rls-edge-guard: after editing 20261017000000_todos.sql: 1 blocking issue(s). ...
supabase/migrations/20261017000000_todos.sql:1  RLS001 [block] table public.todos is exposed
through the Supabase Data API and has RLS disabled. Anyone with the anon key can read and write every row.
    fix: ALTER TABLE public.todos ENABLE ROW LEVEL SECURITY; then add policies scoped TO authenticated ...
```

Claude adds `alter table public.todos enable row level security;` and tells you why.

## Install

```
/plugin marketplace add Rishavbhattarai/rls-edge-guard
/plugin install rls-edge-guard@rls-edge-guard
```

Or from a clone: `claude --plugin-dir /path/to/rls-edge-guard`.

Requires `python3` (3.9+) on `PATH`.

## When it runs (and when it doesn't)

| Hook | Fires on | Acts only when |
|---|---|---|
| `PostToolUse` | `Write`, `Edit`, `MultiEdit` | the edited file is SQL in a Supabase project, Worker code under a wrangler config, a wrangler config itself, or client code / `.env*` in a Supabase project |
| `PreToolUse` | Supabase MCP `apply_migration` / `execute_sql` | always (the tool is Supabase by definition). Lints the SQL before it reaches your database |
| `PreToolUse` | `Bash` matching `supabase db push`, `supabase migration up`, `wrangler deploy`, `wrangler versions ...` | a deploy command. Runs a full audit of the working directory first |

A "Supabase project" means a folder with `supabase/config.toml` or `supabase/migrations/`, or a `package.json` that depends on `@supabase/supabase-js` / `@supabase/ssr`. A "Workers project" means a `wrangler.toml`, `wrangler.json` or `wrangler.jsonc` above the file. In any other project every hook exits immediately without output.

### What it reads

- The hook's JSON input from Claude Code (tool name, file path, SQL text, or command).
- The edited file, the project's migrations, `supabase/config.toml` (`[api] schemas`), the wrangler config, `package.json`, and files the Worker imports.
- For `.env*` files and client code, the edited file only, to classify a key. **Secret values are never printed or stored.**

### What it never does

- No network calls, no telemetry, no update checks.
- No package installs.
- Nothing outside the project directory it finds.

## Rules

| Rule | Severity | What it catches |
|---|---|---|
| RLS001 | block | Table in an exposed schema without RLS (also when RLS is disabled later) |
| RLS002 | block | `INSERT`/`UPDATE`/`DELETE`/`ALL` policy that is always true for anon or authenticated |
| RLS003 | warn | Write policy that never checks who the caller is |
| RLS004 | block | Policy reads `user_metadata` (users can edit it) |
| RLS005 | block | `SECURITY DEFINER` function in an exposed schema without `SET search_path` |
| RLS006 | block | View in an exposed schema without `security_invoker` (bypasses RLS) |
| RLS007 | warn | Policy with no `TO` role |
| RLS008 | warn | Bare `auth.uid()` instead of `(select auth.uid())` |
| RLS010 | warn | `SELECT` policy that makes every row readable |
| RLS011 | warn | `SECURITY DEFINER` function callable over the API |
| RLS012 | warn | Materialized view in an exposed schema |
| STO001 | block | `storage.objects` policy not limited to a bucket |
| KEY001 | block | Service-role or `sb_secret_` key in a browser-exposed variable, a `'use client'` file, or hardcoded |
| EDGE001 | block / warn | Node module whose APIs throw in Workers (`child_process`, `worker_threads`, `vm`, `node:fs` before 2025-09-15, ...); warn for partial stubs (`dgram`, `repl`, ...) |
| EDGE002 | block | Node module that needs `nodejs_compat` (or a newer compatibility date) that this project lacks |
| EDGE003 | block / warn | npm package that can't run in Workers (`bcrypt`, `sharp`, `better-sqlite3`, ...) or fits poorly (`jsonwebtoken`, `express`, ...) |
| EDGE004 | block | `eval()` / `new Function()` |
| EDGE005 | block / warn | `process.env` where `process` is undefined (no `nodejs_compat` and date before 2026-08-04), or before it is populated (2025-04-01 with the flag) |
| EDGE006 | warn | I/O or timers at module scope |
| EDGE007 | warn | `node:fs` from 2025-09-15, which is a virtual filesystem without your project files |

Migrations are replayed in order, so `create table` in one migration and `enable row level security` in a later one is understood. When you edit a file, the hook only reports findings located in that file. Use `/rls-edge-guard:audit` for the whole repo.

## Intentional exceptions

Put a comment with a reason on the line, or the line above:

```sql
-- rls-edge-guard-ignore RLS002: public waitlist form, insert only
create policy "waitlist: anyone can join" on public.waitlist for insert to anon with check (true);
```

```ts
// rls-edge-guard-ignore EDGE003: only used by the build script
import sharp from "sharp";
```

To turn a rule off for a project, add `.rls-edge-guard.json` at the project root: `{"disable": ["RLS007"]}`. Set `RLS_EDGE_GUARD_DISABLE=1` to turn all hooks off for a session.

## Skills and command

- `/rls-edge-guard:audit [path]`: whole-repo report, then proposed fixes.
- `rls-policy-author`: patterns for owner-only, public-read, team membership, admin, and server-only tables, plus storage.
- `rls-pgtap-prover`: generates pgTAP tests that sign in as anon, user A, and user B, then prove A's rows are invisible and immutable to B. Running them needs the Supabase CLI and Docker, and only happens when you ask.
- `workers-edge-port`: Node to Workers rewrites (Web Crypto, D1, R2, Hyperdrive, `env` bindings) and package swaps.

## Limits

This is static analysis built on a SQL tokenizer, not a full Postgres parser. It blocks only on patterns it can read with confidence and warns on the rest. It does not see your live database: run Supabase's database advisors (`supabase db lint`) and the generated pgTAP tests for that. Workers compatibility comes from [`compat_matrix.json`](scripts/rls_edge_guard/compat_matrix.json), **measured in local workerd** (wrangler 4.150.0, workerd 2026-10-06) by [`dev/calibrate_matrix.py`](dev/calibrate_matrix.py). Raw results are in [`docs/evidence/compat-calibration.json`](docs/evidence/compat-calibration.json). Local workerd can differ from the deployed runtime, and Cloudflare keeps adding APIs, so rerun the calibration when you bump Wrangler.

## Development

```bash
python3 -m unittest discover -s tests -v      # 3.9+
claude plugin validate --strict .claude-plugin/plugin.json
python3 scripts/guard.py audit path/to/project
```

## License

Apache-2.0
