#!/usr/bin/env python3
"""rls-edge-guard entry point.

  guard.py hook post-edit     PostToolUse (Write|Edit|MultiEdit)
  guard.py hook pre-mcp       PreToolUse on Supabase MCP apply_migration / execute_sql
  guard.py hook pre-deploy    PreToolUse on Bash: supabase db push / wrangler deploy
  guard.py audit [PATH] [--json]

Every hook exits 0 silently unless the edited file or working directory belongs
to a Supabase project or a Cloudflare Workers project. No network access.
Blocking findings: exit 2 with the report on stderr (Claude sees it and fixes
the code). Warnings: printed as additionalContext.
"""
from __future__ import annotations

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rls_edge_guard import edge, keys, project, rls  # noqa: E402
from rls_edge_guard.findings import BLOCK, render  # noqa: E402

DEPLOY_RE = re.compile(r"(?:^|[;&|]\s*|\s)(?:npx\s+|bunx\s+|pnpm\s+(?:dlx\s+)?|yarn\s+)?"
                       r"(supabase\s+(?:db\s+push|migration\s+up)|"
                       r"wrangler\s+(?:deploy|publish|versions\s+(?:upload|deploy)))\b")
MCP_RE = re.compile(r"^mcp__.*supabase.*__(apply_migration|execute_sql)$", re.I)


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _filter(findings, root):
    off = project.disabled_rules(root) if root else set()
    return [f for f in findings if f.rule not in off]


# ------------------------------------------------------------------ analysis
def check_sql_file(path):
    root = project.supabase_root(path)
    if root and project.is_migration(path, root):
        texts = [(f, _read(f) or "") for f in project.migration_files(root)]
        found = rls.lint_sql_texts(texts, project.exposed_schemas(root))
        return _filter([f for f in found if os.path.abspath(f.file) == os.path.abspath(path)], root)
    root = root or project.supabase_client_root(path)
    if not root:
        return None  # not a Supabase project: stay silent
    schemas = project.exposed_schemas(root)
    return _filter(rls.lint_sql_texts([(path, _read(path) or "")], schemas), root)


def check_js_file(path):
    findings, relevant = [], False
    wpath = edge.find_wrangler(os.path.dirname(path))
    cfg = edge.load_wrangler(wpath) if wpath else None
    if cfg and edge.in_scope(path, cfg):
        relevant = True
        src = _read(path) or ""
        findings += edge.check_source(path, src, cfg)
        # A new relative import can pull in a file written earlier; check what it reaches.
        for other in edge.reachable(path)[1:]:
            if edge.in_scope(other, cfg):
                findings += [f for f in edge.check_source(other, _read(other) or "", cfg)
                             if f.severity == BLOCK]
        findings = _filter(findings, cfg.root)
    sroot = project.supabase_root(path) or project.supabase_client_root(path)
    if sroot and keys.applies(path):
        relevant = True
        findings += _filter(keys.check(path, _read(path) or ""), sroot)
    return findings if relevant else None


def check_wrangler_file(path):
    cfg = edge.load_wrangler(path)
    if not cfg:
        return None
    out = []
    for f in edge.worker_files(cfg):
        out += [x for x in edge.check_source(f, _read(f) or "", cfg) if x.severity == BLOCK]
    return _filter(out, cfg.root)


def check_path(path):
    """Findings for one edited file, or None when the file is out of scope."""
    if not os.path.isfile(path):
        return None
    base = os.path.basename(path)
    if path.endswith(".sql"):
        return check_sql_file(path)
    if base in edge.WRANGLER_FILES:
        return check_wrangler_file(path)
    if path.endswith(edge.JS_EXTS) or keys.applies(path):
        return check_js_file(path)
    return None


def audit(root):
    root = os.path.abspath(root)
    findings = []
    supa_roots, wranglers = project.find_projects(root)
    for sroot in supa_roots:
        texts = [(f, _read(f) or "") for f in project.migration_files(sroot)]
        findings += _filter(rls.lint_sql_texts(texts, project.exposed_schemas(sroot)), sroot)
    client_roots = set(supa_roots)
    if not supa_roots and project.supabase_client_root(root):
        client_roots.add(root)
    for croot in client_roots:
        for dirpath, dirnames, filenames in os.walk(croot):
            dirnames[:] = [d for d in dirnames if d not in edge.SKIP_DIRS - {"scripts"}
                           and not d.startswith(".")]
            for name in filenames:
                p = os.path.join(dirpath, name)
                if keys.applies(p):
                    findings += _filter(keys.check(p, _read(p) or ""), croot)
    for w in wranglers:
        cfg = edge.load_wrangler(w)
        if cfg:
            for f in edge.worker_files(cfg):
                findings += _filter(edge.check_source(f, _read(f) or "", cfg), cfg.root)
    seen, unique = set(), []
    for f in findings:
        k = (f.rule, f.file, f.line, f.message)
        if k not in seen:
            seen.add(k)
            unique.append(f)
    return unique


# ------------------------------------------------------------------ hooks
def emit(findings, event, root, header):
    if findings is None:
        return 0
    blocks = [f for f in findings if f.severity == BLOCK]
    if blocks:
        sys.stderr.write(
            f"rls-edge-guard: {header}: {len(blocks)} blocking issue(s). Fix them before "
            "continuing. If one is intended, add a comment on or above the line: "
            "rls-edge-guard-ignore <RULE>: <reason>\n\n" + render(findings, root) + "\n")
        return 2
    if findings:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": event,
            "additionalContext": "rls-edge-guard warnings (non-blocking):\n" + render(findings, root)}}))
    return 0


def hook(mode):
    if os.environ.get("RLS_EDGE_GUARD_DISABLE") == "1":
        return 0
    try:
        payload = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0
    tool_input = payload.get("tool_input") or {}
    cwd = payload.get("cwd") or os.getcwd()

    if mode == "post-edit":
        path = tool_input.get("file_path") or tool_input.get("notebook_path")
        if not path:
            return 0
        if not os.path.isabs(path):
            path = os.path.join(cwd, path)
        return emit(check_path(path), "PostToolUse", cwd, f"after editing {os.path.basename(path)}")

    if mode == "pre-mcp":
        if not MCP_RE.match(payload.get("tool_name") or ""):
            return 0
        query = tool_input.get("query") or ""
        label = "<" + (tool_input.get("name") or "sql") + ">"
        root = project.supabase_root(cwd)
        texts = [(f, _read(f) or "") for f in project.migration_files(root)] if root else []
        schemas = project.exposed_schemas(root) if root else rls.DEFAULT_EXPOSED
        found = rls.lint_sql_texts(texts + [(label, query)], schemas)
        found = _filter([f for f in found if f.file == label], root)
        return emit(found, "PreToolUse", cwd, "SQL sent to Supabase")

    if mode == "pre-deploy":
        command = tool_input.get("command") or ""
        m = DEPLOY_RE.search(command)
        if not m:
            return 0
        found = audit(cwd)
        if m.group(1).startswith("supabase"):
            found = [f for f in found if not f.rule.startswith("EDGE")]
        elif m.group(1).startswith("wrangler"):
            found = [f for f in found if f.rule.startswith(("EDGE", "KEY"))]
        blocks = [f for f in found if f.severity == BLOCK]
        return emit(blocks, "PreToolUse", cwd, f"before `{m.group(1)}`")
    return 0


def main(argv):
    if argv[:1] == ["hook"] and len(argv) > 1:
        return hook(argv[1])
    if argv[:1] == ["audit"]:
        rest = [a for a in argv[1:] if not a.startswith("--")]
        root = rest[0] if rest else "."
        found = audit(root)
        if "--json" in argv:
            print(json.dumps([f.__dict__ for f in found], indent=2))
        else:
            if found:
                print(render(found, os.path.abspath(root)))
            blocks = sum(f.severity == BLOCK for f in found)
            print(f"\nrls-edge-guard: {blocks} blocking, {len(found) - blocks} warning(s)")
        return 1 if any(f.severity == BLOCK for f in found) else 0
    sys.stderr.write(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
