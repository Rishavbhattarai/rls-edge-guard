"""Project detection (the hooks' relevance gate) and per-project settings."""
from __future__ import annotations

import glob
import json
import os
import re

from .rls import DEFAULT_EXPOSED

SUPABASE_DEPS = ("@supabase/supabase-js", "@supabase/ssr", "@supabase/auth-helpers-nextjs",
                 "@supabase/auth-helpers-react", "@supabase/auth-helpers-sveltekit")
SETTINGS_FILE = ".rls-edge-guard.json"


def _ancestors(start: str):
    d = os.path.abspath(start if os.path.isdir(start) else os.path.dirname(start))
    while True:
        yield d
        parent = os.path.dirname(d)
        if parent == d:
            return
        d = parent


def supabase_root(start: str):
    """Nearest ancestor that holds a Supabase CLI project (supabase/config.toml or migrations)."""
    for d in _ancestors(start):
        s = os.path.join(d, "supabase")
        if os.path.isfile(os.path.join(s, "config.toml")) or os.path.isdir(os.path.join(s, "migrations")):
            return d
    return None


def supabase_client_root(start: str):
    """Nearest package.json that depends on a Supabase client library."""
    for d in _ancestors(start):
        p = os.path.join(d, "package.json")
        if os.path.isfile(p):
            try:
                with open(p, encoding="utf-8") as fh:
                    pkg = json.load(fh)
            except (OSError, ValueError):
                continue
            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            if any(dep in deps for dep in SUPABASE_DEPS):
                return d
    return None


def exposed_schemas(root: str):
    """[api] schemas from supabase/config.toml; Supabase's defaults otherwise."""
    path = os.path.join(root, "supabase", "config.toml")
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return list(DEFAULT_EXPOSED)
    section = re.search(r"^\[api\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    if section:
        m = re.search(r"^\s*schemas\s*=\s*\[(.*?)\]", section.group(1), re.M | re.S)
        if m:
            schemas = re.findall(r'"([^"]+)"', m.group(1))
            if schemas:
                return schemas
    return list(DEFAULT_EXPOSED)


def migration_files(root: str) -> list:
    base = os.path.join(root, "supabase")
    files = sorted(glob.glob(os.path.join(base, "migrations", "*.sql")))
    files += sorted(glob.glob(os.path.join(base, "schemas", "**", "*.sql"), recursive=True))
    return files


def is_migration(path: str, root: str) -> bool:
    return os.path.abspath(path) in {os.path.abspath(f) for f in migration_files(root)}


def disabled_rules(root: str) -> set:
    try:
        with open(os.path.join(root, SETTINGS_FILE), encoding="utf-8") as fh:
            return set(json.load(fh).get("disable", []))
    except (OSError, ValueError, AttributeError):
        return set()


def find_projects(root: str, max_depth: int = 4):
    """For audits: every Supabase root and wrangler config at or below root."""
    supa, wrangler = [], []
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = dirpath[len(root):].count(os.sep)
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", ".wrangler")
                       and not d.startswith(".")] if depth < max_depth else []
        if "supabase" in dirnames:
            s = os.path.join(dirpath, "supabase")
            if os.path.isfile(os.path.join(s, "config.toml")) or os.path.isdir(os.path.join(s, "migrations")):
                supa.append(dirpath)
        for name in ("wrangler.jsonc", "wrangler.json", "wrangler.toml"):
            if name in filenames:
                wrangler.append(os.path.join(dirpath, name))
                break
    return supa, wrangler
