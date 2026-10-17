"""Cloudflare Workers runtime compatibility checks.

Reads the project's wrangler config (compatibility_date, compatibility_flags,
main) and checks Worker source against compat_matrix.json.
"""
from __future__ import annotations

import json
import os
import re

from . import jsscan
from .findings import BLOCK, WARN, Finding

WRANGLER_FILES = ("wrangler.jsonc", "wrangler.json", "wrangler.toml")
JS_EXTS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
SKIP_DIRS = {"node_modules", ".wrangler", ".git", "dist", "build", ".open-next", ".next",
             ".svelte-kit", ".output", "coverage", "test", "tests", "__tests__", "scripts"}
TEST_FILE = re.compile(r"\.(test|spec)\.[cm]?[jt]sx?$|\.config\.[cm]?[jt]s$|\.d\.ts$")
MAX_FILES = 400

_MATRIX = None
OVERRIDES = {}  # abs path -> content, for checking an edit before it is written


def read_source(path: str):
    if path in OVERRIDES:
        return OVERRIDES[path]
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def matrix() -> dict:
    global _MATRIX
    if _MATRIX is None:
        with open(os.path.join(os.path.dirname(__file__), "compat_matrix.json")) as fh:
            _MATRIX = json.load(fh)
    return _MATRIX


# ------------------------------------------------------------ wrangler config
class WranglerConfig:
    def __init__(self, path: str, data: dict):
        self.path = path
        self.root = os.path.dirname(path)
        self.date = str(data.get("compatibility_date") or "")
        self.flags = set(data.get("compatibility_flags") or [])
        self.legacy_node_compat = bool(data.get("node_compat"))
        main = data.get("main")
        self.main = os.path.normpath(os.path.join(self.root, main)) if main else None

    @property
    def nodejs_compat(self) -> bool:
        return bool(self.flags & {"nodejs_compat", "nodejs_compat_v2"})

    @property
    def v2(self) -> bool:
        if "no_nodejs_compat_v2" in self.flags:
            return False
        return self.nodejs_compat and (
            "nodejs_compat_v2" in self.flags or self.date >= matrix()["v2_date"])

    @property
    def fs_real(self) -> bool:
        return self.v2 and self.date >= matrix()["fs_date"]

    @property
    def process_global(self) -> bool:
        return self.nodejs_compat or self.date >= matrix()["process_global_no_flags_date"]

    @property
    def process_env_populated(self) -> bool:
        if "nodejs_compat_do_not_populate_process_env" in self.flags:
            return False
        if not self.nodejs_compat:
            return self.process_global
        return ("nodejs_compat_populate_process_env" in self.flags
                or self.date >= matrix()["process_env_date"])

    def flag_fix(self) -> str:
        if self.path.endswith(".toml"):
            return 'compatibility_flags = ["nodejs_compat"]  (wrangler.toml)'
        return '"compatibility_flags": ["nodejs_compat"]  (wrangler config)'


def find_wrangler(start_dir: str, stop: str = "/"):
    d = os.path.abspath(start_dir)
    while True:
        for name in WRANGLER_FILES:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
        parent = os.path.dirname(d)
        if parent == d or d == stop:
            return None
        d = parent


def load_wrangler(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None
    data = {}
    if path.endswith(".toml"):
        data = _parse_toml(text)
    else:
        try:
            data = json.loads(_strip_jsonc(text))
        except ValueError:
            data = {}
    return WranglerConfig(path, data if isinstance(data, dict) else {})


def _parse_toml(text: str) -> dict:
    try:
        import tomllib  # Python 3.11+
        return tomllib.loads(text)
    except ImportError:
        pass
    except Exception:  # invalid TOML: fall through to the line reader
        pass
    return _parse_toml_lines(text)


def _parse_toml_lines(text: str) -> dict:
    """Top-level main/compatibility_* keys only. Used where tomllib is unavailable."""
    data = {}
    for line in text.splitlines():
        if line.strip().startswith("["):
            break  # top-level keys only
        m = re.match(r'\s*(main|compatibility_date|node_compat)\s*=\s*"?([^"#\n]+?)"?\s*(#.*)?$', line)
        if m:
            data[m.group(1)] = m.group(2) if m.group(1) != "node_compat" else m.group(2) == "true"
        m = re.match(r"\s*compatibility_flags\s*=\s*\[(.*)\]", line)
        if m:
            data["compatibility_flags"] = re.findall(r'"([^"]+)"', m.group(1))
    return data


def _strip_jsonc(text: str) -> str:
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


# ------------------------------------------------------------ worker scope
def _resolve(spec: str, from_file: str):
    base = os.path.normpath(os.path.join(os.path.dirname(from_file), spec))
    stem, ext = os.path.splitext(base)
    candidates = [base]
    if ext in (".js", ".mjs", ".cjs", ".jsx"):  # TS projects import "./x.js" for "./x.ts"
        candidates += [stem + e for e in (".ts", ".tsx", ".mts", ".cts")]
    candidates += [base + e for e in JS_EXTS] + [os.path.join(base, "index" + e) for e in JS_EXTS]
    for c in candidates:
        if (c in OVERRIDES or os.path.isfile(c)) and c.endswith(JS_EXTS):
            return c
    return None


def reachable(entry: str, limit: int = MAX_FILES) -> list:
    """Files reachable from entry through relative imports."""
    seen, stack = [], [entry]
    while stack and len(seen) < limit:
        f = stack.pop()
        if f in seen or not (f in OVERRIDES or os.path.isfile(f)):
            continue
        seen.append(f)
        src = read_source(f)
        if src is None:
            continue
        no_comments, no_strings, _ = jsscan.blank(src)
        for spec, _, type_only in jsscan.imports(no_comments, no_strings):
            if spec.startswith(".") and not type_only:
                r = _resolve(spec, f)
                if r and r not in seen:
                    stack.append(r)
    return seen


def main_is_source(cfg: WranglerConfig) -> bool:
    if not cfg.main:
        return False
    rel = os.path.relpath(cfg.main, cfg.root).split(os.sep)
    return not (set(rel[:-1]) & SKIP_DIRS)


def in_scope(path: str, cfg: WranglerConfig) -> bool:
    """Is this file part of the Worker (rather than tests, config, or build output)?"""
    if not path.endswith(JS_EXTS) or TEST_FILE.search(path):
        return False
    rel = os.path.relpath(path, cfg.root)
    if rel.startswith(".."):
        return False
    if set(rel.split(os.sep)[:-1]) & SKIP_DIRS:
        return False
    if cfg.main and main_is_source(cfg):
        main_dir = os.path.dirname(cfg.main)
        if os.path.abspath(path).startswith(main_dir + os.sep):
            return True
        return path in reachable(cfg.main)
    return True  # main is missing or a build artifact: treat the project as Worker code


def worker_files(cfg: WranglerConfig) -> list:
    files = []
    if cfg.main and main_is_source(cfg):
        files = reachable(cfg.main)
        main_dir = os.path.dirname(cfg.main)
        files += [f for f in _walk(main_dir) if f not in files]
    else:
        files = list(_walk(cfg.root))
    return [f for f in files if in_scope(f, cfg)][:MAX_FILES]


def _walk(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if name.endswith(JS_EXTS):
                yield os.path.join(dirpath, name)


# ------------------------------------------------------------ rules
_EVAL = re.compile(r"(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(")
_PROCESS_ENV = re.compile(r"(?<![\w$.])process\.env\b")
_TOP_LEVEL_IO = re.compile(r"(?<![\w$.])(fetch|setTimeout|setInterval|connect)\s*\(|"
                           r"(?<![\w$.])crypto\.getRandomValues\s*\(|"
                           r"(?<![\w$.])caches\.default\b")


def _builtin_name(spec: str):
    """'node:fs/promises' -> ('fs/promises', True); 'fs' -> ('fs', False); else None."""
    if spec.startswith("node:"):
        return spec[5:], True
    m = matrix()
    if spec in set(m["v1"]) | set(m["v2"]) | set(m["fs"]) | set(m["runtime_error"]) | set(m["partial"]):
        return spec, False
    return None


def _package_name(spec: str):
    if spec.startswith((".", "/", "cloudflare:", "node:", "#", "~", "@/", "virtual:")):
        return None
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") else parts[0]


def check_source(path: str, src: str, cfg: WranglerConfig) -> list:
    m = matrix()
    out = []
    no_comments, no_strings, ignores = jsscan.blank(src)

    def add(rule, sev, line, msg, fix=""):
        if rule in ignores.get(line, {}) or rule in ignores.get(line - 1, {}):
            return
        out.append(Finding(rule, sev, path, line, msg, fix))

    for spec, line, type_only in jsscan.imports(no_comments, no_strings):
        if type_only:
            continue
        b = _builtin_name(spec)
        if b:
            name, prefixed = b
            _check_builtin(name, prefixed, spec, line, cfg, add, m)
            continue
        pkg = _package_name(spec)
        if pkg in m["packages"]["block"]:
            add("EDGE003", BLOCK, line, f"'{pkg}' does not run in Workers: "
                f"{m['packages']['block'][pkg]}")
        elif pkg in m["packages"]["warn"]:
            add("EDGE003", WARN, line, f"'{pkg}' is a poor fit for Workers: "
                f"{m['packages']['warn'][pkg]}")

    for hit in _EVAL.finditer(no_strings):
        add("EDGE004", BLOCK, jsscan.line_of(no_strings, hit.start()),
            "eval() and new Function() are disallowed in Workers and throw at runtime.",
            "Parse data with JSON.parse, or precompile templates at build time.")

    hit = _PROCESS_ENV.search(no_strings)
    if hit:
        line = jsscan.line_of(no_strings, hit.start())
        if not cfg.process_global:
            add("EDGE005", BLOCK, line, "process is not defined in Workers without nodejs_compat "
                f"(compatibility_date {cfg.date or 'unset'}), so process.env throws a ReferenceError.",
                "Read bindings from the env argument (env.MY_SECRET), or add " + cfg.flag_fix())
        elif not cfg.process_env_populated:
            add("EDGE005", WARN, line, f"process.env is empty with compatibility_date {cfg.date}, "
                "so every value reads as undefined.",
                f"Read env.MY_SECRET from the handler's env argument, or set compatibility_date "
                f">= {matrix()['process_env_date']}.")

    _check_top_level_io(no_strings, add)
    return out


def _check_builtin(name, prefixed, spec, line, cfg, add, m):
    base = name
    top = base.split("/")[0]
    if base in m["runtime_error"]:
        add("EDGE001", BLOCK, line, f"'{spec}' can be imported but its APIs throw in Workers.",
            m["alternatives"].get(top, ""))
        return
    if base in m["partial"]:
        add("EDGE001", WARN, line, f"'{spec}' is only a partial stub in Workers. Expect missing "
            "or non-functional APIs.", m["alternatives"].get(top, ""))
        return
    if base in m["no_flags"] and prefixed:
        return
    if not prefixed and not cfg.nodejs_compat and _shim_installed(cfg.root, base):
        return  # bare specifier resolves to an npm polyfill (e.g. 'events', 'buffer')
    if not cfg.nodejs_compat:
        if cfg.legacy_node_compat:
            add("EDGE002", WARN, line, f"'{spec}' relies on legacy node_compat polyfills, which "
                "Wrangler 4 removed.", "Replace node_compat = true with " + cfg.flag_fix())
            return
        add("EDGE002", BLOCK, line, f"'{spec}' needs the nodejs_compat flag, which is not set in "
            f"{os.path.basename(cfg.path)}. The Worker fails to start.", "Add " + cfg.flag_fix())
        return
    if base in m["fs"]:
        if not cfg.v2:
            add("EDGE002", BLOCK, line, f"'{spec}' needs nodejs_compat v2, but compatibility_date "
                f"is {cfg.date or 'unset'}.", f"Set compatibility_date >= {m['fs_date']}.")
        elif not cfg.fs_real:
            add("EDGE001", BLOCK, line, f"'{spec}' is a stub before compatibility_date "
                f"{m['fs_date']} (this project: {cfg.date}); calls like readFileSync throw.",
                f"Set compatibility_date >= {m['fs_date']}, or: {m['alternatives']['fs']}")
        else:
            add("EDGE007", WARN, line, "node:fs in Workers is a virtual filesystem. Files from "
                "your project are not there at runtime.", m["alternatives"]["fs"])
        return
    if cfg.v2:
        return
    if base in m["v1"]:
        if prefixed:
            return
        add("EDGE002", BLOCK, line, f"bare '{spec}' needs the node: prefix under nodejs_compat v1 "
            f"(compatibility_date {cfg.date or 'unset'}).",
            f"Import 'node:{spec}', or set compatibility_date >= {m['v2_date']}.")
    elif base in m["v2"]:
        add("EDGE002", BLOCK, line, f"'{spec}' needs nodejs_compat v2, but compatibility_date is "
            f"{cfg.date or 'unset'}.", f"Set compatibility_date >= {m['v2_date']}.")


def _shim_installed(root: str, name: str) -> bool:
    return os.path.isdir(os.path.join(root, "node_modules", name.split("/")[0]))


def _check_top_level_io(no_strings: str, add):
    """Warn on calls that run at module scope. Text nested in braces is masked out."""
    depth, top = 0, []
    for ch in no_strings:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        top.append(ch if depth == 0 or ch == "\n" else " ")
    top = "".join(top)
    stmt_start = 0
    for k, ch in enumerate(top + "\n"):
        if ch not in ";\n":
            continue
        stmt = top[stmt_start:k]
        hit = _TOP_LEVEL_IO.search(stmt)
        if hit and "=>" not in stmt[:hit.start()] and "function" not in stmt[:hit.start()]:
            add("EDGE006", WARN, jsscan.line_of(top, stmt_start + hit.start()),
                f"'{hit.group(0).strip('( ')}' runs at module scope. Workers do not allow I/O "
                "or timers outside a request handler.",
                "Move it inside fetch()/scheduled(), or into a lazily initialised helper.")
        stmt_start = k + 1
