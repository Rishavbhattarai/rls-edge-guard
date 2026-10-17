"""Supabase Row-Level Security linter.

Replays SQL statements (usually every migration, in order) into a small schema
model, then lints the final state. Rule IDs and intent follow Supabase's own
database advisors (splinter) where one exists.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .findings import BLOCK, WARN, Finding
from .sqltok import find_paren_group, read_qualified_name, split

DEFAULT_EXPOSED = ("public", "graphql_public")
API_ROLES = {"anon", "authenticated", "public"}
IDENTITY_FUNCS = {"uid", "jwt", "role", "email"}  # auth.<fn>()
IDENTITY_IDENTS = {"current_user", "session_user", "current_setting", "current_role"}
USER_META_RE = re.compile(r"\b(?:user_metadata|raw_user_meta_data)\b", re.I)

HINTS = {
    "RLS001": "ALTER TABLE {name} ENABLE ROW LEVEL SECURITY; then add policies scoped "
              "TO authenticated with USING ((select auth.uid()) = user_id).",
    "RLS002": "Replace true with an ownership check, e.g. "
              "WITH CHECK ((select auth.uid()) = user_id).",
    "RLS003": "Tie the written row to the caller, e.g. WITH CHECK ((select auth.uid()) = user_id), "
              "or check membership with a subquery.",
    "RLS004": "user_metadata is editable by the user. Use app_metadata "
              "(auth.jwt() -> 'app_metadata') or a roles table.",
    "RLS005": "Add SET search_path = '' and schema-qualify every name in the body, "
              "or move the function to a non-exposed schema.",
    "RLS006": "CREATE VIEW ... WITH (security_invoker = true) AS ..., or "
              "REVOKE SELECT ON {name} FROM anon, authenticated.",
    "RLS007": "Add TO authenticated (or TO anon) so the policy is not evaluated for every role.",
    "RLS008": "Wrap the call: (select auth.uid()). Postgres then evaluates it once per query "
              "instead of once per row.",
    "RLS010": "Confirm this table is meant to be readable by everyone the policy targets. "
              "If so, add a comment: -- rls-edge-guard-ignore RLS010: <why>",
    "RLS011": "REVOKE EXECUTE ON FUNCTION {name} FROM public, anon, authenticated; or move "
              "it to a private schema. SECURITY DEFINER functions bypass RLS.",
    "RLS012": "Materialized views have no RLS. Move it to a private schema or "
              "REVOKE SELECT ON {name} FROM anon, authenticated.",
    "STO001": "Scope storage policies to a bucket: USING (bucket_id = 'avatars' AND ...).",
}


@dataclass
class Loc:
    file: str
    line: int
    ignores: dict


@dataclass
class Table:
    key: tuple
    loc: Loc
    rls: bool = False


@dataclass
class Policy:
    table: tuple
    name: str
    loc: Loc
    cmd: str = "all"
    permissive: bool = True
    roles: list = field(default_factory=list)
    using: list = None
    check: list = None


@dataclass
class Func:
    key: tuple
    loc: Loc
    definer: bool = False
    search_path: bool = False
    reads_user_metadata: bool = False


@dataclass
class View:
    key: tuple
    loc: Loc
    invoker: bool = False
    materialized: bool = False


def _name(key: tuple) -> str:
    return f"{key[0]}.{key[1]}"


class Model:
    def __init__(self, exposed_schemas=DEFAULT_EXPOSED):
        self.exposed = set(exposed_schemas)
        self.tables, self.policies, self.funcs, self.views = {}, {}, {}, {}
        self.revoked = {}          # relation/function key -> roles revoked from
        self.schema_revoked = {}   # schema -> roles revoked on all tables

    # ---------------------------------------------------------------- replay
    def apply_sql(self, sql: str, file: str):
        for st in split(sql):
            try:
                self.apply(st, file)
            except (IndexError, TypeError, AttributeError):
                continue  # malformed or unsupported syntax: skip the statement

    def apply(self, st, file):
        t = st.tokens
        w = [x.low for x in t[:8]]
        loc = Loc(file, st.line, st.ignores)
        if not w:
            return
        i = 1
        if w[0] == "create":
            if w[1:3] == ["or", "replace"]:
                i = 3
            while i < len(w) and w[i] in ("temp", "temporary", "unlogged", "global", "local"):
                if w[i] in ("temp", "temporary"):
                    return
                i += 1
            kind = w[i] if i < len(w) else ""
            if kind == "table":
                self._create_table(t, i + 1, loc)
            elif kind in ("view", "materialized", "recursive"):
                self._create_view(t, i, loc)
            elif kind == "function":
                self._create_function(t, i + 1, loc)
            elif kind == "policy":
                self._policy(t, 2, loc, create=True)
        elif w[0] == "alter":
            if w[1] == "table":
                self._alter_table(t, 2, loc)
            elif w[1] == "policy":
                self._policy(t, 2, loc, create=False)
            elif w[1] == "view" or w[1:3] == ["materialized", "view"]:
                self._alter_view(t, 2 if w[1] == "view" else 3, loc)
            elif w[1] == "function":
                self._alter_function(t, 2, loc)
        elif w[0] == "drop":
            self._drop(t, w)
        elif w[0] in ("grant", "revoke"):
            self._grant(t, w[0] == "revoke")

    def _skip_if_exists(self, t, i, words=("if", "not", "exists")):
        k = 0
        while i < len(t) and k < len(words) and t[i].low == words[k]:
            i, k = i + 1, k + 1
        return i

    def _create_table(self, t, i, loc):
        i = self._skip_if_exists(t, i)
        key, _ = read_qualified_name(t, i)
        if key:
            self.tables[key] = Table(key, loc)

    def _create_view(self, t, i, loc):
        materialized = t[i].low == "materialized"
        while i < len(t) and t[i].low != "view":
            i += 1
        i = self._skip_if_exists(t, i + 1)
        key, i = read_qualified_name(t, i)
        if not key:
            return
        view = View(key, loc, materialized=materialized)
        if i < len(t) and t[i].value == "(":
            _, i = find_paren_group(t, i)
        if i < len(t) and t[i].low == "with" and i + 1 < len(t) and t[i + 1].value == "(":
            opts, _ = find_paren_group(t, i + 1)
            view.invoker = _option_true(opts, "security_invoker")
        self.views[key] = view

    def _create_function(self, t, i, loc):
        key, i = read_qualified_name(t, i)
        if not key:
            return
        f = Func(key, loc)
        if i < len(t) and t[i].value == "(":
            _, i = find_paren_group(t, i)
        _function_options(t[i:], f)
        f.reads_user_metadata = any(x.kind == "string" and USER_META_RE.search(x.value)
                                    for x in t[i:])
        self.funcs[key] = f

    def _alter_function(self, t, i, loc):
        key, i = read_qualified_name(t, self._skip_if_exists(t, i, ("if", "exists")))
        f = self.funcs.get(key)
        if not f:
            return
        if i < len(t) and t[i].value == "(":
            _, i = find_paren_group(t, i)
        rest = t[i:]
        words = [x.low for x in rest]
        if "reset" in words and "search_path" in words:
            f.search_path = False
        _function_options(rest, f)
        f.loc = loc

    def _alter_table(self, t, i, loc):
        i = self._skip_if_exists(t, i, ("if", "exists"))
        if i < len(t) and t[i].low == "only":
            i += 1
        key, i = read_qualified_name(t, i)
        if not key:
            return
        words = [x.low for x in t[i:]]
        if words[:2] == ["rename", "to"] and len(words) > 2:
            new = (key[0], t[i + 2].low)
            if key in self.tables:
                tbl = self.tables.pop(key)
                tbl.key = new
                self.tables[new] = tbl
            for pk in [k for k in self.policies if k[0] == key]:
                p = self.policies.pop(pk)
                p.table = new
                self.policies[(new, pk[1])] = p
            return
        if words[:2] == ["set", "schema"] and len(words) > 2:
            new = (t[i + 2].low, key[1])
            if key in self.tables:
                tbl = self.tables.pop(key)
                tbl.key = new
                self.tables[new] = tbl
            return
        for k in range(len(words) - 2):
            if words[k:k + 3] == ["row", "level", "security"] and k > 0:
                action = words[k - 1]
                tbl = self.tables.get(key)
                if tbl is None:
                    if action in ("enable", "force"):
                        continue
                    tbl = self.tables[key] = Table(key, loc)
                if action in ("enable", "force"):
                    if not (action == "force" and k > 1 and words[k - 2] == "no"):
                        tbl.rls = True
                elif action == "disable":
                    tbl.rls = False
                    tbl.loc = loc

    def _alter_view(self, t, i, loc):
        key, i = read_qualified_name(t, self._skip_if_exists(t, i, ("if", "exists")))
        v = self.views.get(key)
        if not v:
            return
        words = [x.low for x in t[i:]]
        if words[:1] == ["set"] and i + 1 < len(t) and t[i + 1].value == "(":
            opts, _ = find_paren_group(t, i + 1)
            if any(o.low == "security_invoker" for o in opts):
                v.invoker = _option_true(opts, "security_invoker")
                v.loc = loc
        elif words[:1] == ["reset"] and "security_invoker" in words:
            v.invoker = False
            v.loc = loc

    def _policy(self, t, i, loc, create):
        name_tok = t[i]
        name = name_tok.value if name_tok.kind in ("qident", "string") else name_tok.low
        if t[i + 1].low != "on":
            return
        table, i = read_qualified_name(t, i + 2)
        if not table:
            return
        pkey = (table, name)
        p = Policy(table, name, loc) if create else self.policies.get(pkey)
        if p is None:
            return
        p.loc = loc
        while i < len(t):
            word = t[i].low
            if word == "as" and i + 1 < len(t):
                p.permissive = t[i + 1].low != "restrictive"
                i += 2
            elif word == "for" and i + 1 < len(t):
                p.cmd = t[i + 1].low
                i += 2
            elif word == "to":
                i += 1
                roles = []
                while i < len(t) and t[i].kind in ("ident", "qident"):
                    if t[i].low in ("using", "with"):
                        break
                    roles.append(t[i].low)
                    i += 1
                    if i < len(t) and t[i].value == ",":
                        i += 1
                    else:
                        break
                p.roles = roles
            elif word == "using" and i + 1 < len(t) and t[i + 1].value == "(":
                p.using, i = find_paren_group(t, i + 1)
            elif word == "with" and i + 2 < len(t) and t[i + 1].low == "check" \
                    and t[i + 2].value == "(":
                p.check, i = find_paren_group(t, i + 2)
            elif word == "rename" and i + 2 < len(t):
                self.policies.pop(pkey, None)
                p.name = t[i + 2].value if t[i + 2].kind == "qident" else t[i + 2].low
                pkey = (table, p.name)
                i += 3
            else:
                i += 1
        self.policies[pkey] = p

    def _drop(self, t, w):
        kind = w[1]
        i = 2
        if kind == "materialized":
            kind, i = "view", 3
        if kind not in ("table", "view", "function", "policy"):
            return
        i = self._skip_if_exists(t, i, ("if", "exists"))
        if kind == "policy":
            name = t[i].value if t[i].kind == "qident" else t[i].low
            table, _ = read_qualified_name(t, i + 2)
            self.policies.pop((table, name), None)
            return
        while i < len(t):
            key, i = read_qualified_name(t, i)
            if not key:
                break
            if kind == "table":
                self.tables.pop(key, None)
                for pk in [k for k in self.policies if k[0] == key]:
                    del self.policies[pk]
            elif kind == "view":
                self.views.pop(key, None)
            else:
                self.funcs.pop(key, None)
                if i < len(t) and t[i].value == "(":
                    _, i = find_paren_group(t, i)
            if i < len(t) and t[i].value == ",":
                i += 1
            else:
                break

    def _grant(self, t, revoke):
        words = [x.low for x in t]
        try:
            on = words.index("on")
            sep = words.index("from" if revoke else "to", on)
        except ValueError:
            return
        roles = {x.low for x in t[sep + 1:] if x.kind in ("ident", "qident")} & API_ROLES
        if not roles:
            return
        privs = set(words[1:on])
        if not revoke and not (privs & {"select", "all", "execute"}):
            return
        if revoke and not (privs & {"select", "all", "execute"}):
            return
        targets = t[on + 1:sep]
        tw = [x.low for x in targets]
        if tw[:3] == ["all", "tables", "in"] and "schema" in tw:
            for x in targets[tw.index("schema") + 1:]:
                if x.kind in ("ident", "qident"):
                    self._mark(self.schema_revoked, x.low, roles, revoke)
            return
        i = 1 if tw[:1] in (["table"], ["function"], ["view"]) else 0
        while i < len(targets):
            key, i = read_qualified_name(targets, i)
            if not key:
                break
            self._mark(self.revoked, key, roles, revoke)
            if i < len(targets) and targets[i].value == "(":
                _, i = find_paren_group(targets, i)
            if i < len(targets) and targets[i].value == ",":
                i += 1
            else:
                break

    @staticmethod
    def _mark(store, key, roles, revoke):
        cur = store.setdefault(key, set())
        if revoke:
            cur |= roles
        else:
            cur -= roles

    def _hidden_from_api(self, key) -> bool:
        roles = self.revoked.get(key, set()) | self.schema_revoked.get(key[0], set())
        return "public" in roles or {"anon", "authenticated"} <= roles

    # ----------------------------------------------------------------- lint
    def lint(self) -> list:
        out = []

        def add(rule, sev, loc, msg, name=""):
            if rule in loc.ignores:
                return
            out.append(Finding(rule, sev, loc.file, loc.line, msg,
                               HINTS.get(rule, "").replace("{name}", name)))

        for key, tbl in self.tables.items():
            if key[0] in self.exposed and not tbl.rls and not self._hidden_from_api(key):
                has_pol = any(p.table == key for p in self.policies.values())
                why = ("has policies but RLS is not enabled, so the policies do nothing"
                       if has_pol else "has RLS disabled")
                add("RLS001", BLOCK, tbl.loc,
                    f"table {_name(key)} is exposed through the Supabase Data API and {why}. "
                    "Anyone with the anon key can read and write every row.", _name(key))

        for p in self.policies.values():
            self._lint_policy(p, add)

        for key, f in self.funcs.items():
            if key[0] not in self.exposed or not f.definer:
                continue
            if not f.search_path:
                add("RLS005", BLOCK, f.loc,
                    f"SECURITY DEFINER function {_name(key)} has a mutable search_path. "
                    "A caller can shadow objects it references and run code as the owner.",
                    _name(key))
            if not self._hidden_from_api(key):
                add("RLS011", WARN, f.loc,
                    f"SECURITY DEFINER function {_name(key)} is in an exposed schema, so anon "
                    "and authenticated can call it over the API and it bypasses RLS.",
                    _name(key))

        for key, v in self.views.items():
            if key[0] not in self.exposed or self._hidden_from_api(key):
                continue
            if v.materialized:
                add("RLS012", WARN, v.loc,
                    f"materialized view {_name(key)} is exposed through the API and has no RLS.",
                    _name(key))
            elif not v.invoker:
                add("RLS006", BLOCK, v.loc,
                    f"view {_name(key)} runs with its owner's rights (no security_invoker), so it "
                    "bypasses RLS on the tables it reads.", _name(key))
        return out

    def _lint_policy(self, p, add):
        label = f'policy "{p.name}" on {_name(p.table)}'
        roles = set(p.roles) or {"public"}
        api_facing = bool(roles & API_ROLES)
        exprs = [e for e in (p.using, p.check) if e is not None]
        all_tokens = [tok for e in exprs for tok in e]

        meta_funcs = [_name(k) for k in _called_functions(all_tokens)
                      if k in self.funcs and self.funcs[k].reads_user_metadata]
        if any(tok.low in ("user_metadata", "raw_user_meta_data") for tok in all_tokens):
            add("RLS004", BLOCK, p.loc, f"{label} trusts user_metadata, which any signed-in "
                "user can change with supabase.auth.updateUser().")
        elif meta_funcs:
            add("RLS004", BLOCK, p.loc, f"{label} calls {', '.join(meta_funcs)}, which reads "
                "user_metadata. Any signed-in user can change that with supabase.auth.updateUser().")

        if p.table == ("storage", "objects") and p.permissive and exprs \
                and not any(tok.low == "bucket_id" for tok in all_tokens):
            add("STO001", BLOCK, p.loc, f"{label} is not limited to a bucket, so it applies "
                "to every bucket in the project.")

        if p.permissive and api_facing:
            trivially_true = [e for e in exprs if _is_true(e)]
            if trivially_true and p.cmd != "select":
                add("RLS002", BLOCK, p.loc,
                    f"{label} uses a condition that is always true for {p.cmd.upper()}, so "
                    f"{_who(roles)} can write any row.")
            elif trivially_true and p.cmd == "select":
                add("RLS010", WARN, p.loc,
                    f"{label} makes every row readable by {_who(roles)}.")
            elif p.cmd != "select":
                write_expr = (p.check if p.cmd == "insert" else
                              p.using if p.cmd == "delete" else p.check or p.using)
                if write_expr is not None and not _has_identity(write_expr):
                    add("RLS003", WARN, p.loc,
                        f"{label} allows {p.cmd.upper()} without checking who the caller is.")

        if not p.roles:
            add("RLS007", WARN, p.loc, f"{label} has no TO clause, so it applies to every "
                "role, including anon.")

        for e in exprs:
            if _bare_auth_call(e):
                add("RLS008", WARN, p.loc, f"{label} calls auth.*() without (select ...), "
                    "which re-evaluates it for every row.")
                break


def _who(roles) -> str:
    if "public" in roles or "anon" in roles:
        return "anyone with the anon key"
    return "every signed-in user"


def _is_true(expr) -> bool:
    vals = [x.low for x in expr if x.value not in ("(", ")")]
    return vals in (["true"], ["1", "=", "1"], ["true", "::", "boolean"])


def _has_identity(expr) -> bool:
    for k, x in enumerate(expr):
        if x.low in IDENTITY_IDENTS or x.low in ("select", "exists"):
            return True
        if x.low == "auth" and k + 2 < len(expr) and expr[k + 1].value == "." \
                and expr[k + 2].low in IDENTITY_FUNCS:
            return True
        # A call to a schema-qualified function (e.g. private.is_member(...)) is assumed
        # to perform its own membership check.
        if x.value == "." and k + 2 < len(expr) and expr[k + 2].value == "(":
            return True
    return False


def _called_functions(expr):
    """Keys of functions called in a policy expression: f(...) or schema.f(...)."""
    out = []
    for k, x in enumerate(expr):
        if x.kind not in ("ident", "qident") or k + 1 >= len(expr) or expr[k + 1].value != "(":
            continue
        if k >= 2 and expr[k - 1].value == "." and expr[k - 2].kind in ("ident", "qident"):
            out.append((expr[k - 2].low, x.low))
        else:
            out.append(("public", x.low))
    return out


def _bare_auth_call(expr) -> bool:
    for k, x in enumerate(expr):
        if x.low == "auth" and k + 3 < len(expr) and expr[k + 1].value == "." \
                and expr[k + 2].low in IDENTITY_FUNCS and expr[k + 3].value == "(":
            prev = expr[k - 1].low if k >= 1 else ""
            if prev != "select":
                return True
    return False


def _option_true(opts, name) -> bool:
    for k, o in enumerate(opts):
        if o.low == name:
            if k + 2 < len(opts) and opts[k + 1].value == "=":
                return opts[k + 2].low in ("true", "on", "1", "yes")
            return True  # bare option name means true
    return False


def _function_options(tokens, f):
    for k, x in enumerate(tokens):
        if x.low == "security" and k + 1 < len(tokens):
            f.definer = tokens[k + 1].low == "definer"
        elif x.low == "set" and k + 1 < len(tokens) and tokens[k + 1].low == "search_path":
            f.search_path = True


def lint_sql_texts(texts, exposed_schemas=DEFAULT_EXPOSED) -> list:
    """texts: iterable of (file, sql) in replay order."""
    model = Model(exposed_schemas)
    for file, sql in texts:
        model.apply_sql(sql, file)
    return model.lint()
