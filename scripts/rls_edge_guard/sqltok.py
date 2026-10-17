"""Small PostgreSQL tokenizer and statement splitter.

Not a parser. It knows enough lexical structure (strings, E'' strings, dollar
quoting, quoted identifiers, nested block comments, BEGIN ATOMIC bodies) to split
a migration into statements and hand the rule engine clean token lists.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

IGNORE_RE = re.compile(r"rls-edge-guard-ignore\s+([A-Z]+[0-9]{3})\s*:\s*(\S.*)")

_IDENT_START = re.compile(r"[A-Za-z_\u0080-￿]")
_IDENT_CHARS = re.compile(r"[A-Za-z0-9_$\u0080-￿]*")
_NUMBER = re.compile(r"\d+(?:\.\d*)?(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?")
_DOLLAR_TAG = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")
_OPERATOR_CHARS = set("+-*/<>=~!@#%^&|`?")


@dataclass
class Token:
    kind: str   # ident | qident | string | number | op | punct | param
    value: str  # raw text for punct/op/number; unquoted text for strings and identifiers
    line: int

    @property
    def low(self) -> str:
        # Quoted identifiers keep their case; everything else compares lowercase.
        return self.value if self.kind == "qident" else self.value.lower()

    def is_kw(self, *words: str) -> bool:
        return self.kind == "ident" and self.value.lower() in words


@dataclass
class Statement:
    tokens: list
    line: int                       # line of the first token
    end_line: int
    ignores: dict = field(default_factory=dict)  # RULE -> reason

    def words(self, n: int) -> list:
        return [t.low for t in self.tokens[:n]]


def tokenize(sql: str):
    """Yield Token objects and ('comment', text, line) tuples."""
    i, n, line = 0, len(sql), 1
    while i < n:
        c = sql[i]
        if c == "\n":
            line += 1
            i += 1
        elif c.isspace():
            i += 1
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            j = n if j < 0 else j
            yield ("comment", sql[i + 2:j], line)
            i = j
        elif sql.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if sql.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif sql.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            text = sql[i + 2:j - 2]
            yield ("comment", text, line)
            line += text.count("\n")
            i = j
        elif c in "eE" and i + 1 < n and sql[i + 1] == "'":
            value, j = _read_quoted(sql, i + 1, "'", backslash=True)
            yield Token("string", value, line)
            line += sql.count("\n", i, j)
            i = j
        elif c == "'":
            value, j = _read_quoted(sql, i, "'", backslash=False)
            yield Token("string", value, line)
            line += sql.count("\n", i, j)
            i = j
        elif c == '"':
            value, j = _read_quoted(sql, i, '"', backslash=False)
            yield Token("qident", value, line)
            line += sql.count("\n", i, j)
            i = j
        elif c == "$":
            m = _DOLLAR_TAG.match(sql, i)
            if m:
                tag = m.group(0)
                end = sql.find(tag, m.end())
                end = n if end < 0 else end
                body = sql[m.end():end]
                yield Token("string", body, line)
                line += body.count("\n")
                i = min(n, end + len(tag))
            else:
                m = re.compile(r"\$\d+").match(sql, i)
                j = m.end() if m else i + 1
                yield Token("param", sql[i:j], line)
                i = j
        elif _IDENT_START.match(c):
            m = _IDENT_CHARS.match(sql, i + 1)
            yield Token("ident", sql[i:m.end()], line)
            i = m.end()
        elif c.isdigit() or (c == "." and i + 1 < n and sql[i + 1].isdigit()):
            m = _NUMBER.match(sql, i)
            yield Token("number", m.group(0), line)
            i = m.end()
        elif c in "(),;[].:":
            if sql.startswith("::", i):
                yield Token("op", "::", line)
                i += 2
            else:
                yield Token("punct", c, line)
                i += 1
        elif c in _OPERATOR_CHARS:
            j = i
            while j < n and sql[j] in _OPERATOR_CHARS and not sql.startswith("--", j) \
                    and not sql.startswith("/*", j):
                j += 1
            yield Token("op", sql[i:j] or c, line)
            i = max(j, i + 1)
        else:
            yield Token("punct", c, line)
            i += 1


def _read_quoted(sql: str, i: int, q: str, backslash: bool):
    """Read a quoted literal starting at sql[i] == q. Returns (value, end_index)."""
    out, j, n = [], i + 1, len(sql)
    while j < n:
        ch = sql[j]
        if backslash and ch == "\\" and j + 1 < n:
            out.append(sql[j + 1])
            j += 2
        elif ch == q:
            if j + 1 < n and sql[j + 1] == q:
                out.append(q)
                j += 2
            else:
                return "".join(out), j + 1
        else:
            out.append(ch)
            j += 1
    return "".join(out), n


def split(sql: str) -> list:
    """Split SQL text into Statements, attaching ignore markers.

    A marker applies to a statement when it sits on any of the statement's lines
    or on the line directly above its first token.
    """
    statements, current, markers = [], [], []
    atomic = 0
    for tok in tokenize(sql):
        if isinstance(tok, tuple):
            m = IGNORE_RE.search(tok[1])
            if m:
                markers.append((tok[2], m.group(1), m.group(2).strip()))
            continue
        if tok.kind == "ident" and tok.low == "atomic" and current and current[-1].is_kw("begin"):
            atomic += 1
        elif atomic and tok.is_kw("end"):
            atomic -= 1
        if tok.kind == "punct" and tok.value == ";" and not atomic:
            if current:
                statements.append(current)
            current = []
            continue
        current.append(tok)
    if current:
        statements.append(current)

    result = []
    for toks in statements:
        st = Statement(toks, toks[0].line, toks[-1].line)
        for line, rule, reason in markers:
            if st.line - 1 <= line <= st.end_line:
                st.ignores[rule] = reason
        result.append(st)
    return result


def find_paren_group(tokens: list, start: int):
    """tokens[start] must be '('. Returns (inner_tokens, index_after_close)."""
    depth = 0
    for k in range(start, len(tokens)):
        t = tokens[k]
        if t.kind == "punct" and t.value == "(":
            depth += 1
        elif t.kind == "punct" and t.value == ")":
            depth -= 1
            if depth == 0:
                return tokens[start + 1:k], k + 1
    return tokens[start + 1:], len(tokens)


def read_qualified_name(tokens: list, i: int, default_schema: str = "public"):
    """Read `name` or `schema.name` at tokens[i]. Returns ((schema, name), next_index)."""
    if i >= len(tokens) or tokens[i].kind not in ("ident", "qident"):
        return None, i
    first = tokens[i].low
    if i + 2 < len(tokens) and tokens[i + 1].kind == "punct" and tokens[i + 1].value == "." \
            and tokens[i + 2].kind in ("ident", "qident"):
        return (first, tokens[i + 2].low), i + 3
    return (default_schema, first), i + 1
