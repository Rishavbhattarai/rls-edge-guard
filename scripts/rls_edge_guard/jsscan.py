"""Lexical helpers for JavaScript/TypeScript source.

`blank()` returns two copies of the source with identical length and line
breaks: one with comments blanked, one with comments and string contents
blanked. Rules search the second copy for code patterns and the first for
import specifiers.
"""
from __future__ import annotations

import re

_REGEX_PREV = set("(,=:[!&|?{};+-*%<>~^") | {""}
_REGEX_PREV_WORDS = {"return", "typeof", "case", "do", "else", "in", "of", "void", "yield", "await"}

IGNORE_RE = re.compile(r"rls-edge-guard-ignore\s+([A-Z]+[0-9]{3})\s*:\s*(\S.*)")


def blank(src: str):
    n = len(src)
    no_comments = list(src)
    no_strings = list(src)
    ignores = {}  # line -> {rule: reason}
    i, line = 0, 1
    brace_stack = []  # for template literals: depth of ${ ... } nesting
    prev_sig = ""     # previous significant char or word, for regex detection

    def wipe(a, b, both=True):
        for k in range(a, b):
            if src[k] != "\n":
                no_strings[k] = " "
                if both:
                    no_comments[k] = " "

    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c.isspace():
            i += 1
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            m = IGNORE_RE.search(src, i, j)
            if m:
                ignores.setdefault(line, {})[m.group(1)] = m.group(2).strip()
            wipe(i, j)
            i = j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            m = IGNORE_RE.search(src, i, j)
            if m:
                ignores.setdefault(line, {})[m.group(1)] = m.group(2).strip()
            line += src.count("\n", i, j)
            wipe(i, j)
            i = j
            continue
        if c in "'\"":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            wipe(i + 1, min(j, n), both=False)
            i = j + 1
            prev_sig = "str"
            continue
        if c == "`" or (c == "}" and brace_stack and brace_stack[-1] == 0):
            if c == "}":
                brace_stack.pop()
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                elif src[j] == "`":
                    break
                elif src.startswith("${", j):
                    break
                else:
                    j += 1
            line += src.count("\n", i, min(j, n))
            wipe(i + 1, min(j, n), both=False)
            if j < n and src.startswith("${", j):
                brace_stack.append(0)
                i = j + 2
            else:
                i = j + 1
            prev_sig = "str"
            continue
        if c == "/" and (prev_sig in _REGEX_PREV or prev_sig in _REGEX_PREV_WORDS):
            j, in_class = i + 1, False
            while j < n and src[j] != "\n":
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == "[":
                    in_class = True
                elif src[j] == "]":
                    in_class = False
                elif src[j] == "/" and not in_class:
                    break
                j += 1
            wipe(i + 1, min(j, n), both=False)
            i = j + 1
            prev_sig = "str"
            continue
        if brace_stack:
            if c == "{":
                brace_stack[-1] += 1
            elif c == "}":
                brace_stack[-1] -= 1
        if c.isalnum() or c in "_$":
            m = re.compile(r"[\w$]+").match(src, i)
            prev_sig = m.group(0)
            i = m.end()
            continue
        prev_sig = c
        i += 1
    return "".join(no_comments), "".join(no_strings), ignores


_IMPORT_PATTERNS = [
    re.compile(r"\bimport\s+(?:type\s+)?[\w$*{}\s,]*?\bfrom\s*(['\"])([^'\"\n]+)\1"),
    re.compile(r"\bexport\s+(?:type\s+)?[\w$*{}\s,]*?\bfrom\s*(['\"])([^'\"\n]+)\1"),
    re.compile(r"\bimport\s*(['\"])([^'\"\n]+)\1"),
    re.compile(r"\bimport\s*\(\s*(['\"])([^'\"\n]+)\1\s*\)"),
    re.compile(r"\brequire\s*\(\s*(['\"])([^'\"\n]+)\1\s*\)"),
]
_TYPE_ONLY = re.compile(r"\b(?:import|export)\s+type\b")


def imports(no_comments: str, no_strings: str = None):
    """Yield (specifier, line, type_only) for static imports, re-exports, import(), require().

    Pass no_strings too so that import-looking text inside string literals is skipped.
    """
    seen = set()
    for pat in _IMPORT_PATTERNS:
        for m in pat.finditer(no_comments):
            pos = m.start(2)
            if pos in seen or (no_strings is not None and no_strings[m.start()].isspace()):
                continue
            seen.add(pos)
            line = no_comments.count("\n", 0, pos) + 1
            yield m.group(2), line, bool(_TYPE_ONLY.match(no_comments, m.start()))


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1
