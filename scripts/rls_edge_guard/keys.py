"""Supabase secret-key exposure checks (KEY001).

Only the edited file is read. Secret values are inspected in memory to classify
them and are never printed.
"""
from __future__ import annotations

import base64
import json
import os
import re

from . import jsscan
from .findings import BLOCK, Finding

CLIENT_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro")
PUBLIC_SECRET_VAR = re.compile(
    r"\b(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|PUBLIC_|REACT_APP_|NUXT_PUBLIC_|GATSBY_)"
    r"\w*(?:SERVICE_ROLE|SECRET_KEY|SECRET)\w*")
SB_SECRET = re.compile(r"\bsb_secret_[A-Za-z0-9_-]{8,}")
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}")
USE_CLIENT = re.compile(r"""^\s*(?:(?://[^\n]*|/\*.*?\*/)\s*)*['"]use client['"]""", re.S)
SERVICE_ROLE_REF = re.compile(r"SERVICE_ROLE|sb_secret_")

FIX = ("Keep service-role and sb_secret_ keys on the server only (API routes, server actions, "
       "Edge Functions). Browsers get the anon or publishable key, and RLS does the rest.")


def is_env_file(path: str) -> bool:
    return os.path.basename(path).startswith(".env")


def applies(path: str) -> bool:
    return path.endswith(CLIENT_EXTS) or is_env_file(path)


def _jwt_role(segment: str):
    try:
        pad = "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(segment + pad)).get("role")
    except (ValueError, TypeError, AttributeError):
        return None


def check(path: str, src: str) -> list:
    out = []
    env = is_env_file(path)
    if env:
        code = src
        ignores = {}
    else:
        _, code, ignores = jsscan.blank(src)  # code with strings blanked

    def add(line, msg):
        if "KEY001" in ignores.get(line, {}) or "KEY001" in ignores.get(line - 1, {}):
            return
        out.append(Finding("KEY001", BLOCK, path, line, msg, FIX))

    # Public-prefixed variable names are visible in code identifiers and in .env keys.
    for m in PUBLIC_SECRET_VAR.finditer(src if env else code):
        if env and not re.match(r"\s*(?:export\s+)?$", src[src.rfind("\n", 0, m.start()) + 1:m.start()]):
            continue
        add(jsscan.line_of(src, m.start()),
            f"{m.group(0)} puts a secret in a variable the framework ships to the browser.")
    if env:
        return out

    for m in SB_SECRET.finditer(src):
        add(jsscan.line_of(src, m.start()), "a Supabase secret key (sb_secret_...) is hardcoded "
            "in source. It bypasses RLS for anyone who sees it.")
    for m in JWT.finditer(src):
        if _jwt_role(m.group(1)) == "service_role":
            add(jsscan.line_of(src, m.start()), "a service_role JWT is hardcoded in source. "
                "It bypasses RLS for anyone who sees it.")

    if USE_CLIENT.match(src):
        m = SERVICE_ROLE_REF.search(src)
        if m:
            add(jsscan.line_of(src, m.start()), "a 'use client' component references the "
                "service-role key, so it would be bundled for the browser.")
    return out
