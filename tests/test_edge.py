import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from rls_edge_guard import edge, jsscan  # noqa: E402


def project(files):
    d = tempfile.mkdtemp(prefix="reg-edge-")
    for rel, text in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(text)
    return d


def cfg_for(toml):
    d = project({"wrangler.toml": toml})
    return edge.load_wrangler(os.path.join(d, "wrangler.toml"))


COMPAT = cfg_for('name = "w"\nmain = "src/index.ts"\ncompatibility_date = "2025-06-01"\n'
                 'compatibility_flags = ["nodejs_compat"]\n')
NO_COMPAT = cfg_for('name = "w"\nmain = "src/index.ts"\ncompatibility_date = "2025-06-01"\n')
V1 = cfg_for('name = "w"\ncompatibility_date = "2024-01-01"\ncompatibility_flags = ["nodejs_compat"]\n')


def rules(src, cfg, severity=None):
    return sorted(f.rule for f in edge.check_source("x.ts", src, cfg)
                  if severity is None or f.severity == severity)


class Scanner(unittest.TestCase):
    def test_imports_ignore_comments_and_strings(self):
        src = ("// import fs from 'fs'\n/* require('child_process') */\n"
               "const s = \"import x from 'net'\";\nimport { a } from './a.js';\n"
               "export * from 'node:path';\nconst m = await import('node:zlib');\n"
               "import type { T } from 'node:fs';\n")
        no_comments, _, _ = jsscan.blank(src)
        got = sorted((s, t) for s, _, t in jsscan.imports(no_comments, jsscan.blank(src)[1]))
        self.assertEqual(got, [("./a.js", False), ("node:fs", True), ("node:path", False),
                               ("node:zlib", False)])

    def test_template_literal_and_regex(self):
        src = "const a = `eval(${b}) ${ {x: 1}.x }`;\nconst r = /eval\\(/g;\nlet c = d / e / f;\n"
        _, no_strings, _ = jsscan.blank(src)
        self.assertNotIn("eval(", no_strings)
        self.assertIn("{x: 1}", no_strings)
        self.assertIn("d / e / f", no_strings)

    def test_line_count_preserved(self):
        src = "a\n`x\ny`\n/* c\nd */\n'z'\n"
        for out in jsscan.blank(src)[:2]:
            self.assertEqual(out.count("\n"), src.count("\n"))


class Config(unittest.TestCase):
    def test_toml(self):
        self.assertTrue(COMPAT.nodejs_compat and COMPAT.v2 and COMPAT.process_env_populated)
        self.assertFalse(NO_COMPAT.nodejs_compat)
        self.assertTrue(V1.nodejs_compat and not V1.v2)
        self.assertTrue(COMPAT.main.endswith(os.path.join("src", "index.ts")))

    def test_jsonc(self):
        d = project({"wrangler.jsonc": '{\n // comment\n "main": "src/index.ts", /* x */\n'
                                       ' "compatibility_date": "2024-10-01",\n'
                                       ' "compatibility_flags": ["nodejs_compat",],\n}\n'})
        c = edge.load_wrangler(os.path.join(d, "wrangler.jsonc"))
        self.assertTrue(c.v2)
        self.assertIn("wrangler config", c.flag_fix())

    def test_toml_fallback_parser(self):
        data = edge._parse_toml_lines('name = "w"\nmain = "src/index.ts" # entry\n'
                                      'compatibility_date = "2025-01-01"\n'
                                      'compatibility_flags = [ "nodejs_compat" ]\n[vars]\nmain = "no"\n')
        self.assertEqual(data, {"main": "src/index.ts", "compatibility_date": "2025-01-01",
                                "compatibility_flags": ["nodejs_compat"]})


class Rules(unittest.TestCase):
    def test_runtime_error_modules(self):
        self.assertEqual(rules("import { exec } from 'node:child_process';", COMPAT), ["EDGE001"])
        self.assertEqual(rules("const { Worker } = require('worker_threads');", COMPAT), ["EDGE001"])

    def test_needs_nodejs_compat(self):
        self.assertEqual(rules("import { createHash } from 'node:crypto';", NO_COMPAT), ["EDGE002"])
        self.assertEqual(rules("import { createHash } from 'node:crypto';", COMPAT), [])
        self.assertEqual(rules("import net from 'node:net';", COMPAT), [])

    def test_v1_prefix_and_v2_modules(self):
        self.assertEqual(rules("import { Buffer } from 'node:buffer';", V1), [])
        self.assertEqual(rules("import { Buffer } from 'buffer';", V1), ["EDGE002"])
        self.assertEqual(rules("import zlib from 'node:zlib';", V1), ["EDGE002"])

    def test_bare_builtin_with_npm_shim(self):
        d = project({"wrangler.toml": 'name = "w"\n', "node_modules/events/package.json": "{}"})
        c = edge.load_wrangler(os.path.join(d, "wrangler.toml"))
        self.assertEqual(rules("import { EventEmitter } from 'events';", c), [])
        self.assertEqual(rules("import { EventEmitter } from 'node:events';", c), ["EDGE002"])

    def test_fs_is_virtual(self):
        self.assertEqual(rules("import { readFileSync } from 'node:fs';", COMPAT), ["EDGE007"])
        self.assertEqual(rules("import fs from 'fs/promises';", NO_COMPAT), ["EDGE002", "EDGE007"])

    def test_packages(self):
        self.assertEqual(rules("import bcrypt from 'bcrypt';", COMPAT), ["EDGE003"])
        self.assertEqual(rules("import bcrypt from 'bcryptjs';", COMPAT), [])
        self.assertEqual(rules("import jwt from 'jsonwebtoken';", COMPAT, severity="block"), [])
        self.assertEqual(rules("import { chromium } from 'playwright-core/lib/x';", COMPAT), ["EDGE003"])
        self.assertEqual(rules("import x from '@cloudflare/puppeteer';", COMPAT), [])

    def test_eval(self):
        self.assertEqual(rules("const f = new Function('a', 'return a');", COMPAT), ["EDGE004"])
        self.assertEqual(rules("eval(code)", COMPAT), ["EDGE004"])
        self.assertEqual(rules("const s = 'eval(x)'; obj.eval(x); // eval(y)", COMPAT), [])

    def test_process_env(self):
        self.assertEqual(rules("export default { fetch() { return process.env.KEY } }", NO_COMPAT),
                         ["EDGE005"])
        self.assertEqual(rules("export default { fetch() { return process.env.KEY } }", COMPAT), [])
        old = cfg_for('compatibility_date = "2024-12-01"\ncompatibility_flags = ["nodejs_compat"]\n')
        self.assertEqual(rules("export default { fetch() { return process.env.KEY } }", old), ["EDGE005"])

    def test_module_scope_io(self):
        self.assertEqual(rules("const cfg = await fetch('https://x');\n", COMPAT), ["EDGE006"])
        self.assertEqual(rules("const get = () => fetch('https://x');\n"
                               "export default { async fetch(req) { return fetch(req); } };\n", COMPAT), [])

    def test_inline_ignore(self):
        self.assertEqual(rules("// rls-edge-guard-ignore EDGE003: build-time script only\n"
                               "import sharp from 'sharp';", COMPAT), [])


class Scope(unittest.TestCase):
    def setUp(self):
        self.d = project({
            "wrangler.toml": 'name = "w"\nmain = "src/index.ts"\ncompatibility_date = "2025-06-01"\n',
            "src/index.ts": "import { h } from '../lib/helper.js';\nexport default { fetch: h };\n",
            "lib/helper.ts": "import { exec } from 'node:child_process';\nexport const h = () => exec('ls');\n",
            "lib/unused.ts": "import fs from 'node:fs';\n",
            "src/index.test.ts": "import fs from 'node:fs';\n",
            "vite.config.ts": "import path from 'node:path';\n",
            "scripts/seed.ts": "import fs from 'node:fs';\n",
        })
        self.cfg = edge.load_wrangler(os.path.join(self.d, "wrangler.toml"))

    def test_scope(self):
        p = lambda r: os.path.join(self.d, r)  # noqa: E731
        self.assertTrue(edge.in_scope(p("src/index.ts"), self.cfg))
        self.assertTrue(edge.in_scope(p("lib/helper.ts"), self.cfg))   # reachable from main
        self.assertFalse(edge.in_scope(p("lib/unused.ts"), self.cfg))
        self.assertFalse(edge.in_scope(p("src/index.test.ts"), self.cfg))
        self.assertFalse(edge.in_scope(p("vite.config.ts"), self.cfg))
        self.assertFalse(edge.in_scope(p("scripts/seed.ts"), self.cfg))
        files = sorted(os.path.relpath(f, self.d) for f in edge.worker_files(self.cfg))
        self.assertEqual(files, ["lib/helper.ts", "src/index.ts"])


if __name__ == "__main__":
    unittest.main()
