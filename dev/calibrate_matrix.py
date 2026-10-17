#!/usr/bin/env python3
"""Dev-only: measure Node built-in support in real workerd, per wrangler config.

  python3 dev/calibrate_matrix.py <path/to/node_modules/.bin/wrangler> <out.json>

For each config (flags x compatibility_date) and each module:
  1. bundle:  a Worker that statically imports the module, built with
              `wrangler deploy --dry-run` (wrangler applies its unenv polyfills here,
              exactly as in a real deploy);
  2. runtime: every module that bundled is imported by one Worker run under
              `wrangler dev` (local workerd), and a representative API is called.

Needs wrangler installed locally. Runs only on localhost; nothing is deployed.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

CONFIGS = {
    "no_flags": {"date": "2025-06-01", "flags": []},
    "v1": {"date": "2024-01-01", "flags": ["nodejs_compat"]},
    "v2": {"date": "2024-09-23", "flags": ["nodejs_compat"]},
    "current": {"date": "2026-10-01", "flags": ["nodejs_compat"]},
}

# module -> JS expression using `m` (the module namespace). Must not touch the network.
PROBES = {
    "assert": "m.ok(true), 'ok'",
    "async_hooks": "new m.AsyncLocalStorage().run(1, () => 'ok')",
    "buffer": "m.Buffer.from('hi').toString('base64')",
    "child_process": "m.execSync('echo hi').toString()",
    "cluster": "m.fork(), 'forked'",
    "console": "typeof m.log",
    "constants": "Object.keys(m).length",
    "crypto": "m.createHash('sha256').update('x').digest('hex').slice(0, 8)",
    "dgram": "m.createSocket('udp4'), 'socket'",
    "diagnostics_channel": "typeof m.channel('x').publish",
    "dns": "typeof m.lookup",
    "domain": "typeof m.create().run",
    "events": "new m.EventEmitter().listenerCount('x')",
    "fs": "(m.writeFileSync('/tmp/reg.txt', 'y'), m.readFileSync('/tmp/reg.txt', 'utf8'))",
    "fs/promises": "typeof m.readFile",
    "http": "typeof m.request",
    "http2": "m.connect('http://127.0.0.1:1'), 'connected'",
    "https": "typeof m.request",
    "inspector": "m.url() ?? 'no url'",
    "module": "typeof m.createRequire('/x')",
    "net": "m.isIP('1.1.1.1')",
    "os": "m.platform()",
    "path": "m.join('a', 'b')",
    "perf_hooks": "typeof m.performance.now()",
    "process": "typeof m.default.nextTick",
    "punycode": "m.toASCII('mañana')",
    "querystring": "m.stringify({ a: 1 })",
    "readline": "typeof m.createInterface",
    "repl": "typeof m.start",
    "sqlite": "new m.DatabaseSync(':memory:'), 'db'",
    "stream": "typeof new m.Readable().read",
    "string_decoder": "new m.StringDecoder('utf8').write(new Uint8Array([104, 105]))",
    "timers": "typeof m.setTimeout",
    "tls": "typeof m.connect",
    "trace_events": "m.createTracing({ categories: ['x'] }), 'tracing'",
    "tty": "m.isatty(1)",
    "url": "new m.URL('https://x.dev/p').host",
    "util": "m.format('%s', 'ok')",
    "v8": "typeof m.getHeapStatistics().total_heap_size",
    "vm": "m.runInNewContext('1 + 1')",
    "wasi": "new m.WASI({ version: 'preview1' }), 'wasi'",
    "worker_threads": "new m.Worker('x'), 'worker'",
    "zlib": "m.gzipSync('x').length",
}


def write_project(d, cfg, src):
    os.makedirs(os.path.join(d, "src"), exist_ok=True)
    with open(os.path.join(d, "src", "index.js"), "w") as fh:
        fh.write(src)
    flags = json.dumps(cfg["flags"])
    with open(os.path.join(d, "wrangler.toml"), "w") as fh:
        fh.write(f'name = "calib"\nmain = "src/index.js"\ncompatibility_date = "{cfg["date"]}"\n'
                 f"compatibility_flags = {flags}\n")


def env():
    return {**os.environ, "WRANGLER_SEND_METRICS": "false", "CI": "1", "NO_COLOR": "1"}


def bundles(wrangler, cfg, spec):
    d = tempfile.mkdtemp(prefix="calib-b-")
    try:
        write_project(d, cfg, f'import * as m from "{spec}";\nexport default {{ fetch() {{ '
                              f'return new Response(String(Object.keys(m).length)); }} }};\n')
        p = subprocess.run([wrangler, "deploy", "--dry-run", "--outdir", "out"], cwd=d,
                           capture_output=True, text=True, timeout=120, env=env())
        if p.returncode == 0:
            return True, ""
        err = [ln for ln in (p.stderr + p.stdout).splitlines() if "ERROR" in ln or "Could not" in ln]
        return False, (err[0] if err else p.stderr[-300:]).strip()[:300]
    finally:
        shutil.rmtree(d, ignore_errors=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def runtime(wrangler, cfg, specs):
    """Import all specs statically in one Worker; probe each via ?m=<spec>."""
    lines, cases = [], []
    for k, spec in enumerate(specs):
        name = spec.replace("node:", "")
        lines.append(f'import * as m{k} from "{spec}";')
        cases.append(f'  {json.dumps(spec)}: () => {{ const m = m{k}; return {PROBES[name]}; }},')
    src = "\n".join(lines) + "\nconst probes = {\n" + "\n".join(cases) + "\n};\n" + """
export default {
  async fetch(req) {
    const spec = new URL(req.url).searchParams.get("m");
    try {
      const v = await probes[spec]();
      return Response.json({ ok: true, value: String(v).slice(0, 80) });
    } catch (e) {
      return Response.json({ ok: false, error: String(e && e.message || e).slice(0, 200) });
    }
  },
};
"""
    d = tempfile.mkdtemp(prefix="calib-r-")
    write_project(d, cfg, src)
    port = free_port()
    proc = subprocess.Popen([wrangler, "dev", "--local", "--port", str(port), "--ip", "127.0.0.1",
                             "--show-interactive-dev-session=false"], cwd=d, env=env(),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    results = {}
    try:
        deadline = time.time() + 90
        while time.time() < deadline:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/?m=none", timeout=2)
                break
            except Exception as e:  # noqa: BLE001
                if getattr(e, "code", None):
                    break
                if proc.poll() is not None:
                    return {s: {"ok": False, "error": "worker failed to start: " +
                                (proc.stdout.read() or "")[-300:]} for s in specs}
                time.sleep(1)
        for spec in specs:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/?m={spec}", timeout=20) as r:
                    results[spec] = json.load(r)
            except Exception as e:  # noqa: BLE001
                body = e.read().decode()[:200] if hasattr(e, "read") else str(e)
                results[spec] = {"ok": False, "error": "request failed: " + body}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(d, ignore_errors=True)
    return results


def main(wrangler, out_path):
    version = subprocess.run([wrangler, "--version"], capture_output=True, text=True).stdout.strip()
    report = {"wrangler": version, "measured": time.strftime("%Y-%m-%d"), "configs": {}}
    for cname, cfg in CONFIGS.items():
        rows = {}
        specs = []
        for name in PROBES:
            for spec in ([f"node:{name}", name] if cname in ("no_flags", "v1") else [f"node:{name}"]):
                ok, err = bundles(wrangler, cfg, spec)
                rows[spec] = {"bundles": ok, "bundle_error": err}
                if ok:
                    specs.append(spec)
                print(f"{cname:9} {spec:24} bundle={'ok' if ok else 'FAIL'}", flush=True)
        rt = runtime(wrangler, cfg, specs) if specs else {}
        if specs and all(not r.get("ok") and "failed to start" in r.get("error", "") for r in rt.values()):
            # One module broke startup: fall back to one Worker per module.
            rt = {}
            for spec in specs:
                rt.update(runtime(wrangler, cfg, [spec]))
        for spec, r in rt.items():
            rows[spec]["runtime"] = r
            print(f"{cname:9} {spec:24} runtime={'ok' if r.get('ok') else 'THROWS: ' + r.get('error', '')}",
                  flush=True)
        report["configs"][cname] = {**cfg, "results": rows}
    with open(out_path, "w") as fh:
        json.dump(report, fh, indent=1, ensure_ascii=False)
        fh.write("\n")


if __name__ == "__main__":
    main(os.path.abspath(sys.argv[1]), sys.argv[2])
