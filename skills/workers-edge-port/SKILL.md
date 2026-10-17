---
name: workers-edge-port
description: Port Node.js code to run on Cloudflare Workers. Use when writing or fixing Worker code that uses Node built-ins (fs, crypto, child_process, process.env), native npm packages (bcrypt, sharp, better-sqlite3), or when rls-edge-guard reports an EDGE0xx finding.
---

# Porting Node code to Cloudflare Workers

Workers run on `workerd` (V8 isolates), not Node. Whether a Node API works depends on two settings in the wrangler config:

- `compatibility_flags = ["nodejs_compat"]` turns on Node built-in support.
- `compatibility_date`: from `2024-09-23` on, nodejs_compat means "v2", which has many more modules and allows bare specifiers (`'buffer'` as well as `'node:buffer'`).

So the first step is always to read `wrangler.toml` / `wrangler.jsonc`. Don't assume a built-in is broken. With `nodejs_compat` and a recent date, `node:crypto`, `node:buffer`, `node:stream`, `node:events`, `node:path`, `node:util`, `node:zlib`, and `node:net` all work.

Beware: the Workers Vitest pool turns on `nodejs_compat` by itself, so tests can pass while the real deploy fails. Check the config, not just the tests.

## Fixes by finding

| Finding | Fix |
|---|---|
| EDGE002 (needs nodejs_compat) | Add `"nodejs_compat"` to `compatibility_flags`. If the date is older than 2024-09-23, also bump `compatibility_date`. For v1, use the `node:` prefix. |
| EDGE001 `child_process` | Workers can't spawn processes. Use a Container or Sandbox, or call a service with `fetch()`. |
| EDGE001 `worker_threads` / `cluster` | Background work: `ctx.waitUntil()`, Queues, or Durable Objects. Scaling is automatic. |
| EDGE001 `vm`, EDGE004 `eval` / `new Function` | Disallowed. Use `JSON.parse`, precompiled templates, or a WASM interpreter. |
| EDGE001 `sqlite` | D1, or `ctx.storage.sql` in a Durable Object. |
| EDGE007 `fs` | No project files exist at runtime. Import JSON as a module (`import cfg from './cfg.json'`), embed text with a `Text` module rule, or read from KV / R2 / static assets. |
| EDGE005 `process.env` | Read `env.MY_SECRET` from the handler's `env` argument. With nodejs_compat and date >= 2025-04-01, `process.env` is populated too. |
| EDGE006 module-scope I/O | Move `fetch()`, timers, and random values into the handler, or into a lazily initialised helper called from it. |

## Package swaps (EDGE003)

| Node package | Workers option |
|---|---|
| `bcrypt`, `argon2` (native) | `bcryptjs`, or PBKDF2 with `crypto.subtle` (below) |
| `sharp`, `canvas` | Cloudflare Images / `IMAGES` binding |
| `better-sqlite3`, `sqlite3` | D1 |
| `pg-native` | `pg` or `postgres` through Hyperdrive (needs nodejs_compat) |
| `puppeteer`, `playwright` | `@cloudflare/puppeteer`, `@cloudflare/playwright` (Browser Rendering) |
| `jsonwebtoken` | `jose` |
| `express`, `multer` | `hono`, `request.formData()` |
| `ioredis` | `@upstash/redis` (HTTP) |
| `dotenv`, `node-fetch` | Remove: use `env` bindings and built-in `fetch` |

## Password hashing with Web Crypto

```ts
const enc = new TextEncoder();

export async function hashPassword(password: string, iterations = 100_000) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
  const b64 = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b)));
  return `pbkdf2$${iterations}$${b64(salt)}$${b64(bits)}`;
}
```

Workers cap PBKDF2 at 100,000 iterations. For password storage at higher cost, use a WASM argon2/bcrypt build, or hash in Supabase Auth instead of in the Worker.

## Hashing and HMAC

`crypto.createHash('sha256').update(s).digest('hex')` works under nodejs_compat. Without the flag, use:

```ts
const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
```

## Talking to Supabase from a Worker

Use `@supabase/supabase-js` (fetch-based, works without nodejs_compat). Keep the service-role key as a Worker **secret** (`wrangler secret put SUPABASE_SERVICE_ROLE_KEY`) and read it from `env`. Never put it in `vars` or client bundles.
