# Workers compatibility cutover dates (measured)

Measured on 2026-10-17 with wrangler 4.150.0 / workerd 2026-10-06, running a probe Worker in `wrangler dev --local` at each `compatibility_date`. The probe writes and reads `/tmp/x.txt` with `node:fs` and reads `process.env.MY_VAR` (set under `[vars]`).

| Behavior | Last date without | First date with | Used as |
|---|---|---|---|
| `node:fs` calls work (with `nodejs_compat`) | 2025-09-14: `[unenv] fs.writeFileSync is not implemented yet!` | 2025-09-15 | `fs_date` |
| `process.env` populated (with `nodejs_compat`) | 2025-03-01: `undefined` | 2025-04-01 (coarse: dates between were not tested) | `process_env_date` |
| global `process` exists, env populated (**no** flags) | 2026-08-03: `process is not defined` | 2026-08-04 | `process_global_no_flags_date` |

Separately: PBKDF2 via `crypto.subtle.deriveBits` accepted 100,000, 100,001 and 600,000 iterations in local workerd, so the plugin does not claim an iteration cap.

## Raw probe output

```
2024-09-23 compat {'fs': 'ERR [unenv] fs.writeFileSync is not implemented yet!', 'process_global': 'object', 'env_key': 'undefined'}
2025-03-01 compat {'fs': 'ERR [unenv] fs.writeFileSync is not implemented yet!', 'process_global': 'object', 'env_key': 'undefined'}
2025-04-01 compat {'fs': 'ERR [unenv] fs.writeFileSync is not implemented yet!', 'process_global': 'object', 'env_key': 'hello'}
2025-06-01 compat {'fs': 'ERR [unenv] fs.writeFileSync is not implemented yet!', 'process_global': 'object', 'env_key': 'hello'}
2025-08-15 compat {'fs': 'ERR [unenv] fs.writeFileSync is not implemented yet!', 'process_global': 'object', 'env_key': 'hello'}
2025-09-01 compat {'fs': 'ERR [unenv] fs.writeFileSync is not implemented yet!', 'process_global': 'object', 'env_key': 'hello'}
2025-09-15 compat {'fs': 'y', 'process_global': 'object', 'env_key': 'hello'}
2025-12-01 compat {'fs': 'y', 'process_global': 'object', 'env_key': 'hello'}
2026-03-01 compat {'fs': 'y', 'process_global': 'object', 'env_key': 'hello'}
2026-10-01 noflags {'fs': 'ERR skip', 'process_global': 'object', 'env_key': 'hello'}
2025-06-01 noflags {'fs': 'ERR skip', 'process_global': 'ERR process is not defined'}

# narrowing runs: global process without flags
2026-08-01 noflags process is not defined
2026-08-02 noflags process is not defined
2026-08-03 noflags process is not defined
2026-08-04 noflags process=object env_key=hello
2026-08-15 noflags process=object env_key=hello
# narrowing runs: node:fs with nodejs_compat
2025-09-02 .. 2025-09-14 compat ERR [unenv] fs.writeFileSync is not implemented yet!
2025-09-15 compat y
```
