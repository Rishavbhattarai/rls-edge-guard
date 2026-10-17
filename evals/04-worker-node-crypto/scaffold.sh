#!/usr/bin/env bash
# Starting project for this case (runs in the case's sandbox cwd).
set -euo pipefail
mkdir -p src && printf 'name = "hasher"\nmain = "src/index.ts"\ncompatibility_date = "2025-06-01"\n' > wrangler.toml
