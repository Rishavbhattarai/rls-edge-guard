#!/usr/bin/env bash
# Starting project for this case (runs in the case's sandbox cwd).
set -euo pipefail
mkdir -p db && printf 'Internal Postgres for the billing service. No Supabase.\n' > README.md
