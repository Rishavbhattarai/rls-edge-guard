#!/usr/bin/env bash
# Starting project for this case (runs in the case's sandbox cwd).
set -euo pipefail
mkdir -p supabase/migrations && printf 'project_id = "app"\n\n[api]\nschemas = ["public", "graphql_public"]\n' > supabase/config.toml
