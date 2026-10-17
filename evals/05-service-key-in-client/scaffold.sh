#!/usr/bin/env bash
# Starting project for this case (runs in the case's sandbox cwd).
set -euo pipefail
mkdir -p app/admin lib && printf '{"name":"web","dependencies":{"next":"15.0.0","react":"19.0.0","@supabase/supabase-js":"2.45.0"}}\n' > package.json && printf 'NEXT_PUBLIC_SUPABASE_URL=http://localhost:54321\nNEXT_PUBLIC_SUPABASE_ANON_KEY=anon\nSUPABASE_SERVICE_ROLE_KEY=placeholder\n' > .env.local
