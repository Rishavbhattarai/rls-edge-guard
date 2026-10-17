#!/usr/bin/env bash
# Starting project for this case (runs in the case's sandbox cwd).
set -euo pipefail
printf '{"name":"cli","type":"module","bin":{"cli":"cli.mjs"}}\n' > package.json
