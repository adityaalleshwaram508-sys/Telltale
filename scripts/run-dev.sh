#!/usr/bin/env bash
#
# Local development server: auto-reloads on file changes. Loads .env if present.
# For production (no --reload) use scripts/run.sh, the Dockerfile, or render.yaml.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

exec uvicorn backend.app:app \
  --reload \
  --host 0.0.0.0 \
  --port "${PORT:-8000}"
