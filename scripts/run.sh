#!/usr/bin/env bash
#
# Production server: no --reload, single worker. Loads .env if present.
# This is what the Dockerfile and render.yaml effectively run.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

exec uvicorn backend.app:app \
  --host 0.0.0.0 \
  --port "${PORT:-8000}"
