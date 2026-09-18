#!/usr/bin/env bash

# Load local environment variables when running the app directly.
set -euo pipefail

cd "$(dirname "$0")"

if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

exec uvicorn backend.app:app \
  --reload \
  --host 0.0.0.0 \
  --port "${PORT:-8000}"
