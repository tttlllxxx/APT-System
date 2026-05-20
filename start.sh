#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ ! -d .venv ]]; then
  echo "未找到 .venv，请先运行 ./init.sh"
  exit 1
fi

cleanup() {
  if [[ -n "${BACKEND_PID:-}" ]]; then kill "$BACKEND_PID" 2>/dev/null || true; fi
  if [[ -n "${FRONTEND_PID:-}" ]]; then kill "$FRONTEND_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

.venv/bin/uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 &
BACKEND_PID=$!

npm --prefix frontend run dev &
FRONTEND_PID=$!

echo "后端: http://127.0.0.1:8000"
echo "前端: http://127.0.0.1:5173"
wait
