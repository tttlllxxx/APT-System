#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "==> 当前目录: $PWD"

echo "==> 同步后端依赖"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
.venv/bin/python -m pip install -r backend/requirements.txt

echo "==> 同步前端依赖"
npm install --prefix frontend

echo "==> 运行基础验证"
.venv/bin/python -m compileall backend/app
npm --prefix frontend run build

echo "==> 启动命令"
echo "    ./start.sh"

if [ "${RUN_START_COMMAND:-0}" = "1" ]; then
  echo "==> 启动应用"
  exec ./start.sh
fi

echo "如果希望 init.sh 直接启动应用，请设置 RUN_START_COMMAND=1。"
