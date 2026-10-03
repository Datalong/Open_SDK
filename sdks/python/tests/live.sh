#!/usr/bin/env bash
# live.sh — 真实网络联通测试：Python 客户端 ↔ JS 中继服务器
#
# 运行：./tests/live.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PY_DIR="$(dirname "$HERE")"
SDK_DIR="$(dirname "$PY_DIR")/a2net-sdk"
PORT="${PORT:-8090}"

cleanup() {
  if [[ -n "${RELAY_PID:-}" ]]; then kill "$RELAY_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

echo "── 启动 JS 中继 (:${PORT}) ─────────────────────────"
(cd "$SDK_DIR" && PORT="$PORT" npx tsx "$PY_DIR/tests/live.mjs") > /tmp/a2net-live-relay.log 2>&1 &
RELAY_PID=$!

for _ in $(seq 1 40); do
  if grep -q RELAY_READY /tmp/a2net-live-relay.log 2>/dev/null; then break; fi
  sleep 0.5
done
if ! grep -q RELAY_READY /tmp/a2net-live-relay.log 2>/dev/null; then
  echo "中继启动失败:"; cat /tmp/a2net-live-relay.log; exit 1
fi
echo "  中继就绪 (pid $RELAY_PID)"

echo
echo "── Python 客户端接入并调用 ────────────────────────"
RELAY_URL="ws://127.0.0.1:${PORT}" python3 "$PY_DIR/tests/live_client.py"

echo
echo "✓ Python ↔ JS 真实网络联通成功"
