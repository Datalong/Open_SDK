#!/usr/bin/env bash
# interop.sh — 跨语言互操作测试（双向）
#
#   Python 生成向量  →  JS 校验并生成向量  →  Python 校验
#
# 运行：./tests/interop.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PY_DIR="$(dirname "$HERE")"
SDK_DIR="$(dirname "$PY_DIR")/a2net-sdk"

echo "── 1/3 Python 生成向量 ────────────────────────────"
(cd "$PY_DIR" && python3 tests/emit_fixtures.py)

echo
echo "── 2/3 JS 校验 Python 向量 + 生成 JS 向量 ─────────"
(cd "$SDK_DIR" && npx tsx "$PY_DIR/tests/check_and_emit.mjs")

echo
echo "── 3/3 Python 校验 JS 向量 + 全量单测 ─────────────"
(cd "$PY_DIR" && python3 -m pytest -q)

echo
echo "✓ 跨语言互操作全部通过"
