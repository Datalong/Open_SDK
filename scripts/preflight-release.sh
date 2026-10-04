#!/usr/bin/env bash
#
# preflight-release.sh — 发布前自动化体检
#
# 为什么需要它
# ────────────
# 打包类缺陷**只在真的打包并安装时才暴露**：`files` 漏文件、`exports` 路径写错、
# 缺运行时依赖、README/LICENSE 没进 tarball、子路径导出不可用……
# 本地 `npm test` 全绿也发现不了 —— 因为测试跑的是**源码**，不是**发布产物**。
#
# 本脚本把"发布产物真的可用吗"变成一条命令，可在 CI 与本地重复执行。
#
# 检查项
# ──────
#   1. 构建（发布产物必须能生成）
#   2. 每个 npm 包：pack → 检查必需文件 → 装进干净项目 → **真实使用**
#   3. Python 包：build wheel → 检查内容 → 装进干净 venv → **真实使用**
#   4. 版本一致性（各包版本是否对齐）
#
# 用法
# ────
#   ./scripts/preflight-release.sh              # 全量
#   ./scripts/preflight-release.sh --npm-only   # 只查 npm
#   ./scripts/preflight-release.sh --py-only    # 只查 Python
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ONLY="${1:-all}"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; B='\033[1m'; D='\033[2m'; N='\033[0m'
PASS=0; FAIL=0
FAILURES=()

section() { printf "\n${B}${B}▶ %s${N}\n" "$1"; }
ok()      { PASS=$((PASS+1)); printf "  ${G}✓${N} %s\n" "$1"; }
bad()     { FAIL=$((FAIL+1)); FAILURES+=("$1"); printf "  ${R}✗${N} %s\n" "$1"; [ -n "${2:-}" ] && printf "    ${D}%s${N}\n" "$2"; }
info()    { printf "  ${D}%s${N}\n" "$1"; }

TMP_ROOT="$(mktemp -d)"
cleanup() { rm -rf "$TMP_ROOT"; }
trap cleanup EXIT

# ────────────────────────────────────────────────────────────────
section "1 · 构建"
# ────────────────────────────────────────────────────────────────
if npm run build >/dev/null 2>&1; then
  ok "npm run build 通过"
else
  bad "npm run build 失败" "发布产物无法生成，后续检查无意义"
  printf "\n${R}构建失败，终止。${N}\n"; exit 1
fi

# ────────────────────────────────────────────────────────────────
# npm 包检查
# ────────────────────────────────────────────────────────────────
check_npm_pkg() {
  # 转绝对路径：后续会 cd 进临时项目，相对路径会失效（实测踩过）
  local dir
  dir="$(cd "$1" && pwd)"
  local name
  name="$(node -e "console.log(JSON.parse(require('fs').readFileSync('$dir/package.json','utf8')).name)")"
  section "npm · $name"

  # ── pack ──
  local tarball
  tarball="$(cd "$dir" && npm pack 2>/dev/null | tail -1)"
  if [ -z "$tarball" ] || [ ! -f "$dir/$tarball" ]; then
    bad "$name 打包失败"
    return
  fi
  mkdir -p "$TMP_ROOT/packed"
  cp "$dir/$tarball" "$TMP_ROOT/packed/" 2>/dev/null || true
  ok "打包成功（$tarball）"

  # ── 必需文件必须进 tarball ──
  local listing
  listing="$(cd "$dir" && npm pack --dry-run 2>&1)"

  if grep -qiE "README" <<< "$listing"; then
    ok "tarball 含 README"
  else
    bad "$name 的 tarball **不含 README**" "npm 页面会没有说明内容；公开包应修复"
  fi

  if grep -qiE "LICENSE" <<< "$listing"; then
    ok "tarball 含 LICENSE"
  else
    bad "$name 的 tarball **不含 LICENSE**" "公开包缺许可文件会造成法务歧义"
  fi

  # ── files 字段声明的文件必须真的存在 ──
  local missing=""
  while read -r f; do
    [ -z "$f" ] && continue
    [ -e "$dir/$f" ] || missing="$missing $f"
  done < <(node -e "JSON.parse(require('fs').readFileSync('$dir/package.json','utf8')).files?.forEach(f=>console.log(f))" 2>/dev/null)
  if [ -z "$missing" ]; then
    ok "package.json 声明的 files 均存在"
  else
    bad "$name 的 files 声明了不存在的路径:$missing"
  fi

  # ── 装进干净项目并真实使用 ──
  # 关键：把**所有已打包的 tarball** 一起传入安装。
  # 原因：包间存在发布顺序依赖（@a2net/mcp 依赖未发布的 @a2net/client@0.1.0），
  # 单独安装 mcp 必然失败。一起安装恰好验证了"按顺序发布后能装上"。
  local proj="$TMP_ROOT/npm-$name"
  mkdir -p "$proj"
  local others=""
  for t in "$TMP_ROOT"/packed/*.tgz; do
    [ -e "$t" ] || continue
    [ "$(basename "$t")" = "$tarball" ] && continue
    others="$others $t"
  done
  (cd "$proj" && npm init -y >/dev/null 2>&1 && npm install $others "$dir/$tarball" >/dev/null 2>&1)
  if [ ! -d "$proj/node_modules/$name" ]; then
    bad "$name 安装到干净项目后目录不存在"
    (cd "$dir" && rm -f "$tarball")
    return
  fi
  ok "可安装到干净项目"

  # 导入包根
  if (cd "$proj" && node -e "import('$name').then(()=>process.exit(0)).catch(e=>{console.error(e.message);process.exit(1)})" 2>/dev/null); then
    ok "包根可 import"
  else
    bad "$name 包根 import 失败"
  fi

  # 声明的每个子路径导出都必须真的可用
  local subpaths
  subpaths="$(node -e "
    const e = JSON.parse(require('fs').readFileSync('$dir/package.json','utf8')).exports || {};
    Object.keys(e).filter(k => k !== '.').forEach(k => console.log(k));
  " 2>/dev/null)"
  for sp in $subpaths; do
    if (cd "$proj" && node -e "import('$name${sp#.}').then(()=>process.exit(0)).catch(()=>process.exit(1))" 2>/dev/null); then
      ok "子路径导出可用：$sp"
    else
      bad "$name 的子路径导出 $sp **不可用**" "package.json 声明了但实际 import 失败"
    fi
  done

  (cd "$dir" && rm -f "$tarball")
}

# ────────────────────────────────────────────────────────────────
# Python 包检查
# ────────────────────────────────────────────────────────────────
check_py_pkg() {
  local dir="$1"
  section "PyPI · $(python3 -c "
import tomllib,sys
print(tomllib.load(open('$dir/pyproject.toml','rb'))['project']['name'])" 2>/dev/null || echo "$dir")"

  (cd "$dir" && rm -rf dist build ./*.egg-info >/dev/null 2>&1)
  if ! (cd "$dir" && python3 -m build >/dev/null 2>&1); then
    bad "$dir 构建 wheel 失败"
    return
  fi
  local wheel
  wheel="$(ls "$dir"/dist/*.whl 2>/dev/null | head -1)"
  [ -z "$wheel" ] && { bad "$dir 未产出 wheel"; return; }
  ok "构建 wheel 成功（$(basename "$wheel")）"

  # 内容检查
  local has_license
  has_license="$(python3 -c "
import zipfile
n = zipfile.ZipFile('$wheel').namelist()
print('yes' if any('license' in x.lower() for x in n) else 'no')")"
  if [ "$has_license" = "yes" ]; then
    ok "wheel 含 LICENSE"
  else
    bad "$(basename "$wheel") **不含 LICENSE**" "PyPI 页面会显示 MIT 但无许可文件，造成法务歧义"
  fi

  # 装进干净 venv 并真实使用
  local venv="$TMP_ROOT/py-$(basename "$dir")"
  python3 -m venv "$venv" >/dev/null 2>&1 || { bad "创建 venv 失败"; return; }
  if ! "$venv/bin/pip" install -q "$wheel" >/dev/null 2>&1; then
    bad "安装 wheel 到干净 venv 失败"
    return
  fi
  ok "可安装到干净 venv"

  if "$venv/bin/python" -c "
import a2net
kp = a2net.generate_keypair()
assert kp.address.startswith('did:key:z'), kp.address
sig = a2net.sign_message('hello', kp.private_key)
assert a2net.verify_signature('hello', sig, kp.address)
" >/dev/null 2>&1; then
    ok "真实使用通过（生成身份 + 签名 + 验签）"
  else
    bad "$(basename "$wheel") 在干净环境中真实使用失败"
  fi

  (cd "$dir" && rm -rf dist build ./*.egg-info >/dev/null 2>&1)
}

# ────────────────────────────────────────────────────────────────
if [ "$ONLY" != "--py-only" ]; then
  for d in sdks/typescript sdks/mcp; do
    [ -f "$d/package.json" ] && check_npm_pkg "$d"
  done
fi

if [ "$ONLY" != "--npm-only" ]; then
  [ -f sdks/python/pyproject.toml ] && check_py_pkg sdks/python
fi

# ────────────────────────────────────────────────────────────────
section "npm registry 配置"
# ────────────────────────────────────────────────────────────────
# 国内环境常把 ~/.npmrc 指向只读镜像。发布时必须显式指定官方源，
# 否则 `npm publish` 会尝试往镜像写 —— 报错或发到错误的地方。
CFG_REG="$(npm config get registry 2>/dev/null)"
info "当前 registry: $CFG_REG"
if [ "$CFG_REG" = "https://registry.npmjs.org/" ] || [ "$CFG_REG" = "https://registry.npmjs.org" ]; then
  ok "指向官方 registry"
else
  printf "  ${Y}!${N} 非官方 registry（多为只读镜像）—— 发布时**必须**显式加 --registry=https://registry.npmjs.org\n"
  info "scripts/release.sh 已硬编码官方源，无需手动处理"
fi

# ────────────────────────────────────────────────────────────────
section "版本一致性"
# ────────────────────────────────────────────────────────────────
VERSIONS="$(node -e "
  const fs=require('fs');
  const out=[];
  for (const p of ['sdks/typescript/package.json','sdks/mcp/package.json']) {
    if (fs.existsSync(p)) out.push(p+': '+JSON.parse(fs.readFileSync(p,'utf8')).version);
  }
  console.log(out.join('\n'));
")"
PYVER="$(python3 -c "
import tomllib
print('sdks/python/pyproject.toml: '+tomllib.load(open('sdks/python/pyproject.toml','rb'))['project']['version'])" 2>/dev/null)"
printf '%s\n%s\n' "$VERSIONS" "$PYVER" | while read -r line; do [ -n "$line" ] && info "$line"; done

UNIQ="$(printf '%s\n%s\n' "$VERSIONS" "$PYVER" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sort -u | wc -l | tr -d ' ')"
if [ "$UNIQ" = "1" ]; then
  ok "全部包版本一致"
else
  bad "各包版本不一致" "跨语言/跨包发布应对齐版本号"
fi

# ────────────────────────────────────────────────────────────────
printf "\n${B}══════════════════════════════════════════════════════════════${N}\n"
if [ "$FAIL" -eq 0 ]; then
  printf "${G}${B}  ✓ 发布前体检全部通过（%d 项）${N}\n" "$PASS"
else
  printf "${R}${B}  ✗ %d 项失败 / %d 项通过${N}\n" "$FAIL" "$PASS"
  for f in "${FAILURES[@]}"; do printf "    ${R}·${N} %s\n" "$f"; done
fi
printf "${B}══════════════════════════════════════════════════════════════${N}\n\n"
[ "$FAIL" -eq 0 ]
