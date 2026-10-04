#!/usr/bin/env bash
#
# release.sh — 一条命令完成发布（含顺序保证与安全检查）
#
# 设计目标：把「发布」这件事的所有**容易出错的细节**固化下来，
# 让人只需要保证「凭据已登录」这一件事。
#
# 固化的细节
# ──────────
#   1. 发布前**必跑 preflight**（产物不可用就中止，不浪费时间推送失败）
#   2. **严格按依赖顺序发布**：@a2net/client → a2net-client(PyPI) → @a2net/mcp
#      （mcp 依赖 client；顺序错了 mcp 会因找不到依赖而失败或被 npm 拒绝）
#   3. **二次确认**：真实发布会不可逆，需要显式确认
#   4. **已发布检测**：同名同版本已存在时跳过，避免误报"发布失败"
#   5. **不碰凭据**：登录由使用者自行完成（npm login / TWINE_*）
#
# 用法
# ────
#   ./scripts/release.sh              # 真实发布（会要确认）
#   ./scripts/release.sh --dry-run    # 只演练，不推送任何东西
#   ./scripts/release.sh --yes        # 跳过确认（CI 用）
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DRY_RUN=0
ASSUME_YES=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY_RUN=1 ;;
    --yes|-y)  ASSUME_YES=1 ;;
  esac
done

R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; B='\033[1m'; D='\033[2m'; N='\033[0m'
section() { printf "\n${B}▶ %s${N}\n" "$1"; }
ok()      { printf "  ${G}✓${N} %s\n" "$1"; }
warn()    { printf "  ${Y}!${N} %s\n" "$1"; }
bad()     { printf "  ${R}✗${N} %s\n" "$1"; }

VERSION="$(node -e "console.log(JSON.parse(require('fs').readFileSync('sdks/typescript/package.json','utf8')).version)")"

# 发布**必须显式指定官方 registry**。
#
# 为什么不能依赖全局配置：国内开发者常把 ~/.npmrc 指向 registry.npmmirror.com
# （只读镜像）。此时直接 `npm publish` 会尝试往镜像写 —— 要么报错，
# 要么发到错误的地方。实测本机就是这种配置。
NPM_REGISTRY="https://registry.npmjs.org"

printf "${B}══════════════════════════════════════════════════════════════${N}\n"
printf "${B}  A2Net 发布 v%s${N}%s\n" "$VERSION" "$([ "$DRY_RUN" = "1" ] && printf "  ${Y}(dry-run)${N}")"
printf "${B}══════════════════════════════════════════════════════════════${N}\n"

# ────────────────────────────────────────────────────────────────
section "0 · 发布范围确认"
# ────────────────────────────────────────────────────────────────
cat <<'EOF'
  将按依赖顺序发布以下 3 个包：
    ① @a2net/client   (npm)   — TypeScript SDK
    ② a2net-client    (PyPI)  — Python SDK
    ③ @a2net/mcp      (npm)   — MCP 双向网关（依赖 ①）

  仅在此开源仓发布。私有仓的 @a2net/sdk 与 @a2net/cli 已标记 private，
  不会被 npm 发布。
EOF

# ────────────────────────────────────────────────────────────────
section "1 · 发布前体检"
# ────────────────────────────────────────────────────────────────
if bash scripts/preflight-release.sh > /tmp/preflight.log 2>&1; then
  ok "preflight 全部通过"
  tail -3 /tmp/preflight.log | grep "全部通过" | sed "s/^/    ${D}/;s/$/${N}/"
else
  bad "preflight 未通过 —— 中止发布"
  tail -20 /tmp/preflight.log | sed "s/^/    /"
  exit 1
fi

# ────────────────────────────────────────────────────────────────
if [ "$DRY_RUN" = "1" ]; then
  section "2 · 演练发布（不推送）"
  (cd sdks/typescript && npm publish --dry-run --registry="$NPM_REGISTRY" 2>&1 | tail -3 | sed 's/^/    /') && ok "@a2net/client 可发布"
  (cd sdks/mcp && npm publish --dry-run --registry="$NPM_REGISTRY" 2>&1 | tail -3 | sed 's/^/    /') && ok "@a2net/mcp 可发布"
  section "3 · Python 演练"
  (cd sdks/python && rm -rf dist && python3 -m build >/dev/null 2>&1 && ls dist/ | sed 's/^/    /') && ok "wheel/sdist 可构建"
  printf "\n${G}${B}  演练完成 —— 未推送任何内容${N}\n"
  printf "${D}  正式发布请执行：./scripts/release.sh${N}\n\n"
  exit 0
fi

# ────────────────────────────────────────────────────────────────
section "2 · 二次确认"
# ────────────────────────────────────────────────────────────────
printf "  即将**真实发布** v%s 到 npm 与 PyPI（不可撤销）。\n" "$VERSION"
if [ "$ASSUME_YES" != "1" ]; then
  printf "  输入 ${B}yes${N} 继续："
  read -r answer
  if [ "$answer" != "yes" ]; then
    printf "  已取消，未做任何改动。\n"; exit 0
  fi
fi

# ────────────────────────────────────────────────────────────────
# 已发布检测：避免"其实早就发过了"被误判为失败
# ────────────────────────────────────────────────────────────────
already_published() { # $1 = pkg, $2 = version
  npm view "$1@$2" version --registry="$NPM_REGISTRY" >/dev/null 2>&1
}

section "3 · ① 发布 @a2net/client（npm）"
if already_published "@a2net/client" "$VERSION"; then
  warn "@a2net/client@$VERSION 已存在，跳过"
else
  (cd sdks/typescript && npm publish --access public --registry="$NPM_REGISTRY") || { bad "发布失败"; exit 1; }
  ok "@a2net/client@$VERSION 已发布"
fi

section "4 · ② 发布 a2net-client（PyPI）"
if python3 -c "
import urllib.request,sys
try:
    urllib.request.urlopen('https://pypi.org/pypi/a2net-client/$VERSION/json', timeout=8)
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
  warn "a2net-client $VERSION 已存在，跳过"
else
  (cd sdks/python && rm -rf dist build ./*.egg-info >/dev/null 2>&1 && python3 -m build >/dev/null 2>&1) || { bad "构建失败"; exit 1; }
  (cd sdks/python && python3 -m twine upload dist/*) || { bad "上传失败（检查 TWINE_USERNAME / TWINE_PASSWORD）"; exit 1; }
  ok "a2net-client $VERSION 已发布"
fi

section "5 · ③ 发布 @a2net/mcp（npm，必须在 client 之后）"
if already_published "@a2net/mcp" "$VERSION"; then
  warn "@a2net/mcp@$VERSION 已存在，跳过"
else
  (cd sdks/mcp && npm publish --access public --registry="$NPM_REGISTRY") || { bad "发布失败"; exit 1; }
  ok "@a2net/mcp@$VERSION 已发布"
fi

# ────────────────────────────────────────────────────────────────
section "6 · 打 tag 与后续"
# ────────────────────────────────────────────────────────────────
printf "  后续手动执行（需审阅文案后再推）：\n"
printf "    ${D}git tag -a v%s -m 'A2Net v%s' && git push origin v%s${N}\n" "$VERSION" "$VERSION" "$VERSION"
printf "    ${D}gh release create v%s --notes-file RELEASE_NOTES_v%s.md${N}\n" "$VERSION" "$VERSION"

printf "\n${G}${B}  ✓ 三个包均发布成功${N}\n\n"
