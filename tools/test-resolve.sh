#!/usr/bin/env bash
# 宿主机解析测试：验证 ksu_stage.sh 对**每个**管理器包名都选对 ksud 来源。
#
#   bash tools/test-resolve.sh
#
# 做假目录树（/data/app 形态：<~~hash==>/<pkg>-<hash>/lib/arm64/），
# 用 EXTRACTKIT_APP_ROOT 指过去，EXTRACTKIT_DRYRUN=1 只解析不动真机文件。
set -u
cd "$(dirname "$0")/.." || exit 1
SH=payload/src/ksu_stage.sh
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

pass=0
fail=0

ok()   { pass=$((pass+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ $# -gt 1 ] && printf '        %s\n' "$2"; }

# mk <pkg> <brand>：造一个带 ksud 的管理器 lib 目录
mk() {
  pkg=$1
  brand=$2
  h=$(printf '%s' "$pkg" | md5sum | cut -c1-10)
  d="$ROOT/~~$h==/$pkg-AbCdEf0123456789==/lib/arm64"
  mkdir -p "$d"
  printf '#!/bin/sh\n' > "$d/libksud.so"
  printf 'if [ "$1" = "--version" ]; then echo "ksud %s 0.0.1 (uapi: 6)"; exit 0; fi\n' "$brand" >> "$d/libksud.so"
  printf 'if [ "$1" = "late-load" ]; then echo "usage: ksud late-load --kmi K --allow-shell --package-name P"; exit 0; fi\n' >> "$d/libksud.so"
  printf 'exit 1\n' >> "$d/libksud.so"
  chmod 755 "$d/libksud.so"
  # 干扰项：非 ksud 的 .so + 全零文件
  printf '#!/bin/sh\necho nope\nexit 1\n' > "$d/libnoise.so"
  chmod 755 "$d/libnoise.so"
  : > "$d/libzero.so"
  chmod 755 "$d/libzero.so"
}

run() { EXTRACTKIT_APP_ROOT="$ROOT" EXTRACTKIT_MGR="$1" EXTRACTKIT_DRYRUN=1 sh "$SH" 2>&1; }

# 1) 8 个已知管理器，各建各的树，必须 owner == 自己、cross=0
echo "[1] 已知管理器：owner 必须等于所选包名"
for pair in \
  "com.sukisu.ultra:SukiSU" \
  "io.milksu.manager:MilkSU" \
  "com.milkcode:MilkSU" \
  "me.weishu.kernelsu:KernelSU" \
  "com.resukisu.resukisu:ResukiSU" \
  "org.bakasu.bakasu:Bakasu" \
  "com.ghostlock.ksu:GhostLock" \
  "com.kowx712.supermanager:SuperManager" ; do
  pkg=${pair%%:*}
  brand=${pair##*:}
  mk "$pkg" "$brand"
  out=$(run "$pkg")
  if printf '%s' "$out" | grep -q "\[resolve\] mgr=$pkg .*owner=$pkg cross=0 why=self"; then
    ok "$pkg → 自家 ksud"
  else
    bad "$pkg → 期望 owner=$pkg cross=0" "$(printf '%s' "$out" | grep '\[resolve\]')"
  fi
done

# 2) 任意包名（没有自家 lib）：跨品牌兜底，必须 cross=1 且带警告
echo "[2] 未知包名：允许兜底但必须显式告警"
out=$(run com.example.ghost)
if printf '%s' "$out" | grep -q 'cross=1 why=cross' && printf '%s' "$out" | grep -q '警告:'; then
  ok "com.example.ghost → cross=1 + 警告"
else
  bad "com.example.ghost → 期望 cross=1 且有警告" "$(printf '%s' "$out" | grep -E '\[resolve\]|警告')"
fi

# 3) 官方 KernelSU 场景：删掉它的树，只能借别家
echo "[3] 自家没有 ksud（官方 KernelSU 形态）：cross=1"
rm -rf "$ROOT"/*/me.weishu.kernelsu-* 2>/dev/null
out=$(run me.weishu.kernelsu)
if printf '%s' "$out" | grep -q 'mgr=me.weishu.kernelsu .*owner=com.sukisu.ultra cross=1'; then
  ok "me.weishu.kernelsu → 借 com.sukisu.ultra 且 cross=1"
else
  bad "me.weishu.kernelsu → 期望 owner=com.sukisu.ultra cross=1" "$(printf '%s' "$out" | grep '\[resolve\]')"
fi

# 4) 绝不把 /data/adb/ksu/bin/ksud（我们的软链）当来源
echo "[4] 软链不能当来源"
if run com.sukisu.ultra | grep -q 'src=/data/adb/ksu/bin/ksud'; then
  bad "src 里出现了 /data/adb/ksu/bin/ksud"
else
  ok "src 不含 /data/adb/ksu/bin/ksud"
fi

# 5) 全空树：明确失败
echo "[5] 无任何来源：exit 1"
EMPTY=$(mktemp -d)
out=$(EXTRACTKIT_APP_ROOT="$EMPTY" EXTRACTKIT_MGR=com.sukisu.ultra EXTRACTKIT_DRYRUN=1 sh "$SH" 2>&1)
rc=$?
rm -rf "$EMPTY"
if [ "$rc" = 1 ] && printf '%s' "$out" | grep -q 'ksud 找不到可用来源'; then
  ok "空树 → exit 1 + 明确原因"
else
  bad "空树 → 期望 exit 1" "rc=$rc"
fi

# 6) DRYRUN 不能试图写 /data/adb
echo "[6] DRYRUN 不修改 /data/adb"
out=$(run com.sukisu.ultra)
if printf '%s' "$out" | grep -q 'dryrun=1 未修改'; then
  ok "dryrun 提前退出"
else
  bad "dryrun 未提前退出" "$(printf '%s' "$out" | tail -3)"
fi

printf '\n== %d passed, %d failed ==\n' "$pass" "$fail"
[ "$fail" = 0 ]
