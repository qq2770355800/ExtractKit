#!/usr/bin/env bash
# 用 Android NDK 重新编译 uid0 payload（静态 arm64）。
#
#   NDK=/path/to/android-ndk ./tools/build-payload.sh [输出路径]
#
# 产物默认写到 app/src/main/assets/payload/cve-2026-98260-uid0，
# 并在同目录生成新的 sha256 行——记得把新哈希同步到 PayloadCatalog.kt。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NDK="${NDK:-${ANDROID_NDK_HOME:-}}"
SRC="$ROOT/payload/src/cve-2026-98260-uid0.c"
OUT="${1:-$ROOT/app/src/main/assets/payload/cve-2026-98260-uid0}"

if [[ -z "$NDK" || ! -d "$NDK" ]]; then
  echo "error: 需要 NDK。用法: NDK=/path/to/android-ndk $0 [输出路径]" >&2
  exit 1
fi

case "$(uname -s)" in
  Darwin) HOST=darwin-x86_64 ;;
  MINGW*|MSYS*|CYGWIN*) HOST=windows-x86_64 ;;
  *) HOST=linux-x86_64 ;;
esac

CLANG="$NDK/toolchains/llvm/prebuilt/$HOST/bin/aarch64-linux-android34-clang"
if [[ ! -x "$CLANG" && ! -x "$CLANG.cmd" ]]; then
  echo "error: 找不到 $CLANG（NDK r26+ 才有 android34 target）" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"

echo "[build] $SRC -> $OUT"
"$CLANG" \
  -O2 -static -fno-pie -no-pie \
  -D_GNU_SOURCE \
  -Wall -Wextra -Wno-unused-parameter \
  -pthread \
  -I "$(dirname "$SRC")" \
  -o "$OUT" "$SRC"

"${NDK}/toolchains/llvm/prebuilt/${HOST}/bin/llvm-strip" "$OUT" 2>/dev/null || true

# 包名链路静态护栏：任何一处回退都直接编译失败，别再靠跑一遍链去发现
# 注意：Windows 的 WindowsApps 里有个 python3 假壳，`command -v` 能找到但一跑到就报
# "Python was not found"，所以要真跑一次 `-c` 才算数。
PY_BIN=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c "import sys" >/dev/null 2>&1; then
    PY_BIN="$cand"
    break
  fi
done
if [ -n "$PY_BIN" ]; then
  "$PY_BIN" "$ROOT/tools/check-env-plumbing.py" || exit 1
else
  echo "[build] 跳过 check-env-plumbing（本机没有 python）" >&2
fi

SUM="$(sha256sum "$OUT" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$OUT" | cut -d' ' -f1)"
echo "[build] sha256=$SUM"
echo "[build] 把上面这个哈希同步到 app/src/main/kotlin/com/extractkit/app/PayloadCatalog.kt"
