#!/system/bin/sh
# KernelSU 交接脚本（payload 以 uid=0 + kernel 域执行它）。
#
# 设计要点（每一条都对应一次真机事故）：
#   1. 目标管理器包名来自 EXTRACTKIT_MGR；写死会让「选了 MilkSU 却注册成 SukiSU」。
#   2. ksud 必须来自**同一个**管理器：别的管理器的二进制拿去给本管理器注册，
#      属于跨品牌顶替，只能在没有自家 ksud 时兜底并显式告警。
#   3. /data/adb/ksud 可能是全零坏文件，所以每次都用可信来源原子覆盖。
#   4. /data/adb/ksu/bin/ksud 可能是**我们自己建的软链**，绝不能当候选来源
#      （会自拷贝，也会把别家二进制当成自家）。
#   5. 管理器自己装的 /data/adb/ksu/bin/ksud 是真文件时只备份，不覆盖。
#   6. EXTRACTKIT_DRYRUN=1 只做解析 + 能力探测，不动任何文件（给 App 自检用）。
#   7. EXTRACTKIT_APP_ROOT 可覆盖 /data/app，宿主机才能用假目录树测试解析。
#   8. 同一次开机里 kernelsu 已加载就不要再 late-load：包名在加载时定死。
echo "[ksu] start uid=$(id -u) selinux=$(getenforce)"
grep -E '^(Cap|Seccomp|Uid|Gid)' /proc/self/status
echo "[diag] attr=$(cat /proc/self/attr/current)"

MGR=${EXTRACTKIT_MGR:-com.sukisu.ultra}
APP_ROOT=${EXTRACTKIT_APP_ROOT:-/data/app}
DRYRUN=${EXTRACTKIT_DRYRUN:-0}
echo "[ksu] mgr=$MGR app_root=$APP_ROOT dryrun=$DRYRUN"

# 能不能读 APP_ROOT：shell 域读不了 /data/app，只有 root 能，必须报出来，
# 否则 App 自检会把"没权限"误显示成"缺 ksud"。
ROOT_OK=0
if ls "$APP_ROOT" >/dev/null 2>&1; then
  ROOT_OK=1
fi
echo "[resolve] app_root=$APP_ROOT readable=$ROOT_OK"

KNOWN="com.sukisu.ultra io.milksu.manager com.milkcode me.weishu.kernelsu com.resukisu.resukisu org.bakasu.bakasu com.ghostlock.ksu com.kowx712.supermanager"

# 可执行候选：ELF 真二进制，或带 shebang 的脚本（全零坏文件两者都不满足）
is_bin() {
  head -c 4 "$1" 2>/dev/null | grep -qa ELF && return 0
  head -c 2 "$1" 2>/dev/null | grep -qa "#!" && return 0
  return 1
}
ksud_like() { "$1" --version 2>&1 | head -1 | grep -q ksud; }
ver_of() { "$1" --version 2>&1 | head -1; }

SRC=""
SRC_OWNER=""
SRC_WHY=""

# 扫描一个 lib 目录，命中就填 SRC / SRC_OWNER / SRC_WHY（why=self|cross）
scan_dir() {
  [ -n "$SRC" ] && return 0
  d=$1
  [ -d "$d" ] || return 0
  # 两轮：先只看文件名像 ksud 的（librczajmyvun.so 这种看不出来，就落到第二轮），
  # 避免对每个随机 .so 都跑一次 --version（有的会 SIGILL，日志很脏）。
  for pass in 1 2; do
    for f in "$d"/*.so; do
      [ -f "$f" ] || continue
      case "$f" in
        *ksud*) [ "$pass" = 1 ] || continue ;;
        *)      [ "$pass" = 2 ] || continue ;;
      esac
      chmod 755 "$f" 2>/dev/null
      is_bin "$f" || continue
      ksud_like "$f" || continue
      SRC="$f"
      SRC_OWNER=$2
      SRC_WHY=$3
      return 0
    done
  done
}

# 1) 先只在目标管理器自己的 lib 里找（这才是正确来源）
for d in $(ls -d $APP_ROOT/*/"$MGR"*/lib/arm64 2>/dev/null); do
  scan_dir "$d" "$MGR" self
done

# 2) 自家没有才向已知管理器借，逐家记录 owner
if [ -z "$SRC" ]; then
  for p in $KNOWN; do
    [ "$p" = "$MGR" ] && continue
    for d in $(ls -d $APP_ROOT/*/"$p"*/lib/arm64 2>/dev/null); do
      scan_dir "$d" "$p" cross
    done
    [ -n "$SRC" ] && break
  done
fi

# 3) 最后才是临时目录 / 现有安装（不含 /data/adb/ksu/bin/ksud，那是我们的软链）
if [ -z "$SRC" ]; then
  for f in /data/local/tmp/ksud /data/adb/ksud; do
    [ -f "$f" ] || continue
    is_bin "$f" || continue
    ksud_like "$f" || continue
    SRC="$f"
    SRC_OWNER="installed"
    SRC_WHY=fallback
    break
  done
fi

if [ -z "$SRC" ]; then
  if [ "$ROOT_OK" = 0 ]; then
    echo "[resolve] mgr=$MGR src= owner= cross=0 why=noperm"
    echo "[ksu] 读不了 $APP_ROOT（当前 uid=$(id -u)），要用 root 身份跑才能定位管理器自带的 ksud"
  else
    echo "[resolve] mgr=$MGR src= owner= cross=0 why=none"
    echo "[ksu] ksud 找不到可用来源（扫过 $APP_ROOT 下 $MGR 与已知管理器的 lib/arm64）"
  fi
  exit 1
fi

CROSS=0
[ "$SRC_WHY" = cross ] && CROSS=1
echo "[resolve] mgr=$MGR src=$SRC owner=$SRC_OWNER cross=$CROSS why=$SRC_WHY"
[ "$CROSS" = 1 ] && echo "[ksu] 警告: $MGR 没有自带 ksud，借 $SRC_OWNER 的二进制注册（可能与管理器版本不匹配）"
echo "[ksu] 来源版本: $(ver_of "$SRC")"

# 4) 探测 --package-name 支持（不支持的 ksud 会按默认包名注册 = 白提权）
FLAG_OK=0
HELP=$("$SRC" late-load --help 2>&1)
echo "[ksu] help: $(echo "$HELP" | grep -i -m3 package | tr '\n' '|')"
echo "$HELP" | grep -q -- '--package-name' && FLAG_OK=1
if [ "$FLAG_OK" = 0 ]; then
  "$SRC" --help 2>&1 | grep -q -- '--package-name' && FLAG_OK=1
fi
if [ "$FLAG_OK" = 1 ]; then
  echo "[ksu] flag=package-name ok"
else
  echo "[ksu] warn: 未能从 --help 确认 --package-name，仍按显式参数调用（失败会报 FATAL）"
fi

# 5) 自检模式：到此为止，不碰 /data/adb
if [ "$DRYRUN" != 0 ]; then
  echo "[resolve] dryrun=1 未修改 /data/adb/ksud"
  exit 0
fi

# 6) 每次都用可信来源原子覆盖 /data/adb/ksud（防旧文件损坏）
KSUD="$SRC"
if cp "$SRC" /data/adb/ksud.new 2>/dev/null && chmod 755 /data/adb/ksud.new && mv -f /data/adb/ksud.new /data/adb/ksud; then
  KSUD=/data/adb/ksud
  echo "[ksu] 已替换 /data/adb/ksud <- $SRC"
else
  rm -f /data/adb/ksud.new 2>/dev/null
  echo "[ksu] 替换失败，直接用 $SRC"
fi
if ! is_bin "$KSUD" || ! ksud_like "$KSUD"; then
  echo "[ksu] $KSUD 自检不过，退回 $SRC"
  KSUD="$SRC"
fi

# 7) /data/adb/ksu/bin/ksud：是软链或不存在才重建，真文件先备份再保留
mkdir -p /data/adb/ksu/bin 2>/dev/null
L=/data/adb/ksu/bin/ksud
if [ -L "$L" ] || [ ! -e "$L" ]; then
  ln -sf /data/adb/ksud "$L" 2>/dev/null
else
  [ -f "$L.bak" ] || cp "$L" "$L.bak" 2>/dev/null
  echo "[ksu] 保留管理器自带 $L（备份 .bak）"
fi
echo "[ksu] ksud=$KSUD ver=$(ver_of "$KSUD")"

# 8) KMI 按真实内核推断（可用 EXTRACTKIT_KMI 覆盖）
KV=$(uname -r)
KMI=android15-6.6
case "$KV" in
  5.10.*) KMI=android12-5.10 ;;
  5.15.*) KMI=android13-5.15 ;;
  6.1.*) KMI=android14-6.1 ;;
  6.6.*) KMI=android15-6.6 ;;
  6.12.*) KMI=android16-6.12 ;;
  6.17.*|6.18.*) KMI=android17-6.18 ;;
esac
if [ -n "${EXTRACTKIT_KMI:-}" ]; then
  echo "[ksu] kmi override: $KMI -> $EXTRACTKIT_KMI"
  KMI="$EXTRACTKIT_KMI"
fi

# 9) 已加载就别重复 late-load（包名在加载时定死，换管理器要重启）
if grep -q '^kernelsu ' /proc/modules; then
  echo "KSU_ALREADY"
  echo "[ksu] kernelsu 已在运行；请求的 $MGR 需重启后才会被注册"
  echo "[ksu] hint=reboot"
  echo 1 > /sys/fs/selinux/enforce 2>/dev/null
  echo "[ksu] enforce=$(getenforce)"
  exit 0
fi

echo "[ksu] kmi=$KMI kernel=$KV mgr=$MGR"
# 模块签名强制：有些机型（荣耀/部分鸿蒙底包）默认打开，late-load 会被拒；
# 先临时关掉，无论成败都还原，避免留下「模块校验已关」的状态。
SIGF=/sys/module/module/parameters/sig_enforce
SIGV=""
if [ -w "$SIGF" ]; then
  SIGV=$(cat "$SIGF" 2>/dev/null)
  if echo 0 > "$SIGF" 2>/dev/null; then
    echo "[ksu] sig_enforce=$SIGV -> 0"
  else
    SIGV=""
  fi
fi
# 一次尝试：参数里已经带好 flag；成功标准是 /proc/modules 里真的出现 kernelsu
TRY_N=0
LAST_RC=1
try_load() {
  TRY_N=$((TRY_N + 1))
  echo "[ksu] late-load try=$TRY_N flags=$*"
  "$KSUD" late-load "$@" 2>&1 | tail -n 6
  LAST_RC=${PIPESTATUS[0]:-$?}
  # busybox/ash 没有 PIPESTATUS 时退化成命令自身的退出码
  echo "[ksu] late-load try=$TRY_N rc=$LAST_RC"
  if grep -q '^kernelsu ' /proc/modules; then
    echo "[ksu] try=$TRY_N 生效（/proc/modules 已出现 kernelsu）"
    return 0
  fi
  return 1
}

# ---- 安全模式：加载前临时禁用已有模块，避免某个模块把 kernelsu 堵在初始化 ----
SAFE_FLAG=/data/local/tmp/extract-kit/safe_mode
SAFE_LOG=/data/local/tmp/extract-kit/safe_restore.txt
SAFE=0
[ -f "$SAFE_FLAG" ] && SAFE=1
if [ "${EXTRACTKIT_SAFE_MODE:-0}" = 1 ]; then SAFE=1; fi
safe_restore() {
  [ -f "$SAFE_LOG" ] || return 0
  N_R=0
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    rm -f "$d/disable" 2>/dev/null && N_R=$((N_R + 1))
  done < "$SAFE_LOG"
  echo "[ksu] safe_mode: 已恢复 $N_R 个模块"
  rm -f "$SAFE_LOG"
}
if [ "$SAFE" = 1 ]; then
  : > "$SAFE_LOG"
  N_D=0
  for d in /data/adb/modules/*; do
    [ -d "$d" ] || continue
    [ -f "$d/disable" ] && continue
    echo "$d" >> "$SAFE_LOG"
    touch "$d/disable" 2>/dev/null && N_D=$((N_D + 1))
  done
  echo "[ksu] safe_mode: 已临时禁用 $N_D 个模块（成功后恢复）"
fi

MGR_UID=$(stat -c %u "/data/data/$MGR" 2>/dev/null)
if [ "$FLAG_OK" = 1 ]; then
  try_load --kmi "$KMI" --allow-shell --package-name "$MGR" ||
  try_load --allow-shell --package-name "$MGR" ||
  try_load --kmi "$KMI" --allow-shell ||
  try_load --allow-shell ||
  { echo "[ksu] 四级降级全部失败"; }
elif echo "$HELP" | grep -q -- '--package-uid'; then
  echo "[ksu] 该 ksud 只认 --package-uid（$MGR_UID）"
  try_load --kmi "$KMI" --allow-shell --package-uid "${MGR_UID:-0}" ||
  try_load --allow-shell --package-uid "${MGR_UID:-0}" ||
  try_load --allow-shell ||
  { echo "[ksu] 三级降级全部失败"; }
else
  try_load --kmi "$KMI" --allow-shell ||
  try_load --allow-shell ||
  { echo "[ksu] 两级降级全部失败"; }
fi
RC=$LAST_RC
echo "[ksu] late-load rc=$RC tries=$TRY_N"
safe_restore
if [ -n "$SIGV" ]; then
  echo "$SIGV" > "$SIGF" 2>/dev/null && echo "[ksu] sig_enforce 还原=$SIGV"
fi
if [ "$RC" != 0 ]; then
  KO=$(ls /data/adb/ksu/lib/*kernelsu*.ko 2>/dev/null | head -n1)
  if [ -n "$KO" ]; then
    echo "[ksu] fallback=insmod $KO"
    insmod "$KO" 2>&1 | tail -n 3
  fi
  if ! grep -q '^kernelsu ' /proc/modules; then
    safe_restore
    echo "[ksu] FATAL: late-load 失败 rc=$RC（若提示 unknown option，说明该 ksud 不支持 --package-name）"
    exit 3
  fi
  echo "[ksu] insmod 成功，继续等模块就绪"
fi
i=0
while [ $i -lt 50 ]; do
  grep -q '^kernelsu ' /proc/modules && break
  i=$((i+1))
  sleep 0.1
done
if grep -q '^kernelsu ' /proc/modules; then echo KSU_LOADED; else echo KSU_MISSING; fi
echo 1 > /sys/fs/selinux/enforce 2>/dev/null
echo "[ksu] enforce=$(getenforce)"
