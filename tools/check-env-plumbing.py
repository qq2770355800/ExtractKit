#!/usr/bin/env python3
"""静态护栏：管理器包名必须真的送到「凭据子进程 -> ksud 脚本」那条路上。

踩过的坑（两次）：
  1. 7.8 把 `EXTRACTKIT_MGR=...` 拼在 `cd` 前面，`&&` 后面那条命令拿不到；
  2. 7.11 修了 1，但凭据子进程 `execve("/proc/self/exe", av, ep)` 的 ep[]
     里只有 PATH —— execve 会清空环境，包名又丢了；而 `main()` 里的
     `mgr_sanitize()` 在 "wait" 分支之后，重执行时根本走不到。

这脚本把三处必须同时成立的地方钉死，任何一处回退都会在编译时直接失败。
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "payload/src/cve-2026-98260-uid0.c"

def fail(msg):
    sys.stderr.write("check-env-plumbing: FAIL - %s\n" % msg)
    sys.exit(1)


def main():
    if not SRC.is_file():
        fail("找不到 %s" % SRC)
    text = SRC.read_text(encoding="utf-8")
    lines = text.splitlines()

    # 1. mgr_sanitize(getenv("EXTRACTKIT_MGR")) 必须在 "wait" 分支之前
    sanitize_at = None
    wait_at = None
    for i, ln in enumerate(lines, 1):
        if sanitize_at is None and re.search(r'mgr_sanitize\s*\(\s*getenv\s*\(\s*"EXTRACTKIT_MGR"\s*\)', ln):
            sanitize_at = i
        if wait_at is None and re.search(r'argv\[1\]\s*,\s*"wait"', ln):
            wait_at = i
    if sanitize_at is None:
        fail('没有 mgr_sanitize(getenv("EXTRACTKIT_MGR"))')
    if wait_at is None:
        fail('找不到 argv[1] == "wait" 分支')
    if sanitize_at > wait_at:
        fail('mgr_sanitize 在第 %d 行，晚于 wait 分支（第 %d 行）：子进程重执行时包名会丢'
             % (sanitize_at, wait_at))

    # 2. 凭据子进程的 ep[] 必须带 g_mgr_env（execve 清环境）
    ep_ok = False
    for i, ln in enumerate(lines, 1):
        if re.search(r'char\s*\*\s*const\s+ep\[\]', ln):
            block = "\n".join(lines[i - 1:i + 6])
            if "g_mgr_env" in block and "execve" in "\n".join(lines[i - 1:i + 12]):
                ep_ok = True
                break
    if not ep_ok:
        fail("execve 的 ep[] 里没有 g_mgr_env：重执行后 EXTRACTKIT_MGR 会消失")

    # 3. worker 的 envp[] 必须带 g_mgr_env（脚本靠它决定 --package-name），
    #    并且真正 execve 脚本的那行必须用这个 envp（别只剩个没人用的声明）
    if not re.search(r'g_mgr_env\s*,\s*/\*', text):
        fail("wait_child_main 的 envp[] 里没有 g_mgr_env")
    worker_ok = False
    for i, ln in enumerate(lines, 1):
        if 'execve("/system/bin/sh", av, envp)' in ln:
            head = "\n".join(lines[max(0, i - 140):i])
            if "g_mgr_env" in head and "ksu_stage" in head:
                worker_ok = True
                break
    if not worker_ok:
        fail("跑 ksu_stage.sh 的那次 execve 没带上含 g_mgr_env 的 envp")

    # 4. 自检入口存在（真机验收要用，没有它就只能靠跑整条链）
    if '"mgrprobe"' not in text:
        fail('缺少 mgrprobe 自检分支')

    print("check-env-plumbing: ok (sanitize@%d < wait@%d, ep/envp/probe 都在)"
          % (sanitize_at, wait_at))


if __name__ == "__main__":
    main()
