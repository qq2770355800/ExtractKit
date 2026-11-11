#!/usr/bin/env python3
"""gen-config.py 的自测：造一份合成 BTF + kallsyms，跑一遍并断言输出。

    python3 tools/test-gen-config.py

合成数据的形状照抄真实内核：k_itimer.it 是个匿名 union，里面才是
struct cpu_timer；task_struct.cred/comm、cred 的后半段字段都在。
"""
from __future__ import annotations

import pathlib
import re
import struct
import subprocess
import sys
import tempfile

MAGIC = 0xEB9F


class StrTab:
    def __init__(self) -> None:
        self.buf = bytearray(b"\0")
        self.index: dict[str, int] = {"": 0}

    def add(self, s: str) -> int:
        if s in self.index:
            return self.index[s]
        off = len(self.buf)
        self.buf += s.encode() + b"\0"
        self.index[s] = off
        return off


def build_btf() -> bytes:
    st = StrTab()
    types = bytearray()

    def t(name: str, kind: int, size_or_type: int, vlen: int = 0, kflag: int = 0) -> int:
        info = (kind << 24) | (kflag << 31) | vlen
        types.extend(struct.pack("<III", st.add(name), info, size_or_type))
        return 0

    def member(name: str, type_id: int, byte_off: int) -> None:
        types.extend(struct.pack("<III", st.add(name), type_id, byte_off * 8))

    # id1 INT "int"
    t("int", 1, 4)
    types.extend(struct.pack("<I", 0x0A000000))  # encoding
    int_id = 1

    # id2 PTR -> void
    t("", 2, 0)
    ptr_id = 2

    # id3 STRUCT cpu_timer
    t("cpu_timer", 4, 0x50, vlen=6)
    member("node", int_id, 0x00)
    member("head", int_id, 0x20)
    member("pid", ptr_id, 0x28)
    member("elist", int_id, 0x30)
    member("firing", int_id, 0x40)
    member("handling", int_id, 0x48)
    cpu_timer_id = 3

    # id4 UNION ""  (k_itimer.it 的匿名 union)
    t("", 5, 0x50, vlen=2)
    member("cpu", cpu_timer_id, 0x00)
    member("it_clock", int_id, 0x00)
    anon_union_id = 4

    # id5 STRUCT k_itimer
    t("k_itimer", 4, 0x108, vlen=2)
    member("it", anon_union_id, 0x78)
    member("it_id", int_id, 0x00)
    k_itimer_id = 5

    # id6 STRUCT task_struct
    t("task_struct", 4, 0x14C0, vlen=3)
    member("thread_info", int_id, 0x00)
    member("cred", ptr_id, 0x820)
    member("comm", int_id, 0x830)
    task_id = 6

    # id7 STRUCT cred
    t("cred", 4, 0xB8, vlen=10)
    member("usage", int_id, 0x00)
    member("uid", int_id, 0x08)
    member("euid", int_id, 0x18)
    member("securebits", int_id, 0x28)
    member("cap_effective", int_id, 0x38)
    member("security", ptr_id, 0x80)
    member("user", ptr_id, 0x88)
    member("user_ns", ptr_id, 0x90)
    member("ucounts", ptr_id, 0x98)
    member("group_info", ptr_id, 0xA0)

    header = struct.pack(
        "<HBBIIIII",
        MAGIC, 1, 0,
        24 + len(types) + len(st.buf),  # hdr_len: 放在类型之前，随便对齐即可
        0, len(types), len(types), len(st.buf),
    )
    # 简单一点：类型紧跟在 24 字节头之后，字符串跟在类型后面
    header = struct.pack("<HBBIIIII", MAGIC, 1, 0, 24, 0, len(types), len(types), len(st.buf))
    return bytes(header) + bytes(types) + bytes(st.buf)


KALLSYMS = """\
# names_start=0x1348f00 num_syms=110306 relative_base=0xffffffc080000000
ffffffc0803afc58 do_timer_create
ffffffc0823ba418 selinux_state
ffffffc08216ae0c panic_on_warn
ffffffc08218f228 root_user
ffffffc08218ef98 init_user_ns
ffffffc082190cf8 init_ucounts
ffffffc082190788 init_groups
"""


def main() -> int:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="gencfg-test-"))
    btf = tmp / "vmlinux.btf"
    btf.write_bytes(build_btf())
    sym = tmp / "kallsyms.txt"
    sym.write_text(KALLSYMS, encoding="utf-8")
    tool = pathlib.Path(__file__).with_name("gen-config.py")

    env = dict(**__import__("os").environ, PYTHONIOENCODING="utf-8")
    proc = subprocess.run(
        [sys.executable, str(tool), "--kallsyms", str(sym), "--btf", str(btf), "--print"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
    )
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        print("FAIL: 退出码", proc.returncode)
        return 1

    out = proc.stdout
    expect = {
        "ITIMER_SIZE": 0x108,
        "ITIMER_NODE": 0x78,
        "ITIMER_HEAD": 0x98,
        "ITIMER_ELIST": 0xA8,
        "ITIMER_FIRING": 0xB8,
        "ITIMER_HANDLING": 0xC0,
        "OFF_TASK_CRED": 0x820,
        "OFF_TASK_COMM": 0x830,
        "CRED_UID_OFF": 0x8,
        "CRED_OFF_SECURITY": 0x80,
        "CRED_OFF_USER": 0x88,
        "CRED_OFF_USER_NS": 0x90,
        "CRED_OFF_UCOUNTS": 0x98,
        "CRED_OFF_GROUPS": 0xA0,
    }
    bad = 0
    for macro, want in expect.items():
        m = re.search(rf"#define {macro} (0x[0-9a-f]+|\([^)]*\))", out)
        if not m:
            print(f"FAIL: 输出里没有 {macro}")
            bad += 1
            continue
        got = int(m.group(1), 0) if not m.group(1).startswith("(") else None
        if got != want:
            print(f"FAIL: {macro} 期望 {want:#x} 实际 {m.group(1)}")
            bad += 1

    m = re.search(r"#define STATIC_TIMER_SITE (0x[0-9a-f]+)ULL", out)
    if not m or int(m.group(1), 16) != 0xFFFFFFC0803AFC58 + 0x94:
        print("FAIL: STATIC_TIMER_SITE 不对:", m.group(1) if m else None)
        bad += 1
    m = re.search(r"#define TIMER_SITE_LOW21 (0x[0-9a-f]+)UL", out)
    if not m or int(m.group(1), 16) != (0xFFFFFFC0803AFC58 + 0x94) & 0x1FFFFF:
        print("FAIL: TIMER_SITE_LOW21 不对:", m.group(1) if m else None)
        bad += 1

    for macro, want in {
        "SELINUX_STATE_STATIC": 0xFFFFFFC0823BA418,
        "PANIC_ON_WARN_STATIC": 0xFFFFFFC08216AE0C,
        "ROOT_USER_STATIC": 0xFFFFFFC08218F228,
        "INIT_USER_NS_STATIC": 0xFFFFFFC08218EF98,
        "INIT_UCOUNTS_STATIC": 0xFFFFFFC082190CF8,
        "INIT_GROUPS_STATIC": 0xFFFFFFC082190788,
    }.items():
        m = re.search(rf"#define {macro} (0x[0-9a-f]+)ULL", out)
        if not m or int(m.group(1), 16) != want:
            print(f"FAIL: {macro} 不对:", m.group(1) if m else None)
            bad += 1

    if "cread" in out:
        print("FAIL: 还有 typo")
        bad += 1

    if bad:
        print(f"\n{bad} 项失败\n---- 输出 ----\n{out}")
        return 1
    print("PASS: gen-config.py 在合成数据上输出全部正确")
    print(f"（临时目录 {tmp}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
