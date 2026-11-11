#!/usr/bin/env python3
"""find-kallsyms.py - 从 raw arm64 Image 还原 kallsyms（不需要 root、不需要 vmlinux）。

已用真实镜像验证：对 6.6.118-android15-8-g554929766a0d（AAK-AN00 那份 boot.img）
解出的 do_timer_create / selinux_state / root_user / init_* 与源码常量逐位一致。

格式（scripts/kallsyms.c，6.4+ BASE_RELATIVE）:

    kallsyms_num_syms     u32
    kallsyms_names        每条：uleb128(len) + len 个 token（首个 token 是类型字符 T/t/…）
    kallsyms_markers      (N+255)/256 个 u32：每第 256 个符号在 names 里的偏移
    kallsyms_token_table  256 个 NUL 结尾字符串
    kallsyms_token_index  256 个 u16：每个 token 在 table 内的偏移
    kallsyms_offsets      N 个 u32（相对 relative_base；>=0x80000000 为负）
    kallsyms_relative_base u64

锚点用 markers（唯一一个从 0 起、步长稳定的升序 u32 数组），比按 relative_base
反推稳 —— BOLT/PGO 过的内核里那附近还躺着别的指针，按地址找容易认错。

用法:
    python3 tools/find-kallsyms.py kernel.bin -o kallsyms.txt
"""
from __future__ import annotations

import argparse
import pathlib
import re
import struct
import sys

MIN_MARKERS = 128
MAX_MARKERS = 4096
STEP_MIN = 32
STEP_MAX = 20000
NAME_WINDOW = 8 << 20
IDENT = re.compile(r"^[A-Za-z_.$][A-Za-z0-9_.$]*$")


def align(v: int, a: int) -> int:
    return (v + a - 1) & ~(a - 1)


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def find_markers(img: bytes):
    """markers：4 对齐、首元素 0、严格递增、步长稳定。"""
    out = []
    n = len(img)
    o = 0
    while o + 4 <= n:
        if img[o:o + 4] == b"\0\0\0\0":
            run = 1
            p = o + 4
            prev = 0
            while p + 4 <= n and run < MAX_MARKERS:
                v = u32(img, p)
                d = v - prev
                if d <= STEP_MIN or d > STEP_MAX:
                    break
                run += 1
                prev = v
                p += 4
            if run >= MIN_MARKERS:
                out.append((o, run))
                o = p
                continue
        o += 4
    return out


def parse_tokens(img: bytes, start: int):
    tokens = []
    p = start
    for _ in range(256):
        q = img.find(b"\0", p, p + 512)
        if q < 0:
            return None, p
        tok = img[p:q]
        if tok and any(c < 0x20 or c > 0x7E for c in tok):
            return None, p
        tokens.append(tok)
        p = q + 1
    return tokens, p


def read_record(img: bytes, q: int):
    ln = img[q]
    q += 1
    if ln & 0x80:
        ln = (ln & 0x7F) | (img[q] << 7)
        q += 1
    return ln, q


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("image", type=pathlib.Path)
    ap.add_argument("-o", "--out", type=pathlib.Path, default=pathlib.Path("kallsyms.txt"))
    args = ap.parse_args()

    img = args.image.read_bytes()
    print(f"[*] image {len(img)} B")

    markers_hits = find_markers(img)
    print(f"[*] markers 候选: {[(hex(o), m) for o, m in markers_hits]}")
    if not markers_hits:
        print("[-] 没有 markers 特征，可能不是 BASE_RELATIVE 布局", file=sys.stderr)
        return 1

    for markers_off, mcount in markers_hits:
        markers = [u32(img, markers_off + 4 * i) for i in range(mcount)]

        table_off = align(markers_off + 4 * mcount, 8)
        tokens, table_end = parse_tokens(img, table_off)
        if tokens is None:
            continue

        ti_off = None
        for cand in (table_end, table_end + 2, table_end + 4, table_end + 6):
            if cand + 512 > len(img):
                continue
            if u16(img, cand) != 0:
                continue
            vals = [u16(img, cand + 2 * i) for i in range(256)]
            if all(vals[i] < vals[i + 1] for i in range(255)):
                ti_off = cand
                break
        if ti_off is None:
            continue

        offsets_off = align(ti_off + 512, 4)

        # names 起点：窗口内找“第一条记录像标识符”，且从该点走 256 条正好到 markers[1]
        names_start = None
        lo = max(0, markers_off - NAME_WINDOW)
        p = lo
        while p < markers_off:
            ln, q = read_record(img, p)
            if not (1 <= ln <= 64) or q + ln > markers_off:
                p += 1
                continue
            name = b"".join(tokens[b] for b in img[q:q + ln]).decode("latin1")
            if not IDENT.match(name[1:] or "x"):
                p += 1
                continue
            qq = p
            ok = True
            for _ in range(256):
                l2, qq = read_record(img, qq)
                if not (1 <= l2 <= 512) or qq + l2 > len(img):
                    ok = False
                    break
                qq += l2
            # 走 256 条之后正好停在符号 256 的记录起点 = markers[1]
            if ok and (qq - p) == markers[1]:
                names_start = p
                break
            p += 1
        if names_start is None:
            continue

        # names 末尾到 markers 之间最多有 4 字节对齐填充
        q = names_start
        count = 0
        positions = []
        while q < markers_off - 4:
            start = q
            ln, q2 = read_record(img, q)
            if not (1 <= ln <= 512):
                count = -1
                break
            if count % 256 == 0:
                positions.append(start - names_start)
            q = q2 + ln
            count += 1
        if count <= 0 or positions[:mcount] != markers:
            continue

        base_off = align(offsets_off + 4 * count, 8)
        if base_off + 8 > len(img):
            continue
        base = u64(img, base_off)
        if not (0xFFFFFF8000000000 <= base < 0xFFFFFFFFFFFFFFFF) or (base & 0xFFF):
            continue

        print(f"[+] markers@{markers_off:#x} tokens@{table_off:#x} index@{ti_off:#x} "
              f"offsets@{offsets_off:#x} names@{names_start:#x}")
        print(f"[+] num_syms={count} relative_base={base:#x}")

        out = []
        q = names_start
        bad = 0
        for i in range(count):
            ln, q = read_record(img, q)
            raw = b"".join(tokens[b] for b in img[q:q + ln]).decode("latin1")
            q += ln
            off = u32(img, offsets_off + 4 * i)
            addr = base - (0x100000000 - off) if off >= 0x80000000 else base + off
            typ, name = raw[0], raw[1:]
            if not IDENT.match(name or ""):
                bad += 1
            out.append((addr, typ, name))

        mono = sum(1 for i in range(1, len(out)) if out[i][0] >= out[i - 1][0])
        print(f"[*] {len(out)} symbols, 地址单调 {mono}/{len(out)-1}, 名称异常 {bad}")
        args.out.write_text("".join(f"{a:016x} {t} {n}\n" for a, t, n in out), encoding="utf-8")
        print(f"[+] wrote {args.out}")

        idx = {}
        for a, _t, n in out:
            idx.setdefault(n, a)
        for want in ("_text", "do_timer_create", "prepare_creds", "copy_process",
                     "selinux_state", "panic_on_warn", "root_user",
                     "init_user_ns", "init_ucounts", "init_groups"):
            print(f"    {want:18s} {idx.get(want, 0):#018x}")
        return 0

    print("[-] 没解析出 kallsyms", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
