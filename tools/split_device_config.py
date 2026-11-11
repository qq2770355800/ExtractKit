#!/usr/bin/env python3
"""把 payload 的机型相关常量拆进 device_config.h，并让 .c 改为 include。

一次性迁移脚本（已执行过，保留是为了说明结构怎么来的）。
用法: python tools/split_device_config.py payload/src/cve-2026-98260-uid0.c
"""
import pathlib
import sys

START = "/* Event ids on this exact build"
END = "#define FULLCAP 0x1ffffffffffULL"

HEADER = """/*
 * device_config.h - 机型相关常量（由 tools/gen-config.py 生成）
 *
 * 生成方式:
 *   python3 tools/gen-config.py --kallsyms kallsyms.txt --btf vmlinux.btf \\
 *           --measure measurements.json --out payload/src/device_config.h
 *
 * 手工改也行，但换内核/换固件后请务必重新生成，不要照抄别的机型。
 */
#ifndef DEVICE_CONFIG_H
#define DEVICE_CONFIG_H

{body}
#endif /* DEVICE_CONFIG_H */
"""


def main() -> int:
    src = pathlib.Path(sys.argv[1] if len(sys.argv) > 1
                       else "payload/src/cve-2026-98260-uid0.c")
    text = src.read_text(encoding="utf-8")
    i = text.find(START)
    j = text.find(END)
    if i < 0 or j < 0:
        print("error: 找不到常量块边界", file=sys.stderr)
        return 1
    j += len(END)
    body = text[i:j].rstrip() + "\n"
    out = src.with_name("device_config.h")
    out.write_text(HEADER.format(body=body), encoding="utf-8")
    text = text[:i] + '#include "device_config.h"\n' + text[j:]
    src.write_text(text, encoding="utf-8")
    print(f"wrote {out}")
    print(f"patched {src}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
