#!/usr/bin/env python3
"""ksu_stage.sh -> ksu_stage.h（C 字符串常量）。改脚本后跑一次这个。

生成后立刻做关键字自检：关键逻辑被误删（比如 owner 解析、DRYRUN、
--package-name）会直接非零退出，避免又出一个「静默退化」的包。
"""
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parent.parent
src = root / 'payload/src/ksu_stage.sh'
sh = src.read_text(encoding='utf-8').splitlines()

REQUIRED = ['scan_dir', '[resolve]', '--package-name', 'EXTRACTKIT_DRYRUN',
            'EXTRACTKIT_APP_ROOT', 'KSU_ALREADY', 'late-load']
joined = '\n'.join(sh)
missing = [k for k in REQUIRED if k not in joined]
if missing:
    sys.stderr.write('ksu_stage.sh 缺少关键标记: %s\n' % ', '.join(missing))
    sys.exit(1)


def esc(s: str) -> str:
    return s.replace('\\', '\\\\').replace('"', '\\"')


out = ['/*',
       ' * ksu_stage.h - KernelSU 交接脚本（由 ksu_stage.sh 生成，勿手改）。',
       ' * 重新生成：python tools/gen-ksu-stage.py',
       ' */',
       '#ifndef KSU_STAGE_H',
       '#define KSU_STAGE_H',
       '',
       'static const char KSU_STAGE_SCRIPT[] =']
for i, line in enumerate(sh):
    tail = '' if i == len(sh) - 1 else '\\n'
    out.append('\t"%s%s"' % (esc(line), tail))
out += ['\t;', '', '#endif /* KSU_STAGE_H */']

dst = root / 'payload/src/ksu_stage.h'
dst.write_text('\n'.join(out) + '\n', encoding='utf-8', newline='\n')

hdr = dst.read_text(encoding='utf-8')
bad = [k for k in REQUIRED if k.replace('\\', '\\\\').replace('"', '\\"') not in hdr]
if bad:
    sys.stderr.write('ksu_stage.h 生成后校验失败: %s\n' % ', '.join(bad))
    sys.exit(1)

print('ksu_stage.h: %d lines, %d bytes, markers ok' % (len(sh), dst.stat().st_size))

# 同步一份到 assets：App 的「管理器自检」要拿它去真机上干跑解析（DRYRUN，不改文件）
asset = root / 'app/src/main/assets/stage/ksu_stage.sh'
asset.parent.mkdir(parents=True, exist_ok=True)
asset.write_text('\n'.join(sh) + '\n', encoding='utf-8', newline='\n')
print('assets/stage/ksu_stage.sh: %d bytes' % asset.stat().st_size)
