"""Kotlin 块注释会嵌套：注释里出现 `/*` 必须再配一个 `*/`。
这个检查器会模拟嵌套并报出未闭合的文件（一行输出，便于放进 CI）。"""
import glob
import pathlib
import sys


def scan(path):
    text = pathlib.Path(path).read_text(encoding="utf-8")
    depth = 0
    i = 0
    in_str = False
    n = len(text)
    while i < n:
        ch = text[i]
        if not in_str and text.startswith("/*", i):
            depth += 1
            i += 2
            continue
        if not in_str and depth and text.startswith("*/", i):
            depth -= 1
            i += 2
            continue
        if ch == '"' and (i == 0 or text[i - 1] != "\\"):
            in_str = not in_str
        i += 1
    return depth


def main():
    bad = 0
    for f in sorted(glob.glob("app/src/**/*.kt", recursive=True)):
        d = scan(f)
        if d:
            print(f"UNCLOSED {f} depth={d}")
            bad += 1
    print("comment-nesting OK" if not bad else f"{bad} 个文件有未闭合块注释")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
