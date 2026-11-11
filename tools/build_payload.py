"""用 NDK 编译 uid0 payload（Windows 下不经 bash），并同步 sha256。"""
import hashlib
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
NDK = pathlib.Path("C:/AndroidSdk/android-ndk-r29")
HOST = "windows-x86_64"
CLANG = NDK / "toolchains/llvm/prebuilt" / HOST / "bin/aarch64-linux-android34-clang.cmd"
SRC = ROOT / "payload/src/cve-2026-98260-uid0.c"
OUT = ROOT / "app/src/main/assets/payload/cve-2026-98260-uid0"

cmd = [
    str(CLANG), "-O2", "-static", "-fno-pie", "-no-pie",
    "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Wno-unused-parameter", "-pthread",
    "-I", str(SRC.parent), "-o", str(OUT), str(SRC),
] + [f for f in os.environ.get("EXTRA_CFLAGS", "").split() if f]
print("[build]", CLANG.name, "->", OUT.name)
p = subprocess.run(cmd, capture_output=True, text=True)
if p.stdout.strip():
    print(p.stdout.strip())
if p.stderr.strip():
    print(p.stderr.strip())
if p.returncode != 0:
    sys.exit(f"compile failed rc={p.returncode}")

strip = NDK / "toolchains/llvm/prebuilt" / HOST / "bin/llvm-strip.exe"
s = subprocess.run([str(strip), "-s", str(OUT)], capture_output=True, text=True)
if s.returncode != 0:
    print("[warn] llvm-strip:", s.stderr.strip()[:300])

data = OUT.read_bytes()
sha = hashlib.sha256(data).hexdigest()
print(f"[ok] {len(data)} B sha256={sha}")

# 1) PayloadCatalog.kt 里的 UID0.sha256
cat = ROOT / "app/src/main/kotlin/com/extractkit/app/PayloadCatalog.kt"
text = cat.read_text(encoding="utf-8")
new, n = re.subn(r'(?s)(id = "chain_uid0".*?sha256 = ")[0-9a-f]*(")',
                 lambda m: m.group(1) + sha + m.group(2), text, count=1)
if n != 1:
    new, n = re.subn(r'"[0-9a-f]{64}"', f'"{sha}"', text, count=1)
cat.write_text(new, encoding="utf-8", newline="\n")
print("[catalog] updated", n)

# 2) assets/SHA256SUMS.txt
sums = ROOT / "app/src/main/assets/SHA256SUMS.txt"
lines = []
if sums.exists():
    for line in sums.read_text(encoding="utf-8").splitlines():
        if "cve-2026-98260-uid0" in line:
            continue
        lines.append(line)
lines.append(f"{sha}  payload/cve-2026-98260-uid0")
sums.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
print("[sums] updated")
