import struct, sys, pathlib

data = pathlib.Path(sys.argv[1]).read_bytes()
# BTF 在 image 里以魔数 0xeb9f 开头（小端 b'\x9f\xeb'）
idx = data.find(b'\x9f\xeb\x01\x00')
if idx < 0:
    print("no BTF")
    raise SystemExit(1)

hdr = data[idx:idx + 24]
magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = struct.unpack('<HBBIIIII', hdr)
print(f"BTF magic={magic:#x} ver={version} hdr_len={hdr_len} type_len={type_len} str_len={str_len}")

types_start = idx + hdr_len + type_off
strs_start = idx + hdr_len + str_off


def s(off):
    if off >= str_len:
        return "?"
    end = data.find(b'\x00', strs_start + off)
    return data[strs_start + off:end].decode('utf-8', 'replace')


KIND_NAMES = {1: 'INT', 2: 'PTR', 3: 'ARRAY', 4: 'STRUCT', 5: 'UNION', 6: 'ENUM',
              7: 'FWD', 8: 'TYPEDEF', 9: 'VOLATILE', 10: 'CONST', 11: 'RESTRICT',
              12: 'FUNC', 13: 'FUNC_PROTO', 14: 'VAR', 15: 'DATASEC', 16: 'FLOAT',
              17: 'DECL_TAG', 18: 'TYPE_TAG', 19: 'ENUM64'}

off = types_start
tid = 0
found = {}
while off < types_start + type_len:
    name_off, info, size_or_type = struct.unpack('<III', data[off:off + 12])
    kind = (info >> 24) & 0x1F
    vlen = info & 0xFFFF
    name = s(name_off)
    off += 12
    if kind in (4, 5):          # STRUCT / UNION
        members = []
        for _ in range(vlen):
            m_name, m_type, m_off = struct.unpack('<III', data[off:off + 12])
            members.append((s(m_name), m_type, m_off))
            off += 12
        if name in ('cred', 'task_struct', 'k_itimer'):
            found[name] = (size_or_type, members)
    elif kind == 3:
        off += 12
    elif kind == 1:
        off += 4
    elif kind == 6:
        off += vlen * 8
    elif kind == 19:
        off += vlen * 12
    elif kind == 13:
        off += vlen * 8
    elif kind == 14:
        off += 4
    elif kind == 15:
        off += vlen * 12
    elif kind in (17, 18):
        off += 4
    tid += 1

print("types scanned:", tid)
for nm, (size, members) in found.items():
    print(f"\n{nm}: size=0x{size:x}  ({len(members)} members)")
    for mn, mt, moff in members:
        bit = moff & 0xFFFFFF if (moff >> 24) else moff
        print(f"   {mn:20s} off=0x{bit // 8:x}")
