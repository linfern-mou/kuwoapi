#!/usr/bin/env python3
"""精确读取 POST body 格式字符串 0x1005BD28 的原始字节"""
import pefile

DLL = "/workspace/default_extracted/kuwomusic/8.7.4.0_BDS1/bin/KwMV.dll"
pe = pefile.PE(DLL, fast_load=True)
pe.parse_data_directories()
image_base = pe.OPTIONAL_HEADER.ImageBase
secs = {}
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('latin1')
    secs[name] = (s.VirtualAddress, s.Misc_VirtualSize, s.get_data())
rdata_va, rdata_sz, rdata_raw = secs['.rdata']

# 0x1005BD28 的 RVA 和偏移
va = 0x1005BD28
rva = va - image_base
off = rva - rdata_va

# 读取 0x100 字节
print(f"== 0x{va:08X} (RVA=0x{rva:08X}, off=0x{off:X}) 原始字节 ==")
data = rdata_raw[off:off+0x100]
# 找 \0 终止
end = data.find(b'\x00')
if end < 0: end = len(data)
s = data[:end]
print(f"长度: {len(s)}")
print(f"hex: {s.hex()}")
print(f"repr: {s.decode('latin1')!r}")
print()
print("== 字节级解读 ==")
for i, b in enumerate(s):
    c = chr(b) if 0x20 <= b < 0x7f else f'\\x{b:02x}'
    print(f"  [{i:2d}] 0x{b:02x} {c}")

# 也打印前后 0x80 字节，看是否有相邻字符串
print("\n== 前后 0x80 字节上下文 ==")
ctx = rdata_raw[max(0,off-0x80): off+end+0x80]
print(f"hex: {ctx.hex()}")
# 找出所有可打印子串
i = 0
while i < len(ctx):
    if 0x20 <= ctx[i] < 0x7f:
        j = i
        while j < len(ctx) and 0x20 <= ctx[j] < 0x7f:
            j += 1
        if j - i >= 2:
            rva_s = rdata_va + max(0,off-0x80) + i
            print(f"  VA=0x{image_base+rva_s:08X}  {ctx[i:j].decode('latin1')!r}")
        i = j
    else:
        i += 1
