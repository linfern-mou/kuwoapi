#!/usr/bin/env python3
"""反汇编 0x00014732 函数 - 读取 [ResSearch] SearchServer1/2/3 配置"""
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DLL = "/workspace/default_extracted/kuwomusic/8.7.4.0_BDS1/bin/KwMV.dll"
pe = pefile.PE(DLL, fast_load=True)
pe.parse_data_directories()
image_base = pe.OPTIONAL_HEADER.ImageBase
secs = {}
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('latin1')
    secs[name] = (s.VirtualAddress, s.Misc_VirtualSize, s.get_data())
text_va, text_sz, text_raw = secs['.text']

imports = {}
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode('latin1','replace')
        for imp in entry.imports:
            name = imp.name.decode('latin1','replace') if imp.name else f"ord_{imp.ordinal}"
            imports[imp.address] = (dll, name)

def read_cstr(va):
    rva = va - image_base
    for n,(vs,sz,raw) in secs.items():
        if vs <= rva < vs+sz:
            off = rva - vs
            end = raw.find(b'\x00', off)
            if end < 0: end = len(raw)
            return raw[off:end].decode('latin1','replace')
    return None

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

# 反汇编 0x00014700 到 0x00014900
start = 0x00014700
end = 0x00014900
off = start - text_va
chunk = text_raw[off: end - text_va]
print(f"== 0x{start:08X} 函数 (SearchServer 配置读取) ==")
for it in md.disasm(chunk, start):
    ann = ""
    for o in it.operands:
        if o.type == 2 and 0x10000000 <= o.imm < 0x10073000:
            s = read_cstr(o.imm)
            if s and len(s) < 100:
                ann = f"  ; {s!r}"
        elif o.type == 3 and o.mem.disp and o.mem.base == 0:
            v = o.mem.disp & 0xFFFFFFFF
            if v in imports:
                ann = f"  ; {imports[v][0]}!{imports[v][1]}"
    print(f"  {it.address:08X}: {it.mnemonic:8s} {it.op_str}{ann}")
