#!/usr/bin/env python3
"""反汇编 0x0002D1D0 函数（GET/POST deliver 请求构造）"""
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
    for n,(va_s,sz,raw) in secs.items():
        if va_s <= rva < va_s+sz:
            off = rva - va_s
            end = raw.find(b'\x00', off)
            if end < 0: end = len(raw)
            return raw[off:end].decode('latin1','replace')
    return None

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

# 反汇编 0x0002D1D0 到 0x0002D600
print("== 0x0002D1D0 函数 (deliver 请求发送) ==")
start = 0x0002D1D0
end = 0x0002D600
off = start - text_va
chunk = text_raw[off: end - text_va]
for it in md.disasm(chunk, start):
    ann = ""
    for o in it.operands:
        if o.type == 2 and 0x10000000 <= o.imm < 0x10073000:
            s = read_cstr(o.imm)
            if s and len(s) < 120:
                ann = f"  ; {s!r}"
                break
        elif o.type == 3 and o.mem.disp and o.mem.base == 0:
            v = o.mem.disp & 0xFFFFFFFF
            if v in imports:
                ann = f"  ; {imports[v][0]}!{imports[v][1]}"
    marker = ""
    if it.address in (0x0002D207, 0x0002D55E, 0x0002D5AB, 0x0002D73B):
        marker = " <== KEY"
    print(f"  {it.address:08X}: {it.mnemonic:8s} {it.op_str}{ann}{marker}")
