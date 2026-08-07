#!/usr/bin/env python3
"""从函数入口 0x0002ABF0 精确反汇编到 0x0002AE80，确认 [ebp-0x28] 和 edi 来源"""
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

# 从 0x0002ADC8 (call esi 之后) 到 0x0002AE80，确认 [ebp-0x28] 来源
print("== [ebp-0x28] 和 edi 来源 (0x0002ADC8 ~ 0x0002AE80) ==")
start = 0x0002ADC8
end = 0x0002AE80
off = start - text_va
chunk = text_raw[off: end - text_va]
for it in md.disasm(chunk, start):
    ann = ""
    for o in it.operands:
        if o.type == 2 and 0x10000000 <= o.imm < 0x10073000:
            s = read_cstr(o.imm)
            if s and len(s) < 100:
                ann = f"  ; {s!r}"
                break
        elif o.type == 3 and o.mem.disp and o.mem.base == 0:
            v = o.mem.disp & 0xFFFFFFFF
            if v in imports:
                ann = f"  ; {imports[v][0]}!{imports[v][1]}"
    marker = ""
    if it.mnemonic == "push":
        marker = " <== PUSH"
    print(f"  {it.address:08X}: {it.mnemonic:8s} {it.op_str}{ann}{marker}")
