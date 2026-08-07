#!/usr/bin/env python3
"""查 ResSeaSvr / ResSeaPort 配置项的读取和拼接，确认 host/port 来源"""
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
rdata_va, rdata_sz, rdata_raw = secs['.rdata']

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

# 找 ResSeaSvr / ResSeaPort 字符串 VA
def find_va(s):
    idx = rdata_raw.find(s.encode() if isinstance(s,str) else s)
    if idx < 0: return None
    return image_base + rdata_va + idx

targets = {
    find_va('ResSeaSvr'): 'ResSeaSvr',
    find_va('ResSeaPort'): 'ResSeaPort',
    find_va('deliver.kuwo.cn'): 'deliver.kuwo.cn',
    find_va('yl_res_manage'): 'yl_res_manage',
    find_va('/yl_res_manage.search'): '/yl_res_manage.search',
    find_va('/yl_res_manage.spread'): '/yl_res_manage.spread',
    find_va('ResSeaSvr='): 'ResSeaSvr=',
    find_va('SearchServer'): 'SearchServer',
    find_va('SearchServer1'): 'SearchServer1',
    find_va('1008520484'): '1008520484',
    find_va('spreadurl'): 'spreadurl',
    find_va('applyspread'): 'applyspread',
    find_va('/yl_res_manage'): '/yl_res_manage',
}
target_set = {v:k for k,v in targets.items() if v is not None}
print("== 关键字符串 VA ==")
for va, name in targets.items():
    if va:
        print(f"  VA=0x{va:08X}  {name}")

# 线性扫描 .text 找引用
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

print("\n== 引用点 ==")
for align in range(0,4):
    off = align
    while off < len(text_raw):
        insns = list(md.disasm(text_raw[off:], text_va+off, count=1))
        if not insns:
            off += 1; continue
        ins = insns[0]
        for op in ins.operands:
            if op.type == 2:
                v = op.imm & 0xFFFFFFFF
                if v in target_set:
                    print(f"  0x{ins.address:08X}: {ins.mnemonic} {ins.op_str}  ; {target_set[v]!r}")
        off = ins.address + ins.size - text_va
