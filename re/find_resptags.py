#!/usr/bin/env python3
"""找响应标签 <URL> <CHECKSUM> 等的引用点，反汇编响应解析函数"""
import sys, struct
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

def find_cstr_va(target):
    """在 .rdata 找 target 字符串的 VA"""
    idx = rdata_raw.find(target)
    if idx < 0: return None
    return image_base + rdata_va + idx

def read_cstr(va):
    rva = va - image_base
    for n,(va_s,sz,raw) in secs.items():
        if va_s <= rva < va_s+sz:
            off = rva - va_s
            end = raw.find(b'\x00', off)
            if end < 0: end = len(raw)
            return raw[off:end].decode('latin1','replace')
    return None

# 找标签 VA
TAGS = [b'<URL>', b'<CHECKSUM>', b'<FILE_LEN>', b'<USR_ID>', b'<DENY_IP>',
        b'<RES_DEL>', b'<SNETOPT>', b'<RES>', b'<IP>', b'<PORT>', b'<SVR>']
tag_va = {}
for t in TAGS:
    va = find_cstr_va(t)
    if va:
        tag_va[va] = t.decode()
        print(f"  {t.decode():14s} VA=0x{va:08X}")
    else:
        # 试试更宽的（可能有空格等）
        print(f"  {t.decode():14s} NOT FOUND")

target_set = set(tag_va.keys())
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

# 线性扫描 .text 找引用
print("\n== 引用这些标签的指令 ==")
refs = []
for align in range(0,4):
    off = align
    while off < len(text_raw):
        insns = list(md.disasm(text_raw[off:], text_va+off, count=1))
        if not insns:
            off += 1; continue
        ins = insns[0]
        for op in ins.operands:
            if op.type == 2 and (op.imm & 0xFFFFFFFF) in target_set:
                refs.append((ins.address, op.imm & 0xFFFFFFFF, ins))
        off = ins.address + ins.size - text_va

refs.sort(key=lambda x: (x[0], x[1]))
seen = set()
for insn_rva, tv, ins in refs:
    if (insn_rva, tv) in seen: continue
    seen.add((insn_rva, tv))
    print(f"\n--- VA=0x{insn_rva:08X}: {ins.mnemonic} {ins.op_str}  -> {tag_va[tv]!r} ---")

# 对第一个 <URL> 引用，反汇编其所在函数
print("\n== <URL> 引用所在函数的完整上下文 ==")
url_refs = [(r,tv,i) for r,tv,i in refs if tag_va.get(tv)=='<URL>']
if url_refs:
    # 找函数入口
    target = url_refs[0][0]
    off_t = target - text_va
    pro = -1
    for i in range(off_t, max(0, off_t-0x4000), -1):
        if text_raw[i]==0x55 and text_raw[i+1]==0x8B and text_raw[i+2]==0xEC:
            pro = i
            if pro>0 and text_raw[pro-1] in (0xC3,0xCC,0x90):
                break
    if pro >= 0:
        fs = text_va + pro
        print(f"  函数入口 VA=0x{fs:08X}, 反汇编到 0x{target+0x100:08X}")
        chunk = text_raw[pro: pro + (target - fs) + 0x300]
        for it in md.disasm(chunk, fs):
            ann = ""
            for o in it.operands:
                if o.type == 2 and 0x10000000 <= o.imm < 0x10073000:
                    s = read_cstr(o.imm)
                    if s and len(s) < 80:
                        ann = f"  ; {s!r}"
                        break
                elif o.type == 3 and o.mem.disp and o.mem.base == 0:
                    v = o.mem.disp & 0xFFFFFFFF
                    if v in imports:
                        ann = f"  ; {imports[v][0]}!{imports[v][1]}"
            marker = " <==" if it.address == target else ""
            print(f"  {it.address:08X}: {it.mnemonic:8s} {it.op_str}{ann}{marker}")
