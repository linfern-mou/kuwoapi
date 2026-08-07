#!/usr/bin/env python3
"""精确反汇编：围绕指定 VA 反汇编，并解析字符串/import"""
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
    secs[name] = (s.VirtualAddress, s.Misc_VirtualSize, s.get_data(), s.PointerToRawData)

text_va, text_sz, text_raw, _ = secs['.text']
rdata_va, rdata_sz, rdata_raw, _ = secs['.rdata']

def read_cstr(va):
    # va 是绝对 VA，转 RVA 再定位段
    rva = va - image_base
    for n,(va_s,sz,raw,_) in secs.items():
        if va_s <= rva < va_s+sz:
            off = rva - va_s
            end = raw.find(b'\x00', off)
            if end < 0: end = len(raw)
            return raw[off:end].decode('latin1', 'replace')
    return None

# import 表
print("== 导入表 (关键) ==")
imports = {}
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode('latin1', 'replace')
        for imp in entry.imports:
            # imp.address 是 IAT 项的 VA
            name = imp.name.decode('latin1','replace') if imp.name else f"ord_{imp.ordinal}"
            imports[imp.address] = (dll, name)
# 打印我们关心的 IAT 项
for addr in [0x10053318, 0x10053360, 0x10053174, 0x10053130, 0x1005314c, 0x1005342c, 0x10053558]:
    if addr in imports:
        print(f"  IAT 0x{addr:08X} -> {imports[addr]}")
    else:
        print(f"  IAT 0x{addr:08X} -> (not found, searching nearby)")
        # 找最近的
        for a,(d,n) in imports.items():
            if abs(a-addr) < 0x40:
                print(f"      near 0x{a:08X} -> {d}!{n}")

# 关心字符串
print("\n== 关心字符串内容 ==")
for va in [0x1005bd28, 0x1005bd20, 0x10054884, 0x10053558, 0x10053f1c, 0x1005b9a8,
           0x1005b7e0, 0x1005b8b0, 0x1005b9c8, 0x1005ba98, 0x1005b7f4, 0x1005b8c2,
           0x1005be74, 0x1005b338]:
    s = read_cstr(va)
    print(f"  0x{va:08X}: {s!r}")

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

def disasm_range(start_rva, end_rva, mark=None):
    off = start_rva - text_va
    if off < 0: off = 0
    end = end_rva - text_va
    if end > len(text_raw): end = len(text_raw)
    chunk = text_raw[off:end]
    print(f"  -- 反汇编 0x{start_rva:08X} ~ 0x{end_rva:08X} --")
    for it in md.disasm(chunk, text_va + off):
        marker = " <==" if mark and it.address == mark else ""
        ann = ""
        # 标注字符串引用
        for op in it.operands:
            if op.type == 2:  # IMM
                v = op.imm & 0xFFFFFFFF
                s = read_cstr(v) if 0x10000000 <= v < 0x10073000 else None
                if s and len(s) >= 2 and all(0x20 <= ord(c) < 0x7f or c in '\t\r\n' for c in s[:20]):
                    ann = f"  ; {s!r}"
                    break
            elif op.type == 3:  # MEM
                # IAT 调用
                if op.mem.disp and op.mem.base == 0:
                    v = op.mem.disp & 0xFFFFFFFF
                    if v in imports:
                        ann = f"  ; {imports[v][0]}!{imports[v][1]}"
        print(f"    {it.address:08X}: {it.mnemonic:8s} {it.op_str}{ann}{marker}")

# 重点区域：POST body 构造函数 (包含 0x0002AEBE)
print("\n== 区域1: POST body 构造 (0x0002AD00 ~ 0x0002AF80, mark=0x0002AEBE) ==")
disasm_range(0x0002AD00, 0x0002AF80, mark=0x0002AEBE)

# GET 请求构造 (0x0002D55E)
print("\n== 区域2: GET %s?%s HTTP/1.0 引用 (0x0002D480 ~ 0x0002D680, mark=0x0002D55E) ==")
disasm_range(0x0002D480, 0x0002D680, mark=0x0002D55E)

# POST 请求构造 (0x0002D5AB)
print("\n== 区域3: POST %s HTTP/1.1 引用 (0x0002D560 ~ 0x0002D730, mark=0x0002D5AB) ==")
disasm_range(0x0002D560, 0x0002D730, mark=0x0002D5AB)
