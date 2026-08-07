#!/usr/bin/env python3
"""找 URL path 字符串 + 追踪 ebp-0xbc 写入点"""
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

def read_cstr(va):
    rva = va - image_base
    for n,(va_s,sz,raw) in secs.items():
        if va_s <= rva < va_s+sz:
            off = rva - va_s
            end = raw.find(b'\x00', off)
            if end < 0: end = len(raw)
            return raw[off:end].decode('latin1','replace')
    return None

# 1) 列出所有以 '/' 开头的路径串（在 .rdata）
print("== .rdata 中以 '/' 开头的路径串 ==")
cur = bytearray(); start = 0
paths = []
for i, b in enumerate(rdata_raw):
    if 0x20 <= b < 0x7f:
        if not cur: start = i
        cur.append(b)
    else:
        if len(cur) >= 2 and cur[0:1] == b'/':
            s = bytes(cur)
            rva = rdata_va + start
            paths.append((rva, image_base+rva, s.decode('latin1')))
        cur = bytearray()
if len(cur) >= 2 and cur[0:1] == b'/':
    paths.append((rdata_va + start, image_base+rva, bytes(cur).decode('latin1')))
for rva, va, s in paths:
    if len(s) <= 64:
        print(f"  RVA=0x{rva:08X} VA=0x{va:08X}  {s!r}")

# 2) 找包含 0x0002AEBE 的函数：向前找 prologue (push ebp; mov ebp,esp = 55 8B EC)
print("\n== 找 0x0002AEBE 所在函数入口 ==")
target = 0x0002AEBE
# 向前搜索 0x10000 字节内的 prologue
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
# 简单：找最近的 55 8B EC
off_target = target - text_va
search_start = max(0, off_target - 0x3000)
prologue_off = -1
for i in range(off_target, search_start, -1):
    if text_raw[i] == 0x55 and text_raw[i+1] == 0x8B and text_raw[i+2] == 0xEC:
        prologue_off = i
        # 验证：往前是 ret/cc 填充
        if prologue_off > 0 and text_raw[prologue_off-1] in (0xC3, 0xCC, 0x90):
            break
        # 也接受
        # 不 break，继续找更近的
        # 实际取最近的
        break
if prologue_off >= 0:
    func_start = text_va + prologue_off
    print(f"  函数入口 VA=0x{func_start:08X} (RVA off=0x{prologue_off:X})")
    # 反汇编整个函数到 ret
    chunk = text_raw[prologue_off: prologue_off + 0x4000]
    print("  扫描对 ebp-0xbc / ebp-0xa4 / ebp-0x94 的写入...")
    for it in md.disasm(chunk, func_start):
        if it.address > target + 0x200: break
        # 关注 mov [ebp-0xbc], ... / lea ..., [ebp-0xbc] / 对这些栈对象的调用
        op = it.op_str
        if any(x in op for x in ['ebp - 0xbc', 'ebp - 0xa4', 'ebp - 0x94', 'ebp - 0x90', 'ebp - 0xa8', 'ebp - 0xb0']):
            ann = ""
            for o in it.operands:
                if o.type == 2 and 0x10000000 <= o.imm < 0x10073000:
                    s = read_cstr(o.imm)
                    if s: ann = f"  ; {s!r}"
            print(f"    {it.address:08X}: {it.mnemonic:8s} {it.op_str}{ann}")

# 3) 找包含 0x0002D55E (GET) 的函数入口
print("\n== 找 0x0002D55E 所在函数入口 ==")
target2 = 0x0002D55E
off_t2 = target2 - text_va
pro2 = -1
for i in range(off_t2, max(0, off_t2 - 0x4000), -1):
    if text_raw[i] == 0x55 and text_raw[i+1] == 0x8B and text_raw[i+2] == 0xEC:
        pro2 = i
        if pro2 > 0 and text_raw[pro2-1] in (0xC3, 0xCC, 0x90):
            break
if pro2 >= 0:
    fs = text_va + pro2
    print(f"  函数入口 VA=0x{fs:08X}")
    chunk = text_raw[pro2: pro2 + 0x6000]
    # 找所有 push imm (字符串) 和对 ebp-0xbc 的写入
    print("  函数内字符串引用 + ebp-0xbc/0xa4 写入:")
    for it in md.disasm(chunk, fs):
        if it.address > target2 + 0x300: break
        show = False
        ann = ""
        for o in it.operands:
            if o.type == 2 and 0x10000000 <= o.imm < 0x10073000:
                s = read_cstr(o.imm)
                if s and len(s) < 80:
                    ann = f"  ; {s!r}"
                    show = True
        if any(x in it.op_str for x in ['ebp - 0xbc', 'ebp - 0xa4', 'ebp - 0x94', 'ebp - 0x90', 'ebp - 0xa8', 'ebp - 0xb0', 'ebp - 0x9c']):
            show = True
        if show:
            print(f"    {it.address:08X}: {it.mnemonic:8s} {it.op_str}{ann}")
