#!/usr/bin/env python3
"""
彻底扫描：线性反汇编 .text 全段，记录每条指令中出现的立即数，
匹配目标字符串 VA。同时扫描 .rdata 中的指针表（4字节 = VA）。
"""
import sys, os, struct
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DLL = sys.argv[1] if len(sys.argv) > 1 else \
    "/workspace/default_extracted/kuwomusic/8.7.4.0_BDS1/bin/KwMV.dll"

# 关心的字符串 VA 列表（从上一步输出手动整理）
TARGETS = {
    0x1005B7E0: 'GET %s?%s HTTP/1.0 (copy1)',
    0x1005B7F4: 'Host: deliver.kuwo.cn (copy1)',
    0x1005B8B0: 'POST %s HTTP/1.1 (copy1)',
    0x1005B8C2: 'Host: deliver.kuwo.cn (copy1 POST)',
    0x1005B9C8: 'GET %s?%s HTTP/1.0 (copy2)',
    0x1005B9DC: 'Host: deliver.kuwo.cn (copy2)',
    0x1005BA98: 'POST %s HTTP/1.1 (copy2)',
    0x1005BAAA: 'Host: deliver.kuwo.cn (copy2 POST)',
    0x1005BD28: 'POST body fmt: <%s><%s>|<%u,%u>|<%u><%s><%s>|<%s>|<rid>|...',
    0x1005BE74: 'func:%s|kid:%u|sig1:%u|sig2:%u|res:%s',
    0x1005B338: 'log: kid:%u|sip:%s|sig1:%u|sig2:%u|seares:%s|...|resserver:%s|ressucway:%d',
    0x10059DD9: '<Tracker>deliver.kuwo.cn</Tracker>',
    0x10059EA3: '<ResUpSvr>deliver.kuwo.cn</ResUpSvr>',
    0x10059EE2: '<ResSeaSvr>deliver.kuwo.cn</ResSeaSvr>',
    0x10059F09: '<ResSeaPort>80</ResSeaPort>',
    0x10053A88: 'GET /%s HTTP/1.1',
    0x10053E8C: 'HEAD %s HTTP/1.0',
    0x10053F40: 'GET / HTTP/1.0',
    0x1005C678: 'GET %s HTTP/1.1 (peer?)',
    0x1005C820: 'GET %s HTTP/1.1',
    0x1005CA98: 'GET %s HTTP/1.1',
    0x1005CF28: 'POST / HTTP/1.1',
}

pe = pefile.PE(DLL, fast_load=True)
pe.parse_data_directories()
image_base = pe.OPTIONAL_HEADER.ImageBase

text = rdata = data = None
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('latin1')
    if name == '.text':   text   = (s.VirtualAddress, s.Misc_VirtualSize, s.get_data())
    elif name == '.rdata': rdata = (s.VirtualAddress, s.Misc_VirtualSize, s.get_data())
    elif name == '.data':  data  = (s.VirtualAddress, s.Misc_VirtualSize, s.get_data())

text_va, text_sz, text_raw = text
rdata_va, rdata_sz, rdata_raw = rdata

target_set = set(TARGETS.keys())

# 1) 扫描 .rdata 指针表：找 4 字节 == target VA
print("== .rdata 中指针表引用 (4字节==VA) ==")
for off in range(0, len(rdata_raw) - 4):
    val = struct.unpack_from('<I', rdata_raw, off)[0]
    if val in target_set:
        rva = rdata_va + off
        print(f"  .rdata RVA=0x{rva:08X} VA=0x{image_base+rva:08X}  -> 0x{val:08X} ({TARGETS[val]})")

# 2) 线性反汇编 .text，找任何指令操作数引用 target VA
print("\n== .text 线性反汇编，操作数引用目标 VA ==")
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

# 收集所有引用点 (insn_rva, target_va, insn)
refs = []
# 用大步长扫描，从 .text 起点线性反汇编（不完全准确但能覆盖大部分）
# 为提高准确度，从多个起点扫描：0, 1, 2, 3 (对齐探索)
seen_insn = set()
for align_start in range(0, 4):
    off = align_start
    while off < len(text_raw):
        insns = list(md.disasm(text_raw[off:], text_va + off, count=1))
        if not insns:
            off += 1
            continue
        ins = insns[0]
        if ins.address not in seen_insn:
            seen_insn.add(ins.address)
            # 检查操作数
            for op in ins.operands:
                if op.type == 2:  # X86_OP_IMM
                    if op.imm in target_set:
                        refs.append((ins.address, op.imm, ins))
        off = ins.address + ins.size - text_va

print(f"找到 {len(refs)} 处指令引用：")
# 去重
refs.sort()
seen = set()
for insn_rva, tv, ins in refs:
    key = (insn_rva, tv)
    if key in seen: continue
    seen.add(key)
    print(f"\n--- VA=0x{insn_rva:08X}: {ins.mnemonic} {ins.op_str}  -> 0x{tv:08X} ({TARGETS[tv]}) ---")
    # 反汇编上下文：前 96 字节，后 160 字节
    off = insn_rva - text_va
    start = max(0, off - 96)
    end = min(len(text_raw), off + 160)
    chunk = text_raw[start:end]
    print("  上下文:")
    for it in md.disasm(chunk, text_va + start):
        marker = " <==" if it.address == insn_rva else ""
        ann = ""
        if it.mnemonic in ('push','mov','lea','cmp') and it.op_str:
            for op in it.operands:
                if op.type == 2 and op.imm in target_set:
                    ann = f"  ; -> {TARGETS[op.imm]}"
                    break
        print(f"    {it.address:08X}: {it.mnemonic:8s} {it.op_str}{ann}{marker}")
