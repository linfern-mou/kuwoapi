#!/usr/bin/env python3
"""查找 deliver.kuwo.cn 周围字符串 + ResSeaSvr 默认值"""
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

# 显示 deliver.kuwo.cn (VA=0x10059DE2) 周围 0x200 字节的所有字符串
print("== deliver.kuwo.cn (0x10059DE2) 周围字符串 ==")
center_off = 0x10059DE2 - image_base - rdata_va
start = max(0, center_off - 0x200)
end = min(len(rdata_raw), center_off + 0x400)
i = start
while i < end:
    if 0x20 <= rdata_raw[i] < 0x7f:
        j = i
        while j < end and 0x20 <= rdata_raw[j] < 0x7f:
            j += 1
        if j - i >= 3:
            s = rdata_raw[i:j].decode('latin1')
            rva = rdata_va + i
            print(f"  VA=0x{image_base+rva:08X}  {s!r}")
        i = j
    else:
        i += 1

# 查 ResSeaSvr 在 .text 中所有引用
print("\n== ResSeaSvr (0x100547E8) 引用 ==")
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
target = 0x100547E8
for align in range(0,4):
    off = align
    while off < len(text_raw):
        insns = list(md.disasm(text_raw[off:], text_va+off, count=1))
        if not insns:
            off += 1; continue
        ins = insns[0]
        for op in ins.operands:
            if op.type == 2 and (op.imm & 0xFFFFFFFF) == target:
                print(f"  0x{ins.address:08X}: {ins.mnemonic} {ins.op_str}")
                # 反汇编上下文
                ctx_start = max(0, ins.address - text_va - 0x40)
                ctx_end = min(len(text_raw), ins.address - text_va + 0x80)
                for it in md.disasm(text_raw[ctx_start:ctx_end], text_va+ctx_start):
                    ann = ""
                    for o in it.operands:
                        if o.type == 2 and 0x10000000 <= o.imm < 0x10073000:
                            rva = o.imm - image_base
                            for n,(vs,sz,raw) in secs.items():
                                if vs <= rva < vs+sz:
                                    off2 = rva - vs
                                    e = raw.find(b'\x00', off2)
                                    if e < 0: e = len(raw)
                                    s = raw[off2:e].decode('latin1','replace')
                                    if s and len(s) < 80:
                                        ann = f"  ; {s!r}"
                                    break
                                break
                    mark = " <==" if it.address == ins.address else ""
                    print(f"    {it.address:08X}: {it.mnemonic:8s} {it.op_str}{ann}{mark}")
                print()
        off = ins.address + ins.size - text_va
