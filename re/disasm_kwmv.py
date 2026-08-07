#!/usr/bin/env python3
"""
反汇编 KwMV.dll / pd.dll：
1) 提取所有相关字符串及 RVA
2) 在 .text 段查找引用这些字符串地址的指令（push/mov 立即数）
3) 反汇编引用点附近的代码，分析请求构造逻辑
"""
import sys, os, struct
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DLL = sys.argv[1] if len(sys.argv) > 1 else \
    "/workspace/default_extracted/kuwomusic/8.7.4.0_BDS1/bin/KwMV.dll"

pe = pefile.PE(DLL, fast_load=True)
pe.parse_data_directories()

image_base = pe.OPTIONAL_HEADER.ImageBase
print(f"== {os.path.basename(DLL)} ==")
print(f"ImageBase=0x{image_base:08X}  SizeOfImage=0x{pe.OPTIONAL_HEADER.SizeOfImage:08X}")

# 段信息
sections = {}
text_section = None
rdata_section = None
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('latin1')
    va = s.VirtualAddress
    sz = s.Misc_VirtualSize
    raw = s.get_data()
    sections[name] = (va, sz, raw, s.PointerToRawData)
    print(f"  sec {name:8s} VA=0x{va:08X} VSize=0x{sz:08X} Raw=0x{s.PointerToRawData:08X} RawSz=0x{s.SizeOfRawData:08X}")
    if name == '.text':
        text_section = (va, sz, raw, s.PointerToRawData)
    elif name == '.rdata':
        rdata_section = (va, sz, raw, s.PointerToRawData)

if not text_section or not rdata_section:
    print("missing .text/.rdata")
    sys.exit(1)

text_va, text_sz, text_raw, text_ptr = text_section
rdata_va, rdata_sz, rdata_raw, rdata_ptr = rdata_section

# 关键字
KEYWORDS = [
    b'deliver.kuwo.cn', b'resserver', b'ResSeaSvr', b'ResSeaPort',
    b'sig1', b'sig2', b'seares', b'ressucway', b'ressuccsvr',
    b'GET %s', b'POST %s', b'HTTP/1.0', b'HTTP/1.1',
    b'Host: deliver', b'Host: %s', b'/url?', b'?%s',
    b'kid:', b'sip:', b'%u|%u', b'mode:', b'filetype:',
    b'ResourceSearch', b'ResourceServer', b'SearchRes', b'SearchServer',
    b'p2p', b'P2P', b'peer', b'Peer',
    b'sig.s', b'rid.kuwo.cn',
]

print("\n== 关键字符串 (RVA + VA + 内容) ==")
str_hits = []  # (rva, va, content)
def scan_strings(data, base_va, label):
    # 简单提取 ASCII 可打印串 >=4
    cur = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7f or b == 0x09:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= 4:
                s = bytes(cur)
                for kw in KEYWORDS:
                    if kw in s:
                        rva = base_va + start
                        va = image_base + rva
                        str_hits.append((rva, va, s))
                        break
            cur = bytearray()
    # tail
    if len(cur) >= 4:
        s = bytes(cur)
        for kw in KEYWORDS:
            if kw in s:
                rva = base_va + start
                va = image_base + rva
                str_hits.append((rva, va, s))
                break

scan_strings(rdata_raw, rdata_va, '.rdata')
# 也扫 .data（如果有）
if '.data' in sections:
    dva, dsz, draw, dptr = sections['.data']
    scan_strings(draw, dva, '.data')

# 去重并输出
seen = set()
for rva, va, s in str_hits:
    if rva in seen: continue
    seen.add(rva)
    try:
        txt = s.decode('latin1')
    except:
        txt = repr(s)
    print(f"  RVA=0x{rva:08X} VA=0x{va:08X}  {txt!r}")

# === 找代码引用 ===
print("\n== .text 中引用这些字符串 VA 的指令 ==")
# 构建 va->content 映射
va_to_str = {va: s for rva, va, s in str_hits}

# capstone
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

# 在 text_raw 中找 4 字节小端 immediate == va
print(f"扫描 .text (size=0x{text_sz:X}) 寻找 push/mov 立即数引用...")
ref_sites = []  # (offset_in_text, rva_of_insn, va_referenced)
target_vas = set(va_to_str.keys())
for off in range(0, len(text_raw) - 4):
    val = struct.unpack_from('<I', text_raw, off)[0]
    if val in target_vas:
        # 这是一个潜在引用。回退找到指令起始（capstone 反汇编此偏移）
        ref_sites.append((off, text_va + off, val))

print(f"找到 {len(ref_sites)} 处原始 4 字节匹配，反汇编确认...")

# 对每个引用点，向前回退若干字节反汇编以对齐指令边界
def disasm_around(insn_rva, before=32, after=80):
    off = insn_rva - text_va
    start = max(0, off - before)
    end = min(len(text_raw), off + after)
    chunk = text_raw[start:end]
    insns = list(md.disasm(chunk, text_va + start))
    return insns, start

confirmed_refs = []
for off, insn_rva, val in ref_sites:
    # 尝试从 off 附近反汇编，看是否有一条指令的 op_str 含该 val
    # 先从 off 自身反汇编一条
    insns_one = list(md.disasm(text_raw[off:off+16], text_va + off))
    if not insns_one:
        continue
    ins0 = insns_one[0]
    # 检查是否 push imm32 或 mov reg,imm32 含 hex(val)
    hexval = f"0x{val:x}"
    if hexval in ins0.op_str.lower() or f"0x{val:08x}" in ins0.op_str.lower():
        confirmed_refs.append((off, insn_rva, val, ins0))
        continue
    # 有时 capstone 对齐不对，尝试前 1~3 字节回退
    for back in range(1, 4):
        insns_try = list(md.disasm(text_raw[off-back:off-back+16], text_va + off - back))
        if insns_try:
            it = insns_try[0]
            if it.address <= insn_rva < it.address + it.size:
                hexval = f"0x{val:x}"
                if hexval in it.op_str.lower() or f"0x{val:08x}" in it.op_str.lower():
                    confirmed_refs.append((off, insn_rva, val, it))
                    break

print(f"确认引用 {len(confirmed_refs)} 处：")
for off, insn_rva, val, ins in confirmed_refs:
    s = va_to_str.get(val, b'?')
    try: st = s.decode('latin1')
    except: st = repr(s)
    print(f"\n--- 引用 VA=0x{insn_rva:08X}  -> 字符串 VA=0x{val:08X} ({st!r}) ---")
    print(f"    {ins.address:08X}: {ins.mnemonic} {ins.op_str}")
    # 反汇编上下文
    insns, _start = disasm_around(insn_rva, before=64, after=120)
    print("    上下文:")
    for it in insns:
        marker = " <==" if it.address == ins.address else ""
        # 标注引用的字符串
        annotation = ""
        if it.mnemonic in ('push','mov') and it.op_str:
            for v in target_vas:
                hv = f"0x{v:x}"
                hv2 = f"0x{v:08x}"
                if hv in it.op_str.lower() or hv2 in it.op_str.lower():
                    ss = va_to_str.get(v, b'?')
                    try: sst = ss.decode('latin1')
                    except: sst = repr(ss)
                    annotation = f"  ; -> {sst!r}"
                    break
        print(f"      {it.address:08X}: {it.mnemonic:8s} {it.op_str}{annotation}{marker}")
