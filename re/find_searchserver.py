#!/usr/bin/env python3
"""查 SearchServer / SearchServer1 等 config 项的引用，确认运行时搜索服务器来源"""
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

def find_va(s):
    idx = rdata_raw.find(s.encode() if isinstance(s,str) else s)
    if idx < 0: return None
    return image_base + rdata_va + idx

def read_cstr(va):
    rva = va - image_base
    for n,(vs,sz,raw) in secs.items():
        if vs <= rva < vs+sz:
            off = rva - vs
            end = raw.find(b'\x00', off)
            if end < 0: end = len(raw)
            return raw[off:end].decode('latin1','replace')
    return None

# 找 SearchServer 周围所有相关字符串
ss_va = find_va('SearchServer')
print(f"== SearchServer @ 0x{ss_va:08X} 周围字符串 ==")
center = ss_va - image_base - rdata_va
for i in range(max(0,center-0x100), min(len(rdata_raw), center+0x200)):
    if 0x20 <= rdata_raw[i] < 0x7f:
        j = i
        while j < len(rdata_raw) and 0x20 <= rdata_raw[j] < 0x7f:
            j += 1
        if j - i >= 3 and i <= center:
            s = rdata_raw[i:j].decode('latin1')
            rva = rdata_va + i
            print(f"  VA=0x{image_base+rva:08X}  {s!r}")
        i = j
    else:
        i += 1

# 找其他相关字符串
targets_str = ['SearchServer', 'SearchServer1', 'SearchServer2', 'SearchServer3',
               'ResServCnt', 'ResSearch', 'SearchPort', 'ResSeaSvr', 'ResSeaPort',
               'ResServer', 'ResServer1', 'ResSuccSvr']
target_set = {}
for s in targets_str:
    va = find_va(s)
    if va:
        target_set[va] = s
        print(f"\n  {s!r} @ VA=0x{va:08X}")

# 也查 pd.dll
print("\n== pd.dll 中的搜索服务器配置 ==")
PD = "/workspace/default_extracted/kuwomusic/8.7.4.0_BDS1/bin/pd.dll"
pe_pd = pefile.PE(PD, fast_load=True)
pe_pd.parse_data_directories()
for s in pe_pd.sections:
    name = s.Name.rstrip(b'\x00').decode('latin1')
    if name == '.rdata':
        pd_rdata = s.get_data()
        pd_rdata_va = s.VirtualAddress
        break
for keyword in [b'SearchServer', b'ResSeaSvr', b'ResSearch', b'ResServer', b'deliver', b'spread', b'/yl_res_manage']:
    idx = pd_rdata.find(keyword)
    while idx >= 0:
        # 找完整字符串
        end = pd_rdata.find(b'\x00', idx)
        if end < 0: end = len(pd_rdata)
        start = idx
        while start > 0 and 0x20 <= pd_rdata[start-1] < 0x7f:
            start -= 1
        s = pd_rdata[start:end].decode('latin1','replace')
        if len(s) < 80:
            rva = pd_rdata_va + start
            print(f"  pd.dll VA=0x{pe_pd.OPTIONAL_HEADER.ImageBase+rva:08X}  {s!r}")
        idx = pd_rdata.find(keyword, idx+1)

# 在 .text 中查 SearchServer 引用
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
print(f"\n== .text 中对 SearchServer (0x{ss_va:08X}) 的引用 ==")
for align in range(0,4):
    off = align
    while off < len(text_raw):
        insns = list(md.disasm(text_raw[off:], text_va+off, count=1))
        if not insns:
            off += 1; continue
        ins = insns[0]
        for op in ins.operands:
            if op.type == 2 and (op.imm & 0xFFFFFFFF) in target_set:
                print(f"  0x{ins.address:08X}: {ins.mnemonic} {ins.op_str}  ; {target_set[op.imm&0xFFFFFFFF]!r}")
        off = ins.address + ins.size - text_va
