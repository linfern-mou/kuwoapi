#!/usr/bin/env python3
"""反汇编 0x9EC0 (resserver 直连协议核心) 和 0x0002D1D0 (搜索服务器连接)
重点找：
- TCP 数据包构造（非 HTTP 模式）
- 文件块请求协议
- sig1/sig2 在协议中的位置
"""
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
    for n,(vs,sz,raw) in secs.items():
        if vs <= rva < vs+sz:
            off = rva - vs
            end = raw.find(b'\x00', off)
            if end < 0: end = len(raw)
            return raw[off:end].decode('latin1','replace')
    return None

# 收集 .rdata 中所有可打印字符串（>=3 字符）及其 VA，用于反汇编时自动注释
rdata_strs = {}
i = 0
while i < len(rdata_raw):
    if 0x20 <= rdata_raw[i] < 0x7f:
        j = i
        while j < len(rdata_raw) and 0x20 <= rdata_raw[j] < 0x7f:
            j += 1
        if j - i >= 3:
            va = image_base + rdata_va + i
            rdata_strs[va] = rdata_raw[i:j].decode('latin1','replace')
        i = j
    else:
        i += 1

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

def annotate(ins):
    ann = ""
    for o in ins.operands:
        if o.type == 2:  # imm
            v = o.imm & 0xFFFFFFFF
            if v in rdata_strs:
                s = rdata_strs[v]
                if len(s) < 80:
                    ann = f"  ; {s!r}"
                    break
            if v in imports:
                ann = f"  ; {imports[v][0]}!{imports[v][1]}"
                break
        elif o.type == 3 and o.mem.disp and o.mem.base == 0:  # mem imm
            v = o.mem.disp & 0xFFFFFFFF
            if v in rdata_strs:
                s = rdata_strs[v]
                if len(s) < 80:
                    ann = f"  ; {s!r}"
                    break
            if v in imports:
                ann = f"  ; {imports[v][0]}!{imports[v][1]}"
                break
    return ann

def find_func_end(start, max_bytes=0x2000):
    """通过 ret + 后续 push ebp 模式找函数结束"""
    off = start - text_va
    chunk = text_raw[off: off + max_bytes]
    last_ret = -1
    for ins in md.disasm(chunk, start):
        if ins.mnemonic == 'ret':
            last_ret = ins.address
            # 检查后续是否是 push ebp (新函数开始)
            next_off = (ins.address + ins.size) - text_va
            if next_off < len(text_raw):
                nxt = list(md.disasm(text_raw[next_off:next_off+8], ins.address + ins.size, count=1))
                if nxt and nxt[0].mnemonic == 'push' and 'ebp' in nxt[0].op_str:
                    return ins.address + ins.size
    return last_ret + 1 if last_ret > 0 else start + max_bytes

def disasm_range(start, end, label):
    print(f"\n{'='*70}")
    print(f"== {label} (0x{start:08X} ~ 0x{end:08X}) ==")
    print(f"{'='*70}")
    off = start - text_va
    chunk = text_raw[off: end - text_va]
    for ins in md.disasm(chunk, start):
        ann = annotate(ins)
        marker = ""
        if ins.mnemonic in ('call', 'jmp') and 'dword ptr' not in ins.op_str:
            # 跟踪直接调用
            try:
                tgt = int(ins.op_str, 16)
                marker = f"  -> 0x{tgt:08X}"
            except:
                pass
        print(f"  {ins.address:08X}: {ins.mnemonic:8s} {ins.op_str}{ann}{marker}")

# [1] 反汇编 0x9EC0 - resserver 直连协议核心
end_9ec0 = find_func_end(0x9EC0, 0x3000)
disasm_range(0x9EC0, end_9ec0, "0x9EC0 resserver 直连协议")

# [2] 反汇编 0x0002D1D0 - 搜索服务器连接（含 HTTP/非HTTP 模式判断）
end_d1d0 = find_func_end(0x0002D1D0, 0x3000)
disasm_range(0x0002D1D0, end_d1d0, "0x0002D1D0 搜索服务器连接")

# [3] 反汇编 0x8CB0 / 0x8D10 - IP 选择逻辑
for f in [0x8CB0, 0x8D10, 0x8E40, 0x8F80, 0x8FB0, 0x8D80, 0x9800, 0x60E0, 0x6120, 0x43330, 0x42E90]:
    e = find_func_end(f, 0x800)
    disasm_range(f, e, f"0x{f:X} helper")
