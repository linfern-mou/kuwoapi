#!/usr/bin/env python3
"""精确反汇编 body 构造（0x0002AE40 ~ 0x0002AED0），确认所有 push 参数"""
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

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

# 从函数入口 0x0002ABF0 开始反汇编到 0x0002AF00
print("== body 构造完整反汇编 (0x0002AE40 ~ 0x0002AED0) ==")
start = 0x0002AE40
end = 0x0002AED0
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

# 统计 push 参数
print("\n== _snprintf 调用的参数（从 fmt 前最后一个 push 到 call）==")
# 从 0x0002AEBE (push fmt) 往前找所有 push
# 0x0002AEBE: push 0x1005bd28 (fmt)
# 0x0002AEC3: push 0x103 (size)
# 0x0002AEC8: push eax (buffer)
# 0x0002AEC9: call _snprintf
# 所以参数是 fmt 之前的 push（倒序）
print("  call _snprintf(buf=[ebp-0x7a8], size=0x103, fmt=<%s><%s>|<%u,%u>|...)")
print("  参数（从最后一个到第一个）:")

# 手动列出从反汇编结果中的 push
pushes = [
    (0x0002AEB9, "'001' (0x10054884)", "arg1 -> <%s>"),
    (0x0002AEB4, "'U_QRY' (0x1005BD20)", "arg2 -> <%s>"),
    (0x0002AEAE, "[ebx+0x124] sig1", "arg3 -> <%u"),
    (0x0002AEA8, "[ebx+0x128] sig2", "arg4 -> ,%u>"),
    (0x0002AEA7, "ecx [0x10069c2c+0x7c] 用户IP dword", "arg5 -> <%u>"),
    (0x0002AEA6, "esi 0x1006b514 str", "arg6 -> <%s>"),
    (0x0002AE9C, "ebx 0x1006b52c str", "arg7 -> <%s>"),
    (0x0002AE9B, "[ebp-0x230] 用户IP str", "arg8 -> <%s>"),
    (0x0002AE94, "eax [ebp-0x654] 本地IP:Port", "arg9 -> <uip:%s>"),
    (0x0002AE93, "edx port [0x10069c2c+0x86]", "arg10 -> <nat:%u>"),
    (0x0002AE80, "[eax+0x370] flags", "arg11 -> <flags:%u>"),
]
for addr, desc, mapping in pushes:
    print(f"  {addr:08X}: {desc:40s} {mapping}")

print("\n  格式串剩余 %s (ipdeny:no %s 和 loginid:%s) 无对应 push")
print("  可能是编译器优化或字符串字面量在格式串中")
