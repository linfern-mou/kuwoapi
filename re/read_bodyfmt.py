#!/usr/bin/env python3
"""读取 POST body 格式字符串 + resserver 连接协议关键字符串"""
import pefile

DLL = "/workspace/default_extracted/kuwomusic/8.7.4.0_BDS1/bin/KwMV.dll"
pe = pefile.PE(DLL, fast_load=True)
pe.parse_data_directories()
image_base = pe.OPTIONAL_HEADER.ImageBase
secs = {}
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('latin1')
    secs[name] = (s.VirtualAddress, s.Misc_VirtualSize, s.get_data())
rdata_va, rdata_sz, rdata_raw = secs['.rdata']

def read_cstr_at_va(va):
    rva = va - image_base
    off = rva - rdata_va
    end = rdata_raw.find(b'\x00', off)
    if end < 0: end = len(rdata_raw)
    return rdata_raw[off:end].decode('latin1','replace')

# 关键字符串 VA（从反汇编结果）
targets = {
    0x1005BD28: 'POST body fmt',
    0x1005BD20: 'U_QRY 常量',
    0x10054884: '001 常量',
    0x1005B764: '/yl_res_manage.search',
    0x1005BDB0: 'search succeed log',
    0x1005BDCC: '从服务器检索到结果',
    0x1005BF00: '搜索到%d个服务器资源',
    0x1005BF1C: 'url=%s',
    0x1005BDF0: '防火墙警告',
    0x1005BE28: '网络异常',
    0x1005BD98: '开始搜索候选资源',
    0x1005BEA4: '地址受限',
    0x1005BEDC: '资源已经删除',
    0x1005BEC8: '<RES_DEL>',
    0x1005BE58: '<DENY_IP>',
    0x1005BEF8: '<URL>',
    0x1005BEEC: 'FILE_LEN 标签',
    0x1005BF4C: '<USR_ID>',
    0x1005C008: '<SNETOPT>',
    0x1005C100: '<FILE_LEN>',
    0x1005C128: '<CHECKSUM>',
    0x1005B7E0: 'GET %s?%s HTTP/1.0',
    0x1005B8B0: 'POST %s HTTP/1.1',
    0x1005B9C8: 'GET %s?%s HTTP/1.0 (copy2)',
    0x1005B338: 'P2P_DOWN_FILE log fmt',
    0x1005B330: 'SUCC',
    0x1005B454: 'P2P_DOWN_FILE',
    0x1005BD04: '|<cdnreq>',
    0x1005BD10: 'NetID',
    0x1005BD18: 'Setting',
    0x1005BCEC: 'Enable',
    0x1005BCF4: 'CdnSpeedPolicy',
    0x100547DC: 'ResSeaPort',
    0x100547E8: 'ResSeaSvr',
    0x1005BE64: 'DENY_IP 常量',
    0x1005BE6C: 'SEARCH 常量',
    0x1005BE74: 'func:%s|kid:%u|sig1:%u|sig2:%u|res:%s',
    0x1005BE9C: 'SEARES',
    0x1005BEB0: 'foreign IP',
    0x1005BEBC: 'PLAYFAIL',
    0x1005BED4: 'NoRes',
    0x100535D8: 'IP格式 fmt',
    0x100535CC: '%d.%d.%d.%d',
}

print("== 关键字符串内容 ==")
for va, desc in sorted(targets.items()):
    s = read_cstr_at_va(va)
    # 显示原始字节（含非 ASCII）
    print(f"  VA=0x{va:08X} [{desc}]")
    print(f"    repr: {s!r}")
    print()
