# 酷我P2P协议逆向实现

Go语言实现的酷我音乐PC客户端P2P协议逆向库。

## 项目概述

本项目逆向还原了酷我音乐PC客户端(8.7.4.0_BDS1)的通信协议，实现了完整的HTTP API调用和UDP心跳帧生成。

## 已实现功能

### HTTP API (无需登录)

| 模块 | 函数 | 功能 | 状态 |
|------|------|------|------|
| ipcheck.go | DoIpCheck() | 获取公网IP | ✓ |
| search.go | DhjssSearch() | 搜索音乐 | ✓ |
| musicpay.go | DoMusicPay() | 播放结算/获取音质 | ✓ |
| datacenter.go | DoDataCenter() | 获取音乐信息 | ✓ |
| playlist.go | FetchPlaylistUpdate() | 歌单同步 | ✓ |
| pan.go | DoPan() | 云盘列表 | ✓ |
| newlyric.go | DoNewlyric() | 歌词获取 | ✓ |

### UDP协议

| 模块 | 函数 | 功能 | 状态 |
|------|------|------|------|
| kwmsg.go | BuildKwmsgHeartbeat() | 生成116B心跳帧 | ✓ |
| csf.go | SYN/Data/AckOnly() | UDP25607协议 | ✓ |

## 快速开始

```go
package main

import (
    "fmt"
    "net/http"
    "kuwoapi/module/p2p"
)

func main() {
    client := &http.Client{}
    
    // 1. IP校验
    ipResp, _ := p2p.DoIpCheck(client, 15277654)
    fmt.Printf("IP: %s\n", ipResp.PublicIP)
    
    // 2. 搜索
    results, _ := p2p.DhjssSearch("周杰伦")
    for _, r := range results[:3] {
        fmt.Printf("%s (%s)\n", r.Name, r.Type)
    }
    
    // 3. 播放结算
    payResp, _ := p2p.DoMusicPay(client, 88594783, 1072809302, 228908, 0)
    if len(payResp.Songs) > 0 {
        qualities := p2p.ParseMINFO(payResp.Songs[0].MINFO)
        fmt.Printf("Qualities: %d\n", len(qualities))
    }
    
    // 4. 生成UDP心跳帧
    frame := p2p.BuildKwmsgHeartbeat(15277654, 1, "8.7.4.0_BDS", "8.7.4.0_BDS")
    fmt.Printf("Frame: %d bytes\n", len(frame))
}
```

## API说明

### 搜索接口

```
GET http://dhjss.kuwo.cn/s.c?all={keyword}&tset=artist,album,playlist&multires=1
```

返回：
```json
[
  {
    "id": "336",
    "type": "artist",
    "name": "周杰伦",
    "AARTIST": "Jay Chou",
    "song": [{"id": "228908", "name": "晴天", "artist": "周杰伦"}]
  }
]
```

### 播放结算接口

```
GET http://musicpay.kuwo.cn/music.pay?uid={uid}&sid={sid}&src=mbox&op=query&action=play&ids={rid}&accttype=1
```

返回关键字段：
- `songs[].MINFO` - 音质列表（FLAC/MP3/OGG等）
- `songs[].audio[].p2p_audiosourceid` - 下载源ID
- `songs[].token` - 认证token（每种音质一个）
- `songs[].nsig1/nsig2` - 签名值

### CDN下载URL

格式：
```
http://kw-lw.kuwo.cn/{hash1}/{hash2}/resource/{res_id}/trackmedia/{filename}.flac?source=pc_player.flac
```

注意：hash生成算法需要动态调试KwLib.dll还原。

## 阻塞点

### CDN Hash生成

CDN URL中的hash1/hash2由客户端本地计算，算法在KwLib.dll中实现：

```cpp
// 已知函数签名
string Entrypt::GenerateMD5(string* input, int* len1, int* len2);
bool Sig::CalcSign(char const* data, int* out1, int* out2);
```

**当前状态**: 静态分析无法还原，需要动态调试。

**密钥字符串**（已找到）：
- `yeelion-kuwo-tme`
- `KoOtOiTvINGwd`
- `_Y8g2E6n0E1i7L5t2IoOoNk`

**下一步**: 在Windows环境使用x64dbg动态调试。

## 目录结构

```
module/p2p/
├── ipcheck.go      # IP校验
├── search.go       # dhjss搜索
├── musicpay.go     # 播放结算
├── datacenter.go   # 音乐信息
├── playlist.go     # 歌单同步
├── pan.go          # 云盘
├── newlyric.go     # 歌词
├── kwmsg.go        # UDP 7788心跳帧
├── csf.go          # UDP 25607协议
├── download.go     # 下载URL构造
└── config.go       # 配置解析

cmd/p2pcheck/
└── main.go         # 测试工具
```

## 构建

```bash
# 编译
go build ./...

# 测试
go test ./module/p2p/...

# 运行示例
go run cmd/p2pcheck/main.go
```

## 参考资料

- 抓包文件: `assets/1111_new.pcapng` (84MB)
- 逆向文档: `.monkeycode/docs/p2p-reverse-analysis.md`
- DLL分析: `/tmp/opencode/newver205/kuwomusic/8.7.4.0_BDS1/bin/KwLib.dll`

## License

MIT
