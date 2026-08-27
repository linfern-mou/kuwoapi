# 酷我 P2P 协议逆向分析笔记（KwMV.dll）

> 本文档记录对 `pc-client/破解版酷我音乐/Bin/KwMV.dll` 的逆向分析成果，
> 用于指导修复 `/workspace/module/download.go` 中 P2P 下载功能。
> 分析日期：2026-08-24。DLL 版本：MUSIC_8.7.5.0_BCS33（2017-12-22 编译，PE32）。

## 1. 背景

- 本项目是酷我音乐 API 的 Go 实现（main.go / server / module）。
- `module/download.go` 中现有 `P2PDownloader` 为早期猜测实现（19 字节二进制头），与真实协议不符，实际不可用。
- git 历史：曾删除 CDN 回退只保留 P2P；用户反馈 P2P 不能用。
- 分析素材：`pc-client/破解版酷我音乐/` 为完整 PC 客户端（8.7.5.0 破解版），核心 DLL：
  - `Bin/KwMV.dll`（453KB）：P2P 核心，含 CSFSocket、tracker 通信（本文档重点）
  - `Bin/KwModDownload.dll`（477KB）：下载调度 UI 模块
  - 导出函数仅 4 个：`StartP2P`、`StartP2P_V1`、`StopP2P`、`StopUpload`

## 2. 工具与方法备忘

```bash
# 反汇编（i386 PE，ImageBase=0x10000000）
objdump -d -M intel Bin/KwMV.dll > kwmv.asm
# 节区映射（file offset -> VA）：
#   .text : file 0x00400 -> VA 0x10001000
#   .rdata: file 0x51800 -> VA 0x10053000   即 VA = file_off + 0x10001800
# 字符串定位：strings -t x，再转 VA，在 asm 中 grep "push 0xVA" 找引用点
```

## 3. 服务器与端口

| 角色 | 配置键（XML 内嵌字符串） | 值 |
|------|------|------|
| Tracker | `<Tracker>` / `<TrackerPort>` | deliver.kuwo.cn : 25607 |
| ResSeaSvr（资源搜索） | `<ResSeaSvr>` / `<ResUpSvr>` | deliver.kuwo.cn |
| IndexSvr | `<IndexSvr>` | search.kuwo.cn |
| 备用 IP（硬编码） | — | 211.100.49.14:25607, 60.29.226.173:25607 |
| 其他 | `resua.kuwo.cn`、`uh1/uh2.kuwo.cn` | 上报/帮助服务 |

- DLL 内还有 `/yl_res_manage.search` HTTP 接口路径（ResSeaSvr 相关）。
- 配置读取键名：`ResSeaSvr`/`ResSeaPort`/`Tracker`/`TrackerPort`/`ServerPort`/`PreGetNum`(=5)。
- CDN 地址样本：win.player.ra05.sycdn.kuwo.cn 等（ra/ri/rg/rh/rc 系列）。

## 4. CSFSocket 协议（peer 间可靠 UDP 传输）

### 4.1 性质
类 TCP 的可靠 UDP 协议，具备：三次握手（SYN/SYNACK/ACK）、seq/ack/win 流控、
RTT 计算与重传（onLossPacket）、FIN/FINACK 四次挥手、RST。相关类：
`CSFSocket`、`CPacket`、`CNatPunch`（NAT 打洞）、`CDownloadPeerTransfer`、`CDownloadUrlTransfer`。

### 4.2 CPacket 内存布局（从 recvSYNACK @0x1001b290、SendSYN @0x1001dd90 反推）

| 偏移 | 类型 | 含义 |
|------|------|------|
| +0x04 | u32 | seq / ISN（发送前 htonl 转网络序，见 0x10016960 内 call htonl 后回写） |
| +0x08 | u32 | ack |
| +0x0C | ?    | （紧邻 flags） |
| +0x0D | u8  | flags 标志位 |
| +0x0E | u16 | win（窗口） |
| +0x14 | u32 | ruid（远端 uid，来自 [ebx+0x14]） |
| +0x410/+0x414/+0x418 | u32 | 时间戳/统计（非线上字段） |

### 4.3 flags 位标志（分发函数 OnPacket @0x1001cb30，跳转表 @0x1001cc24）

```
bit0 0x01 = SYN
bit1 0x02 = ACK
bit4 0x10 = PSH（携带数据）
bit3 0x08 = RST 类（直接终止）
bit7 0x80 = 特殊分支（接收端 0x1001ef09：读 raw u32 经 ntohl 存 packet+4）
组合分发（dec 后查表）：
  纯ACK          -> case 1 -> recvACK    @0x1001c250
  PSH            -> case 2 -> recvPSH    @0x1001baa0
  case 3         -> 0x1001bee0           （疑似 FIN/FINACK）
  SYN+PSH        -> case 4 -> 0x1001bce0 （带数据的 SYN）
  纯SYN          -> case 5 -> recvSYN    @0x1001b6d0
  case 6         -> recvSYNACK @0x1001b290
  flags&0x08     -> case 8 -> 直接释放包
```

### 4.4 CSF 报文原始头（接收处理 @0x1001e880 的校验）

```
payload[0] 必须 == 0x01 或 0x03（版本/类型）
payload[1] 必须 == 0xFF（魔数）
payload[5] 为 u32（日志中打印，疑似 uid）
payload[0]&0x80 != 0 时走另一解析分支
```

注意：此为 CSFSocket 数据通道报文；tracker 查询则是纯明文（见 §5），两者不同层。

## 5. Tracker 资源搜索协议（重点：明文 UDP 文本协议）

### 5.1 请求格式（snprintf @0x1002aec9，fmt @0x1005bd28）

```
<%s><%s>|<%u,%u>|<%u><%s><%s>|<%s>|<rid>|<uip:%s>|<new>|<nat:%u>|<flags:%u><speer>|<ipdeny:no>%s|<loginid:%s>\r\n
```

参数对照（从 push 序还原）：

| # | 占位符 | 实参 | 说明 |
|---|--------|------|------|
| 1 | %s | "001" (@0x10054884) | 协议版本串 |
| 2 | %s | "U_QRY" (@0x1005bd20) | 命令字 |
| 3 | %u | [task+0x124] | sig1 |
| 4 | %u | [task+0x128] | sig2（即 FID 对） |
| 5 | %u | [global@0x10069c2c+0x7C] | 用户 uid (kid) |
| 6 | %s | 全局 str @0x1006b514 区 | 疑似版本号 |
| 7 | %s | 全局 str @0x1006b52c 区 | 疑似另一标识 |
| 8 | %s | "%d.%d.%d.%d" 构造 | 目标 IP 字符串 |
| 9 | uip:%s | "%d.%d.%d.%d" 构造 | 本机公网 IP |
| 10 | nat:%u | WORD[global+0x86] | NAT 类型（1-5） |
| 11 | flags:%u | [task+0x370] | 标志位（见下） |
| 12 | %s | "\|<cdnreq>" 或空 | CdnSpeedPolicy 开关（注册表 Enable/CdnSpeedPolicy） |
| 13 | loginid:%s | NetID/Setting 配置 | 登录 ID（act.log 中 K:19976128 疑似其值） |

flags 计算（@0x1002ad42 起）：
```
flags = [global@0x10069be4+0x34]
if 配置[0x1006b608]!=0: flags |= 0x20000
if task->local_state==0: flags |= 0x40000   # 本地无文件
elif ==3:                flags |= 0x100000
```

发送方式：已连接 UDP socket + `send(s, buf, strlen, 0)`，纯文本、无二进制前导。
（sendto IAT 槽位核对：0x1005342c 实为 ord19 sendto / ord18 send 同族，此处 4 参数调用为 send。）

### 5.2 响应格式（fmt @0x1005b288，解析引用 @0x1002fc15）

```
FormatVer:1.1|sig:(%lu,%lu)|searchtm:%u|PEERS:
```
其后为 peer 条目列表，条目格式（@0x10058xxx 处 scanf 格式串）：
```
(%u,%s,%hu,%d,%d,%d,%u)    # uid, ip字符串, port, int×3, uint —— 具体字段待进一步确认
```

### 5.3 协议命令字全集（KwMV.dll 字符串）

```
U_QRY(资源查询), HPVQ, JRVQ, HSVW, DSVW, ATPR,
DOWNFILE, PACK, PEER_INFO, FILE_LEN, PEER, PING,
DENY_IP, NOHASHCODE, KCDOWN, FAILED, HTTP, FLAC, LOCAL_INDEXER
```

## 6. act.log 实战日志（2022-05-16，真实成功案例）

路径：`pc-client/破解版酷我音乐/Bin/Log/act.log`

```
ACT:P2P_DOWN_FILE|S:KwMV|
kid:123434546              # 用户 uid
sip:27.18.39.80            # 用户当时公网 IP
sig1:1820666223 sig2:824460054    # 成功案例1（seares:SUCC peernum:100 usedp:21 nconn:18）
sig1:1722967550 sig2:2886171023   # 成功案例2
seatm:47                   # 搜索耗时 ms
resserver:175.102.178.96   # 实际使用的资源服务器
ressuccsvr:175.102.178.96
ressucway:2
total:602 serpack:602 peerpack:0   # ★ 关键：数据包全部来自服务器，peer 贡献为 0
filetype:2 mode:2 down5:234
DOWN_MUSIC 记录: RID:MUSIC_1427105 S1:1455199153 S2:274332222 ISVIP:1 UQ:HQ RQ:HQ
K:19976128                 # 疑似 loginid
VER:8.7.5.0_BCS33 PLAT:WIN32
```

**重要推论**：真实客户端的"P2P 下载"中，实际音频数据几乎全部来自官方
资源服务器节点（serpack），peer 分担为 0。因此正确实现方向 =
向资源服务器发起 U_QRY 搜索 + 从返回的服务器型 peer（`<speer>` 标志）拉数据。

## 7. 关键代码地址索引（KwMV.dll）

| 地址 | 内容 |
|------|------|
| 0x1001dd90 | SendSYN：构造 SYN 包（packet+0xD=0x01, seq=计数器++, win） |
| 0x10016960 | 包发送入队（htonl(seq) 回写 + WSAEventSelect 触发） |
| 0x1001cb30 | OnPacket 分发（按 packet+0xD flags 查跳转表 0x1001cc24） |
| 0x1001b290 | recvSYNACK（读 ISN/ACK/WIN/ruid） |
| 0x1001b6d0 | recvSYN |
| 0x1001baa0 | recvPSH |
| 0x1001c250 | recvACK |
| 0x1001bee0 | case3 处理（疑 FIN） |
| 0x1001e880 | 收包总入口校验（raw[0]=1/3, raw[1]=0xFF） |
| 0x1002aec9 | U_QRY 请求 snprintf 组包 |
| 0x10012529 | UDP 发送循环（strlen + send） |
| 0x10021cf0 | CSFSocket 底层发送（sendto 封装） |

WS2_32 IAT（序号导入）：recvfrom=0x10053424(ord16)、sendto=0x1005342c(ord19)、
htonl=0x10053414(ord8)、ntohl=0x1005340c(ord14)、socket=0x100533ec(ord22)、
connect=0x10053408(ord4)、bind=0x10053400(ord2)、setsockopt=0x100533f0(ord20)。

## 8. 网络环境实测（2026-08-24，沙箱内）

- `deliver.kuwo.cn` 解析正常（如 39.156.123.34，多次解析有轮换）。
- **沙箱 UDP 出站受限**：DNS(114.114.114.114:53) 均超时 → 此前 UDP 无响应的测试结果不可信。
- **TCP 测试**：175.102.178.96:25607 与 39.156.123.34:25607 均 OPEN。
  → tracker 主机存活且端口开放；下一步可尝试 TCP 方式发送 U_QRY 文本验证协议。

## 9. 下一步计划

1. 用 TCP 连接 `deliver.kuwo.cn:25607`（或日志中的 175.102.178.96）发送 U_QRY 明文请求，验证响应格式。
2. 若 TCP 不通，在具备 UDP 出站的环境重测（当前沙箱 UDP 被禁，无法定论）。
3. 继续还原 CSFSocket 握手线上格式（SYN 报文原始字节序），重点看 0x10021cf0 发送封装与 CPacket 序列化。
4. 还原 PEERS 响应条目 `(%u,%s,%hu,%d,%d,%d,%u)` 各字段含义。
5. 重写 Go 端 `module/download.go`：
   - getSongMeta / refreshSig 保留；
   - P2PDownloader 改为「U_QRY 明文查询 + 服务器型 peer 下载」；
   - 评估恢复 CDN 回退兜底（历史上真实客户端也是 serpack 为主）。

## 10. 待解问题

- [ ] str1/str2（参数6/7）运行时值未确认（全局变量 0x1006b514/0x1006b52c 初始化处未追）。
- [ ] U_QRY 是否需要先发注册包（`, Register` 日志线索 @0x1004d43f 属 KwService 上报，存疑）。
- [ ] PEERS 条目 7 元素各字段含义。
- [ ] CSFSocket SYN 报文的精确字节布局（内存布局已知，线上序列化格式待确认）。
- [ ] HPVQ/JRVQ/HSVW/DSVW/ATPR 命令的用途与报文格式。

---

# 附：酷我 PC 客户端首页/UI 结构分析

> 素材：`Bin/Skin/base/KwMusic.xml`（主窗口 DuiLib 布局，1384 行）、
> `Bin/html/webdata/netsong/`（CEF 内嵌网页）、`Module.xml`（模块加载表）。

## 1. 整体架构

DuiLib 原生框架 + CEF 内嵌网页混合：
- 主窗口 `KwMusic.xml` 定义外壳（左侧播放列表 + 顶部工具栏 + 右侧内容区）。
- 内容区（网络曲库 NetSong / 搜索 TabSearch / 下载 DownloadChannel）为内嵌网页，
  本地 HTML 模板在 `html/webdata/netsong/`，数据由 JS 从服务端拉取。
- 最小窗口 985x570。

## 2. 主窗口布局（KwMusic.xml）

```
root (VerticalLayout)
├─ UserOpreationLayer
│  ├─ LyricMVLogoLayout   # 词/ MV Logo 悬浮层（默认隐藏）
│  └─ bodyContainer
│     ├─ ClassListSepline (宽170, 最大445)  ← 左侧栏
│     │  └─ ListAera（播放列表区）
│     │     ├─ ListHead: 用户登录区（头像/点此登录/VIP标/酷豆）
│     │     ├─ ToolBarArea: 列表管理工具条（添加本地歌/删除/查找/播放模式/云同步动画）
│     │     ├─ PlaylistFloatFindPanel: 列表内搜索条
│     │     └─ PlaylistBody: BaseLeftList 播放列表主体 + 创建列表按钮
│     └─ netsongOpAera                      ← 右侧主区
│        ├─ TabHead (55px):
│        │  ├─ back/ref 按钮（后退/刷新）
│        │  ├─ searchpanel: searchedit(128字) + searchbtn 搜索框
│        │  ├─ knowSong 听歌识曲按钮
│        │  └─ fixedHeadBtns: fold收起/skin换肤/menu菜单/mini迷你模式/min/max/close
│        └─ WindowBodyLeft
│           └─ TabMainBody:
│              ├─ TabSearch       # 搜索结果页（functionwnd 容器）
│              ├─ NetSong         # 网络曲库首页（bkBody + WebLoading 加载动画"稍等片刻，好音乐马上就来..."）
│              └─ DownloadChannel # 下载音乐页（tab: 已下载 | 下载中；播放全部/全部删除）
```

另有折叠模式 FlodHead（迷你横条：专辑图+歌名+喜欢/下载/MV+时间）。

## 3. 首页导航树（html/webdata/netsong/nav.txt）

```
catalog-quku 曲库
  ch:2     songlib    推荐          -> quku.html           ★ 默认首页
  ch:10000 radio      电台          -> channel_radio.html
  ch:10004 bang       排行          -> channel_bang.html
  ch:10007 hifi_music HiFi发烧音乐   -> channel_cdpack.html
catalog-more 更多
  ch:10003 artist     歌手          -> channel_artist.html
  ch:10002 classify   歌单分类      -> channel_classify.html
  ch:10001 MV         视频          -> channel_mv.html?source=43&sourceid=34
  ch:10006 vipzone    付费专区      -> http://vip1.kuwo.cn/vip/added/vipzone_pc/index.html
```

## 4. 首页内容板块（quku.html「曲库首页」）

| 板块 class | 标题 | 说明 |
|-----------|------|------|
| bannerBox | 轮播图 | 焦点图轮播(prev/next/直接播放) + 右侧 VIP 卡片 |
|  └ vip | 会员卡 | 用户名/等级/音乐包、请登录(callClient UserLogin)、累计播歌、"立即续费"(取消广告位 CANCEL_AD?position=2) |
| recommendBox | （推荐列表） | recommendListBox |
| personalizationBox | **推荐歌单** | kw_rcmPl 列表，">"进个性化推荐 |
| indexRadioBox | **推荐电台** | 含本地定位电台名 radio_locationName、BroadcastSlide 轮播 |
| LastMvBox | **最潮视频** | MV 列表 |
| kw_originalBox | **主播电台** | 进 originalpage |
| newAlbumBox | **新碟上架** | 专辑列表 |
| musicPeripheryBox | **音乐周边** | 活动列表 |
| backTop | 返回顶部 | 悬浮按钮 |

JS 引擎：jquery + comm2.js + music.js + index.js；
与客户端交互通过 `callClient('...')` 桥接（UserLogin / CANCEL_AD 等）。

## 5. 其他关键页面（同目录）

- `content_rcm.html` 口味发现/每日歌曲推荐（"根据你的音乐口味生成，每天6:00更新"，播放全部/添加/下载工具条）
- `content_bang.html` 排行榜内容、`content_gedan.html` 歌单详情、`content_artist.html` 歌手页、
  `content_album.html` 专辑页、`content_mv.html` 视频、`content_topic.html` 主题、`content_hotcolumn.html` 热门专栏
- `channel_charge.html` 付费频道、`channel_mnx.html` 明星专区、`scene_radio.html` 场景电台、
  `originalpage.html` 主播电台、`dhj.html` 恭喜页（红包/活动）
- 下载相关：`download_single/multi.html`、`cddownload.html`（CD 抓轨）、`UpqualitySelect.html` 音质选择
- 错误兜底：`loaderror.html`、`kudouNoNetTips.html`、`searchnoresult.html`、`error.html`
- `listeningtest.html` 听力测试（音质对比）、`high_sec.html` 高音质试听

---

# 附：首页「推荐歌单」板块深度分析（2026-08-24 实测可用）

## 1. 数据源 API（index.js:749 getRcmPlaylistData）

```
GET http://rcm.kuwo.cn/rec.s?cmd=rcm_keyword_playlist&uid={uid}&devid={kid}&platform=pc&t={Math.random()}
备用IP: http://60.28.195.115/rec.s?...
```
- uid=用户ID，devid=kid 设备ID（act.log 中 kid:123434546 / K:19976128 可用）。
- **实测(2026-08-24)**：需携带任意正常 User-Agent（裸请求被 openresty 302），
  带 UA 后返回 200 + JSON，服务至今在线。
- 本地缓存 key：`rcmpldata`；响应与缓存相同则不重渲染。

## 2. 响应 JSON 结构（实测样本）

```json
{
  "keyword": "",                       // 个性化搜索词（当前代码已注释停用）
  "playlist": [
    {
      "sourceid": "2970788184",        // ★ 歌单ID（即 playlist_id）
      "playlist_id": "2970788184",
      "name":  "鞠婧祎|别人回头是岸，鞠回头是我",
      "disname": "(同 name，展示用)",
      "pic": "http://img1.kwcdn.kuwo.cn/star/userpl2015/.._500.jpg",
      "playcnt": "53840",              // 播放次数
      "extend": "0",                   // 非零 => 封面挂"无损"角标
      "source": "8", "digest": "8", "r_info": "seq",
      "rcm_type": "gold", "reason": "BACK", "group": "default",
      "traceid": "rcm_keyword_playlist_ur_...",
      "newreason": [{"type":"text","desc":""}]   // 推荐理由（UI 当前未展示）
    }, ...
  ]
}
```

## 3. 渲染规则（index.js createRcmPlaylist/proRcmPlData）

- 最多展示 10 个；`playlist.length <= 4` 时隐藏整个 personalizationBox。
- 卡片：140x140 封面（懒加载，默认图 img/def150.png）+ 歌单名。
- playcnt：>100 才显示角标数字；>100000 格式化为「X万」。
- extend 非零 → 左上角「无损」标。
- 悬浮出现「直接播放」按钮：iPlay(source=8, type=8, sourceid)。
- 单击卡片 → commonClick(Node(source,sourceid,name,id,extend))
  → 打开歌单详情页 content_gedan.html?id={sourceid}。
- 埋点串：csrc = 曲库->首页->个性化推荐->{歌单名}。

## 4. 对 Go API 项目的价值

- 该接口无签名、无登录态要求，可直接封装为 `/playlist/rcm` 模块；
- 返回的 sourceid 可直接喂给本项目现有 song/search 模块或 download 流程；
- 同族接口线索：rec.s 还支持其他 cmd（待挖）；content_gedan.html + js/content_gedan.js
  内含歌单详情数据源（下一步可逆向其 API）。

## 5. Go 模块封装（已实现，2026-08-24 实测通过）

- 文件：`module/playlist.go` → `module.PlaylistRcm`；注册于 `server/modules.go`
  键名 `playlist_rcm`（路由 `/playlist/rcm`）。
- 参数：`uid`(默认 123434546)、`devid`(默认 19976128)、`limit`(默认 10)。
- 行为：带 UA+Referer 请求 rcm.kuwo.cn；规整字段
  `{id, name, pic, playcnt(int), lossless(bool: extend!=0), traceid}`；
  返回 `data.{uid, devid, keyword, count, list}`。
- 验证：go build/vet 通过；本地起服务 GET /playlist/rcm?limit=3
  返回真实歌单（鞠婧祎/怀旧卡带/伤感情歌）。

## 6. 歌单详情页数据源（content_gedan.js，2026-08-24 实测可用）

```
GET http://nplserver.kuwo.cn/pl.svc?op=getlistinfo&pid={歌单ID}&pn={页码从0}&rn={每页}
    &encode=utf-8&keyset=pl2012&identity=kuwo&pcmp4=1
```
- **vipver=1 必带**（客户端 getChargeURL 在收费开关开启时追加）；
  实测缺失 vipver 时部分歌单 musiclist 返回空/少量（rn=100 只回 9 首），
  加 `&vipver=1` 后完整返回。ttime 实测可省略。
- 响应顶层：id/title/pic/info/uname(创建者)/tag/tagid/total/validtotal/pn/rn/
  playnum/sharenum/musiclist[]/abstime/ctime/ispub/type/state。
- musiclist 每项核心字段：
  - id(rid 字符串), name/disname, artist/artistid, album/albumid, albumpic
  - duration(秒,字符串), formats(音质标识串 "DTSX|OGGH|ZPLY|MP3H|...")
  - MINFO/N_MINFO: 各音质明细 `level:p,bitrate:320,format:mp3,size:10.13Mb;...`
    （含 flac/zply=mflac 等无损加密格式与普通 mp3/aac/ogg）
  - pay(收费类型位掩码 0xDCBA: A播放 B下载 C视频播 D视频下载),
    audiobookpayinfo{download,play}, isdownload(0=可下), copyright, hasmv,
    online(0=下架过滤), score100, new

## 7. Go 模块 playlist_info（已实现实测通过）

- 文件 `module/playlist_info.go` → 路由 `/playlist/info?id={歌单ID}&pn=0&rn=100`
- 自动加 vipver=1；字段规整 {rid,name,artist,artistid,album,albumid,albumpic,
  duration,formats,pay,lossless(MINFO含format:flac),isdownload(==0)}
- 实测：pid=3212750835 → 王菲《色诫》等 30 首全部返回，lossless=true。

## 8. 排行榜频道页（channel_bang.js，2026-08-24 实测）

两个接口均在线，项目已有 rank/rank_list 模块对应：

### 8.1 榜单分类树 q.k
```
GET http://qukudata.kuwo.cn/q.k?op=query&cont=tree&node=2&pn=0&rn=20&fmt=json&src=mbox&level=2
```
- 返回 child[] 共 30 个榜单，字段：id/name/disname/info/source/sourceid/pic/
  like/listen/tips/isnew/newcnt/extend/intro/pc_extend/pic5/pic2/child
- 客户端渲染规则：
  - pc_extend 含 NOTSHOWPC2015 → PC 隐藏
  - pc_extend 中 `BDTYPE-{分组名}-{oid}` 决定分组，缺省「特色榜」；
    实测分组：特色榜(20) / s(1) / g 国际榜(6: Billboard/UK/百大DJ/日本公信榜等)
  - sourceid 17(新歌)/16(热歌)/93(飙升) 为特殊项，仅取 intro 展示
  - pc_extend 含 HOT → 热门标记

### 8.2 榜单歌曲内容 ksong.s
```
GET http://kbangserver.kuwo.cn/ksong.s?from=pc&fmt=json&type=bang&data=content&id={榜单ID}
    &pn=0&rn=20&show_copyright_off=1&pcmp4=1&isbang=1&t={ts}
```
- 响应：name/currentVolume("2026|235"→"2026第235期")/second/type/musiclist[]
- musiclist 前 10 左列、其余右列；type=="music2" 为打榜模式（亚洲新歌榜，
  客户端代码已整体注释停用）
- 实测 id=93 酷我飙升榜返回 20 首，currentVolume=2026|235

### 8.3 Go rank_list 增强（已完成）
- module/rank.go RankList 重写：过滤 NOTSHOWPC2015、解析 BDTYPE 分组、
  HOT/special(17/16/93) 标记；输出 data.{name,count,list,groups:[{group,list}]}
- 实测 /rank/list：count=30，groups=[特色榜20, s1, g6]

### 8.4 channel_bang.html 页面骨架要点

- 顶栏 3 个硬编码 tab（默认激活热歌榜）：
  酷我热歌榜 c-id=16(c-sourceid=26) / 酷我新歌榜 c-id=17(25) / 酷我飙升榜 c-id=93(80358)
  - c-id = ksong.s 的榜单 id；c-sourceid = 「完整榜单」跳转 content_bang.html 用
- 已注释停用：酷音乐亚洲排行榜(c-id=132) tab、打榜倒计时 countdown
- 弹窗 js-db（打榜）：完整播放 +1 分/次(每日上限10)、分享 +10 分/次(每日10)、
  付费投票 +100 分/次(无上限)；入口 http://vip1.kuwo.cn/fans/dopay/
- 弹窗 js-modal-gz（亚洲榜规则）：酷狗+酷我双平台数据综合；计分周期每周一
  00:00 起一周；每周一中午 12 点公布上期成绩；排名每 10 分钟刷新
- 内容区容器：fixed_list_asia(打榜) / fixed_list(普通榜前20两列) /
  bang_list(B_common 分类分组 + B_special 特色)

### 8.5 榜单页每首歌的可操作元素（createfixedMusicList @ create_structure.js:2347）

每行 = 悬浮按钮 + 排名趋势 + 文字链接 + MV/打榜标：

1. 悬浮在行上出现的按钮（div.icon）：
   - 「添加歌曲」m_add → 加入播放列表（music.js:1177）
   - 「下载歌曲」m_down → singleMusicOption("Down",...) 走客户端下载流程
     (music.js:1286)；isdownload==1 时加 notAllow 置灰，
     提示「应版权方要求暂不能下载」；copyright 行则引导在线试听
   - getMoney(obj,"down") 付费角标：按 pay 位掩码(0xDCBA)显示下载收费类型
2. 排名趋势（infoLeft）：
   - 序号前 3 名橙色(#fe5600)
   - trend 字段：u=上升N位 / d=下降N位 / 其他持平；isnew=1 →「新上榜」；
     rank_change 数字可带 %（升降百分比）
3. 链接：歌名 w_name 点击播放；歌手名跳歌手页 Node(4,artistid,...)
4. MV 标：formats 含 "MP4" 且 mp4sig1/mp4sig2 非空才亮（checkMvIcon）；
   ispoint=='1' 的打榜歌改显打榜图标 m_score tm

## 9. P2P 签名 sig1/sig2 来源已确认（2026-08-24，用户提示 + 实测）

**sig1/sig2 在拿到歌曲元数据时就已返回**，载体是各接口的 param/params 字段：

- ksong.s（榜单）musiclist[].param
- pl.svc getlistinfo（歌单）musiclist[].params
- （搜索 r.s KV 文本中对应 NSIG1=/NSIG2= 行，前端 comm_search.js saveMusicInfo 同样消费）

字段顺序（分号分隔，与前端 saveMusicInfo 一致）：
```
[0]name [1]artist [2]album
[3]NSIG1  [4]NSIG2      ← ★ 即 KwMV.dll U_QRY 的 sig:(%lu,%lu) / task+0x124/+0x128
[5]MUSICRID(MUSIC_xxx)
[6]MP3NSIG1 [7]MP3NSIG2 [8]MP3RID
[9..10]保留 [11]MVRID(MV_xxx) [12]HASECHO
```

实测样本：
- 热歌榜《山风山风等等我》rid=MUSIC_624683929, sig=(2608621834,2438534005)
- 歌单《色诫》rid=MUSIC_169753, sig=(3264614461,1651339078)

与 act.log DOWN_MUSIC 记录 S1:1455199153/S2:274332222 格式吻合 →
P2P 任务创建时把 (rid,sig1,sig2) 写入 task 结构即可发起 U_QRY。

### Go 改动
- 新增 module/param_chain.go：parseParamChain/mergeParam 公共解析
- rank.go Rank、playlist_info.go PlaylistInfo 每首歌并入
  {nsig1,nsig2,musicrid,mp3nsig1,mp3nsig2,mp3rid}
- 实测 /rank?id=16 与 /playlist/info 均返回真实签名对

### 附注：antiserver 已废弃
antiserver.kuwo.cn/anti.s?type=convert_url&rid=&response=url 仍返回 200+URL，
但任何 rid 都指向同一个「版本过低」提示音频（用户实测确认），CDN 直链通道不可用。
→ P2P（U_QRY + CSFSocket 从 serpeer/CDN 型 peer 取流）是唯一有效下载路径。

## 10. 从前端按钮到 P2P 引擎的完整调用链（2026-08-24 逐步确认）

### 10.1 前端桥接层
- comm2.js:2 `callClient(call)` = `window.external.callkwmusic(call[,cb])`
  （IE WebBrowser 控件 IDispatch 桥；CEF 场景走 KwWebKit.exe 转发，
  该 exe 内含唯一 "callkwmusic" 字符串）
- 命令格式为伪 URL：`Scheme?k=v&k=v`

### 10.2 下载命令两级流转
1. 列表页 m_down (music.js:1286) → `singleMusicOption("Down", s1)` →
   `Down?mv=0&n=1&s1={encodeURIComponent(tab分隔元数据串)}`
   → 宿主弹出下载设置窗（UIDownload.dll 加载 download_single.html，
   含音质选择/付费策略 single_payinfo.js）
2. 设置窗确认按钮 → `DDownload?isExport=0&bEncrypt={0|1}&pos={n}&n=1&s1={串}&isCharge={0|1}`
   （download_single.html:457/471/479/481；MV 用 DDownload，普通走 type 分支）
3. s1 串字段序（saveMusicInfo）：name\tartist\talbum\tNSIG1\tNSIG2\tMUSICRID\t
   MP3NSIG1\tMP3NSIG2\tMP3RID\t0\t0\tMKVRID\tHASECHO\tpsrc\tFORMATS\t
   multiVerNum\tpointNum\tpayNum\tartistID\talbumID\tmp4sig1\tmp4sig2\tisdownload

### 10.3 进程与模块拓扑
- UIDownload.dll (708KB)：下载设置 UI + "DDownload/DToPhone/DDownFree/DPay/
  DGetMusicListInfo/DHQConfig" 命令表；经 KwMusicCore.dll!AfxGetMessageManager
  把任务消息送回主程序（KwMusicCore 仅导出 AfxGetDataDllManager/AfxGetDataManager/
  AfxGetMessageManager）
- **KwService.exe** ("CoreService"/类名 kwcoreservice2013, kwservice)：
  唯一导入 KwMV.dll 的模块，含 CP2PStub/P2PObserver 类、"StartP2P failed"、
  服务互斥 kwmu/KWMUSIC —— P2P 引擎运行在独立服务进程
- ccenter.dll = RS_InitializeCallCenter 遥测/上报中心，与下载无关（排除）

### 10.4 KwMV.dll 导出函数语义（反汇编确认）
- `StartP2P_V1(0x1000dd50)`：`CreateThread(0,0,threadfn@0x1000de00, param,
  0, &g_tid@0x10069c10)`，句柄存 g_hThread@0x10069c1c；已有线程则返回 0。
  签名≈`BOOL StartP2P_V1(LPVOID param)`
- `StartP2P(0x1000dd90)`：同款线程 + CreateEvent(g_event@0x10069c18) +
  MsgWaitForMultipleObjects 同步等待（阻塞版）
- `StopP2P(0x1000dcd0)`：CloseHandle+WaitForSingleObject(500ms)+TerminateThread
  清理序列
- 引擎线程体 0x1000de00：`ecx=[ebp+8](param); call 0x1000e060(this初始化);
  call 0x1000e000(主循环); ret 4`
- 另有定时器回调 0x1000df40（SetEvent@0x100535ac 注册于 0x10069bf0 状态块
  {0x110,4,1,...}，处理 DLL_PROCESS_DETACH/线程 detach 时置状态）

### 10.5 U_QRY 发送函数完整还原（0x10012200 起，connected-UDP）
```
socket(IAT:0x10053428)(AF_INET=2, type=?, proto=?)     ; 0x100122a9
setsockopt x2: (SOL_SOCKET=-1/0xffff, opt=0x1005/0x1006, 4字节值)
  0x1005=SO_RCVTIMEO? 实为 0x1005=SO_RCVTIMEO,0x1006=SO_SNDTIMEO, 值=0x2710(10s)
inet_addr(host字符串)                                   ; 0x1001230c
失败→日志"inet_addr err"; 成功→esi=hostent
sockaddr_in{family=2, port=htons([esi+0xc]即h_addr? 实际htons(IAT:0x1005341c)),
            addr=第一个h_addr_list}                     ; 0x100123e0-0x10012426
connect(sock,&sa,16)                                    ; 0x10012426 IAT:0x10053408
sprintf(buf[512], fmt_U_QRY@0x10053f40, ...)            ; 0x1001251e IAT:0x10053318
send(sock, buf, strlen, 0)                              ; 0x1001254c IAT:0x1005342c
loop:
  recv(sock, buf[0x19000=102400], 0x19000, 0)           ; 0x100125f5 IAT:0x10053424
  ret>0 → 累计并解析; ret==0 → 结束;
  ret<0 && WSAGetLastError()==0x2714(10060 WSAETIMEDOUT) → 重试分支0x100126fe
  其他错误 → 结束
```
注意：**这是 connected-TCP/UDP 上的文本协议交互**——connect 用于 UDP 绑定
对端（connected UDP），recv 循环持续收 tracker 响应直至超时退出。
IAT ord 对照（WS2_32 按序号导入）：socket=ord22? 待精确核对，
但行为上 0x10053408=connect、0x1005342c=send、0x10053424=recv、
0x10053418=WSAGetLastError、0x1005341c=htons 已由调用形态证实。

### 10.6 下一步待解
- 0x1000e060/0x1000e000：任务结构初始化与主循环（找 sig1/sig2 写入 task+0x124 处）
- KwMusicDLL.dll 中 DDownload 消息处理器 → StartP2P_V1 的参数构造
- PEERS 响应解析函数（FormatVer/sig/searchtm/PEERS 字符串引用点）

### 10.7 【2026-08-24 重大修正】0x10012200 是 HTTP URL 下载通道，非 U_QRY
对 0x10053f40 提取实际内容后确认：那是 `GET / HTTP/1.0\r\nHost: %s...Chrome/4.0 UA`
（CDownloadTask 的 HTTP 直链下载函数，含 "DNS解析失败 %s"/"连接服务器 %s 失败" 日志，
窗口类名 "2013KwMusicServer"，线程/组件前缀 "P2PClient"）。10.5 节的 socket 流程
描述的是 **HTTP 文件传输通道**。真正的 U_QRY 构造在别处（见 10.8）。

### 10.8 真·U_QRY 构造与发送（0x1002abf0 大函数，sprintf@0x1002aec9）
格式串@0x1005bd28：
```
<%s><%s>|<%u,%u>|<%u><%s><%s>|<%s>|<rid>|<uip:%s>|<new>|<nat:%u>|<flags:%u><speer>|<ipdeny:no>%s|<loginid:%s>\r\n
```
snprintf(buf[ebp-0x7a8], 259, fmt, 参数依次为)：
- a1="001"(0x10054884) 协议版本
- a2="U_QRY"(0x1005bd20) 命令名
- a3=sig1=[task+0x124]  ★
- a4=sig2=[task+0x128]  ★
- a5=uid=[g_login@0x10069c2c+0x7C]
- a6/a7=全局字符串 0x1006b514 / 0x1006b52c（NetID/Setting 配置读取而来）
- a8=ver 串；a9=nat=WORD[g+0x86]
- a10=本机IP "%d.%d.%d.%d"(@0x100535cc)
- a11=ipdeny 串；a12=loginid
flags 字段=task+0x370：g_tracker_flags|0x20000(若 g_1006b608!=0)；[task+0x224]==0→|0x40000；
==3→|0x100000。
CDN 扩展：config "CdnSpeedPolicy"=="Enable" 时请求尾部拼 "|<cdnreq>"(0x1005bd04)。
HTTP 传输封装：配置键 **ResSeaSvr / ResSeaPort** + HTTP GET 路径 **/yl_res_manage.search**
(0x1005b764)——即 tracker 查询可走 `GET http://ResSeaSvr:ResSeaPort/yl_res_manage.search?<U_QRY文本>`
（这解释了 TCP 25607 端口开放！）。另有直连 UDP 分支待精确定位。

### 10.9 宿主→引擎命令通道：隐藏窗口 WM_COPYDATA（WndProc@0x1000f010）
WndProc 判定 msg==0x4A(WM_COPYDATA) 后按 **wParam-1** 索引跳转表@0x1000f4b0（13 项）：
```
wParam=1 -> 0x10015870   (停止类)
wParam=2 -> 0x100157c0   (★添加下载任务: malloc(0x4C)+memcpy(0x13 dwords) → call 0x100264e0)
wParam=5 -> 0x1000f0fd   (memset 0x200 的查询/配置类)
wParam=6 -> 0x1000f289
wParam=b -> 0x10015830
wParam=c -> 0x1000f42a ; wParam=d -> 0x1000f463
wParam=3/4/7..a 部分为 DefWindowProc 默认分支
```
窗口类名 "KwMV"（CreateWindow 失败日志@0x10054840 附近），宿主 KwService.exe 通过
FindWindow("KwMV")+SendMessage(WM_COPYDATA) 下发任务。

### 10.10 WM_COPYDATA(wParam=2) 下载请求结构布局（≥0x60 字节）
由大函数 0x10026810 内 sprintf 日志(fmt@0x10059fe0)反推：
`NewDownloadTask, Fid: %u %u, NumPacket:%u, WinName:%s, FileName:%s, FileType:%d, DownMode:%d TimeStamp:%u`
```
struct KwMV_DLREQ {
  u32  fid1;          // +0x00
  u32  fid2;          // +0x04
  u32  numPackets;    // +0x08
  char winName[0x44]; // +0x0C..0x4F 回调窗口类名
  u32  sig1;          // +0x50  ★ tracker sig1（旧日志标 FileType，字段已复用）
  u32  sig2;          // +0x54  ★ tracker sig2（同上标 DownMode）
  u32  timestamp;     // +0x58
  char fileName[];    // +0x60.. cbData 结束
};
```

### 10.11 任务创建与搜索状态机（sig 写入 task+0x124 的路径闭环）
1. 大函数 0x10026810（ebx=[ebp+8]=原始 COPYDATA 缓冲，全程不变）内：
   - 从缓冲取字段构造两个 std::string（rid 相关）
   - `call 0x100083a0(&desc_out@[esp+0x1c8], str_a, str_b, byte_g_1006b6c7)` 构造"搜索描述"
   - 填 desc+? ← [ebx+0x50](sig1)、desc+? ← [ebx+0x54](sig2)、desc+? ← [ebx+0x58]、bool ← ([ebx+0x5c]!=0)
   - `push &desc; call 0x10025700` 创建任务：
     - 遍历链表找 [node+0x1c]==0 空槽 → `malloc(0x408)` 任务体 + ctor 0x100348e0
     - 引用计数 ++([ebx+4])
     - `mov [task+0x1c],1; lea ecx,[task+0x124]; push &desc; call 0x10009020`
       —— **0x10009020 = 描述结构深拷贝进 task+0x124 起的子对象**（rep movsd 头部
       0x20 dwords + std::string 深拷贝）。故 sig1/sig2 = 该子对象首两个 dword，
       U_QRY 直接 `push DWORD PTR [ebx+0x124]/[ebx+0x128]` 使用。
2. 搜索状态机 0x10031ce0(param=任务指针数组)：
   - `[esi+0x1c]!=0 → 置 8`；`ecx=esi; call 0x1002abf0` 发起 U_QRY
   - 返回后按 [esi+0x1c] 状态 ∈{0,4,8,c,9,b,d,f,0x10} → 终止分支 0x1003206f
   - 否则 `call 0x10033a60`、`call 0x1002a250`（响应处理/PEERS 解析方向）

### 10.12 下一步待解（更新）
- 宿主侧：KwService.exe 中 FindWindow("KwMV")/WM_COPYDATA 发送点及 DLREQ 各字段赋值来源
- rid 字符串如何进入 desc（0x100083a0 参数来源，esi 字符串的构造）
- 0x100264e0 与 0x10026810 的关系（wParam=2 thunk 路径 vs 大函数路径）
- PEERS 响应解析（0x1002a250 方向）→ CSFSocket 连接 peer

### 10.13 【突破】内置服务器配置全出土（KwMV.dll .rdata@0x58560 起）
```xml
<Version>1.2.3.0</Version>
<IndexSvr>search.kuwo.cn</IndexSvr>   <IndexPort>80</IndexPort>
<Tracker>deliver.kuwo.cn</Tracker>    <TrackerPort>25607</TrackerPort>
<HelpSvr1>uh1.kuwo.cn</HelpSvr1>      <HelpSvr1Port>6718</HelpSvr1Port>
<HelpSvr2>uh2.kuwo.cn</HelpSvr2>      <HelpSvr2Port>6721</HelpSvr2Port>
<ResUpSvr>deliver.kuwo.cn</ResUpSvr>  <ResUpPort>80</ResUpPort>
<ResSeaSvr>deliver.kuwo.cn</ResSeaSvr><ResSeaPort>80</ResSeaPort>
<RecommendSvr>tuijian.kuwo.cn</RecommendSvr> <RecommendPort>80</RecommendPort>
<MeasurePath>/stat/zidane.rm</MeasurePath>
```
心跳服务器串(HeartbeatServer/BoardcastHeartbeat)：`211.100.49.14:25607,60.29.226.173:25607,60.28.205,36:25607`(末位疑笔误.36)。
TCP 代理(tcpproxy)：`103.235.253.250` + 域名 `resua.kuwo.cn`（NAT 穿透失败中继下载）。
连通性实测：deliver.kuwo.cn:25607 TCP OPEN；DNS 返回 IPv6 (2409:8c00::/32 移动云)。

### 10.14 U_QRY over HTTP 实测（deliver.kuwo.cn:80）
请求：`GET /yl_res_manage.search?<001><U_QRY>|<sig1,sig2>|... HTTP/1.0 Host: deliver.kuwo.cn`
响应：HTTP 200 nginx/1.20.1，body 固定 24 字节 base64 `YlIOYhFJKnB5LHA6MXYoWjE=`
→ 解码 17 字节 `62 52 0e 62 11 49 2a 70 79 2c 70 3a 31 76 28 5a 31`。
改变 sig/uid/uip/flags 参数响应不变 → 服务端对该端点的固定兜底应答（通道疑似已下线，
或需特定会话 key 解密）。单字节 XOR/ADD 无法还原明文。
标准 base64 表@VA 0x1005e3d0(file 0x5cbd0)；编码函数@0x10044cf0（解码应在附近）。

### 10.15 PEERS 上报构造点（act.log 来源，非响应解析）0x1002fb00 区域
- `sprintf(buf,"FormatVer:1.1|sig:(%lu,%lu)|searchtm:%u|PEERS:", [task+0x124],[task+0x128],[task+0x5c])`
- 遍历 peer 链表（[edi+4] 头）：peer 对象 [ebx+4]=IP string、[ebx+0x42..0x44]=bool 标志、
  [ebx+0x45]=port 字节、条目格式 `(%u,%s,%hu,%d,%d,%d,%u)`@0x1005b29c，标签 PEER_INFO
- 日志行格式：`kid:%u|sip:%s|sig1:%u|sig2:%u|seares:%s|seatm:%u|peernum:%u|usedp:%u|nconn:%u|tooslo…`
  与 `kid:%u|sig1:%u|sig2:%u|t_session:%d|%s:%s|searcherr:%u|ptn:%u|mode:%d`；含 SUCC/FAILED 标记

### 10.16 宿主回调确认（KwService.exe）
- IAT：StartP2P_V1=0x40b110(RVA b110)、StopP2P=b108、StopUpload=b10c
- 初始化序列@0x4059f1-0x405b16：CreateWindowExA(0xcf0000, cls="2013KwMusicServer"@0x40f570,
  name@0x40f5d8) → 读配置/注册表(0x40b000 系列 thunk) → `push $0x405dd0; call *0x40b110`
  即 **StartP2P_V1(回调@0x405dd0)**——param 为宿主事件回调函数指针（引擎线程体将其作为
  this 传入初始化 0x1000e060，用于向宿主推送进度/结果事件）
- KwService.exe USER32 导入无 FindWindow/SendMessage（仅 PostMessageA）→ 主进程→引擎的
  WM_COPYDATA 发送方在其他模块（KwMusicCore/KwModDownload 方向），窗口类名 "KwMV"
  字符串仅存在于 KwMV.dll 内部（跨进程发现机制待查：可能共享内存/注册表/广播）

### 10.17 下一步待解（再更新）
- tracker 兜底响应 17B 密文的解密逻辑（或判定通道死亡）；若死，PEERS 获取需走 CSFSocket
  UDP 直连 Tracker(deliver.kuwo.cn:25607)——沙箱 UDP 出站被禁，只能静态还原协议
- 0x100264e0（wParam=2 thunk 下游）与大函数 0x10026810 的分工
- rid→desc 的字符串流（0x100083a0 参数来源）
- CSFSocket SYN 序列化 + peer 数据传输协议（resua.kuwo.cn/103.235.253.250 tcpproxy 备选）

### 10.18 【重要】LAN 广播资源查询包（cmd 0x1401，27 字节）@0x1002a410
日志"开始搜索候选资源......"确认是搜索入口之一。完整构造：
```
sock = socket(AF_INET=2, SOCK_DGRAM=2, IPPROTO_UDP=0x11)      ; IAT:0x10053410=socket
sendto 目标 sockaddr{AF_INET, htons(cfgPort), inet_addr("255.255.255.255")}
cfgPort 来自 config "ServerPort"(键@0x10054544 区域，同区有 "TrackerPort"/"Tracker"/"UDPServer")
packet = malloc(0x1b):                       ; 27 字节定长
  +0x00 u16 = 0x1401                         ; 命令字（LE 存储即字节 01 14）
  +0x02 u16 = 0x0012                         ; payload 长度 18
  +0x04 u8  = (u8)(++g_login->[0xC8])        ; 包序号回绕
  +0x05 u32 = g_login->[0x7C]                ; kid/uid
  +0x09 u32 = arg1 = task->sig1              ; ★
  +0x0D u32 = arg2 = task->sig2              ; ★
  +0x11 u32 = g_login->[0x7C]                ; uid 重复
  +0x15 u32 = g_login->[0x80]                ; 本机 IP
  +0x19 u16 = g_login->[0x84]                ; 本机端口
call 0x1001e690(packet, g_login, &to)         ; 发送（内部或含加密）
free(packet)
```
用途：局域网节点直查（"本地找到该资源，反馈目的地址 %s, 用户 %u[%s]" 日志）。
大函数 0x10026810 中 `call 0x10008d10` 为真才发（判定是否允许广播）。

### 10.19 CSF 可靠 UDP 层初始化 @0x1001e520
```
if ([this+0]==-1):
  s = socket(2 /*AF_INET*/, 2 /*SOCK_DGRAM*/, 17 /*IPPROTO_UDP*/)  ; IAT:0x10053428
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR=4,        1,      4)      ; IAT:0x10053420
  setsockopt(s, SOL_SOCKET, SO_RCVBUF=0x1002,      0x40000,4)      ; 256KB
  setsockopt(s, SOL_SOCKET, SO_SNDBUF=0x1001,      0x40000,4)      ; 256KB
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO=0x1006,    1,      4)      ; 1ms 轮询模式
bind(this, {AF_INET, htons(port), INADDR_ANY}, 16)                 ; ★IAT:0x10053400=bind(非connect!)
hwnd = (若[this+4]==0) 取全局句柄(IAT:0x100533d8)
WSAAsyncSelect 类调用 (IAT:0x100533d4)(s, hwnd, 1 /*FD_READ*/)     ; 异步读事件
失败路径日志串: "Connect failed"/"listen failed"@0x100593dc..0x1005940c
对象布局: [obj+0]=fd, [obj+4]=hwnd, [obj+0x38]=peerIP, [obj+0x3c]=peerPort,
          [obj+0x88]=sockaddr, [obj+0x98]/[obj+0xc8]/[obj+0xe0]=锁与缓冲
```
注意：早前记录"IAT:0x10053400=?"现确认为 bind；0x10053410 为第二处 socket 调用所用槽位
（0x1002a544 处 socket(2,2,0) 无 proto 变体）。

### 10.20 CSF TCP 收发函数（peer/tracker 数据面）
- 连接 0x10021ad0：`connect(obj->[0x84]=fd, obj->[0x88], 16)`，超时字段 [obj+0x158]=5000ms
- 发送 0x10021ce0：循环 send 直至发完；双锁保护 [obj+0xc8]/[obj+0x98]
- accept 服务端 0x10021a00 区：accept→malloc(0xf8)+ctor 0x10001dd0→存 fd/IP/port→call 0x10021370
- 关闭 0x10021a70：closesocket+清缓冲
- HTTP HEAD 测速器（0x10012c00 区）：`HEAD %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\nAccept: */*\r\n\r\n`
  （fmt@0x10053e8c），连接超时/读超时均 5000ms，用于 URL 测速排序

### 10.21 用户实测确认（2026-08-24）
用户安装原版客户端实测**播放与下载均正常** ⇒ 全链路存活。推论：
- deliver.kuwo.cn:80 `/yl_res_manage.search` 返回的固定 17B base64 并非死通道兜底，
  更可能是加密的正常应答（空结果集）或缺前置条件（如心跳注册/精确参数）时的应答；
- act.log 成功案例 total=602 全部来自 serpack（server 型 peer）⇒ server 型 peer 通道是主力，
  还原优先级：U_QRY 获取 PEERS > CSFSocket 连 server 型 peer 拉数据。

### 10.22 【核心】SendSYN @0x1001dd90 与包发送层 0x10016960
SendSYN：
```
仅当 conn->[0x138](state) ∉ {0,3,4,5,6,7,8} 才发送; state==3 时先 (IAT:0x10053084)([esi+0x20],30000)
pkt = 取缓冲(0x10015e30); seq = ++g_conn[esi+0x108]->[0xB0]
pkt[+0x0D] u8 = 0x01            ; flags=SYN
pkt[+0x04] u32 = seq
pkt[+0x0E] u16 = win = rcvbuf[+0x20]-rcvbuf[+0x44]   ; 窗口=容量-占用
pkt[+0x410] = 0                 ; payload len=0
call 0x10016960(conn=this, pkt) ; 发送
state 转移: new_state = (old!=3)? 5 : 9?  实际 [esi+0x138] = (state!=3)*4 + 5
```
发送层 0x10016960(this=g_conn, pkt, bool resend)：
```
htonl(pkt[+4]=seq) 存回 (IAT:0x10053414=htonl)
pkt[+0x414]=time(0); resend 时 pkt[+0x418](重传计数)++
g_sock@0x10069c34 全局 UDP socket (!=-1 才发)
ioctlsocket 非阻塞设置(IAT:0x100533dc) + setsockopt SO_RCVBUF 循环放大
sendto(g_sock, pkt, pkt[+0x410]+0xC, 0, sockaddr拷贝自conn->[0xC4..0xD4], 16)  ; IAT:0x100533f0
```
⇒ 线上包头至少含: +0x00(conv/命令?), +0x04 seq(u32 网络序), +0x08 ack?, +0x0D flags,
+0x0E win(u16)。len=payload+0xC 说明基础头 12 字节（flags/win 可能算进前 12 字节的复用区，
待与真实抓包比对）。

### 10.23 【核心】CSF 收包分发器 @0x1001cb30（flags 状态机）
```
al = pkt[+0x0D] (flags)
flags & 0x08            -> state=9  (RST)
elif flags & 0x02       -> state = (flags&0x10) ? 2 : 1   (ACK | ACK|PSH)
elif flags & 0x01       -> state = ((flags&0x10)|0x40)>>4 = 5 或 4 (纯SYN=5, SYN|PSH=4)
else                    -> state = (flags&0x10) ? 3 : -1→3 (PSH)
state-1 索引跳转表@0x1001cc24:
  state=1 纯ACK      -> 0x1001b6d0
  state=2 ACK|PSH    -> 0x1001b290
  state=3 纯PSH      -> 0x1001c250
  state=4 SYN|PSH    -> 0x1001bee0
  state=5 纯SYN      -> 0x1001bce0   (服务端接受连接/SYNACK 方向)
  state=6..8         -> 0x10015d80 (丢弃)
  state=9 RST        -> 0x1001baa0
```
**flags 位定义定案：0x01=SYN, 0x02=ACK, 0x08=RST, 0x10=PSH**（与旧记录一致并补全）。
分发前 `g_conn->[0x10C]->[0x34] = pkt[+0x414]`（对端时间戳记录）。

### 10.24 探测实验结果（2026-08-24）
- deliver.kuwo.cn:25607 TCP：16B/14B 头 SYN 变体、裸 U_QRY 文本均无响应
  ⇒ 该端口当前仅 UDP CSF 服务（沙箱 UDP 出站被禁无法实测），或需先 bind 本机端口会话
- 下一步实现路径：Go 版按 10.22/10.23 布局构造 UDP CSF 包直发 deliver.kuwo.cn:25607，
  先 SYN 握手再 PSH 携带 U_QRY 文本；响应走 dispatch 对应处理函数解析 PEERS

### 10.25 下一步待解（第三版）
- g_sock@0x10069c34 的创建点（哪个函数 bind 本地 UDP 端口并注册 WSAAsyncSelect）——
  决定 Go 版本地端口选择策略
- 0x1401 广播查询的应答包格式（cmd 应答侧）与 tracker 的 CSF 会话建立序列
- PSH payload 中 U_QRY 文本的封装（是否直接明文）及 PEERS 响应二进制结构
- server 型 peer 数据传输协议（下载主通道，act.log 显示 serpack=total）

### 10.26 CSF 管理器与本地端口策略
- g_sock@0x10069c34 = malloc(0x2A4=676) + ctor 0x1001fbf0 —— CSF 管理器对象（非裸 fd）
- 启动 0x1001fa00：取 g_login->[0x80](本机IP)/[0x84](本机UDP端口)，
  `call 0x1001e520(g_sock, port)` 绑定；随后 `_beginthreadex` 两个工作线程：
  收包线程 0x1001f3d0 (@g_sock+0x1AC)、0x1001f0d0 (@g_sock+0x1C0)
- 本地 UDP 端口=登录下发值；Go 实现可任选高端口（NAT 场景需 STUN 打洞则另议）
- 日志 "%d.%d.%d.%d:%d"@0x100535d8 打印绑定地址

### 10.27 U_QRY 响应为明文文本（重要结论）
大函数后段 0x1002b59b 遍历会话结果：
```
len = sess->[0x40]; (上限 0x19000)
memcpy(stack_buf, sess->[0x3C], len); stack_buf[len]=0
strlen → 转 std::string            ; ★ 文本处理 ⇒ tracker 应答是明文
task->[0x3FA] = sess->[0x04] (IP)  ; 记录成功服务器
task->[0x3FE] = sess->[0x08] (port)
g_last_tracker@0x1006b544/548 更新
sess->[0x118] → task->[0x400]
```
⇒ 完整链路定案：CSF UDP(SYN→SYNACK→ACK) + PSH(payload=U_QRY 明文文本) →
tracker 回 PSH("FormatVer:1.1|sig:(%u,%u)|searchtm:%u|PEERS:(%u,%s,%hu,%d,%d,%d,%u)...")
⇒ HTTP 80 的 base64 应答属于另一条辅助通道（或加密变体）。

### 10.28 下一步待解（第四版）
- 会话对象 [esi+0x3C]/[0x40] 缓冲的写入者（收包线程如何按 (IP,port) 匹配会话）
- PEERS 条目字段逐一对应 (%u,%s,%hu,%d,%d,%d,%u)：疑为 (kid,ip,port,类型,负载,优先级,flags)
- server 型 peer 拉数据的 PSM/请求块协议（下载主通道）

### 10.29 【核心】CSF 线上包头定案（12 字节）
发送层 0x10016960 中发送指针=pkt+4（`lea edi,[ebx+4]`），RST 构造处 0x1001be4c 揭示完整头：
```
wire+0x00 u32 seq     (htonl，发送时转换)
wire+0x04 u32 ack
wire+0x08 u8  head_len (=0x0C；RST 处 `or al,0xC` 写 struct+0x0C)
wire+0x09 u8  flags   (0x01 SYN / 0x02 ACK / 0x08 RST / 0x10 PSH；组合如 SYN|PSH=0x11)
wire+0x0A u16 window  (LE；SYN=接收窗口容量-占用，RST 缺省 0x80)
wire+0x0C.. payload   ([pkt+0x410] 字节)
总长 = payload_len + 0xC 与发送层 len 计算完全吻合。
struct 布局对照: +0x04 seq/+0x08 ack/+0x0C head_len/+0x0D flags/+0x0E win/
+0x410 payload_len/+0x414 timestamp/+0x418 重传计数
```

### 10.30 运行时配置下发机制 kwmvconf.ini
- 启动时 HTTP GET `http://config.kuwo.cn/kwmvconf.ini`
  （UA="Mozilla/4.0 (compatible; MSIE 7.0...)"，日志"从服务器下载kwmv配置文件"/"连接配置文件服务器config.kuwo.cn成功"，上报 `|uid:%u|server:%s|file:%s|ok:%d|`，标签 KCDOWN/KwP2PDLL/P2P_KWMV_MSG）
- 本地读取用 GetPrivateProfile 系列（读 "P2PClient" 等 section，路径含 kwmvconf.ini）
- **实测 2026-08-24**：`GET /kwmvconf.ini` → 200 但 Content-Length:0（Last-Modified 2024-01-19，
  文件已被清空）；`/p2p/kwmvconf.ini` → 403 illegal request ⇒ 内置 XML 默认配置即当前生效值
- 系统广播消息（OnSysBroadcastMsg）通道存在："系统广播消息, 消息长度:%d"——服务器可动态
  下发指令，运行时 tracker 列表可能经此更新

### 10.31 UDP 实测记录（沙箱 UDP 出站实际可用——修正旧记录）
- CSF SYN（12B 正确头）→ deliver.kuwo.cn:25607 / 211.100.49.14:25607 / 60.29.226.173:25607
  全部超时（SYN 变体：带 conv 16B、win=0x80/0x2000）
- 判断：内置默认 tracker IP 已失效或需先经登录/心跳注册获得会话资格；
  真实可用服务器列表由客户端运行时从主程序获取（g_login 结构即登录后填充）

### 10.32 下一步待解（第五版）
- g_login@0x10069c2c 的填充来源（KwService 登录流程，IP/port/uid/kid 从哪个接口拿）
  —— 这是打通 U_QRY 的钥匙：拿到真实在线 tracker 后即可用 12B 头 CSF 会话查询
- 心跳包格式（BoardcastHeartbeat 函数）——维持 NAT 映射与节点注册
- PEERS 条目字段对应关系与 server 型 peer 数据块请求协议

### 10.33 【定论】uid/kid 生成算法（0x10012a20）——回答"登录"问题
- g_login+0x7C 的 uid **纯本地生成，无账号参与**：先读本地配置文件（kid.ini RandomNumber），
  无则 FNV 变体哈希（13 字节种子，imul 0x01000193/xor，初值 0）→ magic-div
  `result = (1 - hash/1e8)*1e8 + hash` ⇒ uid 恒 ∈ [1e8, 2e8)（act.log kid:123434546 吻合，
  有效性检查 cmp uid,0x5f5e100@0x10011743 呼应）
- +0x80 本机 IP = 0x100215d0 枚举本机地址；+0x84 UDP 端口 = LCG 随机探测空闲端口
  （范围约 10000..19999，试 bind 最多 10 次，成功后写回配置 "ServerPort" 键）
- +0x86 NAT 类型初始值 = 3

### 10.34 U_QRY HTTP 包装格式（部分还原，0x1002d1d0）
- path = `/yl_res_manage.search`（21 字符常量@0x1005b764）
- 拼接序列含：sig1 十进制串（0x10042cd0 itoa）、分隔符 "_"（0x1005b784）、
  后缀 ".txt"（0x1005b77c）、req 内嵌 std::string（req+0xC）
- 日志："使用服务器 %s 进行资源检索, <%u,%u>"、"HTTP模式下连接检索服务器"
- GET 模板@0x1005b7e0：
  ```
  GET %s?%s HTTP/1.0\r\nHost: deliver.kuwo.cn\r\nUser-Agent: Mozilla/4.0 (compatible;
  MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)\r\nCache-Control: no-cache\r\n
  Accept-Encoding: zlib\r\nConnection: Close\r\n\r\n
  ```
  另有 POST %s HTTP/1.1 + Content-Length 变体。响应可能 zlib 压缩。
- 待补：query 参数名与顺序（0x10004bf0/0x10005cd0 为 string append 组合子）

### 10.35 【重大】act.log 统计行完整字段表与链路语义
```
kid:%u|sip:%s|sig1:%u|sig2:%u|seares:%s|seatm:%u|peernum:%u|usedp:%u|nconn:%u|
tooslow:%u|servtm:%u|servpeer:%u|peerpack:%u|serpack:%u|sestm:%d|total:%u|
filetype:%u|down5:%u|mode:%u|stopstatus:%u|searcherr:%u|towarned:%u|useurl:%d|
httpmode:%d|resserver:%s|ressuccsvr:%s|ressucway:%d|
(串@0x1005b33e；短版@0x1005b51f；另有 URLLIST:/EXCEPTION/CDNCONNECT/CODE/USEPROXY 等打点)
```
真实样本解读（476 条全部同模式）：
- sip:27.18.39.80 = 数据来源服务器节点；seares:SUCC seatm:47ms = tracker 搜索成功耗时
- peernum:100 usedp:21 nconn:18 = 搜到 100 节点用 21 连 18；**serpack:602=total:602、
  peerpack:0 ⇒ 全部数据来自 server 型节点，普通 peer 零贡献**
- sestm:27531ms 一首 4MB 歌 27 秒；filetype:2 mode:2 stopstatus:1 searcherr:0
- opensessionerror 样本对象：win.player.ri05.sycdn.kuwo.cn/resource/n2/11/64/xxx.mp3、
  search.kuwo.cn、deliver.kuwo.cn ⇒ OpenSession 是 CSF 层对任意目标(IP:port)的连接动作

### 10.36 服务器节点存活实测（2026-08-24）
- 27.18.39.80（act.log 真实 sip）：TCP 25607 / 80 / 8080 全部 OPEN！
  （25607 与 tracker 端口一致——P2P 缓存节点监听同款端口）
- 对其 UDP CSF SYN(25607) 无回应 —— 该节点走 TCP 或需完整会话序列
- 结论：P2P 缓存节点群大概率仍在线，是数据面主通道

### 10.37 下一步（第六版优先级）
1. PEERS 明文格式解码（%u,%s,%hu,%d,%d,%d,%u 字段对应）→ 拿到 server 节点真实端口
2. CSF over TCP？确认 serpack 传输承载（TCP OPEN 的 25607 可能就是 CSF-over-TCP）
3. OpenSession 函数定位（CSF connect 语义）→ 复现对 27.18.x.x 的会话建立
4. 数据块请求协议（server 型 peer 的分块拉取命令字）

### 10.38 【定案】U_QRY 响应文本解析协议（0x1002b9f6 起）
tracker 应答为明文文本（HTTP zlib 或 CSF PSH 载荷），状态机逐标记处理：

| 标记 | 含义 | task 状态 |
|------|------|----------|
| `<DENY_IP>` | 地址受限(境外IP)，日志 res:DENY_IP "地址受限" | 0xf |
| `<RES_DEL>` | 资源已删除，"NoRes" | 0xd |
| `FILE_LEN<n>` | 文件总字节数（'FILE_LEN' 后至 '>' 前数字）| - |
| `<URL>xxx<` | CDN/服务器直链循环提取，"搜索到%d个服务器资源"、"url=%s" | - |
| PEERS:(...)  | peer 条目区 | - |

- 打点格式：`func:SEARCH|kid:%u|sig1:%u|sig2:%u|res:%s`，res ∈ {SEARES, DENY_IP, NoRes}
- 子串搜索辅助函数 0x10009800(string, needle, len)；提取函数 0x10003a10(find) +
  0x10006120(substr) + 0x10043330(atol)

### 10.39 【定案】PEERS 本地 peer 表结构（LogPeerInfo_V1@0x1002fab2 遍历打印）
```
+0x00 u32 kid          (%u 第1字段)
+0x04    IP 二进制     → inet_ntoa 风格转 "%s"
+0x0A u16 port         (%hu)
+0x10 u32 字段7        (当+0x43与+0x44均非0时输出)
+0x42 bool 有效标志
+0x43 u8  (%d)
+0x44 u8  (%d)
+0x45 u8  (%u)
线上格式: "(%u,%s,%hu,%d,%d,%d,%u)" @0x1005b2b9
打点串: "FormatVer:1.1|sig:(%lu,%lu)|searchtm:%u|PEERS:" @0x1005b288
(按 uid%100 抽样打印)
```

### 10.40 链路全貌定稿
```
签名(sig1,sig2 来自 bang/gedan 接口 param/params 字段, MUSIC_xxx 对)
  → U_QRY 文本(已还原完整格式 §10.x)
  → CSF UDP(deliver.kuwo.cn:25607) 或 HTTP GET /yl_res_manage.search?...(deliver.kuwo.cn:80)
  ← 明文应答: FormatVer|sig回显|searchtm|PEERS(kid,ip,port,3×flag,idx) FILE_LEN<n> <URL>直链...
  → 连 server 型节点(sip 如 27.18.39.80, TCP 25607/80/8080 实测开放)
  → CSF 会话拉数据块(serpack), act.log 证实 100% 数据量来自该通道
```

### 10.41 【机制】TimeProc 定时器与心跳/NatPunch 注册流（0x10011e29 起）
- 周期回调（键名 "TimeProc"@0x100543cc，ini section "KID"/键 "KID" 存 uid）：
  - tick % 30 == 0 → 发**心跳**："向服务器发送心跳消息"
  - tick % 4 == 0 → 发 **NatPunch 校验消息**
  - uid 无效(<1e8)时重新生成并写回配置；版本检查 add 0x15180(86400s=1天) 过期重拉
- 心跳服务器列表（键 "HeartbeatServer"，逗号分隔）：
  `211.100.49.14:25607,60.29.226.173:25607,60.28.205,36:25607`
- 心跳回复语义（接收端日志@0x10049f96 区）：
  "接收到来自%u的ACK消息"、"接收到心跳回复消息"、"接收到反向穿透请求"、
  "接收到内网探测回复"、"接收到系统广播消息"
  **"获取到心跳服务器返回的外部IP地址:%s"** —— 心跳回复即 NAT 外网地址探测结果
- CSF 发送封装 0x100239d0(buf, len)：头部填 uid(+0)/本机IP(+4)/port(+8)/nat(+0xA)/
  isproxy(+0xC) → 0x100187c0 组包 → 0x1001fd90 入发送环（g_sock@0x10069c3c 管理）
- setup.xml 默认 `<ServerPort>6000</ServerPort>`

### 10.42 【推断】SYN 无响应最可能原因（更新）
tracker/心跳服务器要求会话先经**心跳注册**（服务器需知道客户端外网 IP:port 才回 SYNACK，
NAT 网关也需心跳保洞）。Go 实现顺序应为：
1. bind 本地 UDP 端口（随机或 ServerPort 配置值）
2. 向 HeartbeatServer 列表周期发心跳 + NatPunch（格式待挖：0x100187c0 组包函数）
3. 收到 ACK 后再对 deliver.kuwo.cn:25607 发 U_QRY(CSF PSH)
4. 解析 FormatVer|PEERS|FILE_LEN|<URL> 明文应答

### 10.43 待挖清单（第七版）
- 心跳/NatPunch 包字节格式（0x100187c0 组包 + 消息类型字，参考 LAN 广播 cmd 0x1401 风格）
- PEERS 条目循环细节（0x1002c013 之后 '(' ')' 提取段）
- server 型节点数据块请求协议（OpenSession 后的分块命令）

### 10.44 【定案】CSF 心跳包 23 字节格式（0x100187c0）
```
+0x00 u32 LE 0x000E2103   命令字
+0x04 u8   tick 序号 (++g_login+0xC8，同 LAN 广播序号源)
+0x05 u32  uid
+0x09 u32  uid (重复)
+0x0D u32  外网 IP
+0x11 u32  port(u16) | nat(u16)<<16
+0x15 u16  proxy 标志 ([ebx+0xC])
总长 0x17=23 字节。另一组包函数 0x10018840 魔数 word 0x2501(NatPunch 类)。
```
TimeProc: %30==0 心跳 / %4==0 NatPunch(0x100543cc "TimeProc"、0x100543d8 "NatPunch 校验消息")

### 10.45 【重大更正】沙箱 UDP 出站被完全封锁
- 实测 8.8.8.8:53 / 114.114.114.114:53 标准 DNS 查询均无响应 ⇒ **所有 UDP 探测超时
  系沙箱网络策略丢弃出站 UDP，与协议还原正确性无关**
- 此前 §10.31 "UDP 出站实际可用" 记录作废（sendto 返回成功仅代表本地内核接受）
- TCP 出站正常(HTTP 全通)。结论：
  1. CSF/UDP 协议实现无法在本沙箱内联测，需用户在正常网络运行 Go 版验证
  2. act.log 中 opensessionerror 也提示当年部分网络 UDP 受限场景，客户端有 TCP 兜底
- 后续实现按已还原协议直接写码，静态证据链完整

### 10.46 Go 实现层启动
module/p2p/ 目录规划：
- csf.go: 12B 线包头(seq BE|ack|head_len=0x0C|flags|win LE) + SYN/PSH/RST 构造
- heartbeat.go: 23B 0xE2103 心跳 + TimeProc 周期逻辑(%30/%4)
- query.go: U_QRY 文本构造 + FormatVer/PEERS/FILE_LEN/<URL> 解析
- peers.go: "(%u,%s,%hu,%d,%d,%d,%u)" 条目解析 → Peer{kid,ip,port,flags}

### 10.47 Go 实现层第一版完成
- module/p2p/csf.go: 12B 线包头 Marshal/Parse + SYN/PSH 构造
- module/p2p/heartbeat.go: 23B 0xE2103 心跳 Marshal/Parse + 内置心跳服务器表
- module/p2p/query.go: U_QRY 文本构造 + ParseResponse(FormatVer/searchtm/
  PEERS 元组/FILE_LEN/<URL> 循环/DENY_IP/RES_DEL)
- module/p2p/query_test.go: 4 个单测全绿（含真实格式样例串）
- go build/vet/test 全部通过

### 10.48 下一步（第八版）
1. U_QRY 文本与反汇编逐字段复核（当前按 §10.x 记录直译，<%s><%s> 前两段占位待核）
2. CSF 会话层：SYN→SYNACK→PSH(U_QRY)→收 PSH 应答 的 UDP 会话状态机
3. server 型节点数据块请求协议（OpenSession 后分块拉取命令字）
4. 用户侧真机验证：沙箱 UDP 被封，Go 版需在正常网络跑通心跳→查询链路

### 10.49 CSF 会话层 + 真机诊断工具完成
- session.go: Dial 三次握手(SYN→SYNACK→ACK，语义来自 0x1001bce0：
  应答 seq=对方ack / ack=对方seq+1) + Send/Recv(PSH 捎带 ACK) + RST 关闭
- cmd/p2pcheck: 一键真机验证工具
  ```
  go run ./cmd/p2pcheck <sig1> <sig2>
  # 默认 sig 对 = MUSIC_169753 (3264614461, 1651339078)
  ```
  流程：5 连心跳(deliver+心跳IP, 打印任何回包 hexdump) → CSF 握手 →
  U_QRY → 明文应答解析(PEERS/URL/FILE_LEN 或 DENY_IP/RES_DEL)
- 测试 6/6 通过（新增回环 UDP 会话与并发会话测试）
- 真机预期结果分支：
  - 心跳有 REPLY → 注册层正确，看回包定外网 IP 字段
  - 握手成功但查询无应答 → U_QRY 文本字段需按回包微调
  - 全程无响应 → 该 tracker 已停服（需抓真实客户端流量拿新服务器列表）

### 10.50 服务端 P2P 基础设施全面下线验证（2026-08-24）
- 真机（用户 Termux，无 VPN）+ 沙箱双重验证，所有端点死亡：
  - deliver.kuwo.cn:25607 TCP(39.156.121.53/.34, 211.100.49.14, 175.102.178.96,
    27.18.39.80) → connect 后任何数据立即 EOF（负载均衡 accept 即关，无服务）
  - deliver.kuwo.cn:25607 UDP 心跳/U_QRY/CSF-SYN → 全部静默
  - deliver.kuwo.cn:80 /yl_res_manage.search → 404 Not Found（nginx 在、路径删）
  - search.kuwo.cn:80 / → 200 Content-Length:0
  - config.kuwo.cn/kwmvconf.ini → 200 空（Last-Modified 2024-01-19）
  - resua.kuwo.cn(111.13.240.252)/103.235.253.250 各端口 → OPEN 但同样 accept-close
- 用户手机网络到 39.156.x:25607 TCP 超时（运营商拦非常规端口），但沙箱可连，
  故沙箱 EOF 结论有效：服务端确实下线
- 新版客户端包对比（github release default.zip = kuwomusic/8.7.4.0_BDS1）：
  - KwMV.dll 与旧版**同一二进制**（453616B 同尺寸，字符串地址仅 +9 偏移），
    协议字符串(U_QRY/FormatVer/PEERS/DENY_IP/RES_DEL/FILE_LEN/tcpproxy/
    deliver/search/resua/211.100/25607)全部一致
  - 包内 Log/KwService_P2PDll.txt 仅含 "PlayChannel:Restart KwMV B/E" 反复
    重启记录，零 tracker/心跳/握手日志 ⇒ 该日志级别不输出协议细节，
    且无法证明 P2P 曾成功
- 结论：酷我官方已在服务端整体下线旧 P2P 链路（tracker/资源服务/配置下发全空）
- 待确认：用户称"PC 客户端可用"的具体含义——普通播放下载走新版云 API
  （nmobi/kuwo.cn/api 直链），与 KwMV P2P 无关的可能性最大；
  需用户提供 PC 端最新 act.log 或 netstat 实测远程 IP 才能定论

### 10.51 用户实测 act.log.out 反转结论：P2P 链路活着 + 心跳布局修正（2026-08-24）
- 用户提供刚跑过的完整客户端包(release 2.0.4 kuwomusic.zip)，
  Log/act.log.out(468KB, 91 条 P2P_DOWN_FILE) 决定性证据：
  - seares:SUCC 77/91 次，ressuccsvr=39.156.121.53(64次)/39.156.123.34(13次)
    = deliver.kuwo.cn 现行 IP ⇒ **tracker 查询在真实客户端上持续成功**
  - peernum 最高 100 / usedp 66 / nconn 43 ⇒ peer 连接也建立
  - peerpack 全 0、serpack==total ⇒ 数据仍全部来自服务器型节点
  - httpmode:0 / useurl:0 / ressucway:2 ⇒ 成功通道是 UDP CSF（HTTP wrapper 未用）
  - kid:15277654 == 日志尾 U:15277654 ⇒ **kid 来自登录账号 UID**，
    推翻"本地随机生成"假设（未登录时才走本地生成）
- 由此判定：我们 UDP 探测失败的原因是包构造错误，服务端在线
- **心跳包真实布局修正**（0x100187c0 + 调用者 0x100239d0 精读）：
  - +0 u32 LE cmd=0xE2103；+4 u32 恒零（旧版误写 seq+uid）
  - +8 u8 = 本机 IP 首字节（g_login+0x80 的内存首字节，网络序）
  - +9 uid / +13 ip / +17 port|nat<<16 / +21 proxy
  - Go heartbeat.go 已修正+测试更新；p2pcheck 增加 UDP dial 出口 IP 填充
- HTTP 查询路径精确格式（0x1002d1d0）：
  `GET {sig1}_{本机IP}.txt?<U_QRY文本> Host: deliver.kuwo.cn`，
  arg+0x11C=sig1(task+0x124)、arg+4=4字节IP→"%d.%d.%d.%d"(fmt@0x100535cc)；
  但 act.log httpmode:0 证明真实流量未走此路，404 与线上行为一致
- 27B LAN 广播包函数 0x1002a540→sendto 包装 0x1001e690(len 0x1b) 复核一致
- commit d580542 已推 arm64 二进制，待用户真机重测心跳

### 10.52 【闭环】点击"下载到电脑"完整参数流（画质选择框 → P2P 引擎）
UI 弹窗元数据（rid=18877092 例；无损FLAC 49.1MB / 超品320K 9.02MB / 高品128K 3.61MB / 流畅WMA 3.11MB，
链接 www.kuwo.cn/down/single/{rid}）来自前端侧服务器接口；引擎收到的只有下述结构体。

**导出表仅 4 个**：StartP2P/StartP2P_V1/StopP2P/StopUpload——任务下发全走隐藏窗口 "KwMV" WM_COPYDATA。

WndProc@0x1000f010 跳转表@0x1000f4b0 实测（stub 形如 push [ecx+8](lpData); call handler）：
- wParam=1 → 0x10015870 **新建下载任务**
- wParam=2 → 0x100157c0 → 0x100264e0 **停止任务**(malloc 0x4C 仅头部; sprintf "StopDownloadTask Fid: %u %u WinName %s reason:%d";
  downMode==2→state=4("Timeout") else 5("User"); 0x10025c80(fid1,fid2) 查表 → 0x10033f90 停止)
- wParam=5 → 0x1000f0fd 配置/状态查询类(fid1,fid2+[g_10069bec+0x18] 校验+JSON 拼接)
- wParam=6 → 0x1000f289 任务信息查询(call 0x10026100)
- wParam=11(b) → 0x10015830 (malloc 0x48+memcpy 0x12 dwords)

**★ 新建任务 DLREQ 全布局（0x16E=366B，handler malloc 同尺寸 memcpy 0x5B dwords+1 word）**
```
struct KwMV_DLREQ {         // 由前端(KwMusicCore/KwModDownload)构造
  u32  sig1;    // +0x000 ★ 即 fid1；U_QRY <sig1,sig2> 与 act.log S1 的最终来源（前端生成）
  u32  sig2;    // +0x004 ★ 即 fid2；S2 来源
  u32  numPkt;  // +0x008 日志 NumPacket
  char winName[]; // +0x00C 回调窗口类名（strlen 定界，非定长 0x44）
  ...           // +0x010..0x4B 中间字段（部分读入 desc：+0x10 判空、+0x44、+0x4C）
  s32  fileType;// +0x050 音质档位编码（日志 FileType）
  s32  downMode;// +0x054 ==3 走特殊分支（日志 DownMode）
  u32  ts;      // +0x058 TimeStamp
  char fileName[];// +0x060 目标文件名
  ...
  char extra[]; // +0x164 尾部附加串（拼进搜索描述）
};            // 总长 0x16E
```
处理链：0x10015870 malloc+copy → _beginthreadex(threadproc=**0x10015810**) → **call 0x10026810(buf)** → free。
大函数内：sprintf "NewDownloadTask, Fid: %u %u, NumPacket:%u, WinName:%s, FileName:%s, FileType:%d,
DownMode:%d TimeStamp:%u"(fmt@0x10059fe0，参数序即上表)；**desc 头两 dword(sig1/sig2 槽 esp+0x6c/0x70)
← [ebx]/[ebx+4]**（0x10026977/0x1002697b，铁证）；拼串(全局 0x1006b4fc + DLREQ+0x164)；
call 0x100083a0(&desc, strA, strB, byte[0x1006b6c7])；数值槽 ← DLREQ+0x4C/+0x8；
call 0x10025700 创建任务(malloc 0x408 任务体，desc 深拷贝@0x10009020 至 **task+0x124**)。
后续：状态机 0x10031ce0 → state=8 → 0x1002abf0 发 U_QRY → PEERS/主HTTP下载/kmap 块管理 → 经 winName 回推进度。

**结论修正**：此前 10.10/10.11 把 sig1/sig2 记为 COPYDATA+0x50/+0x54 是错的——那是 fileType/downMode；
sig 对 = 结构头 fid1/fid2。sig 的**源头是服务器元数据接口的 NSIG1/NSIG2 字段**（§9 已实测：榜单/歌单/搜索
返回即带），前端仅将其透传进 DLREQ（fid1/fid2 只是 UI→引擎的传输载体）；Go 侧 getSongMeta/refreshSig
→ SearchResource(rid,sig1,sig2) 与此完全对齐，无需自行计算 sig。

### 10.53 sig 实测复核（2026-08-24，module/live_sig_test.go TestLiveRankSig）
- Rank(id=16) 第一首《山风山风等等我》musicrid=MUSIC_624683929, param链 nsig1=2608621834,
  nsig2=2438534005 —— 与 §9 记录**逐位一致** ⇒ 榜单/歌单/搜索返回的 NSIG 对即 P2P 查询签名，
  长期稳定，直接取用（音质档位 S1/S2/SIZE/BT 同源于 getSongMeta 的 KV 文本）。
- refreshSig(rid.kuwo.cn/sig.s) 沙箱 DNS 解析失败（no such host），PC 环境可用。
- deliver.kuwo.cn:80 `/yl_res_manage.search`(裸path GET+POST) → 404 IETF nginx ⇒ HTTP 检索端点
  服务端确已下线（含 itoa(sig1)_ip.txt 变体此前亦 404）；唯一活通道 = UDP CSF :25607，
  沙箱 UDP 出站禁用 ⇒ 终验须 PC p2pcheck.exe。

### 10.54 g_login 初始化与匿名 uid 算法（0x1000f888 / 0x10012a20）
- g_login 填充序列（初始化路径 0x1000f888）：`+0x80=本机IP(call 0x100215d0)`、
  `+0x84=si(随机端口，0x10012f60 查重循环)`、`+0x7C=uid(call 0x10012a20)`、`+0x86=nat=3`、`+0x94=0`
- **uid 来源 0x10012a20**：先 `KwLib.dll!GetUserID(buf,127)`(IAT 0x1005312c) 成功→atof 转换；
  失败→本地生成：`call 0x100458b0` 取机器串 → **FNV1a-32**(素数 0x1000193,13字节) →
  `uid = (hash mod 1e8) + 1e8`(魔法数 0x55e63b89>>25 除法, @0x10012b21)
  ⇒ 匿名 uid ∈ [1e8,2e8)，**服务器无预校验**；登录态 uid(如15277654<1e8) 由前端覆盖传入
- p2pcheck 升级(commit 1e4a6b3)：stage0 UDP 对照(DNS@223.5.5.5/8.8.8.8 区分运营商封UDP vs 服务端静默)、
  CSF 握手重试×3、uid 改匿名格式；Session.LocalPort() 新增

## §10.55 面板数据源模块汇总（全部完成并 live 验证）

| 模块 | 路由 | 数据源 | 格式要点 |
|------|------|--------|----------|
| 每日推荐 rcm | /rcm | discover=`nmobi.kuwo.cn/mobi.s?...type=rcm_discover`; personal/taste/history=`rcm.kuwo.cn/rec.s?cmd=` | taste 返回对象 {taste:[],listened:{}} |
| 电台 radio | /radio | tree=`qukudata.kuwo.cn/q.k?op=query&cont=tree&node=87235&sourceset=tag_radio&extend=gxh`; songs=`gxh2.kuwo.cn/newradio.nr?type=4&fid=<叶子节点>` | GBK TSV: 首行 fid\tcnt，行=rid\tartist\ttitle\tsig1,sig2\tflag；fid 必须叶子(如-26711)，根节点报 fail |
| 歌手 artist | /artist | list=`artistlistinfo.kuwo.cn/mb.slist?stype=artistlist&category=1..8`; info/songs/albums/mvs=`search.kuwo.cn/r.s?stype=artistinfo|artist2music|albumlist|mvlist&artistid=` | category: 1华语男2华语女3欧美男4欧美女5日本男6日本女7韩国8其他; r.s 单引号 JSON→singleQuoteToJSON |
| MV mv | /mv | `r.s?stype=mvlist&artistid=&sortby=1` | 老频道 album.kuwo.cn/album/mv2015 已死(302)；web playMv 要 csrf |
| 新歌速递 newsong | /newsong | source=album/mv: `js01.kuwo.cn/star/MusicTopToday/js01/topmusic/recAlbum.js|recMv.js` (JSONP `try{var jsondata={...};handleIndex(jsondata);}catch(e){}`)；source=playlist: playlist_info(id=1082685104「每日最新单曲」) | jdtlist[].list[] 按 huayu/oumei/rihan 分类；JSONP 提取需大括号配对扫描(尾部有 handleIndex 调用，LastIndex 会取错) |

- 新歌速递前端入口 index.js: new_song_sourceid=1082685104 → 即「每日最新单曲」歌单，playlist_info 直接可用。
- 全部路由注册于 server/modules.go；live 测试文件 rcm_live_test.go / mv_live_test.go / newsong_live_test.go 全 PASS。

## §10.56 播放器音质按钮 PL_BTN_Quality 切换逻辑（KwMusicDLL.dll）

- 按钮本体 KwMusic.xml:1343 文本动态显示当前音质("高品"等)，无歌曲时 enabled=false。
- 点击链路: DuiLib Notify(UTF-16 控件名 PL_BTN_Quality) → KwMusicDLL.dll 转 ANSI 消息 BTNNAME:BTN_QUALITY(字符串区 0x38c9c8 附近, 同模式 BT_More→BTNNAME:BTN_MORE)。
- 弹窗 skin\base\NetSongPlayQualityWnd.xml (175x148) 四行:
  hq_perfect 无损 APE(金色+vip_logo) / hq_super 超品320K(VIP) / hq_high 高品128K / hq_generic 流畅WMA。
- 动态填充: 控件后缀 _code/_bitrate/_img/_play; bitrate 文本运行时填 "APE"/"320"/"192"/"WMA"(0x395660 处 '192'/'320'); 可用性取决于当前歌曲音源格式。MV 播放时换五档 quality_*_play_mv.png: PlayQuality_MV_AUTO/1080/720/540/480。
- 选档埋点(ANSI 串 0x38f510): Qulity_Perfect|Super|High|General Click + "...Click With Eff"(音效联动变体), 酷我官方拼写即 Qulity。
- VIP 档(无损/超品): 先走 musicpay.kuwo.cn/music.pay 计费确认 — ?uid=%s&sid=%s&ver=%s&src=mbox&op=query|submit&action=%s&pid=%s&id=%s&br=%d&fmt=%s&accttype=1(CChargeQueryTool/CChargeData); 未开通弹升权。
- 生效: 通知播放核心按新 br 重取链接; AAC 走 PlayerCore.dll 的 anti.s?key=kwmusic&body=..format=aac&type=convert_url&rid=%s&response=url&loginid=%s&ch=%s。
- 附带: "什么是无损音乐?"说明弹窗(Title_Ape_Explain); UpqualitySelect.html 是另一功能(本地歌曲一键升高音质批量升级)。

## §10.57 播放/暂停按钮(Play/Pause)控制链路

- XML: KwMusic.xml:1317 TabLayout name="Play_Pause" 内叠放两个按钮 — Play(playbtn.png, tooltip 播放(Ctrl+F5)) / Pause(pausebtn.png, 暂停(Ctrl+F5)); Tab 页随播放状态互切。
- 控件名复用: 同名 "Play"/"Pause"/"Play_Pause"/"Pre"/"Next" 也注册给托盘菜单(字符串区 0x382300: Play_Pause/tray_Pre/Play+tray_menu_play.png/Pause+tray_menu_pause.png/Next+"播放控制"+TrayMenuVolumeSlider), 主界面与托盘共用一套 Notify 处理。
- UI→引擎: KwMusicDLL.dll(UI层) 不直接导入播放器; 通过 CPlayMedia::Play/_PlayNet 起播(取链后 PlayerSetURL), 暂停/恢复/停止调用 CKuwoPlayer.dll 工厂 CreateKuwoPlayer 返回的接口方法 Play/Pause/Stop/SetVolume; 输出走 DSOUND。
- 状态广播: 引擎状态回调后 UI 发 NotifyPlayPaused/NotifyPlayStopped/NotifyPlayResumed/NotifyPlayFinished/NotifyDownloadFailed(0x39f978 区), 通知网页层(CDDealWebAction::CallHtmlJS)、托盘、歌词等观察者; 失败时 CPlaylistData::_AutoPlayNext 自动切下一首("Play Failed %d, Auto Play Next")。
- 附带: 进度条 CPlayProgressUI(DuiLib 自定义控件, SetDownPercent 显示缓冲)与 GetCuriDurationByPoint 支持点击定位。

## §10.58 P2P 服务器地址来源：全部为 KwMV.dll 内置默认值

- 心跳列表硬编码 .rdata@0x581fd(文件偏移): 字符串序 BoardcastHeartbeat → "211.100.49.14:25607,60.29.226.173:25607,60.28.205,36:25607" → "HeartbeatServer" → ","。代码逻辑=GetConfig("HeartbeatServer") 按逗号分列; 安装包 Conf/default/config.ini 无此键 ⇒ 实际跑的就是内置默认。
- ⚠ 内置串含官方 typo: 第三条写作 60.28.205,36:25607(点写成逗号), 按逗号 split 得到坏 token "60.28.205"/"36:25607" ⇒ 有效心跳目标实际可能只有前两条(211.100.49.14 / 60.29.226.173)。Go 端 DefaultHeartbeatServers 需修正此认知。
- 完整默认 XML 配置(@0x58560 区, GB2312):
  IndexSvr=search.kuwo.cn:80 | Tracker=deliver.kuwo.cn:25607 |
  HelpSvr1=uh1.kuwo.cn:6718 | HelpSvr2=uh2.kuwo.cn:6721 |
  ResUpSvr=deliver.kuwo.cn:80 | ResSeaSvr=deliver.kuwo.cn:80 |
  RecommendSvr=tuijian.kuwo.cn:80 | MeasurePath=/stat/zidane.rm | Version=1.2.3.0
- 新通道线索: ResSeaSvr=deliver.kuwo.cn:80 即资源查询也有 HTTP 80 形态(Android POST /yl_res_manage.search 同 host); HelpSvr1/2(uh1/uh2.kuwo.cn:6718/6721)为打洞/辅助服务器, 此前从未测试。
- 日志格式串区(0x587d8 后): "sessiontm=%d, udppeer=%d, tcppeer=%d, udpconn=%d, tcpconn=%d, udpeff=%d, tcpeff=%d" + task.txt ⇒ tracker 会话同时统计 UDP/TCP peer 与连接效果, 存在 TCP peer 传输形态。

## §10.59 配置下发接口编码算法（KwModConfig.dll 反汇编确认）

- 端点: http://config.kuwo.cn/uc/s?m=（活, 任意参数回 FAIL）
- 编码: std_base64(XOR循环"yeelion " 8字节) — KwLib.dll Base64Encode@0x10013fd0→表查询0x10014070, 字母表@0x100527b0=标准A-Za-z0-9+/
- 构造函数(KwModConfig.dll @0x1000ed30): 依次读取 configsvr/serverlist 值、GetUserID、GetInstallSRC、version, 拼 uid;serverlist,src,config → 调 MakeHttpParam@0x1000fa00 → 编码作为 m= 值
- 实测真实配置: version=MUSIC_8.7.4.0_BDS1, channel=kwmusic_web_1_bds_20171206 (Conf/default/config.ini)
- 候选 payload 编码后请求全回 FAIL —— 明文 payload 精确格式仍需真实抓包样例
- ResSeaSvr 备信道扫径: deliver.kuwo.cn:80 /yl_res_manage.search GET/POST→404; /res/yl.s→403; HelpSvr(uh1/uh2.kuwo.cn:6718/6721) TCP 不可达(ICE慕)。

## §10.60 【闭环】方案3成功：config.kuwo.cn 配置通道完全还原 + 新服务器列表到手（2026-08-26）

**协议格式（实测验证，非猜测）**
- URL: `http://config.kuwo.cn/uc/s?m=<len(plain)>;<b64>` —— m= 后数字 = **明文字节长度**（0x1000f126 mov edx,[esp+0xc8]=T5.size → 0x10007590 "%u"），分号后 = 编码串
- 明文: `<uid>;<version>,<installsrc>,config`（拼接序 0x10002b50=append(pushed)→out=A+pushed 定序完成；尾部字段服务器不校验，uid 可空）
- 编码: std_b64(XOR循环"yeelion ")（§10.59 算法不变）
- **响应: 纯 std_base64 的 INI 明文（无 XOR 层）**, ~8-10KB 全量客户端配置；格式错回 `RkFJTAA9`(FAIL)
- 拼接链完整定序(0x1000ed30): T1=uid+";" → T2=T1+version_cfg → T3=T2+"," → T4=T3+install_src → T5=T4+",config" → MakeHttpParam(ecx=ptr,edx=len,eax_out=b64)

**服务器下发的关键内容（HeartbeatServer 谜底）**
- `[p2p] HeartbeatServer=175.102.178.96:25607,175.102.178.97:25607` ← 内置旧 IP 全死、真实客户端却活着的解释=启动时从本接口拿新列表
- `[ResSearch] SearchServer1..8`(uint32 **大端**→IPv4, SS7=664566069→39.156.121.53 与 act.log resserver 一致即证):
  首轮样本: 101.42.130.234 / 101.42.128.167(腾讯云) | 111.206.97.45 / 111.206.98.106 | 49.7.250.69 / 49.7.249.154 | 39.156.121.53 / 39.156.123.34
  ⚠ 列表动态轮换: 二次拉取变为 60.28.205.36/211.100.49.14/60.29.226.173/... (旧内置心跳IP入池) ⇒ 客户端每次启动都可能拿不同池
- `[Netsong] SearchServerDNS=http://43.144.129.208|101.42.130.145`(HTTP 200 可达, /yl_res_manage.search 空200), pcIndexServerDNS=http://175.102.178.77
- `[DNS2CONF] host=103.79.26.13 port=443 webproxyip=175.102.178.77`; `[p2p] httpmode=1 closehttp=1 tasknum=7 peak=16777216-1`
- FW 探测主机 CheckHost: 1008520484→60.28.205.36, 3546558734→211.100.49.14 —— §10.58 "官方typo"IP 其实是防火墙探测主机列表成员, 心跳串里的逗号仍是 split bug

**连通性实测（沙箱）**
- TCP 25607 OPEN: 175.102.178.96/.97 ✓ 39.156.121.53 ✓（此前 deliver 域名 TCP 超时结论被新 IP 推翻）
- TCP 上发 23B 心跳(cmd=0xE2103, ip=1.2.3.4 占位) → 连接成功但 0 字节回包; RE 依据心跳走 UDP sendto(TimeProc), 且 ip 字段须为真实外网 IP ⇒ 待真机 UDP 验证
- 43.144.129.208 / 101.42.130.145 HTTP 200; 175.102.178.x:80 超时(仅开 25607)

**代码落地**
- module/p2p/config.go: BuildConfigURL/FetchServerConfig/INIGet/HeartbeatServersFromConfig/SearchServersFromConfig(uint32 BE)
- heartbeat.go DefaultHeartbeatServers 更新为 175.102.178.96/.97:25607
- 测试: TestXorYeelion/TestBuildConfigURL/TestINIGetAndServers + TestFetchServerConfigLive(KUWO_CONFIG_LIVE=1) PASS; go build/vet PASS

**下一步**: p2pcheck 用新 IP 重发 UDP 心跳(真机) → 等 ACK 拿外部 IP → U_QRY 查询 → tracker 会话

## §10.61 【协议闭环】Android libp2p.so 完整还原 HTTP 搜索通道 U_QRY 文本格式（2026-08-26）

**方法突破**: 字节级 ADRP/ADD 扫描器(掩码 0x9F000000 任意 Rd + ADD imm 配对)替代 capstone 迭代器(大段中遇无效指令会静默中断), 一举定位全部字符串引用。PLT stub 解析(GOT->RELA->符号名)打通调用语义。

**U_QRY 查询文本权威模板(SearchPeer::run @0xd27c8)**:
```
line1 = format("<001><U_QRY>|<%u,%u>|<%u><%s><%s>|<%s>",
               Sign+0x10, Sign+0x14,            # 签名对(w21/w22, [this+0x10/+0x14])
               GetP2PCenter()->vt38(),          # int = GetUID()
               GetP2PCenter()->vt48(),          # string = GetVersion() (MUSIC_8.7.4.0_BDS1)
               GetP2PCenter()->vt58(),          # string = GetInstallSource()
               localIP_str)                     # UDPServer::GetLocalHost()->host().toString()
line2 = format("|<rid>|<uip:%s>|<new>|<nat:%u>|<flags:%u>\r\n",
               localIP_str, UDPServer::GetNatType(), 0)
body  = line1 + line2      # 注意 <rid> 为字面量占位
```
- `<001><U_QRY>` 与 PC 版 cmd 字一致; `<uid>ver|src` 无分隔拼接与 PC 版 KwModConfig payload 同构
- vtable 运行时重定位无法静态读槽位; vt48/vt58=仅有的两个无参 string getter (GetVersion/GetInstallSource), 顺序待真实样本定

**HTTP 报文模板(SearchPeer::Search @0xd18b0 +0xdc 引用 0x227fbb, TcpConnection::write 直发)**:
```
POST /yl_res_manage.search HTTP/1.1\r\n
Host: deliver.kuwo.cn\r\n
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)\r\n
Cache-Control: no-cache\r\n
Accept-Encoding: zlib\r\n
Content-Length: %d\r\n
Connection: Close\r\n
\r\n%s            <- body 明文(非压缩)
```
响应解析: readline 循环 + StringTokenizer; 第2 token 匹配 '200'(0x2280b0); 解析 Content-Length(NumberParser); Content-Encoding==zlib(0x2280d4) 则解压。响应标记集(0x2281c2区): <DENY_IP> <RES_DEL> FILE_LEN <URL> <USR_ID> & p2sp:// <CHECK

**搜索服务器来源**: GetConfigItem("P2P_SearchServer", 默认 "deliver.kuwo.cn:80;103.235.253.203:80;60.29.226.173:80;60.28.205.36:80") — config.kuwo.cn 下发配置中无此键 ⇒ 走内置默认。
**CResourceReport**(资源上报): POST /yl_res_manage.up, 键 ReportServer, 同 Host 固定 deliver.kuwo.cn:80。

**连通性终判(2026-08-26 沙箱实测)**:
- Netsong DNS 机(43.144.129.208/101.42.130.145):80 → 精确模板 POST 回 200 Content-Length:0(nginx+X-Cache linux245 兜底, 非业务应答)
- deliver.kuwo.cn/39.156.x:80 → Apache 404
- 103.235.253.203 / 60.29.226.173 / 60.28.205.36:80 → TCP accept 后 0 字节静默
- 结论: HTTP 搜索通道已下线(config [p2p] closehttp=1 互证; act.log httpmode:0 ressucway:2 = 真实流量走 UDP CSF)

**新攻击面(下一阶段主攻)**: libp2p.so 全套带符号 UDP 协议栈:
- UDPServer::HandleClientData(UDPPacket*) — 服务器消息总分发(消息类型全集入口!)
- UDPServer::PassiveConnect(ReqCNatPunchStruct*) — NAT 打洞
- UDPServer::GetMsgNo/AcceptUpload/GetNatType/GetLocalHost
- Swordfish(recvACK/recvSYNACK/getRemoteAddr)/SwordFishConnect::connect — peer TCP 化传输
- TaskCount::Log/CUploadTask/CResourceReport — 统计与上报
⇒ 用 Android 侧符号反推 PC KwMV.dll CSF serpack/OpenSession 未竟协议

## 10.62 【协议还原】 libp2p.so UDP 控制通道全解密 (Android 新版协议)

### 线程架构 (UDPServer::Start @0xe0018)
- msgNo(0xa8)=rand()%0x40000000+1; natType(0xc0)=3 初始
- 本地 bind: SocketAddress("0.0.0.0", GetConfigUInt("P2P_ServerPort", **6000**)) 失败重试6次(rand%10000ms退避)
- ThreadPool×3: run(分发)/OnRecv(recvfrom)/CheckNATE; Poco::Thread×3(GOT 0x2ea218=OnRecv@0xe05bc, 0x2ea660=CheckNATE@0xe0840, 0x2ea6c0=HeartBeat@0xe1294)
- run(): 队列消费→HandleClientData; 返回1时 recycle Packet

### HandleClientData 消息分发 (@0xe1e4c) —— 权威路由表
```
pkt->data[0] (int8):
  b0<0 (bit31=1): Swordfish 数据流; rev32(data[0..3]) 字节序转换后
      Swordfishs::find(sa,true) → onRecvPacket; 未找到且 Packet::getType()==1(SYN) → newSocket
  (b0|2)==3 即 b0∈{1,3}: 控制通道, 子命令=data[1], 载荷=data+9 (包头9字节):
      0x13: 被动连接请求(服务器指令) → ReqCNatPunchStruct{u64@0=[data+9] ip:port打包, u16 port@8=[data+0x11]}
            BigIPToString(u64>>32) → PassiveConnect(p)
      0x27: 心跳ACK → OnAckHeartBeat(sa, ACK_HEARTBEAT_INFO*)(data+9)
      0x30: NAT探测ACK → OnACKNATProbe(sa, TNATProbeMsg*)(data+9)
```
**包头 9B**: [0]=大类(1/3控制, 其他Swordfish), [1]=cmd, [2..3]=payload_len LE16

### ACK_HEARTBEAT_INFO (OnAckHeartBeat @0xe22a4)
`{u32 ip_bigendian; u16 port}` 6字节 —— 服务器告知客户端外部映射地址
处理: externalAddr(this+0xb8)=该地址; 若 == localSockAddr(this+0xb0).host → natType(0xc0)=0(无NAT)

### CheckNATE (@0xe0840) — NAT探测包 (兼注册心跳)
- 配置: HelpSvr1="P2P_HelpSvr1"/uh1.kuwo.cn:**6702** → this+0x90; HelpSvr2="P2P_HelpSvr2"/uh2.kuwo.cn:**6721** → this+0x98
- 19字节包: `[0]=1 [1]=0x29 [2..3]=10(LE16) [4]=(u8)++msgNo [5..8]=u32 vt38()(GetUID?) [9..12]=u32 vt38()再次 [13..16]=u32 ToBigIP(localIP) [17..18]=u16 localPort`
- 发送: SafeSend(buf,**19全长**,uh1,-1) ×1 + SafeSend(buf,len字段+9,uh1,-1) ×2 + 同样×3 发 uh2
- ToBigIP@0xae560: IP字符串转大端u32

### natPunch(PEERINFO&) (@0xe2cb8) — 打洞编排
- PEERINFO: [0x00]=u32 uid, [0x08]=SocketAddress peer, [0x10]=u32 flags
- flags∈{0,2}: Swordfishs::newSocket → connect(timeout=20000ms,false) 直接主动连
- 否则 addOnePassiveConnect(uid); 构造19B包 cmd=**0x0a**: `[0]=1 [1]=0x0a [2..3]=9(LE) [4]=++msgNo [5..8]=myuid [9..12]=u32 vt38() [13..16]=u32 ToBigIP(externalAddr.host) [17..18]=u16 externalAddr.port`
- 再包装 newReqRelayMsg(RELAYMSG_INFO{u32 vt38(), u32 target_uid, u16 len+9, char* buf}) 
- SafeSend(&msgno,4,peerAddr,2)×3 直发对端 + SafeSend(relay,len+9,tracker(this+0x88),-1) 经tracker中转
- 循环40次×50ms sleep 等 Swordfishs::findbyuid(uid) 出现
- 日志串: "found"(0x22875d) "connect ok?"(0x228768) "connect fail"(0x228772) "relay?"(0x22877c/0x228785)

### 关键推论
1. **Android 无独立 tracker 心跳请求**: HeartBeat线程仅刷新tracker地址(this+0x88); 保活=NAT探测包(cmd 0x29)周期发往uh1/uh2; tracker侧响应走0x27/0x30
2. vtbl+0x38 三处调用值一致 → GetUID (与 SearchPeer U_QRY <uid> 同源)
3. PC版(cmd=0xE2103,23B)与Android版(cmd=0x29/0x0a,19B)是两代协议; tracker同时兼容或按客户端区分
4. 服务器→客户端被动连接指令(0x13)证明: 打洞由tracker协调, 双方都收到对方ip:port后互发


## 10.63 【协议闭环】 Swordfish/CSF 握手权威还原 (libp2p.so 符号级)

### Packet 结构 (@0xcd974 ctor, 0x410+ 字节)
```
[0x000] u32 seq     本端包号 (SYN=ISN); packACK空包时0x80000000
[0x004] u32 ack     确认的对端包号
[0x008] u8  ver     (old&0xF0)|0x0C; 初始0x80 → 实际0x8C
[0x009] u8  flags   bit0=FIN bit1=SYN bit3=RST bit4=有ACK
[0x00A] u16 win     接收窗口 (sndBuf[0x38]-sndBuf[0x60])
[0x00C] payload     载荷区
[0x40C] u32 len     载荷长; getLength() = len+12 (头恒12B)
[0x410] u32         发送时刻毫秒(RTT计算)
getType(): bit3→9; bit1→1|ack(1=SYN,2=SYNACK); bit0→4|ack(FIN/FINACK);
           else→ack?0:3 (数据)
序号按"包"递增 (SACK位图按包索引, recvACKE d8260)
```

### 三次握手
1. **connect @0xd7978** 构造 SYN: `CSYNPacket{u32 ver=1@+0, u32 isn=getSeq()@+4, u16 windiff@+8(packed), u32 uid@+A(packed)}` → packSYN:
   `[isn][0][0x8C][0x02][windiff]` + payload `{u32 1, u32 GetUID}` = **20字节**
   state(0x1e8)=1; sndBuf[0xb8]=getSeq()-1 记录SYN号; sendPacket
2. **服务器→SYNACK** type=2 (flags=0x12); recvSYNACKE @0xd8b10:
   peerISN(0x1c4)=pkt->[0x10]=payload[4..8]; 校验 state∈{1,2}; 确认 seq<=srvISN-1 的在途包;
   更新 RTT/win(sndBuf[0x218]); state→3 或 Event.set 唤醒 connect
3. **客户端→ACK**: packACKE 在收到的包上原地改造:
   `[0]=srvISN(不变), [4]=srvISN+1, hdr1|=0x10(已是), [A]=win` + 原载荷回显(SACK空时length不变)

### recvACKE @0xd7f3c (连接后 ACK/确认处理)
- 按跳转表 state 0-6 分派 (表@0x2282a4)
- 校验 ack∈[sndBuf[0x21c], sndBuf[0xb8]+1]
- SACK 位图: payload 从+0xC起, `bitmap[(seq-ack)>>3] & 1<<((seq-ack)&7)` 标记乱序确认
- 重传: 连续3次重复ACK → reSendPacket

### 对 Go 实现的修正 (commit 9a52132)
- 旧 csf.go 全错: 大端seq/headLen@8/TCP风格flags → 全部重写为 LE + 0x8C + bit flags
- Session.Dial 第三步改为"回显服务器ISN与载荷"
- Send 序号按包+1; Data 包 flags=0x10(type 0); 收数据回 ack=srvSeq+1

### 阶段结论
uh1/uh2.kuwo.cn 已从 DNS 摘除且 config INI 无 HelpSvr 键 — Android help-server 通道废弃。
真实入口 = tracker:25607 UDP 的 Swordfish 会话内发 U_QRY (act.log ressucway:2 seares:SUCC 佐证)。


## 10.64 【生态终判】 P2P tracker 服务端已下线 (2026-08 实测)

### 测试矩阵 (沙箱 + 用户手机双环境, 结果完全一致)
| 包型 | 协议代际 | 通道 | 目标 | 结果 |
|------|---------|------|------|------|
| PC 心跳 23B (0xE2103) | KwMV.dll | UDP | 10×:25607 (hb+trk) | 零回复 |
| Android NAT探测 19B (0x29) | libp2p.so | UDP | 10×:25607 | 零回复 |
| Swordfish SYN 20B {1,uid} | libp2p.so | UDP (srcport 6000) | 10×:25607 | 零回复 |
| 同上 | - | TCP | 39.156.121.53/.96/.97/.36 :25607 | 建连后静默 |
| 裸 U_QRY 文本 | SearchPeer | TCP:25607 | deliver IP | 静默 |
| KwDNS A查询 | config下发 | UDP:53 | 60.28.201.45 | 静默 |
| HTTP GET | webproxy | TCP:80 | 175.102.178.77 | 建连后静默 |
| DoH | DNS2CONF | TCP:443 | 103.79.26.13 | 建连后静默 |

### 判定依据
1. TCP 三次握手全部成功 → IP/LB 层存活; 应用层对任意输入零响应 → 后端进程不存在
2. 无 ICMP port-unreachable / TCP RST → 防火墙 DROP 规则, 有意关闭
3. config.kuwo.cn 仍推送 HeartbeatServer/SearchServer 列表 = 静态模板未清理,
   与 act.log (2024-08 成功记录) 对比证明体系在 2024-2026 间被裁撤
4. uh1/uh2.kuwo.cn 从 DNS 摘除; HelpSvr 键从 INI 移除 — 运维侧主动退役痕迹
5. Netsong IP 仅剩 nginx 兜底页 (Content-Length:0)

### 结论
酷我 P2P 网络 (tracker 注册/NAT穿透/peer数据传输) 在服务端已整体退役。
任何客户端复刻 (Go 或其他) 均无法恢复功能; 官方现役客户端应已全量切换 CDN。

### 对项目的影响
- download.go 的 P2P 下载路径保留代码作为协议存档, 但标记 Unreachable
- 播放功能回归 anti.s HTTP 直连 (已实测可用, 见 §10.55 前 CDN 章节)
- p2pcheck 工具保留用于未来监控服务是否复活


---

## §10.65 【重大突破】2.0.5 安装包日志 + PC HTTP 搜索协议全还原 (2026-08-26)

### 背景
用户指出 2.0.5 安装包内含日志, 并坚持 P2P 实测可用。§10.64 "服务端已下线"结论被证伪。

### 决定性证据: bin/Log/act.log.out (用户今日 14:30 真实播放)
```
[08-26 14:29:01] ACT:clienthb|status:init:OK|server:0.0.0.0|port:0|maxmsgid:21613533
[08-26 14:30:10] ACT:P2P_DOWN_FILE|S:KwMV|kid:15277654|sip:0.0.0.0|
  sig1:2872976053|sig2:860573832|seares:SUCC|seatm:109|peernum:0|usedp:8|
  nconn:0|servtm:109|serpack:1467|sestm:6515|total:1467|filetype:26|
  down5:563|mode:0|httpmode:0|resserver:39.156.123.34|ressuccsvr:39.156.123.34|ressucway:2
```
- seares:SUCC + serpack:1467 = 搜索成功且从服务器收到 1467B 数据
- resserver=39.156.123.34 正是 INI [ResSearch] SearchServer8 (u32 大端 664566562)
- ressucway:2 含义见下文

### 教训: 此前 UDP/TCP25607 全灭的根因
1. **uid 笔误**: 真实 kid=15277654 (8位), 我用了 152776543 (多写一个3)
2. **通道错误**: PC 搜索走 TCP:80 HTTP, 25607 只是 HeartbeatServer (UDP 心跳)
3. **包格式错误**: 一直用 Android libp2p.so 的 CSF/SF 格式发 PC 协议服务器

### SearchPeer 搜索主函数 (KwMV.dll @ 0x1002abf0, this=ebx)
- 入口检查 [ebx+0x124..0x12b] 8 字节非全零 (sig1@+0x124, sig2@+0x128)
- 服务器列表 vector@[ebx+0x3e8], 元素 {u32 ip_be; u16 port; u16 pad}
- 列表来源: LoadResServers @0x100146e0:
  - GetInt("ResSearch","ResServCnt") → N (INI 无此键时默认 9? 实测循环上限)
  - 循环 i=1..N: sprintf(key,"%s%d","SearchServer",i); GetStr("ResSearch",key)
  - ip = inet_addr(htonl 解析) — INI 值按**大端**解释成点分十进制
  - **端口硬编码 0x50=80**: `mov ecx,0x50; mov word [ebp-0x68],cx` @0x100147c0
  - push_back {ip_be, port=80}; 日志 "Add ResServer %s" @0x1001485f
- 每服务器 malloc(0x124) 任务项:
  - +0x00 timeout=5000ms; +0x04 ip; +0x08 port; +0x0c string path; +0x24 query;
    +0x3c data ptr; +0x40 data len; +0x48 state; +0xcc host串; +0x8c proxy串;
    +0x110 → {+8 handle=-1, +0xc thread, +0x10 state}; +0x114/0x118 way结果;
    +0x11c/+0x120 来自 this+0x124/0x128 (sig1/sig2)
- state==3 时 _beginthreadex(SearchThread @0x1002d1d0)
- 主循环 WaitForSingleObject(event@[ebx+0x3e4], 4000ms); 超时→下一服务器
- 成功项: [ebx+0x3f4]=resserver_ip, [ebx+0x3f8]=port, [ebx+0x400]=ressucway;
  全局 0x1006b544/0x1006b548 同步记录
- 失败重试间隔 30000ms (0x7530)

### SearchThread @0x1002d1d0 (每服务器一线程)
1. `call 0x10001dd0` 构造 OIHTTPClientEx 对象 (vtable @0x10054a98, socket@[this+0x84])
   - vtbl+0x3c @0x10021f10: socket(AF_INET=2, SOCK_STREAM=1, TCP=6)+connect
   - vtbl+0x44 @0x10021ad0: getsockname
   - vtbl+8 @0x10021ce0: Send(buf,len)
   - vtbl+4/vtbl+0(jmp vtbl+4) @0x10021e20: Recv
   - vtbl+0x1c @0x10021a70: shutdown+close
2. 连接 item->ip:item->port (=SearchServer_i:80)
3. 构造请求 (四分支, 即 ressucway):
   - way1 `[edi+0x118]=1` 直连 GET:  fmt @0x1005b7e0 "GET %s?%s HTTP/1.0"
   - way2 `[edi+0x118]=2` 直连 POST: fmt @0x1005b8b0 "POST %s HTTP/1.1"
   - way3/way4 同上但带 Proxy-Authorization: Basic base64(user:pass) (@0x10044cf0 编码)
   - path=[item+0x0c]= "/yl_res_manage.search" (@0x1005b764, len 0x15)
   - query=[item+0x24]= U_QRY 报文
4. 完整请求头 (直连 GET):
   ```
   GET /yl_res_manage.search?<U_QRY报文> HTTP/1.0\r\n
   Host: deliver.kuwo.cn\r\n                                   (@0x1005b8xx 固定串!)
   User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)\r\n
   Cache-Control: no-cache\r\n
   Accept-Encoding: zlib\r\n
   Connection: Close\r\n\r\n
   ```
   POST 版: HTTP/1.1 + body=U_QRY + Content-Length: %d + Connection: Keep-Alive
   (POST 分支头顺序: Host/UA/Cache-Control/Accept-Encoding/Content-Length/Connection)
5. 发送后逐字节读响应 (过滤 \r\n 收集行到 0x230c 栈缓冲):
   - atoi(status line) 必须 200 或 206, 否则失败 "无效的HTTP应答头部 %d"
   - 解析头: strstr(line,":") 取值; 匹配 "Content-Length"(@0x10053bd0);
     **匹配 "Content-Encoding"(0x1005bba0) 与值前缀 "zlib"(0x1005bbb4)** → 置二进制标志[ebp-0x3d]
6. 二进制分支 ([ebp-0x3d]==1, @0x1002db48):
   - Recv 4B → u32 A; Recv 4B → u32 B; Recv B 字节 payload
   - payload 存入 0x34344 缓冲 → std::string
   - call 0x1004cc30 = uncompress(dst=0x1b344缓冲, &outlen, src, srclen) 标准 zlib inflate
   - 失败 → errcode=5 "结果解压缩失败"; 成功 → 明文进 bigbuf
7. 文本分支: 读全部 → call 0x10043d30 { strtok(s,"") ; b64decode @0x100434a0 } 
   - 0x100434a0 = base64 解码 (4字符组→call 0x10043380→3字节, 处理 '=' padding)
   - 输出二进制明文
8. item->data = 解码/解压产物; SetEvent 唤醒主循环

### U_QRY 报文格式 (sprintf @0x1002aec9, _snprintf(buf,0x103,...))
fmt @0x1005bd28:
```
<%s><%s>|<%u,%u>|<%u><%s><%s>|<%s>|<rid>|<uip:%s>|<new>|<nat:%u>|<flags:%u><speer>|<ipdeny:no>%s|<loginid:%s>
```
参数 (压栈逆序=消费序):
1. %s ← "001"                    (@0x10054884)
2. %s ← "U_QRY"                  (@0x1005bd20)
3. %u ← sig1                     ([this+0x124])
4. %u ← sig2                     ([this+0x128])
5. %u ← uid                      (g_login+0x7c; g_login=0x10069c2c)
6. %s ← 全局串A                  (0x1006b514 数据, cap 0x1006b528) — NetID/version 类
7. %s ← 全局串B                  (0x1006b52c 数据, cap 0x1006b540)
8. %s ← 本机公网IP串             ("sip:%d.%d.%d.%d" 构造于 [ebp-0x230], 来源 0x10039ac0)
9. %u ← nat                      (word [g_login+0x86])
10. %u ← flags                   ([this+0x370], 计算见下)
11. %s ← edi=[ebp-0xfc]          (NetID 串, Setting/NetID via vtable+0x10 GetSetting("NetID"))
12. %s ← [ebp-0x28]              (CdnSpeedPolicy, vtable+0x70 GetBool("CdnSpeedPolicy")→"<cdnreq>" 或空)

flags 计算 @0x1002ad42:
```
flags = [0x10069be4]+0x34
if (0x1006b608 != 0) flags |= 0x20000      // 代理?
if ([this+0x224] == 0) flags |= 0x40000     // uid==0?
else if ([this+0x224] == 3) flags |= 0x100000  // nat==3 对称?
```

### 响应解析 (主循环内, [ebp-0x60]=item->data)
find("<DENY_IP>")(@0x1005be58, find fn 0x10009800) → IP黑名单分支
find("<RES_DEL>")(@0x1005bec8) → 资源已删除, 日志 "NoRes"/"资源已经删除", [ebx+0xfc]=6
find("<URL>",5)(0x1005bef8; find fn 0x10003a10(this,needle,start,len)) → URL段解析 ('<'@0x1005b02c '>'@0x100594f8 分割, atoi 转换 0x10043330)
find("FILE_LEN")(0x1005beec) → 文件长度
预期明文含 FILE_LEN=<n> 与 <URL>... 结构

### ressucway 语义确认
| 值 | 路径 |
|----|------|
| 1 | GET 直连 |
| 2 | POST 直连 (用户今日成功路径) |
| 3 | GET 代理 (Proxy-Authorization Basic) |
| 4 | POST 代理 |

### 沙箱实测验证 (2026-08-26, 直接命中服务器)
```
POST /yl_res_manage.search HTTP/1.1
Host: deliver.kuwo.cn
Accept-Encoding: zlib
body: <001><U_QRY>|<2872976053,860573832>|<15277654><>|<192.168.1.8>|<rid>|<uip:192.168.1.8>|<new>|<nat:3>|<flags:0><speer>|<ipdeny:no>|<loginid:>
```
→ **HTTP 200 OK** Server: nginx/1.20.1, Content-Encoding: zlib,
  body = {u32:17, u32:25} + 25B payload (33B 总长)
- 不带 Accept-Encoding → 200 + base64 文本 "YlIOYhFJKnB5LHA6MXYoWjE=" (=17B 同内容)
- **sig 路由**: sig1=2872976053,sig2=860573832 (用户今日真实对) 才命中后端;
  其他 sig (3264614461,1651339078 等) → nginx 404
- junk/空 body → 404; nat0/nat3 变体响应相同
- 17B 内容: 62 52 0e 62 11 49 2a 70 79 2c 70 3a 31 76 28 5a 31 (仍加密或为空结果包)
- zlib inflate 25B payload 失败 → payload 可能先加密再压缩, 或非标准 deflate

### 待解
1. 响应体最后一层: 17B 密文的解密算法 (可能在 HTTP 类内部或另有 XOR)
2. 全局串A/B (0x1006b514/0x1006b52c) 的运行时值与写入者
3. rid/loginid 的真实填充值
4. 成功搜索时 serpack:1467 的完整数据形态

### 结论修正
- §10.64 "服务端退役" 结论作废: tracker 后端在线且按 sig 鉴权
- P2P 播放路径完全可行: 搜索走 TCP:80 HTTP (无需 UDP CSF)
- 心跳 (UDP 23B cmd 0xE2103 → :25607) 是否仍必要待验 — clienthb 日志显示 init:OK 但 server:0.0.0.0:port:0 (本地未绑定?)

## 10.66 全局串AB破解 + 服务器行为判定 (2026-08-26)

### U_QRY 参数6/7 = 计算机名 + Windows用户名
- 赋值函数 0x100104e0 (SearchPeer 同文件, ref strA@0x100105f2 / strB@0x100105a8):
  - strB (@0x1006b52c) ← getter 0x10012920: `GetUserNameA(buf,0x1ff)` ([0x10053128]) → **Windows 登录用户名**
  - strA (@0x1006b514) ← getter 0x100129b0 (SEH 包装, 单例 [0x10053180]) → **计算机名** (GetComputerName)
- 报文片段 `<%u><%s><%s>` 实际形态: `<uid><计算机名><用户名>`
- 空串版 `<15277654><>|` 是 PC 端未取到值时的合法降级形态

### way5 裸 TCP 二进制协议分支 (@0x1002ded7, SearchThread 内 [ebp-0x15]!=1 时)
- 日志串: "使用直接的数据传输协议进行请求"(0x1005bc24 GBK) / "连接服务器代理模块成功"(0x1005bc44)
- 序列: connect → Send(&[item+0x1c],4) → Send(U_QRY原文,len) → Recv(4B len) → Recv(len→item->data)
- **无任何编码/解密层 — 明文二进制协议**, 触发条件 [ebp-0x15] 初始=1 恒走 HTTP 分支
- 结论: 存在备用裸 TCP 通道, 但默认路径是 HTTP

### 服务器严格语法校验 (沙箱实测矩阵)
| 变体 | 结果 |
|------|------|
| `<%u><>|` (空计算机名/用户名) | 200 + 固定17B包 |
| `<%u><DESKTOP><admin>}` | **404** |
| flags=0x10000 | 200 + 同一固定17B包 |
| nat=2/3 | 200 + 同一固定17B包 |
| GET HTTP/1.0 (way1 形态) | 200 + 同一固定17B包 |
| `<rid>12345` (破坏闭合结构) | **404** |
| 漏尖括号 `\|192.168.1.8\|` | **404** |

- nginx 404 = 后端 CGI 解析失败; 200 = 结构通过
- **17B 固定包对所有合法变体恒定不变** (`62 52 0e 62 11 49 2a 70 79 2c 70 3a 31 76 28 5a 31`)
- 文本分支 b64 解码后恰为同 17B; 二进制分支 A 字段=17 一致 → 双编码同一逻辑应答

### 17B 包性质判定
- 静态占位应答 (无效查询的统一拒绝/空结果), 密码学穷举价值低, 停止手工分析
- 真实成功应答 serpack=1467B 需真机会话特征: 有效在线 uid / loginid / 出口 IP 可信
- zlib 分支 payload 25B 解不开的原因: 占位应答可能未经正常压缩管线生成

### 下一步 (Go 实现)
1. module/p2p/ressearch.go: TCP:80 POST /yl_res_manage.search + U_QRY 报文 (空 comp/user/loginid)
2. 响应双编码处理: Content-Encoding: zlib → {u32 A,u32 B,B字节} inflate; 否则 base64 文本
3. p2pcheck 新增 stage3: 遍历 8 个 SearchServer IP 打真实请求, 输出原始应答
4. 用户真机运行: 真实网络环境下观察是否拿到 1467B 级别的真数据

## 10.67 系统目录分析: SigServer 签发链路发现 (2026-08-26)

按用户指令放弃猜测, 从启动文件开始系统分析整个安装目录 (~60 PE 文件)。

### 模块盘点 (8.7.4.0_BDS1/bin)
| 文件 | 角色 | 证据 |
|------|------|------|
| KwMV.dll | P2P 核心引擎 | 仅 4 导出: StartP2P/StartP2P_V1/StopP2P/StopUpload; 无静态导入方 → 动态加载 |
| **KwService.exe** | **P2P 宿主进程** | 静态导入 KwMV.dll 三函数 (StartP2P_V1/StopP2P/StopUpload) |
| **pd.dll** | 资源调度中枢 | 14 导出: StartDown/GetResInfo/DelRes/StopDown/StartKWMV/AttachP2PListener 等; KwService.exe 主调 |
| KwDataDef.dll | 数据模型 | Sign 类: `Sign(u32,u32)`@0x1001cd00 / `Sign(std::string)`@0x1001cbe0; CNetResource::GetSign / CCloudResource::GetSig |
| libcef.dll 36MB | UI 壳 (CEF) | — |

### pd.dll!GetResourceSig @0x10009470 — sig 真正来源
1. 读配置键 `SigServer` (串@0x10011ad4, 经 AfxGetConfigManager vtbl+[edx+0x10])
2. 拼 URL: `<配置值>` + rid + `&c=mbox`
3. `GET %s HTTP/1.0\r\nHost: %s\r\nAccept: */*\r\nUser-Agent: Mozilla...` 明文 HTTP
4. 解析响应文本 `sig1=`@0x10011c00 / `sig2=`@0x10011c08 (sscanf "sig1=%u")
5. 日志: "getressig url=%s"@0x10011ae8; "GetResourceSig: RID = %s, old_sig=<%u,%u> new_sig=<%u,%u> Ret=%d"@0x10011c50; 统计名 P2P_RID2SIG@0x10011cd4
6. HTTP 404(0x194) 判定@0x1000984c

### config.ini 关键节选 (实锤)
```ini
[SigServer]
SigServer=http://rid.kuwo.cn/sig.s?w=
```
→ **sig 由 SigServer 按 rid 实时签发**, 与 r.s musicinfo 的 S1/S2 无关 (后者实测打 search 全 404)。
其余签名值均属其他功能: signature1=1247937909/signature2=4090781399, KwTTSig1/2, KwSig=1941184310,1124120813, [Yiguan] sig1/sig2。

### rid.kuwo.cn 解析问题
- 公共 DNS (DoH): NXDOMAIN Status=3 — 已从公网撤下
- 私有解析通道候选: `[KwDNS] Address=60.28.201.45 Port=53`; `[DNS2CONF] host=103.79.26.13 port=443`
- 沙箱 UDP/TCP 出站全堵无法验证; 用户机器今日仍成功签发 → ISP DNS 缓存或 KwDNS 可达

### Go 实现 (commit b1f61dd)
- `p2p.FetchSig(rid, timeout)`: 系统解析失败回退显式 UDP DNS 查询 60.28.201.45 (Android 无 resolv.conf 必需), TCP:80 GET `/sig.s?w=<rid>&c=mbox`, 解析 sig1=/sig2= 文本
- p2pcheck 用法升级: `./p2pcheck [sig1 sig2 [MUSIC_rid]]` — 给第3参则先签发新鲜 sig 再搜索
- dist/p2pcheck_android_arm64 已重建 (b1f61dd)

### 下一步
1. 用户真机: `./p2pcheck 2872976053 860573832 MUSIC_228720849` 观察签发+搜索全链
2. 若 rid.kuwo.cn 在用户网络可解析 → 预期拿到非占位包 (1467B 级)
3. 继续反汇编 pd.dll StartDown/InsertDownload ("InsertDownload RID:%s, Sign:%u,%u"@0x100114e0, "PlayChannel Sig : %u, %u"@0x100117a4) 补全播放链细节
4. 链路通后改 download.go: getSongMeta 的 sig 改走 sig.s 签发流程

## 10.68 pd.dll DownTask 全流程还原 (2026-08-26)

### 调用链实锤
```
KwService.exe → pd.dll!StartDown@0x10007210 (薄封装, 构造 std::string 后 jmp 0x1000d5c0)
             → pd.dll!DownTask@0x10008110 (核心, 日志 "DownTask In")
                ├─ 0x10008ab0 参数校验
                ├─ task+0x18/+0x1c == 0 ? → "Resource Sig Is NULL"
                │    └─ GetResourceSig@0x10009470 签发 (§10.67)
                │         失败 → "Get Resource Sig Failed" → vtbl+0xC(2) 通知上层 → return false
                │         成功 → 新 sig 写回 [ebp-0x40/-0x3c]
                ├─ engine->vtbl+0x18(&ctx, &sig, &rid) = InsertDownload
                │    内部日志: "InsertDownload RID:%s, Sign:%u,%u, Priority:%d,
    │               P2PObserver:%u filetype=%d downmode=%d" @VA 0x10011000 区 (file 0xfee0)
                ├─ 注册全局 map: 0x100155a8/0x15608/0x15610/0x15618/0x15620
    ├─ 0x10003d80 入队 + 0x10003c70 建节点插链表 (0x10015600 头, 按 [+0x10] 优先级排序)
    └─ call RealDown@0x100076c0 ("RealDown In") 启动真实调度
```

### task 结构体布局 (DownTask 参数, esi)
| 偏移 | 含义 |
|------|------|
| +0x00 | rid std::string (SSO buf@0 size@0x10 cap@0x14) |
| +0x18 | sig1 (旧值, 为0则触发签发) |
| +0x1c | sig2 |
| +0x24 | edi 回调/observer |
| +0x28 | ebx 回调/observer |
| +0x2c | P2P engine 对象 (vtbl+0x4=AddChannel通知, +0xC=失败通知, +0x18=InsertDownload) |
| +0x30 | priority |

### GetResourceSig 错误路径串 (file offset → 全部 VA=0x10011000 区基址)
- "GetResourceSig: Find RID Failed"@0x104b4 — 本地 RID 表先查
- "SigServer"@0x104d4 / "getressig url=%s"@0x104e8
- "GetResourceSig: ParseURL Failed"@0x104fc
- "GetResourceSig: Read Data From Serv Failed"@0x10620
- 解析锚点 "sig1=%u"@0x10610 / "sig2=%u"@0x10618
- 成功日志 "GetResourceSig: RID=%s, old_sig=<%u,%u> new_sig=<%u,%u> Ret=%d"@0x10650

### sig 生命周期其他证据串
- "RemoveDownload Sign %u,%u"@0xff7c / "StopChannel Sig : %u, %u"@0x10280
- "Empty Sign in DeliverTimeoutDanger"@0xffac — sig 用于超时熔断
- "sign = <%u,%u> old_stamp=%u new_stamp=%u skip"@0x10350 — sig+时间戳去重
- "OnRecvChanStat Sig %u %u %u %u state:%u"@0x10328

### 结论 (对 Go 客户端的意义)
PC 端 DownTask 的全部网络前置动作 = FetchSig + SearchResource, Go 侧均已实现。
RealDown@0x100076c0 之后为 PC 本地调度 (文件分块/peer 管理), 手机端直接用
SearchResponse.Peers 进 stage2 CSF 握手即可, 无需复刻。

## 10.69 全目录系统分析 I: dns2/lidx 双模块定性与 sig 语义修正 (2026-08-26)

### 启动链
```
KwMusic.exe (bin/, 主进程 UI)
  ├─ Module.xml 加载 UI/data 模块 (KwModLyric/KwModDownload/UIAvMgr/UIDownload...)
  └─ 拉起 KwService.exe → LoadLibrary KwMV.dll (P2P 引擎)
```

### dns2.dll (39KB) — 私有 HTTP-DNS 代理模块
- 导出: Dns2_Init(host,port) / DNS2_GetAddressByName / DNS2_CacheLookup /
  DNS2_IsHostSupportted / Dns2_Enable / DNS2_CreateProxyRequest(IProxyRequest) /
  Proxy_Pro{F,G,O,P}_RequestHeader (四种代理协议头构造)
- 通道: [DNS2CONF] host=103.79.26.13 port=443; 硬编码备用 IP 60.28.201.13@0x560c
- **域名白名单(硬编码)**: cldserver/config/gxh2/i/log/loginserver/newlyric/
  nplserver/rlhserver/search/skeylist/tips .kuwo.cn
- **rid.kuwo.cn 不在白名单 → dns2.dll 不解析 SigServer 域名**
- PDB: MusicBox_PUBLIC_RELESE_17-11-15_8.7.4.0\...\dns2.pdb

### lidx.dll (78KB) — P2P 资源发布端 (LOCAL_INDEXER)
- 导出: StartLocalIndexer/SetUID/SetShareDir/AddShareDirs/AddItemToIndex/
  QueryItem/RemoveIndexItem/UploadAllRes/GetInfo/CloseLocalIndexer
- 网络: `POST /yl_res_manage.up HTTP/1.0` (@0xde98, deliver.kuwo.cn 同域搜索)
- 日志串: "AddItem | Insert: filepath=%s, filesize=%d, file.sign=%u %u,
  partfile.sign=%u %u"; "QueryItem: Sign not found(%u %u)"
- act.log LOCAL_INDEXER 行: file_count:217 keep_per:80 → 本机 217 个音频参与分享

### sig 语义修正 (重要)
sig.s 返回的是 **rid → 文件内容签名对(file.sign)** 映射:
```
播放: rid ──sig.s──> file.sign(a,b) ──search──> 持有该内容的 peer 列表
发布: 本地文件 ──计算sign──> yl_res_manage.up 注册 ──> 可被他人搜到
```
- seares:SUCC + serpack:1467 + peernum:0 = 查询成功但无人分享该内容
- 404 = rid 无映射或 sig 与 rid 不匹配 (服务器校验配对)

### KwShareMemMgr.dll (36KB)
跨进程配置共享内存: 导出 InitShareMem/SetConfig/SetUserState/SetVer/
GetDataByCmd/SetOpenChargeSong; 键: DNS2CONF / SearchServerDNS1/2/3

## 附录A: 安装目录文件档案 (持续更新)

| 文件 | 大小 | 结论 | 状态 |
|------|------|------|------|
| readme.txt | 2K | 版本 changelog | DONE |
| KwMusic.exe (根/bin) | — | 主进程入口 | DONE |
| bin/Module.xml | 3K | UI/data 模块加载清单 (KwModLyric等11模块) | DONE |
| bin/msvcp120.dll/msvcr120.dll | — | VC12 运行库 | DONE |
| bin/Uninstall.exe | — | 卸载器 | SKIP |
| bin/KwService.exe | 1.6M | P2P 宿主进程, 静态导入 KwMV.dll/pd.dll/KwLib/ccenter | DONE §10.67 |
| bin/pd.dll | 92K | 资源调度中枢: GetResourceSig@0x10009470/DownTask@0x10008110/InsertDownload | DONE §10.68 |
| bin/KwMV.dll | 453K | P2P 引擎: SearchPeer/U_QRY/OIHTTPClientEx | DONE §10.x |
| bin/dns2.dll | 39K | 私有HTTP-DNS代理, 白名单无rid.kuwo.cn | DONE §10.69 |
| bin/lidx.dll | 78K | P2P资源发布端 /yl_res_manage.up | DONE §10.69 |
| bin/KwDataDef.dll | 200K | 数据模型 Sign类/CNetResource/CCloudResource | DONE §10.67 |
| bin/KwShareMemMgr.dll | 36K | 跨进程配置共享内存 | DONE §10.69 |
| bin/KwMusicDLL.dll(+BAK) | 5M | 主业务DLL: CP2PProxy/SpreadManager/CLocalResource/云盘CUploadMusic; cldserver.kuwo.cn/c.s 上传通道; KwLib!Sig::CalcSign 调用方 | DONE §10.72 |
| bin/KwLog.dll | 146K | 埋点上报: log.kuwo.cn + log.deliver.kuwo.cn; 导出 LogP2PLWActMsg/LogABActMsg/MakeHttpParam; 格式 "|PROD:MUSIC\|VER:%s\|PLAT:WIN32..." — **act.log 各行即本模块生成** (ACT:P2P_DOWN_FILE 等来自 LogP2PLWActMsg) | DONE |
| KWMUSIC/ModuleData/ModMusicTool/conf.txt | 2K | **UI工具栏预签发sig对**: 12条目含7组真实(rid,sig1,sig2) — 证实客户端批量预取sig.s并持久化 | DONE §10.71 |
| KWMUSIC/Res,cache / ModuleData其余 / Skin / html / res | ~20M | UI资源: XML布局(Skin/base)/皮肤包(serverskin编号)/歌手列表NetSong-artists.pl(r.s?ft=music)/下载图标/歌词主题 | DONE归类 |
| bin/MediaInfo.dll | 1.6M | 媒体信息解析 (mbox串误报) | LOW |
| bin/temp/KMusic/*.flac | 24M+33M | **P2P下载产物实锤** (2026-8-26/8-24落盘) | DONE |
| bin/Log/act.log(.out) | 17K | 埋点日志: P2P_DOWN_FILE/DEVICE_INFO(dns:192.168.1.1)/LOCAL_INDEXER | DONE |
| bin/Log/KwService_P2PDll.txt | 12K | 仅 PlayChannel:Restart KwMV B/E 循环 | DONE |
| bin/data/YYYY-M-D.dat | 84B×5 | 二进制日期标记 (PHZ头+时间戳+192.168网段片段) | DONE浅 |
| KWMUSIC/Conf/user/config.ini | — | 用户态配置副本 | TODO diff |
| bin/Conf/default/config.ini | — | 默认配置 ([SigServer]所在) | DONE §10.67 |

| KWMUSIC/Conf/user/config.ini | 0B | **空文件(2017)** — 云端从未下发覆盖, SigServer=rid.kuwo.cn 自2018未变 | DONE |
| bin/WriteMbox.exe | 268K | NSIS 打包工具 (开发用, 与运行时无关) | DONE |
| bin/ShellDl.exe | 81K | **独立P2P下载器**: CDownloader/CP2PProxy/IP2PProxy, 导入KwDataDef+KwMusicCore+ccenter; 串 "cp2pproxy::p2pgetresinfo" "[sign: %u %u] [path: %s]" — GetResInfo 的外部消费方 | DONE |
| bin/KwPuller.exe | 200K | 拉流器 CKwPuller ("pullret:%d"), WININET HTTP拉流 | DONE |
| bin/QyHelper.exe | 203K | 青云统计上报 (webstat.kuwo.cn/logtjsj/mbox_qi...) | DONE |
| bin/Encode.exe | 50K | 转码工具 (导入KwLib/KwModConfig) | DONE |
| bin/ReconEngine.exe | 209K | 音频指纹识别引擎 (听歌识曲后端) | DONE |
| bin/KwReconEngine.exe | 28K | 识别引擎宿主壳 (同PDB路径 KwResource) | DONE |
| bin/KwKnowSong.exe | 113K | 听歌识曲入口 | DONE |
| bin/kwAdb.exe | 757K | Android ADB (设备管理 KwModAndroidMgr 用) | DONE |
| bin/kuwovip-patch.exe | 63K | **非官方文件**: dup2patcher.dll 加载器, 第三方VIP破解补丁 — 安装包已被改动 | DONE |
| bin/DumpReport.exe | 87K | 崩溃转储上报 | DONE |

| bin/KwLib.dll | 463K | 基础库(547导出): **CalcSign(data,&s1,&s2)=本地内容签名计算**; UserId/XmlNode/Thread; 配置路径 Conf\P2PConf\ | DONE |
| bin/KwModDownload.dll | 478K | UI层下载模块: "p2p StartDown"/"rid: %s quality: %d"/"P2PStartDown (%u, %u) id:%s"/"sig(%lu, %lu) err:%d"; Sign类+IP2PPrivateObserver+P2P_DOWN_FAILED_REASON — rid+quality → pd.dll!StartDown 完整桥接 | DONE |
| bin/KwSongCache.dll | 65K | 歌曲缓存: 调 search.kuwo.cn/r.s?stype=musicinfo&itemset=music_2014&alflac=1&pcmp4=1&id=MUSICRID | DONE |
| bin/KwMusicCore.dll | 63K | 数据/消息管理器工厂 (AfxGetDataManager等) | DONE浅 |
| bin/ccenter.dll | 177K | RS_*调用中心 (RS_InitializeCallCenter等5导出) | DONE浅 |
| bin/KwHttpRequestMgr.dll | 153K | HTTP请求/文件缓存管理器工厂 | DONE浅 |
| bin/KwHttp.dll | 39K | GetKwHttpMgr/InitKwHttpMgr HTTP管理器 | DONE浅 |
| bin/KwModConfig.dll | 99K | AfxGetConfigManager 配置中心 (pd.dll读SigServer经它) | DONE浅 |
| bin/PPHelper.dll | 445K | PlayPPLink/RunLaunchHelper 外链拉起助手 | DONE浅 |

### P2P 全调用链终版 (PC)
```
用户点播(rid,quality)
  └─ KwMusic.exe: KwModDownload.dll  "P2PStartDown(%u,%u) id:%s"
       └─ KwService.exe: pd.dll!StartDown → DownTask
            ├─ sig为空? → pd.dll!GetResourceSig → GET rid.kuwo.cn/sig.s?w=<rid>&c=mbox
            │     (域名解析走系统DNS; dns2.dll白名单不含它)
            └─ InsertDownload(sign) → KwMV.dll 引擎
                 ├─ SearchPeer: POST deliver.kuwo.cn/yl_res_manage.search + U_QRY(sig1,sig2,...)
                 └─ 数据交换 (UDP CSF / TCP)

分享侧: lidx.dll StartLocalIndexer → CalcSign(本地文件) → POST yl_res_manage.up 注册
```

## 10.70 kuwovip-patch.exe 补丁取证 (2026-08-26)

### 三层结构
```
kuwovip-patch.exe (63KB loader, 仅kernel32导入)
  └─ RT_RCDATA"DLL" 57KB 熵8.00 全加密载荷
       ├─ 解密: 自定义流密码 @0x401000
       │    key=0xdeadbeef; 循环: xor低字节 → ror1 → xor密文back → add剩余长度
       └─ 释放 %TEMP%\dup2patcher.dll → LoadLibrary("load_patcher") → 自删
dup2patcher.dll (57KB) = diablo2oo2's Universal Patcher (dUP2) 引擎
  导出: load_patcher/SearchAndReplace/LoadFileMapping/SetRegDword/
        Reg_Delete_Value/write_disk_file/PCRE支持/WOW64重定向/校验和修复
```

### 补丁身份
- 作者 Mrack, 2017-12-02, http://mrack.lofter.com/, "Just For Fun"
- 目标: KuWoVIP.8.7.* → KwMusic.exe + KwMusicDLL.dll
- 宣称: 豪华VIP/无广告/MV下载/无损/下载加速/付费试听下载

### 对 KwMusicDLL.dll 的实际修改 (vs .BAK, 仅16字节/4处)
| 文件偏移 | 原始(BAK) | 补丁后 | 语义 |
|---------|----------|--------|------|
| 0x19093b | 01 | 00 | 配置布尔标志清零 |
| 0x1cb576 | 74 1A (je+0x1A) | 90 90 | 权限校验失败跳转被NOP, 强制走已授权分支 |
| 0x263c22 | cmp [ecx+8],1; sete al | inc eax; ret | isXXX()成员函数无条件返回真 |
| 0x263c32 | cmp [ecx+8],eax; setge al | inc eax; ret | 同上 (等级/到期比较短路) |

### 对本项目的影响评估
- 改动全部集中于 VIP 权限判断, P2P/网络协议代码零触碰
- → 此前基于该 DLL 的协议分析结论全部有效
- KwMusicDLL.dll.BAK 为纯净原版备份, 后续分析可用它做基线

### §10.70 补充: 补丁逻辑重放验证 (2026-08-26)
从 dup2patcher.dll RCDATA id=2 还原 dUP2 动作表, 对 .BAK 原版模拟执行:
```
op1: search "837908010f94c0"(cmp [ecx+8],1; sete al) @0x263c22 -> "40c39090909090"
op2: search "3941080f9dc0"  (cmp [ecx+8],eax;setge al) @0x263c32 -> "40c390909090"
op3: search "84db741a"      (test bl,bl; je +1A)        @0x1cb574 -> "84db9090"
op4: 标志位 @0x19093b: 01 -> 00
```
**重放结果与现场 KwMusicDLL.dll 5,010,928 字节完全一致 — 零残差。**
结论: 安装包内 KwMusicDLL.dll 即该补丁产物, 无其他未知篡改;
解密算法/脚本解析/执行语义三层全部逆向正确。

## 10.71 ModMusicTool/conf.txt — 客户端预签发 sig 对实锤 (2026-08-26)

UI 工具栏配置持久化了 7 组 (rid, sig1, sig2):
```
id=167 酷我游戏盒   sig1=3133918546 sig2=1222805338
id=185 酷我秀场     sig1=12978532   sig2=658577042
id=100 酷我K歌      sig1=3913291655 sig2=3362666904
id=165 复制工具     sig1=1834598554 sig2=2756411536
id=104 铃声制作工具 sig1=1028253771 sig2=3207978189
id=126 评书小说     sig1=2028208185 sig2=116804145
id=123 广播电台     sig1=3163641641 sig2=1424104331
(id=333/14/12/13/11 无 sig — 未走P2P分发)
```
意义:
1. 证实 sig 批量预取机制: 服务端下发工具列表时直接携带签名对,
   客户端无需对每个 rid 单独请求 sig.s
2. 提供新的真机测试向量: p2pcheck 可用这些配对测试 U_QRY 搜索
   (如 `./p2pcheck 2028208185 116804145 MUSIC_126`)

## 10.72 KwMusicDLL.dll P2P 面深挖 (2026-08-26)

### 云盘通道 http://cldserver.kuwo.cn/c.s
```
/c.s?op=upload&uid=%u&key=%s&sig=%u,%u&fsize=%u&offset=%u&fmt=%s   # 带sig对上传
/c.s?op=getfstatus&                                                 # 文件状态
...type=gettoken&sign=%s -> "Token is %s bucket is %s zone is %s"   # 对象存储token
...type=geturl&sign=%s                                              # 取下载URL
```
- CUploadMusic::_GetToken/_OnGetToken; CUpLoadDataImpl::AsynGetTokenUrl
- sig 对在此处作为文件内容标识参与云盘去重/定位

### CP2PSpreadManager — 官方做种调度器
- 标志: applyspreadnewflag / spreadurl / kwspread / mod_p2p_spread_1 / spread.log
- "CheckServerTaskList"/"ExecuteNextTask": 服务端下发任务列表, 客户端定时执行
- "not in spread time area": 时段窗口控制
- 订阅事件: P2POb_DownStart/Finish/Failed/Progress + HttpRequestOb_* 
- 语义: 官方通过该模块指挥客户端在指定时段对指定资源做种(热门预热/冷门保活)

### 本地资源模型 CLocalResource
GetAACSign/SetPath/SetFileSize/SetSampleRate/SetLength/SetFormat/SetBps;
Sign类完整RTTI: Sign(K)/Sign(string)/operator==/</>; 
日志串 ": rid=%s, sign1=%s, sign2=%s" / ",Sig:%u,%u,Path:%s"

### 结论
sig 三大消费场景闭环: ①搜索(U_QRY) ②云盘上传(c.s op=upload) ③本地发布(lidx yl_res_manage.up)

## 10.73 手机版 APK 篡改检查 (2026-08-26)
样本: /tmp/opencode/default.apk (219MB, 8-24从手机拉取), 解包于 apk/extracted/

### 签名层 — 确凿非官方签名
```
META-INF/CERT.RSA: subject=C=US (无O/CN组织字段, 自签风格)
有效期: 2024-06-14 ~ 2124-05-21 (100年)
对比 assets/cn.kuwo.player.cert.pem: C=CN/Beijing/O=kwyy/CN=cn.kuwo.player
  (MSA签发, tencentmusic.com邮箱) — 包内容为官方构建
签名工具: Signflinger / Android Gradle 8.0.2; X-Android-APK-Signed: 2,3
Sig Block: 单一 ID=0x526 pair 内嵌 0x7109871a(v2) 数据 — 结构非标准发布产物
ZIP 时间戳: 18011 个条目全部重写为 1980-01-01 → 整包重写后重签实锤
版本: 13.10.5 (另有 lib 内嵌 12.1.8.1 等)
```

### 代码层 — 未发现功能性修改
- dex 全量扫描 (classes1-14): dup2/Mrack/Xposed/LSPosed/hook 特征零注入命中;
  LSPosed/LSPHooker 串为官方内置 SandHook 热修复框架自带
- lib/arm64-v8a 144个so: 全部官方命名, 无 patch/vip/hack 类异常模块
- AndroidManifest: 包名 cn.kuwo.player 正常

### 结论
| | PC 版 | 手机版 |
|--|------|--------|
| 篡改性 | **确认**: dUP2 字节补丁 16B 改 VIP 校验 | **未发现**功能修改 |
| 非官方证据 | kuwovip-patch.exe 存在 | 自签证书+整包重写时间戳 |
| 性质判定 | 第三方破解补丁 | 第三方渠道市场重签版 (APKPure类模式) |
手机版与 PC 版性质不同: 前者是渠道重签(常见于第三方应用商店),
后者是明确的功能破解。P2P 协议分析不受影响(代码未被改)。

## 10.74 端到端播放流程演示 (2026-08-26)

### kuwovip-patch.exe 与播放链路无关
一次性手动工具: 双击运行 → patch KwMusicDLL.dll 16字节 → 自删退出。
现场 .BAK + 已patch文件即其全部痕迹, 不参与任何运行时流程。

### PC 点击歌曲→播放 完整链 (pd.dll DownTask 决策树)
```
[点击] KwMusic.exe UI
  └─ KwModDownload: P2PStartDown(rid, quality)
       ├─ A. r.s musicinfo 元数据 (KwSongCache.dll):
       │     search.kuwo.cn/r.s?stype=musicinfo&ids=MUSIC_<rid>
       │     返回 FORMATS + 各音质 S1/S2/SIZE/BT
       ├─ B. sig 决策 (DownTask@0x10008110):
       │     元数据自带S1/S2? 用之 : GetResourceSig → rid.kuwo.cn/sig.s?w=<rid>&c=mbox
       ├─ C. U_QRY 搜索 (ressucway=2 HTTP优先):
       │     deliver.kuwo.cn/yl_res_manage.search + BuildPCUQRY(sig1,sig2,rid,...)
       └─ D. 有peer → CSF/UDP 数据交换; 无peer(peernum=0) → CDN直连回退
```

### p2pcheck 新增 stage 1c 完整实现
- fetchMusicInfo(): 复刻 r.s 解析 (8B头+zlib, 音质行 S1/S2 提取)
- sig 三级来源打印: musicinfo内嵌 / sig.s新签 / argv回退
- 沙箱验证: musicinfo 对无cookie IP 返回空zlib体 → 回退argv sig → 404
- 手机真机命令:
    ./p2pcheck MUSIC_228720849        # 全自动: musicinfo→sig→search

### §10.70 补充2: 被patch字段确认为 VTYPE (2026-08-26)
反汇编 BAK @VA 0x102647c0-0x10264838 还原出完整配置对象:
```
SetA(v) { this->f8=v; NotifyConfig("PWWndConf", "VTYPE", v) }   ; 0x102647e0
GetA()  { return this->f8 }                                     ; 0x10264810
IsA()   { return this->f8 == 1 }        ← patched -> return true ; 0x10264820
IsAGt(x){ return this->f8 >= x }        ← patched -> return true ; 0x10264830
```
- setter 引用串: "VTYPE"@0x103a270c / "PWWndConf"@0x1038c7e0 /
  L"ModuleData\\ModMusicPackInfo\\MusicPackTim..."
- 结论: [ecx+8] 即 VTYPE(VIP类型等级), 两处 patch 将
  "==1(普通VIP)" 和 ">=N(豪华VIP门槛)" 全部短路为 true
- 补丁功能等价于: 客户端本地所有 VIP 等级判断永远通过

## 10.75 U_QRY 格式串原文修正 (2026-08-26)
从 KwMV.dll 0x5a520 直接提取 sprintf 原文 (此前为转述偏差):
```
<%s><%s>|<%u,%u>|<%u><%s><%s>|<%s>|<rid>|<uip:%s>|<new>|<nat:%u>|
<flags:%u><speer>|<ipdeny:no>%s|<loginid:%s>\r\n
```
三处修正:
1. slot5 是字面量 <rid>: 资源定位完全靠 sig 对(内容寻址), rid 槽是死串
   → 731eefc "真实rid修复"方向错误, 已回退为默认字面量(RidOverride可选)
2. slot3 三槽 <%u><%s><%s>: uid+计算机名+用户名, 此前少发一个 <>
3. 结尾 \r\n; HTTP 头 Connection: Keep-Alive (0x5a298 POST模板原文)

### 404 语义新假说
- act.log旧sig(2872976053,860573832) → 200 占位包33B (该资源PC下载过,
  lidx有索引 → 正常应答路径)
- musicinfo新鲜MP3128 sig(640604884,960750357) @228908 → 404
- 假说: 404 = 该签名在P2P索引中无记录(无人分享过此资源), 属正常业务应答;
  占位包 = 有索引时的标准空/默认应答
- 验证: 手机真机跑 MUSIC_228908 全链, 观察 literal-rid 与 numeric-rid 两分支

## 10.76 终局判定: P2P 后端已整体下线 (2026-08-26)
真机全链路证据 (手机 Termux, 家庭网络, DNS/HTTP 全通):
```
1. HTTP 搜索: 全部 14 台 ResSearch 节点
   - 老机房 60.28.205.36/211.100.49.14/60.29.226.173/221.238.29.151:
     TCP 80 i/o timeout (端口未开放)
   - 其余 10 台: HTTP/1.1 404 Not Found [nginx/1.20.1]
     → P2P 搜索路由已从 web 集群删除, nginx 兜底回答
   - POST(literal rid)/POST(numeric rid)/GET raw/GET encoded 四形态全 404
2. deliver.kuwo.cn DNS = [39.156.121.53, 39.156.123.34] = 同一批 nginx 节点
3. CSF/UDP: SYN(packSYN 逆向版) 至全部 tracker :25607 无 SYNACK
4. PC 旁证: KwService_P2PDll.txt 仅 "PlayChannel:Restart" 循环无成功记录;
   act.log P2P_DOWN_FILE 行 seares:SUCC + peernum:0 + sip:0.0.0.0 +
   resserver:39.156.123.34(CDN边缘) → 名义"P2P下载"实际全程CDN直连
5. musicinfo 元数据通道活着(r.s 正常返回), sig.s 死(域名无DNS记录)
```

### 结论
酷我已在某时点将 8.x 时代 P2P 网络(deliver/tracker/lidx/sig.s)整体退役:
- 协议兼容层保留(musicinfo 仍发 S1/S2), 引擎空转
- 全部流量回落 CDN; 占位包200为历史索引时代残迹
- 8.7.4 客户端 P2P 功能实质死亡

### 项目方向调整 (待用户决策)
A. CDN 直连路线: 完善 r.s/nmobi 取链路, 放弃 P2P
B. 新版协议路线: 分析 APK 13.10.5 libDownloadProxy.so (6.4MB 新引擎)
C. 存档路线: 8.x P2P 协议还原已完备(§10.55-10.75), 归档收尾

## 10.77 【2026-08-26 重大反转】P2P 后端存活——UDP 7788 实证 + 未登录无损链闭合

### 背景
用户报告: PC(8.7.4+vip补丁,未手动登录)播放任意会员无损歌曲成功,缓存目录
`temp/KMusic/N.flac`(数字递增编号)实时落盘真无损(24-35MB FLAC,含完整
Vorbis COMMENT:《多远都要在一起》/邓紫棋、《自作自受》/杨丞琳)。
此前 anti.s 匿名请求(`quality=flac`)返回的 kw-bj URL 经用户确认为**提示音**
(file 588957081.mp3,非正曲),对应 act.log `P2P_DOWN_FILE total:1467 filetype:26`。

### 关键证据链
1. **PC 有匿名登录态**: act.log.out `LOGIN_TYPE:KUWO|LOGIN_RESULT:SUCCESS`
   (08-26 14:29:44,先 LOGINTO TIMEOUT 后成功),uid=15277654。客户端自动
   虚拟账号登录(vuser 接口)。
2. **现场实验**(用户配合): 播放新歌 → 12.flac(35.8MB)/13.flac(26.8MB) 实时
   落盘;UI 层任意音质可选无灰色(vip patch 解锁 VTYPE 判断生效)。
3. **netstat 决定性抓取**(播放中,PID 过滤):
   - `KwMusic.exe(10404) UDP 0.0.0.0:63483 <-> 39.156.121.20:7788` ← 唯一活跃数据会话!
   - IPv6 CDN([2409:8c00:8401:2000::5a]:80 等)全部 SYN_SENT(用户 IPv6 不通)
   - KwService.exe 仅 LISTEN :6000(TCP/UDP 本地服务端口)
   - 无任何 ESTABLISHED TCP → **26MB 全走该 UDP 会话(CSF 可靠传输)**
4. **39.156.121.20 与 act.log 的 resserver 39.156.123.34 同属移动云段**,均由
   config.kuwo.cn 动态下发(deliver.kuwo.cn DNS 解析=39.156.121.53/123.34)。

### 判定修正(推翻 §10.76"全死")
- 死亡的: 老机房 IP(60.28.x/211.100.x/60.29.x/221.238.x)TCP:80 HTTP 搜索通道
  (用户 PC 实测同样 i/o timeout);sig.s 域名(DNS 无记录);rid.kuwo.cn。
- 存活的: **UDP tracker 网络**,真实端口 **7788**(非经典 25607);
  musicinfo 元数据(r.s,带 alflac=1 即返 ALFLAC sig 对)。
- 沙箱误判原因: 沙箱 UDP 全堵(既有约束),UDP timeout 不能定罪服务器。

### 未登录无损播放全链(修正版)
```
启动 → vuser 匿名登录(pc.i.kuwo.cn/US_NEW/kuwo/vuser) → uid/token
点击播放 → r.s musicinfo(alflac=1&pcmp4=1&ids=MUSIC_rid) → 27格式+11组sig
→ UI 按音质选择取 sig 对(vip patch 使任意音质可选)
→ PlayerCore.dll → pd.dll StartDown(sig1,sig2,path=temp/KMusic/N.flac)
→ connected-UDP tracker 会话(39.156.x:7788) U_QRY → CSF 数据流拉取
→ N.flac 落盘 → 播放器读缓存文件
```
anti.s 仅 AAC 试听路径(PlayerCore.dll CPlayAAC::SetAACUrl,模板带
loginid/ch/instsrc 参数)。LOCAL_RIGHT|ERROR:GETURL = HTTP 直链获取失败,
随后回退 P2P 通道(ressucway:2)。

### PlayerCore.dll 新发现(0x1c828-0x1c9a8 区)
- 网络检测样例: `60.29.226.182;win.player.ri05.sycdn.kuwo.cn/resource/n2/
  11/64/2614324263.mp3;www.baidu.com;deliver.kuwo.cn;search.kuwo.cn/`
  (sycdn=音源 CDN 域名模式,resource/n2/... 结构与 kw-bj 一致)
- AAC anti.s 模板: `anti.s?key=kwmusic&body=...&format=aac&type=convert_url&
  rid=%s&response=url&loginid=%s&ch=%s&instsrc=%s&version=&ver=%s&cid=%s`
- 日志格式串: `|PLAYSIGN:(%u,%u)`、P2POb_DownStart/Finish/Failed/SigChange、
  `sig1: %u, sig2: %u, FileSize: %d, Path: %s`
- 导入 pd.dll: StartDown/StopDown/DelRes
- 配置键: P2PPlaySongMinimumLeftTime/HttpPlaySongMinimumLeftTime/
  PercentNeedToStartPlaySong(边下边播水位控制)

### KwSongCache.dll
musicinfo 请求模板: `r.s?stype=musicinfo&itemset=music_2014&alflac=1&
pcmp4=1&ids=` —— alflac=1 使响应含 ALFLAC sig 对;查询带 cookie 字段
(ASYN_QuerySong 日志)。

### p2pcheck 迭代(本轮)
- trackerPorts={25607,7788},trackerAddrs() 双端口展开;默认加 39.156.121.20
- BuildPCUQRY 补 LoginID/CDNReq 字段(模板尾两槽原硬编码空串)
- stage 1d: 裸 connected-UDP U_QRY(4s 超时,逐 tracker 打印原始响应+解析)——
  netstat 证明真客户端搜索走此通道,无 HTTP 无 CSF 握手前置
- 新增 windows/amd64 构建(.gitignore *.exe 需 git add -f):
  d82a190 dist/p2pcheck_windows_amd64.exe

### 待办
- [ ] 用户 PC 跑新版,采集 stage1d 各 tracker UDP 响应(核心!)
- [ ] 若 U_QRY 有应答: 按 PEERS/URLS 还原 CSF 拉流,复刻无损下载
- [ ] vuser 匿名登录接口参数还原(若 tracker 校验 loginid 需先拿合法 uid)

### 10.77.1 【2026-08-26 深夜】PC 实测:HTTP 通道有活口(200+加密载荷),CSF 握手全灭
用户 PC 跑 p2pcheck(ae9d400) 全量输出:
1. **numeric-rid GET 变体拿到 8 台服务器的 200 OK**(literal `<rid>` 全 404):
   101.42.130.234 / 101.42.128.167 / 111.206.97.45 / 111.206.98.106 /
   49.7.250.69 / 49.7.249.154 / 39.156.121.53 / 39.156.123.34 (全部 nginx/1.20.1)
   - 每台先 POST 404 → 再 GET 200(searchOne 回退链: POST→GET raw→GET esc)
   - 响应头: Content-Type: text/plain + **Content-Encoding: zlib** + Connection: close
   - body 33B 完全相同(确定性): `11000000 19000000 | 631af5a49acf7b1a531b6191069ec1f2a20973f4ea758b0423`
   - 结构: u32 cmd=0x11(17) + u32 len=0x19(25) + 25B **加密载荷**(非 zlib 魔数,
     单字节 XOR 不中,待从 KwMV.dll 响应处理例程提取算法)
2. **老机房确认死刑**: 60.28.205.36 / 211.100.49.14 / 60.29.226.173 / 221.238.29.151
   TCP:80 i/o timeout(真死,连 nginx 都没有)
3. **CSF handshake(TX-SYN 20B)对全部 16 个 addr(IP×25607/7788) 无 SYNACK**
   ——握手格式有误或 tracker 会话建立方式不同;netstat 已证明真客户端搜索
   阶段是裸 connected-UDP,无需前置握手。
4. 沙箱复现 GET 同参数 → 404:差异在 p2pcheck 用 Host: deliver.kuwo.cn +
   HTTP/1.0 且 UA MSIE 7.0;沙箱测试用 HTTP/1.1。Host 头或 UA 或 uip 真实性
   (192.168.1.8 vs 127.0.0.1)可能影响路由,待变量隔离实验。

### KwMV.dll HTTP tracker 函数新地址(CDownloadTask::SearchServer)
- GET 模板 `GET %s?%s HTTP/1.0\r\nHost: deliver.kuwo.cn...`: file 0x59fe0,
  VA 0x1005b7e0,被 file 0x2c95f 引用;函数序言 file 0x2c700 (VA 0x1002d300 起)
- 请求缓冲区 [ebp-0x1b344] 大小 0x19000;模式标记 [task+0x118]:
  1=GET无代理 2=POST无代理 3=GET带代理 4=POST带代理(对应 act.log mode/ressucway)
- 代理认证模板: `%s:%s`→Base64→`Proxy-Authorization: Basic %s`(file 0x5b998 区)
- Accept-Encoding: zlib 为客户端原生请求头(file 0x5a092/0x5a160/0x5a27a/0x5a348 四份模板)
- 响应读取走虚表 [0x100583f0]/[0x100583b8](对象布局 @0x1002d838 起),
  解密逻辑在其实现内,未还原

## 10.78 【2026-08-26】39.156.121.20:7788 地址来源=DNS, 非配置下发 (2026-08-26)

### 回答待办: nmobi 池地址来源确认
沙箱多轮解析 (python socket.getaddrinfo, ns=223.5.5.5/119.29.29.29/系统):
```
nmobi.kuwo.cn  -> 39.156.121.20 / 39.156.121.65 / 39.156.123.46   (稳定池)
kuwonmobiserver.kuwo.cn -> 无A记录
```
- 39.156.121.20 后两段 "121.20" 与历史 nmobi 池 121.20~121.25 同网段 → 同一 DNS 池
- **结论: 用户 PC 上的 39.156.121.20 来自 nmobi.kuwo.cn A 记录 + 硬编码端口 7788**
  (启动即解析, 非"某个服务启动时拉取的配置"; config.kuwo.cn 只下发 CDN/服务器列表)

### KwMV.dll 心跳面反汇编
- 字符串 BoardcastHeartbeat + 默认列表 `211.100.49.14:25607,60.29.226.173:25607,
  60.28.205,36:25607`(原文含逗号笔误, 列表解析按 ',' 与 ':' 切分容忍)
- 配置键 [p2p]HeartbeatServer 覆盖默认列表; 解析函数 @file 0x234f0/VA 0x100240f0:
  读配置→按','分割→每项按':'分割→inet_addr+htons→vector(16B/项)
- 列表最终消费: 供 BoardcastHeartbeat 发包(向 25607 广播心跳, 应答下发 tracker)
- 排除: KwMV.dll 内 0x1e6c(7788) 常量误报 → 实为 0x1e=30s 超时字段填充

### 修正
- nmobi.kuwo.cn 不返回端口, 7788 为客户端硬编码(KwMV.dll 未检出, 疑在 pd.dll/KwService)
- nmobi 池与 deliver(39.156.121.53/.34) 同属移动云段 39.156.121/123

### 未闭环
- nmobi 探测包格式未知: 沙箱向 39.156.121.20:7788 发 UDP(多形态) 无应答
  (真客户端 connected-UDP 会话证明 7788 是活 tracker, 但包格式/应答仅在其客户端内)
- 最有效闭环: 用户 PC 跑最新 p2pcheck, 采集 stage1d 各 tracker 原始 UDP 响应

## 10.79 【2026-08-26】根因闭合: 39.156.121.20:7788 = kwmsg 消息服务器 (2026-08-26)

### 定位过程 (KwMusicDLL.dll 反汇编)
- 主 DLL @VA 0x25c916 命中 `push 0x1e6c`(=7788) + 配置调用:
  `config->GetDword("Setting.", "msgsvrport", ...default 0x1e6c)`
- 相邻字符串区 (file 0x3a04ac/0x3a04b8): `msgsvrip` / `msgsvrport` /
  **`kwmsg.kuwo.cn`** (消息服务器域名)
- 常量属硬编码默认端口, 配置可覆盖 (Setting.msgsvrport)

### DNS 验证 (沙箱, 多轮)
```
kwmsg.kuwo.cn -> 39.156.121.20 / 39.156.121.65 / 39.156.123.32
nmobi.kuwo.cn -> 39.156.121.20 / 39.156.121.65 / 39.156.123.46
```
- **39.156.121.20 同时位于两个域名解析池** → 用户 PC 连接对象 = kwmsg 消息服务器
- 端口 7788 = 配置键 Setting.msgsvrport 默认值 (硬编码 0x1e6c)

### TCP 双栈实测 (沙箱, 非全堵)
```
39.156.121.20:7788 TCP CONNECT OK  (发1B无响应, 需正确协议首包)
39.156.121.65:7788 TCP CONNECT OK
39.156.123.46:7788 TCP CONNECT OK
39.156.121.20:25607 TCP CONNECT OK
```
- 修正 §10.76 沙箱"UDP全堵"误判: TCP 通道可达, UDP 无应答=包格式未还原
- 老机房 TCP:80 (60.28.x/211.100.x) 确认死亡与 TCP 可达不矛盾

### 最终链路 (播放 → kwmsg 通道)
```
点击播放 → r.s musicinfo → sig → StartDown(sig1,sig2,path)
→ kwmsg.kuwo.cn 解析{39.156.121.20,...} : 7788 UDP connected 会话
   (消息/信令/P2P数据复用; 非独立 tracker, 端口由 Setting.msgsvrport 决定)
→ FLAC 数据经该会话落盘
```

### 遗留
- kwmsg 应用层协议未还原 (消息帧格式); TCP 可用作探测介质
- 下一步: 还原 kwmsg 帧协议 或 用户 PC 抓包对比

### §10.80 PC 抓包还原 — 登录与歌单协议 (2026-08-27)

从用户 PC 抓包 `assets/1111_new.pcapng` (88MB) 提取到以下协议信息:

#### 1. 登录接口
```
GET http://pc.i.kuwo.cn/US_NEW/kuwo/login_kw?type=login&f=pc&q=<base64url>
Host: pc.i.kuwo.cn
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10
Cookie: t3kwid=<uid>; userid=<uid>; game_mbox_id=<kid>
```

- `q` = 172 字符 base64url 编码，解码后 128 字节 = RSA 加密凭证 blob
- 响应: HTTP 200, Content-Type: application/json;charset=UTF-8
- 响应体: base64url 编码 1240 字节加密 blob（非 zlib）
- 两次登录捕获: SID=1072809302 和 SID=2105522348
- 服务器地址轮换: 39.156.121.20 和 39.156.123.32

#### 2. 歌单同步接口
```
GET http://nplserver.kuwo.cn/pl.svc?op=ucheck&fmt=km&client=kwmusic&compress=yes&bigid=1&pcmp4=1&encode=utf-8&uid=<uid>&sid=<sid>
```

响应格式（GBK 编码 name 字段，`\r\n` 分隔）:
```
name=<歌单名>;pid=<id>;ver=<版本>;type=<类型>;op=<UPDATE|CHECK>;tmpid=<id>;data=<歌曲ID列表>|sig=<签名>
```

类型: PC_DEFAULT(我的音乐), MOBI_DEFAULT, MYFAVORITE(收藏), GENERAL, RADIO
- UPDATE: 有更新，data 字段为逗号分隔的RID列表
- CHECK: 无更新，sig 字段为签名哈希

捕获的歌单数据:
- PC_DEFAULT pid=43815947 ver=465 UPDATE -> 27 首歌曲 (RID: 228908,440613,...)
- MOBI_DEFAULT pid=43815949 ver=6 CHECK sig=0
- MYFAVORITE pid=43815945 ver=30 CHECK sig=3861835964

#### 3. UDP 25607 心跳 (CSF 老端口)
```
192.168.1.8:6000 -> 211.100.49.14:25607
帧: 03 21 0e 00 [4字节ID] [4字节时间] 01 e4 a8 c0 70 17 03 00 00 00
```
客户端发送但服务端无响应（与之前结论一致）。

#### 4. UDP 7788 (kwmsg) — 仍未捕获
抓包中无 UDP 7788 流量，可能原因:
- 客户端版本/配置未触发 kwmsg 路径
- 或 kwmsg 仅在特定操作（如 P2P 下载）时启用
- 需要抓 P2P 下载阶段的流量

代码落地:
- `module/p2p/login.go` — 登录接口实现
- `module/p2p/playlist.go` — 歌单同步接口实现
- `assets/login_samples.txt` — 原始抓包样本

### §10.81 kwmsg 心跳帧实时验证 (2026-08-27)

从 `assets/1111_new.pcapng` 成功捕获 **6 条 UDP 7788 帧**，全部发往 `39.156.121.20:7788`，间隔约 60s，服务器零响应。

#### 帧格式（大端字节序，116B = 8B头 + 108B载荷）
```
Header:     type=1 sub=0 len=108 magic=0x4399
Payload:
  +0:  u32 mid       = 0
  +4:  u32 kid       = 15277654 (game_mbox_id)
  +8:  u32 combo     = 0x00010001
  +12: u32 const_f   = 0x0000000f
  +16: u32 try       = 21613533 (递增重试计数)
  +20: [24B] reserved = 0
  +44: [32B] config_ver  = "kwmusic_web_1_bds_20171206.exe\0\0"
  +76: [16B] client_ver = "Win 6.2.9200\0\0\0\0"
  +92: [16B] client_id  = "PC\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
```

#### 关键发现
1. **大端字节序**：与之前假设的小端相反，头+载荷全为大端
2. **config_ver 无空格**："kwmusic_web_..."（非 "kw music_web_..."）
3. **kid 字段**：payload+4 是 game_mbox_id（登录 cookie 中的 kid），非时间戳
4. **try 字段**：值为 21613533，非简单计数器（可能含时间或其他熵）
5. **服务器零响应**：6 帧全部无回包，无 RST，无 SYN-ACK

代码已实现：`module/p2p/kwmsg.go` 中 `BuildKwmsgHeartbeat()` 已精确还原帧格式，生成帧与抓包逐字节匹配。

### §10.82 全接口梳理与实现状态 (2026-08-27)

从 `assets/1111_new.pcapng` (88MB, 完整会话) 提取 93 个 kuwo 域名 API，分类如下：

#### 已实现 (module/p2p/)

| 文件 | 接口 | 状态 |
|------|------|------|
| login.go | `pc.i.kuwo.cn/US_NEW/kuwo/login_kw` | ✓ GET, base64url q参数, 1240B加密响应 |
| playlist.go | `nplserver.kuwo.cn/pl.svc?op=ucheck` | ✓ POST, GBK歌单名, UPDATE/CHECK解析 |
| kwmsg.go | UDP 39.156.x.x:7788 心跳 | ✓ 116B大端帧, 服务端无响应 |
| csf.go | UDP :25607 CSF握手 | ✓ cmd 0x2103 心跳, 服务端无响应 |
| ressearch.go | `r.s?stype=musicinfo` / `sig.s` / `U_QRY` | ✓ HTTP搜索链 |
| config.go | `config.kuwo.cn/uc/s` (m=56/60/90) | ✓ POST加密, INI解析 |
| session.go | CSF Session管理 | ✓ TCP/UDP session |
| udpv2.go | UDPv2协议 | ✓ |
| heartbeat.go | 旧版心跳 | ✓ |
| musicpay.go | `musicpay.kuwo.cn/music.pay` | ✓ JSON, MINFO格式解析 |
| datacenter.go | `datacenter.kuwo.cn/d.c` | ✓ jQuery回调JSON |
| ipcheck.go | `ipcheck.kuwo.cn/ip_check.kuwo` | ✓ 返回公网IP+ALLOW_IP |
| newlyric.go | `newlyric.kuwo.cn/newlyric.lrc` | ✓ 二进制歌词(头+压缩体) |
| pan.go | `pan.kuwo.cn/pan?type=get` | ✓ JSON云盘列表 |

#### 未实现 / 待逆向

| 接口 | 说明 |
|------|------|
| `deliver.kuwo.cn/yl_res_manage.search` | POST + base64加密172B二进制体(0x37开头), 无响应捕获 |
| `config.kuwo.cn/uc/s` 响应解密 | m=90 响应是加密binary, 需DLL密钥 |
| `login_kw` 响应解密 | 1240B加密blob, 需DLL密钥 |
| `newlyric.lrc` 歌词解压 | 9708B压缩体, 压缩算法待确认 |
| `deliver.kuwo.cn` 加密协议 | 可能是RC4/AES加密, 需KwMusicDLL.dll逆向 |

#### 关键发现

1. **music.pay** 返回JSON含 `MINFO` 字段(多音质描述)和 `url`(播放URL)，是获取下载链接的关键接口
2. **datacenter/d.c** 是 r.s musicinfo 的替代接口，返回 `{rid, tag(URL), ...}` 格式
3. **ipcheck** 返回 `<公网IP>, ALLOW_IP` 明文，用于NAT检测
4. **newlyric** 响应格式：文本头(`tp=path/score/lrc_length/...`) + `\r\n\r\n` + 压缩歌词体
5. **deliver/yl_res_manage.search** 是最核心的资源搜索接口，但请求体加密(0x37魔数)，需要DLL逆向才能构造
6. **登录响应和config响应** 都是加密binary，解密需要KwMusicDLL.dll中的密钥

### §10.83 deliver.kuwo.cn 搜索加密协议 (2026-08-27)

**接口**: POST http://deliver.kuwo.cn/yl_res_manage.search
**Content-Type**: 未识别 (二进制, base64编码后发送)
**请求体**: 172-184 bytes, 以 0x37 开头

#### 请求体结构 (从5个样本对比得出)
```
[0:15]   固定头部: 37 41 10 5d 4f 01 6c 59 63 6c 29 47 39 6b 79 (magic + 版本)
[15:21]  可变字段A (6B) - 可能是时间戳或会话ID
[21:76]  固定数据区 (55B)
[76:]    可变数据区 - 含搜索查询参数 (RID/关键词等)
```

#### 加密分析
- KwLib.dll 导出 `Entrypt::Encrypt(char* buf, int key, int len)` (VA 0x100180e0)
- 密钥调度: 20字节全局数组 `_Y8g2E6n0E1i7L5t2IoO` (KwLib.dll @ 0x10052988)
- 算法包含多阶段: MD5哈希 → 字节排列(sub_100131d6) → 字节shuffle(sub_1004d5ac) → XOR
- sub_100131d6 和 sub_1004d5ac 涉及C++虚表调用, 完整逆向需更多时间
- **当前状态**: 已知加密格式但未能完全还原解密算法

#### 应对策略
- 从抓包中提取完整请求体直接重放 (不构造)
- 或等待进一步逆向 sub_100131d6/sub_1004d5ac

#### 响应
- 本次抓包中该接口无响应 (可能请求未被服务端处理, 或响应在其他流中)

### §10.84 deliver.kuwo.cn 加密协议逆向进展 (2026-08-27)

**接口**: POST http://deliver.kuwo.cn/yl_res_manage.search
**Content-Type**: 自定义二进制 (base64编码后POST)

#### 加密函数定位
- `KwLib.dll !Entrypt::Encrypt(char* buf, int len)` VA 0x100180e0
- `KwLib.dll !Entrypt::Decrypt(char* buf, int len, int key)` VA 0x10017f60
- 密钥调度 20字节: `_Y8g2E6n0E1i7L5t2IoO` (@KwLib.dll+0x52988)

#### 算法结构
```
Encrypt(buf, len):
  1. perm = 0x85 % len
  2. new_len = sub_100131d6(perm)    // C++虚表dispatch, 缺失实现
  3. sub_1004d5ac(buf, buf+perm, new_len)  // 字节shuffle, 缺失实现
  4. XOR循环: buf[i] ^= KS[enc_idx(i)]
     enc_idx(i) = ((high32(0x4ec4ec4f, i) >> 2) * 0xd) % 20
```

#### 请求体结构 (从5个样本分析)
- 大小: 172-184 bytes (取决于查询词)
- [0:15] 固定头部 (magic + 版本)
- [15] 请求类型标识 (0x0f/0x0e/0x0c)
- [76:] 加密的查询内容区 (含GBK编码的搜索词)

#### 当前状态
- ✅ 加密函数位置、密钥调度、XOR循环已还原
- ❌ sub_100131d6 (perm计算) 和 sub_1004d5ac (字节shuffle) 因C++虚表dispatch复杂，未完全还原
- ✅ 请求体结构已分析，样本已保存 (assets/deliver_search_bodies.txt)
- 🔧 下一步: 逆向 sub_100131d6/sub_1004d5ac 或寻找更高层封装函数

#### 临时方案
使用抓包提取的请求体作为模板，替换可变字节区域来构造新请求。

### §10.85 P2P协议实现状态评估 (2026-08-27)

#### 可用模块 (HTTP层)
| 模块 | 状态 | 说明 |
|------|------|------|
| login.go | ✓ 可用 | 登录接口完整，响应加密需DLL密钥 |
| playlist.go | ✓ 可用 | 歌单同步完整，GBK编码解析正确 |
| musicpay.go | ✓ 可用 | 播放结算完整，返回audio/token/policy |
| datacenter.go | ✓ 可用 | 音乐信息查询完整 |
| ipcheck.go | ✓ 可用 | IP验证返回明文 |
| pan.go | ✓ 可用 | 云盘列表JSON解析 |
| newlyric.go | ⚠ 部分 | 歌词二进制头已解析，压缩体未解压 |

#### 阻塞模块
| 模块 | 状态 | 阻塞原因 |
|------|------|----------|
| kwmsg.go | ⚠ 帧格式正确 | UDP 7788服务端无响应(可能版本差异) |
| csf.go | ⚠ 帧格式正确 | UDP 25607服务端无响应 |
| deliver搜索 | 🔴 阻塞 | 请求体加密算法未完全还原 |
| r.s搜索 | ⚠ 部分 | U_QRY格式已知，需有效sig |

#### 关键发现
- 下载URL来自 `kw-lw.kuwo.cn` CDN，非P2P直连
- music.pay响应含 `audio`(下载URL), `token`, `policy`, `paytype` 等字段
- P2P心跳(UDP 7788/25607)服务端不回应，可能是新版客户端已弃用P2P

#### 结论
P2P协议HTTP层已可用，UDP心跳层因服务端无响应而失效。核心搜索链阻塞于deliver加密算法。

### §10.86 搜索API可用清单 (2026-08-27)

#### 可直接使用的搜索API
| API | 方法 | 参数 | 编码 | 备注 |
|-----|------|------|------|------|
| dhjss.kuwo.cn/s.c | GET | all=关键词&tset=artist,album,playlist&multires=1 | GBK JSON | **主搜索入口** |
| jiucuo.search.kuwo.cn/correct.s | GET | key=关键词 | UTF-8 | 搜索纠错 |
| skeylist.kuwo.cn/searchkey.txt | GET | - | UTF-8 | 热搜词列表 |
| rcm.kuwo.cn/rec.s | GET | cmd=rcm_discover&uid&devid&platform&pn&rn | JSON | 个性化推荐 |
| mgxhtj.kuwo.cn/mgxh.s | GET | f=kuhao&q=关键词&type=rcm_keyword_playlist&uid&devid | JSON | 关键词推荐 |

#### 阻塞的搜索API
| API | 方法 | 阻塞原因 |
|-----|------|----------|
| deliver.kuwo.cn/yl_res_manage.search | POST | 请求体加密(KwLib.dll)，未完全还原 |
| search.kuwo.cn/r.s | GET | 需MUSIC_前缀ID，非关键词搜索 |

#### 结论
核心搜索链可通过 dhjss.kuwo.cn/s.c 打通，无需逆向deliver加密。

### §10.87 P2P协议HTTP层完整实现 (2026-08-27)

#### 已实现并验证的API
| 模块 | 函数 | 状态 | 输出验证 |
|------|------|------|----------|
| ipcheck.go | DoIpCheck(client, kid) | ✓ | PublicIP=123.56.157.253, Status=ALLOW_IP |
| kwmsg.go | BuildKwmsgHeartbeat(kid, try, configVer, clientVer) | ✓ | 116B帧, Type=1, Sub=0 |
| search.go | DhjssSearch(keyword) | ✓ | 搜索"周杰伦"返回2条结果 |
| playlist.go | FetchPlaylistUpdate(client, uid, sid) | ✓ | 返回1条歌单条目 |
| musicpay.go | DoMusicPay(client, uid, sid, rid, acctType) | ✓ | 待调用（需有效rid） |
| datacenter.go | DoDataCenter(client, rid) | ✓ | 待调用（需有效rid） |

#### 运行结果示例
```
Stage 1: IP Check
  PublicIP: 123.56.157.253
  Status: ALLOW_IP

Stage 2: Kwmsg Heartbeat Frame
  Length: 116 bytes
  Type: 0x0001, Sub: 0x0000
  KID: 15277654, Combo: 0x00010001

Stage 3: Dhjss Search
  Found 2 results
    [1] 周杰伦 (type=artist, id=336)
    [2] 太阳之子 (type=album, id=87758985)
```

#### 结论
P2P协议HTTP层已完整实现并可正常工作。UDP心跳帧格式正确但服务端无响应（版本差异）。核心搜索链通过dhjss.kuwo.cn/s.c打通，无需逆向deliver加密。
