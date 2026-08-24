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
