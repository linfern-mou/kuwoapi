# kuwoapi-go

酷我音乐 API 的 Go 实现，提供 HTTP JSON 接口。

## 分支说明

本项目按接口来源分为两个分支，架构完全一致（Go + `module/` 业务模块 + `server/` 路由），区别在于所调用的酷我后端接口来源：

| 分支 | 接口来源 | 说明 |
|------|---------|------|
| `main` | PC 端 | 沿用酷我 Windows 客户端 DLL（KwMusicDLL.dll 等）逆向出的接口，旧版 zlib/KV 文本格式 |
| `kuwoapk` | APK 端（本分支） | 以官方酷我 Android 客户端（kuwoapk）抓包/反编译得到的接口为准，新版 JSON 格式 |

## 快速开始

```bash
go run main.go
# 默认监听 :3000，可用 PORT/HOST 环境变量覆盖
```

### Docker

```bash
docker build -t kuwoapi-go .
docker run -p 3000:3000 kuwoapi-go
```

## 接口约定

- 所有接口为 `GET`/`POST`，参数来自 URL Query 或 JSON Body
- 统一返回 `{"code": 200, "data": ...}`；参数缺失返回 `{"code": 400, "msg": "..."}`
- 已开启 CORS，可直接浏览器/前端调用

## 搜索接口

```
GET /search?key=<关键词>&pn=<页码>&rn=<每页条数>
```

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `key` | string | 是 | - | 搜索关键词 |
| `pn` | int | 否 | 0 | 起始页码 |
| `rn` | int | 否 | 25 | 每页条数 |

### 上游请求（kuwoapk 分支）

后端转发到酷我搜索接口，参数模板来源于 APK：

```
GET http://search.kuwo.cn/r.s?client=kt&all=<key>&pn=<pn>&rn=<rn>&ft=music
    &cluster=0&strategy=2012&ver=mbox&show_copyright_off=1&encoding=utf8
    &rformat=json&mobi=1&vipver=1&issubtitle=1&correct=1&newver=1
    &vermerge=1&srcfrom=preference_bl
```

响应为 JSON（`rformat=json`），核心字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `TOTAL` | int | 总结果数 |
| `SHOW` | int | 本次返回条数 |
| `PN` / `RN` | int | 分页信息 |
| `HIT` | int | 命中数 |
| `abslist` | array | 歌曲列表，每项包含 `MUSICRID`、`SONGNAME`、`ARTIST`、`ALBUM`、`DURATION`、`MINFO`(各音质信息)、`N_MINFO`、`PAY`(付费标记) 等 |
| `searchgroup` | array | 搜索联想分组 |

### 响应示例

```json
{
  "code": 200,
  "data": {
    "total": 3506,
    "show": 25,
    "pn": 0,
    "rn": 25,
    "hit": 3506,
    "songs": [
      {
        "rid": "MUSIC_5886682",
        "name": "海阔天空-《九五2班》网络电影插曲",
        "artist": "BEYOND",
        "artistid": "1250",
        "album": "乐与怒",
        "albumid": "2676",
        "duration": "324",
        "format": "wma",
        "mvflag": "1",
        "mvquality": "MP4;MP4L",
        "mvpic": "324/59/71/2033539703.jpg",
        "pay": "16711935",
        "subtitle": "《九五2班》电影插曲|《中国合伙人》电影插曲|《在远方》电视剧插曲|《三个中国先生》电影插曲",
        "minfo": "level:ff,bitrate:2000,format:flac,size:31.36Mb;level:p,bitrate:192,format:ogg,size:6.95Mb;...",
        "n_minfo": "level:dtsx,bitrate:25000,format:mmp4,size:8.73Mb;...",
        "online": "1",
        "raw": { "...APK 原始字段..." }
      }
    ]
  }
}
```

`songs[]` 为友好字段映射，`songs[].raw` 保留 APK 返回的完整原始对象，方便取用 `SUBLIST`（多版本）、`payInfo`、`mvpayinfo` 等扩展信息。

## 歌曲播放地址接口

```
GET /song/url?id=<rid>&format=<mp3|aac|flac|ape>
```

| 参数 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `id` | string | 是 | - | 歌曲 RID，可带 `MUSIC_` 前缀，如 `228908` 或 `MUSIC_228908` |
| `format` | string | 否 | `mp3` | 音频格式，支持 `mp3`/`aac`；`flac`/`ape` 需 VIP |

### 上游请求（kuwoapk 分支）

后端转发到酷我反盗链转换接口，来源为 APK 内 `antiserver.kuwo.cn`：

```
GET http://antiserver.kuwo.cn/anti.s?type=convert_url&rid=<MUSIC_xxx>&format=<fmt>
```

响应为纯文本：`mp3`/`aac` 返回真实音频直链（如 `https://kw-bj.kuwo.cn/.../588957081.mp3`），`flac`/`ape` 返回 `refuse request!`。

### 响应示例

```json
{
  "code": 200,
  "data": {
    "rid": "MUSIC_228908",
    "format": "mp3",
    "url": "https://kw-bj.kuwo.cn/df0008e8ee04cfab89f996251efacf67/6a77f80e/nf/resource/n1/69/32/588957081.mp3"
  }
}
```

## 接口列表

| 路由 | 说明 | kuwoapk 分支来源 |
|------|------|------------------|
| `GET/POST /search` | 搜索歌曲 | `search.kuwo.cn/r.s` (rformat=json) |
| `GET/POST /song/url` | 歌曲播放地址 | `antiserver.kuwo.cn/anti.s` (convert_url) |
| `GET/POST /song/detail` | 歌曲详情 | 同 `/song/url` |
| `GET/POST /download` | 下载歌曲 | 待按 APK 接口改造 |
| `GET/POST /lyric` | 获取歌词 | 待按 APK 接口改造 |
| `GET/POST /rank` | 排行榜内容 | 待按 APK 接口改造 |
| `GET/POST /rank/list` | 榜单列表 | 待按 APK 接口改造 |

## APK 参考信息

`kuwoapk` 分支的接口来源为官方酷我 Android 客户端（release 2.0.1，包名 `cn.kuwo.music`）。核心接口域名：

- 搜索：`search.kuwo.cn/r.s`
- 播放地址：`player.kuwo.cn/webmusic/play?mid=MUSIC_xxx`
- 反盗链转换：`antiserver.kuwo.cn` (`type=convert_url_with_sign`)
- 歌词：`mlyric.kuwo.cn/mobi.s`
