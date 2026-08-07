# 酷我音乐 API 逆向工程规范文档

> **本文档是项目的唯一事实来源（Single Source of Truth）。**
>
> 所有接口、参数、加解密逻辑**必须且仅必须**来源于 `default.zip` 压缩包内的二进制文件逆向分析。
> 压缩包中不存在的内容，**禁止**从互联网搜索、禁止推测、禁止编造。
> 未确认的部分必须留空并标注 `[未确认]`，由人工补充或进一步逆向确认。

---

## 一、数据来源

### 1.1 压缩包信息

| 项目 | 值 |
|------|-----|
| 下载地址 | `https://github.com/linfern-mou/kugoumusic--new/releases/download/1.4.0.1/default.zip` |
| 解压目录 | `kuwomusic/8.7.4.0_BDS1/` |
| 客户端版本 | 8.7.4.0_BDS1 |
| 分析方法 | `strings` 提取二进制中的字符串常量、函数符号名 |

### 1.2 关键二进制文件

| 文件 | 作用 |
|------|------|
| `bin/KwLib.dll` | 核心库：加密、签名、Base64、MD5 |
| `bin/KwMusicDLL.dll` | 主业务库：搜索、历史、歌词上传 |
| `bin/KwModLyric.dll` | 歌词模块 |
| `bin/KwModDownload.dll` | 下载模块 |
| `bin/PlayerCore.dll` | 播放核心（含 .kwm 解密） |
| `bin/KwHttp.dll` | HTTP 请求库 |
| `bin/KwHttpRequestMgr.dll` | HTTP 请求管理 |
| `bin/KwModConfig.dll` | 配置模块 |
| `bin/Encode.exe` | 编码工具 |
| `bin/KwConfig.exe` | 配置工具 |
| `Conf/default/config.ini` | 默认配置 |

---

## 二、AI 执行约束规则（强制遵守）

### 规则 1：接口来源约束
- 每个接口的 URL、host、路径**必须**在本文档第三章有记录
- 接口参数**必须**与本文档记录的 `%s` 格式化模板一致
- **禁止**使用本文档未记录的接口端点
- **禁止**从互联网搜索酷我音乐的 API 文档

### 规则 2：加解密来源约束
- 加密算法**必须**使用本文档第四章记录的函数/字符串
- 盐值、密钥**必须**使用本文档第四章记录的字符串常量
- **禁止**使用本文档未记录的密钥、盐值、公钥
- **禁止**编造 RSA 公钥、AES 密钥
- 函数的具体算法实现如果未逆向确认，必须标注 `[算法未确认]`，不得用推测实现冒充

### 规则 3：未确认内容处理
- 遇到 `[未确认]` 标记的内容，**禁止**自行实现
- 必须保留空壳函数并抛出明确错误：`throw new Error('[未确认] xxx 的实现需要人工逆向确认')`
- 或询问用户获取确认后再实现

### 规则 4：禁止行为清单
| 禁止行为 | 说明 |
|----------|------|
| 从网上搜索接口 | 所有接口必须来自压缩包 strings 分析 |
| 编造密钥/盐值 | 密钥必须来自压缩包二进制提取 |
| 编造 RSA 公钥 | 压缩包中未发现酷我自有 RSA 公钥 |
| 推测加密算法 | 只能使用压缩包中确认存在的函数符号 |
| 混用其他音乐平台逻辑 | 禁止参考酷狗、网易等平台的实现 |

---

## 三、接口清单（压缩包确认）

> 以下所有接口均通过 `strings` 从压缩包内 DLL/exe 中提取，包含完整的 URL 模板和参数格式。

### 3.1 搜索接口

#### 3.1.1 歌曲搜索
- **端点**: `http://search.kuwo.cn/r.s`
- **方法**: GET
- **URL 模板**（来源：多个 DLL）:
  ```
  http://search.kuwo.cn/r.s?client=kt&all=%s%%20%s%%20%%s&pn=0&rn=10&ft=music&newsearch=1&cluster=0&strategy=2012&itemset=reco&ver=%s&pcmp4=1
  ```
  ```
  http://search.kuwo.cn/r.s?client=kt&all=%s%%20%s&pn=0&rn=10&ft=music&newsearch=1&cluster=0&strategy=2012&itemset=reco&ver=%s&mp4=1
  ```
- **参数说明**:

| 参数 | 值/格式 | 说明 |
|------|---------|------|
| client | `kt` | 固定值 |
| all | `%s` | 搜索关键词（多个用 `%20` 连接） |
| pn | `%d` | 页码，从 0 开始 |
| rn | `10` | 每页数量（固定 10） |
| ft | `music` | 固定值 |
| newsearch | `1` | 固定值 |
| cluster | `0` | 固定值 |
| strategy | `2012` | 固定值 |
| itemset | `reco` | 固定值 |
| ver | `%s` | 客户端版本 |
| pcmp4 / mp4 | `1` | 固定值 |

#### 3.1.2 歌曲详情
- **端点**: `http://search.kuwo.cn/r.s`
- **URL 模板**（来源：多个 DLL）:
  ```
  http://search.kuwo.cn/r.s?stype=musicinfo&itemset=music_2014&alflac=1&pcmp4=1&ids=
  ```
- **参数说明**:

| 参数 | 值 | 说明 |
|------|-----|------|
| stype | `musicinfo` | 固定值 |
| itemset | `music_2014` | 固定值 |
| alflac | `1` | 固定值 |
| pcmp4 | `1` | 固定值 |
| ids | `%s` | 歌曲 ID（多个用逗号连接） |

### 3.2 播放地址接口

#### 3.2.1 转换播放 URL
- **端点**: `http://antiserver.kuwo.cn/anti.s`
- **URL 模板**（来源：KwModDownload.dll）:
  ```
  format=aac&type=convert_url&rid=%s&response=url&loginid=%s&ch=%s&instsrc=%s
  ```
- **参数说明**:

| 参数 | 值/格式 | 说明 |
|------|---------|------|
| format | `aac` | 音频格式 |
| type | `convert_url` | 固定值 |
| rid | `%s` | 歌曲 ID |
| response | `url` | 固定值 |
| loginid | `%s` | 登录 ID |
| ch | `%s` | 渠道 |
| instsrc | `%s` | 安装来源 |

#### 3.2.2 歌单获取播放 URL（带签名）
- **URL 模板**（来源：DLL strings）:
  ```
  ?uid=%s&sid=%s&ver=%s&src=mbox&op=submit&action=%s&pid=%s&id=%s&br=%d&fmt=%s&accttype=1
  ```
  ```
  ?uid=%u&sid=%u&ver=%s&src=mbox&op=query&signver=new&action=%s&ids=%s&accttype=1
  ```
- **参数说明**:

| 参数 | 值/格式 | 说明 |
|------|---------|------|
| uid | `%s` / `%u` | 用户 ID |
| sid | `%s` / `%u` | 会话 ID |
| ver | `%s` | 客户端版本 |
| src | `mbox` | 固定值 |
| op | `submit` / `query` | 操作类型 |
| action | `%s` | 动作 |
| pid | `%s` | 歌单 ID |
| id | `%s` | 歌曲 ID |
| br | `%d` | 码率 |
| fmt | `%s` | 格式 |
| accttype | `1` | 固定值 |
| signver | `new` | 签名版本 |

#### 3.2.3 获取 URL（stype 方式，带签名）
- **URL 模板**（来源：DLL strings）:
  ```
  %stype=geturl&sign=%s
  ```
- **说明**: `sign` 参数由 `Sig::CalcSign` 生成

### 3.3 歌词接口

#### 3.3.1 获取歌词
- **端点**: `http://newlyric.kuwo.cn/newlyric.lrc`
- **参数**（来源：KwModLyric.dll）:
  ```
  &lrcx=1&contenttype=zip&olrc=1
  ```
- **参数说明**:

| 参数 | 值 | 说明 |
|------|-----|------|
| musicId | `%s` | 歌曲 ID |
| lrcx | `1` | 获取增强歌词 |
| contenttype | `zip` | 响应为 zip 压缩格式 |
| olrc | `1` | 获取原始歌词 |

- **响应格式**: zip 压缩包，内含 `.lrc` / `.lrcx` 文件

#### 3.3.2 上传歌词
- **URL 模板**（来源：KwMusicDLL.dll）:
  ```
  act=upfile&wid=%u&fsize=%d&content=%s|LRC|%s
  ```
- **端点**: `http://yinyue.kuwo.cn/yy/gc/LyricUploadAdd`

### 3.4 登录与用户接口

#### 3.4.1 登录
- **端点**: `http://pc.i.kuwo.cn/US_NEW/kuwo/login_kw`
- **方法**: POST

#### 3.4.2 用户信息
- **端点**: `http://pc.i.kuwo.cn/US_NEW/kuwo/vuser`

#### 3.4.3 注册验证
- **端点**: `http://reg.kuwo.cn/regsvr.auth?%d&%s`
- **参数**: 时间戳 + uid

#### 3.4.4 VIP 信息
- **端点**: `http://vip1.kuwo.cn/vip/v2/user/vip`

#### 3.4.5 找回密码
- **端点**: `http://pc.i.kuwo.cn/US/mbox/login2015new/findPwd.jsp`
- **备用**: `http://pc.i.kuwo.cn/US/mbox/login2015/findPwd.jsp`

#### 3.4.6 注册页面
- **端点**: `http://pc.i.kuwo.cn/US/mbox/login2015new/reg.jsp?`

### 3.5 歌单接口

#### 3.5.1 喜欢列表
- **端点**: `http://nplserver.kuwo.cn/pl.svc`
- **URL 模板**:
  ```
  http://nplserver.kuwo.cn/pl.svc?encode=utf-8&op=getlikeinfo&uid=
  ```

#### 3.5.2 歌单操作
- **端点**: `http://pls.kuwo.cn/pl.svc`
- **操作模板**（来源：DLL strings）:

| 操作 | URL 模板 |
|------|----------|
| 创建歌单 | `op=add&uid=%d&sid=%s&name=%s` |
| 删除歌单 | `op=del&uid=%d&sid=%s&pid=%s` |
| 更新歌单 | `op=update&uid=%d&sid=%s&name=%s&pid=%s&rids=` |
| 校验数量 | `op=validate&uid=%d&sid=%s&num=%d` |
| 歌单登录 | `op=login&uname=%s&pwd=%s` |

#### 3.5.3 个人列表服务
- **端点**: `http://hplserver.kuwo.cn/pl.svc`
- **端点**: `http://nplserver.kuwo.cn/pl.svc`

### 3.6 数据与纠错接口

#### 3.6.1 ID3 信息查询
- **端点**: `http://datacenter.kuwo.cn/d.c`
- **URL 模板**:
  ```
  http://datacenter.kuwo.cn/d.c?ft=music&cmkey=search_id3&ids=
  ```

#### 3.6.2 数据纠错
- **端点**: `http://jiucuo.search.kuwo.cn/correct.s?key=%s`

### 3.7 下载与云盘接口

#### 3.7.1 下载状态检查
- **端点**: `http://cldserver.kuwo.cn/c.s`
- **URL 模板**:
  ```
  ?op=ucheck&fmt=km&client=kwmusic&compress=no&bigid=1&pcmp4=1&encode=utf-8&
  ```
  ```
  ?op=ucheck&fmt=km&client=kwmusic&compress=yes&bigid=1&pcmp4=1&encode=utf-8&
  ```

#### 3.7.2 云盘上传
- **端点**: `http://cldserver.kuwo.cn/c.s`
- **URL 模板**:
  ```
  /c.s?op=upload&uid=%u&key=%s&sig=%u,%u&fsize=%u&offset=%u&fmt=%s
  ```

#### 3.7.3 无损列表
- **端点**: `http://misc.service.kuwo.cn/lossless/list`

### 3.8 PC 客户端 Web 接口

#### 3.8.1 升级信息
- **端点**: `http://www.kuwo.cn/api/pc/upgrade/info`

#### 3.8.2 导航配置
- **端点**: `http://www.kuwo.cn/pc/navigation/getNavigationConf`

#### 3.8.3 通用设置
- **端点**: `http://www.kuwo.cn/api/pc/commonSetting/topBarHeadPhone`

#### 3.8.4 皮肤使用计数
- **端点**: `http://www.kuwo.cn/api/pc/skin/addUseCount?id=`

### 3.9 其他已确认端点

| 端点 | 用途 |
|------|------|
| `http://mbox.kuwo.cn` | 音乐盒服务 |
| `http://config.kuwo.cn` | 配置服务 |
| `http://ipcheck.kuwo.cn/ip_check.kuwo` | IP 检查 |
| `http://skeylist.kuwo.cn/searchkey/searchkey.txt` | 搜索关键词列表 |
| `http://client-log.kuwo.cn` | 客户端日志 |
| `http://log.kuwo.cn/music.yl` | 音乐日志（YL=Yeelion） |
| `http://newreco.kuwo.cn/music.yl` | 推荐日志 |
| `http://down.kuwo.cn/mbox/kwmusic2015.exe` | 客户端下载 |
| `http://down.shouji.kuwo.cn/star/mobile/kwplayer_ar_mbox.apk` | 安卓下载 |
| `http://down.shouji.kuwo.cn/star/mobile/kwplayerhd_ar_mbox.apk` | 安卓HD下载 |

### 3.10 CDN 域名（压缩包确认）

```
win.player.ra01.sycdn.kuwo.cn
win.player.ra05.sycdn.kuwo.cn
win.player.rc01.sycdn.kuwo.cn
win.player.rc05.sycdn.kuwo.cn
win.player.rg03.sycdn.kuwo.cn
win.player.rg05.sycdn.kuwo.cn
win.player.rh03.sycdn.kuwo.cn
win.player.rh05.sycdn.kuwo.cn
win.player.ri03.sycdn.kuwo.cn
win.player.ri05.sycdn.kuwo.cn
```
- **CDN 资源路径模板**: `/resource/n2/11/64/{id}.mp3`

---

## 四、加解密信息（压缩包确认）

### 4.1 加密函数符号（来源：KwLib.dll 导出表）

| C++ 符号（修饰名） | 还原签名 | 说明 |
|---------------------|----------|------|
| `?CalcSign@Sig@KwLib@@YA_NPBDPAI1@Z` | `bool Sig::CalcSign(const char* data, unsigned int* out1, unsigned int* out2)` | 签名计算，输入字符串，输出两个无符号整数 |
| `?Encrypt@Entrypt@KwLib@@YAXPADHH@Z` | `void Entrypt::Encrypt(char* data, int len, int mode)` | 加密 |
| `?Decrypt@Entrypt@KwLib@@YAXPADHH@Z` | `void Entrypt::Decrypt(char* data, int len, int mode)` | 解密 |
| `?Base64Encode@Base64@KwLib@@...` | `std::string Base64::Base64Encode(const char*)` 等 | Base64 编码 |
| `?Base64Decode@Base64@KwLib@@...` | `int Base64::Base64Decode(char*, const char*, int)` 等 | Base64 解码 |
| `??0CMD5@@QAE@XZ` | `CMD5::CMD5()` | MD5 类默认构造 |
| `??0CMD5@@QAE@PBD@Z` | `CMD5::CMD5(const char*)` | MD5 类带参构造 |
| `??0CMD5@@QAE@PAK@Z` | `CMD5::CMD5(unsigned long*)` | MD5 类带参构造 |

> **注意**: `Sig::CalcSign` 输出是两个 `unsigned int*`（两个整数），不是 MD5 hex 字符串。
> 具体算法逻辑 **[算法未确认]**——需要反汇编 KwLib.dll 的 CalcSign 函数体才能确认。

### 4.2 字符串常量（来源：strings 提取）

| 字符串 | 出现位置 | 上下文/用途 |
|--------|----------|-------------|
| `yeelion` | KwLib.dll, KwMusicDLL.dll, KwModLyric.dll, KwModDownload.dll, KwModConfig.dll, KwModAndroidMgr.dll, KwUpdate.dll, Encode.exe, KwConfig.exe | 与 Base64 编解码、搜索URL、歌词上传相关 |
| `yeelion-kuwo-tme` | KwLib.dll | 与 `.kwm` 加密格式相关 |
| `yeelion_history` | KwMusicDLL.dll | 与历史记录加载(`_LoadHistory`)相关 |
| `yeelion_rand` | KwMusicDLL.dll | 与搜索请求 URL 生成(`TYPE:CHANGEDNS`)、`/r.s?client=kt&` 相关 |
| `KoOtOiTvINGwd` | KwLib.dll, KwMV.dll, KwMusicDLL.dll, PlayerCore.dll, lidx.dll | 13 字符，密钥候选，与播放核心相关 |
| `_Y8g2E6n0E1i7L5t2IoOoNk` | KwLib.dll, KwMV.dll, KwMusicDLL.dll, PlayerCore.dll, lidx.dll | 24 字符，密钥候选，与 `.kwm` 格式相关 |
| `OOOOOOCCCCCCCCCCCCCCCCCGCC` | KwLib.dll | 模式/掩码字符串，用途 **[未确认]** |
| `Yeelion_KuWo_Tools_2015-1-12` | 多个文件 | 版本标识 |
| `Yeelion_Third_Lyric_2010-10-22` | KwLib.dll | 第三方歌词版本标识 |
| `Yeelion_Update_2006-10-19` | 多个文件 | 更新模块版本标识 |
| `Encryption YL_Base64Encode in.` | KwMusicDLL.dll | 加密日志（YL=Yeelion 缩写） |
| `Encryption YL_Base64Encode out.` | KwMusicDLL.dll | 加密日志 |
| `PlaypanelSecret` | DLL strings | 播放面板密钥标识 |

### 4.3 加密格式

| 格式 | 说明 | 来源 |
|------|------|------|
| `.kwm` | 酷我音乐加密文件格式 | KwLib.dll（与 `yeelion-kuwo-tme`、`_Y8g2E6n0E1i7L5t2IoOoNk` 同区域） |
| `fmt=km` | 歌词压缩格式 | DLL strings |
| `compress=yes/no` | 压缩选项 | DLL strings |

### 4.4 签名使用场景

从 DLL strings 中确认需要 `sign` 参数的接口：

| 接口模板 | sign 来源 |
|----------|-----------|
| `%stype=addnew&sign=%s&hash=%s&key=%s&...&mid=%s&bitrate=%s` | `Sig::CalcSign` |
| `%stype=del&sign=%s` | `Sig::CalcSign` |
| `%stype=find&sign=%s` | `Sig::CalcSign` |
| `%stype=gettoken&sign=%s` | `Sig::CalcSign` |
| `%stype=geturl&sign=%s` | `Sig::CalcSign` |

> `sign` 的具体值由 `Sig::CalcSign` 生成，输出两个 uint。
> **[算法未确认]**: 两个 uint 如何拼成 sign 字符串（hex？decimal？拼接顺序？）需要反汇编确认。

---

## 五、压缩包中不存在的信息（禁止实现）

以下内容在压缩包中**未找到**，**禁止**在代码中实现，**禁止**从网上搜索：

| 内容 | 状态 | 处理方式 |
|------|------|----------|
| 酷我自有 RSA 公钥 | ❌ 不存在 | 禁止编造。crypto.js 中的 RSA 功能应移除或标注 `[未确认]` |
| AES 具体密钥 | ❌ 不存在 | 禁止编造。`Entrypt::Encrypt/Decrypt` 的密钥来源未知 |
| `Sig::CalcSign` 的具体算法 | ❌ 未逆向 | 函数符号确认存在，但算法逻辑未确认 |
| `yeelion` 在签名中的具体用法 | ❌ 未确认 | 字符串确认存在，但用作盐值/密钥/标识符未知 |
| `KoOtOiTvINGwd` 的具体用途 | ❌ 未确认 | 字符串确认存在，具体用途未知 |
| `_Y8g2E6n0E1i7L5t2IoOoNk` 的具体用途 | ❌ 未确认 | 字符串确认存在，具体用途未知 |
| `.kwm` 文件的解密算法 | ❌ 未逆向 | 格式确认，解密逻辑未确认 |
| 网页端 `Hm_Iuvt` Secret 算法 | ❌ 不属于压缩包 | 禁止使用 |
| `kuwo.cn/api/www/*` 接口 | ❌ 不属于压缩包 | 禁止使用 |
| `reqId` 生成算法 | ❌ 不属于压缩包 | 禁止使用 |

---

## 六、当前代码状态与差异

### 6.1 符合文档的部分 ✅

| 模块 | 状态 | 说明 |
|------|------|------|
| `module/search.js` | ✅ 符合 | URL 和参数来自压缩包 |
| `module/song_detail.js` | ✅ 符合 | URL 和参数来自压缩包 |
| `module/song_url.js` | ✅ 符合 | URL 和参数来自压缩包 |
| `module/song_id3.js` | ✅ 符合 | URL 和参数来自压缩包 |
| `module/lyric.js` | ✅ 符合 | URL 和参数来自压缩包 |
| `module/login.js` | ✅ 符合 | URL 来自压缩包 |
| `module/user_info.js` | ✅ 符合 | URL 来自压缩包 |
| `module/user_vip.js` | ✅ 符合 | URL 来自压缩包 |
| `module/reg_auth.js` | ✅ 符合 | URL 来自压缩包 |
| `module/playlist_like.js` | ✅ 符合 | URL 来自压缩包 |
| `module/playlist_op.js` | ✅ 符合 | URL 和参数来自压缩包 |
| `module/correct.js` | ✅ 符合 | URL 来自压缩包 |
| `module/download_check.js` | ✅ 符合 | URL 来自压缩包 |
| `module/lossless_list.js` | ✅ 符合 | URL 来自压缩包 |
| `yeelion` 盐值 | ✅ 符合 | 压缩包确认存在 |

### 6.2 需要修正的部分 ❌

| 模块 | 问题 | 修正方向 |
|------|------|----------|
| `util/crypto.js` RSA 公钥 | 编造的 RSA 公钥 | 移除 `publicRsaKey` 和 `cryptoRSAEncrypt`（压缩包无 RSA 公钥） |
| `util/crypto.js` AES 实现 | 通用 AES 实现，非压缩包逆向 | 保留函数壳，标注 `[算法未确认]`，`Entrypt::Encrypt/Decrypt` 的密钥未知 |
| `util/request.js` `generateSign` | `MD5(params + "yeelion")` 是推测的 | `Sig::CalcSign` 输出是两个 uint，不是 MD5 hex。标注 `[算法未确认]` |
| `util/helper.js` `generateSign` | 同上 | 同上 |

---

## 七、待逆向确认清单

以下内容需要进一步反汇编压缩包内的二进制文件才能确认：

1. **`Sig::CalcSign` 算法**：反汇编 `KwLib.dll` 中 `?CalcSign@Sig@KwLib@@YA_NPBDPAI1@Z` 函数体
2. **`Entrypt::Encrypt/Decrypt` 算法**：反汇编确认是 AES/DES/自定义算法，以及密钥来源
3. **`yeelion` 的具体用途**：是签名盐值、加密密钥、还是版本标识？
4. **`KoOtOiTvINGwd`（13字符）用途**：与 PlayerCore.dll 相关，可能是 .kwm 解密密钥
5. **`_Y8g2E6n0E1i7L5t2IoOoNk`（24字符）用途**：与 .kwm 格式相关，可能是加密密钥
6. **`.kwm` 文件格式**：解密算法
7. **歌词 zip 解压后的格式**：`.lrc` / `.lrcx` 的具体编码
8. **`CMD5` 类的完整接口**：除了构造函数，还有哪些方法

---

## 八、版本记录

| 日期 | 版本 | 说明 |
|------|------|------|
| 2026-08-07 | 1.0 | 初始版本，基于 default.zip 逆向分析 |
