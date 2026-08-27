# 酷我PC客户端API完整汇总

数据来源: `/tmp/1111_new.pcapng` (84MB)
统计时间: 2026-08-27
总请求数: 901 (880 GET + 21 POST)
唯一域名数: 45+

## 一、核心业务API

### 1. 登录认证
| 域名 | 接口 | 功能 |
|------|------|------|
| pc.i.kuwo.cn | `/US_NEW/kuwo/login_kw` | PC客户端登录 |
| i.kuwo.cn | `/US/client/uinfo2012.jsp` | 用户信息 |
| loginserver.kuwo.cn | - | 登录服务器 |

### 2. 搜索
| 域名 | 接口 | 功能 |
|------|------|------|
| dhjss.kuwo.cn | `/s.c` | **主搜索接口** (歌手/专辑/歌单) |
| search.kuwo.cn | `/r.s` | 音乐信息查询 |
| jiucuo.search.kuwo.cn | `/correct.s` | 搜索纠错 |
| skeylist.kuwo.cn | `/searchkey/searchkey.txt` | 热搜词 |

### 3. 播放结算
| 域名 | 接口 | 功能 |
|------|------|------|
| musicpay.kuwo.cn | `/music.pay` | **播放结算** (返回音质/URL/token) |

### 4. 音乐信息
| 域名 | 接口 | 功能 |
|------|------|------|
| datacenter.kuwo.cn | `/d.c` | 数据中心 (返回CDN tag) |

### 5. CDN下载
| 域名 | 请求数 | 功能 |
|------|--------|------|
| kw-lw.kuwo.cn | 4 | 主CDN (trackmedia格式) |
| kw-bj.kuwo.cn | 193 | 北京CDN (resource格式) |
| kw-er.kuwo.cn | 150 | 二级CDN (trackmedia格式) |

## 二、用户功能API

### 6. 歌单
| 域名 | 接口 | 功能 |
|------|------|------|
| nplserver.kuwo.cn | `/pl.svc` | 歌单同步 (ucheck/getlikeinfo) |
| pan.kuwo.cn | `/pan` | 云盘列表 |

### 7. 歌词
| 域名 | 接口 | 功能 |
|------|------|------|
| newlyric.kuwo.cn | `/newlyric.lrc` | 二进制歌词 |
| wa.kuwo.cn | `/lyrics/img/kwgg/` | 歌词广告/图片 |

### 8. 评论
| 域名 | 接口 | 功能 |
|------|------|------|
| comment.kuwo.cn | `/com.s` | 获取评论/推荐评论 |

## 三、推荐与发现

### 9. 推荐
| 域名 | 接口 | 功能 |
|------|------|------|
| rcm.kuwo.cn | `/rec.s` | 个性化推荐 |
| mgxhtj.kuwo.cn | `/mgxh.s` | 关键词推荐 |
| gxh2.kuwo.cn | `/newradio.nr` | 新电台 |
| qukudata.kuwo.cn | `/q.k` | 曲目数据 |

### 10. 榜单
| 域名 | 接口 | 功能 |
|------|------|------|
| topmusic.kuwo.cn | `/today_recommend/` | 今日推荐配置 |
| topmusic.sycdn.kuwo.cn | `/today_recommend/adDown.js` | 榜单广告 |

## 四、配置与通信

### 11. 配置
| 域名 | 接口 | 功能 |
|------|------|------|
| config.kuwo.cn | `/uc/s` | 服务端配置 (m=56/60/90) |
| updatepage.kuwo.cn | `/pagesig/netsong/` | 版本签名 |

### 12. 网络
| 域名 | 接口 | 功能 |
|------|------|------|
| ipcheck.kuwo.cn | `/ip_check.kuwo` | IP校验 |
| ipdomainserver.kuwo.cn | - | IP域名解析 |

## 五、媒体资源

### 13. 图片CDN
| 域名 | 请求数 | 内容 |
|------|--------|------|
| img1.sycdn.kuwo.cn | ~200 | 专辑封面/用户头像 |
| img2.sycdn.kuwo.cn | ~57 | 同上 |
| img3.sycdn.kuwo.cn | ~55 | 同上 |
| img4.sycdn.kuwo.cn | ~55 | 同上 |
| img1.kwcdn.kuwo.cn | ~9 | 星级CDN |
| star.kwcdn.kuwo.cn | ~37 | 电台封面 |

### 14. 歌手/专辑图
| 域名 | 接口 | 功能 |
|------|------|------|
| artistpicserver.kuwo.cn | `/pic.web` | 歌手大图/专辑图 |
| album.kuwo.cn | `/album/jxjPast` | 精选专辑 |
| album.kuwo.cn | `/album/mv2015` | MV专辑 |
| artistlistinfo.kuwo.cn | `/mb.slist` | 歌手列表 |

## 六、其他API

### 15. 网站
| 域名 | 接口 | 功能 |
|------|------|------|
| www.kuwo.cn | `/pc/radio/playing` | 电台播放状态 |
| www.kuwo.cn | `/api/pc/skin/` | 皮肤配置 |
| www.kuwo.cn | `/pc/navigation/` | 导航配置 |

### 16. VIP/广告
| 域名 | 接口 | 功能 |
|------|------|------|
| vip1.kuwo.cn | `/vip/v2/user/vip` | VIP状态 |
| tips.kuwo.cn | `/t.s` | 提示信息 |
| log.kuwo.cn | - | 日志上报 |

### 17. 推送
| 域名 | 接口 | 功能 |
|------|------|------|
| deliver.kuwo.cn | `/yl_res_manage.search` | **加密搜索** (POST) |

## 七、关键发现

### 已验证可用
1. **dhjss.kuwo.cn/s.c** - 搜索接口，无需登录
2. **musicpay.kuwo.cn/music.pay** - 播放结算，返回音质和token
3. **datacenter.kuwo.cn/d.c** - 返回下载tag（第三方域名）
4. **ipcheck.kuwo.cn** - IP校验

### 阻塞点
1. **deliver.kuwo.cn** - POST加密，算法未完全还原
2. **CDN hash生成** - 客户端本地计算，需逆向KwLib.dll
3. **config API** - 返回FAIL，参数可能已变化

### CDN URL格式
```
kw-lw/kw-er: /{hash1}/{hash2}/resource/{res_id}/trackmedia/{filename}.flac
kw-bj: /{hash1}/{hash2}/rc/resource/s2/{path}.flac
```

## 八、请求统计

| 类别 | 域名数 | 请求数 |
|------|--------|--------|
| CDN下载 | 3 | 347 |
| 图片资源 | 10+ | ~400 |
| 核心API | 15+ | ~150 |
| 其他 | 10+ | ~50 |
