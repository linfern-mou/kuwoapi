/**
 * KuwoMusicApi TypeScript 类型定义
 *
 * 所有接口均来源于 default.zip 压缩包内 DLL/exe 逆向分析。
 */

/** 统一响应结构 */
export interface ApiResponse {
  status: number;
  body: any;
  cookie?: string[];
  headers?: Record<string, string>;
}

/** API 函数的公共参数 */
export interface BaseParams {
  /** Cookie 字符串或对象，用于鉴权 */
  cookie?: string | Record<string, string>;
  /** 真实 IP（用于 IP 透传） */
  realIP?: string;
  /** 不返回 Set-Cookie 头 */
  noCookie?: boolean;
}

/** 搜索接口参数 */
export interface SearchParams extends BaseParams {
  /** 搜索关键词 */
  key: string;
  /** 页码，默认 0 */
  pn?: number;
  /** 每页数量，默认 10 */
  rn?: number;
}

/** 歌曲详情参数 */
export interface SongDetailParams extends BaseParams {
  /** 歌曲 ID（支持单个或数组） */
  id: string | string[];
}

/** 歌曲播放地址参数 */
export interface SongUrlParams extends BaseParams {
  /** 歌曲 ID */
  id: string;
  /** 格式，默认 aac */
  format?: string;
}

/** 歌词参数 */
export interface LyricParams extends BaseParams {
  /** 歌曲 ID */
  id: string;
}

/** 登录参数 */
export interface LoginParams extends BaseParams {
  uname: string;
  pwd: string;
}

/** 用户信息参数 */
export interface UserInfoParams extends BaseParams {
  uid?: string;
  sid?: string;
}

/** VIP 信息参数 */
export interface UserVipParams extends BaseParams {
  uid?: string;
}

/** 歌单操作参数 */
export interface PlaylistOpParams extends BaseParams {
  op: 'add' | 'del' | 'update' | 'validate' | 'login' | 'query' | 'submit';
  uid?: string;
  sid?: string;
  name?: string;
  pid?: string;
  rids?: string;
  num?: number;
  uname?: string;
  pwd?: string;
  action?: string;
  ids?: string;
  id?: string;
  br?: number;
  fmt?: string;
}

/** 编程式 API 接口 */
export interface KuwoMusicApi {
  /** 搜索歌曲 (search.kuwo.cn/r.s) */
  search(params: SearchParams): Promise<ApiResponse>;
  /** 歌曲详情 (search.kuwo.cn/r.s?stype=musicinfo) */
  song_detail(params: SongDetailParams): Promise<ApiResponse>;
  /** 播放地址 (antiserver.kuwo.cn/anti.s) */
  song_url(params: SongUrlParams): Promise<ApiResponse>;
  /** ID3信息 (datacenter.kuwo.cn/d.c) */
  song_id3(params: SongDetailParams): Promise<ApiResponse>;
  /** 歌词 (newlyric.kuwo.cn/newlyric.lrc) */
  lyric(params: LyricParams): Promise<ApiResponse>;
  /** 登录 (pc.i.kuwo.cn/US_NEW/kuwo/login_kw) */
  login(params: LoginParams): Promise<ApiResponse>;
  /** 用户信息 (pc.i.kuwo.cn/US_NEW/kuwo/vuser) */
  user_info(params: UserInfoParams): Promise<ApiResponse>;
  /** VIP信息 (vip1.kuwo.cn/vip/v2/user/vip) */
  user_vip(params: UserVipParams): Promise<ApiResponse>;
  /** 注册验证 (reg.kuwo.cn/regsvr.auth) */
  reg_auth(params: UserInfoParams): Promise<ApiResponse>;
  /** 喜欢列表 (nplserver.kuwo.cn/pl.svc?op=getlikeinfo) */
  playlist_like(params: UserVipParams): Promise<ApiResponse>;
  /** 歌单操作 (pls.kuwo.cn/pl.svc) */
  playlist_op(params: PlaylistOpParams): Promise<ApiResponse>;
  /** 数据纠错 (jiucuo.search.kuwo.cn/correct.s) */
  correct(params: { key: string } & BaseParams): Promise<ApiResponse>;
  /** 下载检查 (cldserver.kuwo.cn/c.s?op=ucheck) */
  download_check(params: { fmt?: string } & BaseParams): Promise<ApiResponse>;
  /** 无损列表 (misc.service.kuwo.cn/lossless/list) */
  lossless_list(params: UserVipParams): Promise<ApiResponse>;
}

export = KuwoMusicApi;
