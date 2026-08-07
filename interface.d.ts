/**
 * KuwoMusicApi TypeScript 类型定义
 *
 * 所有 API 函数返回 Promise<ApiResponse>。
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
  /** 客户端版本号 */
  clientver?: string;
  /** 不返回 Set-Cookie 头 */
  noCookie?: boolean;
}

/** 搜索接口参数 */
export interface SearchParams extends BaseParams {
  /** 搜索关键词 */
  key: string;
  /** 页码，默认 1 */
  pn?: number;
  /** 每页数量，默认 30 */
  rn?: number;
}

/** 歌曲播放地址参数 */
export interface SongUrlParams extends BaseParams {
  /** 歌曲 ID（支持单个或数组） */
  id: string | string[];
  /** 音质码率：128/192/320/2000/1411 */
  br?: number;
}

/** 歌词参数 */
export interface LyricParams extends BaseParams {
  /** 歌曲 ID */
  id: string;
}

/** 歌曲详情参数 */
export interface SongDetailParams extends BaseParams {
  /** 歌曲 ID（支持单个或数组） */
  id: string | string[];
}

/** 二维码登录 key 参数 */
export interface LoginQrKeyParams extends BaseParams {}

/** 二维码登录检查参数 */
export interface LoginQrCheckParams extends BaseParams {
  /** 由 /login/qr/key 返回的 key */
  key: string;
}

/** 登录状态参数 */
export interface LoginStatusParams extends BaseParams {
  token?: string;
}

/** 用户详情参数 */
export interface UserDetailParams extends BaseParams {
  uid?: string;
}

/** 排行榜歌曲参数 */
export interface TopListParams extends BaseParams {
  bangId: string;
  pn?: number;
  rn?: number;
}

/** 编程式 API 接口 */
export interface KuwoMusicApi {
  /** 搜索歌曲 */
  search(params: SearchParams): Promise<ApiResponse>;
  /** 获取播放地址 */
  song_url(params: SongUrlParams): Promise<ApiResponse>;
  /** 获取歌曲详情 */
  song_detail(params: SongDetailParams): Promise<ApiResponse>;
  /** 获取歌词 */
  lyric(params: LyricParams): Promise<ApiResponse>;
  /** 获取登录二维码 key */
  login_qr_key(params?: LoginQrKeyParams): Promise<ApiResponse>;
  /** 检查扫码状态 */
  login_qr_check(params: LoginQrCheckParams): Promise<ApiResponse>;
  /** 登录状态 */
  login_status(params?: LoginStatusParams): Promise<ApiResponse>;
  /** 用户详情 */
  user_detail(params: UserDetailParams): Promise<ApiResponse>;
  /** 排行榜分类 */
  top_category(params?: BaseParams): Promise<ApiResponse>;
  /** 排行榜歌曲列表 */
  top_list(params: TopListParams): Promise<ApiResponse>;
}

export = KuwoMusicApi;
