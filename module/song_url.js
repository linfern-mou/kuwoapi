/**
 * @fileoverview 酷我音乐歌曲播放地址接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * 端点：http://antiserver.kuwo.cn/anti.s
 * 参数：format=aac&type=convert_url&rid=%s&response=url&loginid=%s&ch=%s&instsrc=%s
 *
 * 路由: /song/url
 *
 * @module song_url
 */

module.exports = (params, useAxios) => {
  const rid = params?.id || params?.rid || '';

  const dataMap = {
    format: params?.format || 'aac',
    type: 'convert_url',
    rid: rid,
    response: 'url',
    loginid: params?.loginid || '',
    ch: params?.ch || '',
    instsrc: params?.instsrc || '',
  };

  return useAxios({
    baseURL: 'http://antiserver.kuwo.cn',
    url: '/anti.s',
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
