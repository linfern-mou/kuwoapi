/**
 * @fileoverview 酷我音乐歌词接口
 *
 * 接口来源：default.zip 中 KwModLyric.dll strings 分析
 * 端点：http://newlyric.kuwo.cn/newlyric.lrc
 * 参数：&lrcx=1&contenttype=zip&olrc=1
 *
 * 路由: /lyric
 *
 * @module lyric
 */

module.exports = (params, useAxios) => {
  const musicId = params?.id || params?.musicId || '';

  const dataMap = {
    musicId: musicId,
    lrcx: 1,
    contenttype: 'zip',
    olrc: 1,
  };

  return useAxios({
    baseURL: 'http://newlyric.kuwo.cn',
    url: '/newlyric.lrc',
    method: 'GET',
    params: dataMap,
    responseType: 'arraybuffer',
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
