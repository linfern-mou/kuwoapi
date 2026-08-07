/**
 * @fileoverview 酷我音乐歌词接口
 *
 * 获取指定歌曲的歌词（LRC 格式）。
 *
 * 路由: /lyric
 *
 * @example
 * // GET /lyric?id=123456
 * const res = await api.lyric({ id: '123456' });
 *
 * @module lyric
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    musicId: params?.id || params?.musicId || '',
    type: 'lrc',
    clientver: params?.clientver || '8.7.4.0',
    platform: 'android',
  };

  return useAxios({
    url: '/openapi/v1/music/lyrics',
    method: 'GET',
    params: dataMap,
    encryptType: 'android',
    headers: { 'x-router': 'nmobi.kuwo.cn' },
    cookie: params?.cookie || {},
  });
};
