/**
 * @fileoverview 酷我音乐歌曲详情接口
 *
 * 获取指定歌曲的详细信息（歌名、歌手、专辑、时长等）。
 *
 * 路由: /song/detail
 *
 * @example
 * // GET /song/detail?id=123456
 * const res = await api.song_detail({ id: '123456' });
 *
 * @module song_detail
 */

module.exports = (params, useAxios) => {
  const ids = Array.isArray(params?.id) ? params.id : [params?.id].filter(Boolean);

  const dataMap = {
    musicIds: ids.join(','),
    ids: ids.join(','),
    type: 'music',
    clientver: params?.clientver || '8.7.4.0',
    platform: 'android',
  };

  return useAxios({
    url: '/openapi/v1/music/batchInfo',
    method: 'GET',
    params: dataMap,
    encryptType: 'android',
    headers: { 'x-router': 'nmobi.kuwo.cn' },
    cookie: params?.cookie || {},
  });
};
