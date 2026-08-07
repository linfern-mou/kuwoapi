/**
 * @fileoverview 酷我音乐排行榜歌曲列表接口
 *
 * 获取指定排行榜的歌曲列表。
 *
 * 路由: /top/list
 *
 * @example
 * // GET /top/list?bangId=93&pn=1&rn=30
 * const res = await api.top_list({ bangId: '93', pn: 1, rn: 30 });
 *
 * @module top_list
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    bangId: params?.bangId || '',
    pn: params?.pn || 1,
    rn: params?.rn || 30,
    platform: 'android',
    clientver: params?.clientver || '8.7.4.0',
  };

  return useAxios({
    url: '/openapi/v1/bang/musicList',
    method: 'GET',
    params: dataMap,
    encryptType: 'android',
    headers: { 'x-router': 'bang.kuwo.cn' },
    cookie: params?.cookie || {},
  });
};
