/**
 * @fileoverview 酷我音乐排行榜分类接口
 *
 * 获取所有排行榜分类列表。
 *
 * 路由: /top/category
 *
 * @example
 * // GET /top/category
 * const res = await api.top_category();
 *
 * @module top_category
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    platform: 'android',
    clientver: params?.clientver || '8.7.4.0',
  };

  return useAxios({
    url: '/openapi/v1/bang/list',
    method: 'GET',
    params: dataMap,
    encryptType: 'android',
    headers: { 'x-router': 'bang.kuwo.cn' },
    cookie: params?.cookie || {},
  });
};
