/**
 * @fileoverview 酷我音乐搜索接口
 *
 * 调用酷我音乐 API 进行歌曲搜索，支持设置每页数量和页码。
 *
 * 路由: /search
 *
 * @example
 * // GET /search?key=海阔天空&pn=1&rn=30
 * const res = await api.search({ key: '海阔天空', pn: 1, rn: 30 });
 *
 * @example
 * // 编程式调用
 * const api = require('./main');
 * const res = await api.search({ key: '海阔天空', pn: 1, rn: 30 });
 *
 * @module search
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    all: params?.key || '',
    pn: params?.pn || 1,
    rn: params?.rn || 30,
    vipver: 1,
    ft: 'music',
    clientver: params?.clientver || '8.7.4.0',
    platform: 'android',
    product: 'KuwoPlayer',
    encoding: 'utf8',
  };

  return useAxios({
    url: '/openapi/v1/search',
    method: 'GET',
    params: dataMap,
    encryptType: 'android',
    headers: { 'x-router': 'search.kuwo.cn' },
    cookie: params?.cookie || {},
  });
};
