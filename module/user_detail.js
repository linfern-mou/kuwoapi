/**
 * @fileoverview 酷我音乐用户详情接口
 *
 * 获取指定用户的详细信息。
 *
 * 路由: /user/detail
 *
 * @example
 * // GET /user/detail?uid=123
 * const res = await api.user_detail({ uid: '123' });
 *
 * @module user_detail
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    uid: params?.uid || params?.cookie?.userid || '',
    platform: 'android',
    clientver: params?.clientver || '8.7.4.0',
  };

  return useAxios({
    url: '/openapi/v1/user/detail',
    method: 'GET',
    params: dataMap,
    encryptType: 'android',
    headers: { 'x-router': 'user.kuwo.cn' },
    cookie: params?.cookie || {},
  });
};
