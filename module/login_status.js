/**
 * @fileoverview 酷我音乐登录状态接口
 *
 * 通过 token 检查当前登录状态和用户信息。
 *
 * 路由: /login/status
 *
 * @example
 * // GET /login/status?token=xxxx
 * const res = await api.login_status({ cookie: { token: 'xxxx' } });
 *
 * @module login_status
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    token: params?.cookie?.token || params?.token || '',
    platform: 'android',
    clientver: params?.clientver || '8.7.4.0',
  };

  return useAxios({
    url: '/openapi/v1/user/info',
    method: 'GET',
    params: dataMap,
    encryptType: 'android',
    headers: { 'x-router': 'user.kuwo.cn' },
    cookie: params?.cookie || {},
  });
};
