/**
 * @fileoverview 酷我音乐二维码登录 - 轮询检查接口
 *
 * 检查二维码扫码状态，返回登录 token。
 *
 * 路由: /login/qr/check
 *
 * @example
 * // GET /login/qr/check?key=xxxx
 * const res = await api.login_qr_check({ key: 'xxxx' });
 *
 * @module login_qr_check
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    key: params?.key || '',
    platform: 'android',
    clientver: params?.clientver || '8.7.4.0',
  };

  return useAxios({
    url: '/openapi/v1/login/qrcode/check',
    method: 'GET',
    params: dataMap,
    encryptType: 'android',
    headers: { 'x-router': 'login.kuwo.cn' },
    cookie: params?.cookie || {},
  });
};
