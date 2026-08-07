/**
 * @fileoverview 酷我音乐二维码登录 - 获取 key 接口
 *
 * 生成用于扫码登录的二维码 key 和图片链接。
 *
 * 路由: /login/qr/key
 *
 * @example
 * // GET /login/qr/key
 * const res = await api.login_qr_key();
 *
 * @module login_qr_key
 */

const QRCode = require('qrcode');
const { cryptoMd5, randomString } = require('../util');

module.exports = async (params, useAxios) => {
  const key = cryptoMd5(`${Date.now()}${randomString(16)}`);
  const ts = Math.floor(Date.now() / 1000);

  const dataMap = {
    key,
    timestamp: ts,
    platform: 'android',
    clientver: params?.clientver || '8.7.4.0',
  };

  const response = await useAxios({
    url: '/openapi/v1/login/qrcode/create',
    method: 'POST',
    data: dataMap,
    encryptType: 'android',
    headers: { 'x-router': 'login.kuwo.cn' },
    cookie: params?.cookie || {},
  });

  // 生成二维码图片（Base64）
  if (response?.body?.data?.qrcode) {
    const qrcodeBase64 = await QRCode.toDataURL(response.body.data.qrcode, { margin: 1 });
    response.body.data.qrcodeImg = qrcodeBase64;
  }

  return response;
};
