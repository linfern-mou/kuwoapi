/**
 * @fileoverview 酷我音乐 API 请求签名工具
 *
 * 本模块提供多种签名算法，用于对 API 请求参数进行加密签名
 */

const CryptoJS = require('crypto-js');
const { cryptoMd5, wordArrayFromBuffer } = require('./crypto');
const { appid: useAppid, clientver: useClientver } = require('./config.json');

/**
 * Web 版 API 请求 signature 签名
 */
const signatureWebParams = (params) => {
  const str = 'NVPh5oo715z5DIWAeQlhMDsWXXQV4hwt';
  const paramsString = Object.keys(params)
    .map((key) => `${key}=${params[key]}`)
    .sort()
    .join('');
  return cryptoMd5(`${str}${paramsString}${str}`);
};

/**
 * Android 版 API 请求 signature 签名
 */
const signatureAndroidParams = (params, data) => {
  const str = 'OIlwieks28dk2k092lksi2UIkp';
  const paramsString = Object.keys(params)
    .sort()
    .map((key) => `${key}=${typeof params[key] === 'object' ? JSON.stringify(params[key]) : params[key]}`)
    .join('');

  if (Buffer.isBuffer(data)) {
    const hasher = CryptoJS.algo.MD5.create();
    hasher.update(CryptoJS.enc.Utf8.parse(str));
    hasher.update(CryptoJS.enc.Utf8.parse(paramsString));
    hasher.update(wordArrayFromBuffer(data));
    hasher.update(CryptoJS.enc.Utf8.parse(str));
    return hasher.finalize().toString(CryptoJS.enc.Hex);
  }

  return cryptoMd5(`${str}${paramsString}${data || ''}${str}`);
};

/**
 * 请求密钥签名（signKey）
 */
const signKey = (hash, dev, userid, appid) => {
  const str = '57ae12eb6890223e355ccfcb74edf70d';
  return cryptoMd5(`${hash}${str}${appid || useAppid}${dev}${userid || 0}`);
};

/**
 * 参数密钥签名（signParamsKey）
 */
const signParamsKey = (data, appid, clientver) => {
  const str = 'OIlwieks28dk2k092lksi2UIkp';
  appid = appid || useAppid;
  clientver = clientver || useClientver;
  return cryptoMd5(`${appid}${str}${clientver}${data}`);
};

module.exports = {
  signKey,
  signParamsKey,
  signatureAndroidParams,
  signatureWebParams,
};
