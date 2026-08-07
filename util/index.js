/**
 * @fileoverview 工具模块统一导出入口
 */

const { appid, clientver } = require('./config.json');

const {
  cryptoAesDecrypt,
  cryptoAesEncrypt,
  cryptoMd5,
  cryptoRSAEncrypt,
  cryptoSha1,
  publicRsaKey,
} = require('./crypto');

const { createRequest } = require('./request');

const { signKey, signParamsKey, signatureAndroidParams, signatureWebParams } = require('./helper');

const { randomString, decodeLyrics, parseCookieString, cookieToJson, randomNumber, getGuid } = require('./util');

module.exports = {
  appid,
  clientver,
  cryptoAesDecrypt,
  cryptoAesEncrypt,
  cryptoMd5,
  cryptoRSAEncrypt,
  cryptoSha1,
  createRequest,
  signKey,
  signParamsKey,
  signatureAndroidParams,
  signatureWebParams,
  randomString,
  parseCookieString,
  cookieToJson,
  publicRsaKey,
  randomNumber,
  getGuid,
};
