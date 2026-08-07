/**
 * @fileoverview 工具模块统一导出入口
 */

const { clientver, channel, framever, corever } = require('./config.json');

const {
  cryptoAesDecrypt,
  cryptoAesEncrypt,
  cryptoMd5,
  cryptoRSAEncrypt,
  cryptoSha1,
  publicRsaKey,
} = require('./crypto');

const { createRequest, generateSign } = require('./request');

const { generateSign: generateSignHelper, SIGN_SALT } = require('./helper');

const { randomString, decodeLyrics, parseCookieString, cookieToJson, randomNumber, getGuid } = require('./util');

module.exports = {
  clientver,
  channel,
  framever,
  corever,
  cryptoAesDecrypt,
  cryptoAesEncrypt,
  cryptoMd5,
  cryptoRSAEncrypt,
  cryptoSha1,
  createRequest,
  generateSign: generateSignHelper,
  SIGN_SALT,
  randomString,
  parseCookieString,
  cookieToJson,
  publicRsaKey,
  randomNumber,
  getGuid,
};
