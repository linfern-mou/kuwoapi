/**
 * @fileoverview 工具模块统一导出入口
 *
 * 严格遵守 REVERSE_SPEC.md 约束。
 */

const { clientver, channel, framever, corever } = require('./config.json');

const {
  // 压缩包确认的字符串常量
  YEELION,
  YEELION_KUWO_TME,
  YEELION_HISTORY,
  YEELION_RAND,
  KEY_CANDIDATE_1,
  KEY_CANDIDATE_2,
  LOGIN_SALT,
  // 压缩包确认的加密函数（已实现）
  cryptoMd5,
  base64Encode,
  base64Decode,
  // 压缩包确认存在但算法未确认的函数（空壳）
  entryptEncrypt,
  entryptDecrypt,
  calcSign,
} = require('./crypto');

const { createRequest } = require('./request');

const { generateSign } = require('./helper');

const { randomString, parseCookieString, cookieToJson, randomNumber, getGuid } = require('./util');

module.exports = {
  clientver,
  channel,
  framever,
  corever,

  // 字符串常量
  YEELION,
  YEELION_KUWO_TME,
  YEELION_HISTORY,
  YEELION_RAND,
  KEY_CANDIDATE_1,
  KEY_CANDIDATE_2,
  LOGIN_SALT,

  // 已实现的加密函数
  cryptoMd5,
  base64Encode,
  base64Decode,

  // 算法未确认的函数（空壳）
  entryptEncrypt,
  entryptDecrypt,
  calcSign,

  // 请求工具
  createRequest,
  generateSign,

  // 通用工具
  randomString,
  parseCookieString,
  cookieToJson,
  randomNumber,
  getGuid,
};
