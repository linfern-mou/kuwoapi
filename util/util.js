/**
 * @fileoverview 通用工具函数库
 *
 * 提供酷我音乐 API 项目中常用的工具函数
 */

const pako = require('pako');
const CryptoJS = require('crypto-js');

/**
 * 生成随机字符串（大写字母 + 数字）
 */
const randomString = (len = 16) => {
  const keyString = '1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const _key = [];
  const keyStringArr = keyString.split('');
  for (let i = 0; i < len; i += 1) {
    const ceil = Math.ceil((keyStringArr.length - 1) * Math.random());
    const _tmp = keyStringArr[ceil];
    _key.push(_tmp);
  }
  return _key.join('');
};

/**
 * 生成随机数字字符串
 */
const randomNumber = (len = 16) => {
  const keyString = '1234567890';
  const _key = [];
  const keyStringArr = keyString.split('');
  for (let i = 0; i < len; i += 1) {
    const ceil = Math.ceil((keyStringArr.length - 1) * Math.random());
    const _tmp = keyStringArr[ceil];
    _key.push(_tmp);
  }
  return _key.join('');
};

/**
 * 格式化 Cookie 字符串
 */
const parseCookieString = (cookie) => {
  const t = cookie.replace(/\s*(Domain|domain|path|expires)=[^(;|$)]+;*/g, '');
  return t.replace(/;HttpOnly/g, '');
};

/**
 * Cookie 字符串转 JSON 对象
 */
const cookieToJson = (cookie) => {
  if (!cookie) return {};
  let cookieArr = cookie.split(';');
  let obj = {};
  cookieArr.forEach((i) => {
    let arr = i.split('=');
    obj[arr[0]] = arr[1];
  });
  return obj;
};

/**
 * 生成随机 GUID（UUID v4 格式）
 */
const getGuid = () => {
  const e = () => {
    return ((65536 * (1 + Math.random())) | 0).toString(16).substring(1);
  };
  return `${e()}${e()}-${e()}-${e()}-${e()}-${e()}${e()}${e()}`;
};

module.exports = {
  randomString,
  randomNumber,
  parseCookieString,
  cookieToJson,
  getGuid,
};
