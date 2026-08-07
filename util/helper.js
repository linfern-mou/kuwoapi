/**
 * @fileoverview 酷我音乐 API 请求签名工具
 *
 * 来源：default.zip 中 KwLib.dll 的 Sig::CalcSign 函数分析。
 *
 * 酷我 PC 客户端 r.s 系列接口使用 MD5 签名，
 * sign 参数通过对请求参数排序拼接后 MD5 生成。
 */

const { cryptoMd5 } = require('./crypto');

// 签名盐值（来源压缩包 KwLib.dll Sig::CalcSign 关联分析）
const SIGN_SALT = 'yeelion';

/**
 * 生成 r.s 接口签名
 *
 * 签名规则（来源压缩包 stype=geturl&sign=%s 等格式）：
 * 1. 参数按 key 排序
 * 2. 拼接为 key=value&key=value 格式
 * 3. 末尾追加盐值
 * 4. MD5 取十六进制
 *
 * @param {Object} params - 请求参数对象
 * @returns {string} 32位十六进制签名
 */
const generateSign = (params) => {
  const queryStr = Object.keys(params)
    .sort()
    .map((key) => `${key}=${params[key]}`)
    .join('&');
  return cryptoMd5(`${queryStr}${SIGN_SALT}`);
};

module.exports = {
  generateSign,
  SIGN_SALT,
};
