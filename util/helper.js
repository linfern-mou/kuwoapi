/**
 * @fileoverview 酷我音乐 API 请求签名工具
 *
 * 严格遵守 REVERSE_SPEC.md 约束：
 * - 签名函数 Sig::CalcSign 的算法 [未确认]
 * - 禁止用 MD5(params+yeelion) 等推测实现冒充
 *
 * 来源：default.zip 中 KwLib.dll 的 Sig::CalcSign 函数符号分析
 * - ?CalcSign@Sig@KwLib@@YA_NPBDPAI1@Z
 * - 函数签名：bool CalcSign(const char* data, unsigned int* out1, unsigned int* out2)
 * - 输出两个 unsigned int，拼接方式未知
 *
 * @module helper
 * @see REVERSE_SPEC.md 第四章第4.1节、第四章第4.4节
 */

const { calcSign, YEELION } = require('./crypto');

/**
 * [算法未确认] 生成请求签名 sign
 *
 * ⚠️ 警告：Sig::CalcSign 的具体算法未逆向确认。
 *
 * 已知信息（来源压缩包）：
 * - 函数输出两个 unsigned int
 * - 用于 stype=geturl&sign=%s 等接口
 * - yeelion 字符串确认存在，但具体用途未知
 *
 * 未知信息（禁止推测）：
 * - 两个 uint 如何拼成 sign 字符串
 * - yeelion 是否作为盐值参与计算
 *
 * @param {Object|string} params - 请求参数
 * @returns {string} 签名字符串
 * @throws {Error} 算法未确认时抛出错误
 */
const generateSign = (params) => {
  // 委托给 calcSign（空壳函数，调用即抛错）
  // 当算法逆向确认后，在此实现具体逻辑
  const data = typeof params === 'object' ? JSON.stringify(params) : params;
  return calcSign(data);
};

module.exports = {
  generateSign,
  YEELION,
};
